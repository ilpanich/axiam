//! Webhook AMQP consumer — drives `WebhookDeliveryService::deliver_once` for
//! each queued delivery (CORR-03/D-06), schedules retries natively via the
//! `axiam.webhook.retry` queue's per-message TTL + DLX (D-07/D-08 — no
//! in-process wait tying up a consumer slot), and writes per-attempt +
//! terminal audit records (D-09).
//!
//! Lives in `axiam-api-rest` (NOT `axiam-amqp`) per the 26-03 architecture
//! note: `axiam-amqp` cannot depend on `axiam-federation`/`axiam-auth`/
//! `axiam-api-rest` without introducing a dependency cycle, and
//! `deliver_once` needs the shared SSRF guard (SEC-019/SECHRD-02) and
//! webhook-secret decryption (SEC-031). It uses `lapin::Channel`,
//! `axiam_amqp::connection::queues::{WEBHOOK,WEBHOOK_RETRY,WEBHOOK_DLQ}`,
//! `axiam_amqp::WebhookMessage`, and `axiam_amqp::WebhookPublisher` — all
//! already present in `axiam-amqp` (a dependency of this crate).

use axiam_amqp::{WebhookMessage, WebhookPublisher, connection::queues};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogRepository, WebhookRepository};
use futures_lite::StreamExt;
use lapin::Acker;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions};
use lapin::types::{DeliveryTag, FieldTable};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::webhook::WebhookDeliveryService;

// ---------------------------------------------------------------------------
// Retry config (D-08/D-20)
// ---------------------------------------------------------------------------

/// Default maximum delivery attempts before a webhook delivery is
/// dead-lettered to `WEBHOOK_DLQ`. Matches the mail-consumer's convention of
/// a small, safe default (`mail_consumer::MAX_RETRIES = 3`) scaled slightly
/// up for webhooks, whose receivers are external/third-party endpoints more
/// prone to transient outages than the mail-consumer's SMTP relay.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default base backoff (milliseconds) applied to the first retry.
const DEFAULT_BACKOFF_BASE_MS: u64 = 5_000; // 5s

/// Default backoff ceiling (milliseconds) — no single retry TTL exceeds this.
const DEFAULT_BACKOFF_CEILING_MS: u64 = 3_600_000; // 1h

/// Exponential backoff multiplier applied per subsequent retry attempt.
/// Mirrors `mail_consumer::MAIL_RETRY_BACKOFF_MULTIPLIER`.
const BACKOFF_MULTIPLIER: f64 = 2.0;

/// Config-driven webhook retry policy (D-20): `AXIAM__WEBHOOK__MAX_ATTEMPTS`,
/// `AXIAM__WEBHOOK__BACKOFF_BASE_MS`, `AXIAM__WEBHOOK__BACKOFF_CEILING_MS`.
/// Every field has a safe default and is fully overridable — nothing is
/// mandatory for the server to boot with webhook delivery enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebhookRetryConfig {
    /// Maximum number of delivery attempts (first attempt counts as 1)
    /// before a delivery is dead-lettered to `WEBHOOK_DLQ`.
    pub max_attempts: u32,
    /// Base backoff (milliseconds) used for the first retry.
    pub backoff_base_ms: u64,
    /// Upper bound (milliseconds) any single retry TTL can reach.
    pub backoff_ceiling_ms: u64,
}

impl Default for WebhookRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            backoff_base_ms: DEFAULT_BACKOFF_BASE_MS,
            backoff_ceiling_ms: DEFAULT_BACKOFF_CEILING_MS,
        }
    }
}

impl WebhookRetryConfig {
    /// Reads `AXIAM__WEBHOOK__MAX_ATTEMPTS`, `AXIAM__WEBHOOK__BACKOFF_BASE_MS`,
    /// `AXIAM__WEBHOOK__BACKOFF_CEILING_MS` via
    /// `std::env::var(...).ok().and_then(parse).unwrap_or(default)`, mirroring
    /// the existing `AXIAM__SECTION__KEY` env-config precedent
    /// (`axiam-api-grpc::middleware::rate_limit::trusted_hops_from_env`).
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            max_attempts: std::env::var("AXIAM__WEBHOOK__MAX_ATTEMPTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.max_attempts),
            backoff_base_ms: std::env::var("AXIAM__WEBHOOK__BACKOFF_BASE_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.backoff_base_ms),
            backoff_ceiling_ms: std::env::var("AXIAM__WEBHOOK__BACKOFF_CEILING_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.backoff_ceiling_ms),
        }
    }
}

/// Bounded exponential backoff (D-08): `base_ms * multiplier^(attempt-1)`,
/// clamped to `[0, ceiling_ms]`. The result becomes the retry queue's
/// per-message TTL (`WebhookPublisher::publish_retry`'s `ttl_ms`), not an
/// in-process sleep duration — RabbitMQ's native TTL + DLX schedules the
/// delay so no consumer slot is held for its duration (D-07).
///
/// `attempt` is the *post-increment* attempt number about to be published
/// (`1` for the first retry, `2` for the second, ...), mirroring
/// `mail_consumer::backoff_delay_secs`'s convention.
pub fn backoff_ttl_ms(attempt: u32, cfg: &WebhookRetryConfig) -> u64 {
    let exponent = attempt.saturating_sub(1) as i32;
    let delay_ms = cfg.backoff_base_ms as f64 * BACKOFF_MULTIPLIER.powi(exponent);
    let ceiling_ms = cfg.backoff_ceiling_ms as f64;
    delay_ms.clamp(0.0, ceiling_ms) as u64
}

// ---------------------------------------------------------------------------
// AMQP consumer loop
// ---------------------------------------------------------------------------

/// Build the terminal/per-attempt audit entry for a webhook delivery outcome
/// (D-09). `actor_id` uses the `Uuid::nil()` system-actor convention (no
/// human/service-account initiated this delivery attempt — mirrors
/// `mail_consumer`'s and `axiam-federation::secrets`'s existing
/// `ActorType::System` + nil-actor-id pattern).
fn build_audit_entry(
    tenant_id: Uuid,
    webhook_id: Uuid,
    action: &str,
    outcome: AuditOutcome,
    metadata: serde_json::Value,
) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: action.into(),
        resource_id: Some(webhook_id),
        outcome,
        ip_address: None,
        metadata: Some(metadata),
    }
}

/// Start consuming webhook deliveries from `queues::WEBHOOK` (D-06).
///
/// For each dequeued [`WebhookMessage`]:
/// - Deserialize; a malformed payload is nacked `requeue:false` (bad
///   payload, not retried forever — mirrors `mail_consumer`'s bad-payload
///   handling).
/// - Call `delivery_service.deliver_once` exactly once.
/// - On a 2xx response: ack + write a terminal `webhook.delivery_succeeded`
///   audit record.
/// - On a non-2xx response or `WebhookError`, with `attempt+1 < max_attempts`:
///   publish a copy (with incremented `attempt`) to `queues::WEBHOOK_RETRY`
///   with `expiration = backoff_ttl_ms(attempt+1, cfg)`, write a per-attempt
///   `webhook.delivery_attempt` audit record, then ack the ORIGINAL message
///   (the retry copy re-enters `queues::WEBHOOK` via TTL+DLX once the delay
///   expires — no in-process wait ties up this consumer's slot, D-07).
/// - On exhaustion (`attempt+1 >= max_attempts`): nack `requeue:false` so the
///   message dead-letters to `queues::WEBHOOK_DLQ` (replayable), and write a
///   terminal `webhook.delivery_failed` audit record.
///
/// SEC-019/SECHRD-02: `deliver_once` is reused unchanged — the SSRF guard is
/// preserved when delivery is driven from AMQP, not bypassed.
pub async fn start_webhook_consumer<W, A>(
    channel: Channel,
    delivery_service: WebhookDeliveryService<W>,
    publisher: WebhookPublisher,
    audit_repo: A,
    cfg: WebhookRetryConfig,
) where
    W: WebhookRepository + Clone + 'static,
    A: AuditLogRepository + 'static,
{
    info!("Starting webhook AMQP consumer");

    let mut consumer = match channel
        .basic_consume(
            queues::WEBHOOK.into(),
            "axiam-webhook-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to start webhook consumer");
            return;
        }
    };

    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "Error receiving webhook delivery");
                continue;
            }
        };

        let tag = delivery.delivery_tag;

        // Deserialize. Bad payload -> nack requeue:false (not re-deliverable).
        let msg: WebhookMessage = match serde_json::from_slice(&delivery.data) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    error = %e,
                    delivery_tag = tag,
                    "Invalid webhook message payload, nacking"
                );
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                continue;
            }
        };

        let result = delivery_service
            .deliver_once(
                msg.tenant_id,
                msg.webhook_id,
                msg.delivery_id,
                &msg.event_type,
                &msg.payload,
            )
            .await;

        match result {
            Ok(status) if status.is_success() => {
                let entry = build_audit_entry(
                    msg.tenant_id,
                    msg.webhook_id,
                    "webhook.delivery_succeeded",
                    AuditOutcome::Success,
                    serde_json::json!({
                        "delivery_id": msg.delivery_id,
                        "attempt": msg.attempt + 1,
                        "status": status.as_u16(),
                    }),
                );
                if let Err(e) = audit_repo.append(entry).await {
                    error!(error = %e, "Failed to write webhook.delivery_succeeded audit event");
                }
                if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
                    error!(error = %e, delivery_tag = tag, "Failed to ack webhook delivery");
                }
            }
            Ok(status) => {
                handle_delivery_failure(
                    &msg,
                    &publisher,
                    &audit_repo,
                    &cfg,
                    format!("non-2xx status: {}", status.as_u16()),
                    tag,
                    &delivery.acker,
                )
                .await;
            }
            Err(e) => {
                handle_delivery_failure(
                    &msg,
                    &publisher,
                    &audit_repo,
                    &cfg,
                    e.to_string(),
                    tag,
                    &delivery.acker,
                )
                .await;
            }
        }
    }

    warn!("Webhook AMQP consumer stream ended");
}

/// Shared failure-path handling for both a non-2xx delivery response and a
/// `WebhookError` (SSRF-blocked, secret-decrypt failure, lookup failure,
/// etc.) — both are "this attempt did not succeed" and follow the same
/// retry-or-exhaust decision (D-07/D-09).
async fn handle_delivery_failure<A>(
    msg: &WebhookMessage,
    publisher: &WebhookPublisher,
    audit_repo: &A,
    cfg: &WebhookRetryConfig,
    error_detail: String,
    delivery_tag: DeliveryTag,
    acker: &Acker,
) where
    A: AuditLogRepository + 'static,
{
    let next_attempt = msg.attempt + 1;

    if next_attempt < cfg.max_attempts {
        let ttl_ms = backoff_ttl_ms(next_attempt, cfg);
        let mut retry_msg = msg.clone();
        retry_msg.attempt = next_attempt;

        // CQ-B49: if the retry copy fails to enqueue, the original message must
        // NOT be acked — acking it would drop the delivery entirely (no retry,
        // no DLQ) while the audit trail falsely claims a retry was scheduled.
        // Nack with requeue so the broker redelivers the original for another
        // attempt, and skip the "retry scheduled" audit record.
        if let Err(e) = publisher.publish_retry(&retry_msg, ttl_ms).await {
            error!(
                error = %e,
                webhook_id = %msg.webhook_id,
                delivery_id = %msg.delivery_id,
                delivery_tag,
                "Failed to publish webhook retry — requeuing original instead of acking"
            );
            if let Err(nack_err) = acker
                .nack(BasicNackOptions {
                    requeue: true,
                    ..BasicNackOptions::default()
                })
                .await
            {
                error!(
                    error = %nack_err,
                    delivery_tag,
                    "Failed to nack original webhook delivery after retry-publish failure"
                );
            }
            return;
        }

        let entry = build_audit_entry(
            msg.tenant_id,
            msg.webhook_id,
            "webhook.delivery_attempt",
            AuditOutcome::Failure,
            serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempt": next_attempt,
                "error": error_detail,
                "next_retry_in_ms": ttl_ms,
            }),
        );
        if let Err(e) = audit_repo.append(entry).await {
            error!(error = %e, "Failed to write webhook.delivery_attempt audit event");
        }

        // Ack the ORIGINAL message — the retry copy has been queued onto
        // WEBHOOK_RETRY and will re-enter WEBHOOK via TTL+DLX (D-07).
        if let Err(e) = acker.ack(BasicAckOptions::default()).await {
            error!(error = %e, delivery_tag, "Failed to ack original webhook delivery");
        }
    } else {
        warn!(
            webhook_id = %msg.webhook_id,
            delivery_id = %msg.delivery_id,
            attempt = next_attempt,
            max_attempts = cfg.max_attempts,
            error = %error_detail,
            "Webhook delivery exhausted retries — dead-lettering"
        );

        let entry = build_audit_entry(
            msg.tenant_id,
            msg.webhook_id,
            "webhook.delivery_failed",
            AuditOutcome::Failure,
            serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempt": next_attempt,
                "error": error_detail,
                "next_retry_in_ms": null,
            }),
        );
        if let Err(e) = audit_repo.append(entry).await {
            error!(error = %e, "Failed to write webhook.delivery_failed audit event");
        }

        // Terminal exhaustion -> nack requeue:false -> WEBHOOK's own DLX ->
        // WEBHOOK_DLQ (replayable, per 26-03's topology).
        let _ = acker
            .nack(BasicNackOptions {
                requeue: false,
                ..BasicNackOptions::default()
            })
            .await;
    }
}

// ---------------------------------------------------------------------------
// Tests: retry config + bounded exponential backoff (D-08/D-20)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod webhook_consumer_tests {
    use super::*;

    #[test]
    fn backoff_ttl_ms_nonzero_at_attempt_1() {
        let cfg = WebhookRetryConfig::default();
        assert!(
            backoff_ttl_ms(1, &cfg) > 0,
            "first retry TTL must not be zero-delay"
        );
    }

    #[test]
    fn backoff_ttl_ms_increases_until_ceiling() {
        let cfg = WebhookRetryConfig::default();
        let first = backoff_ttl_ms(1, &cfg);
        let second = backoff_ttl_ms(2, &cfg);
        let third = backoff_ttl_ms(3, &cfg);
        assert!(second > first, "backoff must increase between attempts");
        assert!(third > second, "backoff must increase between attempts");
    }

    #[test]
    fn backoff_ttl_ms_clamped_to_ceiling() {
        let cfg = WebhookRetryConfig::default();
        let delay = backoff_ttl_ms(1_000, &cfg);
        assert!(
            delay <= cfg.backoff_ceiling_ms,
            "backoff TTL must never exceed the ceiling, got {delay}"
        );
    }

    #[test]
    fn backoff_ttl_ms_never_negative_defensively() {
        let cfg = WebhookRetryConfig::default();
        // attempt = 0 is defensive (the retry branch always passes attempt >= 1).
        let delay = backoff_ttl_ms(0, &cfg);
        // u64 cannot be negative; assert it is well-formed (no panic/overflow).
        assert!(delay <= cfg.backoff_ceiling_ms);
    }

    /// Direct unit test for the private `build_audit_entry` helper (D-09):
    /// proves the system-actor convention (`Uuid::nil()` + `ActorType::System`)
    /// and that every field passed through is threaded into the resulting
    /// `CreateAuditLogEntry` unchanged. This is the only part of the
    /// AMQP-consumer module reachable without a live RabbitMQ broker — the
    /// surrounding `start_webhook_consumer`/`handle_delivery_failure` drive a
    /// real `lapin::Channel`/`Acker`/`WebhookPublisher` (concrete types wired
    /// to an actual broker connection, not trait objects), so they cannot be
    /// exercised here; the crate's own `#[ignore]`d
    /// `webhook_consumer_retries_then_dlqs_and_audits_end_to_end` integration
    /// test (run via `just dev-up`) is the intended coverage path for those.
    #[test]
    fn build_audit_entry_builds_expected_entry() {
        let tenant_id = Uuid::new_v4();
        let webhook_id = Uuid::new_v4();
        let metadata = serde_json::json!({"delivery_id": "abc", "attempt": 2});

        let entry = build_audit_entry(
            tenant_id,
            webhook_id,
            "webhook.delivery_attempt",
            AuditOutcome::Failure,
            metadata.clone(),
        );

        assert_eq!(entry.tenant_id, tenant_id);
        assert_eq!(
            entry.actor_id,
            Uuid::nil(),
            "webhook delivery is system-initiated, never attributed to a real actor"
        );
        assert!(matches!(entry.actor_type, ActorType::System));
        assert_eq!(entry.action, "webhook.delivery_attempt");
        assert_eq!(entry.resource_id, Some(webhook_id));
        assert!(matches!(entry.outcome, AuditOutcome::Failure));
        assert!(
            entry.ip_address.is_none(),
            "webhook delivery has no client IP to attribute"
        );
        assert_eq!(entry.metadata, Some(metadata));
    }

    #[test]
    fn webhook_retry_config_defaults_resolve_when_env_unset() {
        // AXIAM__WEBHOOK__* is unique to this module — no other test in this
        // crate reads or writes these vars, so removing them here cannot
        // race with unrelated tests running in parallel in the same binary.
        unsafe {
            std::env::remove_var("AXIAM__WEBHOOK__MAX_ATTEMPTS");
            std::env::remove_var("AXIAM__WEBHOOK__BACKOFF_BASE_MS");
            std::env::remove_var("AXIAM__WEBHOOK__BACKOFF_CEILING_MS");
        }
        let cfg = WebhookRetryConfig::from_env();
        let defaults = WebhookRetryConfig::default();
        assert_eq!(cfg, defaults);
    }
}

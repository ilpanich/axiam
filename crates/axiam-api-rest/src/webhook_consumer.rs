//! Webhook AMQP consumer: the webhook kind of the shared outbound dispatcher
//! (CORR-03/D-06, generalised by D-36/T23.5.1).
//!
//! The consume loop, the TTL + DLX retry scheduling (D-07/D-08), the retry
//! policy and the per-attempt/terminal audit records (D-09) are now the
//! kind-generic machinery in `axiam_amqp::outbound`. What stays here is what is
//! webhook-specific:
//!
//! * the deliverer: `WebhookDeliveryService` implements
//!   `axiam_core::outbound::OutboundDeliverer` (see `webhook.rs`), keeping the
//!   SSRF guard (SEC-019/SECHRD-02) and secret decryption (SEC-031) in this
//!   crate, which `axiam-amqp` cannot depend on without a cycle;
//! * [`start_webhook_consumer`]: registers that deliverer for
//!   `OutboundKind::Webhook` and runs the generic loop. `axiam-server` does the
//!   same registration itself; this wrapper keeps the pre-extraction entry
//!   point for callers and tests that already use it.
//!
//! [`WebhookRetryConfig`] and [`backoff_ttl_ms`] are the generic
//! `OutboundRetryConfig` / `backoff_ttl_ms`, re-exported under their original
//! names; the webhook kind reads `AXIAM__WEBHOOK__MAX_ATTEMPTS`,
//! `AXIAM__WEBHOOK__BACKOFF_BASE_MS` and `AXIAM__WEBHOOK__BACKOFF_CEILING_MS`
//! exactly as before, via
//! `OutboundRetryConfig::from_env_for(OutboundKind::Webhook)`.

use std::sync::Arc;

use axiam_amqp::WebhookPublisher;
use axiam_amqp::outbound::{OutboundDeliverers, run_outbound_consumer};
use axiam_core::outbound::OutboundKind;
use axiam_core::repository::{AuditLogRepository, WebhookRepository};
use lapin::Channel;
use tracing::error;

use crate::webhook::WebhookDeliveryService;

pub use axiam_amqp::outbound::{OutboundRetryConfig as WebhookRetryConfig, backoff_ttl_ms};

/// Start consuming webhook deliveries from `axiam.webhook` (D-06).
///
/// Registers `delivery_service` as the webhook [`OutboundDeliverer`] and runs
/// `axiam_amqp::outbound::run_outbound_consumer` for `OutboundKind::Webhook`.
/// Per message (see that function for the full table): a 2xx is acked and
/// audited `webhook.delivery_succeeded`; a non-2xx or `WebhookError` with
/// attempts left is republished to `axiam.webhook.retry` with TTL
/// `backoff_ttl_ms(attempt + 1, cfg)` and audited `webhook.delivery_attempt`;
/// on exhaustion it is nacked `requeue:false` to `axiam.webhook.dlq` and audited
/// `webhook.delivery_failed`; a malformed payload is nacked `requeue:false`.
///
/// Returns when the delivery stream ends or the consume fails (logged); the
/// caller supervises and reconnects.
///
/// [`OutboundDeliverer`]: axiam_core::outbound::OutboundDeliverer
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
    let mut deliverers = OutboundDeliverers::new();
    if let Err(e) = deliverers.register(Arc::new(delivery_service)) {
        error!(error = %e, "Failed to register the webhook deliverer");
        return;
    }
    if let Err(e) = run_outbound_consumer(
        channel,
        OutboundKind::Webhook,
        &deliverers,
        publisher.as_outbound(),
        &audit_repo,
        cfg,
    )
    .await
    {
        error!(error = %e, "Webhook AMQP consumer failed");
    }
}

// ---------------------------------------------------------------------------
// Tests: retry config + bounded exponential backoff (D-08/D-20). The loop's
// own behaviour (ack, retry TTL, dead-letter, error mapping) is tested in
// `axiam_amqp::outbound::consumer`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod webhook_consumer_tests {
    use super::*;
    use axiam_amqp::outbound::OutboundRetryConfig;
    use axiam_core::outbound::OutboundKind;

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
        let cfg = OutboundRetryConfig::from_env_for(OutboundKind::Webhook);
        let defaults = WebhookRetryConfig::default();
        assert_eq!(cfg, defaults);
    }
}

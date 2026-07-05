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

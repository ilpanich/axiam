//! The bounded exponential retry policy, generic over kind.
//!
//! The policy is the one webhooks already had (D-08/D-20), now parameterised
//! by the env-var prefix: `AXIAM__<SLUG>__MAX_ATTEMPTS`,
//! `AXIAM__<SLUG>__BACKOFF_BASE_MS`, `AXIAM__<SLUG>__BACKOFF_CEILING_MS`. For
//! [`OutboundKind::Webhook`] those are exactly the three
//! `AXIAM__WEBHOOK__*` variables operators already set.

use axiam_core::outbound::OutboundKind;

/// Default maximum delivery attempts before a delivery is dead-lettered.
const DEFAULT_MAX_ATTEMPTS: u32 = 5;

/// Default base backoff (milliseconds) applied to the first retry.
const DEFAULT_BACKOFF_BASE_MS: u64 = 5_000; // 5s

/// Default backoff ceiling (milliseconds); no single retry TTL exceeds this.
const DEFAULT_BACKOFF_CEILING_MS: u64 = 3_600_000; // 1h

/// Exponential backoff multiplier applied per subsequent retry attempt.
const BACKOFF_MULTIPLIER: f64 = 2.0;

/// Retry policy for one outbound kind. Every field has a safe default and is
/// fully overridable; nothing is mandatory for the server to boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboundRetryConfig {
    /// Maximum number of delivery attempts (the first attempt counts as 1)
    /// before a delivery is dead-lettered.
    pub max_attempts: u32,
    /// Base backoff (milliseconds) used for the first retry.
    pub backoff_base_ms: u64,
    /// Upper bound (milliseconds) any single retry TTL can reach.
    pub backoff_ceiling_ms: u64,
}

impl Default for OutboundRetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            backoff_base_ms: DEFAULT_BACKOFF_BASE_MS,
            backoff_ceiling_ms: DEFAULT_BACKOFF_CEILING_MS,
        }
    }
}

/// The environment variable `suffix` (`MAX_ATTEMPTS`, `BACKOFF_BASE_MS`,
/// `BACKOFF_CEILING_MS`) is read from for `kind`: `AXIAM__<SLUG>__<suffix>`.
pub fn env_var_name(kind: OutboundKind, suffix: &str) -> String {
    format!("AXIAM__{}__{suffix}", kind.as_str().to_ascii_uppercase())
}

impl OutboundRetryConfig {
    /// Read `kind`'s three variables from the process environment, falling back
    /// to the default for any that is unset or does not parse (the existing
    /// `AXIAM__SECTION__KEY` precedent).
    pub fn from_env_for(kind: OutboundKind) -> Self {
        Self::from_lookup(kind, |name| std::env::var(name).ok())
    }

    /// As [`Self::from_env_for`], with the variable source injected so tests do
    /// not have to mutate the process environment.
    pub fn from_lookup(kind: OutboundKind, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let defaults = Self::default();
        let read = |suffix: &str| lookup(&env_var_name(kind, suffix));
        Self {
            max_attempts: read("MAX_ATTEMPTS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.max_attempts),
            backoff_base_ms: read("BACKOFF_BASE_MS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.backoff_base_ms),
            backoff_ceiling_ms: read("BACKOFF_CEILING_MS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(defaults.backoff_ceiling_ms),
        }
    }
}

/// Bounded exponential backoff (D-08): `base_ms * 2^(attempt-1)`, clamped to
/// `[0, ceiling_ms]`. The result becomes the retry queue's per-message TTL, not
/// an in-process sleep, so no consumer slot is held for its duration.
///
/// `attempt` is the *post-increment* attempt number about to be published
/// (`1` for the first retry, `2` for the second, ...).
pub fn backoff_ttl_ms(attempt: u32, cfg: &OutboundRetryConfig) -> u64 {
    let exponent = attempt.saturating_sub(1) as i32;
    let delay_ms = cfg.backoff_base_ms as f64 * BACKOFF_MULTIPLIER.powi(exponent);
    let ceiling_ms = cfg.backoff_ceiling_ms as f64;
    delay_ms.clamp(0.0, ceiling_ms) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn webhook_env_var_names_are_pinned() {
        assert_eq!(
            env_var_name(OutboundKind::Webhook, "MAX_ATTEMPTS"),
            "AXIAM__WEBHOOK__MAX_ATTEMPTS"
        );
        assert_eq!(
            env_var_name(OutboundKind::Webhook, "BACKOFF_BASE_MS"),
            "AXIAM__WEBHOOK__BACKOFF_BASE_MS"
        );
        assert_eq!(
            env_var_name(OutboundKind::Webhook, "BACKOFF_CEILING_MS"),
            "AXIAM__WEBHOOK__BACKOFF_CEILING_MS"
        );
    }

    #[test]
    fn defaults_are_unchanged() {
        let d = OutboundRetryConfig::default();
        assert_eq!(d.max_attempts, 5);
        assert_eq!(d.backoff_base_ms, 5_000);
        assert_eq!(d.backoff_ceiling_ms, 3_600_000);
    }

    #[test]
    fn unset_variables_resolve_to_defaults() {
        let cfg = OutboundRetryConfig::from_lookup(OutboundKind::Webhook, |_| None);
        assert_eq!(cfg, OutboundRetryConfig::default());
    }

    #[test]
    fn set_variables_override_and_garbage_falls_back() {
        let vars: HashMap<&str, &str> = HashMap::from([
            ("AXIAM__WEBHOOK__MAX_ATTEMPTS", "9"),
            ("AXIAM__WEBHOOK__BACKOFF_BASE_MS", "250"),
            ("AXIAM__WEBHOOK__BACKOFF_CEILING_MS", "not-a-number"),
        ]);
        let cfg = OutboundRetryConfig::from_lookup(OutboundKind::Webhook, |n| {
            vars.get(n).map(|v| v.to_string())
        });
        assert_eq!(cfg.max_attempts, 9);
        assert_eq!(cfg.backoff_base_ms, 250);
        assert_eq!(cfg.backoff_ceiling_ms, 3_600_000);
    }

    #[test]
    fn backoff_doubles_and_clamps() {
        let cfg = OutboundRetryConfig {
            max_attempts: 5,
            backoff_base_ms: 100,
            backoff_ceiling_ms: 500,
        };
        assert_eq!(backoff_ttl_ms(1, &cfg), 100);
        assert_eq!(backoff_ttl_ms(2, &cfg), 200);
        assert_eq!(backoff_ttl_ms(3, &cfg), 400);
        assert_eq!(backoff_ttl_ms(4, &cfg), 500);
        assert_eq!(backoff_ttl_ms(1_000, &cfg), 500);
        assert_eq!(backoff_ttl_ms(0, &cfg), 100, "attempt 0 is defensive");
    }
}

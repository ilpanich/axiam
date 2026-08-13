//! FIDO MDS3 background refresh job (X3 wave 3, D10) — pure decision/jitter
//! helpers factored out of `main.rs`.
//!
//! `main.rs` is a binary entry point and cannot be linked from `tests/`
//! (Rust integration tests only link a package's *library* crate), so the
//! one piece of this job's logic worth asserting in a test — "is the
//! disabled-by-default posture actually disabled" (the wave spec's "Default
//! is disabled ⇒ zero outbound calls" requirement) — is pulled out here as a
//! pure function `main.rs` calls as its single spawn gate. See this module's
//! tests for the assertion.

use axiam_pki::PkiConfig;

/// Whether the weekly background refresh job should be spawned at all.
///
/// `mds_enabled: false` is [`PkiConfig::default`]'s shipped value — "off
/// means zero outbound calls" (D10) — so this returns `false` whenever the
/// master switch is off, AND whenever the refresh interval is `0` (D10:
/// "`0` disables the background job", while leaving the admin-triggered
/// `POST /api/v1/mds/refresh` endpoint working). `main.rs`'s `tokio::spawn`
/// for this job is gated on this function and nothing else, so a default
/// (unconfigured) deployment makes zero outbound MDS calls — see
/// `disabled_by_default_never_spawns` below.
pub fn should_spawn_refresh_job(cfg: &PkiConfig) -> bool {
    cfg.mds_enabled && cfg.mds_refresh_interval_secs > 0
}

/// Compute the startup jitter (seconds) for the job's first fire, so
/// replicas that start at the same instant do not all hit the MDS BLOB
/// source in the same second (D10: "jittered"). Bounded to 10% of the
/// refresh interval, capped at one hour, and clamped to at least 1 second so
/// the modulus below is never a divide-by-zero.
///
/// `entropy` is injected so this stays a pure, deterministically-testable
/// function — the production caller passes `Uuid::new_v4().as_u128()`
/// (`uuid` is already a dependency of this binary; no new crate needed for
/// randomness).
pub fn jitter_secs(interval_secs: u64, entropy: u128) -> u64 {
    let cap = interval_secs.saturating_div(10).clamp(1, 3600);
    (entropy % cap as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mds_enabled: bool, interval: u64) -> PkiConfig {
        PkiConfig {
            mds_enabled,
            mds_refresh_interval_secs: interval,
            ..Default::default()
        }
    }

    #[test]
    fn disabled_by_default_never_spawns() {
        // The exact posture the wave spec requires: PkiConfig::default()
        // (what an unconfigured deployment gets) must gate the background
        // job off, so main.rs makes zero outbound MDS calls out of the box.
        assert!(!should_spawn_refresh_job(&PkiConfig::default()));
    }

    #[test]
    fn enabled_with_positive_interval_spawns() {
        assert!(should_spawn_refresh_job(&cfg(true, 604_800)));
    }

    #[test]
    fn enabled_with_zero_interval_does_not_spawn() {
        // D10: "0 disables the background job" even with the master switch on.
        assert!(!should_spawn_refresh_job(&cfg(true, 0)));
    }

    #[test]
    fn disabled_with_positive_interval_does_not_spawn() {
        assert!(!should_spawn_refresh_job(&cfg(false, 604_800)));
    }

    #[test]
    fn jitter_is_bounded_by_the_one_hour_cap() {
        for entropy in [0u128, 1, 999_999, u128::MAX] {
            let j = jitter_secs(604_800, entropy);
            assert!(j < 3600, "jitter must stay within the 1h cap, got {j}");
        }
    }

    #[test]
    fn jitter_cap_clamps_to_at_least_one_second() {
        // A pathologically small interval (only realistic in a test) must
        // not divide-by-zero or produce an empty modulus range.
        let j = jitter_secs(1, 42);
        assert_eq!(j, 0, "cap clamps to 1, so entropy % 1 == 0");
    }

    #[test]
    fn jitter_is_a_pure_function_of_its_inputs() {
        assert_eq!(jitter_secs(604_800, 12345), jitter_secs(604_800, 12345));
    }
}

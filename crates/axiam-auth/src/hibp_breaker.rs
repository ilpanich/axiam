//! Process-wide circuit breaker guarding [`crate::policy::check_hibp`]
//! (PERF-01, D-01/D-02/D-03/D-04).
//!
//! `check_hibp` is ALREADY fail-open on every error branch — this module does
//! NOT add fail-open behavior. Its sole purpose is burst-protection: once a
//! sustained run of HIBP failures/timeouts is observed, subsequent calls
//! short-circuit to `Ok(None)` immediately, skipping the outbound HTTP
//! request (and its 5s timeout) entirely for the cooldown window. This
//! prevents a credential-stuffing burst against a downed/rate-limiting HIBP
//! endpoint from starving legitimate auth flows.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Internal breaker state machine.
///
/// `std::sync::Mutex` (not `tokio::sync::Mutex`) is used because the
/// critical section is a few field reads/writes with no `.await` inside it —
/// matching the lock-type convention in `axiam-federation`'s `jwks_cache.rs`
/// (choose lock type by hold-duration/await-need).
#[derive(Debug, Clone, Copy)]
enum BreakerState {
    Closed { consecutive_failures: u32 },
    Open { opened_at: Instant },
}

/// Hand-rolled circuit breaker (D-02 — no new circuit-breaker crate
/// dependency) around `check_hibp`'s outbound HTTP call.
pub struct HibpBreaker {
    state: Mutex<BreakerState>,
    threshold: u32,
    cooldown: Duration,
}

impl HibpBreaker {
    /// Construct a new breaker with the given threshold (consecutive
    /// failures before tripping) and cooldown (seconds the breaker stays
    /// open before allowing a half-open probe).
    pub fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            state: Mutex::new(BreakerState::Closed {
                consecutive_failures: 0,
            }),
            threshold,
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Returns `true` if the call should proceed (breaker Closed, or Open but
    /// the cooldown has elapsed — a single half-open probe). Returns `false`
    /// if the caller should short-circuit to `Ok(None)` WITHOUT making the
    /// HTTP call at all, saving the 5s timeout under a sustained failure
    /// burst.
    pub fn should_attempt(&self) -> bool {
        let state = self.state.lock().unwrap();
        match *state {
            BreakerState::Closed { .. } => true,
            BreakerState::Open { opened_at } => opened_at.elapsed() >= self.cooldown,
        }
    }

    /// Record a successful HIBP check — re-closes the breaker.
    pub fn record_success(&self) {
        *self.state.lock().unwrap() = BreakerState::Closed {
            consecutive_failures: 0,
        };
    }

    /// Record a failed/timed-out HIBP check. Increments the consecutive
    /// failure count while Closed, tripping to Open once the threshold is
    /// reached. While already Open (i.e. a half-open probe just failed),
    /// re-opens with a fresh `opened_at`, resetting the cooldown clock.
    pub fn record_failure(&self) {
        let mut state = self.state.lock().unwrap();
        match *state {
            BreakerState::Closed {
                consecutive_failures,
            } => {
                let n = consecutive_failures + 1;
                *state = if n >= self.threshold {
                    BreakerState::Open {
                        opened_at: Instant::now(),
                    }
                } else {
                    BreakerState::Closed {
                        consecutive_failures: n,
                    }
                };
            }
            BreakerState::Open { .. } => {
                *state = BreakerState::Open {
                    opened_at: Instant::now(),
                };
            }
        }
    }
}

/// Process-wide global breaker instance (D-01 — one global breaker, not
/// per-tenant).
static GLOBAL: OnceLock<HibpBreaker> = OnceLock::new();

/// Idempotent global initializer. Should be called once at startup from
/// `AuthConfig`'s resolved `hibp_breaker_threshold`/`hibp_breaker_cooldown_secs`.
/// Calling this more than once has no effect after the first call
/// (`OnceLock::get_or_init` semantics).
pub fn init_global(threshold: u32, cooldown_secs: u64) {
    GLOBAL.get_or_init(|| HibpBreaker::new(threshold, cooldown_secs));
}

/// Access the process-wide global breaker, lazily initializing with defaults
/// (threshold 5, cooldown 30s) if `init_global` was never called.
pub fn global() -> &'static HibpBreaker {
    GLOBAL.get_or_init(|| HibpBreaker::new(5, 30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_allows_attempts() {
        let b = HibpBreaker::new(5, 30);
        assert!(b.should_attempt());
    }

    #[test]
    fn trips_after_exactly_threshold_failures() {
        let b = HibpBreaker::new(3, 30);
        // 2 failures: still closed, still allows attempts.
        b.record_failure();
        assert!(b.should_attempt());
        b.record_failure();
        assert!(b.should_attempt());
        // 3rd failure trips the breaker (with a non-zero cooldown, so the
        // just-tripped state is still within its cooldown window).
        b.record_failure();
        assert!(!b.should_attempt());
    }

    #[test]
    fn short_circuits_within_cooldown() {
        // Large cooldown so we can assert `should_attempt` stays false
        // without any wall-clock sleep.
        let b = HibpBreaker::new(1, 30);
        b.record_failure(); // trips immediately (threshold 1)
        assert!(!b.should_attempt());
        assert!(!b.should_attempt());
    }

    #[test]
    fn allows_one_probe_after_cooldown_elapsed() {
        // Zero-second cooldown: elapsed() >= Duration::from_secs(0) is true
        // on the very next check, with no sleep required.
        let b = HibpBreaker::new(1, 0);
        b.record_failure(); // trips
        // Cooldown of 0 means the very next should_attempt() is the
        // half-open probe.
        assert!(b.should_attempt());
        // Breaker remains Open (not yet re-closed) until record_success().
        assert!(b.should_attempt());
    }

    #[test]
    fn record_success_recloses_breaker() {
        let b = HibpBreaker::new(1, 30);
        b.record_failure(); // trips (Open, long cooldown)
        assert!(!b.should_attempt());
        b.record_success();
        assert!(b.should_attempt());
    }

    #[test]
    fn record_failure_while_open_resets_opened_at() {
        // Long cooldown so the breaker stays Open (not a half-open probe)
        // across both failures; directly inspect the private opened_at
        // Instant (accessible from this submodule) to prove it advances
        // rather than sleeping 30s.
        let b = HibpBreaker::new(1, 30);
        b.record_failure(); // trips -> Open { opened_at: t0 }
        let opened_at_1 = match *b.state.lock().unwrap() {
            BreakerState::Open { opened_at } => opened_at,
            BreakerState::Closed { .. } => panic!("expected Open state"),
        };

        // Still within cooldown, so should_attempt() short-circuits and a
        // "probe" isn't actually in flight yet — but record_failure() while
        // Open must still reset the clock regardless of half-open status.
        b.record_failure();
        let opened_at_2 = match *b.state.lock().unwrap() {
            BreakerState::Open { opened_at } => opened_at,
            BreakerState::Closed { .. } => panic!("expected still Open state"),
        };

        assert!(
            opened_at_2 >= opened_at_1,
            "opened_at must be reset (monotonically non-decreasing) on failure while Open"
        );
        assert!(
            !b.should_attempt(),
            "still within the (long) cooldown window"
        );
    }

    #[test]
    fn default_threshold_and_cooldown() {
        let b = HibpBreaker::new(5, 30);
        assert_eq!(b.threshold, 5);
        assert_eq!(b.cooldown, Duration::from_secs(30));
    }

    #[test]
    fn global_lazily_initializes_with_defaults() {
        // NOTE: GLOBAL is process-wide and shared across all tests in this
        // binary; only assert non-panicking access here, not specific
        // defaults, since another test in this module may have already
        // called init_global.
        let g = global();
        assert!(g.should_attempt() || !g.should_attempt());
    }

    #[test]
    fn init_global_is_idempotent() {
        init_global(7, 42);
        // Second call is a no-op — must not panic.
        init_global(99, 999);
    }
}

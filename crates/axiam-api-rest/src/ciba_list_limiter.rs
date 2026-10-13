//! The CIBA pending list's in-process limiter (R101W3-04).
//!
//! `GET /api/v1/ciba/requests` is limited per signed-in user, not per address
//! (D-4, #599): thirty console tabs behind one egress address must not silence
//! each other's badges. The principal exists only once the handler's extractor
//! has authenticated the token, so the bucket cannot be route middleware; the
//! handler spends `ciba_approval_list:{tenant}:{user}` from the shared counter.
//!
//! That counter admits everything when it is switched off
//! (`AXIAM__RATE_LIMIT__SHARED=off`). The route then had no limiter at all, so
//! the handler falls back to this one: a keyed `governor` limiter held in
//! `AppState`, one cell per `(tenant, user)`, with the same allowance
//! (`ciba_approval_per_min`, burst = per-minute rate, as `build_governor`
//! sizes the neighbouring routes) and the same `429`. It is per process, as
//! every in-process limiter is; the shared counter is what makes the limit hold
//! across replicas when it is on.
//!
//! # Memory
//!
//! A key reaches this limiter only after the bearer token has authenticated as
//! a console sign-in of that user, so the map is bounded by the number of users
//! who list in a window, never by what a caller can invent. It is still swept:
//! [`CibaListLimiter::check`] drops every cell that has fully replenished
//! (`retain_recent`) and returns the freed capacity (`shrink_to_fit`) at most
//! once a minute, which is the time a cell takes to replenish.

use std::num::NonZeroU32;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use uuid::Uuid;

/// How often a call may sweep replenished cells out of the map.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// A keyed `(tenant, user)` limiter, built on first use from the allowance the
/// handler passes (so a state whose configuration is set after construction,
/// as the tests' is, is honoured).
#[derive(Debug, Default)]
pub struct CibaListLimiter {
    limiter: OnceLock<DefaultKeyedRateLimiter<(Uuid, Uuid)>>,
    last_sweep: Mutex<Option<Instant>>,
}

impl CibaListLimiter {
    /// Spend one call of `(tenant_id, user_id)`'s `per_min` allowance; `false`
    /// means it is spent and the caller answers `429`.
    ///
    /// The allowance is fixed by the first call; it is configuration, read once
    /// at boot, and a limiter that rebuilt itself on a change would forget
    /// every spent call.
    pub fn check(&self, tenant_id: Uuid, user_id: Uuid, per_min: u32) -> bool {
        let limiter = self.limiter.get_or_init(|| {
            let rate = NonZeroU32::new(per_min).unwrap_or(NonZeroU32::MIN);
            RateLimiter::keyed(Quota::per_minute(rate))
        });
        self.sweep(limiter);
        limiter.check_key(&(tenant_id, user_id)).is_ok()
    }

    /// Number of `(tenant, user)` cells currently held (for tests and metrics).
    pub fn len(&self) -> usize {
        self.limiter.get().map_or(0, |l| l.len())
    }

    /// Whether no cell is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop replenished cells, at most once per [`SWEEP_EVERY`].
    fn sweep(&self, limiter: &DefaultKeyedRateLimiter<(Uuid, Uuid)>) {
        // Never block a request on the sweep: a caller that finds it held
        // simply skips, the holder is doing the work.
        let Ok(mut last) = self.last_sweep.try_lock() else {
            return;
        };
        let now = Instant::now();
        match *last {
            None => *last = Some(now),
            Some(at) if now.duration_since(at) >= SWEEP_EVERY => {
                *last = Some(now);
                limiter.retain_recent();
                limiter.shrink_to_fit();
            }
            Some(_) => {}
        }
    }

    /// Test hook: sweep now, whatever the clock says.
    #[doc(hidden)]
    pub fn sweep_now(&self) {
        if let Some(limiter) = self.limiter.get() {
            limiter.retain_recent();
            limiter.shrink_to_fit();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_user_is_refused_after_the_allowance_and_another_is_not() {
        let l = CibaListLimiter::default();
        let (t, a, b) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert!(l.check(t, a, 2));
        assert!(l.check(t, a, 2));
        assert!(!l.check(t, a, 2));
        assert!(l.check(t, b, 2), "a second user has a cell of their own");
        // The same user id in another tenant is another key.
        assert!(l.check(Uuid::new_v4(), a, 2));
        assert_eq!(l.len(), 3);
    }

    #[test]
    fn replenished_cells_are_swept() {
        let l = CibaListLimiter::default();
        // 6000 a minute replenishes a cell in 10 ms.
        for _ in 0..50 {
            assert!(l.check(Uuid::new_v4(), Uuid::new_v4(), 6000));
        }
        assert_eq!(l.len(), 50);
        std::thread::sleep(Duration::from_millis(50));
        l.sweep_now();
        assert_eq!(l.len(), 0, "a replenished cell is not kept");
    }
}

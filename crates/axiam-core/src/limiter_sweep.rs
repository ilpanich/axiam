//! The registry of in-process rate-limiter maps that need sweeping (#673,
//! R110W2-05).
//!
//! A keyed `governor` limiter keeps one cell per key it has seen, and neither
//! `actix-governor` nor `tower_governor` ever evicts one. The key is an
//! address (which an IPv6 sender rotates at will) or, on the five federation
//! routes, a verified principal, so every map grows with the number of distinct
//! keys seen since start. A cell replenishes within a minute, after which it
//! carries no information a fresh cell would not.
//!
//! Each limiter's owner registers one closure here when it builds the limiter;
//! one interval task calls [`sweep_all`]. The REST and gRPC crates are siblings
//! that may not depend on each other, so the registry lives below both, and it
//! holds closures rather than limiters so that this crate needs no `governor`.
//!
//! A closure holds its limiter by `Weak`, so the registry never keeps a map
//! alive: when the server (or a test's app) that built it is dropped, the
//! closure reports itself dead and the next sweep forgets it.

use std::sync::Mutex;

/// What one registered sweeper reports after it ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepOutcome {
    /// The limiter is gone; forget this sweeper.
    Dropped,
    /// The limiter was swept and holds this many cells afterwards.
    Swept {
        /// Cells that remain in the map.
        remaining: usize,
    },
}

/// What a [`sweep_all`] pass found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Limiters still alive.
    pub limiters: usize,
    /// Cells still held across all of them.
    pub cells: usize,
}

type Sweeper = Box<dyn Fn() -> SweepOutcome + Send + Sync>;

static REGISTRY: Mutex<Vec<Sweeper>> = Mutex::new(Vec::new());

fn registry() -> std::sync::MutexGuard<'static, Vec<Sweeper>> {
    // A sweeper that panicked poisons nothing worth refusing the rest for.
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register one limiter's sweeper. The closure must hold the limiter weakly and
/// return [`SweepOutcome::Dropped`] once it can no longer be upgraded.
pub fn register(sweeper: impl Fn() -> SweepOutcome + Send + Sync + 'static) {
    registry().push(Box::new(sweeper));
}

/// Sweep every registered limiter once and forget the dead ones.
pub fn sweep_all() -> SweepReport {
    let mut report = SweepReport::default();
    registry().retain(|sweep| match sweep() {
        SweepOutcome::Dropped => false,
        SweepOutcome::Swept { remaining } => {
            report.limiters += 1;
            report.cells += remaining;
            true
        }
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Weak};

    #[test]
    fn a_dead_sweeper_is_forgotten_and_a_live_one_is_counted() {
        let live = Arc::new(7usize);
        let dead = Arc::new(3usize);
        for owner in [&live, &dead] {
            let weak: Weak<usize> = Arc::downgrade(owner);
            register(move || match weak.upgrade() {
                Some(n) => SweepOutcome::Swept { remaining: *n },
                None => SweepOutcome::Dropped,
            });
        }
        drop(dead);
        let first = sweep_all();
        assert!(first.cells >= 7 && first.limiters >= 1);
        // The dead one is gone: a second pass reports the same figures.
        assert_eq!(sweep_all(), first);
    }
}

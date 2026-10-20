//! The interval task that sweeps the in-process rate-limiter maps (#673).
//!
//! Every governor of the REST and gRPC crates registers its map with
//! `axiam_core::limiter_sweep` when it is built; this task calls the sweep once
//! a minute, the time a cell takes to replenish. It stops with the cleanup
//! task's shutdown signal, so it ends with the server.

use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// How often the maps are swept: one replenish period of the slowest quota.
pub const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// Spawn the sweep; it returns when `shutdown` turns `true` (or is dropped).
pub fn spawn(mut shutdown: watch::Receiver<bool>, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tick.tick().await; // the first tick is immediate; nothing to sweep yet
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let report = axiam_core::limiter_sweep::sweep_all();
                    tracing::debug!(
                        limiters = report.limiters,
                        cells = report.cells,
                        "in-process rate-limiter maps swept"
                    );
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn the_task_sweeps_on_its_interval_and_stops_on_shutdown() {
        let (tx, rx) = watch::channel(false);
        let handle = spawn(rx, Duration::from_secs(60));
        tokio::time::sleep(Duration::from_secs(130)).await;
        assert!(!handle.is_finished());
        tx.send_replace(true);
        handle.await.expect("the sweep task ends cleanly");
    }
}

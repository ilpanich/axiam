//! Periodic cleanup task for expired federation rows.
//!
//! SurrealDB v3 does not support native TTL on rows (RESEARCH §7), so this task
//! periodically sweeps `saml_assertion_replay` and `federation_login_state` of
//! any rows whose `expires_at` is in the past.
//!
//! The task shuts down cleanly when the caller sends `true` through the watch
//! channel (D-09, D-24).

use std::sync::Arc;
use std::time::Duration;

use axiam_core::error::AxiamError;
use axiam_core::repository::{AssertionReplayRepository, FederationLoginStateRepository};
use axiam_db::{SurrealAssertionReplayRepository, SurrealFederationLoginStateRepository};
use surrealdb::Connection;
use tokio::sync::watch;

/// Background task that sweeps expired rows from both federation tables.
pub struct CleanupTask<C: Connection> {
    replay_repo: Arc<SurrealAssertionReplayRepository<C>>,
    state_repo: Arc<SurrealFederationLoginStateRepository<C>>,
    interval: Duration,
    shutdown: watch::Receiver<bool>,
}

impl<C: Connection + Send + Sync + 'static> CleanupTask<C> {
    /// Construct a new `CleanupTask`.
    ///
    /// `interval` must be between 60 s and 3600 s (enforced by the caller in
    /// `main.rs`; the type itself does not constrain it further so tests can
    /// use short intervals without issue).
    pub fn new(
        replay_repo: Arc<SurrealAssertionReplayRepository<C>>,
        state_repo: Arc<SurrealFederationLoginStateRepository<C>>,
        interval: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            replay_repo,
            state_repo,
            interval,
            shutdown,
        }
    }

    /// Run the cleanup loop until a shutdown signal is received.
    ///
    /// Never returns `Err` — all sweep errors are logged at `warn` level and
    /// the loop continues (T-04-36).
    pub async fn run(mut self) -> Result<(), AxiamError> {
        let mut ticker = tokio::time::interval(self.interval);
        // Skip ticks that were missed while the sweep was running to prevent
        // catch-up storms after a pause (T-04-35).
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.replay_repo.cleanup_expired().await {
                        Ok(n) if n > 0 => {
                            tracing::debug!(deleted = n, "saml_assertion_replay cleanup");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = ?e, "saml_assertion_replay cleanup failed");
                        }
                    }

                    match self.state_repo.cleanup_expired().await {
                        Ok(n) if n > 0 => {
                            tracing::debug!(deleted = n, "federation_login_state cleanup");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = ?e, "federation_login_state cleanup failed");
                        }
                    }
                }
                changed = self.shutdown.changed() => {
                    if changed.is_ok() && *self.shutdown.borrow() {
                        tracing::info!("cleanup task received shutdown signal");
                        return Ok(());
                    }
                }
            }
        }
    }
}

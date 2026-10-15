//! The bounded wait for the deployment's crypto semaphore (#654, R101-02).
//!
//! Every SAML signature verification (the ACS's, the metadata's, the IdP
//! receiver's) runs on the blocking pool under the one semaphore that also
//! bounds Argon2id and the CRL re-sign. The semaphore is fair, so an acquire
//! with no bound queues behind every earlier waiter, and the SAML routes are
//! unauthenticated: a flood of signed posts would hold the bounded waiters
//! (logins, a CRL re-sign) at their own `503` for as long as it lasted. A SAML
//! acquire therefore gives up after the same `hash_acquire_timeout_secs` the
//! Argon2id path uses, and the caller answers with the refusal its path already
//! has.
//!
//! The permit is taken **before** anything about the document is evaluated, so
//! a busy gate says nothing about a signature: an invalid signature and a busy
//! gate can be answered alike without an oracle.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Why a [`CryptoGate`] gave no permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateRefusal {
    /// Every permit stayed held for the whole wait.
    Busy,
    /// The semaphore is closed (never happens in practice; the gate is never
    /// closed).
    Closed,
}

/// The deployment's crypto semaphore with the wait a SAML verification gives it.
#[derive(Clone, Debug)]
pub struct CryptoGate {
    semaphore: Arc<Semaphore>,
    wait: Duration,
}

impl CryptoGate {
    /// The wait used by a gate nobody configured: `AuthConfig`'s own default
    /// for `hash_acquire_timeout_secs`.
    pub const DEFAULT_WAIT: Duration = Duration::from_secs(5);

    /// `semaphore` with an acquire bounded by `wait`.
    #[must_use]
    pub fn new(semaphore: Arc<Semaphore>, wait: Duration) -> Self {
        Self { semaphore, wait }
    }

    /// The semaphore, for tests that hold its permits.
    #[doc(hidden)]
    #[must_use]
    pub fn semaphore(&self) -> &Arc<Semaphore> {
        &self.semaphore
    }

    /// A permit, or the refusal once `wait` has passed.
    ///
    /// A timeout is logged at `warn` under `site` (a fixed label, never
    /// request content), so an operator can see the gate saturating.
    ///
    /// # Errors
    ///
    /// [`GateRefusal::Busy`] when no permit came free in time,
    /// [`GateRefusal::Closed`] when the semaphore is closed.
    pub async fn acquire(&self, site: &'static str) -> Result<OwnedSemaphorePermit, GateRefusal> {
        match tokio::time::timeout(self.wait, Arc::clone(&self.semaphore).acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(GateRefusal::Closed),
            Err(_elapsed) => {
                tracing::warn!(
                    site,
                    wait_ms = u64::try_from(self.wait.as_millis()).unwrap_or(u64::MAX),
                    "SAML signature verification refused: no crypto permit came free in time"
                );
                Err(GateRefusal::Busy)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_free_permit_is_granted() {
        let gate = CryptoGate::new(Arc::new(Semaphore::new(1)), Duration::from_millis(50));
        assert!(gate.acquire("test").await.is_ok());
    }

    #[tokio::test]
    async fn a_held_gate_refuses_within_the_wait() {
        let gate = CryptoGate::new(Arc::new(Semaphore::new(1)), Duration::from_millis(100));
        let _held = gate.semaphore().clone().acquire_owned().await.unwrap();
        let started = std::time::Instant::now();
        assert_eq!(gate.acquire("test").await.unwrap_err(), GateRefusal::Busy);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_released_permit_reaches_the_waiter() {
        let gate = CryptoGate::new(Arc::new(Semaphore::new(1)), Duration::from_secs(5));
        let held = gate.semaphore().clone().acquire_owned().await.unwrap();
        let waiter = {
            let gate = gate.clone();
            tokio::spawn(async move { gate.acquire("test").await.map(|_| ()) })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(held);
        assert_eq!(waiter.await.unwrap(), Ok(()));
    }

    #[tokio::test]
    async fn a_closed_semaphore_is_closed() {
        let sem = Arc::new(Semaphore::new(1));
        sem.close();
        let gate = CryptoGate::new(sem, Duration::from_millis(50));
        assert_eq!(gate.acquire("test").await.unwrap_err(), GateRefusal::Closed);
    }
}

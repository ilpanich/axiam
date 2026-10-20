//! The bounded wait for the shared crypto semaphore (#671, T-102).
//!
//! `axiam-pki` cannot call `axiam_auth::crypto_gate::acquire_hash_permit`
//! (the two crates share a layer), so the PKI services carry the same bound:
//! the deployment's `hash_acquire_timeout_secs`, set at the composition root
//! with each service's `with_permit_wait`.

use std::time::Duration;

use axiam_core::error::{AxiamError, AxiamResult};
use tokio::sync::{Semaphore, SemaphorePermit};

/// The wait a service uses until the composition root replaces it; equal to
/// the default of `hash_acquire_timeout_secs`.
pub const DEFAULT_PERMIT_WAIT: Duration = Duration::from_secs(5);

/// A permit of `semaphore`, or `ServiceUnavailable` (HTTP 503) once `wait` has
/// passed. A closed semaphore is `Internal`, as the untimed call was.
pub(crate) async fn bounded_permit(
    semaphore: &Semaphore,
    wait: Duration,
) -> AxiamResult<SemaphorePermit<'_>> {
    match tokio::time::timeout(wait, semaphore.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_closed)) => Err(AxiamError::Internal("crypto semaphore closed".into())),
        Err(_elapsed) => Err(AxiamError::ServiceUnavailable(
            "the service is at capacity; please retry shortly".into(),
        )),
    }
}

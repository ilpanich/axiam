//! Backpressure gate for CPU-bound Argon2id operations (B1).
//!
//! A single process-wide `tokio::sync::Semaphore` bounds how many Argon2id
//! hash/verify operations run at once. The permit *count* caps peak memory:
//! each in-flight Argon2id operation allocates a ~19 MiB arena (OWASP params
//! m=19456), so without a bound an unauthenticated login flood is a
//! memory-DoS vector (the login benchmark reached ~970 MiB RSS ≈ 50
//! concurrent × 19 MiB against a 1024 MiB cap).
//!
//! This module adds an *acquire timeout* on top of that bound so that, once
//! every permit is held, further callers fail fast with a 503 backpressure
//! error rather than queueing unboundedly (which turns a memory problem into
//! a tail-latency problem).

use std::time::Duration;

use axiam_core::error::{AxiamError, AxiamResult};
use tokio::sync::{Semaphore, SemaphorePermit};

/// Acquire a permit from the crypto semaphore, bounded by `timeout`.
///
/// * On success, returns the held [`SemaphorePermit`] (drop it to release).
/// * On timeout, returns [`AxiamError::ServiceUnavailable`], which the REST
///   layer maps to **HTTP 503** — the existing "service unavailable /
///   overloaded" variant, chosen because a saturated hash gate is a transient
///   server-capacity condition, not a per-client rate-limit violation.
/// * A closed semaphore (never happens in practice — the gate is never
///   closed) maps to [`AxiamError::Internal`], matching the prior behaviour of
///   the untimed `acquire()` call sites.
pub(crate) async fn acquire_hash_permit(
    semaphore: &Semaphore,
    timeout: Duration,
) -> AxiamResult<SemaphorePermit<'_>> {
    match tokio::time::timeout(timeout, semaphore.acquire()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_closed)) => Err(AxiamError::Internal("crypto semaphore closed".into())),
        Err(_elapsed) => Err(AxiamError::ServiceUnavailable(
            "authentication service is at capacity; please retry shortly".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn returns_permit_when_capacity_available() {
        let sem = Semaphore::new(2);
        let permit = acquire_hash_permit(&sem, Duration::from_secs(5)).await;
        assert!(permit.is_ok(), "should acquire when permits are free");
        assert_eq!(sem.available_permits(), 1, "one permit taken");
    }

    #[tokio::test]
    async fn times_out_to_service_unavailable_when_saturated() {
        let sem = Semaphore::new(1);
        // Saturate: hold the only permit for the duration of the test.
        let _held = sem.acquire().await.unwrap();

        // A second acquire with a tiny timeout must return the backpressure
        // error (HTTP 503), not block forever.
        let result = acquire_hash_permit(&sem, Duration::from_millis(20)).await;
        match result {
            Err(AxiamError::ServiceUnavailable(_)) => {}
            other => panic!("expected ServiceUnavailable backpressure error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn permit_release_lets_a_waiter_through() {
        let sem = Arc::new(Semaphore::new(1));
        let permit = acquire_hash_permit(&sem, Duration::from_secs(5))
            .await
            .expect("first acquire");
        drop(permit); // release
        let second = acquire_hash_permit(&sem, Duration::from_millis(50)).await;
        assert!(second.is_ok(), "released permit should be reusable");
    }

    /// With N permits, more than N concurrent hash-gated sections must never
    /// run at once — the surplus callers serialize behind the semaphore. This
    /// is the memory-DoS bound: peak concurrent Argon2id arenas ≤ N.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_is_bounded_to_permit_count() {
        const PERMITS: usize = 2;
        const TASKS: usize = 8;
        let sem = Arc::new(Semaphore::new(PERMITS));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..TASKS {
            let sem = Arc::clone(&sem);
            let in_flight = Arc::clone(&in_flight);
            let max_observed = Arc::clone(&max_observed);
            handles.push(tokio::spawn(async move {
                let _permit = acquire_hash_permit(&sem, Duration::from_secs(5))
                    .await
                    .expect("permit acquired within timeout");
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_observed.fetch_max(now, Ordering::SeqCst);
                // Hold the permit briefly to force overlap between tasks.
                tokio::time::sleep(Duration::from_millis(25)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert!(
            max_observed.load(Ordering::SeqCst) <= PERMITS,
            "observed concurrency {} exceeded permit bound {PERMITS}",
            max_observed.load(Ordering::SeqCst)
        );
    }
}

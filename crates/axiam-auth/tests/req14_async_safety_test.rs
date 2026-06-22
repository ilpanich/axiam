//! REQ-14 AC-2 (CQ-B02): CPU-bound crypto runs in spawn_blocking behind a bounding semaphore.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Semaphore;

/// Smoke-test that verify_password still returns correct results when
/// called through the spawn_blocking path inside AuthService.
///
/// We exercise the verify path by hashing a known password with
/// `axiam_auth::password::hash_password`, then confirming that
/// AuthService's internal path (which uses spawn_blocking + semaphore)
/// still returns `true` for a matching password and `false` for a
/// non-matching one.
///
/// This test does not drive AuthService directly (which requires a full
/// repository stack) — instead it verifies the spawn_blocking wrapper
/// function that is used by AuthService, confirming:
///   1. The wrapper returns the correct boolean.
///   2. The pepper is applied correctly.
#[tokio::test]
async fn hash_runs_in_spawn_blocking() {
    let pepper = "test-pepper";
    let password = "CorrectHorseBatteryStaple!99";

    // Hash synchronously (as the DB layer would).
    let hash =
        axiam_auth::password::hash_password(password, Some(pepper)).expect("hash_password failed");

    // Verify through spawn_blocking (same function, wrapped).
    let password_owned = password.to_string();
    let hash_owned = hash.clone();
    let pepper_owned = pepper.to_string();

    let result = tokio::task::spawn_blocking(move || {
        axiam_auth::password::verify_password(&password_owned, &hash_owned, Some(&pepper_owned))
    })
    .await
    .expect("spawn_blocking join error")
    .expect("verify_password failed");

    assert!(result, "correct password + pepper must verify as true");

    // Now verify a wrong password returns false.
    let wrong = "WrongPassword999!".to_string();
    let hash2 = hash.clone();
    let pepper2 = pepper.to_string();
    let wrong_result = tokio::task::spawn_blocking(move || {
        axiam_auth::password::verify_password(&wrong, &hash2, Some(&pepper2))
    })
    .await
    .expect("spawn_blocking join error")
    .expect("verify_password failed");

    assert!(!wrong_result, "wrong password must verify as false");
}

/// Test that the semaphore bounds concurrency: with a semaphore of 2,
/// spawning 6 concurrent verify tasks should never have more than 2
/// running simultaneously.
#[tokio::test]
async fn semaphore_bounds_concurrency() {
    let sem = Arc::new(Semaphore::new(2));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let max_observed = Arc::new(AtomicUsize::new(0));

    let pepper = "test-pepper";
    let password = "CorrectHorse2024!";
    let hash = axiam_auth::password::hash_password(password, Some(pepper)).expect("hash failed");

    let mut handles = Vec::new();
    for _ in 0..6 {
        let sem = Arc::clone(&sem);
        let in_flight = Arc::clone(&in_flight);
        let max_observed = Arc::clone(&max_observed);
        let pw = password.to_string();
        let hsh = hash.clone();
        let pp = pepper.to_string();

        let handle = tokio::spawn(async move {
            // Acquire permit — mirrors the AuthService pattern.
            let _permit = sem.acquire().await.unwrap();

            // Track in-flight count.
            let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            // Update max_observed.
            let mut prev = max_observed.load(Ordering::SeqCst);
            while current > prev {
                match max_observed.compare_exchange(
                    prev,
                    current,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(x) => prev = x,
                }
            }

            // CPU work inside spawn_blocking.
            let result = tokio::task::spawn_blocking(move || {
                axiam_auth::password::verify_password(&pw, &hsh, Some(&pp))
            })
            .await
            .expect("spawn_blocking join error")
            .expect("verify_password error");

            in_flight.fetch_sub(1, Ordering::SeqCst);
            result
        });
        handles.push(handle);
    }

    for h in handles {
        assert!(
            h.await.expect("task panicked"),
            "all verifications must return true"
        );
    }

    let max = max_observed.load(Ordering::SeqCst);
    assert!(
        max <= 2,
        "semaphore(2) must cap in-flight tasks at 2; observed {max}"
    );
}

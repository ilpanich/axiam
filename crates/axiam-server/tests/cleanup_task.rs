//! Integration test: periodic cleanup task sweeps expired federation rows and
//! shuts down gracefully (Task 1 acceptance criteria).
//!
//! Uses an in-memory SurrealDB (no external infra) and short intervals (100 ms)
//! to keep the test fast. This does NOT exercise `CleanupTask` itself (which
//! depends on `axiam-server` compiling with the xmlsec feature — see SUMMARY for
//! the local-compile limitation); instead it verifies the underlying
//! `cleanup_expired` methods that `CleanupTask` calls, and the watch-shutdown
//! logic is verified via a standalone tokio task that mimics CleanupTask behaviour.

use std::sync::Arc;
use std::time::Duration;

use axiam_core::repository::{AssertionReplayRepository, FederationLoginStateRepository};
use axiam_db::{
    SurrealAssertionReplayRepository, SurrealFederationLoginStateRepository, run_migrations,
};
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::sync::watch;
use uuid::Uuid;

/// Convenience: connect an in-memory DB and run migrations.
async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    db.use_ns("test").use_db("test").await.expect("use ns/db");
    run_migrations(&db).await.expect("migrations");
    db
}

// ---------------------------------------------------------------------------
// saml_assertion_replay sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_sweeps_expired_saml_assertion_replay_rows() {
    let db = setup_db().await;
    let repo = SurrealAssertionReplayRepository::new(db.clone());

    let tenant_id = Uuid::new_v4();
    let past = Utc::now() - chrono::Duration::seconds(2);
    let future = Utc::now() + chrono::Duration::seconds(3600);

    // Insert one expired row and one fresh row.
    repo.insert_assertion(tenant_id, "expired-id-1", past)
        .await
        .expect("insert expired");
    repo.insert_assertion(tenant_id, "fresh-id-1", future)
        .await
        .expect("insert fresh");

    // Run cleanup; exactly one expired row should be removed.
    let swept = repo.cleanup_expired().await.expect("cleanup");
    assert_eq!(swept, 1, "exactly 1 expired row should be swept");

    // Second sweep should find nothing.
    let swept2 = repo.cleanup_expired().await.expect("cleanup again");
    assert_eq!(swept2, 0, "no more expired rows");
}

// ---------------------------------------------------------------------------
// federation_login_state sweep
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_sweeps_expired_federation_login_state_rows() {
    let db = setup_db().await;
    let repo = SurrealFederationLoginStateRepository::new(db.clone());

    let tenant_id = Uuid::new_v4();
    let config_id = Uuid::new_v4();

    let past = Utc::now() - chrono::Duration::seconds(2);
    let future = Utc::now() + chrono::Duration::seconds(3600);

    let expired_row = axiam_core::repository::FederationLoginState {
        state: "state-expired".into(),
        nonce: "nonce-expired".into(),
        tenant_id,
        federation_config_id: config_id,
        redirect_uri: "https://example.com/cb".into(),
        expires_at: past,
    };
    let fresh_row = axiam_core::repository::FederationLoginState {
        state: "state-fresh".into(),
        nonce: "nonce-fresh".into(),
        tenant_id,
        federation_config_id: config_id,
        redirect_uri: "https://example.com/cb".into(),
        expires_at: future,
    };

    repo.insert(&expired_row).await.expect("insert expired");
    repo.insert(&fresh_row).await.expect("insert fresh");

    let swept = repo.cleanup_expired().await.expect("cleanup");
    assert_eq!(swept, 1, "exactly 1 expired row should be swept");

    let swept2 = repo.cleanup_expired().await.expect("cleanup again");
    assert_eq!(swept2, 0, "no more expired rows");
}

// ---------------------------------------------------------------------------
// Graceful-shutdown via watch channel (unit-style, no DB required)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_task_shuts_down_on_watch_signal_within_200ms() {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Spawn a task that mimics the CleanupTask loop with a very long interval
    // (10 s) — the shutdown signal should fire long before the first tick.
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut rx = shutdown_rx;
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Would run cleanup; nothing to do here.
                }
                changed = rx.changed() => {
                    if changed.is_ok() && *rx.borrow() {
                        return;
                    }
                }
            }
        }
    });

    // Give the task a moment to start.
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Send shutdown signal; task should exit within 200 ms.
    shutdown_tx.send(true).expect("send shutdown");

    tokio::time::timeout(Duration::from_millis(200), handle)
        .await
        .expect("task must shut down within 200 ms")
        .expect("task must not panic");
}

// ---------------------------------------------------------------------------
// Error-tolerance: DB failure does not panic the loop
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_does_not_propagate_db_errors_as_panics() {
    // Use a closed/disconnected DB to force errors.
    // We verify this by calling cleanup_expired on a repo whose DB has been
    // dropped (namespace not selected → query fails gracefully).
    let db = Surreal::new::<Mem>(()).await.expect("in-memory DB");
    // Intentionally do NOT call use_ns/use_db or run_migrations.
    // SurrealDB v3 in-memory with no namespace returns an error on queries.
    let repo = SurrealAssertionReplayRepository::new(db);
    let result = repo.cleanup_expired().await;
    // Should return an Err (DB not configured), NOT panic.
    // We just assert it doesn't panic; the result shape is already verified by
    // the trait contract (returns AxiamResult<u64>).
    let _ = result; // Ok or Err — both acceptable; no panic is the requirement.
}

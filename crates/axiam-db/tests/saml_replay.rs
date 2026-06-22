//! Integration tests for `SurrealAssertionReplayRepository`.
//!
//! Tests the insert-or-conflict semantics required for SAML assertion replay
//! protection (D-09): duplicate `(tenant_id, assertion_id)` within a tenant
//! must return `AxiamError::ReplayDetected`; the same `assertion_id` for a
//! different tenant must succeed; and `cleanup_expired` deletes only expired
//! rows.

use axiam_core::error::AxiamError;
use axiam_core::repository::AssertionReplayRepository;
use axiam_db::repository::SurrealAssertionReplayRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// Spin up an in-memory SurrealDB and run migrations.
async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

// ---------------------------------------------------------------------------
// Test: duplicate assertion_id within same tenant → ReplayDetected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplicate_assertion_within_tenant_returns_replay_detected() {
    let db = setup().await;
    let repo = SurrealAssertionReplayRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let assertion_id = "test-assertion-1";
    let expires_at = Utc::now() + Duration::minutes(5);

    // First insert should succeed.
    repo.insert_assertion(tenant_id, assertion_id, expires_at)
        .await
        .expect("first insert should succeed");

    // Second insert of the same assertion_id within the same tenant should fail.
    let err = repo
        .insert_assertion(tenant_id, assertion_id, expires_at)
        .await
        .expect_err("second insert should return ReplayDetected");

    assert!(
        matches!(err, AxiamError::ReplayDetected),
        "expected ReplayDetected, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test: same assertion_id for different tenants → both Ok
// ---------------------------------------------------------------------------

#[tokio::test]
async fn same_assertion_different_tenants_both_succeed() {
    let db = setup().await;
    let repo = SurrealAssertionReplayRepository::new(db);

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let assertion_id = "cross-tenant-assertion";
    let expires_at = Utc::now() + Duration::minutes(5);

    repo.insert_assertion(tenant_a, assertion_id, expires_at)
        .await
        .expect("tenant A insert should succeed");

    repo.insert_assertion(tenant_b, assertion_id, expires_at)
        .await
        .expect("tenant B insert should succeed (different tenant)");
}

// ---------------------------------------------------------------------------
// Test: cleanup_expired deletes expired rows only
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_expired_deletes_expired_rows() {
    let db = setup().await;
    let repo = SurrealAssertionReplayRepository::new(db);

    let tenant_id = Uuid::new_v4();

    // Insert one already-expired row and one not-yet-expired row.
    let expired_at = Utc::now() - Duration::hours(1);
    let fresh_at = Utc::now() + Duration::minutes(5);

    repo.insert_assertion(tenant_id, "expired-assertion", expired_at)
        .await
        .expect("insert expired row");

    repo.insert_assertion(tenant_id, "fresh-assertion", fresh_at)
        .await
        .expect("insert fresh row");

    // cleanup_expired should delete exactly 1 row.
    let deleted = repo
        .cleanup_expired()
        .await
        .expect("cleanup_expired failed");
    assert_eq!(deleted, 1, "expected 1 expired row deleted, got {deleted}");

    // The fresh row should still exist (duplicate insert should be ReplayDetected).
    let err = repo
        .insert_assertion(tenant_id, "fresh-assertion", fresh_at)
        .await
        .expect_err("fresh row should still exist");

    assert!(
        matches!(err, AxiamError::ReplayDetected),
        "fresh row should still be present: {err:?}"
    );

    // The expired row should be gone (re-insert should succeed).
    repo.insert_assertion(tenant_id, "expired-assertion", fresh_at)
        .await
        .expect("expired row should have been cleaned up");
}

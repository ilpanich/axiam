//! Integration tests for `SurrealAmqpNonceRepository` (NEW-4 AMQP replay
//! protection). Mirrors `saml_replay.rs`: duplicate `(tenant_id, nonce)`
//! within a tenant returns `AxiamError::ReplayDetected`; the same nonce for a
//! different tenant succeeds; `cleanup_expired` deletes only expired rows.

use axiam_core::error::AxiamError;
use axiam_core::repository::AmqpNonceRepository;
use axiam_db::repository::SurrealAmqpNonceRepository;
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
// Test: duplicate nonce within same tenant → ReplayDetected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplicate_nonce_within_tenant_returns_replay_detected() {
    let db = setup().await;
    let repo = SurrealAmqpNonceRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(5);

    // First insert should succeed.
    repo.insert_nonce(tenant_id, nonce, expires_at)
        .await
        .expect("first insert should succeed");

    // Second insert of the same nonce within the same tenant should fail.
    let err = repo
        .insert_nonce(tenant_id, nonce, expires_at)
        .await
        .expect_err("second insert should return ReplayDetected");

    assert!(
        matches!(err, AxiamError::ReplayDetected),
        "expected ReplayDetected, got: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Test: same nonce for different tenants → both Ok
// ---------------------------------------------------------------------------

#[tokio::test]
async fn same_nonce_different_tenants_both_succeed() {
    let db = setup().await;
    let repo = SurrealAmqpNonceRepository::new(db);

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let nonce = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(5);

    repo.insert_nonce(tenant_a, nonce, expires_at)
        .await
        .expect("tenant A insert should succeed");

    repo.insert_nonce(tenant_b, nonce, expires_at)
        .await
        .expect("tenant B insert should succeed (different tenant)");
}

// ---------------------------------------------------------------------------
// Test: distinct nonces within same tenant → both Ok (no false-positive
// replay on unrelated nonces)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn distinct_nonces_same_tenant_both_succeed() {
    let db = setup().await;
    let repo = SurrealAmqpNonceRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(5);

    repo.insert_nonce(tenant_id, Uuid::new_v4(), expires_at)
        .await
        .expect("first nonce insert should succeed");
    repo.insert_nonce(tenant_id, Uuid::new_v4(), expires_at)
        .await
        .expect("second distinct nonce insert should succeed");
}

// ---------------------------------------------------------------------------
// Test: cleanup_expired deletes expired rows only
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_expired_deletes_expired_rows() {
    let db = setup().await;
    let repo = SurrealAmqpNonceRepository::new(db);

    let tenant_id = Uuid::new_v4();

    // Insert one already-expired row and one not-yet-expired row.
    let expired_at = Utc::now() - Duration::hours(1);
    let fresh_at = Utc::now() + Duration::minutes(5);
    let expired_nonce = Uuid::new_v4();
    let fresh_nonce = Uuid::new_v4();

    repo.insert_nonce(tenant_id, expired_nonce, expired_at)
        .await
        .expect("insert expired row");

    repo.insert_nonce(tenant_id, fresh_nonce, fresh_at)
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
        .insert_nonce(tenant_id, fresh_nonce, fresh_at)
        .await
        .expect_err("fresh row should still exist");

    assert!(
        matches!(err, AxiamError::ReplayDetected),
        "fresh row should still be present: {err:?}"
    );

    // The expired row should be gone (re-insert should succeed).
    repo.insert_nonce(tenant_id, expired_nonce, fresh_at)
        .await
        .expect("expired row should have been cleaned up");
}

// ---------------------------------------------------------------------------
// Test: cleanup_expired on an empty table returns 0
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_expired_empty_table_returns_zero() {
    let db = setup().await;
    let repo = SurrealAmqpNonceRepository::new(db);

    let deleted = repo
        .cleanup_expired()
        .await
        .expect("cleanup_expired failed");
    assert_eq!(deleted, 0);
}

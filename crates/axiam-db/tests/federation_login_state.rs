//! Integration tests for `SurrealFederationLoginStateRepository`.
//!
//! Covers insert + consume semantics, expiry enforcement, single-use
//! guarantee, cleanup_expired, and duplicate-state rejection (D-24).

use axiam_core::error::AxiamError;
use axiam_core::repository::{FederationLoginState, FederationLoginStateRepository};
use axiam_db::repository::SurrealFederationLoginStateRepository;
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

fn fresh_row() -> FederationLoginState {
    FederationLoginState {
        state: Uuid::new_v4().to_string(),
        nonce: Uuid::new_v4().to_string(),
        tenant_id: Uuid::new_v4(),
        federation_config_id: Uuid::new_v4(),
        redirect_uri: "https://app.example.com/callback".into(),
        expires_at: Utc::now() + Duration::minutes(10),
        request_id: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Test: insert + consume returns the same row; second consume returns None
// ---------------------------------------------------------------------------

#[tokio::test]
async fn insert_then_consume_returns_row_second_consume_returns_none() {
    let db = setup().await;
    let repo = SurrealFederationLoginStateRepository::new(db);

    let row = fresh_row();
    let state = row.state.clone();

    repo.insert(&row).await.expect("insert should succeed");

    let consumed = repo
        .consume_by_state(&state)
        .await
        .expect("first consume should not error")
        .expect("first consume should return Some");

    assert_eq!(consumed.state, state);
    assert_eq!(consumed.nonce, row.nonce);
    assert_eq!(consumed.tenant_id, row.tenant_id);
    assert_eq!(consumed.federation_config_id, row.federation_config_id);
    assert_eq!(consumed.redirect_uri, row.redirect_uri);

    // Second consume must return None (row was deleted).
    let second = repo
        .consume_by_state(&state)
        .await
        .expect("second consume should not error");
    assert!(
        second.is_none(),
        "second consume must return None (single-use)"
    );
}

// ---------------------------------------------------------------------------
// Test: expired row → consume returns None AND row is deleted
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_row_consume_returns_none_and_row_is_deleted() {
    let db = setup().await;
    let repo = SurrealFederationLoginStateRepository::new(db);

    let mut row = fresh_row();
    row.expires_at = Utc::now() - Duration::seconds(1); // already expired
    let state = row.state.clone();

    repo.insert(&row).await.expect("insert expired row");

    let result = repo
        .consume_by_state(&state)
        .await
        .expect("consume should not error on expired row");
    assert!(result.is_none(), "expired row should return None");

    // Row must be gone — re-insert with the same state must succeed.
    let mut fresh = fresh_row();
    fresh.state = state.clone();
    repo.insert(&fresh)
        .await
        .expect("re-insert after expire+delete should succeed");
}

// ---------------------------------------------------------------------------
// Test: cleanup_expired deletes expired rows and leaves fresh ones
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cleanup_expired_deletes_one_expired_leaves_one_fresh() {
    let db = setup().await;
    let repo = SurrealFederationLoginStateRepository::new(db);

    let mut expired = fresh_row();
    expired.expires_at = Utc::now() - Duration::hours(1);
    let expired_state = expired.state.clone();

    let fresh = fresh_row();
    let fresh_state = fresh.state.clone();

    repo.insert(&expired).await.expect("insert expired row");
    repo.insert(&fresh).await.expect("insert fresh row");

    let deleted = repo
        .cleanup_expired()
        .await
        .expect("cleanup_expired failed");
    assert_eq!(deleted, 1, "expected 1 expired row deleted, got {deleted}");

    // Fresh row still consumable.
    let result = repo
        .consume_by_state(&fresh_state)
        .await
        .expect("consume fresh row");
    assert!(result.is_some(), "fresh row should still be present");

    // Expired row should be gone — re-insert must succeed.
    let mut re = fresh_row();
    re.state = expired_state;
    repo.insert(&re)
        .await
        .expect("re-insert of expired state should succeed after cleanup");
}

// ---------------------------------------------------------------------------
// Test: duplicate state value → AlreadyExists error
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplicate_state_returns_already_exists() {
    let db = setup().await;
    let repo = SurrealFederationLoginStateRepository::new(db);

    let row = fresh_row();
    let mut dup = fresh_row();
    dup.state = row.state.clone(); // same state, different record ID

    repo.insert(&row)
        .await
        .expect("first insert should succeed");

    let err = repo
        .insert(&dup)
        .await
        .expect_err("duplicate state should fail");

    assert!(
        matches!(err, AxiamError::AlreadyExists { .. }),
        "expected AlreadyExists, got: {err:?}"
    );
}

//! Integration tests for `SurrealSsoHandoffCodeRepository`.
//!
//! A handoff code is a bearer credential for a session: the cross-site half of
//! the SAML and Apple returns mints one, and redeeming it issues the cookies.
//! Its whole security argument is single use, short life, and hash-only
//! storage, so each of those gets a test rather than a comment. See
//! `claude_dev/federation-sso-login-design.md` §5.2 and threat model T-219.

use axiam_core::error::AxiamError;
use axiam_core::repository::{SsoHandoffCode, SsoHandoffCodeRepository};
use axiam_db::repository::SurrealSsoHandoffCodeRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// The stored form is a hash; these tests never need the pre-image, so they use
/// a distinct opaque string per row rather than pretending to hash one.
fn fresh_row() -> SsoHandoffCode {
    SsoHandoffCode {
        code_hash: Uuid::new_v4().simple().to_string(),
        tenant_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        redirect_uri: "https://app.example.com/auth/sso/callback".into(),
        expires_at: Utc::now() + Duration::seconds(60),
    }
}

#[tokio::test]
async fn insert_then_consume_returns_the_row() {
    let db = setup().await;
    let repo = SurrealSsoHandoffCodeRepository::new(db);

    let row = fresh_row();
    repo.insert(&row).await.expect("insert should succeed");

    let got = repo
        .consume_by_hash(&row.code_hash)
        .await
        .expect("consume should not error")
        .expect("a live code should be found");

    assert_eq!(got.code_hash, row.code_hash);
    assert_eq!(got.tenant_id, row.tenant_id);
    assert_eq!(got.user_id, row.user_id);
    assert_eq!(got.redirect_uri, row.redirect_uri);
}

/// The single-use guarantee. A second redemption must be indistinguishable
/// from a code that never existed — the session it would buy is the whole
/// reason the code is worth stealing.
#[tokio::test]
async fn a_code_can_be_redeemed_exactly_once() {
    let db = setup().await;
    let repo = SurrealSsoHandoffCodeRepository::new(db);

    let row = fresh_row();
    repo.insert(&row).await.unwrap();

    assert!(
        repo.consume_by_hash(&row.code_hash)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.consume_by_hash(&row.code_hash)
            .await
            .unwrap()
            .is_none(),
        "the row must be gone after the first redemption"
    );
}

#[tokio::test]
async fn an_unknown_code_is_not_found() {
    let db = setup().await;
    let repo = SurrealSsoHandoffCodeRepository::new(db);

    assert!(
        repo.consume_by_hash("no-such-hash")
            .await
            .unwrap()
            .is_none(),
        "an unknown hash must be a plain miss, not an error"
    );
}

/// Expiry is checked *after* the delete, deliberately: an expired code that is
/// presented must not survive to be presented again, and "expired" and "never
/// existed" must answer the same thing.
#[tokio::test]
async fn an_expired_code_is_refused_and_is_still_consumed() {
    let db = setup().await;
    let repo = SurrealSsoHandoffCodeRepository::new(db.clone());

    let mut row = fresh_row();
    row.expires_at = Utc::now() - Duration::seconds(1);
    repo.insert(&row).await.unwrap();

    assert!(
        repo.consume_by_hash(&row.code_hash)
            .await
            .unwrap()
            .is_none(),
        "an expired code must not yield a session"
    );

    // And the row is gone, so a second attempt cannot race a clock adjustment
    // into a success.
    let remaining: Vec<serde_json::Value> = db
        .query("SELECT code_hash FROM sso_handoff_code WHERE code_hash = $h")
        .bind(("h", row.code_hash.clone()))
        .await
        .unwrap()
        .take(0)
        .unwrap();
    assert!(remaining.is_empty(), "an expired row must be deleted too");
}

/// A collision on 256 bits of entropy is a thing that does not happen — but if
/// it did, the alternative reading is "somebody replayed a code", so it must
/// not look like a success.
#[tokio::test]
async fn a_duplicate_code_hash_is_a_conflict() {
    let db = setup().await;
    let repo = SurrealSsoHandoffCodeRepository::new(db);

    let row = fresh_row();
    repo.insert(&row).await.unwrap();

    let err = repo
        .insert(&row)
        .await
        .expect_err("a second row with the same hash must be refused");
    assert!(
        matches!(
            err,
            AxiamError::Conflict { .. } | AxiamError::AlreadyExists { .. }
        ),
        "expected a conflict, got {err:?}"
    );
}

#[tokio::test]
async fn cleanup_removes_only_expired_rows() {
    let db = setup().await;
    let repo = SurrealSsoHandoffCodeRepository::new(db);

    let live = fresh_row();
    repo.insert(&live).await.unwrap();

    for _ in 0..2 {
        let mut stale = fresh_row();
        stale.expires_at = Utc::now() - Duration::seconds(30);
        repo.insert(&stale).await.unwrap();
    }

    let removed = repo
        .cleanup_expired()
        .await
        .expect("cleanup should succeed");
    assert_eq!(removed, 2, "both expired rows, and only those");

    assert!(
        repo.consume_by_hash(&live.code_hash)
            .await
            .unwrap()
            .is_some(),
        "the live code must survive the sweep"
    );
}

#[tokio::test]
async fn cleanup_on_an_empty_table_reports_nothing_removed() {
    let db = setup().await;
    let repo = SurrealSsoHandoffCodeRepository::new(db);
    assert_eq!(repo.cleanup_expired().await.unwrap(), 0);
}

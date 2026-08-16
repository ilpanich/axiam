//! SCIM provisioning tokens against the real datastore.
//!
//! The properties tested here are the ones that live in `WHERE` clauses rather
//! than in Rust, so a mock would agree with whatever the query happened to do:
//!
//! - lookup is by **hash across all tenants** (there is no authenticated
//!   tenant yet when a handle is presented — the row is what establishes one),
//! - lookup does **not** filter revoked or expired rows, because the caller
//!   needs to tell "withdrawn" apart from "never existed" for the audit trail,
//! - revoke is idempotent in the specific sense that a second call keeps the
//!   original timestamp, so the trail records when authority was actually
//!   withdrawn rather than when somebody last clicked.

use axiam_core::models::scim_token::CreateScimToken;
use axiam_core::repository::ScimTokenRepository;
use axiam_db::repository::SurrealScimTokenRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

mod common;

async fn repo() -> SurrealScimTokenRepository<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    SurrealScimTokenRepository::new(db)
}

fn input(tenant: Uuid, user: Uuid, hash: &str, days: i64) -> CreateScimToken {
    CreateScimToken {
        tenant_id: tenant,
        user_id: user,
        name: "okta-production".into(),
        token_hash: hash.into(),
        created_by: Uuid::new_v4(),
        expires_at: Utc::now() + Duration::days(days),
    }
}

#[tokio::test]
async fn create_round_trips_every_field() {
    let repo = repo().await;
    let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());

    let created = repo
        .create(input(tenant, user, "hash-a", 30))
        .await
        .unwrap();

    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.user_id, user);
    assert_eq!(created.name, "okta-production");
    assert_eq!(created.token_hash, "hash-a");
    assert!(created.last_used_at.is_none());
    assert!(created.revoked_at.is_none());
    assert!(created.is_usable(Utc::now()));
}

#[tokio::test]
async fn lookup_by_hash_finds_the_row_without_knowing_the_tenant() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    repo.create(input(tenant, Uuid::new_v4(), "hash-b", 30))
        .await
        .unwrap();

    // This is the whole authentication path: a presented handle is all the
    // caller has, and the row's own tenant_id is what establishes scope.
    let found = repo.get_by_token_hash("hash-b").await.unwrap().unwrap();
    assert_eq!(found.tenant_id, tenant);
}

#[tokio::test]
async fn an_unknown_hash_is_none_rather_than_an_error() {
    let repo = repo().await;
    assert!(repo.get_by_token_hash("nope").await.unwrap().is_none());
}

/// The query must NOT filter these out: the caller distinguishes "revoked" from
/// "never existed" so the audit trail can say which happened, and a filtering
/// query would collapse both to `None`.
#[tokio::test]
async fn lookup_still_returns_revoked_and_expired_rows() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    let revoked = repo
        .create(input(tenant, Uuid::new_v4(), "hash-revoked", 30))
        .await
        .unwrap();
    repo.revoke(tenant, revoked.id).await.unwrap();

    repo.create(input(tenant, Uuid::new_v4(), "hash-expired", -1))
        .await
        .unwrap();

    let r = repo
        .get_by_token_hash("hash-revoked")
        .await
        .unwrap()
        .expect("revoked row must still be findable");
    assert!(r.revoked_at.is_some());
    assert!(!r.is_usable(Utc::now()));

    let e = repo
        .get_by_token_hash("hash-expired")
        .await
        .unwrap()
        .expect("expired row must still be findable");
    assert!(e.revoked_at.is_none());
    assert!(!e.is_usable(Utc::now()));
}

#[tokio::test]
async fn revoking_twice_keeps_the_first_timestamp() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let t = repo
        .create(input(tenant, Uuid::new_v4(), "hash-c", 30))
        .await
        .unwrap();

    repo.revoke(tenant, t.id).await.unwrap();
    let first = repo.get_by_id(tenant, t.id).await.unwrap().revoked_at;
    assert!(first.is_some());

    repo.revoke(tenant, t.id).await.unwrap();
    let second = repo.get_by_id(tenant, t.id).await.unwrap().revoked_at;

    // When authority was withdrawn, not when somebody last clicked.
    assert_eq!(first, second);
}

#[tokio::test]
async fn revoke_and_get_by_id_are_tenant_scoped() {
    let repo = repo().await;
    let (tenant_a, tenant_b) = (Uuid::new_v4(), Uuid::new_v4());
    let t = repo
        .create(input(tenant_a, Uuid::new_v4(), "hash-d", 30))
        .await
        .unwrap();

    assert!(repo.get_by_id(tenant_b, t.id).await.is_err());

    // A cross-tenant revoke must change nothing rather than silently succeed.
    repo.revoke(tenant_b, t.id).await.unwrap();
    assert!(
        repo.get_by_id(tenant_a, t.id)
            .await
            .unwrap()
            .revoked_at
            .is_none()
    );
}

#[tokio::test]
async fn list_is_scoped_to_one_tenant() {
    let repo = repo().await;
    let (tenant_a, tenant_b) = (Uuid::new_v4(), Uuid::new_v4());
    repo.create(input(tenant_a, Uuid::new_v4(), "hash-e", 30))
        .await
        .unwrap();
    repo.create(input(tenant_a, Uuid::new_v4(), "hash-f", 30))
        .await
        .unwrap();
    repo.create(input(tenant_b, Uuid::new_v4(), "hash-g", 30))
        .await
        .unwrap();

    assert_eq!(repo.list_for_tenant(tenant_a).await.unwrap().len(), 2);
    assert_eq!(repo.list_for_tenant(tenant_b).await.unwrap().len(), 1);
}

#[tokio::test]
async fn touch_last_used_records_a_timestamp() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let t = repo
        .create(input(tenant, Uuid::new_v4(), "hash-h", 30))
        .await
        .unwrap();
    assert!(t.last_used_at.is_none());

    repo.touch_last_used(tenant, t.id).await.unwrap();
    assert!(
        repo.get_by_id(tenant, t.id)
            .await
            .unwrap()
            .last_used_at
            .is_some()
    );
}

/// Deleting a user must not leave a year-long credential naming them.
#[tokio::test]
async fn delete_for_user_removes_only_that_users_tokens() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let (doomed, kept) = (Uuid::new_v4(), Uuid::new_v4());

    repo.create(input(tenant, doomed, "hash-i", 30))
        .await
        .unwrap();
    repo.create(input(tenant, doomed, "hash-j", 30))
        .await
        .unwrap();
    repo.create(input(tenant, kept, "hash-k", 30))
        .await
        .unwrap();

    repo.delete_for_user(tenant, doomed).await.unwrap();

    let remaining = repo.list_for_tenant(tenant).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].user_id, kept);
    assert!(repo.get_by_token_hash("hash-i").await.unwrap().is_none());
}

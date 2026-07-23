//! Additional `SurrealRefreshTokenRepository` coverage not exercised by
//! `oauth2_refresh_revoke_all.rs`: lookup failure modes (unknown/expired/
//! revoked), single-use `revoke()` semantics, `revoke_all_for_client`, and
//! `delete_expired`.

use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, RefreshTokenRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealRefreshTokenRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org-rtg".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant-rtg".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "rtg-user".into(),
            email: "rtg-user@example.com".into(),
            password: "pass123!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user.id)
}

async fn insert_token_expiring(
    repo: &SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: &str,
    expires_at: chrono::DateTime<Utc>,
) -> String {
    let hash = Uuid::new_v4().to_string();
    repo.create(CreateRefreshToken {
        tenant_id,
        user_id: Some(user_id),
        token_hash: hash.clone(),
        client_id: client_id.into(),
        scopes: vec!["openid".into()],
        expires_at,
    })
    .await
    .unwrap();
    hash
}

// ---------------------------------------------------------------------------
// get_by_token_hash failure modes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_token_hash_unknown_hash_errors() {
    let (db, tenant_id, _user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let result = repo.get_by_token_hash(tenant_id, "never-existed").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn get_by_token_hash_expired_token_is_not_returned() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let hash = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() - Duration::seconds(1),
    )
    .await;

    let result = repo.get_by_token_hash(tenant_id, &hash).await;
    assert!(result.is_err(), "an expired token must not be returned");
}

#[tokio::test]
async fn get_by_token_hash_revoked_token_is_not_returned() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let hash = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;
    repo.revoke(tenant_id, &hash).await.unwrap();

    let result = repo.get_by_token_hash(tenant_id, &hash).await;
    assert!(result.is_err(), "a revoked token must not be returned");
}

// ---------------------------------------------------------------------------
// revoke() single-use semantics
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_twice_second_call_errors() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let hash = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;

    repo.revoke(tenant_id, &hash).await.unwrap();
    let second = repo.revoke(tenant_id, &hash).await;
    assert!(
        second.is_err(),
        "revoking an already-revoked token must error (single-use rotation)"
    );
}

#[tokio::test]
async fn revoke_unknown_hash_errors() {
    let (db, tenant_id, _user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let result = repo.revoke(tenant_id, "no-such-hash").await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// revoke_all_for_client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_all_for_client_revokes_only_that_clients_tokens() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let hash_a = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;
    let hash_b = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-b",
        Utc::now() + Duration::days(1),
    )
    .await;

    repo.revoke_all_for_client(tenant_id, "client-a")
        .await
        .unwrap();

    assert!(repo.get_by_token_hash(tenant_id, &hash_a).await.is_err());
    assert!(repo.get_by_token_hash(tenant_id, &hash_b).await.is_ok());
}

// ---------------------------------------------------------------------------
// delete_expired
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_expired_removes_expired_and_revoked_but_keeps_active() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let expired_hash = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() - Duration::seconds(1),
    )
    .await;
    let revoked_hash = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;
    repo.revoke(tenant_id, &revoked_hash).await.unwrap();
    let active_hash = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;

    let deleted_count = repo.delete_expired().await.unwrap();
    assert_eq!(deleted_count, 2, "expired + revoked rows should be purged");

    assert!(
        repo.get_by_token_hash(tenant_id, &expired_hash)
            .await
            .is_err()
    );
    assert!(
        repo.get_by_token_hash(tenant_id, &revoked_hash)
            .await
            .is_err()
    );
    assert!(
        repo.get_by_token_hash(tenant_id, &active_hash)
            .await
            .is_ok()
    );
}

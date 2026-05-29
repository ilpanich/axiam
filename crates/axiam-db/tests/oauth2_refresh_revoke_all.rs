//! Integration tests for `RefreshTokenRepository::revoke_all_for_user`.
//!
//! Verifies user-wide revocation, cross-user isolation, and idempotency.

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

/// Spin up in-memory DB and run migrations; create org + tenant + 2 users.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // tenant_id
    uuid::Uuid, // user_id_u
    uuid::Uuid, // user_id_v
) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org-rra".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant-rra".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let u = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "user-u-rra".into(),
            email: "u-rra@example.com".into(),
            password: "pass".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let v = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "user-v-rra".into(),
            email: "v-rra@example.com".into(),
            password: "pass".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, u.id, v.id)
}

/// Helper: insert a refresh token for a user and return its hash.
async fn insert_token(
    repo: &SurrealRefreshTokenRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> String {
    let hash = Uuid::new_v4().to_string();
    repo.create(CreateRefreshToken {
        tenant_id,
        user_id: Some(user_id),
        token_hash: hash.clone(),
        client_id: "test-client".into(),
        scopes: vec![],
        expires_at: Utc::now() + Duration::days(30),
    })
    .await
    .unwrap();
    hash
}

// ---------------------------------------------------------------------------
// Test: revoke_all_for_user revokes U's tokens, leaves V's alone
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oauth2_revoke_all_for_user() {
    let (db, tenant_id, user_u, user_v) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    let _hash_u1 = insert_token(&repo, tenant_id, user_u).await;
    let _hash_u2 = insert_token(&repo, tenant_id, user_u).await;
    let hash_v = insert_token(&repo, tenant_id, user_v).await;

    // Revoke all for U.
    let count = repo.revoke_all_for_user(tenant_id, user_u).await.unwrap();
    assert_eq!(count, 2, "should have revoked 2 tokens for user U");

    // V's token should still be valid (not revoked).
    let v_token = repo.get_by_token_hash(tenant_id, &hash_v).await;
    assert!(v_token.is_ok(), "user V's token should still be valid");
}

// ---------------------------------------------------------------------------
// Test: second call returns 0 (idempotent)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oauth2_revoke_all_idempotent() {
    let (db, tenant_id, user_u, _user_v) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);

    insert_token(&repo, tenant_id, user_u).await;

    // First call revokes the token.
    let first = repo.revoke_all_for_user(tenant_id, user_u).await.unwrap();
    assert_eq!(first, 1);

    // Second call — all tokens already revoked — returns 0.
    let second = repo.revoke_all_for_user(tenant_id, user_u).await.unwrap();
    assert_eq!(second, 0, "second call should be idempotent (no newly-revoked tokens)");
}

//! Additional `SurrealRefreshTokenRepository` coverage not exercised by
//! `oauth2_refresh_revoke_all.rs`: lookup failure modes (unknown/expired/
//! revoked), single-use `revoke()` semantics, `revoke_all_for_client`, and
//! `delete_expired`.

use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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
            kind: TenantKind::Standard,
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
        session_id: None,
        requested_userinfo_claims: Vec::new(),
        expires_at,
        resource: None,
        auth_time: None,
        acr: None,
        amr: Vec::new(),
        dpop_jkt: None,
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

    assert_eq!(
        repo.revoke_all_for_client(tenant_id, "client-a")
            .await
            .unwrap(),
        1
    );

    assert!(repo.get_by_token_hash(tenant_id, &hash_a).await.is_err());
    assert!(repo.get_by_token_hash(tenant_id, &hash_b).await.is_ok());
    assert_eq!(
        repo.revoke_all_for_client(tenant_id, "client-a")
            .await
            .unwrap(),
        0,
        "an already-revoked token is not counted again"
    );
}

// ---------------------------------------------------------------------------
// delete_expired
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_expired_removes_rows_expired_before_the_cutoff_and_keeps_the_rest() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);
    let cutoff = Utc::now() - Duration::days(7);

    // Expired well before the cutoff: swept, whether or not it was revoked.
    let long_expired = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        cutoff - Duration::hours(1),
    )
    .await;
    let long_expired_revoked = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        cutoff - Duration::hours(1),
    )
    .await;
    repo.revoke(tenant_id, &long_expired_revoked).await.unwrap();
    // Expired, but inside the retention: kept.
    let _inside_window = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        cutoff + Duration::hours(1),
    )
    .await;
    // Revoked with its expiry still ahead: kept (a replay must stay detectable).
    let revoked_live = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;
    repo.revoke(tenant_id, &revoked_live).await.unwrap();
    let active = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;

    let deleted = repo.delete_expired(cutoff).await.unwrap();
    assert_eq!(deleted, 2, "only the two rows expired before the cutoff");

    for gone in [&long_expired, &long_expired_revoked] {
        assert!(repo.get_by_token_hash(tenant_id, gone).await.is_err());
    }
    // The survivors are counted by the sweep itself: a second pass at the
    // same cutoff finds nothing more.
    assert!(repo.get_by_token_hash(tenant_id, &active).await.is_ok());
    assert_eq!(repo.delete_expired(cutoff).await.unwrap(), 0);
    // A later cutoff reaches the in-window row, and still not the live ones.
    assert_eq!(repo.delete_expired(Utc::now()).await.unwrap(), 1);
    assert!(repo.get_by_token_hash(tenant_id, &active).await.is_ok());
}

#[tokio::test]
async fn a_rotated_token_stays_a_detectable_replay_until_the_sweep_reaches_its_expiry() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);
    let cutoff = Utc::now() - Duration::days(7);

    let rotated = insert_token_expiring(
        &repo,
        tenant_id,
        user_id,
        "client-a",
        Utc::now() + Duration::days(1),
    )
    .await;
    repo.revoke_rotated(tenant_id, &rotated).await.unwrap();

    assert_eq!(repo.delete_expired(cutoff).await.unwrap(), 0);
    assert!(
        repo.find_rotated(tenant_id, &rotated)
            .await
            .unwrap()
            .is_some(),
        "the sweep must not erase the evidence that makes a replay detectable"
    );
}

// ---------------------------------------------------------------------------
// delete_all_for_user
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_all_for_user_removes_every_row_of_that_user_only_and_is_idempotent() {
    let (db, tenant_id, user_id) = setup().await;
    let repo = SurrealRefreshTokenRepository::new(db);
    let later = Utc::now() + Duration::days(1);

    let live = insert_token_expiring(&repo, tenant_id, user_id, "client-a", later).await;
    let revoked = insert_token_expiring(&repo, tenant_id, user_id, "client-b", later).await;
    repo.revoke(tenant_id, &revoked).await.unwrap();
    let rotated = insert_token_expiring(&repo, tenant_id, user_id, "client-a", later).await;
    repo.revoke_rotated(tenant_id, &rotated).await.unwrap();
    // Another user in the same tenant.
    let other_user = Uuid::new_v4();
    let others = insert_token_expiring(&repo, tenant_id, other_user, "client-a", later).await;

    assert_eq!(
        repo.delete_all_for_user(tenant_id, user_id).await.unwrap(),
        3
    );
    for gone in [&live, &revoked, &rotated] {
        assert!(repo.get_by_token_hash(tenant_id, gone).await.is_err());
    }
    assert!(
        repo.find_rotated(tenant_id, &rotated)
            .await
            .unwrap()
            .is_none()
    );
    assert!(repo.get_by_token_hash(tenant_id, &others).await.is_ok());
    // A re-entered erasure finds nothing and is not an error.
    assert_eq!(
        repo.delete_all_for_user(tenant_id, user_id).await.unwrap(),
        0
    );
    // Another tenant's rows with the same user id are out of reach.
    assert_eq!(
        repo.delete_all_for_user(Uuid::new_v4(), other_user)
            .await
            .unwrap(),
        0
    );
    assert!(repo.get_by_token_hash(tenant_id, &others).await.is_ok());
}

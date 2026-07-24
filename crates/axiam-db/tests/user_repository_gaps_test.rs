//! Coverage for `SurrealUserRepository` branches not exercised by
//! `user_repository_test.rs` or the in-src `user.rs` test module:
//! not-found arms (get_by_username/email, update, delete), the
//! `update_totp_step` compare-and-set win/lose branches,
//! `increment_failed_logins`' lockout-threshold trigger, and
//! `clear_deletion_pending`.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup() -> (Surreal<surrealdb::engine::local::Db>, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id)
}

fn test_password() -> String {
    std::env::var("AXIAM_TEST_PASSWORD").unwrap_or_else(|_| ["Super", "Secret123!"].concat())
}

// ---------------------------------------------------------------------------
// Not-found branches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn not_found_branches() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.get_by_id(tenant_id, missing).await.is_err());
    assert!(
        repo.get_by_username(tenant_id, "no-such-user")
            .await
            .is_err()
    );
    assert!(
        repo.get_by_email(tenant_id, "no-such@example.com")
            .await
            .is_err()
    );
    assert!(
        repo.update(
            tenant_id,
            missing,
            axiam_core::models::user::UpdateUser {
                username: Some("x".into()),
                ..Default::default()
            },
        )
        .await
        .is_err()
    );
    assert!(repo.delete(tenant_id, missing).await.is_err());
}

// ---------------------------------------------------------------------------
// update_totp_step CAS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_totp_step_cas_win_and_lose() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "totp-user".into(),
            email: "totp-user@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    // First-ever verification: stored step is NONE, any step wins.
    let won = repo
        .update_totp_step(tenant_id, user.id, 100)
        .await
        .unwrap();
    assert!(won, "first CAS write (from NONE) must win");

    // Replaying the SAME step must lose (not strictly greater).
    let replay = repo
        .update_totp_step(tenant_id, user.id, 100)
        .await
        .unwrap();
    assert!(!replay, "replaying the same step must lose the CAS");

    // A LOWER step must also lose.
    let lower = repo.update_totp_step(tenant_id, user.id, 50).await.unwrap();
    assert!(!lower, "a lower step must lose the CAS");

    // A strictly higher step must win.
    let higher = repo
        .update_totp_step(tenant_id, user.id, 101)
        .await
        .unwrap();
    assert!(higher, "a strictly higher step must win the CAS");
}

// ---------------------------------------------------------------------------
// increment_failed_logins lockout threshold
// ---------------------------------------------------------------------------

#[tokio::test]
async fn increment_failed_logins_locks_after_threshold() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "lockout-user".into(),
            email: "lockout-user@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let threshold = 3u32;
    // Fail twice — below threshold, no lock yet.
    for _ in 0..2 {
        repo.increment_failed_logins(tenant_id, user.id, threshold, 30, 2.0, 3600)
            .await
            .unwrap();
    }
    let mid = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(mid.failed_login_attempts, 2);
    assert!(
        mid.locked_until.is_none(),
        "account must not be locked before reaching the threshold"
    );

    // Third failure crosses the threshold — lock must be set.
    repo.increment_failed_logins(tenant_id, user.id, threshold, 30, 2.0, 3600)
        .await
        .unwrap();
    let locked = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(locked.failed_login_attempts, 3);
    assert!(
        locked.locked_until.is_some(),
        "account must be locked once failed_login_attempts reaches the threshold"
    );
    assert!(locked.last_failed_login_at.is_some());
}

// ---------------------------------------------------------------------------
// clear_deletion_pending
// ---------------------------------------------------------------------------

#[tokio::test]
async fn clear_deletion_pending_reactivates_user() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "cancel-deletion".into(),
            email: "cancel-deletion@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let purge_at = chrono::Utc::now() + chrono::Duration::days(30);
    repo.mark_deletion_pending(tenant_id, user.id, purge_at)
        .await
        .unwrap();
    let pending = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert!(pending.deletion_pending);
    assert_eq!(pending.status, UserStatus::Inactive);

    repo.clear_deletion_pending(tenant_id, user.id)
        .await
        .unwrap();

    let cleared = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert!(!cleared.deletion_pending);
    assert!(cleared.scheduled_purge_at.is_none());
    assert_eq!(cleared.status, UserStatus::Active);
}

// ---------------------------------------------------------------------------
// update(): mfa_secret Some(Some)/Some(None) clear, metadata, status, and
// remaining scalar fields not covered by user_repository_test.rs::update_user.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_sets_and_clears_mfa_secret_and_metadata() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "mfa-user".into(),
            email: "mfa-user@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    // Set mfa_secret and mfa_enabled and metadata together.
    let updated = repo
        .update(
            tenant_id,
            user.id,
            axiam_core::models::user::UpdateUser {
                mfa_enabled: Some(true),
                mfa_secret: Some(Some("encrypted-secret".into())),
                metadata: Some(serde_json::json!({"k": "v"})),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(updated.mfa_enabled);
    assert_eq!(updated.mfa_secret.as_deref(), Some("encrypted-secret"));
    assert_eq!(updated.metadata, serde_json::json!({"k": "v"}));

    // Clear mfa_secret explicitly (Some(None) => SQL NONE).
    let cleared = repo
        .update(
            tenant_id,
            user.id,
            axiam_core::models::user::UpdateUser {
                mfa_secret: Some(None),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(cleared.mfa_secret.is_none());
}

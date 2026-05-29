//! Integration tests for `SessionRepository::invalidate_user_sessions_except`.
//!
//! Verifies that selective session invalidation preserves the current session
//! and does not affect other users (cross-user isolation).

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealTenantRepository,
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
            slug: "test-org-se".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant-se".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let u = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "user-u".into(),
            email: "u@example.com".into(),
            password: "pass".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let v = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "user-v".into(),
            email: "v@example.com".into(),
            password: "pass".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, u.id, v.id)
}

/// Helper: create a session for a user and return the session id.
async fn create_session(
    repo: &SurrealSessionRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Uuid {
    repo.create(CreateSession {
        tenant_id,
        user_id,
        token_hash: Uuid::new_v4().to_string(),
        ip_address: None,
        user_agent: None,
        expires_at: Utc::now() + Duration::hours(1),
    })
    .await
    .unwrap()
    .id
}

// ---------------------------------------------------------------------------
// Test: current session is preserved; others are deleted; count is correct
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalidate_except_preserves_current() {
    let (db, tenant_id, user_id, _) = setup().await;
    let repo = SurrealSessionRepository::new(db);

    let session_a = create_session(&repo, tenant_id, user_id).await;
    let session_b = create_session(&repo, tenant_id, user_id).await;
    let session_c = create_session(&repo, tenant_id, user_id).await;

    // Invalidate all except B.
    let deleted = repo
        .invalidate_user_sessions_except(tenant_id, user_id, session_b)
        .await
        .unwrap();

    assert_eq!(deleted, 2, "should have deleted 2 sessions (A and C)");

    // B must still be alive.
    let still_alive = repo.get_by_id(tenant_id, session_b).await;
    assert!(still_alive.is_ok(), "current session B should still exist");

    // A and C must be gone.
    let a_gone = repo.get_by_id(tenant_id, session_a).await;
    assert!(a_gone.is_err(), "session A should have been deleted");

    let c_gone = repo.get_by_id(tenant_id, session_c).await;
    assert!(c_gone.is_err(), "session C should have been deleted");
}

// ---------------------------------------------------------------------------
// Test: other users' sessions are untouched
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalidate_except_other_users_untouched() {
    let (db, tenant_id, user_u, user_v) = setup().await;
    let repo = SurrealSessionRepository::new(db);

    let session_u = create_session(&repo, tenant_id, user_u).await;
    let session_v = create_session(&repo, tenant_id, user_v).await;

    // Invalidate U's sessions except session_u (which is the only one anyway).
    let deleted = repo
        .invalidate_user_sessions_except(tenant_id, user_u, session_u)
        .await
        .unwrap();

    assert_eq!(
        deleted, 0,
        "no U sessions should be deleted (only the preserved one)"
    );

    // V's session must be untouched.
    let v_alive = repo.get_by_id(tenant_id, session_v).await;
    assert!(v_alive.is_ok(), "user V's session should be untouched");
}

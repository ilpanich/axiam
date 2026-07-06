//! Integration tests for `POST /api/v1/auth/password/change` (Task 3 — D-14, D-15).
//!
//! Scenarios:
//! - Correct current password + policy-compliant new password → 204.
//! - Caller's session (A) remains valid after the change.
//! - Other concurrent session (B) is invalidated after the change → 401.
//! - Wrong current password → 401, password unchanged.
//! - Weak new password (policy violation) → 422.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const TEST_PEER: &str = "127.0.0.1:12345";
/// Test-only placeholder — not a real credential. gitleaks:allow
const INITIAL_PASSWORD: &str = "InitialPassw0rdStrong";
const NEW_PASSWORD: &str = "NewStr0ngPassword123X";
const WEAK_PASSWORD: &str = "aaa";

type TestDb = surrealdb::engine::local::Db;

// Test-only Ed25519 keypair with no real-world value. nosemgrep
fn test_auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
            "-----END PRIVATE KEY-----"
        )
        .into(),
        jwt_public_key_pem: concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
            "-----END PUBLIC KEY-----"
        )
        .into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "pw-change-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "pw-change-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Seed effective settings so the password policy resolves.
    let settings_repo = SurrealSettingsRepository::new(db.clone());
    settings_repo
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: INITIAL_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(
                    Arc::new(SurrealSessionRepository::new($db.clone()))
                        as Arc<dyn axiam_api_rest::SessionValidator>,
                ))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

/// Log in as alice and return (access_cookie, csrf_cookie), or None on failure.
async fn login(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
    password: &str,
) -> Option<(String, String)> {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": password,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    if resp.status().as_u16() != 200 {
        return None;
    }
    let access = resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_access")
        .map(|c| c.value().to_owned())?;
    let csrf = resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_csrf")
        .map(|c| c.value().to_owned())?;
    Some((access, csrf))
}

/// Call `GET /api/v1/auth/me` and return the HTTP status code.
async fn me_status(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    access: &str,
    csrf: &str,
) -> u16 {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf.to_owned()))
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

/// Helper: POST /api/v1/auth/password/change and return the HTTP status.
async fn change_password(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    access: &str,
    csrf: &str,
    current_password: &str,
    new_password: &str,
) -> u16 {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/password/change")
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf.to_owned()))
        .set_json(serde_json::json!({
            "current_password": current_password,
            "new_password": new_password,
        }))
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Correct current password + policy-compliant new password → 204.
#[actix_rt::test]
async fn change_password_success_returns_204() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("login must succeed");

    let status = change_password(&app, &access, &csrf, INITIAL_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(status, 204, "correct change must return 204");
}

/// Session A (the one that performed the change) remains usable after the
/// change — D-15: current session preserved.
#[actix_rt::test]
async fn current_session_still_works_after_change() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access_a, csrf_a) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("login must succeed");

    let status = change_password(&app, &access_a, &csrf_a, INITIAL_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(status, 204);

    // Session A must still work.
    assert_eq!(
        me_status(&app, &access_a, &csrf_a).await,
        200,
        "session A must still work after own password change"
    );
}

/// Session B (a concurrent session) is revoked after a password change from
/// session A — D-14: all other sessions die.
#[actix_rt::test]
async fn other_session_revoked_after_change() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access_a, csrf_a) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session A login must succeed");
    let (access_b, csrf_b) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session B login must succeed");

    // Both sessions work before the change.
    assert_eq!(me_status(&app, &access_a, &csrf_a).await, 200);
    assert_eq!(me_status(&app, &access_b, &csrf_b).await, 200);

    // Change password from session A.
    let status = change_password(&app, &access_a, &csrf_a, INITIAL_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(status, 204);

    // Session B must now be revoked.
    assert_eq!(
        me_status(&app, &access_b, &csrf_b).await,
        401,
        "session B must be revoked after password change from A"
    );
}

/// Wrong current password → 401; original password unchanged.
#[actix_rt::test]
async fn wrong_current_password_returns_401_and_leaves_password_unchanged() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("login must succeed");

    let status = change_password(&app, &access, &csrf, "WrongCurrentPw123", NEW_PASSWORD).await;
    assert_eq!(status, 401, "wrong current password must return 401");

    // Old password must still work.
    let still_works = login(&app, org_id, tenant_id, INITIAL_PASSWORD).await;
    assert!(
        still_works.is_some(),
        "original password must still work after failed change"
    );
}

/// Weak new password (fails password policy) → 422.
#[actix_rt::test]
async fn weak_new_password_returns_422() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access, csrf) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("login must succeed");

    let status = change_password(&app, &access, &csrf, INITIAL_PASSWORD, WEAK_PASSWORD).await;
    assert_eq!(status, 422, "policy-failing new password must return 422");
}

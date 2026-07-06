//! Integration test for password-reset session revocation (Task 3 — D-16).
//!
//! Scenario: a user has an active session (cookie A). A password reset is
//! confirmed (caller is unauthenticated, proving possession of the reset
//! token). After the reset, cookie A must be rejected with 401 — ALL of the
//! user's sessions die because there is no "current" session to preserve.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, PasswordResetTokenRepository, SettingsRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPasswordResetTokenRepository, SurrealSessionRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const TEST_PEER: &str = "127.0.0.1:12345";
/// Test-only placeholder — not a real credential. gitleaks:allow
const INITIAL_PASSWORD: &str = "InitialPassw0rdStrong";
const NEW_PASSWORD: &str = "ResetStr0ngPassword99";

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
            slug: "reset-revoke-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "reset-revoke-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

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

/// Log in and return (access_cookie, csrf_cookie).
async fn login(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
) -> (String, String) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": INITIAL_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "login must succeed");
    let access = resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_access")
        .map(|c| c.value().to_owned())
        .expect("axiam_access cookie");
    let csrf = resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_csrf")
        .map(|c| c.value().to_owned())
        .expect("axiam_csrf cookie");
    (access, csrf)
}

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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// A previously-issued session cookie must return 401 after a password reset
/// confirm — D-16: password reset invalidates ALL of the user's sessions.
#[actix_rt::test]
async fn password_reset_confirm_revokes_existing_sessions() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Establish an active session.
    let (access, csrf) = login(&app, org_id, tenant_id).await;
    assert_eq!(
        me_status(&app, &access, &csrf).await,
        200,
        "session must work before reset"
    );

    // Mint a reset token directly (email delivery is not wired in tests).
    let raw_token = generate_refresh_token();
    let token_hash = hash_refresh_token(&raw_token);
    let token_repo = SurrealPasswordResetTokenRepository::new(db.clone());
    token_repo
        .create(CreatePasswordResetToken {
            tenant_id,
            user_id,
            token_hash,
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    // Confirm the reset (unauthenticated endpoint).
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset/confirm")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "token": raw_token,
            "new_password": NEW_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "reset confirm must succeed (200)"
    );

    // The previously-issued cookie must now be rejected.
    assert_eq!(
        me_status(&app, &access, &csrf).await,
        401,
        "session cookie must be revoked after password reset"
    );
}

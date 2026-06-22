//! REQ-7 session lifecycle end-to-end tests.
//!
//! Covers every acceptance criterion in REQUIREMENTS.md §REQ-7:
//!   - password_change_revokes_other_sessions (D-14)
//!   - password_change_revokes_oauth2_refresh_tokens (D-15 two-chokepoint fix, RESEARCH §4)
//!   - password_reset_confirm_revokes_all_sessions (D-16)
//!   - password_reset_confirm_revokes_oauth2_refresh_tokens (D-16 OAuth2 chokepoint)
//!   - mfa_reset_revokes_sessions (D-17)
//!   - password_change_wrong_current_password_returns_401_and_keeps_sessions
//!   - password_change_weak_new_password_returns_422_and_keeps_sessions
//!
//! Tests follow the exact pattern of crates/axiam-api-rest/tests/password_change.rs
//! and crates/axiam-api-rest/tests/password_reset_revokes_sessions.rs.
//!
//! CI-authoritative: these tests are gated on the xmlsec-enabled CI build that can
//! compile axiam-server. The local-compile limitation (samael/libxml version skew)
//! is documented in 04-06-SUMMARY.md.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
use axiam_auth::{AuthService, MfaMethodService};
use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, PasswordResetTokenRepository, RefreshTokenRepository,
    SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository,
    SurrealPasswordHistoryRepository, SurrealPasswordResetTokenRepository,
    SurrealPermissionRepository, SurrealRefreshTokenRepository, SurrealRoleRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use chrono::{Duration, Utc};
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
            slug: format!("req7-org-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: format!("req7-tenant-{}", Uuid::new_v4()),
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

fn make_auth_service(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
) -> AuthService<
    SurrealUserRepository<TestDb>,
    SurrealSessionRepository<TestDb>,
    SurrealFederationLinkRepository<TestDb>,
    SurrealRefreshTokenRepository<TestDb>,
> {
    AuthService::new(
        SurrealUserRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        auth.clone(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    )
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(make_auth_service(&$db, &$auth)))
                .app_data(web::Data::new(SurrealUserRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealSettingsRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealRoleRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealPermissionRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealSessionRepository::new($db.clone())))
                .app_data(web::Data::new(Arc::new(SurrealSessionRepository::new(
                    $db.clone(),
                ))
                    as Arc<dyn axiam_api_rest::SessionValidator>))
                .app_data(web::Data::new(SurrealRefreshTokenRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealPasswordHistoryRepository::new(
                    $db.clone(),
                )))
                // confirm_reset handler also needs these (token + federation link
                // repos + an http client for the optional HIBP check).
                .app_data(web::Data::new(
                    axiam_db::SurrealPasswordResetTokenRepository::new($db.clone()),
                ))
                .app_data(web::Data::new(
                    axiam_db::SurrealFederationLinkRepository::new($db.clone()),
                ))
                .app_data(web::Data::new(reqwest::Client::new()))
                .app_data(web::Data::new(MfaMethodService::new(
                    SurrealUserRepository::new($db.clone()),
                    SurrealWebauthnCredentialRepository::new($db.clone()),
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

/// T-REQ-7-01: password change revokes other sessions (D-14).
#[actix_rt::test]
async fn password_change_revokes_other_sessions() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access_a, csrf_a) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session A login must succeed");
    let (access_b, csrf_b) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session B login must succeed");

    assert_eq!(me_status(&app, &access_a, &csrf_a).await, 200);
    assert_eq!(me_status(&app, &access_b, &csrf_b).await, 200);

    let status = change_password(&app, &access_a, &csrf_a, INITIAL_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(status, 204, "password change must return 204");

    // Session A preserved (current session — D-15).
    assert_eq!(
        me_status(&app, &access_a, &csrf_a).await,
        200,
        "session A must still work after own password change"
    );
    // Session B revoked.
    assert_eq!(
        me_status(&app, &access_b, &csrf_b).await,
        401,
        "session B must be revoked after password change from A"
    );
}

/// T-REQ-7-02: password change revokes OAuth2 refresh tokens (two-chokepoint fix, RESEARCH §4).
#[actix_rt::test]
async fn password_change_revokes_oauth2_refresh_tokens() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db.clone(), auth);

    // Establish a session (login).
    let (access_a, csrf_a) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("login must succeed");

    // Insert a fake OAuth2 refresh token for the user (simulates
    // authorization-code flow token issuance).
    let raw_token = generate_refresh_token();
    let token_hash = hash_refresh_token(&raw_token);
    let rt_repo = SurrealRefreshTokenRepository::new(db.clone());
    rt_repo
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: token_hash.clone(),
            client_id: "test-oauth2-client".into(),
            user_id: Some(user_id),
            scopes: vec!["openid".into(), "profile".into()],
            expires_at: Utc::now() + Duration::hours(24),
        })
        .await
        .expect("create refresh token");

    // Verify token exists in DB (not revoked, not expired).
    let token_before = rt_repo.get_by_token_hash(tenant_id, &token_hash).await;
    assert!(
        token_before.is_ok(),
        "refresh token must exist before change: {token_before:?}"
    );

    // Change password from session A.
    let status = change_password(&app, &access_a, &csrf_a, INITIAL_PASSWORD, NEW_PASSWORD).await;
    assert_eq!(status, 204);

    // OAuth2 refresh token must now be revoked or deleted.
    // get_by_token_hash only returns non-revoked tokens, so if the token was
    // revoked (or deleted) it will return NotFound — which is the success case.
    let token_after = rt_repo.get_by_token_hash(tenant_id, &token_hash).await;
    assert!(
        token_after.is_err(),
        "OAuth2 refresh token must be revoked or deleted after password change; \
         found: {token_after:?}"
    );
}

/// T-REQ-7-03: password reset confirm revokes all sessions (D-16).
#[actix_rt::test]
async fn password_reset_confirm_revokes_all_sessions() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db.clone(), auth);

    // Establish sessions A and B.
    let (access_a, csrf_a) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session A");
    let (access_b, csrf_b) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session B");

    assert_eq!(me_status(&app, &access_a, &csrf_a).await, 200);
    assert_eq!(me_status(&app, &access_b, &csrf_b).await, 200);

    // Mint a reset token directly.
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

    // Confirm the reset.
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
    assert_eq!(resp.status().as_u16(), 200, "reset confirm must succeed");

    // Both sessions must be revoked (no current session on reset — D-16).
    assert_eq!(
        me_status(&app, &access_a, &csrf_a).await,
        401,
        "session A must be revoked after password reset"
    );
    assert_eq!(
        me_status(&app, &access_b, &csrf_b).await,
        401,
        "session B must be revoked after password reset"
    );
}

/// T-REQ-7-04: password reset confirm revokes OAuth2 refresh tokens (D-16 OAuth2 chokepoint).
#[actix_rt::test]
async fn password_reset_confirm_revokes_oauth2_refresh_tokens() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db.clone(), auth);

    // Login to establish a session.
    let (_access, _csrf) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("login");

    // Insert an OAuth2 refresh token.
    let raw_token = generate_refresh_token();
    let token_hash = hash_refresh_token(&raw_token);
    let rt_repo = SurrealRefreshTokenRepository::new(db.clone());
    rt_repo
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: token_hash.clone(),
            client_id: "test-client".into(),
            user_id: Some(user_id),
            scopes: vec!["openid".into()],
            expires_at: Utc::now() + Duration::hours(24),
        })
        .await
        .expect("create oauth2 refresh token");

    // Mint a password reset token.
    let reset_raw = generate_refresh_token();
    let reset_hash = hash_refresh_token(&reset_raw);
    let token_repo = SurrealPasswordResetTokenRepository::new(db.clone());
    token_repo
        .create(CreatePasswordResetToken {
            tenant_id,
            user_id,
            token_hash: reset_hash,
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    // Confirm the reset.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset/confirm")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "token": reset_raw,
            "new_password": NEW_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // OAuth2 refresh token must be revoked or deleted.
    // get_by_token_hash only returns non-revoked tokens; NotFound = revoked/deleted = success.
    let token_after = rt_repo.get_by_token_hash(tenant_id, &token_hash).await;
    assert!(
        token_after.is_err(),
        "OAuth2 refresh token must be revoked or deleted after password reset; \
         found: {token_after:?}"
    );
}

/// T-REQ-7-05: MFA reset revokes all sessions (D-17).
#[actix_rt::test]
async fn mfa_reset_revokes_sessions() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db.clone(), auth);

    let (access, csrf) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("login");
    assert_eq!(me_status(&app, &access, &csrf).await, 200);

    // Admin MFA reset — POST /api/v1/users/:id/reset-mfa.
    // Uses AllowAllAuthzChecker, so RBAC passes for any token.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let mfa_reset_status = resp.status().as_u16();
    assert!(
        mfa_reset_status == 200 || mfa_reset_status == 204,
        "MFA reset must return 200 or 204, got {mfa_reset_status}"
    );

    // The pre-reset session must be invalidated.
    assert_eq!(
        me_status(&app, &access, &csrf).await,
        401,
        "session must be revoked after MFA reset"
    );
}

/// T-REQ-7-06: wrong current password → 401 and sessions NOT revoked.
#[actix_rt::test]
async fn password_change_wrong_current_password_returns_401_and_keeps_sessions() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access_a, csrf_a) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session A");
    let (access_b, csrf_b) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session B");

    let status = change_password(&app, &access_a, &csrf_a, "WrongCurrentPw123", NEW_PASSWORD).await;
    assert_eq!(status, 401, "wrong current password must return 401");

    // Both sessions must still work (no side-effect on failed change).
    assert_eq!(
        me_status(&app, &access_a, &csrf_a).await,
        200,
        "session A must not be revoked on failed change"
    );
    assert_eq!(
        me_status(&app, &access_b, &csrf_b).await,
        200,
        "session B must not be revoked on failed change"
    );
}

/// T-REQ-7-07: weak new password → 422 and sessions NOT revoked.
#[actix_rt::test]
async fn password_change_weak_new_password_returns_422_and_keeps_sessions() {
    let (db, org_id, tenant_id, _uid) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access_a, csrf_a) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session A");
    let (access_b, csrf_b) = login(&app, org_id, tenant_id, INITIAL_PASSWORD)
        .await
        .expect("session B");

    let status = change_password(&app, &access_a, &csrf_a, INITIAL_PASSWORD, WEAK_PASSWORD).await;
    assert_eq!(status, 422, "weak new password must return 422");

    // Both sessions must still work (no side-effect on policy violation).
    assert_eq!(
        me_status(&app, &access_a, &csrf_a).await,
        200,
        "session A must not be revoked on policy violation"
    );
    assert_eq!(
        me_status(&app, &access_b, &csrf_b).await,
        200,
        "session B must not be revoked on policy violation"
    );
}

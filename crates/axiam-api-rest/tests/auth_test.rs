//! Integration tests for authentication endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::{AuthService, MfaMethodService};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealSessionRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebauthnCredentialRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

fn test_keypair() -> (String, String) {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    (private_key.into(), public_key.into())
}

fn test_auth_config() -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
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
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Activate the user (created as PendingVerification by default).
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
> {
    AuthService::new(
        SurrealUserRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        auth.clone(),
    )
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(make_auth_service(&$db, &$auth)))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealSettingsRepository::new($db.clone())))
                .app_data(web::Data::new(MfaMethodService::new(
                    SurrealUserRepository::new($db.clone()),
                    SurrealWebauthnCredentialRepository::new($db.clone()),
                )))
                .configure(register_api_v1_routes::<TestDb>),
        )
        .await
    };
}

#[actix_rt::test]
async fn login_with_valid_credentials_returns_200() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert!(body["session_id"].is_string());
    assert!(body["expires_in"].is_number());
}

#[actix_rt::test]
async fn login_with_invalid_password_returns_401() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "wrongpassword1"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn login_with_nonexistent_user_returns_401() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "nobody",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn logout_returns_204() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // First login to get a session
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let login_body: serde_json::Value = test::read_body_json(resp).await;
    let access_token = login_body["access_token"].as_str().unwrap();
    let session_id = login_body["session_id"].as_str().unwrap();

    // Now logout
    let req = test::TestRequest::post()
        .uri("/auth/logout")
        .insert_header(("Authorization", format!("Bearer {access_token}")))
        .set_json(serde_json::json!({ "session_id": session_id }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

#[actix_rt::test]
async fn refresh_returns_new_tokens() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login first
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let login_body: serde_json::Value = test::read_body_json(resp).await;
    let refresh_token = login_body["refresh_token"].as_str().unwrap();

    // Refresh
    let req = test::TestRequest::post()
        .uri("/auth/refresh")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "refresh_token": refresh_token
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    // New refresh token should differ from original (single-use rotation)
    assert_ne!(body["refresh_token"].as_str().unwrap(), refresh_token);
}

#[actix_rt::test]
async fn refresh_with_invalid_token_returns_401() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/auth/refresh")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "refresh_token": "invalid-token-value"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should be 401 Unauthorized when the refresh token is invalid
    let status = resp.status().as_u16();
    assert_eq!(status, 401, "Expected 401, got {status}");
}

// -----------------------------------------------------------------------
// T14.1 — MFA Enforcement REST
// -----------------------------------------------------------------------

const TEST_MFA_KEY: [u8; 32] = [42u8; 32];

/// Auth config with MFA encryption key enabled (needed for MFA flows).
fn mfa_auth_config() -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        mfa_encryption_key: Some(TEST_MFA_KEY),
        totp_issuer: "AXIAM-Test".into(),
        ..AuthConfig::default()
    }
}

/// Save org settings with MFA enforcement enabled.
async fn enable_mfa_enforcement(db: &Surreal<TestDb>, org_id: Uuid) {
    let settings_repo = SurrealSettingsRepository::new(db.clone());
    let mut defaults = system_defaults();
    defaults.mfa_enforced = true;
    settings_repo
        .set_org_settings(org_id, defaults)
        .await
        .unwrap();
}

#[actix_rt::test]
async fn mfa_enforcement_login_returns_403_with_setup_token() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = mfa_auth_config();

    // Enable MFA enforcement in org settings.
    enable_mfa_enforcement(&db, org_id).await;

    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["mfa_setup_required"], true);
    assert!(
        body["setup_token"].is_string(),
        "expected setup_token in response"
    );
    assert!(
        !body["setup_token"].as_str().unwrap().is_empty(),
        "setup_token should be non-empty"
    );
}

#[actix_rt::test]
async fn mfa_setup_enroll_with_setup_token_returns_200() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = mfa_auth_config();
    enable_mfa_enforcement(&db, org_id).await;
    let app = test_app!(db, auth);

    // Login to get setup_token.
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let setup_token = body["setup_token"].as_str().unwrap();

    // Enroll with setup_token.
    let req = test::TestRequest::post()
        .uri("/auth/mfa/setup/enroll")
        .set_json(serde_json::json!({ "setup_token": setup_token }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["secret_base32"].is_string());
    assert!(
        body["totp_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/")
    );
}

#[actix_rt::test]
async fn mfa_setup_full_flow_returns_tokens() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = mfa_auth_config();
    enable_mfa_enforcement(&db, org_id).await;
    let app = test_app!(db, auth);

    // Step 1: Login → 403 with setup_token.
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let setup_token = body["setup_token"].as_str().unwrap().to_string();

    // Step 2: Enroll → get secret.
    let req = test::TestRequest::post()
        .uri("/auth/mfa/setup/enroll")
        .set_json(serde_json::json!({ "setup_token": &setup_token }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let secret_base32 = body["secret_base32"].as_str().unwrap();

    // Step 3: Generate TOTP code.
    let secret = totp_rs::Secret::Encoded(secret_base32.to_string());
    let secret_bytes = secret.to_bytes().unwrap();
    let totp = totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some("AXIAM-Test".into()),
        "alice@example.com".into(),
    )
    .unwrap();
    let code = totp.generate_current().unwrap();

    // Step 4: Confirm → 200 with tokens.
    let req = test::TestRequest::post()
        .uri("/auth/mfa/setup/confirm")
        .set_json(serde_json::json!({
            "setup_token": &setup_token,
            "totp_code": code
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert!(body["session_id"].is_string());
    assert!(body["expires_in"].is_number());
}

#[actix_rt::test]
async fn reset_mfa_requires_authentication() {
    let (db, _org_id, _tenant_id, user_id) = setup_db().await;
    let auth = mfa_auth_config();
    let app = test_app!(db, auth);

    // POST without Authorization header → 401.
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "expected 401 without auth header"
    );
}

#[actix_rt::test]
async fn reset_mfa_returns_403_until_rbac() {
    let (db, org_id, tenant_id, _admin_user_id) = setup_db().await;
    let auth = mfa_auth_config();

    // Create a second user to be the target of the reset.
    let user_repo = SurrealUserRepository::new(db.clone());
    let target = user_repo
        .create(axiam_core::models::user::CreateUser {
            tenant_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Activate the target user.
    user_repo
        .update(
            tenant_id,
            target.id,
            axiam_core::models::user::UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let app = test_app!(db, auth);

    // Login as alice (admin) to get an access token.
    let req = test::TestRequest::post()
        .uri("/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let access_token = body["access_token"].as_str().unwrap();

    // Reset MFA for the target user.
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/users/{}/reset-mfa", target.id))
        .insert_header(("Authorization", format!("Bearer {access_token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "expected 403 — MFA reset is disabled until RBAC is implemented"
    );
}

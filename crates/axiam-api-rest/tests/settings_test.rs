//! Integration tests for security settings endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
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
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(user_id, tenant_id, org_id, &[], auth).unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealSettingsRepository::new($db.clone())))
                .configure(register_api_v1_routes::<TestDb>),
        )
        .await
    };
}

// -----------------------------------------------------------------------
// GET /api/v1/organizations/:org_id/settings
// -----------------------------------------------------------------------

#[actix_rt::test]
async fn get_org_settings_returns_defaults() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    // System defaults: min_length = 12
    assert_eq!(body["password"]["min_length"], 12);
    assert_eq!(body["scope"], "Org");
}

// -----------------------------------------------------------------------
// PUT /api/v1/organizations/:org_id/settings
// -----------------------------------------------------------------------

#[actix_rt::test]
async fn set_org_settings_returns_200() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "min_length": 16,
            "require_uppercase": true,
            "require_lowercase": true,
            "require_digits": true,
            "require_symbols": true,
            "password_history_count": 10,
            "hibp_check_enabled": true,
            "mfa_enforced": true,
            "mfa_challenge_lifetime_secs": 300,
            "max_failed_login_attempts": 3,
            "lockout_duration_secs": 600,
            "lockout_backoff_multiplier": 2.0,
            "max_lockout_duration_secs": 3600,
            "access_token_lifetime_secs": 900,
            "refresh_token_lifetime_secs": 2592000,
            "email_verification_required": true,
            "email_verification_grace_period_hours": 24,
            "default_cert_validity_days": 365,
            "max_cert_validity_days": 730,
            "admin_notifications_enabled": true
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["password"]["min_length"], 16);
    assert_eq!(body["password"]["require_symbols"], true);
    assert_eq!(body["mfa"]["mfa_enforced"], true);
    assert_eq!(body["scope"], "Org");
}

// -----------------------------------------------------------------------
// GET /api/v1/settings (tenant effective)
// -----------------------------------------------------------------------

#[actix_rt::test]
async fn get_tenant_settings_inherits_from_org() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    // No tenant overrides → inherits org defaults
    assert_eq!(body["password"]["min_length"], 12);
    // Must always be tenant-scoped even when inheriting from org
    assert_eq!(body["scope"], "Tenant");
    assert_eq!(body["scope_id"], tenant_id.to_string());
}

// -----------------------------------------------------------------------
// PUT /api/v1/settings (valid — more restrictive)
// -----------------------------------------------------------------------

#[actix_rt::test]
async fn set_tenant_settings_more_restrictive_ok() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Set more restrictive overrides
    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "min_length": 16,
            "access_token_lifetime_secs": 600,
            "max_failed_login_attempts": 3
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["password"]["min_length"], 16);
    assert_eq!(body["token"]["access_token_lifetime_secs"], 600);
    assert_eq!(body["lockout"]["max_failed_login_attempts"], 3);
    assert_eq!(body["scope"], "Tenant");
}

// -----------------------------------------------------------------------
// PUT /api/v1/settings (invalid — less restrictive)
// -----------------------------------------------------------------------

#[actix_rt::test]
async fn set_tenant_settings_less_restrictive_returns_400() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Try less restrictive: shorter password, longer tokens
    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "min_length": 4,
            "access_token_lifetime_secs": 9999
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let msg = body["message"].as_str().unwrap();
    assert!(msg.contains("min_length"), "got: {msg}");
    assert!(msg.contains("access_token_lifetime_secs"), "got: {msg}");
}

// -----------------------------------------------------------------------
// GET /api/v1/settings reflects overrides after PUT
// -----------------------------------------------------------------------

#[actix_rt::test]
async fn get_tenant_settings_reflects_overrides() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Set override
    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "min_length": 20,
            "mfa_enforced": true
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Read back
    let req = test::TestRequest::get()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["password"]["min_length"], 20);
    assert_eq!(body["mfa"]["mfa_enforced"], true);
    // Non-overridden fields still inherit
    assert_eq!(body["token"]["access_token_lifetime_secs"], 900);
}

// -----------------------------------------------------------------------
// Unauthenticated requests → 401
// -----------------------------------------------------------------------

#[actix_rt::test]
async fn settings_endpoints_require_auth() {
    let (db, org_id, _tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Org settings — no token
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);

    // Tenant settings — no token
    let req = test::TestRequest::get()
        .uri("/api/v1/settings")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

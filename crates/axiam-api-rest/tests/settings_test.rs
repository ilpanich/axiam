//! Integration tests for security settings endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Arbitrary CSRF token for the double-submit check (SEC-046). These
/// Bearer-token tests have no login/`axiam_csrf` cookie, so we send a matching
/// `axiam_csrf` cookie + `X-CSRF-Token` header; the middleware only checks they
/// are equal (no session lookup). Safe (GET) requests ignore it.
const CSRF_TOKEN: &str = "test-csrf-token";

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
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        uuid::Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
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
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
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
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
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
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
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
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
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

// -----------------------------------------------------------------------
// OPAQUE serviceability guard
//
// `POST /api/v1/admin/bootstrap` has always refused `opaque_mode != disabled`
// on a server holding no OPAQUE keys. The settings writes did not, so an org
// could be configured into a state where every `/api/v1/auth/opaque/*` route
// fails at runtime. These pin the guard on both scopes, and pin that the
// `disabled` path — the one every deployment that has never heard of OPAQUE
// takes — is untouched by it.
// -----------------------------------------------------------------------

/// An `AuthConfig` whose OPAQUE keys are present, so `AppState::for_test`
/// builds an `opaque_server`. The values are arbitrary: nothing in these tests
/// runs a PAKE exchange, they only need the server to hold *some* keys.
fn test_auth_config_with_opaque_keys() -> AuthConfig {
    AuthConfig {
        opaque_session_key: Some([7u8; 32]),
        opaque_setup_key: Some([9u8; 32]),
        ..test_auth_config()
    }
}

/// A complete `SetOrgSettings` body. Every field is required (the struct is a
/// whole-row replace), so tests that vary one field still have to send all of
/// them.
fn org_settings_body(opaque: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "min_length": 12,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_digits": true,
        "require_symbols": false,
        "password_history_count": 5,
        "hibp_check_enabled": true,
        "mfa_enforced": false,
        "mfa_challenge_lifetime_secs": 300,
        "max_failed_login_attempts": 5,
        "lockout_duration_secs": 300,
        "lockout_backoff_multiplier": 2.0,
        "max_lockout_duration_secs": 3600,
        "access_token_lifetime_secs": 900,
        "refresh_token_lifetime_secs": 2592000,
        "email_verification_required": true,
        "email_verification_grace_period_hours": 24,
        "default_cert_validity_days": 365,
        "max_cert_validity_days": 730,
        "admin_notifications_enabled": true
    });
    if let Some(mode) = opaque {
        body["opaque_mode"] = serde_json::Value::String(mode.into());
    }
    body
}

#[actix_rt::test]
async fn set_org_settings_refuses_opaque_without_the_server_keys() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    // No OPAQUE keys — `AppState::for_test` leaves `opaque_server` as `None`.
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(org_settings_body(Some("required")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "enabling OPAQUE on a server that cannot serve it must be refused"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    let msg = body["message"].as_str().unwrap();
    // The message must name what is missing, exactly as bootstrap's does —
    // an operator reading it should not have to go find the env var names.
    assert!(
        msg.contains("AXIAM__AUTH__OPAQUE_SESSION_KEY"),
        "got: {msg}"
    );
    assert!(msg.contains("AXIAM__AUTH__OPAQUE_SETUP_KEY"), "got: {msg}");
}

/// `optional` is refused for the same reason `required` is: the routes it makes
/// reachable are the ones the server has no keys to answer.
#[actix_rt::test]
async fn set_org_settings_refuses_opaque_optional_without_the_server_keys() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(org_settings_body(Some("optional")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

/// The guard is about the keys, not about OPAQUE: with both configured, the
/// same write goes through.
#[actix_rt::test]
async fn set_org_settings_accepts_opaque_when_the_server_keys_are_configured() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config_with_opaque_keys();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(org_settings_body(Some("required")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["opaque"]["opaque_mode"], "required");
}

/// The `disabled` path is untouched: a deployment with no OPAQUE keys — which
/// is every deployment that has never enabled it — still saves org settings
/// normally, whether it names `opaque_mode` or omits it entirely.
#[actix_rt::test]
async fn set_org_settings_leaves_the_disabled_path_alone() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    for body in [org_settings_body(None), org_settings_body(Some("disabled"))] {
        let req = test::TestRequest::put()
            .uri(&format!("/api/v1/organizations/{org_id}/settings"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200);

        let saved: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(saved["opaque"]["opaque_mode"], "disabled");
    }
}

/// The tenant override raises the mode above the org baseline — a legal
/// tighten, and exactly as unserviceable as the org write would be.
#[actix_rt::test]
async fn set_tenant_settings_refuses_an_override_that_raises_opaque_without_keys() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "opaque_mode": "required" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let msg = body["message"].as_str().unwrap();
    assert!(
        msg.contains("AXIAM__AUTH__OPAQUE_SESSION_KEY"),
        "got: {msg}"
    );
    assert!(msg.contains("AXIAM__AUTH__OPAQUE_SETUP_KEY"), "got: {msg}");
}

/// An override that never mentions `opaque_mode` inherits the org baseline and
/// changes nothing about OPAQUE, so the guard must not fire on it — otherwise
/// editing an unrelated tenant field would start failing.
#[actix_rt::test]
async fn set_tenant_settings_ignores_the_guard_when_the_override_omits_opaque() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "min_length": 16 }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["password"]["min_length"], 16);
    assert_eq!(body["opaque"]["opaque_mode"], "disabled");
}

#[actix_rt::test]
async fn set_tenant_settings_accepts_opaque_when_the_server_keys_are_configured() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config_with_opaque_keys();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "opaque_mode": "optional" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["opaque"]["opaque_mode"], "optional");
}

// -----------------------------------------------------------------------
// Enabling OPAQUE provisions the tenant's key material there and then
// -----------------------------------------------------------------------
//
// `opaque_server_setup` used to appear only when somebody first hit
// `/auth/opaque/*`, so "I turned OPAQUE on and nothing happened" was a correct
// observation with no way to tell it from a misconfiguration. Provisioning at
// the settings write puts the one step that can fail server-side — the seal,
// the row — in the request the operator is watching.

/// Count the tenant's `opaque_server_setup` rows directly. The repository
/// exposes only `get`/`get_or_create`, and `get_or_create` would create the
/// row this test is asking about.
async fn opaque_setup_count(db: &Surreal<TestDb>, tenant_id: Uuid) -> usize {
    let mut result = db
        .query(
            "SELECT VALUE tenant_id FROM opaque_server_setup \
             WHERE tenant_id = $tenant_id",
        )
        .bind(("tenant_id", tenant_id.to_string()))
        .await
        .unwrap();
    let rows: Vec<String> = result.take(0).unwrap();
    rows.len()
}

#[actix_rt::test]
async fn enabling_opaque_on_the_org_provisions_every_tenant() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config_with_opaque_keys();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    assert_eq!(opaque_setup_count(&db, tenant_id).await, 0);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(org_settings_body(Some("optional")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    assert_eq!(
        opaque_setup_count(&db, tenant_id).await,
        1,
        "enabling OPAQUE must leave the tenant with key material, not wait for a login"
    );
}

#[actix_rt::test]
async fn provisioning_is_idempotent_across_repeated_writes() {
    // `get_or_create` addresses a record id derived from (tenant, suite), so a
    // second write must find the first row rather than mint a second seed. A
    // tenant with two seeds has records that only sometimes open.
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config_with_opaque_keys();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    for _ in 0..3 {
        let req = test::TestRequest::put()
            .uri(&format!("/api/v1/organizations/{org_id}/settings"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(org_settings_body(Some("optional")))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
    }

    assert_eq!(opaque_setup_count(&db, tenant_id).await, 1);
}

#[actix_rt::test]
async fn leaving_opaque_disabled_provisions_nothing() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config_with_opaque_keys();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(org_settings_body(Some("disabled")))
        .to_request();

    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
    assert_eq!(opaque_setup_count(&db, tenant_id).await, 0);
}

#[actix_rt::test]
async fn a_tenant_override_that_raises_the_mode_provisions_that_tenant() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config_with_opaque_keys();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "opaque_mode": "optional" }))
        .to_request();

    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
    assert_eq!(opaque_setup_count(&db, tenant_id).await, 1);
}

#[actix_rt::test]
async fn provisioning_failure_does_not_refuse_the_settings_write() {
    // No OPAQUE keys, and `opaque_mode` left alone: the write inherits the
    // org's `disabled` baseline, so the guard does not fire and provisioning
    // has nothing to do. The point is that an unrelated tenant edit still
    // succeeds on a server that could not provision even if asked.
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri("/api/v1/settings")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "min_length": 16 }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["password"]["min_length"], 16);
    assert_eq!(opaque_setup_count(&db, tenant_id).await, 0);
}

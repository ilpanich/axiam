//! Integration tests for the WebAuthn passkey handlers
//! (`/api/v1/auth/webauthn/*`): auth-required guards, `start_registration`
//! success, `finish_registration` cross-tenant/garbage-token rejection,
//! `start_authentication` bad-challenge/no-credentials branches, and the
//! `finish_authentication` `peek_tenant_id` helper's error branches (missing
//! segment, bad base64, non-JSON, missing/invalid `tenant_id`).
//!
//! Real ceremony completion (a genuine authenticator response) is out of
//! scope for a headless integration test — see the equivalent constraint
//! documented in `axiam-auth/tests/webauthn_tests.rs`.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        // Required for WebauthnService's ceremony-state encryption.
        mfa_encryption_key: Some([5u8; 32]),
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        ..AuthConfig::default()
    }
}

/// Create org + tenant + active user, returning IDs.
async fn setup_tenant(db: &Surreal<TestDb>, slug_suffix: &str) -> (Uuid, Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {slug_suffix}"),
            slug: format!("org-wa-{slug_suffix}"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: format!("Tenant {slug_suffix}"),
            slug: format!("tenant-wa-{slug_suffix}"),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: format!("wa-user-{slug_suffix}"),
            email: format!("wa-user-{slug_suffix}@example.com"),
            password: TEST_PASSWORD.into(),
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

    (org.id, tenant.id, user.id)
}

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "a").await;
    (db, org_id, tenant_id, user_id)
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test($db.clone(), $auth.clone())))
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

fn dummy_register_response_json() -> Value {
    json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "attestationObject": "AAAA",
            "clientDataJSON": "AAAA"
        },
        "extensions": {}
    })
}

fn dummy_auth_response_json() -> Value {
    json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "authenticatorData": "AAAA",
            "clientDataJSON": "AAAA",
            "signature": "AAAA"
        },
        "extensions": {}
    })
}

/// Build a syntactically 3-part "JWT-shaped" state token whose payload
/// segment base64url-decodes to the given raw bytes. Header/signature
/// segments are arbitrary — `peek_tenant_id` never inspects them.
fn fake_state_token(payload_raw: &[u8]) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    format!(
        "header.{}.signature",
        URL_SAFE_NO_PAD.encode(payload_raw)
    )
}

// ---------------------------------------------------------------------------
// start_registration
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn start_registration_requires_auth() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/register/start")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn start_registration_succeeds_with_valid_token() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/register/start")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert!(body.get("challenge").is_some());
    assert!(body.get("state_token").and_then(Value::as_str).is_some());
}

// ---------------------------------------------------------------------------
// finish_registration
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn finish_registration_requires_auth() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/register/finish")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": "not.a.jwt",
            "credential_name": "my key",
            "response": dummy_register_response_json(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn finish_registration_rejects_garbage_state_token() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/register/finish")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": "not.a.jwt",
            "credential_name": "my key",
            "response": dummy_register_response_json(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn finish_registration_rejects_cross_tenant_state_token() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_a, tenant_a, user_a) = setup_tenant(&db, "a").await;
    let (_org_b, tenant_b, user_b) = setup_tenant(&db, "b").await;

    let auth = test_auth_config();
    let token_a = mint_token(&auth, user_a, tenant_a, org_a);
    let app = test_app!(db, auth);

    // Mint a registration state token scoped to tenant A.
    let start_req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/register/start")
        .insert_header(("Authorization", format!("Bearer {token_a}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let start_resp = test::call_service(&app, start_req).await;
    assert_eq!(start_resp.status().as_u16(), 200);
    let start_body: Value = test::read_body_json(start_resp).await;
    let state_token = start_body["state_token"].as_str().unwrap().to_string();

    // Authenticate as a DIFFERENT tenant's user and try to finish with
    // tenant A's state token — the tenant-mismatch guard in
    // WebauthnService::finish_registration must reject this.
    let token_b = issue_access_token(
        user_b,
        tenant_b,
        Uuid::new_v4(),
        &[],
        &auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();

    let finish_req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/register/finish")
        .insert_header(("Authorization", format!("Bearer {token_b}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": state_token,
            "credential_name": "my key",
            "response": dummy_register_response_json(),
        }))
        .to_request();
    let finish_resp = test::call_service(&app, finish_req).await;
    assert_eq!(finish_resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// start_authentication
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn start_authentication_rejects_garbage_challenge_token() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/start")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "challenge_token": "not.a.jwt" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn start_authentication_with_real_challenge_but_no_credentials_errors() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    // Enable MFA for the user so /login returns a 202 MFA-required
    // response with a genuine challenge_token instead of logging in.
    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                mfa_enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let login_req = test::TestRequest::post()
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "wa-user-a",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(
        login_resp.status().as_u16(),
        202,
        "MFA-enabled user must get a 202 challenge response"
    );
    let login_body: Value = test::read_body_json(login_resp).await;
    let challenge_token = login_body["challenge_token"].as_str().unwrap().to_string();

    // The user has zero registered WebAuthn credentials, so starting a
    // passkey authentication ceremony with an otherwise-valid challenge
    // token must fail (WebauthnNoCredentials).
    let start_req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/start")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "challenge_token": challenge_token }))
        .to_request();
    let start_resp = test::call_service(&app, start_req).await;
    assert_eq!(start_resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// finish_authentication — peek_tenant_id branches
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn finish_authentication_rejects_two_segment_token() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/finish")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": "only.two",
            "response": dummy_auth_response_json(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn finish_authentication_rejects_non_base64_payload() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/finish")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": "header.not!!valid!!base64.signature",
            "response": dummy_auth_response_json(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn finish_authentication_rejects_non_json_payload() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let state_token = fake_state_token(b"not json at all");
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/finish")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": state_token,
            "response": dummy_auth_response_json(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn finish_authentication_rejects_invalid_tenant_uuid() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let state_token = fake_state_token(br#"{"tenant_id": "not-a-uuid"}"#);
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/finish")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": state_token,
            "response": dummy_auth_response_json(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn finish_authentication_peek_succeeds_but_service_rejects_invalid_jwt() {
    // A well-formed 3-segment token with a valid tenant_id in the payload
    // passes `peek_tenant_id`, but header/signature are garbage so the
    // downstream `WebauthnService::finish_authentication` JWT verification
    // still fails — proving both layers are actually enforced in sequence.
    let (db, _org, tenant_id, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let payload = format!(r#"{{"tenant_id": "{tenant_id}"}}"#);
    let state_token = fake_state_token(payload.as_bytes());
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/finish")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "state_token": state_token,
            "response": dummy_auth_response_json(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

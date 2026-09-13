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

use std::net::SocketAddr;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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

/// The six `/auth/webauthn/*` routes are wrapped in `build_governor`, whose
/// per-peer key extractor fails the request outright with 500 "no peer address"
/// when none is set — so every request below must carry one, exactly as
/// `auth_test.rs` does for the login/MFA routes. A bare `TestRequest` never
/// reaches the handler.
const TEST_PEER: &str = "127.0.0.1:12345";
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";

/// Generates a fresh Ed25519 JWT signing keypair at test runtime (no literal
/// key material in source — avoids new secret-scanner findings).
fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
}

fn test_auth_config() -> AuthConfig {
    let (private_key, public_key) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        // Required for WebauthnService's ceremony-state encryption.
        mfa_encryption_key: Some([5u8; 32]),
        opaque_session_key: None,
        opaque_setup_key: None,
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
            kind: TenantKind::Standard,
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
    format!("header.{}.signature", URL_SAFE_NO_PAD.encode(payload_raw))
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// start_discoverable_authentication — workspace resolution
// ---------------------------------------------------------------------------

/// A usernameless ceremony must be reachable at organization level.
///
/// The login page collects the workspace in one step and starts this ceremony
/// from it — behind the explicit "sign in with a passkey" button and again as
/// passkey autofill — so for the principal a first-run bootstrap creates it
/// arrives with the tenant blank. Demanding a tenant here made a passkey the
/// one credential an organization-level administrator could not sign in with,
/// and the autofill variant swallows its own errors, so it failed silently.
///
/// Both spellings are covered: the field omitted, and the field sent as the
/// empty string a form binds to when the human left it blank.
#[actix_web::test]
async fn discoverable_authentication_starts_at_organization_level() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org WA Discoverable".into(),
            slug: "org-wa-discoverable".into(),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();

    let auth = test_auth_config();
    let app = test_app!(db, auth);

    for body in [
        json!({ "org_slug": "org-wa-discoverable" }),
        json!({ "org_slug": "org-wa-discoverable", "tenant_slug": "" }),
    ] {
        let req = test::TestRequest::post()
            .uri("/api/v1/auth/webauthn/authenticate/discoverable/start")
            .peer_addr(TEST_PEER.parse().unwrap())
            .set_json(&body)
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status().as_u16();
        let out = test::read_body(resp).await;
        assert_eq!(
            status,
            200,
            "the ceremony must resolve the organization's own scope. body = {}",
            String::from_utf8_lossy(&out)
        );
    }
}

/// Naming a tenant still resolves that tenant, and naming an organization with
/// no organization scope is refused the same enumeration-safe way a wrong slug
/// is — never a 400 that says which half was missing.
#[actix_web::test]
async fn discoverable_authentication_refuses_an_unreachable_workspace() {
    let (db, _org, _tenant, _user) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/discoverable/start")
        .peer_addr(TEST_PEER.parse().unwrap())
        .set_json(json!({ "org_slug": "org-wa-a", "tenant_slug": "tenant-wa-a" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        200,
        "naming a tenant must still resolve that tenant"
    );

    // `setup` creates no organization scope, so omitting the tenant has nowhere
    // to land.
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/discoverable/start")
        .peer_addr(TEST_PEER.parse().unwrap())
        .set_json(json!({ "org_slug": "org-wa-a" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        401,
        "an organization with no organization scope must refuse, not disclose"
    );

    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/authenticate/discoverable/start")
        .peer_addr(TEST_PEER.parse().unwrap())
        .set_json(json!({ "tenant_slug": "tenant-wa-a" }))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        400,
        "the organization is still required"
    );
}

// ---------------------------------------------------------------------------
// Forced first-login enrolment: the setup-token registration pair
// (M-3, T-269)
// ---------------------------------------------------------------------------
//
// The ceremony itself still cannot be completed here — see this file's header
// — so what is asserted is everything up to it: that the setup token is the
// only credential, that only a *setup* token works, and that an account with a
// factor is refused. The evidence a completion records, and the assurance class
// it lands in, are pinned by unit tests on `setup_registration_amr` in the
// handler module, where they can be reached without an authenticator.

/// Enable `mfa_enforced` at the organization level, so a password login
/// answers `403 { mfa_setup_required, setup_token }` instead of a session.
async fn enforce_mfa(db: &Surreal<TestDb>, org_id: Uuid) {
    use axiam_core::models::settings::system_defaults;
    use axiam_core::repository::SettingsRepository;

    let mut defaults = system_defaults();
    defaults.mfa_enforced = true;
    axiam_db::SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org_id, defaults)
        .await
        .unwrap();
}

/// Sign in far enough to be handed a setup token — the situation a user of an
/// enforcing tenant is in on their very first login.
async fn setup_token_for<S>(app: &S, org_id: Uuid, tenant_id: Uuid, username: &str) -> String
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >,
{
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": username,
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "an enforcing tenant interrupts the login of a user with no factor"
    );
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["mfa_setup_required"], true);
    body["setup_token"].as_str().unwrap().to_string()
}

fn setup_start(setup_token: &str) -> test::TestRequest {
    test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/webauthn/setup/register/start")
        .set_json(json!({ "setup_token": setup_token }))
}

#[actix_web::test]
async fn setup_register_start_issues_a_challenge_for_a_factorless_account() {
    let (db, org_id, tenant_id, _user_id) = setup().await;
    enforce_mfa(&db, org_id).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let token = setup_token_for(&app, org_id, tenant_id, "wa-user-a").await;
    let resp = test::call_service(&app, setup_start(&token).to_request()).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: Value = test::read_body_json(resp).await;
    assert!(
        body.get("challenge").is_some(),
        "the same response shape as the profile-page ceremony: {body}"
    );
    assert!(body.get("state_token").and_then(Value::as_str).is_some());
}

#[actix_web::test]
async fn setup_register_start_takes_the_token_and_nothing_else() {
    // Rule 1. The token is the only credential — no session, no bearer — which
    // is the whole point: a user mid-forced-enrolment has no session to
    // present. An empty or absent token is a 401, not a 500.
    let (db, org_id, _tenant_id, _user_id) = setup().await;
    enforce_mfa(&db, org_id).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    for (what, token) in [("empty", ""), ("not a JWT at all", "garbage")] {
        let resp = test::call_service(&app, setup_start(token).to_request()).await;
        assert_eq!(
            resp.status().as_u16(),
            401,
            "a {what} setup token must be a 401"
        );
    }
}

#[actix_web::test]
async fn setup_register_start_refuses_a_session_bearer_as_the_setup_token() {
    // Rule 1, the case that matters: an access token is a perfectly valid JWT
    // signed by the same key. What makes a setup token a setup token is its
    // `purpose` claim, and `decode_setup_token` checks it. Without that check
    // any signed-in caller could register a credential against any account
    // whose id they could put in a token.
    let (db, org_id, tenant_id, user_id) = setup().await;
    enforce_mfa(&db, org_id).await;
    let auth = test_auth_config();
    let access_token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let resp = test::call_service(&app, setup_start(&access_token).to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "an access token is not a setup token, however well signed"
    );
}

#[actix_web::test]
async fn setup_register_start_refuses_an_account_that_already_has_a_factor() {
    // Rule 2. A setup token adds the account's FIRST factor, never a second —
    // the same answer `setup/enroll` gives. The check spans the TOTP secret and
    // the WebAuthn credential rows, so it is asked of `MfaMethodService`: a
    // check that read only the TOTP half would let a captured token add a
    // second passkey to an account that already had one, which is the shape of
    // T-269.
    let (db, org_id, tenant_id, user_id) = setup().await;
    enforce_mfa(&db, org_id).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Take the token while the account still has nothing, then give it a
    // factor — the race a captured token would be replayed into.
    let token = setup_token_for(&app, org_id, tenant_id, "wa-user-a").await;

    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                mfa_enabled: Some(true),
                mfa_secret: Some(Some("encrypted-secret-placeholder".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let resp = test::call_service(&app, setup_start(&token).to_request()).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "an account with a factor is refused, however valid the token — with \
         the same status `POST /auth/mfa/setup/enroll` gives for the same \
         refusal, because it is the same rule"
    );
    let body: Value = test::read_body_json(resp).await;
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("already"),
        "and the message says so: {body}"
    );
}

#[actix_web::test]
async fn setup_register_finish_refuses_the_same_tokens_start_refuses() {
    // Both halves take the token, so both must check it. A `finish` that
    // trusted the state token alone would let a caller who never held a setup
    // token complete a ceremony somebody else started.
    let (db, org_id, _tenant_id, _user_id) = setup().await;
    enforce_mfa(&db, org_id).await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/webauthn/setup/register/finish")
        .set_json(json!({
            "setup_token": "garbage",
            "state_token": fake_state_token(b"{}"),
            "credential_name": "My key",
            "response": dummy_register_response_json(),
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 401);
}

//! Integration tests for the OAuth2 Authorization Code (+ PKCE) flow.
//!
//! Each test exercises the full authorize → token exchange round-trip through
//! the real HTTP layer, using an in-memory SurrealDB instance.

use actix_web::{App, test, web};
use std::net::SocketAddr;

use axiam_api_rest::RateLimitConfig;

/// Loopback peer address for test requests so the rate-limiter key extractor
/// can resolve a client IP without a real socket.
const TEST_PEER: &str = "127.0.0.1:12345";
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Arbitrary CSRF token for the double-submit check (SEC-046). These
/// Bearer-token tests have no login/`axiam_csrf` cookie, so we send a matching
/// `axiam_csrf` cookie + `X-CSRF-Token` header; the middleware only checks they
/// are equal (no session lookup). Safe (GET) requests ignore it.
/// `/oauth2/*` endpoints are CSRF-exempt and intentionally receive no token.
const CSRF_TOKEN: &str = "test-csrf-token";

// ---------------------------------------------------------------------------
// Test scaffolding — mirrors webhook_test.rs conventions exactly
// ---------------------------------------------------------------------------

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
        oauth2_issuer_url: "https://localhost".into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
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
            kind: TenantKind::Standard,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

async fn create_admin_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    user.id
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
    ($db:expr, $auth:expr) => {{
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
    }};
}

// ---------------------------------------------------------------------------
// PKCE helpers
// ---------------------------------------------------------------------------

/// Generate a PKCE S256 challenge from a verifier string.
fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Flow helpers
// ---------------------------------------------------------------------------

/// Create a confidential OAuth2 client via the CRUD API.
/// Returns `(client_id, client_secret, redirect_uri)`.
async fn create_client(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> (String, String, String) {
    let redirect_uri = "https://app.example.com/callback";
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Flow Test Client",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "scopes": ["openid", "profile"]
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    (
        body["client_id"].as_str().unwrap().to_string(),
        body["client_secret"].as_str().unwrap().to_string(),
        redirect_uri.to_string(),
    )
}

/// Call GET /oauth2/authorize and extract the authorization code from the
/// Location header redirect (302).
async fn do_authorize(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    client_id: &str,
    redirect_uri: &str,
    state: Option<&str>,
    code_challenge: Option<&str>,
) -> String {
    let mut uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}"
    );
    if let Some(s) = state {
        uri.push_str("&state=");
        uri.push_str(s);
    }
    if let Some(ch) = code_challenge {
        uri.push_str("&code_challenge=");
        uri.push_str(ch);
        uri.push_str("&code_challenge_method=S256");
    }

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        302,
        "authorize must redirect with 302"
    );

    let location = resp
        .headers()
        .get("Location")
        .expect("Location header missing")
        .to_str()
        .unwrap()
        .to_string();

    // Extract the code query parameter from the redirect location
    let url = url::Url::parse(&location).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code not found in redirect Location")
}

/// POST to /oauth2/token with form-encoded params, return the response body.
async fn do_token_exchange(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    tenant_id: Uuid,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    let mut form = format!(
        "grant_type=authorization_code&code={code}&redirect_uri={redirect_uri}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    if let Some(v) = code_verifier {
        form.push_str("&code_verifier=");
        form.push_str(v);
    }

    test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request()
        .pipe(|req| test::call_service(app, req))
        .await
}

// Workaround: actix test doesn't provide a direct `.pipe()` — define a trait
trait PipeExt: Sized {
    fn pipe<F, O>(self, f: F) -> O
    where
        F: FnOnce(Self) -> O;
}
impl<T> PipeExt for T {
    fn pipe<F, O>(self, f: F) -> O
    where
        F: FnOnce(Self) -> O,
    {
        f(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn full_authorization_code_flow() {
    // Complete flow without PKCE:
    //   1. Create OAuth2 client
    //   2. Authenticate user and call authorize endpoint → get code
    //   3. Exchange code for tokens → get access_token + refresh_token
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let code = do_authorize(
        &app,
        &user_jwt,
        &client_id,
        &redirect_uri,
        Some("abc123"),
        None,
    )
    .await;

    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string(), "access_token missing");
    assert!(body["refresh_token"].is_string(), "refresh_token missing");
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["expires_in"].is_number());
}

#[actix_rt::test]
async fn full_authorization_code_flow_with_pkce() {
    // Same as above, but with PKCE S256.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let verifier = "my-pkce-code-verifier-for-test-1234567890ab";
    let challenge = pkce_challenge(verifier);

    let code = do_authorize(
        &app,
        &user_jwt,
        &client_id,
        &redirect_uri,
        Some("pkce-state"),
        Some(&challenge),
    )
    .await;

    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        Some(verifier),
    )
    .await;

    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
}

#[actix_rt::test]
async fn auth_code_is_single_use() {
    // The authorization code must be invalidated after the first exchange.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;

    // First exchange succeeds
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);

    // Second exchange with the same code must fail (invalid_grant)
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "reused code must return 400 invalid_grant"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_rt::test]
async fn pkce_verification_failure() {
    // Providing the wrong code_verifier must return invalid_grant.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let correct_verifier = "correct-verifier-string-1234567890abcdefghi";
    let challenge = pkce_challenge(correct_verifier);

    let code = do_authorize(
        &app,
        &user_jwt,
        &client_id,
        &redirect_uri,
        None,
        Some(&challenge),
    )
    .await;

    // Use the wrong verifier
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        Some("wrong-verifier-that-does-not-match-at-all99"),
    )
    .await;

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_rt::test]
async fn invalid_redirect_uri_rejected_at_authorize() {
    // An unregistered redirect_uri at the authorize step must produce an
    // error redirect (302 with error=invalid_request) rather than success.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _client_secret, _redirect_uri) = create_client(&app, &user_jwt).await;

    let bad_redirect = "https://evil.com/steal";
    let uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={bad_redirect}"
    );

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Per RFC 6749 section 3.1.2.4: if the redirect_uri is invalid or
    // unregistered, the authorization server MUST NOT redirect and
    // SHOULD inform the resource owner of the error.
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("redirect_uri"),
        "error_description should mention redirect_uri"
    );
}

#[actix_rt::test]
async fn invalid_client_secret_rejected() {
    // Token exchange with a wrong client secret must return 401 invalid_client.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _correct_secret, redirect_uri) = create_client(&app, &user_jwt).await;
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;

    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        "wrong-secret-value",
        &code,
        &redirect_uri,
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
}

#[actix_rt::test]
async fn unsupported_response_type_rejected() {
    // response_type != "code" must produce an error redirect.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let uri = format!(
        "/oauth2/authorize?response_type=token&client_id={client_id}&redirect_uri={redirect_uri}"
    );
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    assert!(
        location.contains("error=unsupported_response_type"),
        "expected unsupported_response_type error, got: {location}"
    );
}

#[actix_rt::test]
async fn missing_code_returns_error() {
    // Token request without a code parameter must return 400 invalid_request.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Send form without "code"
    let form = format!(
        "grant_type=authorization_code&redirect_uri={redirect_uri}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_request");
}

#[actix_rt::test]
async fn unsupported_grant_type_returns_error() {
    // grant_type != "authorization_code" at the token endpoint must return 400.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let form = format!(
        "grant_type=implicit&code=fakecode&redirect_uri={redirect_uri}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "unsupported_grant_type");
}

#[actix_rt::test]
async fn redirect_uri_mismatch_at_token_rejected() {
    // A redirect_uri in the token request that differs from the one used in
    // authorize must return 400 invalid_grant (RFC 6749 §4.1.3).
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;

    // Swap the redirect_uri in the token request
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        "https://different.example.com/callback",
        None,
    )
    .await;

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_rt::test]
async fn state_parameter_echoed_in_redirect() {
    // The state parameter must be echoed back in the redirect Location.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let state_value = "csrf-token-xyz-789";
    let uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect_uri}&state={state_value}"
    );

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);

    let location = resp.headers().get("Location").unwrap().to_str().unwrap();

    let url = url::Url::parse(location).unwrap();
    let returned_state = url
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("state not echoed in Location");

    assert_eq!(returned_state, state_value);
}

#[actix_rt::test]
async fn pkce_required_when_challenge_registered() {
    // If a code_challenge was registered, omitting code_verifier in the
    // token exchange must return invalid_grant.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let verifier = "a-valid-code-verifier-string-1234567890abcd";
    let challenge = pkce_challenge(verifier);

    let code = do_authorize(
        &app,
        &user_jwt,
        &client_id,
        &redirect_uri,
        None,
        Some(&challenge),
    )
    .await;

    // Omit code_verifier entirely
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None, // no verifier
    )
    .await;

    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant");
}

// ===========================================================================
// T10.2 — Client Credentials Grant
// ===========================================================================

/// Helper: create an OAuth2 client with `client_credentials` grant type.
async fn create_cc_client(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> (String, String) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "M2M Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["client_credentials"],
            "scopes": ["read:data", "write:data"]
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    (
        body["client_id"].as_str().unwrap().to_string(),
        body["client_secret"].as_str().unwrap().to_string(),
    )
}

#[actix_rt::test]
async fn client_credentials_grant() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret) = create_cc_client(&app, &user_jwt).await;

    let form = format!(
        "grant_type=client_credentials\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert_eq!(body["token_type"], "Bearer");
    // Client credentials should NOT return a refresh token
    assert!(
        body.get("refresh_token").is_none() || body["refresh_token"].is_null(),
        "client_credentials must not return refresh_token"
    );
    assert_eq!(body["scope"], "read:data write:data");
}

#[actix_rt::test]
async fn client_credentials_wrong_secret() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _) = create_cc_client(&app, &user_jwt).await;

    let form = format!(
        "grant_type=client_credentials\
         &client_id={client_id}&client_secret=wrong-secret"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
}

#[actix_rt::test]
async fn client_credentials_unauthorized_grant() {
    // Client registered for authorization_code only — client_credentials
    // must be rejected with unauthorized_client.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // create_client registers with grant_types: ["authorization_code"]
    let (client_id, client_secret, _) = create_client(&app, &user_jwt).await;

    let form = format!(
        "grant_type=client_credentials\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "unauthorized_client");
}

// ===========================================================================
// T10.2 — Refresh Token Grant
// ===========================================================================

#[actix_rt::test]
async fn refresh_token_grant() {
    // Full flow: auth_code → tokens → use refresh_token → new tokens
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Step 1: authorize + exchange code
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let refresh_token = body["refresh_token"].as_str().unwrap();

    // Step 2: use refresh token to get new tokens
    let form = format!(
        "grant_type=refresh_token&refresh_token={refresh_token}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    // New refresh token must differ from the old one (rotation)
    assert_ne!(
        body["refresh_token"].as_str().unwrap(),
        refresh_token,
        "refresh token must be rotated"
    );
}

#[actix_rt::test]
async fn refresh_token_rotation_invalidates_old() {
    // After rotation, the old refresh token must be rejected.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let old_refresh = body["refresh_token"].as_str().unwrap().to_string();

    // Use old refresh token (succeeds, rotates)
    let form = format!(
        "grant_type=refresh_token&refresh_token={old_refresh}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Try the old refresh token again — must fail
    let form = format!(
        "grant_type=refresh_token&refresh_token={old_refresh}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant");
}

// ===========================================================================
// T10.2 — Token Revocation (RFC 7009)
// ===========================================================================

#[actix_rt::test]
async fn revoke_refresh_token() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Get a refresh token via auth_code flow
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let refresh_token = body["refresh_token"].as_str().unwrap();

    // Revoke it
    let form = format!(
        "token={refresh_token}&token_type_hint=refresh_token\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/revoke?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Try using the revoked refresh token
    let form = format!(
        "grant_type=refresh_token&refresh_token={refresh_token}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_rt::test]
async fn revoke_unknown_token_returns_200() {
    // Per RFC 7009, revoking an unknown token must still return 200.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, _) = create_client(&app, &user_jwt).await;

    let form = format!(
        "token=nonexistent-token-value\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/revoke?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

// ===========================================================================
// T10.2 — Token Introspection (RFC 7662)
// ===========================================================================

#[actix_rt::test]
async fn introspect_active_access_token() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Get an access token via auth_code flow
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let access_token = body["access_token"].as_str().unwrap();

    // Introspect it
    let form = format!(
        "token={access_token}&token_type_hint=access_token\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/introspect?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], true);
    assert_eq!(body["token_type"], "Bearer");
    assert!(body["sub"].is_string());
    assert!(body["exp"].is_number());
    assert!(body["iat"].is_number());
}

#[actix_rt::test]
async fn introspect_unknown_token_returns_inactive() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, _) = create_client(&app, &user_jwt).await;

    let form = format!(
        "token=totally-bogus-token-value\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/introspect?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], false);
}

#[actix_rt::test]
async fn introspect_requires_client_auth() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _, _) = create_client(&app, &user_jwt).await;

    let form = format!(
        "token=some-token\
         &client_id={client_id}&client_secret=wrong-secret"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/introspect?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "invalid_client");
}

#[actix_rt::test]
async fn introspect_revoked_refresh_token() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Get refresh token
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None, None).await;
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    let refresh_token = body["refresh_token"].as_str().unwrap();

    // Revoke it
    let form = format!(
        "token={refresh_token}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/revoke?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    test::call_service(&app, req).await;

    // Introspect the revoked token — must be inactive
    let form = format!(
        "token={refresh_token}\
         &client_id={client_id}&client_secret={client_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/introspect?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["active"], false);
}

// ===========================================================================
// T10.3 — OpenID Connect
// ===========================================================================

#[actix_rt::test]
async fn oidc_discovery_document() {
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let _user_id = create_admin_user(&db, tenant_id).await;
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["issuer"], "https://localhost");
    assert!(body["authorization_endpoint"].is_string());
    assert!(body["token_endpoint"].is_string());
    assert!(body["userinfo_endpoint"].is_string());
    assert!(body["jwks_uri"].is_string());
    let scopes = body["scopes_supported"].as_array().unwrap();
    assert!(
        scopes.iter().any(|s| s == "openid"),
        "scopes_supported must include openid"
    );
    let algs = body["id_token_signing_alg_values_supported"]
        .as_array()
        .unwrap();
    assert!(
        algs.iter().any(|a| a == "EdDSA"),
        "must advertise EdDSA signing"
    );
}

#[actix_rt::test]
async fn oidc_jwks_endpoint() {
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let _user_id = create_admin_user(&db, tenant_id).await;
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/jwks")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    let keys = body["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "OKP");
    assert_eq!(keys[0]["crv"], "Ed25519");
    assert_eq!(keys[0]["alg"], "EdDSA");
    assert_eq!(keys[0]["use"], "sig");
    assert!(keys[0]["x"].is_string());
    assert!(keys[0]["kid"].is_string());
}

#[actix_rt::test]
async fn oidc_userinfo_returns_sub() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/userinfo")
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["sub"], user_id.to_string());
    assert_eq!(body["tenant_id"], tenant_id.to_string());
    assert_eq!(body["org_id"], org_id.to_string());
}

#[actix_rt::test]
async fn oidc_userinfo_requires_auth() {
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let _user_id = create_admin_user(&db, tenant_id).await;
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/userinfo")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn oidc_userinfo_with_email_scope() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let scopes = vec!["openid".to_owned(), "email".to_owned()];
    let user_jwt = issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &scopes,
        &auth,
        uuid::Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/userinfo")
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["sub"], user_id.to_string());
    assert_eq!(body["email"], "admin@example.com");
}

#[actix_rt::test]
async fn oidc_userinfo_with_profile_scope() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let scopes = vec!["openid".to_owned(), "profile".to_owned()];
    let user_jwt = issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &scopes,
        &auth,
        uuid::Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/oauth2/userinfo")
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["sub"], user_id.to_string());
    assert_eq!(body["preferred_username"], "admin");
}

#[actix_rt::test]
async fn oidc_id_token_in_auth_code_flow() {
    // When `openid` scope is requested, the token response must
    // include an id_token JWT with the expected claims.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Authorize with openid scope and a nonce
    let uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect_uri}&scope=openid%20profile\
         &nonce=test-nonce-123"
    );
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 302);

    let location = resp
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let url = url::Url::parse(&location).unwrap();
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .unwrap();

    // Exchange for tokens
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert!(
        body["id_token"].is_string(),
        "id_token must be present when openid scope is requested"
    );

    // Verify the id_token is a valid JWT
    let id_token = body["id_token"].as_str().unwrap();
    let parts: Vec<&str> = id_token.split('.').collect();
    assert_eq!(parts.len(), 3, "id_token must be a valid JWT");

    // Decode and inspect claims
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(claims["sub"], user_id.to_string());
    assert_eq!(claims["aud"], client_id);
    assert_eq!(claims["iss"], "https://localhost");
    assert_eq!(claims["nonce"], "test-nonce-123");
    assert!(claims["iat"].is_number());
    assert!(claims["exp"].is_number());
}

#[actix_rt::test]
async fn oidc_no_id_token_without_openid_scope() {
    // When `openid` is NOT in the requested scopes, no id_token
    // should be returned.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create a client registered with only "read:data" scope (no openid)
    let redirect_uri = "https://app.example.com/callback";
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "No OpenID Client",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code"],
            "scopes": ["read:data"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let client_id = body["client_id"].as_str().unwrap().to_string();
    let client_secret = body["client_secret"].as_str().unwrap().to_string();

    // Authorize WITHOUT openid scope
    let code = do_authorize(&app, &user_jwt, &client_id, redirect_uri, None, None).await;

    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        redirect_uri,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["access_token"].is_string());
    assert!(
        body.get("id_token").is_none() || body["id_token"].is_null(),
        "id_token must not be present without openid scope"
    );
}

// ---------------------------------------------------------------------------
// SEC-087 — the failed-client-auth audit row is written on an UNAUTHENTICATED
// endpoint, so every input to it is attacker-controlled.
// ---------------------------------------------------------------------------

/// POST a deliberately-failing client authentication, with full control over
/// the tenant, client id and forwarding header.
async fn failing_token_post(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    tenant_id: Uuid,
    client_id: &str,
    forwarded_for: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    let form =
        format!("grant_type=client_credentials&client_id={client_id}&client_secret=wrong-secret");
    let mut r = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"));
    if let Some(f) = forwarded_for {
        r = r.insert_header(("X-Forwarded-For", f));
    }
    test::call_service(app, r.set_payload(form).to_request()).await
}

async fn client_auth_failure_rows(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
) -> Vec<axiam_core::models::audit::AuditLogEntry> {
    use axiam_core::repository::{AuditLogFilter, AuditLogRepository};
    axiam_db::SurrealAuditLogRepository::new(db.clone())
        .list(
            tenant_id,
            AuditLogFilter {
                action: Some("oauth2.client_auth_failed".into()),
                ..Default::default()
            },
            axiam_core::repository::Pagination::default(),
        )
        .await
        .unwrap()
        .items
}

/// Rows in the **system partition** (`tenant_id = nil`) — where a failure that
/// cannot be attributed to a real tenant is recorded (§22.3 residual 2).
async fn client_auth_failure_system_rows(
    db: &Surreal<TestDb>,
) -> Vec<axiam_core::models::audit::AuditLogEntry> {
    use axiam_core::repository::{AuditLogFilter, AuditLogRepository};
    axiam_db::SurrealAuditLogRepository::new(db.clone())
        .list_system(
            AuditLogFilter {
                action: Some("oauth2.client_auth_failed".into()),
                ..Default::default()
            },
            axiam_core::repository::Pagination::default(),
        )
        .await
        .unwrap()
        .items
}

/// The audit write is deliberately **off the response path** (§22.3 residual 1),
/// so a row appears shortly after the 401 rather than before it. Poll instead of
/// sleeping a fixed amount: a fixed sleep is either flaky or slow, and this also
/// documents that the detachment is the intended behaviour rather than a race.
async fn eventually<F, Fut, T>(mut f: F) -> Vec<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Vec<T>>,
{
    for _ in 0..100 {
        let rows = f().await;
        if !rows.is_empty() {
            return rows;
        }
        actix_web::rt::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Vec::new()
}

#[actix_rt::test]
async fn a_failed_client_auth_is_audited_against_a_real_tenant() {
    // The control case. Detection is the whole point of this row (§17.2
    // residual 3), so the SEC-087 hardening must not silence the true event:
    // a failed authentication against a tenant that exists is still recorded,
    // and against that tenant, not the system partition.
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let resp = failing_token_post(&app, tenant_id, "oa_nosuchclient", None).await;
    assert_eq!(resp.status().as_u16(), 401);

    let rows = eventually(|| client_auth_failure_rows(&db, tenant_id)).await;
    assert_eq!(rows.len(), 1, "the real event must still be recorded");
    assert!(
        rows[0].metadata["unattributed_reason"].is_null(),
        "a row for a real tenant must not be marked unattributed"
    );
}

#[actix_rt::test]
async fn an_anonymous_caller_cannot_write_audit_rows_into_an_unknown_tenant() {
    // SEC-087. `/oauth2/token` needs no credential and takes `tenant_id`
    // straight from the query string, so before the fix any anonymous caller
    // could append rows to an append-only log under *any* uuid.
    //
    // §22.3 residual 2 changed what happens to the refused row rather than
    // whether it is refused: it is no longer dropped, it is routed to the
    // system partition. The property that matters is unchanged and asserted
    // here — the caller still cannot place a row under an id of their choosing.
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let victim = Uuid::new_v4(); // never created
    let resp = failing_token_post(&app, victim, "oa_nosuchclient", None).await;

    // The caller must not be able to tell where the row went.
    assert_eq!(
        resp.status().as_u16(),
        401,
        "routing the audit row must not change the response"
    );

    // The signal is preserved...
    let system = eventually(|| client_auth_failure_system_rows(&db)).await;
    assert_eq!(
        system.len(),
        1,
        "the failure must still be recorded somewhere"
    );
    assert_eq!(
        system[0].metadata["unattributed_reason"].as_str(),
        Some("unknown_tenant")
    );
    assert_eq!(
        system[0].metadata["claimed_tenant_id_untrusted"].as_str(),
        Some(victim.to_string().as_str()),
        "the caller-named tenant is kept as evidence, marked untrusted"
    );

    // ...but not under the id the caller named.
    let rows = client_auth_failure_rows(&db, victim).await;
    assert!(
        rows.is_empty(),
        "no audit row may be written into a tenant the caller merely named"
    );
}

#[actix_rt::test]
async fn the_audited_client_id_is_truncated_and_the_forwarded_ip_is_untrusted() {
    // Two smaller SEC-087 defects in the same row, both stemming from the same
    // cause — this endpoint is unauthenticated, so both values are supplied by
    // whoever is attacking it.
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // `client_id` was recorded verbatim, unlike the sibling ip/user-agent
    // helpers which have always capped their inputs.
    let huge = format!("oa_{}", "A".repeat(5000));
    let resp = failing_token_post(&app, tenant_id, &huge, Some("203.0.113.9")).await;
    assert_eq!(resp.status().as_u16(), 401);

    let rows = eventually(|| client_auth_failure_rows(&db, tenant_id)).await;
    assert_eq!(rows.len(), 1);
    let meta = &rows[0].metadata;

    let recorded = meta["client_id"].as_str().expect("client_id recorded");
    assert!(
        recorded.len() <= 128,
        "client_id must be truncated, got {} bytes",
        recorded.len()
    );

    // The IP an operator would act on must be the transport peer, which a
    // caller cannot forge — not the X-Forwarded-For value, which anyone can
    // assert on an unauthenticated endpoint. Blocking a forged IP means acting
    // against an innocent host.
    let ip = rows[0].ip_address.as_deref().expect("ip recorded");
    assert!(
        ip.starts_with("127.0.0.1"),
        "ip_address must be the unforgeable peer address, got {ip}"
    );
    assert_eq!(
        meta["forwarded_for_untrusted"].as_str(),
        Some("203.0.113.9"),
        "the forgeable value is kept, but only under a name that says so"
    );
}

#[actix_rt::test]
async fn a_multibyte_client_id_is_capped_in_bytes_not_code_points() {
    // §22.3 residual 3. The cap used `chars().take(128)`, so a multibyte id
    // stored up to 512 bytes — and the previous test could not see it, because
    // its payload was ASCII and so byte length and code-point count agreed.
    // 'é' is two bytes in UTF-8, so 5000 of them is 10 000 bytes and would have
    // stored 256.
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let multibyte = format!("oa_{}", "é".repeat(5000));
    let resp = failing_token_post(&app, tenant_id, &multibyte, None).await;
    assert_eq!(resp.status().as_u16(), 401);

    let rows = eventually(|| client_auth_failure_rows(&db, tenant_id)).await;
    assert_eq!(rows.len(), 1);
    let recorded = rows[0].metadata["client_id"]
        .as_str()
        .expect("client_id recorded");

    assert!(
        recorded.len() <= 128,
        "the cap is a BYTE bound: got {} bytes ({} chars)",
        recorded.len(),
        recorded.chars().count()
    );
    // And the stored value must still be valid UTF-8 — truncating mid-character
    // would either panic or corrupt the record.
    assert!(
        std::str::from_utf8(recorded.as_bytes()).is_ok(),
        "truncation must land on a character boundary"
    );
}

#[actix_rt::test]
async fn an_audit_sink_problem_does_not_cost_the_failure_signal() {
    // §22.3 residual 2: a tenant read that fails for any reason other than
    // NotFound used to drop the row entirely, so a database fault cost exactly
    // the telemetry this row exists to provide — and a database fault is
    // plausibly correlated with an incident.
    //
    // The indeterminate branch cannot be provoked through the HTTP surface
    // without tearing down the DB mid-request, so this asserts the reachable
    // half of the same property: every failed client authentication lands
    // SOMEWHERE queryable, whatever the tenant turns out to be.
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // A real tenant → its own partition.
    let r1 = failing_token_post(&app, tenant_id, "oa_a", None).await;
    assert_eq!(r1.status().as_u16(), 401);
    let real = eventually(|| client_auth_failure_rows(&db, tenant_id)).await;
    assert_eq!(real.len(), 1);

    // An unknown tenant → the system partition, never lost.
    let r2 = failing_token_post(&app, Uuid::new_v4(), "oa_b", None).await;
    assert_eq!(r2.status().as_u16(), 401);
    let system = eventually(|| client_auth_failure_system_rows(&db)).await;
    assert_eq!(
        system.len(),
        1,
        "an unattributable failure must be recorded, not dropped"
    );
}

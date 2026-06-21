//! RFC 6749 / RFC 7636 MUST-level conformance tests.
//!
//! Covers gap behaviors NOT exercised by oauth2_flow_test.rs:
//! - PKCE plain method rejection (RFC 7636 §4.2)
//! - PKCE verifier length bounds (RFC 7636 §4.1)
//! - WWW-Authenticate header on 401 invalid_client (RFC 6749 §5.2)
//! - token_type=Bearer in success response (RFC 6749 §7.1)
//! - Cross-client refresh token rejection (RFC 6749 §6)
//!
//! Harness is a verbatim copy of oauth2_flow_test.rs — house style
//! for this project (no shared utility module exists).

use actix_web::{App, test, web};
use std::net::SocketAddr;

use axiam_api_rest::RateLimitConfig;

/// Loopback peer address for test requests so the rate-limiter key extractor
/// can resolve a client IP without a real socket.
const TEST_PEER: &str = "127.0.0.1:12345";

use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealAuthorizationCodeRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealRefreshTokenRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_oauth2::authorize::AuthorizeService;
use axiam_oauth2::token::TokenService;
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
// Test scaffolding — mirrors oauth2_flow_test.rs exactly
// ---------------------------------------------------------------------------

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
        oauth2_issuer_url: "https://localhost".into(),
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
        let client_repo = SurrealOAuth2ClientRepository::new($db.clone());
        let code_repo = SurrealAuthorizationCodeRepository::new($db.clone());
        let tenant_repo = SurrealTenantRepository::new($db.clone());
        let refresh_repo = SurrealRefreshTokenRepository::new($db.clone());
        let user_repo = SurrealUserRepository::new($db.clone());

        let authz_service = AuthorizeService::new(
            client_repo.clone(),
            code_repo.clone(),
            600, // 10-minute code lifetime
        );
        let token_service = TokenService::new(
            client_repo.clone(),
            code_repo.clone(),
            tenant_repo.clone(),
            refresh_repo,
            user_repo.clone(),
            $auth.clone(),
            2_592_000, // 30-day refresh token lifetime
        );

        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(client_repo))
                .app_data(web::Data::new(code_repo))
                .app_data(web::Data::new(tenant_repo))
                .app_data(web::Data::new(user_repo))
                .app_data(web::Data::new(authz_service))
                .app_data(web::Data::new(token_service))
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

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Flow helpers
// ---------------------------------------------------------------------------

/// Create a confidential OAuth2 client (authorization_code + refresh_token).
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
            "name": "Conformance Test Client",
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

/// GET /oauth2/authorize and return the raw 302 response (without following).
async fn do_authorize_raw(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    uri: &str,
) -> actix_web::dev::ServiceResponse {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(uri)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    test::call_service(app, req).await
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
    code_challenge: Option<&str>,
) -> String {
    let mut uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}"
    );
    if let Some(ch) = code_challenge {
        uri.push_str("&code_challenge=");
        uri.push_str(ch);
        uri.push_str("&code_challenge_method=S256");
    }

    let resp = do_authorize_raw(app, token, &uri).await;
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

    let url = url::Url::parse(&location).unwrap();
    url.query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("code not found in redirect Location")
}

/// POST to /oauth2/token with form-encoded params, return the response.
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
// RFC 7636 §4.2 — S256-only enforcement: plain method MUST be rejected
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn pkce_plain_method_rejected() {
    // RFC 7636 §4.2: Servers MUST support S256 and MAY support plain.
    // AXIAM policy: only S256 is supported — plain is rejected.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Use plain challenge method — AXIAM should reject it.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // 43 chars
    let challenge = verifier; // plain method: challenge == verifier

    let uri = format!(
        "/oauth2/authorize?response_type=code&client_id={client_id}\
         &redirect_uri={redirect_uri}\
         &code_challenge={challenge}&code_challenge_method=plain"
    );

    let resp = do_authorize_raw(&app, &user_jwt, &uri).await;

    // Expect either an error redirect (302 with error=) or a direct 400.
    // Per RFC 7636 §4.2: server MUST NOT issue a code for an unsupported method.
    if resp.status().as_u16() == 302 {
        let location = resp.headers().get("Location").unwrap().to_str().unwrap();
        assert!(
            location.contains("error="),
            "plain method redirect must contain error param, got: {location}"
        );
    } else {
        // Direct error response is also acceptable
        assert_eq!(
            resp.status().as_u16(),
            400,
            "plain method must be rejected with error redirect or 400"
        );
        let body: serde_json::Value = test::read_body_json(resp).await;
        let error = body["error"].as_str().unwrap_or("");
        assert!(
            error == "invalid_request" || error == "unsupported_challenge_method",
            "unexpected error code: {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// RFC 7636 §4.1 — Verifier length bounds
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn pkce_verifier_too_short_rejected() {
    // RFC 7636 §4.1: code_verifier MUST be ≥ 43 characters.
    // A verifier < 43 chars at the token endpoint must return invalid_grant.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Register a valid S256 challenge
    let valid_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // 43 chars
    let challenge = pkce_challenge(valid_verifier);

    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, Some(&challenge)).await;

    // Submit a 42-character verifier (one below minimum) at token exchange
    let short_verifier = "a".repeat(42);
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        Some(&short_verifier),
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        400,
        "verifier < 43 chars must be rejected with 400"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "invalid_grant",
        "short verifier must produce invalid_grant"
    );
}

#[actix_rt::test]
async fn pkce_verifier_too_long_rejected() {
    // RFC 7636 §4.1: code_verifier MUST be ≤ 128 characters.
    // A verifier > 128 chars at the token endpoint must return invalid_grant.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;

    // Register a valid S256 challenge
    let valid_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"; // 43 chars
    let challenge = pkce_challenge(valid_verifier);

    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, Some(&challenge)).await;

    // Submit a 129-character verifier (one above maximum) at token exchange
    let long_verifier = "a".repeat(129);
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        &client_secret,
        &code,
        &redirect_uri,
        Some(&long_verifier),
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        400,
        "verifier > 128 chars must be rejected with 400"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "invalid_grant",
        "long verifier must produce invalid_grant"
    );
}

// ---------------------------------------------------------------------------
// RFC 6749 §5.2 — WWW-Authenticate header on 401 invalid_client
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn invalid_client_returns_www_authenticate_header() {
    // RFC 6749 §5.2: The authorization server MUST include the
    // "WWW-Authenticate" response header field when returning a 401
    // Unauthorized status code.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, _correct_secret, redirect_uri) = create_client(&app, &user_jwt).await;
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None).await;

    // Submit request with WRONG client secret
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_id,
        "definitely-wrong-secret",
        &code,
        &redirect_uri,
        None,
    )
    .await;

    assert_eq!(
        resp.status().as_u16(),
        401,
        "wrong client secret must return 401"
    );

    // RFC 6749 §5.2: 401 MUST include WWW-Authenticate
    assert!(
        resp.headers().get("WWW-Authenticate").is_some(),
        "401 invalid_client response must include WWW-Authenticate header"
    );

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "invalid_client",
        "error body must be invalid_client"
    );
}

// ---------------------------------------------------------------------------
// RFC 6749 §7.1 — token_type=Bearer in successful token response
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn token_response_includes_bearer_token_type() {
    // RFC 6749 §7.1: The token type value is case insensitive.
    // AXIAM returns "Bearer" (capitalized) per convention.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (client_id, client_secret, redirect_uri) = create_client(&app, &user_jwt).await;
    let code = do_authorize(&app, &user_jwt, &client_id, &redirect_uri, None).await;

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

    // RFC 6749 §7.1: token_type MUST be present and case-insensitively equal to "bearer"
    let token_type = body["token_type"]
        .as_str()
        .expect("token_type must be a string in token response");
    assert_eq!(
        token_type.to_lowercase(),
        "bearer",
        "token_type must be Bearer (got: {token_type})"
    );
}

// ---------------------------------------------------------------------------
// RFC 6749 §6 — refresh token is bound to the issuing client
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn refresh_token_bound_to_original_client() {
    // RFC 6749 §6: The authorization server MUST ... validate the
    // client credentials ... and ensure that the refresh token was
    // issued to the authenticated client.
    // Redeeming a refresh token issued to client A with client B credentials
    // must return invalid_grant.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let user_jwt = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create client A and get a refresh token
    let (client_a_id, client_a_secret, redirect_uri) = create_client(&app, &user_jwt).await;
    let code = do_authorize(&app, &user_jwt, &client_a_id, &redirect_uri, None).await;
    let resp = do_token_exchange(
        &app,
        tenant_id,
        &client_a_id,
        &client_a_secret,
        &code,
        &redirect_uri,
        None,
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let refresh_token = body["refresh_token"]
        .as_str()
        .expect("refresh_token missing from auth-code response")
        .to_string();

    // Create client B (separate client registration)
    let (client_b_id, client_b_secret, _) = create_client(&app, &user_jwt).await;
    assert_ne!(client_a_id, client_b_id, "must be distinct clients");

    // Attempt to use client A's refresh token with client B credentials
    let form = format!(
        "grant_type=refresh_token&refresh_token={refresh_token}\
         &client_id={client_b_id}&client_secret={client_b_secret}"
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
        .set_payload(form)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.status().as_u16(),
        400,
        "cross-client refresh must be rejected with 400"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "invalid_grant",
        "cross-client refresh must return invalid_grant"
    );
}

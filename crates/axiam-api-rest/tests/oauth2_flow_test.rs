//! Integration tests for the OAuth2 Authorization Code (+ PKCE) flow.
//!
//! Each test exercises the full authorize → token exchange round-trip through
//! the real HTTP layer, using an in-memory SurrealDB instance.

use actix_web::{App, test, web};
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
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

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
    issue_access_token(user_id, tenant_id, org_id, &[], auth).unwrap()
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
                .configure(register_api_v1_routes::<TestDb>),
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
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
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

    let verifier = "my-pkce-code-verifier-for-test-1234567890";
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

    let correct_verifier = "correct-verifier-string-1234567890abcd";
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
        Some("wrong-verifier-that-does-not-match"),
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
        .uri(&uri)
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // The spec redirects with an error; we still get a 302 but with error params
    assert_eq!(resp.status().as_u16(), 302);
    let location = resp.headers().get("Location").unwrap().to_str().unwrap();
    // The Location must point to the bad redirect with an error parameter
    assert!(
        location.contains("error="),
        "expected error param in Location, got: {location}"
    );
    assert!(
        !location.contains("code="),
        "code must not be issued for unregistered redirect_uri"
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

    let verifier = "a-valid-code-verifier-string-1234567890";
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
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
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
        .uri("/.well-known/openid-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["issuer"], "axiam-test");
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

    let req = test::TestRequest::get().uri("/oauth2/jwks").to_request();
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
    let user_jwt = issue_access_token(user_id, tenant_id, org_id, &scopes, &auth).unwrap();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
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
    let user_jwt = issue_access_token(user_id, tenant_id, org_id, &scopes, &auth).unwrap();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
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
    assert_eq!(claims["iss"], "axiam-test");
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
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {user_jwt}")))
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

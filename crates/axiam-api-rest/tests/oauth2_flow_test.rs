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
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
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
    issue_access_token(user_id, tenant_id, org_id, auth).unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {{
        let client_repo = SurrealOAuth2ClientRepository::new($db.clone());
        let code_repo = SurrealAuthorizationCodeRepository::new($db.clone());
        let tenant_repo = SurrealTenantRepository::new($db.clone());

        let authz_service = AuthorizeService::new(
            client_repo.clone(),
            code_repo.clone(),
            600, // 10-minute code lifetime
        );
        let token_service = TokenService::new(
            client_repo.clone(),
            code_repo.clone(),
            tenant_repo.clone(),
            $auth.clone(),
        );

        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(client_repo))
                .app_data(web::Data::new(code_repo))
                .app_data(web::Data::new(tenant_repo))
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
            "grant_types": ["authorization_code"],
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
    let location = resp
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap();
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
    let location = resp
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap();
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
        "grant_type=client_credentials&code=fakecode&redirect_uri={redirect_uri}\
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

    let location = resp
        .headers()
        .get("Location")
        .unwrap()
        .to_str()
        .unwrap();

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

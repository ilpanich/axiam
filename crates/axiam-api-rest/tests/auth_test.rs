//! Integration tests for authentication endpoints.
//!
//! All tests use cookie-based auth (cookie jar pattern, no Authorization
//! header). CSRF double-submit cookie flow is validated throughout.

use actix_web::{App, test, web};
use std::net::SocketAddr;

use axiam_api_rest::RateLimitConfig;

/// Loopback peer address for test requests so the rate-limiter key extractor
/// (XForwardedForKeyExtractor) can resolve a client IP without a real socket.
const TEST_PEER: &str = "127.0.0.1:12345";
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
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
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealRoleRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use std::sync::Arc;
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

// ---------------------------------------------------------------------------
// Cookie jar helpers
// ---------------------------------------------------------------------------

/// Extract the raw value of a named cookie from a response's Set-Cookie headers.
fn extract_cookie_value<B>(
    resp: &actix_web::dev::ServiceResponse<B>,
    name: &str,
) -> Option<String> {
    resp.response()
        .cookies()
        .find(|c: &actix_web::cookie::Cookie| c.name() == name)
        .map(|c| c.value().to_owned())
}

/// Extract the full Set-Cookie header string that matches the given cookie name.
/// Used to verify cookie attributes (httpOnly, Secure, SameSite, Path, Max-Age)
/// because the parsed Cookie object may not expose all attributes.
fn extract_set_cookie_header<B>(
    resp: &actix_web::dev::ServiceResponse<B>,
    name: &str,
) -> Option<String> {
    use actix_web::http::header::SET_COOKIE;
    resp.headers()
        .get_all(SET_COOKIE)
        .filter_map(|v: &actix_web::http::header::HeaderValue| v.to_str().ok())
        .find(|s: &&str| s.starts_with(&format!("{}=", name)))
        .map(|s| s.to_owned())
}

/// Build a `Cookie` header value from a slice of (name, value) pairs,
/// simulating the browser sending stored cookies back to the server.
fn cookie_header(cookies: &[(&str, &str)]) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// Login tests — cookie attributes (01-01-01, 01-01-02)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn login_sets_httponly_access_cookie() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "login should return 200");

    // Access cookie must be present and non-empty.
    let access_value = extract_cookie_value(&resp, "axiam_access");
    assert!(
        access_value.is_some(),
        "axiam_access cookie must be set on login"
    );
    assert!(
        !access_value.unwrap().is_empty(),
        "axiam_access cookie value must not be empty"
    );

    // Verify cookie attributes via Set-Cookie header string.
    let set_cookie = extract_set_cookie_header(&resp, "axiam_access")
        .expect("Set-Cookie header for axiam_access must be present");
    let lower = set_cookie.to_lowercase();
    assert!(
        lower.contains("httponly"),
        "axiam_access must have HttpOnly"
    );
    assert!(
        lower.contains("samesite=strict"),
        "axiam_access must have SameSite=Strict"
    );
    assert!(lower.contains("path=/"), "axiam_access must have Path=/");

    // Response body must contain user info but NOT access_token / refresh_token.
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["user"]["id"].is_string(),
        "response body must include user.id"
    );
    assert!(
        body["user"]["username"].is_string(),
        "response body must include user.username"
    );
    assert!(
        body["user"]["email"].is_string(),
        "response body must include user.email"
    );
    assert!(
        body["session_id"].is_string(),
        "response body must include session_id"
    );
    assert!(
        body["expires_in"].is_number(),
        "response body must include expires_in"
    );
    assert!(
        body["access_token"].is_null() || body.get("access_token").is_none(),
        "access_token must NOT appear in response body"
    );
    assert!(
        body["refresh_token"].is_null() || body.get("refresh_token").is_none(),
        "refresh_token must NOT appear in response body"
    );
}

#[actix_rt::test]
async fn login_sets_pathscoped_refresh_cookie() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let refresh_value = extract_cookie_value(&resp, "axiam_refresh");
    assert!(
        refresh_value.is_some(),
        "axiam_refresh cookie must be set on login"
    );
    assert!(
        !refresh_value.unwrap().is_empty(),
        "axiam_refresh cookie value must not be empty"
    );

    let set_cookie = extract_set_cookie_header(&resp, "axiam_refresh")
        .expect("Set-Cookie header for axiam_refresh must be present");
    let lower = set_cookie.to_lowercase();
    assert!(
        lower.contains("httponly"),
        "axiam_refresh must have HttpOnly"
    );
    assert!(
        lower.contains("samesite=strict"),
        "axiam_refresh must have SameSite=Strict"
    );
    assert!(
        lower.contains("path=/api/v1/auth/refresh"),
        "axiam_refresh must be path-scoped to /api/v1/auth/refresh"
    );
}

#[actix_rt::test]
async fn login_sets_csrf_cookie() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let csrf_value = extract_cookie_value(&resp, "axiam_csrf");
    assert!(
        csrf_value.is_some(),
        "axiam_csrf cookie must be set on login"
    );
    assert!(
        !csrf_value.unwrap().is_empty(),
        "axiam_csrf cookie value must not be empty"
    );

    let set_cookie = extract_set_cookie_header(&resp, "axiam_csrf")
        .expect("Set-Cookie header for axiam_csrf must be present");
    let lower = set_cookie.to_lowercase();

    // axiam_csrf must NOT be httpOnly (JS-readable for CSRF double-submit).
    assert!(
        !lower.contains("httponly"),
        "axiam_csrf must NOT have HttpOnly (must be JS-readable)"
    );
    assert!(lower.contains("path=/"), "axiam_csrf must have Path=/");
}

// ---------------------------------------------------------------------------
// CSRF middleware tests (01-01-03)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn csrf_missing_header_returns_403() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to get access cookie.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let access_token = extract_cookie_value(&resp, "axiam_access").unwrap();
    let session_id: serde_json::Value = test::read_body_json(resp).await;
    let session_id = session_id["session_id"].as_str().unwrap().to_owned();

    // POST /auth/logout with access cookie but WITHOUT X-CSRF-Token header.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/logout")
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .set_json(serde_json::json!({ "session_id": session_id }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "POST without X-CSRF-Token must be rejected with 403"
    );
}

#[actix_rt::test]
async fn csrf_valid_header_allows_request() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to get cookies.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let access_token = extract_cookie_value(&resp, "axiam_access").unwrap();
    let csrf_token = extract_cookie_value(&resp, "axiam_csrf").unwrap();
    let body: serde_json::Value = test::read_body_json(resp).await;
    let session_id = body["session_id"].as_str().unwrap().to_owned();

    // POST with valid X-CSRF-Token — should NOT be rejected with 403.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/logout")
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token.clone()))
        .set_json(serde_json::json!({ "session_id": session_id }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // The request must not be rejected with 403 (CSRF check passes).
    // A 204 means logout succeeded; other non-403 codes are also acceptable.
    assert_ne!(
        resp.status().as_u16(),
        403,
        "POST with valid X-CSRF-Token must not return 403"
    );
}

#[actix_rt::test]
async fn csrf_get_request_passes_without_token() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to get access cookie.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let access_token = extract_cookie_value(&resp, "axiam_access").unwrap();

    // GET /auth/me with only access cookie — no X-CSRF-Token needed for GET.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "GET must pass through CSRF middleware without a token"
    );
}

// ---------------------------------------------------------------------------
// Logout test — cookie clearing (01-01-04)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn logout_clears_cookies() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to get all cookies.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let access_token = extract_cookie_value(&resp, "axiam_access").unwrap();
    let csrf_token = extract_cookie_value(&resp, "axiam_csrf").unwrap();
    let body: serde_json::Value = test::read_body_json(resp).await;
    let session_id = body["session_id"].as_str().unwrap().to_owned();

    // POST /auth/logout with cookies + CSRF header.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/logout")
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token))
        .set_json(serde_json::json!({ "session_id": session_id }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204, "logout must return 204");

    // All three cookies must be cleared (Max-Age=0 or expires in the past).
    let access_hdr = extract_set_cookie_header(&resp, "axiam_access")
        .expect("Set-Cookie for axiam_access must be present on logout");
    let refresh_hdr = extract_set_cookie_header(&resp, "axiam_refresh")
        .expect("Set-Cookie for axiam_refresh must be present on logout");
    let csrf_hdr = extract_set_cookie_header(&resp, "axiam_csrf")
        .expect("Set-Cookie for axiam_csrf must be present on logout");

    // Actix's `make_removal()` sets Max-Age=0; assert any of the clearing signals.
    for (name, hdr) in [
        ("axiam_access", &access_hdr),
        ("axiam_refresh", &refresh_hdr),
        ("axiam_csrf", &csrf_hdr),
    ] {
        let lower = hdr.to_lowercase();
        let cleared = lower.contains("max-age=0")
            || lower.contains("expires=thu, 01 jan 1970")
            || lower.contains("expires=thu,01 jan 1970");
        assert!(
            cleared,
            "{name} Set-Cookie header must indicate cookie removal (Max-Age=0 or past Expires): {hdr}"
        );
    }
}

// ---------------------------------------------------------------------------
// Refresh test — cookie rotation (01-01-05)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn refresh_uses_cookie_returns_new_access_cookie() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to get cookies.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let refresh_token = extract_cookie_value(&resp, "axiam_refresh").unwrap();
    let old_access = extract_cookie_value(&resp, "axiam_access").unwrap();

    // POST /auth/refresh with the refresh cookie.
    // The refresh endpoint reads axiam_refresh from the cookie and is CSRF-exempt
    // (no session cookie exists yet during refresh flows; login/mfa/refresh are exempt).
    // However the CSRF middleware path exemption list only covers login/mfa/confirm/device.
    // Refresh is NOT exempt — supply the CSRF token if we have it.
    let csrf_token = extract_cookie_value(&resp, "axiam_csrf").unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/refresh")
        .insert_header((
            "Cookie",
            cookie_header(&[
                ("axiam_refresh", &refresh_token),
                ("axiam_csrf", &csrf_token),
            ]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token))
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "refresh must return 200");

    // New axiam_access cookie must be set.
    let new_access = extract_cookie_value(&resp, "axiam_access");
    assert!(
        new_access.is_some(),
        "refresh response must set a new axiam_access cookie"
    );
    assert!(
        !new_access.as_ref().unwrap().is_empty(),
        "new axiam_access cookie value must not be empty"
    );
    assert_ne!(
        new_access.unwrap(),
        old_access,
        "new axiam_access cookie must differ from the original (token rotation)"
    );

    // Response body must have expires_in but NOT access_token.
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["expires_in"].is_number(),
        "refresh response body must include expires_in"
    );
    assert!(
        body["access_token"].is_null() || body.get("access_token").is_none(),
        "access_token must NOT appear in refresh response body"
    );
}

// ---------------------------------------------------------------------------
// /me endpoint tests
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn me_returns_user_info() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to get access cookie.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let access_token = extract_cookie_value(&resp, "axiam_access").unwrap();

    // GET /auth/me with access cookie.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "/me must return 200");

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["user"]["id"].is_string(),
        "/me response must include user.id"
    );
    assert!(
        body["user"]["username"].is_string(),
        "/me response must include user.username"
    );
    assert!(
        body["user"]["email"].is_string(),
        "/me response must include user.email"
    );
    assert_eq!(
        body["user"]["username"].as_str().unwrap(),
        "alice",
        "username must match the logged-in user"
    );
}

#[actix_rt::test]
async fn me_returns_401_without_cookie() {
    let (db, _org_id, _tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // GET /auth/me with no cookies and no Authorization header.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "/me must return 401 when no cookie or auth header is present"
    );
}

// ---------------------------------------------------------------------------
// Invalid credential tests (unchanged behavior)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn login_with_invalid_password_returns_401() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
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
async fn refresh_with_invalid_token_returns_401() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Need a CSRF token to pass the middleware — get one from a login first,
    // then pass an invalid refresh cookie value.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let csrf_token = extract_cookie_value(&resp, "axiam_csrf").unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/refresh")
        .insert_header((
            "Cookie",
            cookie_header(&[
                ("axiam_refresh", "invalid-token-value"),
                ("axiam_csrf", &csrf_token),
            ]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token))
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/setup/enroll")
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
async fn mfa_setup_full_flow_sets_cookies() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = mfa_auth_config();
    enable_mfa_enforcement(&db, org_id).await;
    let app = test_app!(db, auth);

    // Step 1: Login → 403 with setup_token.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
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
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/setup/enroll")
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

    // Step 4: Confirm → 200 with cookies (not tokens in body).
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/setup/confirm")
        .set_json(serde_json::json!({
            "setup_token": &setup_token,
            "totp_code": code
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Cookies must be set on MFA confirm (not tokens in body).
    let access_value = extract_cookie_value(&resp, "axiam_access");
    let csrf_value = extract_cookie_value(&resp, "axiam_csrf");
    assert!(
        access_value.is_some() && !access_value.unwrap().is_empty(),
        "axiam_access cookie must be set after MFA confirm"
    );
    assert!(
        csrf_value.is_some() && !csrf_value.unwrap().is_empty(),
        "axiam_csrf cookie must be set after MFA confirm"
    );

    // Response body: user info present, access_token NOT present.
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["user"]["id"].is_string(),
        "response body must include user.id after MFA confirm"
    );
    assert!(
        body["session_id"].is_string(),
        "response body must include session_id after MFA confirm"
    );
    assert!(
        body["access_token"].is_null() || body.get("access_token").is_none(),
        "access_token must NOT appear in MFA confirm response body"
    );
}

#[actix_rt::test]
async fn reset_mfa_requires_authentication() {
    let (db, _org_id, _tenant_id, user_id) = setup_db().await;
    let auth = mfa_auth_config();
    let app = test_app!(db, auth);

    // POST without any cookie → 401.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "expected 401 without auth cookie"
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

    // Login as alice to get access cookie.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let access_token = extract_cookie_value(&resp, "axiam_access").unwrap();

    // Reset MFA for the target user — using cookie-based auth.
    // The /api/v1 scope has no CSRF middleware, so no X-CSRF-Token needed here.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{}/reset-mfa", target.id))
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "expected 403 — MFA reset is disabled until RBAC is implemented"
    );
}

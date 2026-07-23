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
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker, DenyAllAuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
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

macro_rules! test_app {
    // Default: allow-all authz checker (most tests don't exercise RBAC denial).
    ($db:expr, $auth:expr) => {
        test_app!(
            $db,
            $auth,
            Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
        )
    };
    // Explicit checker: lets a test assert the forbidden path (e.g. DenyAll).
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(
                    Arc::new(SurrealSessionRepository::new($db.clone()))
                        as Arc<dyn axiam_api_rest::SessionValidator>,
                ))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new($authz))
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

    // POST /auth/logout with cookies + CSRF header — no request body (D-03 /
    // SECFIX-05): the session to revoke is derived solely from the caller's
    // verified JWT `jti`, never a client-supplied session_id.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/logout")
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token))
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

    // SECFIX-05 defining negative signal: replaying the OLD access cookie
    // after logout must be unauthenticated. The session row behind the JWT
    // `jti` is hard-deleted by `AuthService::logout`, so `SessionValidator`'s
    // per-request liveness check (extractors/auth.rs) must reject the replay
    // even though the JWT itself has not expired.
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "replaying the pre-logout access cookie must be unauthenticated (session revoked)"
    );
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

    // POST with a valid CSRF double-submit token but NO access cookie. The CSRF
    // middleware (outermost on /api/v1) passes when cookie == header; the inner
    // AuthzMiddleware then rejects the missing credential with 401.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .insert_header(("Cookie", cookie_header(&[("axiam_csrf", "test-csrf")])))
        .insert_header(("X-CSRF-Token", "test-csrf"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "expected 401 without auth cookie"
    );
}

// A non-admin caller (one whose `users:admin` check is denied by the authz
// engine) must NOT be able to reset another user's MFA. We register a
// `DenyAllAuthzChecker` to simulate the missing permission, and the handler's
// `RequirePermission` gate must turn that denial into HTTP 403 — proving the
// privilege-escalation guard (any authenticated user resetting another's MFA)
// is closed. See [`reset_mfa_allowed_for_admin_returns_204`] for the allow path.
#[actix_rt::test]
async fn reset_mfa_denied_for_non_admin_returns_403() {
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

    // Authz engine denies the `users:admin` permission for this caller.
    let app = test_app!(
        db,
        auth,
        Arc::new(DenyAllAuthzChecker) as Arc<dyn AuthzChecker>
    );

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
    let csrf_token = extract_cookie_value(&resp, "axiam_csrf").unwrap();

    // Reset MFA for the target user — cookie-based auth plus the CSRF
    // double-submit token (the /api/v1 scope is CSRF-protected, SEC-046).
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{}/reset-mfa", target.id))
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "non-admin caller must be forbidden from resetting another user's MFA"
    );
}

// The mirror of [`reset_mfa_denied_for_non_admin_returns_403`]: when the authz
// engine GRANTS `users:admin` (here via `AllowAllAuthzChecker`), the reset
// succeeds and returns 204. This confirms the gate is a real authorization
// decision, not a blanket deny.
#[actix_rt::test]
async fn reset_mfa_allowed_for_admin_returns_204() {
    let (db, org_id, tenant_id, _admin_user_id) = setup_db().await;
    let auth = mfa_auth_config();

    // Create + activate a second user to be the target of the reset.
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

    // Default app uses AllowAllAuthzChecker → caller is treated as authorized.
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
    let csrf_token = extract_cookie_value(&resp, "axiam_csrf").unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{}/reset-mfa", target.id))
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        204,
        "authorized admin caller must succeed in resetting MFA"
    );
}

// ---------------------------------------------------------------------------
// R4: login workspace-identity validation arms (org/tenant id-vs-slug).
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn login_rejects_missing_org_identifier() {
    let (db, _org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn login_rejects_missing_tenant_identifier() {
    let (db, org_id, _tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn login_rejects_unknown_org_slug() {
    let (db, _org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_slug": "no-such-org",
            "tenant_id": tenant_id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn login_rejects_unknown_tenant_slug() {
    let (db, org_id, _tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_slug": "no-such-tenant",
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn login_accepts_org_slug_and_tenant_slug() {
    let (db, _org_id, _tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "org_slug": "test-org",
            "tenant_slug": "test-tenant",
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "slug-based org/tenant resolution must succeed"
    );
}

/// SECURITY (NEW-1): a caller passing a raw `tenant_id` that legitimately
/// exists but belongs to a DIFFERENT org than the supplied `org_id` must be
/// rejected — otherwise a client could bind their own tenant to a foreign
/// org_id and mint a cross-organization token.
#[actix_rt::test]
async fn login_rejects_tenant_org_mismatch() {
    let (db, _org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();

    // Create a second, unrelated organization (no tenant relationship to
    // `tenant_id` above).
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let other_org = org_repo
        .create(CreateOrganization {
            name: "Other Org".into(),
            slug: "other-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            // tenant_id is real, but belongs to the ORIGINAL org, not other_org.
            "tenant_id": tenant_id,
            "org_id": other_org.id,
            "username_or_email": "alice",
            "password": "password12345"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "tenant/org mismatch must be rejected as invalid credentials"
    );
}

// ---------------------------------------------------------------------------
// R4: refresh — missing cookie / unknown tenant arms.
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn refresh_missing_cookie_returns_401() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Need a CSRF-cookie pair from a login first so we don't get a 403
    // before ever reaching the handler's missing-refresh-cookie check.
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
        .insert_header(("Cookie", format!("axiam_csrf={csrf_token}")))
        .insert_header(("X-CSRF-Token", csrf_token))
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn refresh_with_unknown_tenant_id_returns_401() {
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
    let refresh_token = extract_cookie_value(&resp, "axiam_refresh").unwrap();
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
            "tenant_id": Uuid::new_v4(),
            "org_id": org_id,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// R4: session-based voluntary MFA enroll/confirm + login MfaRequired/verify
// branches. These endpoints (enroll_mfa/confirm_mfa/verify_mfa) had no
// coverage — only the setup-token variants (mfa/setup/enroll,
// mfa/setup/confirm) were exercised above.
// ---------------------------------------------------------------------------

/// Helper: log in as alice and return (access_token, csrf_token).
async fn login_get_cookies(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    tenant_id: Uuid,
    org_id: Uuid,
) -> (String, String) {
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
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "login must succeed");
    let access_token = extract_cookie_value(&resp, "axiam_access").unwrap();
    let csrf_token = extract_cookie_value(&resp, "axiam_csrf").unwrap();
    (access_token, csrf_token)
}

#[actix_rt::test]
async fn enroll_and_confirm_mfa_then_login_requires_verify() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = mfa_auth_config(); // MFA encryption key set, enforcement OFF.
    let app = test_app!(db, auth);

    let (access_token, csrf_token) = login_get_cookies(&app, tenant_id, org_id).await;

    // Step 1: voluntary enroll (session-based, not setup-token).
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/enroll")
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "enroll_mfa must succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    let secret_base32 = body["secret_base32"].as_str().unwrap().to_string();
    assert!(
        body["totp_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/"),
        "enroll_mfa must return a totp_uri"
    );

    // `step_offset` lets the caller request a code for a step other than the
    // current one (e.g. `+1`) — needed because the server persists a
    // `totp_last_used_step` replay guard (SECHRD-01): reusing a code from an
    // already-consumed step is correctly rejected, so step 7 below must mint
    // a code for the NEXT step rather than the exact same code confirm_mfa
    // already consumed in step 3 (no real sleep needed — skew=1 accepts the
    // next step early).
    let gen_code_at_offset = |secret_b32: &str, step_offset: i64| -> String {
        let secret = totp_rs::Secret::Encoded(secret_b32.to_string());
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let current_step = now / 30;
        let target_time = ((current_step as i64 + step_offset).max(0) as u64) * 30;
        totp.generate(target_time)
    };
    let gen_code = |secret_b32: &str| -> String { gen_code_at_offset(secret_b32, 0) };

    // Step 2: confirm with a WRONG code first — must 401 and NOT enable MFA.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/confirm")
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token.clone()))
        .set_json(serde_json::json!({ "totp_code": "000000" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "confirm_mfa with a wrong TOTP code must fail"
    );

    // Step 3: confirm with the correct code — must succeed.
    let code = gen_code(&secret_base32);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/confirm")
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token.clone()))
        .set_json(serde_json::json!({ "totp_code": code }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "confirm_mfa must succeed");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["mfa_enabled"], true);

    // Step 4: a FRESH login must now be challenged (202 MfaRequired) instead
    // of succeeding outright — exercises the login handler's MfaRequired
    // branch (available_methods lookup) which was previously untested.
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
    assert_eq!(
        resp.status().as_u16(),
        202,
        "login for an MFA-enabled user must return 202 MfaRequired"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["mfa_required"], true);
    let challenge_token = body["challenge_token"].as_str().unwrap().to_string();
    assert!(
        body["available_methods"]
            .as_array()
            .map(|a| !a.is_empty())
            .unwrap_or(false),
        "available_methods must be populated for an MFA-enabled user, got {body}"
    );

    // Step 5: verify_mfa with a WRONG code must 401.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/verify")
        .set_json(serde_json::json!({
            "challenge_token": &challenge_token,
            "totp_code": "000000"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "verify_mfa with a wrong TOTP code must fail"
    );

    // Step 6: verify_mfa with a garbage challenge_token must 401.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/verify")
        .set_json(serde_json::json!({
            "challenge_token": "not-a-real-challenge-token",
            "totp_code": "000000"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "verify_mfa with an invalid challenge_token must fail"
    );

    // Step 7: verify_mfa with the CORRECT code must succeed and set cookies
    // (not return tokens in the body — same contract as the setup/confirm
    // and login-success paths). Use the NEXT step (see `gen_code_at_offset`
    // docs above) since step 3 already consumed the current step.
    let code = gen_code_at_offset(&secret_base32, 1);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/verify")
        .set_json(serde_json::json!({
            "challenge_token": &challenge_token,
            "totp_code": code
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "verify_mfa must succeed");

    let access_value = extract_cookie_value(&resp, "axiam_access");
    assert!(
        access_value.is_some() && !access_value.unwrap().is_empty(),
        "axiam_access cookie must be set after verify_mfa"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(
        body["access_token"].is_null() || body.get("access_token").is_none(),
        "access_token must NOT appear in verify_mfa response body"
    );
}

// ---------------------------------------------------------------------------
// R4: change_password — oversized new_password DoS guard.
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn change_password_rejects_oversized_new_password() {
    let (db, org_id, tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let (access_token, csrf_token) = login_get_cookies(&app, tenant_id, org_id).await;

    let oversized = "a".repeat(1025);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/password/change")
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token))
        .set_json(serde_json::json!({
            "current_password": "password12345",
            "new_password": oversized
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

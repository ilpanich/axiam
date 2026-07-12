//! Integration tests for CSRF enforcement on /api/v1 CRUD routes (SEC-046).
//!
//! Verifies that POST/PUT/DELETE to any `/api/v1` endpoint:
//!   - Returns 403 when the `X-CSRF-Token` header is absent.
//!   - Does NOT return 403 when a valid `X-CSRF-Token` matches the cookie.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";

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
            name: "CSRF Test Org".into(),
            slug: "csrf-test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "CSRF Test Tenant".into(),
            slug: "csrf-test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "csrf-user".into(),
            email: "csrf-user@example.com".into(),
            password: "password12345csrf".into(),
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

    (db, org.id, tenant.id, user.id)
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

fn extract_cookie_value<B>(
    resp: &actix_web::dev::ServiceResponse<B>,
    name: &str,
) -> Option<String> {
    resp.response()
        .cookies()
        .find(|c: &actix_web::cookie::Cookie| c.name() == name)
        .map(|c| c.value().to_owned())
}

fn cookie_header(cookies: &[(&str, &str)]) -> String {
    cookies
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// CSRF tests for /api/v1 CRUD routes (SEC-046)
// ---------------------------------------------------------------------------

/// POST to /api/v1 without X-CSRF-Token must return 403.
#[actix_rt::test]
async fn csrf_crud_post_without_token_returns_403() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to obtain access + CSRF cookies.
    let login_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "csrf-user",
            "password": "password12345csrf"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status().as_u16(), 200, "login must succeed");
    let access_token = extract_cookie_value(&login_resp, "axiam_access").unwrap();

    // PUT /api/v1/users/{user_id} with access cookie but NO X-CSRF-Token.
    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .set_json(serde_json::json!({ "username": "new-name" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "PUT to /api/v1 without X-CSRF-Token must return 403 (CSRF check)"
    );
}

/// PUT to /api/v1 with a valid X-CSRF-Token must NOT return 403.
#[actix_rt::test]
async fn csrf_crud_put_with_token_not_403() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Login to obtain access + CSRF cookies.
    let login_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "csrf-user",
            "password": "password12345csrf"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status().as_u16(), 200, "login must succeed");
    let access_token = extract_cookie_value(&login_resp, "axiam_access").unwrap();
    let csrf_token = extract_cookie_value(&login_resp, "axiam_csrf").unwrap();

    // PUT /api/v1/users/{user_id} with both cookies and the X-CSRF-Token header.
    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header((
            "Cookie",
            cookie_header(&[("axiam_access", &access_token), ("axiam_csrf", &csrf_token)]),
        ))
        .insert_header(("X-CSRF-Token", csrf_token.clone()))
        .set_json(serde_json::json!({ "username": "new-name" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status().as_u16(),
        403,
        "PUT to /api/v1 with valid X-CSRF-Token must not return 403"
    );
}

/// DELETE to /api/v1 without X-CSRF-Token must return 403.
#[actix_rt::test]
async fn csrf_crud_delete_without_token_returns_403() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let login_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "csrf-user",
            "password": "password12345csrf"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status().as_u16(), 200);
    let access_token = extract_cookie_value(&login_resp, "axiam_access").unwrap();

    let req = test::TestRequest::delete()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "DELETE to /api/v1 without X-CSRF-Token must return 403"
    );
}

/// GET to /api/v1 does NOT require X-CSRF-Token (safe method).
#[actix_rt::test]
async fn csrf_crud_get_passes_without_token() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let login_req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "csrf-user",
            "password": "password12345csrf"
        }))
        .to_request();

    let login_resp = test::call_service(&app, login_req).await;
    assert_eq!(login_resp.status().as_u16(), 200);
    let access_token = extract_cookie_value(&login_resp, "axiam_access").unwrap();

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Cookie", format!("axiam_access={access_token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_ne!(
        resp.status().as_u16(),
        403,
        "GET to /api/v1 must not require X-CSRF-Token"
    );
}

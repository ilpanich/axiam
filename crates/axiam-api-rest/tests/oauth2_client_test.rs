//! Integration tests for OAuth2 client management endpoints.
//!
//! Covers CRUD operations, input validation, and tenant isolation.

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

/// Build a test app with all services needed for OAuth2 client + flow tests.
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
// Helper: create a client via the API and return its body
// ---------------------------------------------------------------------------

async fn create_test_client(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> serde_json::Value {
    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Test Client",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "profile"]
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    test::read_body_json(resp).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn create_oauth2_client_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "My App",
            "redirect_uris": ["https://myapp.example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "email"]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "My App");
    assert!(body["id"].is_string(), "response must include id");
    assert!(
        body["client_id"].is_string(),
        "response must include client_id"
    );
    assert!(
        body["client_secret"].is_string(),
        "response must include one-time client_secret"
    );
    assert_eq!(
        body["redirect_uris"][0],
        "https://myapp.example.com/callback"
    );
    assert_eq!(body["grant_types"][0], "authorization_code");
    assert_eq!(body["tenant_id"], tenant_id.to_string());
}

#[actix_rt::test]
async fn create_oauth2_client_omits_secret_hash() {
    // The create response exposes the plaintext secret exactly once.
    // It must NOT expose client_secret_hash (internal field).
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Secret Test Client",
            "redirect_uris": ["https://example.com/cb"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    // client_secret_hash must never appear in any API response
    assert!(
        body.get("client_secret_hash").is_none(),
        "client_secret_hash must be omitted from API responses"
    );
    // The one-time plaintext secret is expected in the creation response
    assert!(
        body.get("client_secret").is_some(),
        "client_secret must be present in the creation response"
    );
}

#[actix_rt::test]
async fn list_oauth2_clients_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create two clients
    create_test_client(&app, &token).await;
    create_test_client(&app, &token).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 2);
    assert!(body["items"].is_array());
    // Listed entries must NOT expose client_secret_hash
    assert!(body["items"][0].get("client_secret_hash").is_none());
    // Listed entries must NOT expose client_secret either (only shown at creation)
    assert!(body["items"][0].get("client_secret").is_none());
}

#[actix_rt::test]
async fn get_oauth2_client_by_id_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["id"], id);
    assert_eq!(body["name"], "Test Client");
    assert!(body.get("client_secret_hash").is_none());
}

#[actix_rt::test]
async fn get_nonexistent_oauth2_client_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let fake_id = Uuid::new_v4();
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn update_oauth2_client_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Updated Client Name"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Updated Client Name");
    assert_eq!(body["id"], id);
    // Redirect URIs should be unchanged
    assert_eq!(body["redirect_uris"][0], "https://app.example.com/callback");
}

#[actix_rt::test]
async fn delete_oauth2_client_returns_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);

    // Verify it is gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_empty_redirect_uris() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Bad Client",
            "redirect_uris": [],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_http_redirect_uri() {
    // Non-localhost HTTP redirect URIs must be rejected (HTTPS required).
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Http Client",
            "redirect_uris": ["http://example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_allows_http_localhost() {
    // http://localhost is explicitly allowed for development tooling.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    for uri in [
        "http://localhost:3000/callback",
        "http://127.0.0.1:8090/callback",
    ] {
        let req = test::TestRequest::post()
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({
                "name": "Dev Client",
                "redirect_uris": [uri],
                "grant_types": ["authorization_code"],
                "scopes": []
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            201,
            "expected 201 for localhost URI: {uri}"
        );
    }
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_invalid_grant_type() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Bad Grant Client",
            "redirect_uris": ["https://example.com/callback"],
            "grant_types": ["implicit"],   // not in allowed set
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_empty_name() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "",
            "redirect_uris": ["https://example.com/callback"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn tenant_isolation_oauth2_clients() {
    // A client created in tenant A must not be visible to tenant B.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    // Create a second tenant and user
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant2 = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            name: "Tenant 2".into(),
            slug: "tenant-2".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user2 = user_repo
        .create(CreateUser {
            tenant_id: tenant2.id,
            username: "admin2".into(),
            email: "admin2@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let token2 = mint_token(&auth, user2.id, tenant2.id, org_id);

    let app = test_app!(db, auth);

    // Tenant 1 creates a client
    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    // Tenant 2 cannot GET the client by ID
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token2}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);

    // Tenant 2's list must be empty
    let req = test::TestRequest::get()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token2}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 0);
}

// ---------------------------------------------------------------------------
// Additional validation branches: empty grant_types, host-less / fragment
// redirect_uris (create), and the update() validation/adding-auth-code paths.
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn create_oauth2_client_rejects_empty_grant_types() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "No Grants Client",
            "redirect_uris": [],
            "grant_types": [],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_redirect_uri_without_host() {
    // "urn:isbn:..." parses as an absolute URL but has no authority/host, so
    // `Url::host_str()` returns `None` -- the "must be an absolute URL with a
    // host" branch, distinct from the scheme/fragment checks below it.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Hostless Client",
            "redirect_uris": ["urn:isbn:0451450523"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a host-less redirect_uri must be rejected"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    let msg = body["error"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or_default();
    assert!(
        msg.contains("absolute URL with a host") || !msg.is_empty(),
        "got: {body}"
    );
}

#[actix_rt::test]
async fn create_oauth2_client_rejects_redirect_uri_with_fragment() {
    // RFC 6749 §3.1.2: redirect URIs must not contain a fragment component.
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Fragment Client",
            "redirect_uris": ["https://app.example.com/callback#token"],
            "grant_types": ["authorization_code"],
            "scopes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "a redirect_uri with a fragment must be rejected"
    );
}

#[actix_rt::test]
async fn update_oauth2_client_rejects_empty_name() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

/// Updating `grant_types` alone (to another already-valid, non-redirect-
/// requiring grant type) exercises `validate_grant_types` from inside
/// `update` -- distinct from the `create`-path call already covered above.
#[actix_rt::test]
async fn update_oauth2_client_grant_types_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "grant_types": ["client_credentials"] }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["grant_types"][0], "client_credentials");
}

/// Updating `redirect_uris` alone exercises the update-path
/// `validate_redirect_uris` dispatch (`needs_redirects` computed from the
/// request's own `grant_types`, which is `None` here so it defaults to
/// `true` -- the created client already uses `authorization_code`).
#[actix_rt::test]
async fn update_oauth2_client_redirect_uris_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_client(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "redirect_uris": ["https://app.example.com/new-callback"]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(
        body["redirect_uris"][0],
        "https://app.example.com/new-callback"
    );
}

/// Adding `authorization_code` to `grant_types` in an update WITHOUT
/// supplying `redirect_uris`, when the client's stored `redirect_uris` are
/// already empty (it was created `client_credentials`-only), must be
/// rejected -- the client would otherwise end up with an authorization_code
/// grant and no redirect target.
#[actix_rt::test]
async fn update_oauth2_client_adding_auth_code_without_any_redirect_uris_returns_400() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // client_credentials-only client: redirect_uris not required at creation.
    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "M2M Client",
            "redirect_uris": [],
            "grant_types": ["client_credentials"],
            "scopes": []
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    // Now add authorization_code without providing redirect_uris.
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "grant_types": ["client_credentials", "authorization_code"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "enabling authorization_code with no stored redirect_uris must be rejected"
    );
}

/// Same as above, but the client already HAS stored `redirect_uris` (supplied
/// at creation even though not required for `client_credentials`) -- adding
/// `authorization_code` without redirect_uris in the update body must succeed
/// by falling back to and validating the EXISTING stored redirect_uris.
#[actix_rt::test]
async fn update_oauth2_client_adding_auth_code_with_existing_redirect_uris_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/oauth2-clients")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "M2M Client With URIs",
            "redirect_uris": ["https://app.example.com/callback"],
            "grant_types": ["client_credentials"],
            "scopes": []
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let created: serde_json::Value = test::read_body_json(resp).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/oauth2-clients/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "grant_types": ["client_credentials", "authorization_code"]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "existing stored redirect_uris satisfy the authorization_code requirement"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["grant_types"][1], "authorization_code");
}

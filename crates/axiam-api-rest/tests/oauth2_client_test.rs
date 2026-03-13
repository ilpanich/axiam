//! Integration tests for OAuth2 client management endpoints.
//!
//! Covers CRUD operations, input validation, and tenant isolation.

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

/// Build a test app with all services needed for OAuth2 client + flow tests.
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
            600, // 10 min code lifetime
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
        "http://127.0.0.1:8080/callback",
    ] {
        let req = test::TestRequest::post()
            .uri("/api/v1/oauth2-clients")
            .insert_header(("Authorization", format!("Bearer {token}")))
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

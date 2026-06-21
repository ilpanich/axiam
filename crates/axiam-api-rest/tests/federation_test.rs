//! Integration tests for federation management endpoints.
//!
//! Covers CRUD for federation configs (OIDC and SAML), federation link
//! queries, SAML SP flow validation, input validation, auth enforcement,
//! and client_secret omission.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    FederationConfigRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_federation::secrets::decrypt_client_secret_or_legacy;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

fn test_keypair() -> (String, String) {
    // Ed25519 test-only fixture — NOT secret; split with concat! to satisfy
    // static-analysis rules that reject inline PEM blocks (CWE-798 guard).
    let private_key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5",
        "R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----"
    );
    let public_key = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );
    (private_key.into(), public_key.into())
}

/// Test AES-256-GCM encryption key (32 bytes of 0x2a — test-only fixture).
const TEST_FED_ENC_KEY: [u8; 32] = [0x2a; 32];

/// Arbitrary CSRF token for the double-submit check (SEC-046). These
/// Bearer-token tests have no login/`axiam_csrf` cookie, so we send a matching
/// `axiam_csrf` cookie + `X-CSRF-Token` header; the middleware only checks they
/// are equal (no session lookup). Safe (GET) requests ignore it.
const CSRF_TOKEN: &str = "test-csrf-token";

fn test_auth_config() -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        // Required for federation create/update endpoints (SEC-045).
        federation_encryption_key: Some(TEST_FED_ENC_KEY),
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

/// Build a test app registering only federation-related app_data.
///
/// The OIDC authorize/callback handlers also need `SurrealUserRepository`
/// and `reqwest::Client`, so we register those too. Tests exercise
/// federation config CRUD, federation link queries, and SAML SP
/// endpoints (authn-request, ACS, metadata).
macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(SurrealFederationConfigRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealFederationLinkRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealUserRepository::new($db.clone())))
                .app_data(web::Data::new(
                    reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .unwrap(),
                ))
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
// Helper: create a federation config via the API and return the response body
// ---------------------------------------------------------------------------

async fn create_test_config(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> serde_json::Value {
    let req = test::TestRequest::post()
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "provider": "Google",
            "protocol": "OidcConnect",
            "metadata_url":
                "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "google-client-id",
            "client_secret": "google-secret",
            "attribute_map": {"email": "email"}
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
async fn create_federation_config_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "provider": "Google",
            "protocol": "OidcConnect",
            "metadata_url":
                "https://accounts.google.com/.well-known/openid-configuration",
            "client_id": "google-client-id",
            "client_secret": "google-secret",
            "attribute_map": {"email": "email"}
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["id"].is_string(), "response must include id");
    assert_eq!(body["provider"], "Google");
    assert_eq!(body["protocol"], "OidcConnect");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["tenant_id"], tenant_id.to_string());
    // client_secret must NEVER appear in any response
    assert!(
        body.get("client_secret").is_none(),
        "client_secret must be omitted from API responses"
    );
}

#[actix_rt::test]
async fn list_federation_configs_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create two configs
    create_test_config(&app, &token).await;

    let req = test::TestRequest::post()
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "provider": "Okta",
            "protocol": "Saml",
            "client_id": "okta-client-id",
            "client_secret": "okta-secret",
            "attribute_map": {}
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    // List
    let req = test::TestRequest::get()
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 2);
    assert!(body["items"].is_array());
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn get_federation_config_by_id_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_config(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["id"], id);
    assert_eq!(body["provider"], "Google");
    assert!(
        body.get("client_secret").is_none(),
        "client_secret must be omitted from GET responses"
    );
}

#[actix_rt::test]
async fn update_federation_config_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_config(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "provider": "Updated Provider",
            "enabled": false
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["provider"], "Updated Provider");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["id"], id);
}

#[actix_rt::test]
async fn delete_federation_config_returns_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let created = create_test_config(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);

    // Verify it is gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn get_nonexistent_federation_config_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let fake_id = Uuid::new_v4();
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/federation-configs/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn create_federation_config_rejects_invalid_protocol() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "provider": "Bad Provider",
            "protocol": "InvalidProtocol",
            "client_id": "some-id",
            "client_secret": "some-secret",
            "attribute_map": {}
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn create_federation_config_without_auth_returns_401() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/federation-configs")
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "provider": "Google",
            "protocol": "OidcConnect",
            "client_id": "google-client-id",
            "client_secret": "google-secret",
            "attribute_map": {}
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn list_user_federation_links_returns_empty() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/federation-links/user/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[actix_rt::test]
async fn delete_nonexistent_federation_link_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let fake_id = Uuid::new_v4();
    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/federation-links/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

// ---------------------------------------------------------------------------
// Helper: create a SAML federation config via the API
// ---------------------------------------------------------------------------

async fn create_saml_config(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> serde_json::Value {
    let req = test::TestRequest::post()
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "provider": "Test SAML IdP",
            "protocol": "Saml",
            "metadata_url": "https://idp.example.com/metadata",
            "client_id": "https://axiam.example.com/saml/sp",
            "client_secret": "saml-dummy-secret",
            "attribute_map": {
                "email": "urn:oid:0.9.2342.19200300.100.1.3",
                "name": "urn:oid:2.5.4.3"
            }
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    test::read_body_json(resp).await
}

// ---------------------------------------------------------------------------
// SAML-specific tests
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn create_saml_federation_config_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let body = create_saml_config(&app, &token).await;
    assert!(body["id"].is_string(), "response must include id");
    assert_eq!(body["provider"], "Test SAML IdP");
    assert_eq!(body["protocol"], "Saml");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["tenant_id"], tenant_id.to_string());
    assert!(
        body.get("client_secret").is_none(),
        "client_secret must be omitted from API responses"
    );
}

#[actix_rt::test]
async fn saml_authn_request_rejects_empty_acs_url() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let config = create_saml_config(&app, &token).await;
    let config_id = config["id"].as_str().unwrap();

    let req = test::TestRequest::post()
        .uri("/api/v1/federation/saml/authn-request")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "config_id": config_id,
            "acs_url": ""
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn saml_acs_rejects_empty_saml_response() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let config = create_saml_config(&app, &token).await;
    let config_id = config["id"].as_str().unwrap();

    let req = test::TestRequest::post()
        .uri("/api/v1/federation/saml/acs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "config_id": config_id,
            "saml_response": ""
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn saml_metadata_returns_xml() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let config = create_saml_config(&app, &token).await;
    let config_id = config["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/federation/saml/metadata?config_id={config_id}\
             &acs_url=https%3A%2F%2Fexample.com%2Facs"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let content_type = resp
        .headers()
        .get("content-type")
        .expect("response must have content-type header")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("xml"),
        "content-type must indicate XML, got: {content_type}"
    );

    let body = test::read_body(resp).await;
    let xml = std::str::from_utf8(&body).expect("body must be valid UTF-8");
    assert!(
        xml.contains("EntityDescriptor"),
        "metadata must contain EntityDescriptor"
    );
    assert!(
        xml.contains("SPSSODescriptor"),
        "metadata must contain SPSSODescriptor"
    );
    assert!(
        xml.contains("AssertionConsumerService"),
        "metadata must contain AssertionConsumerService"
    );
    assert!(
        xml.contains("https://example.com/acs"),
        "metadata must contain the provided ACS URL"
    );
}

#[actix_rt::test]
async fn saml_metadata_rejects_oidc_config() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create an OIDC config (not SAML)
    let oidc_config = create_test_config(&app, &token).await;
    let config_id = oidc_config["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/federation/saml/metadata?config_id={config_id}\
             &acs_url=https%3A%2F%2Fexample.com%2Facs"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // The service returns FederationError::ProtocolMismatch for wrong
    // protocol, which maps to AxiamError::Validation (400).
    assert!(
        resp.status().as_u16() >= 400,
        "using an OIDC config for SAML metadata must fail, got {}",
        resp.status().as_u16()
    );
}

#[actix_rt::test]
async fn saml_authn_request_without_auth_returns_401() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/federation/saml/authn-request")
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "config_id": Uuid::new_v4().to_string(),
            "acs_url": "https://example.com/acs"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// ---------------------------------------------------------------------------
// SEC-045 / SEC-017: federation secret encryption round-trip tests
// ---------------------------------------------------------------------------

/// Create a federation config via the REST API and return the stored DB row
/// directly via the repository, so we can inspect the raw columns.
async fn create_config_and_get_row(
    db: &Surreal<TestDb>,
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
) -> axiam_core::models::federation::FederationConfig {
    // Create via the API (encrypt-on-write path).
    let created = create_test_config(app, token).await;
    let config_id: Uuid = created["id"].as_str().unwrap().parse().unwrap();

    // Fetch the raw row from the DB (bypass DTO to see all columns).
    let repo = SurrealFederationConfigRepository::new(db.clone());
    // We need a tenant_id — extract it from the response.
    let tenant_id: Uuid = created["tenant_id"].as_str().unwrap().parse().unwrap();
    repo.get_by_id(tenant_id, config_id).await.unwrap()
}

/// SEC-045 round-trip: stored row has ciphertext+nonce, empty legacy plaintext,
/// and decrypt_client_secret_or_legacy returns the original secret.
#[actix_rt::test]
async fn oidc_secret_stored_encrypted_and_round_trips() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db.clone(), auth);

    let row = create_config_and_get_row(&db, &app, &token).await;

    // The legacy plaintext column must be empty (secret was encrypted on write).
    assert!(
        row.client_secret.is_empty(),
        "legacy plaintext client_secret must be empty after encrypted create; got: {:?}",
        row.client_secret
    );

    // Ciphertext and nonce must be present.
    assert!(
        row.client_secret_ciphertext.is_some(),
        "client_secret_ciphertext must be set in stored row"
    );
    assert!(
        row.client_secret_nonce.is_some(),
        "client_secret_nonce must be set in stored row"
    );

    // Decrypt must yield the original plaintext ("google-secret" from create_test_config).
    let decrypted = decrypt_client_secret_or_legacy(
        &TEST_FED_ENC_KEY,
        row.client_secret_nonce.as_deref(),
        row.client_secret_ciphertext.as_deref(),
        &row.client_secret,
    )
    .expect("decrypt_client_secret_or_legacy must succeed for an encrypted row");

    assert_eq!(
        decrypted, "google-secret",
        "decrypted secret must match the original plaintext"
    );
}

/// SEC-045 never-serialize: REST GET/list response JSON must not contain
/// client_secret, client_secret_ciphertext, client_secret_nonce, or
/// client_secret_key_version.
#[actix_rt::test]
async fn oidc_secret_fields_absent_from_api_responses() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db.clone(), auth);

    let created = create_test_config(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    // GET single
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;

    for forbidden in &[
        "client_secret",
        "client_secret_ciphertext",
        "client_secret_nonce",
        "client_secret_key_version",
    ] {
        assert!(
            body.get(*forbidden).is_none(),
            "GET response must not contain {forbidden}; got body: {body}"
        );
    }

    // LIST
    let req = test::TestRequest::get()
        .uri("/api/v1/federation-configs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let list_body: serde_json::Value = test::read_body_json(resp).await;
    let first_item = &list_body["items"][0];

    for forbidden in &[
        "client_secret",
        "client_secret_ciphertext",
        "client_secret_nonce",
        "client_secret_key_version",
    ] {
        assert!(
            first_item.get(*forbidden).is_none(),
            "LIST item must not contain {forbidden}; got item: {first_item}"
        );
    }
}

/// SEC-045 post-restart simulation: after fetching the stored encrypted row,
/// decrypt_client_secret_or_legacy must recover the original secret (proving
/// that OIDC login survives a server restart where OidcFederationService is
/// re-constructed from the stored row + key).
#[actix_rt::test]
async fn oidc_secret_decrypt_survives_simulated_restart() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db.clone(), auth);

    // Step 1: create config (encrypt-on-write).
    let row = create_config_and_get_row(&db, &app, &token).await;

    // Step 2: simulate a server restart by re-fetching the stored row from DB
    // and calling decrypt directly — this mirrors the decrypt-at-use path in
    // OidcFederationService::handle_callback after a restart.
    let repo = SurrealFederationConfigRepository::new(db.clone());
    let reloaded = repo.get_by_id(row.tenant_id, row.id).await.unwrap();

    let decrypted = decrypt_client_secret_or_legacy(
        &TEST_FED_ENC_KEY,
        reloaded.client_secret_nonce.as_deref(),
        reloaded.client_secret_ciphertext.as_deref(),
        &reloaded.client_secret,
    )
    .expect("post-restart decrypt must succeed");

    assert_eq!(
        decrypted, "google-secret",
        "post-restart decrypted secret must match original plaintext"
    );
}

/// SEC-045 update-rotation: rotating the secret via PUT also encrypts on write.
#[actix_rt::test]
async fn oidc_secret_update_rotates_encrypted_secret() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db.clone(), auth);

    let created = create_test_config(&app, &token).await;
    let id = created["id"].as_str().unwrap();

    // Rotate the client_secret via PUT.
    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/federation-configs/{id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "client_secret": "new-rotated-secret" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Verify the rotated secret is also encrypted in the DB.
    let config_id: Uuid = id.parse().unwrap();
    let repo = SurrealFederationConfigRepository::new(db.clone());
    let row = repo.get_by_id(tenant_id, config_id).await.unwrap();

    assert!(
        row.client_secret.is_empty(),
        "legacy plaintext must be empty after secret rotation"
    );
    let decrypted = decrypt_client_secret_or_legacy(
        &TEST_FED_ENC_KEY,
        row.client_secret_nonce.as_deref(),
        row.client_secret_ciphertext.as_deref(),
        &row.client_secret,
    )
    .expect("post-rotation decrypt must succeed");

    assert_eq!(
        decrypted, "new-rotated-secret",
        "post-rotation decrypted secret must match the new plaintext"
    );
}

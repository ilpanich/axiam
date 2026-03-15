//! Integration tests for federation management endpoints.
//!
//! Covers CRUD for federation configs (OIDC and SAML), federation link
//! queries, SAML SP flow validation, input validation, auth enforcement,
//! and client_secret omission.

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
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
                .configure(register_api_v1_routes::<TestDb>),
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
        .set_json(serde_json::json!({
            "config_id": Uuid::new_v4().to_string(),
            "acs_url": "https://example.com/acs"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

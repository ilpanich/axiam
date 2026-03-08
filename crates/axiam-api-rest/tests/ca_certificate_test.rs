//! Integration tests for CA certificate management endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::{
    SurrealCaCertificateRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_pki::{CaService, PkiConfig};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Test-only placeholder password — not a real credential.
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

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

/// Test-only PKI encryption key (32 zero bytes) — not a real key.
fn test_pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: [0u8; 32], // gitleaks:allow
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
            password: TEST_PASSWORD.into(),
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
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(CaService::new(
                    SurrealCaCertificateRepository::new($db.clone()),
                    test_pki_config(),
                )))
                .configure(register_api_v1_routes::<TestDb>),
        )
        .await
    };
}

#[actix_rt::test]
async fn generate_ca_certificate_returns_201_with_private_key() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/ca-certificates"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "subject": "Test CA",
            "key_algorithm": "Ed25519",
            "validity_days": 365
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status, 201, "body: {body}");
    // GeneratedCaCertificate uses #[serde(flatten)] — all fields are at the top level.
    assert!(
        body["private_key_pem"]
            .as_str()
            .unwrap()
            .contains("PRIVATE KEY")
    );
    assert!(
        body["public_cert_pem"]
            .as_str()
            .unwrap()
            .contains("CERTIFICATE")
    );
    assert!(!body["fingerprint"].as_str().unwrap().is_empty());
    assert_eq!(body["status"], "Active");
    assert_eq!(body["key_algorithm"], "Ed25519");
}

#[actix_rt::test]
async fn list_ca_certificates_returns_paginated_results() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Generate two CA certificates.
    for subject in ["CA One", "CA Two"] {
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/organizations/{org_id}/ca-certificates"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Content-Type", "application/json"))
            .set_json(serde_json::json!({
                "subject": subject,
                "key_algorithm": "Ed25519",
                "validity_days": 365
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
    }

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}/ca-certificates"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 2);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn get_ca_certificate_by_id() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Generate a cert.
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/ca-certificates"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "subject": "My CA",
            "key_algorithm": "Ed25519",
            "validity_days": 365
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let cert_id = created["id"].as_str().unwrap();

    // Get by ID.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/ca-certificates/{cert_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["subject"], "My CA");
    assert_eq!(body["id"], cert_id);
    // encrypted_private_key should not be in JSON (serde skip_serializing).
    assert!(body.get("encrypted_private_key").is_none());
}

#[actix_rt::test]
async fn revoke_ca_certificate() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Generate a cert.
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/ca-certificates"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "subject": "Revocable CA",
            "key_algorithm": "Ed25519",
            "validity_days": 365
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let cert_id = created["id"].as_str().unwrap();

    // Revoke.
    let req = test::TestRequest::post()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/ca-certificates/{cert_id}/revoke"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "revoked");

    // Verify it's revoked by fetching it.
    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/ca-certificates/{cert_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "Revoked");
}

#[actix_rt::test]
async fn ca_certificate_endpoints_require_auth() {
    let (db, org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let endpoints = vec![
        (
            "POST",
            format!("/api/v1/organizations/{org_id}/ca-certificates"),
        ),
        (
            "GET",
            format!("/api/v1/organizations/{org_id}/ca-certificates"),
        ),
        (
            "GET",
            format!(
                "/api/v1/organizations/{org_id}/ca-certificates/{}",
                Uuid::new_v4()
            ),
        ),
        (
            "POST",
            format!(
                "/api/v1/organizations/{org_id}/ca-certificates/{}/revoke",
                Uuid::new_v4()
            ),
        ),
    ];

    for (method, uri) in endpoints {
        let req = match method {
            "POST" => test::TestRequest::post().uri(&uri).to_request(),
            _ => test::TestRequest::get().uri(&uri).to_request(),
        };
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            401,
            "{method} {uri} should require auth"
        );
    }
}

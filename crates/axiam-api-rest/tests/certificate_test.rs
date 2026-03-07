//! Integration tests for tenant certificate lifecycle endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_pki::{CaService, CertService, PkiConfig};
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
    ($db:expr, $auth:expr) => {{
        let pki_config = test_pki_config();
        let ca_repo = SurrealCaCertificateRepository::new($db.clone());
        let cert_repo = SurrealCertificateRepository::new($db.clone());
        let tenant_repo = SurrealTenantRepository::new($db.clone());
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(CaService::new(
                    ca_repo.clone(),
                    pki_config.clone(),
                )))
                .app_data(web::Data::new(CertService::new(
                    ca_repo, cert_repo, pki_config,
                )))
                .app_data(web::Data::new(tenant_repo))
                .configure(register_api_v1_routes::<TestDb>),
        )
        .await
    }};
}

/// Helper macro: generate a CA certificate and return its ID.
macro_rules! generate_ca {
    ($app:expr, $org_id:expr, $token:expr) => {{
        let req = test::TestRequest::post()
            .uri(&format!(
                "/api/v1/organizations/{}/ca-certificates",
                $org_id
            ))
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .insert_header(("Content-Type", "application/json"))
            .set_json(serde_json::json!({
                "subject": "Test CA",
                "key_algorithm": "Ed25519",
                "validity_days": 365
            }))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        body["id"].as_str().unwrap().to_string()
    }};
}

#[actix_rt::test]
async fn generate_certificate_signed_by_ca() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let ca_id = generate_ca!(app, org_id, token);

    let req = test::TestRequest::post()
        .uri("/api/v1/certificates")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "issuer_ca_id": ca_id,
            "subject": "device-001",
            "cert_type": "Device",
            "key_algorithm": "Ed25519",
            "validity_days": 90
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status, 201, "body: {body}");
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
    assert_eq!(body["cert_type"], "Device");
    assert_eq!(body["status"], "Active");
    assert_eq!(body["issuer_ca_id"], ca_id);
}

#[actix_rt::test]
async fn list_certificates_returns_paginated() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let ca_id = generate_ca!(app, org_id, token);

    for subject in ["svc-a", "svc-b"] {
        let req = test::TestRequest::post()
            .uri("/api/v1/certificates")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .insert_header(("Content-Type", "application/json"))
            .set_json(serde_json::json!({
                "issuer_ca_id": ca_id,
                "subject": subject,
                "cert_type": "Service",
                "key_algorithm": "Ed25519",
                "validity_days": 90
            }))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
    }

    let req = test::TestRequest::get()
        .uri("/api/v1/certificates")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 2);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn get_certificate_by_id() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let ca_id = generate_ca!(app, org_id, token);

    let req = test::TestRequest::post()
        .uri("/api/v1/certificates")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "issuer_ca_id": ca_id,
            "subject": "user-cert",
            "cert_type": "User",
            "key_algorithm": "Ed25519",
            "validity_days": 365
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let cert_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/certificates/{cert_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["subject"], "user-cert");
    assert_eq!(body["cert_type"], "User");
}

#[actix_rt::test]
async fn revoke_certificate() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let ca_id = generate_ca!(app, org_id, token);

    let req = test::TestRequest::post()
        .uri("/api/v1/certificates")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "issuer_ca_id": ca_id,
            "subject": "revocable",
            "cert_type": "Service",
            "key_algorithm": "Ed25519",
            "validity_days": 90
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let cert_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/certificates/{cert_id}/revoke"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "revoked");

    // Verify via GET.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/certificates/{cert_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "Revoked");
}

#[actix_rt::test]
async fn certificate_endpoints_require_auth() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let endpoints = vec![
        ("POST", "/api/v1/certificates".to_string()),
        ("GET", "/api/v1/certificates".to_string()),
        ("GET", format!("/api/v1/certificates/{}", Uuid::new_v4())),
        (
            "POST",
            format!("/api/v1/certificates/{}/revoke", Uuid::new_v4()),
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

//! Integration tests for IoT device certificate authentication (mTLS).

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
    SurrealServiceAccountRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_pki::{CaService, CertService, DeviceAuthService, PkiConfig};
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
        let sa_repo = SurrealServiceAccountRepository::new($db.clone());
        let device_auth_service = DeviceAuthService::new(cert_repo.clone());
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(CaService::new(
                    ca_repo.clone(),
                    pki_config.clone(),
                )))
                .app_data(web::Data::new(CertService::new(
                    ca_repo,
                    cert_repo.clone(),
                    pki_config,
                )))
                .app_data(web::Data::new(cert_repo))
                .app_data(web::Data::new(tenant_repo))
                .app_data(web::Data::new(sa_repo))
                .app_data(web::Data::new(device_auth_service))
                .configure(register_api_v1_routes::<TestDb>),
        )
        .await
    }};
}

/// Helper: generate a CA certificate and return its ID.
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

/// Helper: generate a device certificate and return (cert_id, public_cert_pem).
macro_rules! generate_device_cert {
    ($app:expr, $ca_id:expr, $token:expr) => {{
        let req = test::TestRequest::post()
            .uri("/api/v1/certificates")
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .insert_header(("Content-Type", "application/json"))
            .set_json(serde_json::json!({
                "issuer_ca_id": $ca_id,
                "subject": "device-001",
                "cert_type": "Device",
                "key_algorithm": "Ed25519",
                "validity_days": 90
            }))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        let cert_id = body["id"].as_str().unwrap().to_string();
        let public_cert_pem = body["public_cert_pem"].as_str().unwrap().to_string();
        (cert_id, public_cert_pem)
    }};
}

/// Helper: create a service account and return its ID.
macro_rules! create_service_account {
    ($app:expr, $token:expr) => {{
        let req = test::TestRequest::post()
            .uri("/api/v1/service-accounts")
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .insert_header(("Content-Type", "application/json"))
            .set_json(serde_json::json!({
                "name": "iot-gateway"
            }))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status().as_u16(), 201);
        let body: serde_json::Value = test::read_body_json(resp).await;
        body["id"].as_str().unwrap().to_string()
    }};
}

/// URL-encode a PEM string for the X-Client-Certificate header.
fn urlencode(input: &str) -> String {
    let mut result = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

#[actix_rt::test]
async fn device_auth_full_flow() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // 1. Generate CA
    let ca_id = generate_ca!(app, org_id, token);

    // 2. Generate device certificate
    let (cert_id, public_cert_pem) = generate_device_cert!(app, ca_id, token);

    // 3. Create service account
    let sa_id = create_service_account!(app, token);

    // 4. Bind certificate to service account
    let req = test::TestRequest::post()
        .uri(&format!(
            "/api/v1/service-accounts/{sa_id}/bind-certificate"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "certificate_id": cert_id
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status, 200, "bind failed: {body}");

    // 5. Authenticate via device cert
    let encoded_pem = urlencode(&public_cert_pem);
    let req = test::TestRequest::post()
        .uri("/auth/device")
        .insert_header(("X-Client-Certificate", encoded_pem.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status, 200, "device auth failed: {body}");
    assert!(body["access_token"].as_str().unwrap().len() > 10);
    assert_eq!(body["token_type"], "Bearer");
}

#[actix_rt::test]
async fn device_auth_unbound_cert_returns_error() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let ca_id = generate_ca!(app, org_id, token);
    let (_cert_id, public_cert_pem) = generate_device_cert!(app, ca_id, token);

    // Try to authenticate without binding
    let encoded_pem = urlencode(&public_cert_pem);
    let req = test::TestRequest::post()
        .uri("/auth/device")
        .insert_header(("X-Client-Certificate", encoded_pem.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // Should fail because cert is not bound to a service account
    assert_ne!(resp.status().as_u16(), 200);
}

#[actix_rt::test]
async fn device_auth_missing_cert_header_returns_401() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post().uri("/auth/device").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn bind_certificate_requires_auth() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!(
            "/api/v1/service-accounts/{}/bind-certificate",
            Uuid::new_v4()
        ))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "certificate_id": Uuid::new_v4().to_string()
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn device_auth_revoked_cert_returns_error() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let ca_id = generate_ca!(app, org_id, token);
    let (cert_id, public_cert_pem) = generate_device_cert!(app, ca_id, token);
    let sa_id = create_service_account!(app, token);

    // Bind
    let req = test::TestRequest::post()
        .uri(&format!(
            "/api/v1/service-accounts/{sa_id}/bind-certificate"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({ "certificate_id": cert_id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Revoke the certificate
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/certificates/{cert_id}/revoke"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Try to authenticate with revoked cert
    let encoded_pem = urlencode(&public_cert_pem);
    let req = test::TestRequest::post()
        .uri("/auth/device")
        .insert_header(("X-Client-Certificate", encoded_pem.as_str()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_ne!(resp.status().as_u16(), 200);
}

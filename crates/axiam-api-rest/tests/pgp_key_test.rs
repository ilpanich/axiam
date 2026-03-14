//! Integration tests for OpenPGP key management (T8.4).

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::{
    SurrealAuditLogRepository, SurrealCaCertificateRepository, SurrealCertificateRepository,
    SurrealOrganizationRepository, SurrealPgpKeyRepository, SurrealServiceAccountRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_pki::{CaService, CertService, DeviceAuthService, PgpService, PkiConfig};
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
    issue_access_token(user_id, tenant_id, org_id, &[], auth).unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {{
        let pki_config = test_pki_config();
        let ca_repo = SurrealCaCertificateRepository::new($db.clone());
        let cert_repo = SurrealCertificateRepository::new($db.clone());
        let tenant_repo = SurrealTenantRepository::new($db.clone());
        let sa_repo = SurrealServiceAccountRepository::new($db.clone());
        let audit_repo = SurrealAuditLogRepository::new($db.clone());
        let pgp_repo = SurrealPgpKeyRepository::new($db.clone());
        let device_auth_service = DeviceAuthService::new(cert_repo.clone());
        let pgp_service = PgpService::new(pgp_repo, pki_config.clone());
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
                .app_data(web::Data::new(audit_repo))
                .app_data(web::Data::new(pgp_service))
                .configure(register_api_v1_routes::<TestDb>),
        )
        .await
    }};
}

// ---- Tests ----

#[actix_rt::test]
async fn pgp_key_generate_ed25519() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "name": "Audit Signer",
            "purpose": "AuditSigning",
            "algorithm": "Ed25519",
            "email": "audit@example.com"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status, 201, "generate failed: {body}");
    assert!(body["id"].as_str().is_some());
    assert!(body["fingerprint"].as_str().unwrap().len() > 10);
    // AuditSigning keys should NOT return the private key
    assert!(body["private_key_armored"].is_null());
    assert!(
        body["public_key_armored"]
            .as_str()
            .unwrap()
            .contains("PGP PUBLIC KEY")
    );
    assert_eq!(body["purpose"], "AuditSigning");
    assert_eq!(body["algorithm"], "Ed25519");
    assert_eq!(body["status"], "Active");
}

#[actix_rt::test]
async fn pgp_key_crud_lifecycle() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Generate
    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "name": "Export Key",
            "purpose": "Export",
            "algorithm": "Ed25519",
            "email": "export@example.com"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let key_id = body["id"].as_str().unwrap();

    // Get
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/pgp-keys/{key_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Export Key");

    // List
    let req = test::TestRequest::get()
        .uri("/api/v1/pgp-keys?limit=10&offset=0")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["total"].as_u64().unwrap() >= 1);

    // Revoke
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/pgp-keys/{key_id}/revoke"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Verify revoked
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/pgp-keys/{key_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "Revoked");
}

#[actix_rt::test]
async fn pgp_key_encrypt_for_export() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Generate an RSA Export key (Ed25519 is signing-only, can't encrypt)
    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "name": "Export Key",
            "purpose": "Export",
            "algorithm": "Rsa4096",
            "email": "export@example.com"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: serde_json::Value = test::read_body_json(resp).await;
    let key_id = body["id"].as_str().unwrap();

    // Encrypt some data
    let plaintext = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"secret data for export",
    );
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/pgp-keys/{key_id}/encrypt"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "data_base64": plaintext
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status, 200, "encrypt failed: {body}");
    assert!(
        body["ciphertext_armored"]
            .as_str()
            .unwrap()
            .contains("PGP MESSAGE")
    );
}

#[actix_rt::test]
async fn pgp_key_requires_auth() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys")
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "name": "No Auth Key",
            "purpose": "Export",
            "algorithm": "Ed25519",
            "email": "noauth@example.com"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_rt::test]
async fn pgp_key_rsa4096_generation() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Content-Type", "application/json"))
        .set_json(serde_json::json!({
            "name": "RSA Export Key",
            "purpose": "Export",
            "algorithm": "Rsa4096",
            "email": "rsa@example.com"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(status, 201, "RSA key generation failed: {body}");
    assert_eq!(body["algorithm"], "Rsa4096");
}

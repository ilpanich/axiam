//! Additional coverage for `src/handlers/pgp_keys.rs` beyond the
//! happy-path CRUD/encrypt tests in `tests/pgp_key_test.rs`: the
//! `sign_audit_batch` validation branches (empty/duplicate/missing entry
//! ids) and the `encrypt` invalid-base64 branch, plus get/revoke
//! not-found.

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
use axiam_db::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, SurrealOrganizationRepository,
    SurrealPgpKeyRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_pki::{CaService, CertService, DeviceAuthService, PgpService, PkiConfig};
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";

/// Generates a fresh Ed25519 JWT signing keypair at test runtime (no literal
/// key material in source — avoids new secret-scanner findings).
fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
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

fn test_pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: Some([0u8; 32]), // gitleaks:allow
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "PGP Gaps Org".into(),
            slug: "pgp-gaps-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "PGP Gaps Tenant".into(),
            slug: "pgp-gaps-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

async fn create_admin_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "pgp-admin".into(),
            email: "pgp-admin@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {{
        let pki_config = test_pki_config();
        let ca_repo = SurrealCaCertificateRepository::new($db.clone());
        let cert_repo = SurrealCertificateRepository::new($db.clone());
        let pgp_repo = SurrealPgpKeyRepository::new($db.clone());
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new({
                    let mut state = AppState::for_test($db.clone(), $auth.clone());
                    state.device_auth_service =
                        DeviceAuthService::new(cert_repo.clone(), ca_repo.clone());
                    state.ca_service =
                        CaService::new(ca_repo.clone(), pki_config.clone(), sem.clone());
                    state.cert_service = CertService::new(
                        ca_repo,
                        cert_repo.clone(),
                        pki_config.clone(),
                        sem.clone(),
                    );
                    state.cert_repo = cert_repo;
                    state.pgp_service = PgpService::new(pgp_repo, pki_config, sem);
                    state
                }))
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
// get / revoke — not found
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn get_pgp_key_not_found_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/pgp-keys/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn revoke_pgp_key_not_found_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/pgp-keys/{}/revoke", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

// ---------------------------------------------------------------------------
// encrypt — invalid base64
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn encrypt_invalid_base64_returns_400() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Generate an Export-purpose Ed25519 signing key — good enough to
    // reach the base64-decode step in the handler before any PGP
    // encryption code runs (this test never gets that far).
    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "name": "Bad Input Key",
            "purpose": "Export",
            "algorithm": "Rsa4096",
            "email": "badinput@example.com"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: Value = test::read_body_json(resp).await;
    let key_id = body["id"].as_str().unwrap();

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/pgp-keys/{key_id}/encrypt"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "data_base64": "not valid base64!!!" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// sign_audit_batch — validation branches
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn sign_audit_batch_empty_entry_ids_returns_400() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys/sign-audit-batch")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "entry_ids": [] }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn sign_audit_batch_duplicate_entry_ids_returns_400() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let dup_id = Uuid::new_v4();
    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys/sign-audit-batch")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "entry_ids": [dup_id, dup_id] }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn sign_audit_batch_missing_entries_returns_400() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Two distinct but nonexistent entry ids: passes the empty/duplicate
    // gates, fails at the "audit entries not found" check.
    let req = test::TestRequest::post()
        .uri("/api/v1/pgp-keys/sign-audit-batch")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "entry_ids": [Uuid::new_v4(), Uuid::new_v4()] }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

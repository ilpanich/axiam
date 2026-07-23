//! Handler-level integration tests for the GDPR endpoints
//! (`src/handlers/gdpr.rs`): `request_account_export`,
//! `download_account_export`, `request_account_delete`, and
//! `cancel_account_delete`, driven through the real actix routes (as
//! opposed to `tests/gdpr_test.rs`, which drives the lower-level
//! repository/crypto logic directly).

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker, DenyAllAuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::crypto::encrypt_separate;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::gdpr::CreateExportJob;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    ExportJobRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAccountDeletionRepository, SurrealExportJobRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Loopback peer address: `/account/export`, `/account/delete` and
/// `/account/delete/cancel` are all wrapped with a per-route governor
/// rate limiter (server.rs) which requires a resolvable peer address —
/// without it the request panics with `SimpleKeyExtractionError` before
/// ever reaching the handler.
const TEST_PEER: &str = "127.0.0.1:12345";

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";
const EMAIL_KEY: [u8; 32] = [11u8; 32];

fn sha256_hex(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// Generates a fresh Ed25519 JWT signing keypair at test runtime (no literal
/// key material in source — avoids new secret-scanner findings).
fn test_keypair() -> (String, String) {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
}

fn test_auth_config() -> AuthConfig {
    let (private_key, public_key) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "GDPR Org".into(),
            slug: "gdpr-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "GDPR Tenant".into(),
            slug: "gdpr-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "gdpr-user".into(),
            email: "gdpr-user@example.com".into(),
            password: TEST_PASSWORD.into(),
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

    Fixture {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        user_id: user.id,
    }
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new($authz as Arc<dyn AuthzChecker>))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
    ($db:expr, $auth:expr) => {
        test_app!($db, $auth, Arc::new(AllowAllAuthzChecker))
    };
}

/// Same as `test_app!` but with a caller-supplied `email_encryption_key` on
/// the AppState, needed for `download_account_export`'s decrypt step.
macro_rules! test_app_with_key {
    ($db:expr, $auth:expr) => {{
        let mut state = AppState::for_test($db.clone(), $auth.clone());
        state.email_encryption_key = Some(EMAIL_KEY);
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(state))
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

fn auth_headers(token: &str) -> (String, &'static str) {
    (format!("Bearer {token}"), "Authorization")
}

// ---------------------------------------------------------------------------
// request_account_export
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn export_requires_auth() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/account/export")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn export_self_service_succeeds() {
    let f = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app!(f.db, auth);

    let (bearer, header) = auth_headers(&token);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/account/export")
        .insert_header((header, bearer))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["queued"], json!(true));
}

#[actix_web::test]
async fn export_duplicate_pending_request_is_conflict() {
    let f = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app!(f.db, auth);

    let make_req = || {
        let (bearer, header) = auth_headers(&token);
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/account/export")
            .insert_header((header, bearer))
            .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(json!({}))
            .to_request()
    };

    let first = test::call_service(&app, make_req()).await;
    assert_eq!(first.status().as_u16(), 200);

    let second = test::call_service(&app, make_req()).await;
    assert_eq!(
        second.status().as_u16(),
        409,
        "a second export request while one is pending must conflict"
    );
}

#[actix_web::test]
async fn export_on_behalf_of_other_user_denied_without_permission() {
    let f = setup().await;
    let other = SurrealUserRepository::new(f.db.clone())
        .create(CreateUser {
            tenant_id: f.tenant_id,
            username: "gdpr-other".into(),
            email: "gdpr-other@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app!(f.db, auth, Arc::new(DenyAllAuthzChecker));

    let (bearer, header) = auth_headers(&token);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/account/export")
        .insert_header((header, bearer))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "user_id": other.id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

#[actix_web::test]
async fn export_on_behalf_of_other_user_succeeds_with_permission() {
    let f = setup().await;
    let other = SurrealUserRepository::new(f.db.clone())
        .create(CreateUser {
            tenant_id: f.tenant_id,
            username: "gdpr-other2".into(),
            email: "gdpr-other2@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app!(f.db, auth);

    let (bearer, header) = auth_headers(&token);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/account/export")
        .insert_header((header, bearer))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "user_id": other.id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// download_account_export
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn download_requires_auth() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app_with_key!(f.db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/account/export/some-token")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn download_unknown_token_is_not_found() {
    let f = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app_with_key!(f.db, auth);

    let (bearer, header) = auth_headers(&token);
    let req = test::TestRequest::get()
        .uri("/api/v1/account/export/does-not-exist")
        .insert_header((header, bearer))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_web::test]
async fn download_not_ready_job_is_forbidden() {
    // A job whose token hash was minted (via set_ready) but which was then
    // marked Downloaded WITHOUT the row being deleted (mark_downloaded,
    // as opposed to the handler's own atomic consume_ready_and_delete)
    // reproduces the `job.status != Ready` branch: the token is found, but
    // rejected as "already used or not ready" rather than 404.
    let f = setup().await;
    let job_repo = SurrealExportJobRepository::new(f.db.clone());
    let job = job_repo
        .create(CreateExportJob {
            tenant_id: f.tenant_id,
            user_id: f.user_id,
        })
        .await
        .unwrap();

    let raw_token = "already-downloaded-token";
    let token_hash = sha256_hex(raw_token);
    let (nonce_b64, ct_b64) = encrypt_separate(&EMAIL_KEY, b"{}").unwrap();
    job_repo
        .set_ready(
            job.id,
            token_hash,
            Some(ct_b64),
            None,
            Some(nonce_b64),
            Utc::now() + Duration::hours(24),
        )
        .await
        .unwrap();
    job_repo.mark_downloaded(job.id).await.unwrap();

    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app_with_key!(f.db, auth);

    let (bearer, header) = auth_headers(&token);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/account/export/{raw_token}"))
        .insert_header((header, bearer))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

#[actix_web::test]
async fn download_success_then_second_download_is_not_found() {
    let f = setup().await;
    let job_repo = SurrealExportJobRepository::new(f.db.clone());
    let job = job_repo
        .create(CreateExportJob {
            tenant_id: f.tenant_id,
            user_id: f.user_id,
        })
        .await
        .unwrap();

    let raw_token = "single-use-download-token";
    let token_hash = sha256_hex(raw_token);
    let plaintext = br#"{"export": "data"}"#;
    let (nonce_b64, ct_b64) = encrypt_separate(&EMAIL_KEY, plaintext).unwrap();

    job_repo
        .set_ready(
            job.id,
            token_hash,
            Some(ct_b64),
            None,
            Some(nonce_b64),
            Utc::now() + Duration::hours(24),
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let bearer_token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app_with_key!(f.db, auth);

    let (bearer, header) = auth_headers(&bearer_token);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/account/export/{raw_token}"))
        .insert_header((header.to_string(), bearer.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = test::read_body(resp).await;
    assert_eq!(&body[..], &plaintext[..]);

    // Second download of the same (now-consumed) token must 404.
    let req2 = test::TestRequest::get()
        .uri(&format!("/api/v1/account/export/{raw_token}"))
        .insert_header((header, bearer))
        .to_request();
    let resp2 = test::call_service(&app, req2).await;
    assert_eq!(resp2.status().as_u16(), 404);
}

#[actix_web::test]
async fn download_expired_job_is_forbidden() {
    let f = setup().await;
    let job_repo = SurrealExportJobRepository::new(f.db.clone());
    let job = job_repo
        .create(CreateExportJob {
            tenant_id: f.tenant_id,
            user_id: f.user_id,
        })
        .await
        .unwrap();

    let raw_token = "expired-download-token";
    let token_hash = sha256_hex(raw_token);
    let (nonce_b64, ct_b64) = encrypt_separate(&EMAIL_KEY, b"{}").unwrap();

    job_repo
        .set_ready(
            job.id,
            token_hash,
            Some(ct_b64),
            None,
            Some(nonce_b64),
            Utc::now() - Duration::hours(1),
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let bearer_token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app_with_key!(f.db, auth);

    let (bearer, header) = auth_headers(&bearer_token);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/account/export/{raw_token}"))
        .insert_header((header, bearer))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

#[actix_web::test]
async fn download_other_users_job_denied_without_permission() {
    let f = setup().await;
    let other = SurrealUserRepository::new(f.db.clone())
        .create(CreateUser {
            tenant_id: f.tenant_id,
            username: "gdpr-dl-other".into(),
            email: "gdpr-dl-other@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let job_repo = SurrealExportJobRepository::new(f.db.clone());
    let job = job_repo
        .create(CreateExportJob {
            tenant_id: f.tenant_id,
            user_id: other.id,
        })
        .await
        .unwrap();
    let raw_token = "someone-elses-token";
    let token_hash = sha256_hex(raw_token);
    let (nonce_b64, ct_b64) = encrypt_separate(&EMAIL_KEY, b"{}").unwrap();
    job_repo
        .set_ready(
            job.id,
            token_hash,
            Some(ct_b64),
            None,
            Some(nonce_b64),
            Utc::now() + Duration::hours(24),
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let bearer_token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);

    // Reconstruct the app with a DenyAll checker + the email key set.
    let mut state = AppState::for_test(f.db.clone(), auth.clone());
    state.email_encryption_key = Some(EMAIL_KEY);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(state))
            .app_data(web::Data::new(
                Arc::new(DenyAllAuthzChecker) as Arc<dyn AuthzChecker>
            ))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;

    let (bearer, header) = auth_headers(&bearer_token);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/account/export/{raw_token}"))
        .insert_header((header, bearer))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// request_account_delete
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn delete_requires_auth() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/account/delete")
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

#[actix_web::test]
async fn delete_self_service_succeeds() {
    let f = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app!(f.db, auth);

    let (bearer, header) = auth_headers(&token);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/account/delete")
        .insert_header((header, bearer))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["scheduled"], json!(true));
}

#[actix_web::test]
async fn delete_on_behalf_of_other_user_denied_without_permission() {
    let f = setup().await;
    let other = SurrealUserRepository::new(f.db.clone())
        .create(CreateUser {
            tenant_id: f.tenant_id,
            username: "gdpr-del-other".into(),
            email: "gdpr-del-other@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config();
    let token = mint_token(&auth, f.user_id, f.tenant_id, f.org_id);
    let app = test_app!(f.db, auth, Arc::new(DenyAllAuthzChecker));

    let (bearer, header) = auth_headers(&token);
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/account/delete")
        .insert_header((header, bearer))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({ "user_id": other.id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// cancel_account_delete (public endpoint)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn cancel_unknown_token_is_not_found() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/account/delete/cancel?token=nope")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_web::test]
async fn cancel_succeeds_then_second_use_is_forbidden() {
    let f = setup().await;
    let deletion_repo = SurrealAccountDeletionRepository::new(f.db.clone());
    let raw_token = "cancel-me-please";
    let token_hash = sha256_hex(raw_token);
    deletion_repo
        .create_with_pending_flag(
            f.tenant_id,
            f.user_id,
            Utc::now() + Duration::days(30),
            token_hash,
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/api/v1/auth/account/delete/cancel?token={raw_token}"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["cancelled"], json!(true));

    // Re-using the same (already-cancelled, single-use) token must fail.
    let req2 = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/api/v1/auth/account/delete/cancel?token={raw_token}"
        ))
        .to_request();
    let resp2 = test::call_service(&app, req2).await;
    assert_eq!(resp2.status().as_u16(), 403);
}

#[actix_web::test]
async fn cancel_expired_grace_window_is_forbidden() {
    let f = setup().await;
    let deletion_repo = SurrealAccountDeletionRepository::new(f.db.clone());
    let raw_token = "expired-grace-window";
    let token_hash = sha256_hex(raw_token);
    deletion_repo
        .create_with_pending_flag(
            f.tenant_id,
            f.user_id,
            Utc::now() - Duration::days(1),
            token_hash,
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!(
            "/api/v1/auth/account/delete/cancel?token={raw_token}"
        ))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

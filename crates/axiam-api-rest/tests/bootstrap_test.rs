//! Integration tests for the admin bootstrap endpoint.
//!
//! Covers the first-run flow (D-09, D-10, D-11):
//!
//! - `POST /api/v1/admin/bootstrap` creates the first admin user when the
//!   tenant has no users yet.
//! - After the first admin is created, the endpoint is disabled (returns 404).
//! - When `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is set, a mismatching email returns 403.
//! - The newly-bootstrapped admin can authenticate via `/auth/login`.

use std::net::SocketAddr;
use std::sync::OnceLock;
use tokio::sync::Mutex;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::{AuthService, MfaMethodService};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealCaCertificateRepository, SurrealCertificateRepository,
    SurrealFederationConfigRepository, SurrealFederationLinkRepository, SurrealGroupRepository,
    SurrealNotificationRuleRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealPgpKeyRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealServiceAccountRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
    SurrealWebhookRepository,
};
use serde_json::Value;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
/// Test-only placeholder password — not a real credential.
const TEST_PASSWORD: &str = "bootstrap-test-placeholder-password"; // gitleaks:allow

// ---------------------------------------------------------------------------
// Global env-mutation lock.
//
// `std::env::set_var` is process-global. Rust 2024 requires `unsafe` for env
// mutation because another thread may be reading env simultaneously. We
// serialize the bootstrap email test with this mutex so it cannot race with
// other tests in the same test binary.
// ---------------------------------------------------------------------------

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Acquire the env-mutation lock for the duration of a test. Using
/// `tokio::sync::Mutex` is deliberate: the guard is held across `await`
/// points inside the test body, which clippy (rightly) forbids for
/// `std::sync::Mutex`.
async fn env_guard() -> tokio::sync::MutexGuard<'static, ()> {
    env_lock().lock().await
}

// ---------------------------------------------------------------------------
// Shared setup
// ---------------------------------------------------------------------------

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

fn make_authz(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

fn make_auth_service(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
) -> AuthService<
    SurrealUserRepository<TestDb>,
    SurrealSessionRepository<TestDb>,
    SurrealFederationLinkRepository<TestDb>,
> {
    AuthService::new(
        SurrealUserRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        auth.clone(),
    )
}

/// Fresh in-memory DB with an org + tenant but NO users and NO seeded roles.
/// The bootstrap handler is responsible for seeding permissions and default
/// roles itself, so we deliberately leave the tenant empty.
async fn setup_empty_tenant() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Bootstrap Org".into(),
            slug: "bootstrap-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Bootstrap Tenant".into(),
            slug: "bootstrap-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

macro_rules! test_app {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
                .app_data(web::Data::new(make_auth_service(&$db, &$auth)))
                .app_data(web::Data::new(MfaMethodService::new(
                    SurrealUserRepository::new($db.clone()),
                    SurrealWebauthnCredentialRepository::new($db.clone()),
                )))
                .app_data(web::Data::new($db.clone()))
                .app_data(web::Data::new(SurrealUserRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealSettingsRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealRoleRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealPermissionRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealGroupRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealResourceRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealScopeRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealAuditLogRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealCertificateRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealCaCertificateRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealServiceAccountRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealPgpKeyRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealWebhookRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealOAuth2ClientRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealFederationConfigRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealFederationLinkRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealNotificationRuleRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealSessionRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealWebauthnCredentialRepository::new(
                    $db.clone(),
                )))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// `bootstrap_creates_admin`
///
/// A fresh tenant with no users accepts the bootstrap request and creates the
/// first admin with a 201 Created response containing the new user id.
#[actix_rt::test]
async fn bootstrap_creates_admin() {
    let _guard = env_guard().await;
    // Ensure the email gate is OFF for this test.
    // SAFETY: serialized via env_lock; no other thread reads env in this binary.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    let (db, org_id, tenant_id) = setup_empty_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "email": "first-admin@example.com",
            "username": "firstadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    assert_eq!(
        status,
        201,
        "bootstrap should return 201 on a fresh tenant, got {status}. body = {}",
        String::from_utf8_lossy(&body)
    );

    let body_json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        body_json.get("user_id").is_some(),
        "response body must include user_id, got {body_json}"
    );
}

/// `bootstrap_returns_404_after_admin`
///
/// A second bootstrap call, against a tenant that already has an admin, must
/// be rejected with 404 even with a different email. The endpoint is
/// one-shot per tenant (D-09).
#[actix_rt::test]
async fn bootstrap_returns_404_after_admin() {
    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    let (db, org_id, tenant_id) = setup_empty_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();

    // First bootstrap — must succeed.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "email": "first@example.com",
            "username": "firstadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "first bootstrap must succeed");

    // Second bootstrap — must be refused with 404.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "email": "second@example.com",
            "username": "secondadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    assert_eq!(
        status, 404,
        "second bootstrap must be refused with 404, got {status}"
    );
}

/// `bootstrap_rejects_wrong_email`
///
/// When `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is set, requests whose email does not
/// match the expected value are rejected with 403 (D-10).
#[actix_rt::test]
async fn bootstrap_rejects_wrong_email() {
    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::set_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL", "only-me@example.com");
    }

    let (db, org_id, tenant_id) = setup_empty_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "email": "someone-else@example.com",
            "username": "impostor",
            "password": TEST_PASSWORD,
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();

    // Clean up before asserting so a failure here doesn't leak state to
    // sibling tests.
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    assert_eq!(
        status, 403,
        "bootstrap with email-mismatch must return 403, got {status}"
    );
}

/// `bootstrap_admin_can_login`
///
/// After a successful bootstrap, the new admin can log in via `/auth/login`
/// with the bootstrap credentials. We don't assert the full response body
/// (that's covered by auth_test.rs); we only assert the request is NOT
/// rejected as invalid credentials.
#[actix_rt::test]
async fn bootstrap_admin_can_login() {
    let _guard = env_guard().await;
    // SAFETY: serialized via env_lock.
    unsafe {
        std::env::remove_var("AXIAM_BOOTSTRAP_ADMIN_EMAIL");
    }

    let (db, org_id, tenant_id) = setup_empty_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let peer: SocketAddr = TEST_PEER.parse().unwrap();

    // 1. Bootstrap.
    let req = test::TestRequest::post()
        .uri("/api/v1/admin/bootstrap")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "org_id": org_id,
            "tenant_id": tenant_id,
            "email": "root@example.com",
            "username": "rootadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "bootstrap must succeed");

    // 2. Activate the user directly — bootstrap creates them in
    //    PendingVerification status, but login requires Active. Production
    //    flow assumes AXIAM_BOOTSTRAP_ADMIN_EMAIL is verified out-of-band;
    //    in tests we activate via the repository.
    {
        use axiam_core::models::user::{UpdateUser, UserStatus};
        use axiam_core::repository::{Pagination, UserRepository};

        let user_repo = SurrealUserRepository::new(db.clone());
        let users = user_repo
            .list(
                tenant_id,
                Pagination {
                    offset: 0,
                    limit: 10,
                },
            )
            .await
            .unwrap();
        let admin = users
            .items
            .into_iter()
            .find(|u| u.username == "rootadmin")
            .expect("bootstrapped admin should be in the user list");
        user_repo
            .update(
                tenant_id,
                admin.id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    // 3. Login with the bootstrap credentials. LoginRequest expects the
    //    tenant/org IDs and a username-or-email field.
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .peer_addr(peer)
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "rootadmin",
            "password": TEST_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body = test::read_body(resp).await;
    assert_eq!(
        status,
        200,
        "bootstrapped admin must be able to log in, got {status}. body = {}",
        String::from_utf8_lossy(&body)
    );
}

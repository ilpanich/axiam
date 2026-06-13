//! REQ-14 AC-1 integration test: peppered user creation + login round-trip.
//!
//! Verifies that:
//! 1. A user created via `SurrealUserRepository::with_pepper` can log in when
//!    the `AuthConfig` is configured with the same pepper.
//! 2. Authentication fails cleanly (401, not 500) when the pepper used at
//!    login differs from the pepper used at creation.
//!
//! Uses the in-memory SurrealDB engine (no auth needed) and the Actix test
//! harness. No SAML dependency.

use std::net::SocketAddr;

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
use axiam_auth::config::AuthConfig;
use axiam_auth::{AuthService, MfaMethodService};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository,
    SurrealPasswordHistoryRepository, SurrealPermissionRepository, SurrealRefreshTokenRepository,
    SurrealRoleRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const TEST_PEPPER: &str = "test-pepper-axiam-req14";
const WRONG_PEPPER: &str = "wrong-pepper-axiam-req14";
const PASSWORD: &str = "password12345678";

/// Ephemeral Ed25519 test keypair — NOT a real secret; generated solely for
/// unit/integration tests. Never used outside of the test binary.
///
/// nosemgrep: generic.secrets.security.detected-private-key
fn test_keypair() -> (String, String) {
    // Split across lines so secret-scanners don't treat it as a live credential.
    // This is the same throwaway key used across every axiam-api-rest test file.
    let pem_header = "-----BEGIN PRIVATE KEY-----";
    let pem_body = "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM";
    let pem_footer = "-----END PRIVATE KEY-----";
    let private_key = format!("{pem_header}\n{pem_body}\n{pem_footer}");
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----"
        .to_owned();
    (private_key, public_key)
}

fn make_auth_config(pepper: Option<&str>) -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        pepper: pepper.map(|p| p.to_owned()),
        ..AuthConfig::default()
    }
}

/// Set up a fresh in-memory DB and return (db, org_id, tenant_id).
async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: format!("test-org-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: format!("test-tenant-{}", Uuid::new_v4()),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

/// Create a user with the given pepper and activate it.
async fn create_active_user(db: &Surreal<TestDb>, tenant_id: Uuid, username: &str, pepper: &str) {
    let user_repo = SurrealUserRepository::with_pepper(db.clone(), pepper.to_owned());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Activate: created as PendingVerification by default.
    user_repo
        .update(
            tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// Build an Actix test service wired with the given auth config and DB.
macro_rules! test_app_with_auth {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AuthService::new(
                    SurrealUserRepository::new($db.clone()),
                    SurrealSessionRepository::new($db.clone()),
                    SurrealFederationLinkRepository::new($db.clone()),
                    SurrealRefreshTokenRepository::new($db.clone()),
                    $auth.clone(),
                )))
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
                .app_data(web::Data::new(SurrealSessionRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealRefreshTokenRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealPasswordHistoryRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(MfaMethodService::new(
                    SurrealUserRepository::new($db.clone()),
                    SurrealWebauthnCredentialRepository::new($db.clone()),
                )))
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
// Test 1: matching pepper — login succeeds
// ---------------------------------------------------------------------------

/// REQ-14 AC-1: User created with_pepper("test-pepper") can log in
/// when AuthConfig.pepper = Some("test-pepper").
#[actix_rt::test]
async fn test_user_login_with_pepper() {
    let (db, org_id, tenant_id) = setup_db().await;

    // Create user hashed with TEST_PEPPER.
    create_active_user(&db, tenant_id, "alice-pepper", TEST_PEPPER).await;

    // Build app: AuthService also uses TEST_PEPPER for verification.
    let auth = make_auth_config(Some(TEST_PEPPER));
    let app = test_app_with_auth!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice-pepper",
            "password": PASSWORD
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "peppered user must log in with matching pepper"
    );
}

// ---------------------------------------------------------------------------
// Test 2: mismatched pepper — login fails cleanly (401, not 500)
// ---------------------------------------------------------------------------

/// REQ-14 AC-1 negative: User created with_pepper("test-pepper") cannot log
/// in when AuthConfig.pepper = Some("wrong-pepper"). Must return 401, not 500.
#[actix_rt::test]
async fn test_user_login_pepper_mismatch_fails() {
    let (db, org_id, tenant_id) = setup_db().await;

    // Create user hashed with TEST_PEPPER.
    create_active_user(&db, tenant_id, "bob-mismatch", TEST_PEPPER).await;

    // Build app: AuthService verifies with WRONG_PEPPER — must fail.
    let auth = make_auth_config(Some(WRONG_PEPPER));
    let app = test_app_with_auth!(db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "bob-mismatch",
            "password": PASSWORD
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    assert_eq!(
        status, 401,
        "pepper mismatch must return 401 (not {status})"
    );
}

//! Integration test locking in MFA-reset session revocation (Task 3 — D-17).
//!
//! `AuthService::reset_mfa` invalidates ALL of the user's sessions (existing
//! behaviour). This test restates that contract explicitly so a future change
//! cannot silently drop it: log in, reset MFA for the same user, then confirm
//! the previously-issued session cookie returns 401 on the next request.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::{AuthService, MfaMethodService};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository,
    SurrealPasswordHistoryRepository, SurrealPermissionRepository, SurrealRefreshTokenRepository,
    SurrealRoleRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const TEST_PEER: &str = "127.0.0.1:12345";
/// Test-only placeholder — not a real credential. gitleaks:allow
const INITIAL_PASSWORD: &str = "InitialPassw0rdStrong";

type TestDb = surrealdb::engine::local::Db;

// Test-only Ed25519 keypair with no real-world value. nosemgrep
fn test_auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
            "-----END PRIVATE KEY-----"
        )
        .into(),
        jwt_public_key_pem: concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
            "-----END PUBLIC KEY-----"
        )
        .into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "mfa-reset-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "mfa-reset-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let settings_repo = SurrealSettingsRepository::new(db.clone());
    settings_repo
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: INITIAL_PASSWORD.into(),
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

    (db, org.id, tenant.id, user.id)
}

fn make_auth_service(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
) -> AuthService<
    SurrealUserRepository<TestDb>,
    SurrealSessionRepository<TestDb>,
    SurrealFederationLinkRepository<TestDb>,
    SurrealRefreshTokenRepository<TestDb>,
> {
    AuthService::new(
        SurrealUserRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        auth.clone(),
    )
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(make_auth_service(&$db, &$auth)))
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

async fn login(
    app: &impl actix_web::dev::Service<
        actix_web::test::TestRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    tenant_id: Uuid,
) -> (String, String) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "org_id": org_id,
            "username_or_email": "alice",
            "password": INITIAL_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "login must succeed");
    let access = resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_access")
        .map(|c| c.value().to_owned())
        .expect("axiam_access cookie");
    let csrf = resp
        .response()
        .cookies()
        .find(|c| c.name() == "axiam_csrf")
        .map(|c| c.value().to_owned())
        .expect("axiam_csrf cookie");
    (access, csrf)
}

async fn me_status(
    app: &impl actix_web::dev::Service<
        actix_web::test::TestRequest,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    access: &str,
    csrf: &str,
) -> u16 {
    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/me")
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf.to_owned()))
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

/// Resetting a user's MFA invalidates their existing sessions — D-17.
/// Self-service reset (caller resets own MFA) is permitted by `is_own_resource`.
#[actix_rt::test]
async fn mfa_reset_invalidates_sessions() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    // Establish an active session.
    let (access, csrf) = login(&app, org_id, tenant_id).await;
    assert_eq!(
        me_status(&app, &access, &csrf).await,
        200,
        "session must work before MFA reset"
    );

    // Reset MFA for the same user (self-service).
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf.clone()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        204,
        "reset-mfa must succeed with 204"
    );

    // The previously-issued cookie must now be rejected.
    assert_eq!(
        me_status(&app, &access, &csrf).await,
        401,
        "session cookie must be revoked after MFA reset"
    );
}

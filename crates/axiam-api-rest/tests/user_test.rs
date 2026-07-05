//! Integration tests for user management endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Arbitrary CSRF token for the double-submit check (SEC-046). These
/// Bearer-token tests have no login/`axiam_csrf` cookie, so we send a matching
/// `axiam_csrf` cookie + `X-CSRF-Token` header; the middleware only checks they
/// are equal (no session lookup). Safe (GET) requests ignore it.
const CSRF_TOKEN: &str = "test-csrf-token";

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

/// Set up in-memory DB with org + tenant, return (db, org_id, tenant_id).
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

/// Create a user in the DB and return its ID (for minting JWT).
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
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        uuid::Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

/// Fresh in-memory DB with org+tenant AND the real permission registry +
/// default roles seeded — required for RBAC-gated (non-`AllowAllAuthzChecker`)
/// tests (FUNC-04).
async fn setup_db_with_rbac() -> (Surreal<TestDb>, Uuid, Uuid) {
    let (db, org_id, tenant_id) = setup_db().await;
    seed_permissions(&db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    (db, org_id, tenant_id)
}

/// Real RBAC engine (not `AllowAllAuthzChecker`) — needed to genuinely
/// exercise `RequirePermission` gates rather than bypass them.
fn make_real_authz(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

/// Create a user with NO role assigned — lacks every permission, including
/// `users:list` (FUNC-04 non-privileged-caller fixture).
async fn create_user_no_role(db: &Surreal<TestDb>, tenant_id: Uuid, username: &str, email: &str) -> Uuid {
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: email.into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    user.id
}

macro_rules! test_app_real_authz {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealUserRepository::new($db.clone())))
                .app_data(web::Data::new($authz.clone()))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealUserRepository::new($db.clone())))
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

#[actix_rt::test]
async fn create_user_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "alice",
            "email": "alice@example.com",
            "password": "securepass123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.com");
    assert!(body["id"].is_string());
    assert_eq!(body["status"], "PendingVerification");
}

#[actix_rt::test]
async fn create_user_omits_sensitive_fields() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "bob",
            "email": "bob@example.com",
            "password": "securepass123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("password_hash").is_none());
    assert!(body.get("mfa_secret").is_none());
    // failed_login_attempts and locked_until are now exposed in UserResponse
    // for admin visibility of lockout state
    assert!(body["failed_login_attempts"].is_number());
    assert!(body.get("locked_until").is_some()); // present (may be null)
}

#[actix_rt::test]
async fn list_users_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1); // admin user created in setup
    assert!(body["items"].is_array());
    assert!(body["items"][0].get("password_hash").is_none());
}

#[actix_rt::test]
async fn get_user_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "admin");
    assert_eq!(body["email"], "admin@example.com");
}

#[actix_rt::test]
async fn update_user_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "admin-updated",
            "status": "Active"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "admin-updated");
    // SEC-050: `status` is stripped on self-update (a user cannot change their
    // own account status), so it stays at the created default rather than the
    // requested "Active". This positively asserts the privilege-escalation guard.
    assert_eq!(body["status"], "PendingVerification");
}

#[actix_rt::test]
async fn delete_user_returns_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create a second user to delete
    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "to-delete",
            "email": "delete@example.com",
            "password": "securepass123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let delete_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{delete_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

#[actix_rt::test]
async fn user_response_includes_lock_state_fields() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    // is_locked should be present and false for a freshly created user
    assert_eq!(body["is_locked"], false);
    // locked_until should be present (null for a non-locked user)
    assert!(body.get("locked_until").is_some());
    // failed_login_attempts should be 0
    assert_eq!(body["failed_login_attempts"], 0);
}

#[actix_rt::test]
async fn unlock_user_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // POST to unlock endpoint — user is not locked but unlock is idempotent
    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}/unlock"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["is_locked"], false);
    assert_eq!(body["failed_login_attempts"], 0);
    assert!(body["locked_until"].is_null());
    // status should be Active after unlock
    assert_eq!(body["status"], "Active");
}

/// FUNC-04 (Task 3, verify-only): a caller lacking `users:list` must be
/// denied (403) on `GET /api/v1/users`. Uses the real `AuthorizationEngine`
/// (not `AllowAllAuthzChecker`) so the existing
/// `RequirePermission::new("users:list", ...)` gate in `handlers/users.rs`
/// is genuinely exercised end-to-end. No handler code was changed — this
/// test only proves the pre-existing gate works.
#[actix_rt::test]
async fn list_users_non_privileged_caller_returns_403() {
    let (db, org_id, tenant_id) = setup_db_with_rbac().await;
    let auth = test_auth_config();
    let authz = make_real_authz(&db);
    let no_role_user_id =
        create_user_no_role(&db, tenant_id, "no-role", "no-role@example.com").await;
    let token = mint_token(&auth, no_role_user_id, tenant_id, org_id);
    let app = test_app_real_authz!(db, auth, authz);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

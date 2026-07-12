//! RBAC enforcement integration tests.
//!
//! These tests verify that authorization is wired to every protected REST
//! endpoint (D-01, D-02, D-03) and that the static permission registry stays
//! in sync with the route map (D-08):
//!
//! - **401** on missing credentials
//! - **403** on insufficient permissions
//! - **200** for admin users with the super-admin role
//! - **200** for self-service access (owner accessing own profile)
//! - **403** for self-service pattern used against another user
//! - Public routes bypass the middleware
//! - Every entry in `ROUTE_PERMISSION_MAP` has a matching entry in
//!   `PERMISSION_REGISTRY`

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::{PERMISSION_REGISTRY, ROUTE_PERMISSION_MAP};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Test-only placeholder password — not a real credential.
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

/// Arbitrary CSRF double-submit token (SEC-046) — matching the `axiam_csrf`
/// cookie and `X-CSRF-Token` header; the middleware only checks they are equal.
const CSRF_TOKEN: &str = "test-csrf-token";

// -------------------------------------------------------------------------
// Key / config helpers (same Ed25519 keypair as other integration tests)
// -------------------------------------------------------------------------

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

// -------------------------------------------------------------------------
// Shared authz + repo setup
// -------------------------------------------------------------------------

fn make_authz(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

/// Fresh in-memory DB with an org + tenant + the default permission registry
/// and default roles seeded. Returns the IDs a test needs to mint tokens.
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

    // Seed the registry + default roles — permissions must exist before
    // any RequirePermission check runs.
    seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

/// Create a user and (optionally) assign them one of the default roles
/// (`"super-admin"`, `"admin"`, `"viewer"`). Returns the user id.
async fn create_user_with_role(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    username: &str,
    email: &str,
    role_name: Option<&str>,
) -> Uuid {
    use axiam_core::repository::{Pagination, RoleRepository};

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: email.into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Activate so /auth/login would succeed (not strictly needed for RBAC
    // tests but keeps the fixture realistic).
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

    if let Some(name) = role_name {
        let role_repo = SurrealRoleRepository::new(db.clone());
        let roles = role_repo
            .list(
                tenant_id,
                Pagination {
                    offset: 0,
                    limit: 1000,
                },
            )
            .await
            .unwrap();
        let role = roles
            .items
            .into_iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("default role `{name}` not seeded"));
        role_repo
            .assign_to_user(tenant_id, user.id, role.id, None)
            .await
            .unwrap();
    }

    user.id
}

// -------------------------------------------------------------------------
// App-data bundle — mirrors the production composition so
// `register_api_v1_routes` can resolve every handler's extractors.
// -------------------------------------------------------------------------

macro_rules! test_app {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

/// `unauthenticated_returns_401`
///
/// A request to a protected endpoint without any cookie or Authorization
/// header must be rejected by the AuthzMiddleware with 401 (D-03).
#[actix_rt::test]
async fn unauthenticated_returns_401() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let req = test::TestRequest::get().uri("/api/v1/users").to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

/// `no_permission_returns_403`
///
/// A user with the `viewer` role (read-only) attempting a create endpoint
/// must be rejected with 403 — the middleware lets them through (they have
/// credentials) and the per-handler RequirePermission check denies.
#[actix_rt::test]
async fn no_permission_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let viewer_id = create_user_with_role(
        &db,
        tenant_id,
        "viewer",
        "viewer@example.com",
        Some("viewer"),
    )
    .await;
    let token = mint_token(&auth, viewer_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let req = test::TestRequest::post()
        .uri("/api/v1/users")
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "newcomer",
            "email": "newcomer@example.com",
            "password": "securepass123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    // SDK-Q02: the 403 body carries structured `action`/`resource_id`
    // fields so SDKs can parse them without string-matching `message`.
    // `RequirePermission::new("users:create", Uuid::nil())` checks the
    // "global" sentinel, so `resource_id` must be omitted (null), while
    // `action` must echo the checked permission string.
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "authorization_denied");
    assert_eq!(body["action"], "users:create");
    assert!(
        body.get("resource_id").is_none() || body["resource_id"].is_null(),
        "expected no resource_id for a global (nil-resource) denial, got {body:?}"
    );
}

/// `no_permission_returns_403_with_resource_scoped_fields`
///
/// A resource-scoped denial (not the `Uuid::nil()` "global" sentinel) must
/// carry a non-null `resource_id` alongside `action` in the 403 body.
/// `POST /api/v1/authz/check` with a `subject_id` override requires the
/// `authz:check_as` permission, checked against `user.tenant_id` (never
/// nil in a seeded tenant) — see `RequirePermission::new("authz:check_as",
/// user.tenant_id)` in `handlers/authz_check.rs`.
#[actix_rt::test]
async fn no_permission_returns_403_with_resource_scoped_fields() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let viewer_id = create_user_with_role(
        &db,
        tenant_id,
        "viewer2",
        "viewer2@example.com",
        Some("viewer"),
    )
    .await;
    let token = mint_token(&auth, viewer_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let req = test::TestRequest::post()
        .uri("/api/v1/authz/check")
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "action": "users:get",
            "resource_id": Uuid::new_v4(),
            "subject_id": Uuid::new_v4(),
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["error"], "authorization_denied");
    assert_eq!(body["action"], "authz:check_as");
    assert_eq!(body["resource_id"], tenant_id.to_string());
}

/// `admin_can_access`
///
/// A user with the `super-admin` role must be allowed to call any endpoint.
#[actix_rt::test]
async fn admin_can_access() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let admin_id = create_user_with_role(
        &db,
        tenant_id,
        "root",
        "root@example.com",
        Some("super-admin"),
    )
    .await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let req = test::TestRequest::get()
        .uri("/api/v1/users")
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

/// `self_service_owner_allowed`
///
/// A viewer (no `users:update`) must be able to GET their own profile
/// via `/users/{own_id}` — self-service bypasses the admin-permission
/// check (D-13, D-14).
#[actix_rt::test]
async fn self_service_owner_allowed() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let viewer_id =
        create_user_with_role(&db, tenant_id, "self1", "self1@example.com", Some("viewer")).await;
    let token = mint_token(&auth, viewer_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    // GET own profile — should be 200 even without `users:get` (viewer has
    // :list/:get so this is a double-positive but still exercises the path).
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{viewer_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

/// `self_service_nonowner_denied`
///
/// A viewer (no `users:update`) attempting to PUT another user's profile
/// must be rejected with 403 — self-service only applies to own resources.
#[actix_rt::test]
async fn self_service_nonowner_denied() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let viewer_id = create_user_with_role(
        &db,
        tenant_id,
        "reader",
        "reader@example.com",
        Some("viewer"),
    )
    .await;
    let other_id =
        create_user_with_role(&db, tenant_id, "target", "target@example.com", None).await;
    let token = mint_token(&auth, viewer_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/users/{other_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "hijacked"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

/// `public_routes_no_auth_required`
///
/// `/health` and `/auth/login` must NOT be blocked by AuthzMiddleware.
/// Login with a bad payload returns a 4xx auth-related response, but crucially
/// not the middleware's blanket 401 for missing credentials.
#[actix_rt::test]
async fn public_routes_no_auth_required() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);

    // /health route is registered separately — not via register_api_v1_routes
    // — so build a minimal app for it.
    let health_app =
        test::init_service(App::new().configure(axiam_api_rest::health_routes::<TestDb>)).await;
    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&health_app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // Login with a body missing the `password` field — the JSON parser must
    // reject with 400 AFTER the request gets past AuthzMiddleware. We
    // deliberately send an incomplete body so the failure is at the
    // serde-layer (400), not at the handler-level credentials check (401 —
    // which 01-05 returns for unknown slugs to prevent enumeration). A 400
    // here is definitive proof that the middleware did not block the route.
    let app = test_app!(db, auth, authz);
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .set_json(serde_json::json!({
            "username": "nobody",
            "tenant_slug": "test-tenant",
            "org_slug": "test-org",
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    assert_eq!(
        status, 400,
        "/api/v1/auth/login must reach the JSON parser (got {status} — middleware likely blocked)"
    );
}

/// `all_routes_have_permission` — D-08 static analysis.
///
/// Every `(method, path, permission)` entry in `ROUTE_PERMISSION_MAP` must
/// have a matching `(action, description)` entry in `PERMISSION_REGISTRY`.
/// This is the CI tripwire that catches missing permission definitions
/// before a handler is shipped with an unresolvable permission name.
#[::core::prelude::v1::test]
fn all_routes_have_permission() {
    let mut missing: Vec<String> = Vec::new();
    for (method, path, permission) in ROUTE_PERMISSION_MAP {
        let found = PERMISSION_REGISTRY
            .iter()
            .any(|(action, _)| *action == *permission);
        if !found {
            missing.push(format!("{method} {path} -> `{permission}`"));
        }
    }

    assert!(
        missing.is_empty(),
        "ROUTE_PERMISSION_MAP references permissions not in PERMISSION_REGISTRY:\n  - {}",
        missing.join("\n  - ")
    );
}

// -------------------------------------------------------------------------
// NEW-2 — org-baseline settings must require the dedicated org-level
// permission, NOT the tenant-scoped `settings:*` self-management permission.
// -------------------------------------------------------------------------

/// Create a fresh role granted exactly one permission (by its action string)
/// and assign it to a new user. Returns the user id.
async fn user_with_single_permission(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    username: &str,
    permission_action: &str,
) -> Uuid {
    use axiam_core::models::role::CreateRole;
    use axiam_core::repository::{Pagination, PermissionRepository, RoleRepository};

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let role_repo = SurrealRoleRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: format!("role-{username}"),
            description: format!("grants only {permission_action}"),
            // Global so the grant applies to the nil-resource permission check
            // the org-settings handlers perform (RequirePermission uses
            // Uuid::nil()); a non-global role would be filtered out by the
            // engine's resource-scope check.
            is_global: true,
        })
        .await
        .unwrap();

    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let perms = perm_repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
            },
        )
        .await
        .unwrap();
    let perm = perms
        .items
        .into_iter()
        .find(|p| p.action == permission_action)
        .unwrap_or_else(|| panic!("permission `{permission_action}` not seeded"));
    perm_repo
        .grant_to_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant_id, user.id, role.id, None)
        .await
        .unwrap();

    user.id
}

/// Full valid org-settings body (mirrors settings_test::set_org_settings_returns_200).
fn valid_org_settings_body() -> serde_json::Value {
    serde_json::json!({
        "min_length": 16,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_digits": true,
        "require_symbols": true,
        "password_history_count": 10,
        "hibp_check_enabled": true,
        "mfa_enforced": true,
        "mfa_challenge_lifetime_secs": 300,
        "max_failed_login_attempts": 3,
        "lockout_duration_secs": 600,
        "lockout_backoff_multiplier": 2.0,
        "max_lockout_duration_secs": 3600,
        "access_token_lifetime_secs": 900,
        "refresh_token_lifetime_secs": 2592000,
        "email_verification_required": true,
        "email_verification_grace_period_hours": 24,
        "default_cert_validity_days": 365,
        "max_cert_validity_days": 730,
        "admin_notifications_enabled": true
    })
}

/// A tenant-scoped `settings:update` grant must NOT authorize writing the
/// organization baseline settings (regression for NEW-2 — the handler used to
/// enforce `settings:update` instead of `organizations:update_settings`).
#[actix_rt::test]
async fn org_settings_update_denies_tenant_settings_permission() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let user_id =
        user_with_single_permission(&db, tenant_id, "tenantadmin", "settings:update").await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(valid_org_settings_body())
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "settings:update (tenant permission) must not authorize org-baseline writes"
    );
}

/// The dedicated `organizations:update_settings` grant authorizes the org
/// baseline write (confirms the handler now enforces the org-level permission).
#[actix_rt::test]
async fn org_settings_update_allows_org_settings_permission() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let user_id =
        user_with_single_permission(&db, tenant_id, "orgadmin", "organizations:update_settings")
            .await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, authz);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}/settings"))
        .peer_addr("127.0.0.1:12345".parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(valid_org_settings_body())
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "organizations:update_settings must authorize the org-baseline write"
    );
}

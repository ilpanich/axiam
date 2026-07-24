//! Additional coverage for the roles/permissions/scopes REST handlers not
//! exercised by the happy-path-only `tests/role_permission_test.rs` and
//! `tests/resource_scope_test.rs`: not-found branches, cross-resource scope
//! mismatch, permission-denied (403), and `roles.rs`'s `list_users`/
//! `list_groups` endpoints (previously untested at any level).

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker, DenyAllAuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const CSRF_TOKEN: &str = "test-csrf-token";
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

/// Generates a fresh Ed25519 JWT signing keypair at test runtime (no literal
/// key material in source — avoids new secret-scanner findings).
fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
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

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "RBAC Gaps Org".into(),
            slug: "rbac-gaps-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "RBAC Gaps Tenant".into(),
            slug: "rbac-gaps-tenant".into(),
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
            username: format!("admin-{}", Uuid::new_v4().simple()),
            email: format!("{}@example.com", Uuid::new_v4().simple()),
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

fn auth_header(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {token}"))
}

fn with_csrf(rb: test::TestRequest) -> test::TestRequest {
    rb.insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
}

// ---------------------------------------------------------------------------
// permissions.rs — not-found / conflict / denied
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn get_permission_not_found_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (h, v) = auth_header(&token);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/permissions/{}", Uuid::new_v4()))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

// Creating a permission with an `action` that already exists in the tenant
// must return 409 Conflict: `SurrealPermissionRepository::create` now routes
// its unique-index violation through `classify_write_error` (the QUAL-03/D-09
// policy used by sibling repos), mapping it to `AxiamError::AlreadyExists` ->
// HTTP 409 rather than the former `DbError::Migration` -> `AxiamError::Database`
// -> HTTP 500. This test locks in the corrected behavior end-to-end.
#[actix_rt::test]
async fn create_permission_duplicate_action_returns_409_conflict() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (h, v) = auth_header(&token);
    let make_req = || {
        with_csrf(test::TestRequest::post())
            .uri("/api/v1/permissions")
            .insert_header((h, v.clone()))
            .set_json(json!({ "action": "users:read", "description": "Read users" }))
            .to_request()
    };

    let first = test::call_service(&app, make_req()).await;
    assert_eq!(first.status().as_u16(), 201);

    let second = test::call_service(&app, make_req()).await;
    assert_eq!(
        second.status().as_u16(),
        409,
        "a duplicate permission action must return 409 Conflict via \
         classify_write_error, not 500"
    );
}

#[actix_rt::test]
async fn create_permission_denied_without_grant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/permissions")
        .insert_header((h, v))
        .set_json(json!({ "action": "x:y", "description": "d" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

#[actix_rt::test]
async fn update_permission_not_found_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::put())
        .uri(&format!("/api/v1/permissions/{}", Uuid::new_v4()))
        .insert_header((h, v))
        .set_json(json!({ "description": "won't apply" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

/// Unlike `get`/`update`, `delete` on a nonexistent permission is idempotent
/// (204) rather than 404 — this locks in that actual repository behavior
/// (deleting a row that's already absent is a no-op success, not an error).
#[actix_rt::test]
async fn delete_permission_not_found_is_idempotent_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!("/api/v1/permissions/{}", Uuid::new_v4()))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

#[actix_rt::test]
async fn update_permission_denied_without_grant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::put())
        .uri(&format!("/api/v1/permissions/{}", Uuid::new_v4()))
        .insert_header((h, v))
        .set_json(json!({ "description": "won't apply" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

#[actix_rt::test]
async fn delete_permission_denied_without_grant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!("/api/v1/permissions/{}", Uuid::new_v4()))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// permissions.rs — role<->permission grant/revoke not-found / denied
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn grant_to_role_denied_without_grant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::post())
        .uri(&format!("/api/v1/roles/{}/permissions", Uuid::new_v4()))
        .insert_header((h, v))
        .set_json(json!({ "permission_id": Uuid::new_v4() }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

#[actix_rt::test]
async fn grant_to_role_nonexistent_role_returns_error() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);
    let (h, v) = auth_header(&token);

    // Create a real permission, but reference a role_id that was never created.
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/permissions")
        .insert_header((h, v.clone()))
        .set_json(json!({ "action": "grants:nonexistent-role", "description": "d" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let perm: Value = test::read_body_json(resp).await;
    let perm_id = perm["id"].as_str().unwrap();

    let req = with_csrf(test::TestRequest::post())
        .uri(&format!("/api/v1/roles/{}/permissions", Uuid::new_v4()))
        .insert_header((h, v))
        .set_json(json!({ "permission_id": perm_id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(
        resp.status().as_u16() >= 400,
        "granting a permission to a nonexistent role must fail, got {}",
        resp.status().as_u16()
    );
}

#[actix_rt::test]
async fn revoke_from_role_denied_without_grant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!(
            "/api/v1/roles/{}/permissions/{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        ))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

/// CQ-B07: `revoke_from_role`'s repository implementation verifies BOTH the
/// role AND the permission resolve within the caller's tenant before the
/// DELETE runs — a `permission_id` that doesn't exist at all (never created,
/// in any tenant) fails that same existence check and is treated identically
/// to a genuine cross-tenant edge: 403 `AuthorizationDenied`, not a 404. This
/// locks in that real (and previously untested) security-first behavior.
#[actix_rt::test]
async fn revoke_from_role_nonexistent_permission_returns_403_cross_tenant_denied() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (h, v) = auth_header(&token);
    // Create a real role so the revoke path runs the full repo query, just
    // with a permission_id that was never created anywhere.
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/roles")
        .insert_header((h, v.clone()))
        .set_json(json!({
            "name": "Revoke Target Role",
            "description": "role for revoke-never-granted test",
            "is_global": true
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201, "role creation must succeed");
    let role: Value = test::read_body_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!(
            "/api/v1/roles/{role_id}/permissions/{}",
            Uuid::new_v4()
        ))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "revoking a nonexistent permission must fail the CQ-B07 tenant-membership guard"
    );
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["message"],
        "Authorization denied: cross-tenant permission revocation denied"
    );
}

#[actix_rt::test]
async fn list_role_permissions_denied_without_grant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));

    let (h, v) = auth_header(&token);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/roles/{}/permissions", Uuid::new_v4()))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// roles.rs — not-found, list_users, list_groups
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn get_role_not_found_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (h, v) = auth_header(&token);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/roles/{}", Uuid::new_v4()))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn update_role_not_found_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::put())
        .uri(&format!("/api/v1/roles/{}", Uuid::new_v4()))
        .insert_header((h, v))
        .set_json(json!({ "name": "renamed" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn list_role_users_returns_assigned_users() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_id = create_admin_user(&db, tenant_id).await;
    let member_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth);
    let (h, v) = auth_header(&token);

    // Create role.
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/roles")
        .insert_header((h, v.clone()))
        .set_json(json!({ "name": "viewer", "description": "d", "is_global": true }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let role: Value = test::read_body_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    // Assign to member_id.
    let req = with_csrf(test::TestRequest::post())
        .uri(&format!("/api/v1/roles/{role_id}/users"))
        .insert_header((h, v.clone()))
        .set_json(json!({ "user_id": member_id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);

    // list_users must return exactly that member.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/roles/{role_id}/users"))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    let users = body.as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["id"], json!(member_id));
}

#[actix_rt::test]
async fn list_role_groups_returns_assigned_groups() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth);
    let (h, v) = auth_header(&token);

    // Create a group directly via the API.
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/groups")
        .insert_header((h, v.clone()))
        .set_json(json!({ "name": "Engineers", "description": "d" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let group: Value = test::read_body_json(resp).await;
    let group_id = group["id"].as_str().unwrap();

    // Create role.
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/roles")
        .insert_header((h, v.clone()))
        .set_json(json!({ "name": "deployer", "description": "d", "is_global": false }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let role: Value = test::read_body_json(resp).await;
    let role_id = role["id"].as_str().unwrap();

    // Assign role to group.
    let req = with_csrf(test::TestRequest::post())
        .uri(&format!("/api/v1/roles/{role_id}/groups"))
        .insert_header((h, v.clone()))
        .set_json(json!({ "group_id": group_id }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/roles/{role_id}/groups"))
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    let groups = body.as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["id"], json!(group_id));
}

#[actix_rt::test]
async fn assign_role_to_user_denied_without_grant_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin_id = create_admin_user(&db, tenant_id).await;
    let member_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, admin_id, tenant_id, org_id);

    // First create the role with AllowAll so the request body's role_id is
    // real, then re-issue the assign call against a DenyAll-wired app.
    let allow_app = test_app!(db, auth.clone());
    let (h, v) = auth_header(&token);
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/roles")
        .insert_header((h, v.clone()))
        .set_json(json!({ "name": "guarded-role", "description": "d", "is_global": true }))
        .to_request();
    let resp = test::call_service(&allow_app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let role: Value = test::read_body_json(resp).await;
    let role_id = role["id"].as_str().unwrap().to_string();
    drop(allow_app);

    let deny_app = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));
    let req = with_csrf(test::TestRequest::post())
        .uri(&format!("/api/v1/roles/{role_id}/users"))
        .insert_header((h, v))
        .set_json(json!({ "user_id": member_id }))
        .to_request();
    let resp = test::call_service(&deny_app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// scopes.rs — cross-resource mismatch / not-found
// ---------------------------------------------------------------------------

async fn create_resource(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    name: &str,
) -> String {
    let req = with_csrf(test::TestRequest::post())
        .uri("/api/v1/resources")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({ "name": name, "resource_type": "service" }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let body: Value = test::read_body_json(resp).await;
    body["id"].as_str().unwrap().to_string()
}

#[actix_rt::test]
async fn get_scope_not_found_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let resource_id = create_resource(&app, &token, "Res A").await;
    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/resources/{resource_id}/scopes/{}",
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn get_scope_wrong_resource_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let resource_a = create_resource(&app, &token, "Res A").await;
    let resource_b = create_resource(&app, &token, "Res B").await;

    // Create a scope under resource A.
    let req = with_csrf(test::TestRequest::post())
        .uri(&format!("/api/v1/resources/{resource_a}/scopes"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({ "name": "read:a", "description": "d" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);
    let scope: Value = test::read_body_json(resp).await;
    let scope_id = scope["id"].as_str().unwrap();

    // GET/PUT/DELETE it via resource B's path — must 404 (belongs to A, not B).
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/resources/{resource_b}/scopes/{scope_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);

    let req = with_csrf(test::TestRequest::put())
        .uri(&format!("/api/v1/resources/{resource_b}/scopes/{scope_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({ "name": "renamed" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);

    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!("/api/v1/resources/{resource_b}/scopes/{scope_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

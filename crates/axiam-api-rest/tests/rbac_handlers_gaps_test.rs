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

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
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

// NOTE (found while writing this test, not fixed here per the additive-only
// mandate): `SurrealPermissionRepository::create` maps its unique-index
// violation via a bare `.map_err(|e| DbError::Migration(e.to_string()))`
// instead of routing it through `classify_write_error` the way sibling
// repos do (e.g. `role.rs`'s `assign_to_user`/`assign_to_group`, per the
// QUAL-03/D-09 policy documented on `classify_write_error`). `DbError::
// Migration` converts to `AxiamError::Database` -> HTTP 500, so creating a
// permission with an `action` that already exists in the tenant currently
// returns 500 instead of the expected 409. This test asserts the ACTUAL
// (buggy) behavior rather than the intended one, per the "verify real
// behavior, don't assume" rule — flip the expected status to 409 once
// `permission.rs::create` is fixed to call `classify_write_error`.
#[actix_rt::test]
async fn create_permission_duplicate_action_returns_500_not_409_known_bug() {
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
        500,
        "documents a real bug: duplicate permission action should be 409, is 500 \
         (permission.rs::create doesn't use classify_write_error)"
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

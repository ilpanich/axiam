//! Integration tests for organization CRUD endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, Pagination, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealRoleRepository, SurrealTenantRepository,
    SurrealUserRepository,
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
    // Test-only non-secret Ed25519 key pair used solely for JWT signing in unit tests.
    let private_key = [
        "-----BEGIN PRIVATE KEY-----\n", // nosemgrep: generic.secrets.security.detected-private-key
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----",
    ]
    .concat();
    let public_key = [
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----",
    ]
    .concat();
    (private_key, public_key)
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

/// Set up in-memory DB with org + tenant + seeded roles.
/// Returns (db, org_id, tenant_id).
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

    // Seed permissions and default roles so super-admin checks work.
    seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

/// Create a user and optionally assign a named role. Returns user_id.
async fn create_user_with_role(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    username: &str,
    email: &str,
    role_name: Option<&str>,
) -> Uuid {
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
            .unwrap_or_else(|| panic!("role `{name}` not seeded"));
        role_repo
            .assign_to_user(tenant_id, user.id, role.id, None)
            .await
            .unwrap();
    }

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

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealRoleRepository::new($db.clone())))
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
// Existing positive-path tests (updated to use super-admin where needed)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn create_organization_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    // create/list requires super-admin
    let user_id = create_user_with_role(
        &db,
        tenant_id,
        "admin",
        "admin@example.com",
        Some("super-admin"),
    )
    .await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/organizations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "New Org",
            "slug": "new-org"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "New Org");
    assert_eq!(body["slug"], "new-org");
    assert!(body["id"].is_string());
}

#[actix_rt::test]
async fn list_organizations_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    // create/list requires super-admin
    let user_id = create_user_with_role(
        &db,
        tenant_id,
        "admin",
        "admin@example.com",
        Some("super-admin"),
    )
    .await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/organizations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1); // setup_db created one
    assert!(body["items"].is_array());
}

#[actix_rt::test]
async fn get_organization_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(&db, tenant_id, "admin", "admin@example.com", None).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Test Org");
}

#[actix_rt::test]
async fn get_nonexistent_organization_returns_404() {
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    // Use a fake org_id that matches the JWT so ownership guard passes, but record doesn't exist.
    let user_id = create_user_with_role(&db, tenant_id, "admin", "admin@example.com", None).await;
    let fake_id = Uuid::new_v4();
    // Mint a token that claims org = fake_id so the ownership guard allows it.
    let token = mint_token(&auth, user_id, tenant_id, fake_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn update_organization_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(&db, tenant_id, "admin", "admin@example.com", None).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{org_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Updated Org" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Updated Org");
}

#[actix_rt::test]
async fn delete_organization_returns_204() {
    let (db, _org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(&db, tenant_id, "admin", "admin@example.com", None).await;

    // The delete guard only allows deleting your own org_id, so create a second org
    // and mint a token claiming that second org to delete it.
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let second_org = org_repo
        .create(CreateOrganization {
            name: "To Delete".into(),
            slug: "to-delete".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let delete_id = second_org.id;

    let delete_token = mint_token(&auth, user_id, tenant_id, delete_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/organizations/{delete_id}"))
        .insert_header(("Authorization", format!("Bearer {delete_token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

// ---------------------------------------------------------------------------
// SEC-002: Cross-org 403 negative tests
// ---------------------------------------------------------------------------

/// A caller authenticated for org A gets 403 on GET /organizations/{org_B_id}.
/// Regression guard: same-org caller gets 200.
#[actix_rt::test]
async fn cross_org_get_organization_returns_403() {
    let (db, org_a_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(&db, tenant_id, "admin", "admin@example.com", None).await;

    // Create org B.
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let org_b_id = org_b.id;

    // Token claims org A.
    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    // Cross-org: should get 403.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_b_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403, "cross-org GET must return 403");

    // Same-org regression guard: should get 200.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_a_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "same-org GET must return 200");
}

/// A caller authenticated for org A gets 403 on PUT /organizations/{org_B_id}.
#[actix_rt::test]
async fn cross_org_update_organization_returns_403() {
    let (db, org_a_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(&db, tenant_id, "admin", "admin@example.com", None).await;

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-upd".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Token claims org A.
    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/organizations/{}", org_b.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Hacked" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403, "cross-org PUT must return 403");
}

/// A caller authenticated for org A gets 403 on DELETE /organizations/{org_B_id}.
#[actix_rt::test]
async fn cross_org_delete_organization_returns_403() {
    let (db, org_a_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(&db, tenant_id, "admin", "admin@example.com", None).await;

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-del".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Token claims org A.
    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/organizations/{}", org_b.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org DELETE must return 403"
    );
}

// ---------------------------------------------------------------------------
// SEC-002: System-admin restriction on create/list
// ---------------------------------------------------------------------------

/// A non-super-admin caller gets 403 on POST /organizations.
#[actix_rt::test]
async fn non_super_admin_create_organization_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    // Regular admin (not super-admin).
    let user_id =
        create_user_with_role(&db, tenant_id, "admin", "admin@example.com", Some("admin")).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/organizations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Unauthorized Org",
            "slug": "unauth-org"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "non-super-admin create must return 403"
    );
}

/// A non-super-admin caller gets 403 on GET /organizations.
#[actix_rt::test]
async fn non_super_admin_list_organizations_returns_403() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    // Regular admin (not super-admin).
    let user_id =
        create_user_with_role(&db, tenant_id, "admin", "admin@example.com", Some("admin")).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/organizations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "non-super-admin list must return 403"
    );
}

/// A super-admin caller gets 2xx on POST /organizations.
#[actix_rt::test]
async fn super_admin_create_organization_returns_2xx() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(
        &db,
        tenant_id,
        "admin",
        "admin@example.com",
        Some("super-admin"),
    )
    .await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/organizations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Super Admin Org",
            "slug": "super-admin-org"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    assert!(
        (200..300).contains(&status),
        "super-admin create must return 2xx, got {status}"
    );
}

/// A super-admin caller gets 2xx on GET /organizations.
#[actix_rt::test]
async fn super_admin_list_organizations_returns_2xx() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_user_with_role(
        &db,
        tenant_id,
        "admin",
        "admin@example.com",
        Some("super-admin"),
    )
    .await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/organizations")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    assert!(
        (200..300).contains(&status),
        "super-admin list must return 2xx, got {status}"
    );
}

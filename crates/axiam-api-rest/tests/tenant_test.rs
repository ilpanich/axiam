//! Integration tests for tenant CRUD endpoints.

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
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
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

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
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

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
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
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
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

#[actix_rt::test]
async fn create_tenant_returns_201() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "New Tenant",
            "slug": "new-tenant"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "New Tenant");
    assert_eq!(body["slug"], "new-tenant");
    assert_eq!(body["organization_id"], org_id.to_string());
}

#[actix_rt::test]
async fn list_tenants_returns_200() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1); // setup_db created one
    assert!(body["items"].is_array());
}

#[actix_rt::test]
async fn get_tenant_returns_200() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{tenant_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Test Tenant");
}

#[actix_rt::test]
async fn update_tenant_returns_200() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{tenant_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Updated Tenant" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Updated Tenant");
}

#[actix_rt::test]
async fn delete_tenant_returns_204() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create a second tenant to delete
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "To Delete",
            "slug": "to-delete"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let delete_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{delete_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

// ---------------------------------------------------------------------------
// SEC-002: Cross-org 403 negative tests
// ---------------------------------------------------------------------------

/// A caller authenticated for org A gets 403 on GET /organizations/{org_B_id}/tenants.
/// Regression guard: same-org caller gets 200.
#[actix_rt::test]
async fn cross_org_list_tenants_returns_403() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    // Create org B with a distinct id.
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

    // Cross-org list: path org_id = org_B, JWT org_id = org_A -> 403.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_b_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant list must return 403"
    );

    // Same-org regression guard.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_a_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "same-org tenant list must return 200"
    );
}

/// A caller authenticated for org A gets 403 on POST /organizations/{org_B_id}/tenants.
#[actix_rt::test]
async fn cross_org_create_tenant_returns_403() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-create".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{}/tenants", org_b.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Sneaky Tenant",
            "slug": "sneaky-tenant"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant create must return 403"
    );
}

/// A caller authenticated for org A gets 403 on GET a single tenant under org B.
/// The ownership guard must reject before any DB read.
#[actix_rt::test]
async fn cross_org_get_tenant_returns_403() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-get".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_b.id,
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant get must return 403"
    );
}

/// A caller authenticated for org A gets 403 on PUT a single tenant under org B
/// (the same top-of-handler ownership guard as GET, exercised for `update`).
#[actix_rt::test]
async fn cross_org_update_tenant_returns_403() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-update".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_b.id,
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Sneaky Update" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant update must return 403"
    );
}

/// A caller authenticated for org A gets 403 on DELETE a single tenant under
/// org B (same top-of-handler ownership guard, exercised for `delete`).
#[actix_rt::test]
async fn cross_org_delete_tenant_returns_403() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-delete".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_b.id,
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant delete must return 403"
    );
}

// ---------------------------------------------------------------------------
// Tenant-belongs-to-a-different-org 404s: distinct from the 403 guards above.
// The caller's org DOES match the URL's org_id (passes the ownership guard),
// but the tenant_id in the URL names a tenant that actually belongs to some
// OTHER organization — the handler must look the tenant up and then 404
// rather than trusting the path alone.
// ---------------------------------------------------------------------------

/// GET a tenant that exists but under a different org than the URL/token's
/// org_id -> 404 (not 200), even though the ownership guard itself passes.
#[actix_rt::test]
async fn get_tenant_wrong_org_returns_404() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-tenant-mismatch-get".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let other_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "Org B's Tenant".into(),
            slug: "org-b-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Token's org_id is org A, and the URL's org_id is also org A (guard
    // passes), but the tenant_id in the path belongs to org B.
    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_a_id, other_tenant.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "a tenant belonging to a different org must 404, not leak via 200"
    );
}

/// PUT a tenant that exists but under a different org -> 404.
#[actix_rt::test]
async fn update_tenant_wrong_org_returns_404() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-tenant-mismatch-update".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let other_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "Org B's Tenant".into(),
            slug: "org-b-tenant-update".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_a_id, other_tenant.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Should Not Apply" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "updating a tenant belonging to a different org must 404"
    );
}

/// DELETE a tenant that exists but under a different org -> 404 (and it must
/// NOT actually be deleted).
#[actix_rt::test]
async fn delete_tenant_wrong_org_returns_404() {
    let (db, org_a_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-tenant-mismatch-delete".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let other_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "Org B's Tenant".into(),
            slug: "org-b-tenant-delete".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, tenant_id, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_a_id, other_tenant.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "deleting a tenant belonging to a different org must 404"
    );

    // Still there, under its real org.
    let still_there = tenant_repo.get_by_id(other_tenant.id).await.unwrap();
    assert_eq!(still_there.organization_id, org_b.id);
}

/// `create`'s permission-seeding step (`seed_permissions`) is best-effort but
/// its failure must be surfaced as a mapped 500, not silently swallowed or a
/// raw internal error. Forced by redefining the `permission.action` field to
/// an incompatible type so the seeder's UPSERT fails with a genuine SurrealDB
/// coercion error — no production code changes, just DB-level fault
/// injection ahead of the request.
#[actix_rt::test]
async fn create_tenant_seed_permissions_failure_returns_500() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    // Force every subsequent `permission` UPSERT (including the one
    // `seed_permissions` issues for the newly-created tenant) to fail.
    db.query("DEFINE FIELD OVERWRITE action ON TABLE permission TYPE int PERMISSIONS FULL")
        .await
        .unwrap();

    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Broken Seed Tenant",
            "slug": "broken-seed-tenant"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        500,
        "a seed_permissions failure must map to a 500, not succeed or panic"
    );
}

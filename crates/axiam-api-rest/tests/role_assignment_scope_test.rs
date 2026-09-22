//! The read surface for **resource-scoped** role assignments.
//!
//! Three holes closed together, because each is useless without the others:
//!
//! * `GET /api/v1/roles/{role_id}/users` and `.../groups` returned bare subject
//!   rows, so a resource-scoped assignment looked exactly like a global one and
//!   a revoke next to it removed the wrong grant.
//! * `GET /api/v1/groups/{group_id}/roles` was never registered, though the
//!   admin UI's group detail page has always called it — the panel 404'd.
//!   `group_roles_endpoint_is_registered` is the regression pin for that.
//! * `GET /api/v1/users/{user_id}/roles` was referenced by a doc comment in
//!   `handlers/roles.rs` and by nothing else.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker, DenyAllAuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
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
            name: "Scope Org".into(),
            slug: "scope-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Scope Tenant".into(),
            slug: "scope-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

async fn create_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: format!("u-{}", Uuid::new_v4().simple()),
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

fn with_csrf(req: test::TestRequest) -> test::TestRequest {
    req.insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
}

/// The fixture every test below shares: an authenticated admin, a role, a user,
/// a group and a resource, with the plumbing to talk to the API as that admin.
struct Fixture {
    token: String,
}

impl Fixture {
    fn bearer(&self) -> (&'static str, String) {
        ("Authorization", format!("Bearer {}", self.token))
    }
}

async fn post_json(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    fx: &Fixture,
    uri: &str,
    body: Value,
    expect: u16,
) -> Value {
    let (h, v) = fx.bearer();
    let req = with_csrf(test::TestRequest::post())
        .uri(uri)
        .insert_header((h, v))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    assert_eq!(status, expect, "POST {uri}");
    if status == 204 {
        return Value::Null;
    }
    test::read_body_json(resp).await
}

async fn get_json(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    fx: &Fixture,
    uri: &str,
) -> Value {
    let (h, v) = fx.bearer();
    let req = test::TestRequest::get()
        .uri(uri)
        .insert_header((h, v))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "GET {uri}");
    test::read_body_json(resp).await
}

async fn get_status(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    fx: &Fixture,
    uri: &str,
) -> u16 {
    let (h, v) = fx.bearer();
    let req = test::TestRequest::get()
        .uri(uri)
        .insert_header((h, v))
        .to_request();
    test::call_service(app, req).await.status().as_u16()
}

// ---------------------------------------------------------------------------
// GET /groups/{group_id}/roles — the endpoint the admin UI already called
// ---------------------------------------------------------------------------

/// Regression pin: `roleService.listByGroup` has called this from the group
/// detail page since CQ-F18, and no route was ever registered — the panel 404'd
/// against a real server. A 404 here means the route was dropped again.
#[actix_rt::test]
async fn group_roles_endpoint_is_registered() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let group = post_json(
        &app,
        &fx,
        "/api/v1/groups",
        json!({ "name": "Engineers", "description": "d" }),
        201,
    )
    .await;
    let group_id = group["id"].as_str().unwrap();

    assert_eq!(
        get_status(&app, &fx, &format!("/api/v1/groups/{group_id}/roles")).await,
        200,
        "the group roles panel must have an endpoint to call"
    );
}

#[actix_rt::test]
async fn group_roles_carries_the_resource_scope_of_each_assignment() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let group = post_json(
        &app,
        &fx,
        "/api/v1/groups",
        json!({ "name": "Ops", "description": "d" }),
        201,
    )
    .await;
    let group_id = group["id"].as_str().unwrap();

    let resource = post_json(
        &app,
        &fx,
        "/api/v1/resources",
        json!({ "name": "prod-cluster", "resource_type": "cluster" }),
        201,
    )
    .await;
    let resource_id = resource["id"].as_str().unwrap();

    let global_role = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "reader", "description": "d", "is_global": true }),
        201,
    )
    .await;
    let scoped_role = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "operator", "description": "d", "is_global": false }),
        201,
    )
    .await;
    let global_role_id = global_role["id"].as_str().unwrap();
    let scoped_role_id = scoped_role["id"].as_str().unwrap();

    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{global_role_id}/groups"),
        json!({ "group_id": group_id }),
        204,
    )
    .await;
    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{scoped_role_id}/groups"),
        json!({ "group_id": group_id, "resource_id": resource_id }),
        204,
    )
    .await;

    let body = get_json(&app, &fx, &format!("/api/v1/groups/{group_id}/roles")).await;
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 2);

    let global = rows
        .iter()
        .find(|r| r["role"]["id"] == json!(global_role_id))
        .expect("the global assignment must be listed");
    assert_eq!(
        global["resource_id"],
        Value::Null,
        "a global assignment carries no resource scope"
    );

    let scoped = rows
        .iter()
        .find(|r| r["role"]["id"] == json!(scoped_role_id))
        .expect("the scoped assignment must be listed");
    assert_eq!(
        scoped["resource_id"],
        json!(resource_id),
        "a scoped assignment must name the resource it applies under"
    );
}

#[actix_rt::test]
async fn group_roles_404s_for_a_group_that_does_not_exist() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let missing = Uuid::new_v4();
    assert_eq!(
        get_status(&app, &fx, &format!("/api/v1/groups/{missing}/roles")).await,
        404,
        "an unknown group must not read as a group with no roles"
    );
}

// ---------------------------------------------------------------------------
// GET /users/{user_id}/roles
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn user_roles_lists_direct_and_group_inherited_assignments_with_scope() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let member = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let resource = post_json(
        &app,
        &fx,
        "/api/v1/resources",
        json!({ "name": "billing", "resource_type": "service" }),
        201,
    )
    .await;
    let resource_id = resource["id"].as_str().unwrap();

    let group = post_json(
        &app,
        &fx,
        "/api/v1/groups",
        json!({ "name": "Finance", "description": "d" }),
        201,
    )
    .await;
    let group_id = group["id"].as_str().unwrap();
    post_json(
        &app,
        &fx,
        &format!("/api/v1/groups/{group_id}/members"),
        json!({ "user_id": member }),
        204,
    )
    .await;

    let direct = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "auditor", "description": "d", "is_global": false }),
        201,
    )
    .await;
    let inherited = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "approver", "description": "d", "is_global": true }),
        201,
    )
    .await;
    let direct_id = direct["id"].as_str().unwrap();
    let inherited_id = inherited["id"].as_str().unwrap();

    // Direct, scoped to a resource.
    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{direct_id}/users"),
        json!({ "user_id": member, "resource_id": resource_id }),
        204,
    )
    .await;
    // Reaches the user only through their group, and globally.
    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{inherited_id}/groups"),
        json!({ "group_id": group_id }),
        204,
    )
    .await;

    let body = get_json(&app, &fx, &format!("/api/v1/users/{member}/roles")).await;
    let rows = body.as_array().unwrap();

    let direct_row = rows
        .iter()
        .find(|r| r["role"]["id"] == json!(direct_id))
        .expect("the direct assignment must be listed");
    assert_eq!(direct_row["resource_id"], json!(resource_id));

    let inherited_row = rows
        .iter()
        .find(|r| r["role"]["id"] == json!(inherited_id))
        .expect("a role reaching the user through a group must be listed too");
    assert_eq!(inherited_row["resource_id"], Value::Null);
}

#[actix_rt::test]
async fn user_roles_404s_for_a_user_that_does_not_exist() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let missing = Uuid::new_v4();
    assert_eq!(
        get_status(&app, &fx, &format!("/api/v1/users/{missing}/roles")).await,
        404
    );
}

#[actix_rt::test]
async fn the_new_read_endpoints_are_permission_gated() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };

    let group_id = {
        let app = test_app!(db, auth.clone());
        let group = post_json(
            &app,
            &fx,
            "/api/v1/groups",
            json!({ "name": "Gated", "description": "d" }),
            201,
        )
        .await;
        group["id"].as_str().unwrap().to_string()
    };

    let deny = test_app!(db, auth, Arc::new(DenyAllAuthzChecker));
    assert_eq!(
        get_status(&deny, &fx, &format!("/api/v1/groups/{group_id}/roles")).await,
        403
    );
    assert_eq!(
        get_status(&deny, &fx, &format!("/api/v1/users/{admin}/roles")).await,
        403
    );
}

// ---------------------------------------------------------------------------
// GET /roles/{role_id}/users and .../groups — now assignment rows
// ---------------------------------------------------------------------------

/// The reason the members table needed `resource_id` at all: an unassign that
/// does not name the resource deletes the edge whose `resource_id` is `NONE`.
/// Rendered without the scope, a revoke button next to a resource-scoped grant
/// silently deletes nothing — the row stays, the grant stays, and the admin is
/// told it worked.
#[actix_rt::test]
async fn revoking_a_scoped_assignment_needs_the_resource_id_the_listing_now_carries() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let member = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let resource = post_json(
        &app,
        &fx,
        "/api/v1/resources",
        json!({ "name": "eu-west", "resource_type": "region" }),
        201,
    )
    .await;
    let resource_id = resource["id"].as_str().unwrap();

    let role = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "maintainer", "description": "d", "is_global": false }),
        201,
    )
    .await;
    let role_id = role["id"].as_str().unwrap();

    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{role_id}/users"),
        json!({ "user_id": member, "resource_id": resource_id }),
        204,
    )
    .await;

    // The listing is what tells a client this grant is scoped at all.
    let body = get_json(&app, &fx, &format!("/api/v1/roles/{role_id}/users")).await;
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["user"]["id"], json!(member));
    assert_eq!(rows[0]["resource_id"], json!(resource_id));

    // Revoke as the UI used to, with no resource_id: reported as success, and
    // the grant is still there.
    let (h, v) = fx.bearer();
    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!("/api/v1/roles/{role_id}/users/{member}"))
        .insert_header((h, v.clone()))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    let body = get_json(&app, &fx, &format!("/api/v1/roles/{role_id}/users")).await;
    assert_eq!(
        body.as_array().unwrap().len(),
        1,
        "an unscoped revoke must not have removed the scoped grant"
    );

    // Revoke with the resource_id the listing hands the client: gone.
    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!(
            "/api/v1/roles/{role_id}/users/{member}?resource_id={resource_id}"
        ))
        .insert_header((h, v))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    let body = get_json(&app, &fx, &format!("/api/v1/roles/{role_id}/users")).await;
    assert!(
        body.as_array().unwrap().is_empty(),
        "revoking with the scope must remove the grant"
    );
}

/// `has_role` is `UNIQUE(in, out)`: a subject holds a given role once, globally
/// **or** under one resource, never both and never under two resources. Pinned
/// because it is what makes one row per subject the right shape for the members
/// table — and because the admin UI has to render the 409 rather than pretend
/// the second assignment landed.
#[actix_rt::test]
async fn a_subject_holds_a_role_at_most_once() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let member = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let resource = post_json(
        &app,
        &fx,
        "/api/v1/resources",
        json!({ "name": "ap-south", "resource_type": "region" }),
        201,
    )
    .await;
    let resource_id = resource["id"].as_str().unwrap();

    let role = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "reviewer", "description": "d", "is_global": false }),
        201,
    )
    .await;
    let role_id = role["id"].as_str().unwrap();

    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{role_id}/users"),
        json!({ "user_id": member }),
        204,
    )
    .await;
    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{role_id}/users"),
        json!({ "user_id": member, "resource_id": resource_id }),
        409,
    )
    .await;

    let body = get_json(&app, &fx, &format!("/api/v1/roles/{role_id}/users")).await;
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "the refused assignment must not be listed");
    assert_eq!(rows[0]["resource_id"], Value::Null);
}

#[actix_rt::test]
async fn role_groups_carries_the_resource_scope() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let resource = post_json(
        &app,
        &fx,
        "/api/v1/resources",
        json!({ "name": "staging", "resource_type": "environment" }),
        201,
    )
    .await;
    let resource_id = resource["id"].as_str().unwrap();

    let group = post_json(
        &app,
        &fx,
        "/api/v1/groups",
        json!({ "name": "Deployers", "description": "d" }),
        201,
    )
    .await;
    let group_id = group["id"].as_str().unwrap();

    let role = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "deployer", "description": "d", "is_global": false }),
        201,
    )
    .await;
    let role_id = role["id"].as_str().unwrap();

    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{role_id}/groups"),
        json!({ "group_id": group_id, "resource_id": resource_id }),
        204,
    )
    .await;

    let body = get_json(&app, &fx, &format!("/api/v1/roles/{role_id}/groups")).await;
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["group"]["id"], json!(group_id));
    assert_eq!(rows[0]["resource_id"], json!(resource_id));
}

/// The listings must not leak a subject that merely shares a role name, nor a
/// group edge into the user listing: `has_role` carries both kinds of edge and
/// only the `in` endpoint tells them apart.
#[actix_rt::test]
async fn role_users_excludes_group_edges_and_role_groups_excludes_user_edges() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let member = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let group = post_json(
        &app,
        &fx,
        "/api/v1/groups",
        json!({ "name": "Mixed", "description": "d" }),
        201,
    )
    .await;
    let group_id = group["id"].as_str().unwrap();

    let role = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "mixed-role", "description": "d", "is_global": true }),
        201,
    )
    .await;
    let role_id = role["id"].as_str().unwrap();

    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{role_id}/users"),
        json!({ "user_id": member }),
        204,
    )
    .await;
    post_json(
        &app,
        &fx,
        &format!("/api/v1/roles/{role_id}/groups"),
        json!({ "group_id": group_id }),
        204,
    )
    .await;

    let users = get_json(&app, &fx, &format!("/api/v1/roles/{role_id}/users")).await;
    let users = users.as_array().unwrap();
    assert_eq!(users.len(), 1, "the group edge must not appear here");
    assert_eq!(users[0]["user"]["id"], json!(member));

    let groups = get_json(&app, &fx, &format!("/api/v1/roles/{role_id}/groups")).await;
    let groups = groups.as_array().unwrap();
    assert_eq!(groups.len(), 1, "the user edge must not appear here");
    assert_eq!(groups[0]["group"]["id"], json!(group_id));
}

#[actix_rt::test]
async fn role_listings_are_empty_for_a_role_nobody_holds() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_user(&db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(&auth, admin, tenant_id, org_id),
    };
    let app = test_app!(db, auth);

    let role = post_json(
        &app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "unheld", "description": "d", "is_global": true }),
        201,
    )
    .await;
    let role_id = role["id"].as_str().unwrap();

    for uri in [
        format!("/api/v1/roles/{role_id}/users"),
        format!("/api/v1/roles/{role_id}/groups"),
    ] {
        let body = get_json(&app, &fx, &uri).await;
        assert!(body.as_array().unwrap().is_empty(), "{uri}");
    }
}

// ---------------------------------------------------------------------------
// T22.11 — `inherit` on a role assignment (DF-021)
//
// `inherit: false` stops a resource-scoped assignment at its resource. Two
// requests would store a flag the engine then ignores, and all three assign
// paths refuse both with 400. Every negative has its I4 twin: a request that
// omits the field, or sends `true`, is today's request.
// ---------------------------------------------------------------------------

/// A resource, a non-global role and a global role, plus one subject of each
/// kind: user, group and service account.
struct InheritFixture {
    fx: Fixture,
    tenant_id: Uuid,
    resource_id: String,
    role_id: String,
    global_role_id: String,
    member: Uuid,
    group_id: String,
    service_account_id: String,
}

async fn inherit_fixture(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    org_id: Uuid,
    tenant_id: Uuid,
) -> InheritFixture {
    let admin = create_user(db, tenant_id).await;
    let member = create_user(db, tenant_id).await;
    let fx = Fixture {
        token: mint_token(auth, admin, tenant_id, org_id),
    };
    let id = |v: &Value| v["id"].as_str().unwrap().to_owned();
    let resource_id = id(&post_json(
        app,
        &fx,
        "/api/v1/resources",
        json!({ "name": "fleet", "resource_type": "fleet" }),
        201,
    )
    .await);
    let role_id = id(&post_json(
        app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "fleet-reader", "description": "d", "is_global": false }),
        201,
    )
    .await);
    let global_role_id = id(&post_json(
        app,
        &fx,
        "/api/v1/roles",
        json!({ "name": "auditor", "description": "d", "is_global": true }),
        201,
    )
    .await);
    let group_id = id(&post_json(
        app,
        &fx,
        "/api/v1/groups",
        json!({ "name": "Fleet ops", "description": "d" }),
        201,
    )
    .await);
    let service_account_id = id(&post_json(
        app,
        &fx,
        "/api/v1/service-accounts",
        json!({ "name": "fleet-bot" }),
        201,
    )
    .await);
    InheritFixture {
        fx,
        tenant_id,
        resource_id,
        role_id,
        global_role_id,
        member,
        group_id,
        service_account_id,
    }
}

impl InheritFixture {
    /// The three assign routes for `role_id`, each with the body naming its
    /// subject, merged with `extra`.
    fn assign_paths(&self, role_id: &str, extra: &Value) -> Vec<(String, Value)> {
        let with = |mut body: Value| {
            for (k, v) in extra.as_object().unwrap() {
                body[k] = v.clone();
            }
            body
        };
        vec![
            (
                format!("/api/v1/roles/{role_id}/users"),
                with(json!({ "user_id": self.member })),
            ),
            (
                format!("/api/v1/roles/{role_id}/groups"),
                with(json!({ "group_id": self.group_id })),
            ),
            (
                format!("/api/v1/roles/{role_id}/service-accounts"),
                with(json!({ "service_account_id": self.service_account_id })),
            ),
        ]
    }
}

/// `inherit: false` with no `resource_id` is a tenant-wide assignment told to
/// stop at a node it does not have. Refused on every path, and nothing is
/// written.
#[actix_rt::test]
async fn inherit_false_without_a_resource_is_refused_on_every_assign_path() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let f = inherit_fixture(&app, &db, &auth, org_id, tenant_id).await;

    for (uri, body) in f.assign_paths(&f.role_id, &json!({ "inherit": false })) {
        let err = post_json(&app, &f.fx, &uri, body, 400).await;
        assert!(
            err.to_string().contains("inherit"),
            "the refusal must name the field: {uri}"
        );
    }
    for listing in ["users", "groups", "service-accounts"] {
        let rows = get_json(
            &app,
            &f.fx,
            &format!("/api/v1/roles/{}/{listing}", f.role_id),
        )
        .await;
        assert!(
            rows.as_array().unwrap().is_empty(),
            "a refused assignment must not be written ({listing})"
        );
    }
}

/// `inherit: false` on a global role would be stored and then ignored — a
/// global role applies everywhere. Refused on every path, even with a
/// resource named.
#[actix_rt::test]
async fn inherit_false_on_a_global_role_is_refused_on_every_assign_path() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let f = inherit_fixture(&app, &db, &auth, org_id, tenant_id).await;

    let extra = json!({ "resource_id": f.resource_id, "inherit": false });
    for (uri, body) in f.assign_paths(&f.global_role_id, &extra) {
        let err = post_json(&app, &f.fx, &uri, body, 400).await;
        assert!(
            err.to_string().contains("global"),
            "the refusal must say why: {uri}"
        );
    }
}

/// The I4 twin of both refusals: without the field — and with an explicit
/// `true` — every assignment the two tests above refuse is accepted exactly as
/// before, and reads back as inheritable.
#[actix_rt::test]
async fn an_assignment_without_the_field_inherits() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let f = inherit_fixture(&app, &db, &auth, org_id, tenant_id).await;

    // Tenant-wide, field omitted.
    for (uri, body) in f.assign_paths(&f.role_id, &json!({})) {
        post_json(&app, &f.fx, &uri, body, 204).await;
    }
    // A global role at a resource, `inherit: true` spelled out.
    let extra = json!({ "resource_id": f.resource_id, "inherit": true });
    for (uri, body) in f.assign_paths(&f.global_role_id, &extra) {
        post_json(&app, &f.fx, &uri, body, 204).await;
    }

    for role_id in [&f.role_id, &f.global_role_id] {
        for listing in ["users", "groups", "service-accounts"] {
            let rows = get_json(&app, &f.fx, &format!("/api/v1/roles/{role_id}/{listing}")).await;
            let rows = rows.as_array().unwrap();
            assert_eq!(rows.len(), 1, "{listing}");
            assert_eq!(rows[0]["inherit"], json!(true), "{listing}");
        }
    }
    let rows = get_json(&app, &f.fx, &format!("/api/v1/users/{}/roles", f.member)).await;
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|r| r["inherit"] == json!(true)),
        "every assignment written without the flag reads back as inheritable"
    );
}

/// `inherit: false` at a resource, on an ordinary role, is accepted on every
/// path and read back by every listing that shows an assignment.
#[actix_rt::test]
async fn a_non_inheritable_assignment_is_accepted_and_listed_on_every_path() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);
    let f = inherit_fixture(&app, &db, &auth, org_id, tenant_id).await;

    let extra = json!({ "resource_id": f.resource_id, "inherit": false });
    for (uri, body) in f.assign_paths(&f.role_id, &extra) {
        post_json(&app, &f.fx, &uri, body, 204).await;
    }

    for listing in ["users", "groups", "service-accounts"] {
        let rows = get_json(
            &app,
            &f.fx,
            &format!("/api/v1/roles/{}/{listing}", f.role_id),
        )
        .await;
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 1, "{listing}");
        assert_eq!(rows[0]["resource_id"], json!(f.resource_id), "{listing}");
        assert_eq!(rows[0]["inherit"], json!(false), "{listing}");
    }
    // Labelled by a static name, not the URI: the URI carries the service
    // account's id, which CodeQL reads as sensitive once it reaches a message.
    for (label, uri) in [
        ("users", format!("/api/v1/users/{}/roles", f.member)),
        ("groups", format!("/api/v1/groups/{}/roles", f.group_id)),
        (
            "service-accounts",
            format!("/api/v1/service-accounts/{}/roles", f.service_account_id),
        ),
    ] {
        let rows = get_json(&app, &f.fx, &uri).await;
        let rows = rows.as_array().unwrap();
        assert!(!rows.is_empty(), "{label}");
        assert!(
            rows.iter().all(|r| r["inherit"] == json!(false)),
            "{label} must show the flag"
        );
    }
}

/// An `AuthzChecker` that allows everything and records every invalidation, so
/// a test can see what the handlers flush.
#[derive(Default)]
struct RecordingAuthzChecker {
    subjects: std::sync::Mutex<Vec<(Uuid, Uuid)>>,
    tenants: std::sync::Mutex<Vec<Uuid>>,
}

impl AuthzChecker for RecordingAuthzChecker {
    fn check_access<'a>(
        &'a self,
        _request: &'a axiam_authz::AccessRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = axiam_core::error::AxiamResult<axiam_authz::AccessDecision>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Ok(axiam_authz::AccessDecision::Allow) })
    }

    fn invalidate_tenant<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = axiam_core::error::AxiamResult<()>> + Send + 'a>,
    > {
        self.tenants.lock().unwrap().push(tenant_id);
        Box::pin(async { Ok(()) })
    }

    fn invalidate_subject<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = axiam_core::error::AxiamResult<()>> + Send + 'a>,
    > {
        self.subjects.lock().unwrap().push((tenant_id, subject_id));
        Box::pin(async { Ok(()) })
    }
}

/// Changing the flag is unassign-then-assign: `has_role` is `UNIQUE(in, out)`,
/// so re-assigning with the other value is a 409, not an update. Both halves of
/// the change flush the subject's cached decisions. The flag moves access in
/// both directions — `false` on an allow narrows it, `false` on a deny widens it
/// (§2.2 row 10) — and a cached allow that outlived a narrowing change would be
/// a stale grant.
#[actix_rt::test]
async fn changing_the_flag_is_unassign_then_assign_and_both_invalidate() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let recorder = Arc::new(RecordingAuthzChecker::default());
    let app = test_app!(db, auth, recorder.clone());
    let f = inherit_fixture(&app, &db, &auth, org_id, tenant_id).await;
    let (role_id, member) = (&f.role_id, f.member);
    let users = format!("/api/v1/roles/{role_id}/users");

    post_json(
        &app,
        &f.fx,
        &users,
        json!({ "user_id": member, "resource_id": f.resource_id }),
        204,
    )
    .await;
    post_json(
        &app,
        &f.fx,
        &users,
        json!({ "user_id": member, "resource_id": f.resource_id, "inherit": false }),
        409,
    )
    .await;
    let rows = get_json(&app, &f.fx, &users).await;
    assert_eq!(rows[0]["inherit"], json!(true), "a 409 must change nothing");

    recorder.subjects.lock().unwrap().clear();
    let (h, v) = f.fx.bearer();
    let req = with_csrf(test::TestRequest::delete())
        .uri(&format!(
            "/api/v1/roles/{role_id}/users/{member}?resource_id={}",
            f.resource_id
        ))
        .insert_header((h, v))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);
    post_json(
        &app,
        &f.fx,
        &users,
        json!({ "user_id": member, "resource_id": f.resource_id, "inherit": false }),
        204,
    )
    .await;

    let rows = get_json(&app, &f.fx, &users).await;
    assert_eq!(rows[0]["inherit"], json!(false));
    assert_eq!(
        *recorder.subjects.lock().unwrap(),
        [(f.tenant_id, member), (f.tenant_id, member)],
        "the unassign and the assign must each flush the subject's decisions"
    );
}

//! SCIM integration tests: Okta/Entra contract fixtures, PATCH wiring, and
//! (the security-critical half) adversarial tenant isolation.
//!
//! Fixtures under `tests/fixtures/{okta,entra}/` are **hand-constructed**
//! from each vendor's published SCIM documentation and RFC 7644's own
//! examples — this sandbox has no network access to Okta or Entra, so
//! nothing here was captured from real traffic. See
//! `tests/fixtures/README.md` and `docs/api/scim-provisioning.md`'s
//! "Fixtures are hand-constructed, not captured" section for the same
//! disclosure. The PATCH-op **parsing** matrix (every supported path ×
//! add/replace/remove) lives as unit tests in `src/patch.rs` — this file
//! proves the HTTP wiring, not the full combinatorial matrix again.

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, PermissionRepository, RoleRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

// ---------------------------------------------------------------------------
// Fixture loading
// ---------------------------------------------------------------------------

fn fixture(path: &str) -> Value {
    let full = format!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/{}"),
        path
    );
    let raw = std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("read fixture {full}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse fixture {full}: {e}"))
}

/// Fixtures that reference a not-yet-known member id carry the literal
/// placeholder `__MEMBER_ID__` (in a `path` string) — substitute it with a
/// real id generated during the test.
fn substitute_member_id(mut value: Value, member_id: Uuid) -> Value {
    if let Some(ops) = value.get_mut("Operations").and_then(|o| o.as_array_mut()) {
        for op in ops {
            if let Some(path) = op
                .get_mut("path")
                .and_then(|p| p.as_str().map(str::to_owned))
            {
                op["path"] = json!(path.replace("__MEMBER_ID__", &member_id.to_string()));
            }
            if let Some(values) = op.get_mut("value").and_then(|v| v.as_array_mut()) {
                for entry in values {
                    if entry.get("value").and_then(|v| v.as_str()) == Some("__MEMBER_ID__") {
                        entry["value"] = json!(member_id.to_string());
                    }
                }
            }
        }
    }
    value
}

// ---------------------------------------------------------------------------
// Fixture setup (mirrors axiam-api-rest/tests/rbac_test.rs exactly)
// ---------------------------------------------------------------------------

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

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
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

/// Fresh in-memory DB with an org + tenant + the default permission
/// registry/roles seeded — the SAME registry `scim:provision` is declared
/// in (`axiam_api_rest::permissions::PERMISSION_REGISTRY`), so
/// `seed_default_roles` grants it to `admin`/`super-admin` automatically.
async fn setup_tenant() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: format!("tenant-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();

    seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

/// Create an active user and assign them the tenant's `admin` role (which
/// carries `scim:provision`, per `seed_default_roles`). This is the
/// "SCIM-provisioner bearer principal" the provisioning guide describes —
/// see `crates/axiam-scim/src/auth.rs`'s module docs for why it's a user,
/// not a `service_account`.
async fn scim_admin_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    create_user_with_role(db, tenant_id, "admin").await
}

/// Create an active user with the `viewer` role — a valid, well-formed
/// AXIAM principal for this tenant, but one that does NOT carry
/// `scim:provision` (`viewer` only gets `:list`/`:get` actions).
async fn scim_unprivileged_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    create_user_with_role(db, tenant_id, "viewer").await
}

async fn create_user_with_role(db: &Surreal<TestDb>, tenant_id: Uuid, role_name: &str) -> Uuid {
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: format!("bearer-{}", Uuid::new_v4().simple()),
            email: format!("bearer-{}@example.com", Uuid::new_v4().simple()),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
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
        .find(|r| r.name == role_name)
        .unwrap_or_else(|| panic!("default role `{role_name}` not seeded"));
    role_repo
        .assign_to_user(tenant_id, user.id, role.id, None)
        .await
        .unwrap();

    user.id
}

/// A minimal role holding ONLY `scim:provision` — proves the permission is
/// independently sufficient, not merely riding along on `admin`.
async fn least_privilege_scim_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: format!("scim-only-{}", Uuid::new_v4().simple()),
            description: "SCIM provisioning only".into(),
            is_global: true,
        })
        .await
        .unwrap();

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
    let scim_perm = perms
        .items
        .into_iter()
        .find(|p| p.action == "scim:provision")
        .expect("scim:provision must be seeded from PERMISSION_REGISTRY");
    perm_repo
        .grant_to_role(tenant_id, role.id, scim_perm.id)
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: format!("scim-only-{}", Uuid::new_v4().simple()),
            email: format!("scim-only-{}@example.com", Uuid::new_v4().simple()),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    role_repo
        .assign_to_user(tenant_id, user.id, role.id, None)
        .await
        .unwrap();
    user.id
}

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
                .configure(axiam_scim::scim_routes::<TestDb>),
        )
        .await
    };
}

fn bearer(token: &str) -> (&'static str, String) {
    ("Authorization", format!("Bearer {token}"))
}

/// Every request in this file carries a peer address (R5.2).
///
/// `/scim/v2` is now wrapped in the same IP-keyed rate limiters every other
/// AXIAM family uses, and `XForwardedForKeyExtractor` rejects a request it
/// cannot key — a real connection always has a peer address, so a
/// `TestRequest` without one is the unrealistic case, not the limiter. The
/// shipped 600/min ceiling is far above anything this file drives, and each
/// test builds its own app (hence its own governor store and its own shared
/// counter), so the limiter never influences a contract assertion.
/// Enforcement itself is proven in `tests/scim_rate_limit_test.rs`.
fn bench_peer() -> std::net::SocketAddr {
    "203.0.113.7:5000".parse().expect("valid test peer address")
}

// ---------------------------------------------------------------------------
// Okta contract fixtures
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn okta_create_user_fixture_provisions_a_user() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    let body = fixture("okta/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        201,
        "Okta create-user fixture must provision"
    );

    let created: Value = test::read_body_json(resp).await;
    assert_eq!(created["userName"], "jsmith@example.com");
    assert_eq!(created["externalId"], "00u1a2b3c4d5e6f7g8h9");
    assert_eq!(created["name"]["givenName"], "Jane");
    assert_eq!(created["active"], true);
    assert_eq!(created["emails"][0]["value"], "jsmith@example.com");
    assert!(created["id"].as_str().is_some());
    assert_eq!(
        created["schemas"][0],
        "urn:ietf:params:scim:schemas:core:2.0:User"
    );

    // Round-trips via GET.
    let id = created["id"].as_str().unwrap();
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{id}"))
        .insert_header(bearer(&token))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

#[actix_rt::test]
async fn okta_patch_deactivate_user_fixture() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    let create_body = fixture("okta/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .set_json(&create_body)
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["active"], true);

    let patch_body = fixture("okta/patch_deactivate_user.json");
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{id}"))
        .insert_header(bearer(&token))
        .set_json(&patch_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Okta deactivate PATCH must succeed"
    );
    let patched: Value = test::read_body_json(resp).await;
    assert_eq!(
        patched["active"], false,
        "Okta's replace/active/false must deactivate"
    );

    // The underlying AXIAM user really is Inactive, not just the SCIM view.
    let user_repo = SurrealUserRepository::new(db.clone());
    let stored = user_repo
        .get_by_id(tenant_id, Uuid::parse_str(&id).unwrap())
        .await
        .unwrap();
    assert_eq!(stored.status, UserStatus::Inactive);
}

#[actix_rt::test]
async fn okta_group_add_then_remove_member_fixture() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    // A member to add/remove.
    let member_body = fixture("okta/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .set_json(&member_body)
        .to_request();
    let member: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let member_id = Uuid::parse_str(member["id"].as_str().unwrap()).unwrap();

    let group_body = fixture("okta/create_group.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Groups")
        .insert_header(bearer(&token))
        .set_json(&group_body)
        .to_request();
    let group: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let group_id = group["id"].as_str().unwrap().to_string();
    assert_eq!(group["displayName"], "Engineering");

    let add_body = substitute_member_id(fixture("okta/patch_group_add_member.json"), member_id);
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group_id}"))
        .insert_header(bearer(&token))
        .set_json(&add_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let after_add: Value = test::read_body_json(resp).await;
    assert_eq!(after_add["members"].as_array().unwrap().len(), 1);
    assert_eq!(after_add["members"][0]["value"], member_id.to_string());

    // Okta's single-member removal: `members[value eq "<uuid>"]`, remove.
    let remove_body =
        substitute_member_id(fixture("okta/patch_group_remove_member.json"), member_id);
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group_id}"))
        .insert_header(bearer(&token))
        .set_json(&remove_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let after_remove: Value = test::read_body_json(resp).await;
    // `members` is `skip_serializing_if = "Vec::is_empty"` — an empty
    // membership renders as a MISSING key, not `"members": []`.
    assert!(
        after_remove
            .get("members")
            .and_then(|m| m.as_array())
            .map(|a| a.is_empty())
            .unwrap_or(true),
        "expected no members left, got: {after_remove:?}"
    );
}

// ---------------------------------------------------------------------------
// Entra contract fixtures
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn entra_create_user_fixture_provisions_a_user() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    let body = fixture("entra/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        201,
        "Entra create-user fixture must provision"
    );
    let created: Value = test::read_body_json(resp).await;
    assert_eq!(created["userName"], "AdeleV@example.com");
    assert_eq!(created["name"]["familyName"], "Vance");
    assert_eq!(
        created["externalId"],
        "a1b2c3d4-e5f6-4a1b-9c2d-3e4f5a6b7c8d"
    );
}

#[actix_rt::test]
async fn entra_patch_deactivate_user_pathless_fixture() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    let create_body = fixture("entra/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .set_json(&create_body)
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();

    // Entra's path-less shape: {"op":"replace","value":{"active":false}}.
    let patch_body = fixture("entra/patch_deactivate_user.json");
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{id}"))
        .insert_header(bearer(&token))
        .set_json(&patch_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Entra path-less deactivate PATCH must succeed"
    );
    let patched: Value = test::read_body_json(resp).await;
    assert_eq!(patched["active"], false);
}

#[actix_rt::test]
async fn entra_patch_update_name_fixture() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    let create_body = fixture("entra/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .set_json(&create_body)
        .to_request();
    let created: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let id = created["id"].as_str().unwrap().to_string();

    let patch_body = fixture("entra/patch_update_name.json");
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{id}"))
        .insert_header(bearer(&token))
        .set_json(&patch_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let patched: Value = test::read_body_json(resp).await;
    assert_eq!(patched["name"]["familyName"], "Vance-Smith");
    // givenName must be untouched by a familyName-only PATCH.
    assert_eq!(patched["name"]["givenName"], "Adele");
}

#[actix_rt::test]
async fn entra_group_add_member_fixture() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    let member_body = fixture("entra/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .set_json(&member_body)
        .to_request();
    let member: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let member_id = Uuid::parse_str(member["id"].as_str().unwrap()).unwrap();

    let group_body = fixture("entra/create_group.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Groups")
        .insert_header(bearer(&token))
        .set_json(&group_body)
        .to_request();
    let group: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let group_id = group["id"].as_str().unwrap().to_string();

    let add_body = substitute_member_id(fixture("entra/patch_group_add_member.json"), member_id);
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group_id}"))
        .insert_header(bearer(&token))
        .set_json(&add_body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let after_add: Value = test::read_body_json(resp).await;
    assert_eq!(after_add["members"][0]["value"], member_id.to_string());
}

// ---------------------------------------------------------------------------
// Discovery endpoints
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn discovery_endpoints_require_a_credential_but_not_a_permission() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    // No Authorization header at all -> 401 (AuthzMiddleware, same as every
    // other /scim/v2 route).
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri("/scim/v2/ServiceProviderConfig")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);

    // An unprivileged (no scim:provision) but otherwise valid token DOES
    // reach the discovery endpoints — they carry no tenant data and no
    // handler-level RequirePermission check gates them.
    let unprivileged = scim_unprivileged_user(&db, tenant_id).await;
    let token = mint_token(&auth, unprivileged, tenant_id, org_id);
    for path in [
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/ResourceTypes",
        "/scim/v2/Schemas",
    ] {
        let req = test::TestRequest::get()
            .peer_addr(bench_peer())
            .uri(path)
            .insert_header(bearer(&token))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "path={path}");
    }
}

#[actix_rt::test]
async fn bulk_returns_correct_scim_error() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user, tenant_id, org_id);

    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Bulk")
        .insert_header(bearer(&token))
        .set_json(json!({"Operations": []}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 501);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    assert_eq!(body["status"], "501");
}

#[actix_rt::test]
async fn complex_filter_returns_invalid_filter_error() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user, tenant_id, org_id);

    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri(
            "/scim/v2/Users?filter=emails%5Btype%20eq%20%22work%22%5D.value%20eq%20%22x%40y.com%22",
        )
        .insert_header(bearer(&token))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["scimType"], "invalidFilter");
}

// ---------------------------------------------------------------------------
// Dedicated-permission enforcement
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn unprivileged_tenant_user_is_forbidden_on_every_verb() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    // A real, valid, correctly-scoped AXIAM token — just without
    // scim:provision. Proves the permission gate is load-bearing, not
    // "any authenticated tenant user can provision."
    let viewer = scim_unprivileged_user(&db, tenant_id).await;
    let token = mint_token(&auth, viewer, tenant_id, org_id);

    for (method, uri) in [
        ("GET", "/scim/v2/Users"),
        ("POST", "/scim/v2/Users"),
        ("GET", "/scim/v2/Groups"),
        ("POST", "/scim/v2/Groups"),
    ] {
        let req = test::TestRequest::default()
            .peer_addr(bench_peer())
            .method(method.parse().unwrap())
            .uri(uri)
            .insert_header(bearer(&token))
            .set_json(json!({"userName":"x","displayName":"x","emails":[{"value":"x@y.com"}]}))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status().as_u16(), 403, "method={method} uri={uri}");
    }
}

#[actix_rt::test]
async fn least_privilege_scim_only_role_is_sufficient() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    // A role with ONLY scim:provision (no other permission at all) — proves
    // the dedicated permission is independently sufficient, mirroring the
    // "least privilege" setup the provisioning guide recommends.
    let bearer_user = least_privilege_scim_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// Tenant isolation — adversarial (the security-critical tests)
// ---------------------------------------------------------------------------

/// A SCIM token issued for tenant A must not be able to READ tenant B's
/// user by id — not "denied", genuinely `404` (no cross-tenant existence
/// oracle either).
#[actix_rt::test]
async fn cross_tenant_get_user_is_not_found() {
    let (db, org_a, tenant_a) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    // Tenant B lives in the SAME db instance (shared SurrealDB, isolated by
    // tenant_id column/predicate — exactly the production topology).
    let org_b = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: format!("org-b-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "Tenant B".into(),
            slug: format!("tenant-b-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    seed_permissions(&db, tenant_b.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant_b.id, PERMISSION_REGISTRY)
        .await
        .unwrap();

    // A user provisioned in tenant B.
    let bearer_b_user = scim_admin_user(&db, tenant_b.id).await;
    let token_b = mint_token(&auth, bearer_b_user, tenant_b.id, org_b.id);
    let create_body = fixture("okta/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token_b))
        .set_json(&create_body)
        .to_request();
    let victim: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let victim_id = victim["id"].as_str().unwrap().to_string();

    // Tenant A's SCIM token tries to read it directly by id.
    let bearer_a_user = scim_admin_user(&db, tenant_a).await;
    let token_a = mint_token(&auth, bearer_a_user, tenant_a, org_a);
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{victim_id}"))
        .insert_header(bearer(&token_a))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "tenant A must not be able to read tenant B's user"
    );

    // ... nor PUT ...
    let req = test::TestRequest::put()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{victim_id}"))
        .insert_header(bearer(&token_a))
        .set_json(json!({"userName":"hijacked","emails":[{"value":"h@x.com"}]}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "tenant A must not be able to PUT tenant B's user"
    );

    // ... nor PATCH ...
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{victim_id}"))
        .insert_header(bearer(&token_a))
        .set_json(json!({"Operations":[{"op":"replace","path":"active","value":false}]}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "tenant A must not be able to PATCH tenant B's user"
    );

    // ... nor DELETE.
    let req = test::TestRequest::delete()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{victim_id}"))
        .insert_header(bearer(&token_a))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "tenant A must not be able to DELETE tenant B's user"
    );

    // The victim is provably untouched: tenant B's own token still sees it,
    // active and unmodified.
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{victim_id}"))
        .insert_header(bearer(&token_b))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let still_there: Value = test::read_body_json(resp).await;
    assert_eq!(still_there["userName"], "jsmith@example.com");
    assert_eq!(still_there["active"], true);
}

/// The same battery against `/Groups`, plus membership: tenant A must not
/// be able to add/remove members of tenant B's group.
#[actix_rt::test]
async fn cross_tenant_group_mutation_is_not_found() {
    let (db, org_a, tenant_a) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let org_b = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: format!("org-b-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "Tenant B".into(),
            slug: format!("tenant-b-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    seed_permissions(&db, tenant_b.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant_b.id, PERMISSION_REGISTRY)
        .await
        .unwrap();

    let bearer_b = scim_admin_user(&db, tenant_b.id).await;
    let token_b = mint_token(&auth, bearer_b, tenant_b.id, org_b.id);
    let group_body = fixture("okta/create_group.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Groups")
        .insert_header(bearer(&token_b))
        .set_json(&group_body)
        .to_request();
    let victim_group: Value = test::read_body_json(test::call_service(&app, req).await).await;
    let victim_group_id = victim_group["id"].as_str().unwrap().to_string();

    let bearer_a = scim_admin_user(&db, tenant_a).await;
    let token_a = mint_token(&auth, bearer_a, tenant_a, org_a);

    for (method, body) in [
        ("GET", None),
        ("PUT", Some(json!({"displayName":"hijacked"}))),
        (
            "PATCH",
            Some(json!({"Operations":[{"op":"replace","path":"displayName","value":"hijacked"}]})),
        ),
        ("DELETE", None),
    ] {
        let mut builder = test::TestRequest::default()
            .peer_addr(bench_peer())
            .method(method.parse().unwrap())
            .uri(&format!("/scim/v2/Groups/{victim_group_id}"))
            .insert_header(bearer(&token_a));
        if let Some(b) = &body {
            builder = builder.set_json(b);
        }
        let resp = test::call_service(&app, builder.to_request()).await;
        assert_eq!(resp.status().as_u16(), 404, "method={method}");
    }

    // Group genuinely untouched — tenant B still sees its original name.
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{victim_group_id}"))
        .insert_header(bearer(&token_b))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let still_there: Value = test::read_body_json(resp).await;
    assert_eq!(still_there["displayName"], "Engineering");
}

/// A tenant's `GET /Users` listing (unfiltered, `userName eq`, and
/// `externalId eq`) must never surface another tenant's rows.
#[actix_rt::test]
async fn cross_tenant_list_and_filter_never_leak() {
    let (db, org_a, tenant_a) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let org_b = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: format!("org-b-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_b.id,
            name: "Tenant B".into(),
            slug: format!("tenant-b-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    seed_permissions(&db, tenant_b.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant_b.id, PERMISSION_REGISTRY)
        .await
        .unwrap();

    // Same userName/externalId in BOTH tenants — the adversarial case: if
    // tenant scoping were even slightly wrong, a same-named row from the
    // other tenant would satisfy the filter.
    let bearer_b = scim_admin_user(&db, tenant_b.id).await;
    let token_b = mint_token(&auth, bearer_b, tenant_b.id, org_b.id);
    let body = fixture("okta/create_user.json");
    let req = test::TestRequest::post()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token_b))
        .set_json(&body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let bearer_a = scim_admin_user(&db, tenant_a).await;
    let token_a = mint_token(&auth, bearer_a, tenant_a, org_a);

    // Unfiltered list from tenant A: only the bearer-provisioning admin
    // user itself (created by `scim_admin_user`) — never tenant B's user.
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users")
        .insert_header(bearer(&token_a))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let list: Value = test::read_body_json(resp).await;
    let names: Vec<&str> = list["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["userName"].as_str().unwrap())
        .collect();
    assert!(
        !names.contains(&"jsmith@example.com"),
        "tenant A's list leaked tenant B's user: {names:?}"
    );

    // userName-filtered list from tenant A for tenant B's exact username.
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users?filter=userName%20eq%20%22jsmith%40example.com%22")
        .insert_header(bearer(&token_a))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let list: Value = test::read_body_json(resp).await;
    assert_eq!(
        list["totalResults"], 0,
        "tenant A must not find tenant B's user by userName"
    );
    assert!(list["Resources"].as_array().unwrap().is_empty());

    // externalId-filtered list from tenant A for tenant B's exact externalId.
    let req = test::TestRequest::get()
        .peer_addr(bench_peer())
        .uri("/scim/v2/Users?filter=externalId%20eq%20%2200u1a2b3c4d5e6f7g8h9%22")
        .insert_header(bearer(&token_a))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let list: Value = test::read_body_json(resp).await;
    assert_eq!(
        list["totalResults"], 0,
        "tenant A must not find tenant B's user by externalId"
    );
}

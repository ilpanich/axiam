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
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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
            kind: TenantKind::Standard,
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
                search: None,
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
                search: None,
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
            kind: TenantKind::Standard,
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
            kind: TenantKind::Standard,
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
            kind: TenantKind::Standard,
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

// ---------------------------------------------------------------------------
// Group collection + full-replace surface
//
// `GET /Groups` had no test at all — neither the unfiltered branch nor the
// `externalId eq` one — and `PUT /Groups/{id}`, whose whole job is to compute
// a membership add/remove diff against the current set, was reached only
// through `create`. These drive the handlers an IdP's group-push actually
// uses.
// ---------------------------------------------------------------------------

/// Create a group through the API and return its id.
///
/// A macro rather than a function for the same reason `test_app!` is one: the
/// service type `test::init_service` returns is unnameable here without
/// pulling `actix-http` in as a dev-dependency just to spell one bound.
macro_rules! make_group {
    ($app:expr, $token:expr, $display_name:expr, $external_id:expr, $members:expr) => {{
        let mut body = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": $display_name,
            "members": $members
                .iter()
                .map(|m: &Uuid| json!({ "value": m.to_string() }))
                .collect::<Vec<_>>(),
        });
        let ext: Option<&str> = $external_id;
        if let Some(ext) = ext {
            body["externalId"] = json!(ext);
        }
        let req = test::TestRequest::post()
            .peer_addr(bench_peer())
            .uri("/scim/v2/Groups")
            .insert_header(bearer($token))
            .set_json(&body)
            .to_request();
        let resp = test::call_service($app, req).await;
        assert_eq!(resp.status().as_u16(), 201, "group create must succeed");
        let created: Value = test::read_body_json(resp).await;
        Uuid::parse_str(created["id"].as_str().unwrap()).unwrap()
    }};
}

/// Create a SCIM user through the API and return its id.
macro_rules! make_user {
    ($app:expr, $token:expr, $user_name:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(bench_peer())
            .uri("/scim/v2/Users")
            .insert_header(bearer($token))
            .set_json(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": $user_name,
                "emails": [{
                    "value": format!("{}@example.com", $user_name),
                    "primary": true,
                }],
            }))
            .to_request();
        let resp = test::call_service($app, req).await;
        assert_eq!(resp.status().as_u16(), 201, "user create must succeed");
        let created: Value = test::read_body_json(resp).await;
        Uuid::parse_str(created["id"].as_str().unwrap()).unwrap()
    }};
}

/// Assert a group resource carries no members.
///
/// `ScimGroup::members` is `skip_serializing_if = "Vec::is_empty"`, so an empty
/// membership is spelled by *omitting* the key, not by sending `[]` — which is
/// what RFC 7644 §3.4.1 asks for ("unassigned attributes SHALL be omitted").
/// Accept either spelling so the assertion pins the meaning rather than the
/// encoding.
macro_rules! assert_no_members {
    ($group:expr, $what:expr) => {{
        let members = $group.get("members");
        assert!(
            members.is_none_or(|m| m.as_array().is_some_and(|a| a.is_empty())),
            "{} must leave the group with no members, got {:?}",
            $what,
            members
        );
    }};
}

/// `GET` a SCIM URI, returning the status and decoded body together.
macro_rules! get_json {
    ($app:expr, $token:expr, $uri:expr) => {{
        let req = test::TestRequest::get()
            .peer_addr(bench_peer())
            .uri($uri)
            .insert_header(bearer($token))
            .to_request();
        let resp = test::call_service($app, req).await;
        let status = resp.status().as_u16();
        let body: Value = test::read_body_json(resp).await;
        (status, body)
    }};
}

#[actix_rt::test]
async fn group_list_embeds_members_and_pages() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let alice = make_user!(&app, &token, "alice");
    make_group!(&app, &token, "Engineering", Some("ext-eng"), &[alice]);
    make_group!(&app, &token, "Sales", Some("ext-sales"), &[]);

    let (status, list) = get_json!(&app, &token, "/scim/v2/Groups");
    assert_eq!(status, 200);
    assert_eq!(list["totalResults"], 2);
    assert_eq!(
        list["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );

    // The members embed is what makes this handler more than a table dump:
    // each group carries its resolved membership, not just ids.
    let eng = list["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["displayName"] == "Engineering")
        .expect("Engineering must be listed");
    assert_eq!(eng["members"][0]["value"], alice.to_string());
    assert_eq!(eng["members"][0]["display"], "alice");
    assert_eq!(eng["members"][0]["type"], "User");

    let sales = list["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["displayName"] == "Sales")
        .expect("Sales must be listed");
    assert_no_members!(sales, "a group created with no members");

    // startIndex is 1-based (RFC 7644 §3.4.2.4) and is echoed back as sent.
    let (_, page) = get_json!(&app, &token, "/scim/v2/Groups?startIndex=2&count=1");
    assert_eq!(page["startIndex"], 2);
    assert_eq!(page["itemsPerPage"], 1);
    assert_eq!(
        page["totalResults"], 2,
        "totalResults counts the whole collection, not the page"
    );
}

#[actix_rt::test]
async fn group_list_filters_by_external_id() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let wanted = make_group!(&app, &token, "Engineering", Some("ext-eng"), &[]);
    make_group!(&app, &token, "Sales", Some("ext-sales"), &[]);

    let (status, list) = get_json!(
        &app,
        &token,
        "/scim/v2/Groups?filter=externalId%20eq%20%22ext-eng%22"
    );
    assert_eq!(status, 200);
    assert_eq!(list["totalResults"], 1);
    assert_eq!(list["Resources"][0]["id"], wanted.to_string());

    // A filter that matches nothing is an empty 200, not a 404 — RFC 7644
    // §3.4.2: a query returning no results is still a successful query.
    let (status, empty) = get_json!(
        &app,
        &token,
        "/scim/v2/Groups?filter=externalId%20eq%20%22nobody%22"
    );
    assert_eq!(status, 200);
    assert_eq!(empty["totalResults"], 0);
    assert!(empty["Resources"].as_array().unwrap().is_empty());

    // `displayName eq` is a User-only attribute here: Groups accept only
    // `externalId`, and anything else is a 400 rather than a silent full scan.
    let (status, err) = get_json!(
        &app,
        &token,
        "/scim/v2/Groups?filter=displayName%20eq%20%22Engineering%22"
    );
    assert_eq!(status, 400);
    assert_eq!(err["scimType"], "invalidFilter");
}

#[actix_rt::test]
async fn group_put_replaces_membership_as_a_diff() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let stays = make_user!(&app, &token, "stays");
    let leaves = make_user!(&app, &token, "leaves");
    let joins = make_user!(&app, &token, "joins");
    let group = make_group!(
        &app,
        &token,
        "Engineering",
        Some("ext-eng"),
        &[stays, leaves]
    );

    // PUT is a *full* replace of membership: `stays` is in both sets and must
    // survive untouched, `leaves` is dropped, `joins` is added. Asserting all
    // three at once is what distinguishes a real diff from a clear-then-add.
    let req = test::TestRequest::put()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering Renamed",
            "externalId": "ext-eng-2",
            "members": [
                { "value": stays.to_string() },
                { "value": joins.to_string() },
            ],
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;

    assert_eq!(body["displayName"], "Engineering Renamed");
    assert_eq!(body["externalId"], "ext-eng-2");

    let members: std::collections::HashSet<String> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["value"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        members,
        [stays.to_string(), joins.to_string()].into_iter().collect(),
        "PUT membership must be exactly the requested set"
    );
}

#[actix_rt::test]
async fn group_put_with_empty_members_clears_the_group() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let member = make_user!(&app, &token, "member");
    let group = make_group!(&app, &token, "Engineering", None, &[member]);

    // The removal side of the diff on its own. An empty `members` array is a
    // legitimate instruction ("this group has nobody in it"), distinct from
    // omitting the attribute, and it is the shape an IdP sends when the last
    // person leaves a group.
    let req = test::TestRequest::put()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Engineering",
            "members": [],
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_no_members!(body, "a PUT with an empty members array");

    let (_, refetched) = get_json!(&app, &token, &format!("/scim/v2/Groups/{group}"));
    assert_no_members!(
        refetched,
        "the clear must be durable, not just reflected in the PUT response —"
    );
}

#[actix_rt::test]
async fn group_patch_replace_members_is_clear_then_add() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let old = make_user!(&app, &token, "old");
    let new = make_user!(&app, &token, "new");
    let group = make_group!(&app, &token, "Engineering", None, &[old]);

    // `replace` on the whole `members` attribute means "the set is now exactly
    // this", which `parse_group_patch` lowers to RemoveAll + Add. The
    // RemoveAll arm re-reads the current membership to remove it, and was the
    // one member action with no test.
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "members",
                "value": [{ "value": new.to_string() }],
            }],
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;

    let members: Vec<&str> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["value"].as_str().unwrap())
        .collect();
    assert_eq!(members, vec![new.to_string().as_str()]);
}

#[actix_rt::test]
async fn group_patch_remove_all_members_empties_the_group() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let a = make_user!(&app, &token, "a");
    let b = make_user!(&app, &token, "b");
    let group = make_group!(&app, &token, "Engineering", None, &[a, b]);

    // `remove` on `members` with no value filter — RFC 7644 §3.5.2.2's "clear
    // every value of a multi-valued attribute". Distinct from the single-member
    // `members[value eq "..."]` removal the Okta fixture already covers.
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:PatchOp"],
            "Operations": [{ "op": "remove", "path": "members" }],
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_no_members!(body, "a `remove` on the whole members attribute");
}

#[actix_rt::test]
async fn group_patch_renames_and_sets_external_id() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let group = make_group!(&app, &token, "Engineering", None, &[]);

    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:PatchOp"],
            "Operations": [
                { "op": "replace", "path": "displayName", "value": "Platform" },
                { "op": "replace", "path": "externalId", "value": "ext-platform" },
            ],
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["displayName"], "Platform");
    assert_eq!(body["externalId"], "ext-platform");

    // externalId is stored in `metadata`, so it is the attribute most likely
    // to be lost by a rename that rebuilds the object — check it survives a
    // second, unrelated patch.
    let req = test::TestRequest::patch()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "path": "displayName", "value": "Platform Eng" }],
        }))
        .to_request();
    let body: Value = test::read_body_json(test::call_service(&app, req).await).await;
    assert_eq!(body["displayName"], "Platform Eng");
    assert_eq!(
        body["externalId"], "ext-platform",
        "a displayName-only patch must not drop externalId"
    );
}

#[actix_rt::test]
async fn group_delete_of_an_unknown_id_is_not_found() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    // SEC-104 moved the existence guard into the repository's own transaction;
    // this is the assertion that the 404 still reaches the client as RFC 7644
    // §3.6 requires, rather than a 204 for a group that was never there.
    let req = test::TestRequest::delete()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{}", Uuid::new_v4()))
        .insert_header(bearer(&token))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);

    // And the happy path stays a 204 with no body.
    let group = make_group!(&app, &token, "Engineering", None, &[]);
    let req = test::TestRequest::delete()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Groups/{group}"))
        .insert_header(bearer(&token))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);
}

// ---------------------------------------------------------------------------
// User collection paging
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn user_list_unfiltered_pages_and_counts() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let bearer_user = scim_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, bearer_user, tenant_id, org_id);

    make_user!(&app, &token, "u1");
    make_user!(&app, &token, "u2");

    // The bearer principal is itself a user in this tenant, so the collection
    // is the two provisioned users plus them.
    let (status, list) = get_json!(&app, &token, "/scim/v2/Users");
    assert_eq!(status, 200);
    assert_eq!(list["totalResults"], 3);
    assert_eq!(list["Resources"].as_array().unwrap().len(), 3);

    // `count=0` is RFC 7644 §3.4.2.4's "tell me how many there are without
    // sending any": an accurate totalResults with an empty Resources array.
    // It takes a separate probe path in the handler precisely so the total
    // stays right, which is the only thing the caller asked for.
    let (status, counted) = get_json!(&app, &token, "/scim/v2/Users?count=0");
    assert_eq!(status, 200);
    assert_eq!(counted["totalResults"], 3);
    assert!(
        counted["Resources"].as_array().unwrap().is_empty(),
        "count=0 must return no resources"
    );

    let (_, page) = get_json!(&app, &token, "/scim/v2/Users?startIndex=3&count=10");
    assert_eq!(page["startIndex"], 3);
    assert_eq!(
        page["Resources"].as_array().unwrap().len(),
        1,
        "startIndex is 1-based, so 3 of 3 is the last single item"
    );
}

#[actix_rt::test]
async fn user_put_replaces_the_whole_scim_representation() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let user = make_user!(&app, &token, "before");

    let req = test::TestRequest::put()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{user}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "after",
            "externalId": "ext-after",
            "name": { "givenName": "Ada", "familyName": "Lovelace" },
            "emails": [{ "value": "after@example.com", "primary": true }],
            "active": true,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;

    assert_eq!(body["userName"], "after");
    assert_eq!(body["externalId"], "ext-after");
    assert_eq!(body["name"]["givenName"], "Ada");
    assert_eq!(body["name"]["familyName"], "Lovelace");
    assert_eq!(body["emails"][0]["value"], "after@example.com");
    assert_eq!(body["active"], true);
    assert_eq!(body["id"], user.to_string(), "PUT must not re-key the user");
}

#[actix_rt::test]
async fn user_put_without_emails_is_invalid_value() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let user = make_user!(&app, &token, "before");

    // `emails` is `#[serde(default)]`, so an omitted array deserializes fine
    // and only the handler's own check stands between that and a user row with
    // no email. The error must be RFC 7644's `invalidValue`, not a 500.
    let req = test::TestRequest::put()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{user}"))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "after",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["scimType"], "invalidValue");
}

#[actix_rt::test]
async fn user_put_on_an_unknown_id_is_not_found() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);
    let token = mint_token(
        &auth,
        scim_admin_user(&db, tenant_id).await,
        tenant_id,
        org_id,
    );

    let req = test::TestRequest::put()
        .peer_addr(bench_peer())
        .uri(&format!("/scim/v2/Users/{}", Uuid::new_v4()))
        .insert_header(bearer(&token))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "ghost",
            "emails": [{ "value": "ghost@example.com", "primary": true }],
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);
}

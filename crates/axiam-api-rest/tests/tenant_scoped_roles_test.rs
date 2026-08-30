//! Organization-level principals restricted to particular tenants.
//!
//! An organization-level principal's global role assignments reach **every**
//! tenant of its organization. That is right for the organization's own
//! administrator and wrong for an account created to administer two of its
//! twelve tenants, which until now could not be expressed at all.
//!
//! A `tenant_scope` on the assignment expresses it. These tests cover the
//!三 places the REST layer has to honour it, none of which `axiam_authz` can:
//!
//! * organization-level **actions**, which name no tenant for the engine to
//!   compare a scope against (`handlers::org_scope`);
//! * the tenant **roster**, which every principal holding `tenants:list` used
//!   to see in full (`handlers::tenants::list`);
//! * `X-Axiam-Tenant`, so a switch to an unreachable tenant is one refusal
//!   rather than a 403 on every page that follows.
//!
//! Plus the validation on the way in: a scope that could never apply is
//! refused rather than stored.

use actix_web::{App, http::header, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_api_rest::{
    PrincipalReachResolver, RateLimitConfig, TenantScopeResolver, register_api_v1_routes,
};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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

/// Arbitrary CSRF token for the double-submit check (SEC-046) — these
/// bearer-token tests have no login cookie, and the middleware only checks the
/// header and cookie agree. Safe (GET) requests ignore it entirely.
const CSRF_TOKEN: &str = "test-csrf-token";

fn test_auth_config() -> AuthConfig {
    // Test-only, non-secret Ed25519 pair, the same one the other REST suites
    // sign with, so a token minted here validates against the config the app is
    // handed.
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
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// An organization with its organization scope tenant and two ordinary tenants.
struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    org_tenant: Uuid,
    tenant_a: Uuid,
    tenant_b: Uuid,
}

async fn fixture() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Acme".into(),
            slug: "acme".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenants = SurrealTenantRepository::new(db.clone());
    let org_tenant = tenants
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();

    let mut ids = Vec::new();
    for (slug, name) in [("alpha", "Alpha"), ("beta", "Beta")] {
        let t = tenants
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: name.into(),
                slug: slug.into(),
                metadata: None,
            })
            .await
            .unwrap();
        ids.push(t.id);
    }

    for tenant in [org_tenant.id, ids[0], ids[1]] {
        seed_permissions(&db, tenant, PERMISSION_REGISTRY)
            .await
            .unwrap();
        seed_default_roles(&db, tenant, PERMISSION_REGISTRY)
            .await
            .unwrap();
    }

    Fixture {
        db,
        org_id: org.id,
        org_tenant: org_tenant.id,
        tenant_a: ids[0],
        tenant_b: ids[1],
    }
}

/// Create a user in `tenant` holding the seeded `role_name`, with an optional
/// tenant scope on the assignment.
async fn user_with_role(
    db: &Surreal<TestDb>,
    tenant: Uuid,
    username: &str,
    role_name: &str,
    tenant_scope: Option<Vec<Uuid>>,
) -> Uuid {
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant,
            username: username.into(),
            email: format!("{username}@acme.test"),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
        .list(
            tenant,
            Pagination {
                offset: 0,
                limit: 1000,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name == role_name)
        .unwrap_or_else(|| panic!("role `{role_name}` not seeded in {tenant}"));

    roles
        .assign_to_user(
            tenant,
            user.id,
            role.id,
            AssignmentScope {
                resource_id: None,
                tenant_scope,
            },
        )
        .await
        .unwrap();

    user.id
}

fn token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
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

/// The app under test.
///
/// Both resolvers are registered, unlike most REST suites: this file is about
/// what happens at the `X-Axiam-Tenant` boundary, and an unregistered
/// [`TenantScopeResolver`] refuses the header outright — which would make the
/// reach test pass for the wrong reason.
macro_rules! app {
    ($f:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $f.db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($f.db.clone()))
                        as Arc<dyn TenantScopeResolver>,
                ))
                .app_data(web::Data::new(
                    Arc::new(SurrealRoleRepository::new($f.db.clone()))
                        as Arc<dyn PrincipalReachResolver>,
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

// ---------------------------------------------------------------------------
// Organization-level actions
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_restricted_organization_principal_cannot_create_a_tenant() {
    // The gap `axiam_authz` structurally cannot close: creating a tenant names
    // no tenant, so there is nothing for the engine to compare the scope
    // against. Without the guard, an account confined to `alpha` could add
    // itself a thirteenth tenant.
    let f = fixture().await;
    let auth = test_auth_config();
    let restricted = user_with_role(
        &f.db,
        f.org_tenant,
        "alpha-admin",
        "super-admin",
        Some(vec![f.tenant_a]),
    )
    .await;
    let app = app!(f, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{}/tenants", f.org_id))
        .insert_header((
            header::AUTHORIZATION,
            format!(
                "Bearer {}",
                token(&auth, restricted, f.org_tenant, f.org_id)
            ),
        ))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Gamma",
            "slug": "gamma",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(
        resp.status(),
        403,
        "an account restricted to particular tenants is not an organization administrator"
    );
}

#[actix_rt::test]
async fn an_unrestricted_organization_principal_still_creates_tenants() {
    // The other half, and the one that would catch an over-tight guard: the
    // organization's own administrator must be unaffected.
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.org_tenant, "org-admin", "super-admin", None).await;
    let app = app!(f, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{}/tenants", f.org_id))
        .insert_header((
            header::AUTHORIZATION,
            format!("Bearer {}", token(&auth, admin, f.org_tenant, f.org_id)),
        ))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Gamma",
            "slug": "gamma",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(
        resp.status().is_success(),
        "unrestricted organization principal was refused: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// The tenant roster
// ---------------------------------------------------------------------------

async fn listed_tenant_names(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    org_id: Uuid,
    bearer: &str,
) -> Vec<String> {
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header((header::AUTHORIZATION, format!("Bearer {bearer}")))
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(app, req).await;
    body["items"]
        .as_array()
        .expect("a paginated result")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

#[actix_rt::test]
async fn a_tenant_administrator_sees_only_its_own_tenant() {
    // `tenants:list` says the caller may see a tenant roster; it never said
    // which one. Every principal holding it saw the whole organization —
    // including a tenant administrator, whose reach is one tenant, and who was
    // then refused everything it clicked on.
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.tenant_a, "alpha-local", "super-admin", None).await;
    let org_id = f.org_id;
    let app = app!(f, auth);

    let names = listed_tenant_names(&app, org_id, &token(&auth, admin, f.tenant_a, org_id)).await;

    assert_eq!(names, vec!["Alpha".to_string()]);
}

#[actix_rt::test]
async fn a_restricted_organization_principal_sees_only_the_tenants_it_reaches() {
    let f = fixture().await;
    let auth = test_auth_config();
    let restricted = user_with_role(
        &f.db,
        f.org_tenant,
        "alpha-admin",
        "super-admin",
        Some(vec![f.tenant_a]),
    )
    .await;
    let (org_id, org_tenant) = (f.org_id, f.org_tenant);
    let app = app!(f, auth);

    let names =
        listed_tenant_names(&app, org_id, &token(&auth, restricted, org_tenant, org_id)).await;

    assert_eq!(names, vec!["Alpha".to_string()]);
}

#[actix_rt::test]
async fn an_unrestricted_organization_principal_sees_the_whole_roster() {
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.org_tenant, "org-admin", "super-admin", None).await;
    let (org_id, org_tenant) = (f.org_id, f.org_tenant);
    let app = app!(f, auth);

    let names = listed_tenant_names(&app, org_id, &token(&auth, admin, org_tenant, org_id)).await;

    assert!(names.contains(&"Alpha".to_string()));
    assert!(names.contains(&"Beta".to_string()));
}

// ---------------------------------------------------------------------------
// Switching tenant
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn switching_to_an_unreachable_tenant_is_refused_at_the_header() {
    // Not the enforcement — the engine already denies every action in a tenant
    // the scope does not name. This turns "every page fails differently" into
    // one answer at the moment the caller asked.
    let f = fixture().await;
    let auth = test_auth_config();
    let restricted = user_with_role(
        &f.db,
        f.org_tenant,
        "alpha-admin",
        "super-admin",
        Some(vec![f.tenant_a]),
    )
    .await;
    let (org_id, org_tenant, tenant_b) = (f.org_id, f.org_tenant, f.tenant_b);
    let app = app!(f, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/auth/me")
        .insert_header((
            header::AUTHORIZATION,
            format!("Bearer {}", token(&auth, restricted, org_tenant, org_id)),
        ))
        .insert_header(("X-Axiam-Tenant", tenant_b.to_string()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 403);
}

#[actix_rt::test]
async fn switching_to_a_reachable_tenant_is_allowed() {
    let f = fixture().await;
    let auth = test_auth_config();
    let restricted = user_with_role(
        &f.db,
        f.org_tenant,
        "alpha-admin",
        "super-admin",
        Some(vec![f.tenant_a]),
    )
    .await;
    let (org_id, org_tenant, tenant_a) = (f.org_id, f.org_tenant, f.tenant_a);
    let app = app!(f, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/auth/me")
        .insert_header((
            header::AUTHORIZATION,
            format!("Bearer {}", token(&auth, restricted, org_tenant, org_id)),
        ))
        .insert_header(("X-Axiam-Tenant", tenant_a.to_string()))
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert!(
        resp.status().is_success(),
        "the scope names this tenant: {}",
        resp.status()
    );
}

// ---------------------------------------------------------------------------
// What `/auth/me` tells the admin UI
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_restricted_super_admin_is_not_told_it_can_do_everything() {
    // B-09's rule, extended. The `*` wildcard short-circuits every client-side
    // `can()` check, so emitting it for a principal the server refuses
    // organization-level actions renders controls that end in a 403 — which is
    // the defect this whole area exists to close.
    let f = fixture().await;
    let auth = test_auth_config();
    let restricted = user_with_role(
        &f.db,
        f.org_tenant,
        "alpha-admin",
        "super-admin",
        Some(vec![f.tenant_a]),
    )
    .await;
    let (org_id, org_tenant, tenant_a) = (f.org_id, f.org_tenant, f.tenant_a);
    let app = app!(f, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/auth/me")
        .insert_header((
            header::AUTHORIZATION,
            format!("Bearer {}", token(&auth, restricted, org_tenant, org_id)),
        ))
        .insert_header(("X-Axiam-Tenant", tenant_a.to_string()))
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let permissions: Vec<&str> = body["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(
        !permissions.contains(&"*"),
        "a restricted principal must not be handed the wildcard"
    );
    assert!(
        !permissions.is_empty(),
        "...but it still holds every action that applies inside its reach"
    );

    // And the UI is told what to filter its switcher by.
    let reachable = body["user"]["reachable_tenant_ids"]
        .as_array()
        .expect("the reach is reported");
    assert_eq!(reachable.len(), 1);
    assert_eq!(reachable[0].as_str().unwrap(), tenant_a.to_string());
}

#[actix_rt::test]
async fn an_unrestricted_super_admin_keeps_the_wildcard() {
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.org_tenant, "org-admin", "super-admin", None).await;
    let (org_id, org_tenant) = (f.org_id, f.org_tenant);
    let app = app!(f, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/auth/me")
        .insert_header((
            header::AUTHORIZATION,
            format!("Bearer {}", token(&auth, admin, org_tenant, org_id)),
        ))
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let permissions: Vec<&str> = body["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(permissions.contains(&"*"));
    assert!(
        body["user"]["reachable_tenant_ids"].is_null(),
        "an unrestricted principal reports no restriction at all"
    );
}

// ---------------------------------------------------------------------------
// Validation on the way in
// ---------------------------------------------------------------------------

/// `POST /api/v1/roles/{role}/users` with the given scope, as `actor`.
async fn assign_with_scope(
    f: &Fixture,
    auth: &AuthConfig,
    actor: Uuid,
    actor_tenant: Uuid,
    role_tenant: Uuid,
    target: Uuid,
    tenant_scope: serde_json::Value,
) -> u16 {
    let role = SurrealRoleRepository::new(f.db.clone())
        .list(
            role_tenant,
            Pagination {
                offset: 0,
                limit: 1000,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name == "viewer")
        .unwrap();

    let app = app!(f, auth);
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/roles/{}/users", role.id))
        .insert_header((
            header::AUTHORIZATION,
            format!("Bearer {}", token(auth, actor, actor_tenant, f.org_id)),
        ))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "user_id": target,
            "tenant_scope": tenant_scope,
        }))
        .to_request();
    test::call_service(&app, req).await.status().as_u16()
}

#[actix_rt::test]
async fn a_tenant_scope_is_refused_outside_an_organization_scope() {
    // In an ordinary tenant the only tenant an assignment could name is that
    // tenant itself, so a scope is either a no-op or a contradiction. Accepting
    // it silently would tell an operator a restriction was applied when none
    // could be.
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.tenant_a, "alpha-local", "super-admin", None).await;
    let target = user_with_role(&f.db, f.tenant_a, "victim", "viewer", None).await;

    let status = assign_with_scope(
        &f,
        &auth,
        admin,
        f.tenant_a,
        f.tenant_a,
        target,
        serde_json::json!([f.tenant_a.to_string()]),
    )
    .await;

    assert_eq!(status, 400, "expected a validation refusal, got {status}");
}

#[actix_rt::test]
async fn an_empty_tenant_scope_is_refused() {
    // An assignment reaching no tenant is not a restriction, it is a grant that
    // does nothing anywhere — the least debuggable thing this API could store.
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.org_tenant, "org-admin", "super-admin", None).await;
    let target = user_with_role(&f.db, f.org_tenant, "newcomer", "viewer", None).await;

    let status = assign_with_scope(
        &f,
        &auth,
        admin,
        f.org_tenant,
        f.org_tenant,
        target,
        serde_json::json!([]),
    )
    .await;

    assert_eq!(status, 400, "expected a validation refusal, got {status}");
}

#[actix_rt::test]
async fn naming_the_organization_scope_tenant_is_refused() {
    // It would hand back the organization-wide reach the restriction exists to
    // remove, in the exact place `require_organization_principal` looks for it.
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.org_tenant, "org-admin", "super-admin", None).await;
    let target = user_with_role(&f.db, f.org_tenant, "newcomer", "viewer", None).await;

    let status = assign_with_scope(
        &f,
        &auth,
        admin,
        f.org_tenant,
        f.org_tenant,
        target,
        serde_json::json!([f.org_tenant.to_string()]),
    )
    .await;

    assert_eq!(status, 400, "expected a validation refusal, got {status}");
}

#[actix_rt::test]
async fn a_tenant_of_another_organization_is_refused() {
    // The boundary an organization *is*.
    let f = fixture().await;
    let auth = test_auth_config();
    let other_org = SurrealOrganizationRepository::new(f.db.clone())
        .create(CreateOrganization {
            name: "Other".into(),
            slug: "other".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let outsider = SurrealTenantRepository::new(f.db.clone())
        .create(CreateTenant {
            organization_id: other_org.id,
            kind: TenantKind::Standard,
            name: "Outsider".into(),
            slug: "outsider".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let admin = user_with_role(&f.db, f.org_tenant, "org-admin", "super-admin", None).await;
    let target = user_with_role(&f.db, f.org_tenant, "newcomer", "viewer", None).await;

    let status = assign_with_scope(
        &f,
        &auth,
        admin,
        f.org_tenant,
        f.org_tenant,
        target,
        serde_json::json!([outsider.id.to_string()]),
    )
    .await;

    assert_eq!(status, 400, "expected a validation refusal, got {status}");
}

#[actix_rt::test]
async fn a_valid_tenant_scope_is_stored_deduplicated_and_ordered() {
    // Two requests naming the same tenants in different orders must produce the
    // same edge, or "has this grant changed?" becomes unanswerable.
    let f = fixture().await;
    let auth = test_auth_config();
    let admin = user_with_role(&f.db, f.org_tenant, "org-admin", "super-admin", None).await;
    // Holds `admin`, not `viewer`: `has_role` is UNIQUE on (subject, role), so
    // seeding the target with the very role the request assigns would answer
    // 409 and prove nothing about the scope.
    let target = user_with_role(&f.db, f.org_tenant, "newcomer", "admin", None).await;

    let status = assign_with_scope(
        &f,
        &auth,
        admin,
        f.org_tenant,
        f.org_tenant,
        target,
        serde_json::json!([
            f.tenant_b.to_string(),
            f.tenant_a.to_string(),
            f.tenant_b.to_string(),
        ]),
    )
    .await;
    assert_eq!(status, 204, "expected the assignment to be accepted");

    let assignments = SurrealRoleRepository::new(f.db.clone())
        .get_user_role_assignments(f.org_tenant, target)
        .await
        .unwrap();
    let scoped: Vec<_> = assignments
        .iter()
        .filter_map(|a| a.tenant_scope.clone())
        .collect();
    assert_eq!(scoped.len(), 1, "exactly one scoped assignment");
    let mut expected = vec![f.tenant_a, f.tenant_b];
    expected.sort();
    assert_eq!(scoped[0], expected, "deduplicated and in a stable order");
}

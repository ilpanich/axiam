//! S-9 (DF-013) — service-account principals on the management routes.
//!
//! D-5 admits a service-account token (`aud = axiam:m2m`,
//! `sub_kind = service_account`) on eight permission families and on nothing
//! else. What this file pins, in the order the plan asks for it:
//!
//! * **The boundary, both directions, derived from the registry.** A route's
//!   family is the namespace of the permission `ROUTE_PERMISSION_MAP` gives it;
//!   the family lists are checked against `PERMISSION_REGISTRY` so that neither
//!   can drift, and every mapped route is then driven with a real service
//!   account token through the real route table.
//! * **Default-deny.** A service account with no role reaches nothing — 403
//!   `authorization_denied`, never the audience refusal and never a 2xx.
//! * **The I1.** A user token is authenticated by the same code on a converted
//!   route as on an unconverted one, compared request by request.
//! * **Sender constraint, tenant and CA scope, CSRF, audit.**

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use actix_web::http::Method;
use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::permissions::{
    HUMAN_ONLY_FAMILIES, M2M_MANAGEMENT_FAMILIES, PERMISSION_REGISTRY, PUBLIC_PATHS,
    ROUTE_PERMISSION_MAP,
};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{
    AuthenticatedPrincipal, AuthenticatedUser, PrincipalReachResolver, RateLimitConfig,
    SessionValidator, TenantScopeResolver, register_api_v1_routes,
};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_M2M, AUD_USER, AccessTokenSpec, CnfClaim, SubjectKind, issue_access_token,
    issue_service_account_token,
};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::audit::ActorType;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, RoleRepository,
    ServiceAccountRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealServiceAccountRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_db::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, seed_default_roles,
    seed_permissions,
};
use axiam_pki::{CaService, CertService, PkiConfig};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Test-only placeholder password — not a real credential.
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

/// Arbitrary CSRF double-submit token (SEC-046).
const CSRF_TOKEN: &str = "test-csrf-token";

/// What `AuthenticatedUser` answers a machine token with. The sweep compares
/// against it exactly, so a 401 for any *other* reason cannot pass as the
/// audience refusal.
const AUDIENCE_REFUSAL: &str =
    "Authentication failed: audience mismatch — this route requires axiam:user audience";

// -------------------------------------------------------------------------
// Keys, tokens, fixtures
// -------------------------------------------------------------------------

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----"; // gitleaks:allow
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

fn user_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
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

fn service_account_token(
    auth: &AuthConfig,
    account: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
) -> String {
    issue_service_account_token(
        account,
        tenant_id,
        org_id,
        Uuid::new_v4().to_string(),
        None,
        auth,
    )
    .unwrap()
}

/// An organization, one ordinary tenant in it, and that tenant's permission
/// registry and default roles.
struct World {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_id = standard_tenant(&db, org.id, "home").await;
    World {
        db,
        org_id: org.id,
        tenant_id,
    }
}

/// A seeded ordinary tenant of `org_id`.
async fn standard_tenant(db: &Surreal<TestDb>, org_id: Uuid, slug: &str) -> Uuid {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap();
    seed(db, tenant.id).await;
    tenant.id
}

/// The organization's own reserved tenant, seeded.
async fn organization_tenant(db: &Surreal<TestDb>, org_id: Uuid) -> Uuid {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org_id))
        .await
        .unwrap();
    seed(db, tenant.id).await;
    tenant.id
}

async fn seed(db: &Surreal<TestDb>, tenant_id: Uuid) {
    seed_permissions(db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
}

async fn role_named(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    SurrealRoleRepository::new(db.clone())
        .list(
            tenant_id,
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
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("role `{name}` not seeded"))
        .id
}

/// A service account in `tenant_id`, holding `role` globally when one is named.
async fn service_account(db: &Surreal<TestDb>, tenant_id: Uuid, role: Option<&str>) -> Uuid {
    let (account, _secret) = SurrealServiceAccountRepository::new(db.clone())
        .create(CreateServiceAccount {
            tenant_id,
            name: format!("sa-{}", Uuid::new_v4().simple()),
            description: None,
        })
        .await
        .unwrap();
    if let Some(role) = role {
        let role_id = role_named(db, tenant_id, role).await;
        SurrealRoleRepository::new(db.clone())
            .assign_to_service_account(tenant_id, account.id, role_id, AssignmentScope::global())
            .await
            .unwrap();
    }
    account.id
}

/// A user in `tenant_id`, holding `role` globally when one is named.
async fn user(db: &Surreal<TestDb>, tenant_id: Uuid, role: Option<&str>) -> Uuid {
    let name = format!("u{}", Uuid::new_v4().simple());
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: name.clone(),
            email: format!("{name}@example.com"),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    if let Some(role) = role {
        let role_id = role_named(db, tenant_id, role).await;
        SurrealRoleRepository::new(db.clone())
            .assign_to_user(tenant_id, user.id, role_id, AssignmentScope::global())
            .await
            .unwrap();
    }
    user.id
}

fn engine(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

/// The production route table with the real RBAC engine and the real tenant
/// and reach resolvers (`main.rs` registers both), so `X-Axiam-Tenant` is
/// decided as it is in production.
macro_rules! app {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($db.clone()))
                        as Arc<dyn TenantScopeResolver>,
                ))
                .app_data(web::Data::new(
                    Arc::new(SurrealRoleRepository::new($db.clone()))
                        as Arc<dyn PrincipalReachResolver>,
                ))
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

/// A bearer-only request: no cookie, so no CSRF token is needed (T-200).
fn bearer(method: &Method, uri: &str, token: &str) -> test::TestRequest {
    test::TestRequest::default()
        .method(method.clone())
        .uri(uri)
        .peer_addr("127.0.0.1:40000".parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
}

async fn call<S, B>(app: &S, req: test::TestRequest) -> (u16, serde_json::Value)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let resp = test::call_service(app, req.to_request()).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

/// `{param}` placeholders replaced by fresh ids: nothing the sweep addresses
/// exists, which is what makes a 2xx from an unprivileged caller impossible to
/// explain except by a missing guard.
fn concrete(pattern: &str) -> String {
    let mut out = String::new();
    let mut rest = pattern;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}').expect("unbalanced placeholder") + open;
        out.push_str(&Uuid::new_v4().to_string());
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    out
}

/// A route's family: the namespace of the permission it requires.
fn family_of(permission: &str) -> &str {
    permission.split_once(':').expect("namespaced permission").0
}

fn admits_machines(permission: &str) -> bool {
    M2M_MANAGEMENT_FAMILIES.contains(&family_of(permission))
}

// -------------------------------------------------------------------------
// (a) The boundary is D-5, pinned — and derived, not hand-listed per route
// -------------------------------------------------------------------------

/// Every family in the registry is placed in exactly one of the two lists, and
/// neither list names a family the registry does not have.
///
/// This is what keeps the sweep below honest: the sweep classifies a route by
/// its permission's namespace, so a new family added to the registry without a
/// decision would otherwise be silently human-only (safe) or, if someone added
/// it to the wrong list, silently machine-reachable. It fails either way until
/// the family is placed.
#[actix_rt::test]
async fn every_registry_family_is_placed_on_exactly_one_side_of_d5() {
    let registry: BTreeSet<&str> = PERMISSION_REGISTRY
        .iter()
        .map(|(action, _)| family_of(action))
        .collect();
    let admitted: BTreeSet<&str> = M2M_MANAGEMENT_FAMILIES.iter().copied().collect();
    let human: BTreeSet<&str> = HUMAN_ONLY_FAMILIES.iter().copied().collect();

    assert!(
        admitted.is_disjoint(&human),
        "a family on both sides of D-5: {:?}",
        admitted.intersection(&human).collect::<Vec<_>>()
    );
    let placed: BTreeSet<&str> = admitted.union(&human).copied().collect();
    assert_eq!(
        placed, registry,
        "D-5 must place every family of PERMISSION_REGISTRY, and only those"
    );

    // The decision itself, so a change to it is a visible diff in a test and
    // not only in a constant.
    assert_eq!(
        admitted,
        BTreeSet::from([
            "resources",
            "scopes",
            "permissions",
            "roles",
            "groups",
            "service_accounts",
            "certificates",
            "webhooks",
        ])
    );

    // And every mapped route's permission is one the registry has, so
    // `family_of` over the route map is a function over registry families.
    let actions: HashSet<&str> = PERMISSION_REGISTRY.iter().map(|(a, _)| *a).collect();
    for (method, path, permission) in ROUTE_PERMISSION_MAP {
        assert!(
            actions.contains(permission),
            "{method} {path} requires `{permission}`, which is not in the registry"
        );
    }
}

/// The sweep. Every route of `ROUTE_PERMISSION_MAP`, driven through the real
/// route table with two service accounts — one holding no role, one holding
/// `super-admin`:
///
/// * **in scope** — neither token gets the audience refusal. The one with no
///   role gets no 2xx, and where the handler ran its guard, a 403
///   `authorization_denied` naming the route's own permission. The one with
///   `super-admin` is never refused by RBAC.
/// * **out of scope** — both get 401 with the audience refusal, whatever role
///   they hold: the refusal is the extractor's, before RBAC is asked.
#[actix_rt::test]
async fn the_route_map_admits_a_service_account_exactly_on_the_d5_families() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let bare = service_account(&w.db, w.tenant_id, None).await;
    let admin = service_account(&w.db, w.tenant_id, Some("super-admin")).await;
    let bare_token = service_account_token(&auth, bare, w.tenant_id, w.org_id);
    let admin_token = service_account_token(&auth, admin, w.tenant_id, w.org_id);
    let app = app!(w.db, auth, authz);

    let (mut admitted, mut refused, mut guarded) = (0, 0, 0);
    for (method, pattern, permission) in ROUTE_PERMISSION_MAP {
        let method = Method::from_bytes(method.as_bytes()).unwrap();
        let uri = concrete(pattern);
        let (bare_status, bare_body) = call(&app, bearer(&method, &uri, &bare_token)).await;
        let (admin_status, admin_body) = call(&app, bearer(&method, &uri, &admin_token)).await;
        let route = format!("{method} {pattern} ({permission})");

        if admits_machines(permission) {
            admitted += 1;
            assert_ne!(bare_status, 401, "{route}: no-role account: {bare_body}");
            assert_ne!(
                admin_status, 401,
                "{route}: super-admin account: {admin_body}"
            );
            assert!(
                !(200..300).contains(&bare_status),
                "{route}: a service account with no role got {bare_status} — default-deny broken"
            );
            if bare_status == 403 {
                guarded += 1;
                assert_eq!(bare_body["error"], "authorization_denied", "{route}");
                assert_eq!(bare_body["action"], *permission, "{route}");
            }
            // The route guard's refusal is the 403 that names the action it
            // checked. A handler may still refuse after the guard — `unassign`
            // answers a user of no tenant it knows with 403 — and that is the
            // handler's rule applied to a machine exactly as to a person.
            assert!(
                admin_status != 403 || admin_body["action"].is_null(),
                "{route}: RBAC refused a super-admin service account: {admin_body}"
            );
        } else {
            refused += 1;
            for (who, status, body) in [
                ("no-role", bare_status, &bare_body),
                ("super-admin", admin_status, &admin_body),
            ] {
                assert_eq!(status, 401, "{route}: {who} account: {body}");
                assert_eq!(body["message"], AUDIENCE_REFUSAL, "{route}: {who} account");
            }
        }
    }

    // The sweep walked something on both sides, and on the admitted side it
    // reached the RBAC guard for every route that has no request body to fail
    // before it — which is every GET and DELETE.
    let bodyless = ROUTE_PERMISSION_MAP
        .iter()
        .filter(|(m, _, p)| admits_machines(p) && matches!(*m, "GET" | "DELETE"))
        .count();
    assert!(
        admitted > 0 && refused > 0,
        "{admitted} admitted, {refused} refused"
    );
    assert!(
        guarded >= bodyless,
        "only {guarded} admitted routes reached the RBAC guard; {bodyless} have no body"
    );
}

/// The out-of-scope direction for the routes the permission map cannot see:
/// self-service (`/auth/me`, MFA enrolment, password change), which carries no
/// named permission and so is not in `ROUTE_PERMISSION_MAP`.
///
/// Walked from the OpenAPI document: every non-public `/api/v1` operation that
/// does not list the service-account scheme must refuse a `super-admin`
/// service account with the audience refusal. The spec and the code are
/// asserted to agree in the next test, and `route_openapi_parity_test` holds
/// the spec to the route table, so this covers the whole guarded surface
/// rather than a hand-picked list.
#[actix_rt::test]
async fn every_route_outside_d5_refuses_a_service_account_including_self_service() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let admin = service_account(&w.db, w.tenant_id, Some("super-admin")).await;
    let token = service_account_token(&auth, admin, w.tenant_id, w.org_id);
    let app = app!(w.db, auth, authz);

    let spec = serde_json::to_value(axiam_api_rest::openapi::api_doc()).unwrap();
    let mut walked = BTreeSet::new();
    for (path, item) in spec["paths"].as_object().unwrap() {
        if !path.starts_with("/api/v1/") {
            continue;
        }
        for (method, op) in item.as_object().unwrap() {
            let Ok(method) = Method::from_bytes(method.to_uppercase().as_bytes()) else {
                continue;
            };
            if is_public(path) || security_schemes(op).contains("service_account") {
                continue;
            }
            let (status, body) = call(&app, bearer(&method, &concrete(path), &token)).await;
            let route = format!("{method} {path}");
            assert_eq!(status, 401, "{route}: {body}");
            assert_eq!(body["message"], AUDIENCE_REFUSAL, "{route}");
            walked.insert(route);
        }
    }

    // The families D-5 names as out of scope, by a route each, so the walk
    // demonstrably covered them rather than skipping them.
    for route in [
        "GET /api/v1/auth/me",
        "POST /api/v1/auth/mfa/enroll",
        "POST /api/v1/auth/password/change",
        "GET /api/v1/users/{user_id}/mfa-methods",
        "GET /api/v1/users/{user_id}/sessions",
        "GET /api/v1/organizations",
        "GET /api/v1/organizations/{org_id}/tenants",
        "GET /api/v1/settings",
        "GET /api/v1/organizations/{org_id}/ca-certificates",
        "GET /api/v1/pgp-keys",
        "GET /api/v1/scim-tokens",
        "GET /api/v1/federation-configs",
    ] {
        assert!(walked.contains(route), "the walk did not reach {route}");
    }
}

/// `AuthzMiddleware`'s public-path rule: exact, or a prefix for a `*` entry.
fn is_public(path: &str) -> bool {
    PUBLIC_PATHS.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => path.starts_with(prefix),
        None => path == *p,
    })
}

fn security_schemes(op: &serde_json::Value) -> BTreeSet<String> {
    op["security"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|req| req.as_object())
        .flat_map(|req| req.keys().cloned())
        .collect()
}

/// The OpenAPI document says what the code does: an operation lists the
/// service-account scheme if and only if its family is in D-5 — or it is one
/// of the two authorization-check endpoints, which admitted machines before
/// S-9 and are not in the permission map at all.
#[actix_rt::test]
async fn the_spec_lists_the_service_account_scheme_exactly_where_the_code_admits_it() {
    let spec = serde_json::to_value(axiam_api_rest::openapi::api_doc()).unwrap();
    let mapped: std::collections::HashMap<(String, String), &str> = ROUTE_PERMISSION_MAP
        .iter()
        .map(|(m, p, perm)| ((m.to_string(), p.to_string()), *perm))
        .collect();
    let checks = [
        ("POST".to_string(), "/api/v1/authz/check".to_string()),
        ("POST".to_string(), "/api/v1/authz/check/batch".to_string()),
    ];

    let mut listed = 0;
    for (path, item) in spec["paths"].as_object().unwrap() {
        for (method, op) in item.as_object().unwrap() {
            let key = (method.to_uppercase(), path.clone());
            let lists = security_schemes(op).contains("service_account");
            let admits =
                mapped.get(&key).is_some_and(|p| admits_machines(p)) || checks.contains(&key);
            assert_eq!(lists, admits, "{} {}: spec and code disagree", key.0, key.1);
            listed += usize::from(lists);
        }
    }
    let expected = ROUTE_PERMISSION_MAP
        .iter()
        .filter(|(_, _, p)| admits_machines(p))
        .count()
        + checks.len();
    assert_eq!(
        listed, expected,
        "an admitted route is missing from the spec"
    );

    let scheme = &spec["components"]["securitySchemes"]["service_account"];
    assert_eq!(scheme["scheme"], "bearer");
    assert!(
        scheme["description"]
            .as_str()
            .unwrap()
            .contains("axiam:m2m"),
        "{scheme}"
    );
}

// -------------------------------------------------------------------------
// (b) Status and body; the I1; default-deny
// -------------------------------------------------------------------------

/// One representative route per family, and the permission a role needs for it.
const FAMILY_PROBES: &[(&str, &str, &str)] = &[
    ("resources", "/api/v1/resources", "resources:list"),
    ("permissions", "/api/v1/permissions", "permissions:list"),
    ("roles", "/api/v1/roles", "roles:list"),
    ("groups", "/api/v1/groups", "groups:list"),
    (
        "service_accounts",
        "/api/v1/service-accounts",
        "service_accounts:list",
    ),
    ("certificates", "/api/v1/certificates", "certificates:list"),
    ("webhooks", "/api/v1/webhooks", "webhooks:list"),
];

/// Per family: a service account holding the read-only `viewer` role gets
/// 200; one holding nothing gets 403 `authorization_denied` naming the action,
/// not 401 and not the audience message. The I4 twin: a user token is answered
/// identically in both cases, so the conversion moved nothing for people.
///
/// `scopes` is a sub-resource of a resource and is probed on one below.
#[actix_rt::test]
async fn per_family_a_role_admits_a_service_account_and_no_role_refuses_it_with_403() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let viewer_sa = service_account(&w.db, w.tenant_id, Some("viewer")).await;
    let bare_sa = service_account(&w.db, w.tenant_id, None).await;
    let viewer_user = user(&w.db, w.tenant_id, Some("viewer")).await;
    let bare_user = user(&w.db, w.tenant_id, None).await;
    let app = app!(w.db, auth, authz);

    let resource = {
        let token = service_account_token(
            &auth,
            service_account(&w.db, w.tenant_id, Some("admin")).await,
            w.tenant_id,
            w.org_id,
        );
        let (status, body) = call(
            &app,
            bearer(&Method::POST, "/api/v1/resources", &token).set_json(serde_json::json!({
                "name": "fleet", "resource_type": "site", "parent_id": null, "metadata": null
            })),
        )
        .await;
        assert_eq!(status, 201, "{body}");
        body["id"].as_str().unwrap().to_owned()
    };
    let scopes = format!("/api/v1/resources/{resource}/scopes");
    let probes = FAMILY_PROBES
        .iter()
        .map(|(f, u, p)| (*f, u.to_string(), *p))
        .chain([("scopes", scopes, "scopes:list")]);

    for (family, uri, permission) in probes {
        let cases = [
            (
                service_account_token(&auth, viewer_sa, w.tenant_id, w.org_id),
                200,
                "viewer account",
            ),
            (
                service_account_token(&auth, bare_sa, w.tenant_id, w.org_id),
                403,
                "no-role account",
            ),
            (
                user_token(&auth, viewer_user, w.tenant_id, w.org_id),
                200,
                "viewer user",
            ),
            (
                user_token(&auth, bare_user, w.tenant_id, w.org_id),
                403,
                "no-role user",
            ),
        ];
        for (token, expected, who) in cases {
            let (status, body) = call(&app, bearer(&Method::GET, &uri, &token)).await;
            assert_eq!(status, expected, "{family}: {who}: {body}");
            if expected == 403 {
                assert_eq!(body["error"], "authorization_denied", "{family}: {who}");
                assert_eq!(body["action"], permission, "{family}: {who}");
            }
        }
    }
}

/// The writes a provisioning tool makes, each by a service account holding
/// `admin`: create a role, a group, a permission, a service account, and
/// assign the role to that new account. The DF-013 scenario end to end — the
/// demo's bootstrap needed a human credential for exactly these.
#[actix_rt::test]
async fn a_service_account_with_a_role_can_provision_the_management_families() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let sa = service_account(&w.db, w.tenant_id, Some("admin")).await;
    let token = service_account_token(&auth, sa, w.tenant_id, w.org_id);
    let app = app!(w.db, auth, authz);

    let post =
        |uri: &str, body: serde_json::Value| bearer(&Method::POST, uri, &token).set_json(body);

    let (s, role) = call(
        &app,
        post(
            "/api/v1/roles",
            serde_json::json!({"name": "operator", "description": "ops", "is_global": false}),
        ),
    )
    .await;
    assert_eq!(s, 201, "{role}");
    let (s, body) = call(
        &app,
        post(
            "/api/v1/groups",
            serde_json::json!({"name": "ops", "description": "ops", "metadata": null}),
        ),
    )
    .await;
    assert_eq!(s, 201, "{body}");
    let (s, body) = call(
        &app,
        post(
            "/api/v1/permissions",
            serde_json::json!({"action": "reactor:scram", "description": "scram"}),
        ),
    )
    .await;
    assert_eq!(s, 201, "{body}");
    let (s, account) = call(
        &app,
        post(
            "/api/v1/service-accounts",
            serde_json::json!({"name": "unit-7"}),
        ),
    )
    .await;
    // The body carries the one-time `client_secret`; a failure must not print
    // it into the CI log, so only the status is reported.
    assert_eq!(s, 201, "creating the service account failed");
    let (s, body) = call(
        &app,
        post(
            &format!(
                "/api/v1/roles/{}/service-accounts",
                role["id"].as_str().unwrap()
            ),
            serde_json::json!({"service_account_id": account["id"]}),
        ),
    )
    .await;
    assert_eq!(s, 204, "{body}");
}

/// Default-deny, stated as the plan states it: a service account with no role
/// assignment reaches nothing it did not reach before. Before S-9 it reached
/// the two authorization-check endpoints and nothing else; it still reaches
/// those (a self-check is not a grant), and every mapped route refuses it —
/// 403 on the admitted families, 401 on the rest. The sweep proves the second
/// half route by route; this one proves the first.
#[actix_rt::test]
async fn a_service_account_with_no_role_still_reaches_only_the_authorization_check() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let bare = service_account(&w.db, w.tenant_id, None).await;
    let token = service_account_token(&auth, bare, w.tenant_id, w.org_id);
    let app = app!(w.db, auth, authz);

    let (status, body) = call(
        &app,
        bearer(&Method::POST, "/api/v1/authz/check", &token)
            .set_json(serde_json::json!({"action": "roles:list", "resource_id": Uuid::nil()})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["allowed"], false, "{body}");
}

// --- The I1, as a differential ------------------------------------------

/// A session store holding exactly the sessions a test declares active.
struct Sessions(Mutex<HashSet<(Uuid, Uuid)>>);

impl SessionValidator for Sessions {
    fn is_session_active<'a>(
        &'a self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        let active = self.0.lock().unwrap().contains(&(tenant_id, session_id));
        Box::pin(async move { active })
    }
}

async fn as_user(user: AuthenticatedUser) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "subject": user.user_id,
        "tenant": user.tenant_id,
        "home": user.principal_tenant_id,
        "organization_level": user.organization_level,
        "scope": format!("{:?}", user.subject_scope()),
    }))
}

async fn as_principal(p: AuthenticatedPrincipal) -> HttpResponse {
    assert!(!p.is_machine, "a user token reached the machine branch");
    HttpResponse::Ok().json(serde_json::json!({
        "subject": p.subject_id,
        "tenant": p.tenant_id,
        "home": p.principal_tenant_id,
        "organization_level": p.organization_level,
        "scope": format!("{:?}", p.subject_scope()),
    }))
}

/// **The I1.** Every user-token shape the narrow extractor has a rule for,
/// presented to `AuthenticatedUser` (every unconverted route) and to
/// `AuthenticatedPrincipal` (every converted route): the status, the body and
/// the resolved principal must be identical.
///
/// The `sid` case is not hypothetical. Before this change the principal
/// extractor read the session id from `jti` where the user extractor reads
/// `sid` first, so an OAuth2-issued token (random `jti`, session in `sid`)
/// was accepted on every unconverted route and would have been refused as
/// "session revoked or expired" on every converted one.
#[actix_rt::test]
async fn a_user_token_is_answered_identically_by_both_extractors() {
    let w = world().await;
    let auth = test_auth_config();
    let org_scope = organization_tenant(&w.db, w.org_id).await;
    let neighbour = standard_tenant(&w.db, w.org_id, "neighbour").await;
    let tenant_user = user(&w.db, w.tenant_id, Some("admin")).await;
    let org_admin = user(&w.db, org_scope, Some("super-admin")).await;

    let (live, dead, oauth_sid) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let sessions = Arc::new(Sessions(Mutex::new(HashSet::from([
        (w.tenant_id, live),
        (org_scope, live),
        (w.tenant_id, oauth_sid),
    ]))));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(sessions as Arc<dyn SessionValidator>))
            .app_data(web::Data::new(
                Arc::new(SurrealTenantRepository::new(w.db.clone()))
                    as Arc<dyn TenantScopeResolver>,
            ))
            .route("/user", web::get().to(as_user))
            .route("/principal", web::get().to(as_principal)),
    )
    .await;

    let session_token = |user: Uuid, tenant: Uuid, jti: Uuid| {
        issue_access_token(
            user,
            tenant,
            w.org_id,
            &[],
            &auth,
            jti.to_string(),
            AUD_USER,
        )
        .unwrap()
    };
    let oauth_token = AccessTokenSpec::user(
        tenant_user,
        w.tenant_id,
        w.org_id,
        Uuid::new_v4().to_string(),
    )
    .session(Some(oauth_sid))
    .issue(&auth)
    .unwrap();
    let bound = AccessTokenSpec::user(tenant_user, w.tenant_id, w.org_id, live.to_string())
        .cnf(Some(CnfClaim::from_certificate_thumbprint(
            "not-this-connection",
        )))
        .issue(&auth)
        .unwrap();
    let unknown_aud = AccessTokenSpec::user(tenant_user, w.tenant_id, w.org_id, live.to_string())
        .aud("https://elsewhere.example")
        .issue(&auth);

    let mut cases: Vec<(&str, String, Option<Uuid>, u16)> = vec![
        (
            "live session",
            session_token(tenant_user, w.tenant_id, live),
            None,
            200,
        ),
        (
            "revoked session",
            session_token(tenant_user, w.tenant_id, dead),
            None,
            401,
        ),
        ("session in sid, random jti", oauth_token, None, 200),
        ("certificate-bound, no certificate", bound, None, 401),
        (
            "organization admin, own scope",
            session_token(org_admin, org_scope, live),
            None,
            200,
        ),
        (
            "organization admin, acting on a tenant",
            session_token(org_admin, org_scope, live),
            Some(neighbour),
            200,
        ),
        (
            "tenant user naming a neighbour",
            session_token(tenant_user, w.tenant_id, live),
            Some(neighbour),
            403,
        ),
        (
            "tenant user naming its own tenant",
            session_token(tenant_user, w.tenant_id, live),
            Some(w.tenant_id),
            200,
        ),
    ];
    // The validator refuses an audience it does not know before either
    // extractor runs, which is itself the same answer on both.
    if let Ok(token) = unknown_aud {
        cases.push(("unknown audience", token, None, 401));
    }

    for (case, token, acting, expected) in cases {
        let request = |uri: &str| {
            let mut req = bearer(&Method::GET, uri, &token);
            if let Some(tenant) = acting {
                req = req.insert_header(("X-Axiam-Tenant", tenant.to_string()));
            }
            req
        };
        let (user_status, user_body) = call(&app, request("/user")).await;
        let (principal_status, principal_body) = call(&app, request("/principal")).await;
        assert_eq!(user_status, expected, "{case}: {user_body}");
        assert_eq!(principal_status, user_status, "{case}: status differs");
        assert_eq!(principal_body, user_body, "{case}: body differs");
    }
}

/// An RFC 8693 exchange can narrow a *user's* token to `axiam:m2m`
/// (`sub_kind = user`). The machine branch skips the session check, which is
/// sound only for a service account; such a token is therefore refused on a
/// converted route rather than evaluated as the user without a session behind
/// it. The same rule holds on `/authz/check`, which shares the extractor.
#[actix_rt::test]
async fn a_user_token_narrowed_to_the_machine_audience_is_not_a_service_account() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let person = user(&w.db, w.tenant_id, Some("super-admin")).await;
    let exchanged = AccessTokenSpec::exchanged(
        &person.to_string(),
        SubjectKind::User,
        w.tenant_id,
        w.org_id,
        Uuid::new_v4().to_string(),
        AUD_M2M,
    )
    .issue(&auth)
    .unwrap();
    let app = app!(w.db, auth, authz);

    for (method, uri) in [
        (Method::GET, "/api/v1/roles"),
        (Method::POST, "/api/v1/authz/check"),
    ] {
        let mut req = bearer(&method, uri, &exchanged);
        if method == Method::POST {
            req = req
                .set_json(serde_json::json!({"action": "roles:list", "resource_id": Uuid::nil()}));
        }
        let (status, body) = call(&app, req).await;
        assert_eq!(status, 401, "{uri}: {body}");
        assert_eq!(
            body["message"],
            "Authentication failed: a machine-audience token is accepted here only for a service account",
            "{uri}"
        );
    }
}

// -------------------------------------------------------------------------
// (c) Sender constraint on the new surface
// -------------------------------------------------------------------------

/// A device token (certificate-bound, `cnf.x5t#S256`, S-3) on a converted
/// route, presented without its certificate: 401, before RBAC is asked — the
/// account holds `super-admin`, so nothing else could refuse it. The I4 twin:
/// the same account's unbound token is admitted.
///
/// The positive half — the bound token *with* its certificate — cannot be
/// driven from here: `actix_web::test::TestRequest` builds every request with
/// no connection data, so no test can put a verified client certificate on
/// it (S-3's EXECUTED note 4). It is pinned in `axiam-auth` against
/// `verify_token_binding`, which `enforce_sender_constraint` calls.
#[actix_rt::test]
async fn a_certificate_bound_device_token_is_refused_on_a_converted_route_without_its_certificate()
{
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let device = service_account(&w.db, w.tenant_id, Some("super-admin")).await;
    let bound = issue_service_account_token(
        device,
        w.tenant_id,
        w.org_id,
        Uuid::new_v4().to_string(),
        Some(CnfClaim::from_certificate_thumbprint(
            "thumbprint-of-the-device-certificate",
        )),
        &auth,
    )
    .unwrap();
    let unbound = service_account_token(&auth, device, w.tenant_id, w.org_id);
    let app = app!(w.db, auth, authz);

    let (status, body) = call(&app, bearer(&Method::GET, "/api/v1/roles", &bound)).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "authentication_failed", "{body}");

    let (status, body) = call(&app, bearer(&Method::GET, "/api/v1/roles", &unbound)).await;
    assert_eq!(status, 200, "{body}");
}

// -------------------------------------------------------------------------
// (d) Tenant and organization scope for a service account
// -------------------------------------------------------------------------

/// `X-Axiam-Tenant` means for a service account what it means for a user:
///
/// * an account in an **ordinary tenant** acts there and nowhere else — naming
///   a neighbour, or the organization scope, is 403;
/// * an account in the **organization scope** acts on a tenant of its own
///   organization, with its global grants — the deployment-wide automation the
///   scope exists for — and on nothing outside the organization;
/// * one whose assignment names particular tenants (`tenant_scope`) reaches
///   those and no other.
///
/// Every refusal is the one a user in the same position gets, compared body for
/// body: there is one implementation, and this is its I4 twin.
#[actix_rt::test]
async fn a_service_account_reaches_another_tenant_only_as_an_organization_principal_would() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let org_scope = organization_tenant(&w.db, w.org_id).await;
    let neighbour = standard_tenant(&w.db, w.org_id, "neighbour").await;
    let elsewhere = {
        let org = SurrealOrganizationRepository::new(w.db.clone())
            .create(CreateOrganization {
                name: "Other Org".into(),
                slug: "other-org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        standard_tenant(&w.db, org.id, "elsewhere").await
    };

    let tenant_sa = service_account(&w.db, w.tenant_id, Some("super-admin")).await;
    let tenant_user = user(&w.db, w.tenant_id, Some("super-admin")).await;
    let org_sa = service_account(&w.db, org_scope, Some("super-admin")).await;
    let org_user = user(&w.db, org_scope, Some("super-admin")).await;
    // An organization-level account confined to the home tenant alone.
    let confined_sa = {
        let (account, _) = SurrealServiceAccountRepository::new(w.db.clone())
            .create(CreateServiceAccount {
                tenant_id: org_scope,
                name: "confined".into(),
                description: None,
            })
            .await
            .unwrap();
        let role = role_named(&w.db, org_scope, "super-admin").await;
        SurrealRoleRepository::new(w.db.clone())
            .assign_to_service_account(
                org_scope,
                account.id,
                role,
                AssignmentScope {
                    tenant_scope: Some(vec![w.tenant_id]),
                    ..AssignmentScope::global()
                },
            )
            .await
            .unwrap();
        account.id
    };
    let app = app!(w.db, auth, authz);

    let roles_in = |token: &str, acting: Option<Uuid>| {
        let req = bearer(&Method::GET, "/api/v1/roles", token);
        match acting {
            Some(t) => req.insert_header(("X-Axiam-Tenant", t.to_string())),
            None => req,
        }
    };
    let sa = |id, home| service_account_token(&auth, id, home, w.org_id);
    let person = |id, home| user_token(&auth, id, home, w.org_id);

    // Refusals, each beside the user in the same position.
    for (who, machine, human, target) in [
        (
            "tenant principal → neighbour",
            sa(tenant_sa, w.tenant_id),
            person(tenant_user, w.tenant_id),
            neighbour,
        ),
        (
            "tenant principal → organization scope",
            sa(tenant_sa, w.tenant_id),
            person(tenant_user, w.tenant_id),
            org_scope,
        ),
        (
            "organization principal → another organization",
            sa(org_sa, org_scope),
            person(org_user, org_scope),
            elsewhere,
        ),
    ] {
        let (status, body) = call(&app, roles_in(&machine, Some(target))).await;
        assert_eq!(status, 403, "{who}: {body}");
        assert_eq!(body["error"], "authorization_denied", "{who}");
        let (human_status, human_body) = call(&app, roles_in(&human, Some(target))).await;
        assert_eq!(
            (status, &body),
            (human_status, &human_body),
            "{who}: a user is answered differently"
        );
    }
    let (status, body) = call(&app, roles_in(&sa(confined_sa, org_scope), Some(neighbour))).await;
    assert_eq!(
        status, 403,
        "confined account → a tenant it does not reach: {body}"
    );
    assert_eq!(
        body["message"],
        "Authorization denied: this account's roles do not reach the requested tenant"
    );

    // What is allowed: its own tenant, named or not; and, for an organization
    // principal, a tenant of its organization — where it sees that tenant's
    // roles, not its own scope's.
    for (who, token, acting) in [
        (
            "tenant principal, own tenant named",
            sa(tenant_sa, w.tenant_id),
            Some(w.tenant_id),
        ),
        (
            "tenant principal, no header",
            sa(tenant_sa, w.tenant_id),
            None,
        ),
        (
            "organization principal → a tenant",
            sa(org_sa, org_scope),
            Some(neighbour),
        ),
        (
            "confined account → its tenant",
            sa(confined_sa, org_scope),
            Some(w.tenant_id),
        ),
    ] {
        let (status, body) = call(&app, roles_in(&token, acting)).await;
        assert_eq!(status, 200, "{who}: {body}");
        let expected = acting.unwrap_or(w.tenant_id).to_string();
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["tenant_id"] == expected.as_str()),
            "{who}: listed another tenant's roles: {body}"
        );
    }
}

/// A PEM PKCS#10 request carrying nothing but a common name.
fn plain_csr(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params
        .serialize_request(&key)
        .expect("csr")
        .pem()
        .expect("pem")
}

fn test_ca_custodians() -> Arc<axiam_pki::CaKeyCustodians> {
    Arc::new(
        axiam_pki::custodians_from_env(Some([0u8; 32])) // gitleaks:allow
            .expect("test CA key custodians"),
    )
}

/// The certificate routes with real PKI services. RBAC allows everything, so
/// the only thing that can refuse an issuance is the CA scope S-1 added.
macro_rules! pki_app {
    ($db:expr, $auth:expr) => {{
        let pki_config = PkiConfig {
            encryption_key: Some([0u8; 32]), // gitleaks:allow
            ..Default::default()
        };
        let ca_repo = SurrealCaCertificateRepository::new($db.clone());
        let cert_repo = SurrealCertificateRepository::new($db.clone());
        let mut state = AppState::for_test($db.clone(), $auth.clone());
        state.pki.ca_service = CaService::new(
            ca_repo.clone(),
            pki_config.clone(),
            Arc::new(tokio::sync::Semaphore::new(4)),
            test_ca_custodians(),
        );
        state.pki.cert_service = CertService::new(
            ca_repo,
            cert_repo,
            pki_config,
            Arc::new(tokio::sync::Semaphore::new(4)),
            test_ca_custodians(),
        );
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($db.clone()))
                        as Arc<dyn TenantScopeResolver>,
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    }};
}

async fn created_id<S, B>(app: &S, req: test::TestRequest, what: &str) -> String
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let (status, body) = call(app, req).await;
    assert_eq!(status, 201, "{what}: {body}");
    body["id"].as_str().unwrap().to_owned()
}

/// S-1's gates hold for a service account. Under the organization CA: refused
/// (404) even to an account living in the organization's reserved tenant,
/// which a human there passes, and whichever tenant it acts on. Under another
/// tenant's signing CA: refused (404). Under the signing CA of the tenant it
/// acts on: issued — the I4 twin.
#[actix_rt::test]
async fn a_service_account_issues_only_under_its_own_tenants_signing_ca() {
    let w = world().await;
    let auth = test_auth_config();
    let org_scope = organization_tenant(&w.db, w.org_id).await;
    let neighbour = standard_tenant(&w.db, w.org_id, "neighbour").await;
    let org_admin = user(&w.db, org_scope, None).await;
    let tenant_sa = service_account(&w.db, w.tenant_id, None).await;
    let org_sa = service_account(&w.db, org_scope, None).await;
    let app = pki_app!(w.db, auth);

    let admin = user_token(&auth, org_admin, org_scope, w.org_id);
    let with_csrf = |req: test::TestRequest| {
        req.insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
    };
    let org_ca = created_id(
        &app,
        with_csrf(bearer(&Method::POST, &format!("/api/v1/organizations/{}/ca-certificates", w.org_id), &admin))
            .set_json(serde_json::json!({"subject": "Org CA", "key_algorithm": "Ed25519", "validity_days": 365})),
        "organization CA",
    )
    .await;
    let signing_ca = |tenant: Uuid| {
        with_csrf(bearer(
            &Method::POST,
            &format!("/api/v1/organizations/{}/tenants/{tenant}/signing-cas", w.org_id),
            &admin,
        ))
        .set_json(serde_json::json!({
            "parent_ca_id": org_ca, "subject": "Tenant CA", "key_algorithm": "Ed25519", "validity_days": 364
        }))
    };
    let ours = created_id(&app, signing_ca(w.tenant_id), "own signing CA").await;
    let theirs = created_id(&app, signing_ca(neighbour), "neighbour signing CA").await;

    let sign = |token: &str, issuer: &str| {
        bearer(&Method::POST, "/api/v1/certificates/sign-csr", token).set_json(serde_json::json!({
            "issuer_ca_id": issuer,
            "csr_pem": plain_csr("unit-7"),
            "cert_type": "Device",
            "validity_days": 30
        }))
    };
    let tenant_token = service_account_token(&auth, tenant_sa, w.tenant_id, w.org_id);
    let org_token = service_account_token(&auth, org_sa, org_scope, w.org_id);

    let acting_on = |req: test::TestRequest, tenant: Uuid| {
        req.insert_header(("X-Axiam-Tenant", tenant.to_string()))
    };
    for (who, req) in [
        (
            "tenant account, organization CA",
            sign(&tenant_token, &org_ca),
        ),
        (
            "tenant account, neighbour's CA",
            sign(&tenant_token, &theirs),
        ),
        (
            "organization-scope account, organization CA",
            sign(&org_token, &org_ca),
        ),
        (
            "organization-scope account acting on the tenant, organization CA",
            acting_on(sign(&org_token, &org_ca), w.tenant_id),
        ),
        (
            "organization-scope account acting on the tenant, neighbour's CA",
            acting_on(sign(&org_token, &theirs), w.tenant_id),
        ),
    ] {
        let (status, body) = call(&app, req).await;
        assert_eq!(status, 404, "{who}: {body}");
    }

    // An organization-level account is an organization principal for
    // everything but the organization CA: acting on the tenant, it issues
    // under that tenant's signing CA, and the leaf belongs to that tenant.
    let (status, body) = call(&app, acting_on(sign(&org_token, &ours), w.tenant_id)).await;
    assert_eq!(
        status, 201,
        "organization-scope account acting on the tenant: {body}"
    );
    assert_eq!(body["tenant_id"], w.tenant_id.to_string());

    let (status, body) = call(&app, sign(&tenant_token, &ours)).await;
    assert_eq!(status, 201, "own signing CA: {body}");
    assert_eq!(body["issuer_ca_id"], ours.as_str());
    assert_eq!(body["tenant_id"], w.tenant_id.to_string());

    // The human I4 twin of the organization-scope refusal above.
    let (status, body) = call(&app, with_csrf(sign(&admin, &org_ca))).await;
    assert_eq!(
        status, 201,
        "organization administrator, organization CA: {body}"
    );
}

// -------------------------------------------------------------------------
// (e) CSRF and audit
// -------------------------------------------------------------------------

/// T-200 still holds for a machine caller and does not widen: a bearer-only
/// service-account write needs no CSRF token; the same write with a session
/// cookie beside the bearer header — the shape a cross-site forgery takes —
/// is refused without one.
#[actix_rt::test]
async fn the_csrf_exemption_covers_a_bearer_only_service_account_and_nothing_wider() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let sa = service_account(&w.db, w.tenant_id, Some("admin")).await;
    let token = service_account_token(&auth, sa, w.tenant_id, w.org_id);
    let app = app!(w.db, auth, authz);

    let create = |name: &str| {
        bearer(&Method::POST, "/api/v1/groups", &token)
            .set_json(serde_json::json!({"name": name, "description": "x", "metadata": null}))
    };
    let (status, body) = call(&app, create("bearer-only")).await;
    assert_eq!(status, 201, "{body}");

    let (status, body) = call(
        &app,
        create("with-cookie").insert_header(("Cookie", format!("axiam_access={token}"))),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    // Refused by the CSRF middleware, not by RBAC: the account holds `admin`.
    assert_eq!(
        body["message"], "Authorization denied: CSRF validation failed",
        "{body}"
    );
}

/// A service account's write is audited as a service account, a user's as a
/// user, through the production audit middleware on a converted route.
#[actix_rt::test]
async fn a_service_account_write_on_a_converted_route_is_audited_as_one() {
    let w = world().await;
    let auth = test_auth_config();
    let authz = engine(&w.db);
    let sa = service_account(&w.db, w.tenant_id, Some("admin")).await;
    let person = user(&w.db, w.tenant_id, Some("admin")).await;
    let audit = SurrealAuditLogRepository::new(w.db.clone());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(authz.clone()))
            .app_data(web::Data::new(AppState::for_test(
                w.db.clone(),
                auth.clone(),
            )))
            .wrap(axiam_audit::middleware::AuditMiddleware::spawn(
                audit.clone(),
            ))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;

    for (actor, token, expected) in [
        (
            sa,
            service_account_token(&auth, sa, w.tenant_id, w.org_id),
            ActorType::ServiceAccount,
        ),
        (
            person,
            user_token(&auth, person, w.tenant_id, w.org_id),
            ActorType::User,
        ),
    ] {
        let (status, body) = call(
            &app,
            bearer(&Method::POST, "/api/v1/roles", &token).set_json(serde_json::json!({
                "name": format!("r-{actor}"), "description": "d", "is_global": false
            })),
        )
        .await;
        assert_eq!(status, 201, "{body}");

        let filter = AuditLogFilter {
            actor_id: Some(actor),
            ..Default::default()
        };
        let mut entries = Vec::new();
        for _ in 0..100 {
            entries = audit
                .list(
                    w.tenant_id,
                    filter.clone(),
                    Pagination {
                        offset: 0,
                        limit: 10,
                        search: None,
                    },
                )
                .await
                .unwrap()
                .items;
            if !entries.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let entry = entries.first().expect("the write was audited");
        assert_eq!(entry.actor_type, expected);
        assert_eq!(entry.action, "POST /api/v1/roles");
    }
}

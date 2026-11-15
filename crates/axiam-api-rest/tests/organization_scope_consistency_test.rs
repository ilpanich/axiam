//! The two layers that keep organization-level actions inside the
//! organization scope must name the same set of actions.
//!
//! # What can drift, and why it is invisible
//!
//! B-04 is enforced twice, on purpose:
//!
//! 1. `handlers::org_scope::require_organization_principal` refuses a caller
//!    whose own record does not live in the organization scope. This is the
//!    load-bearing layer.
//! 2. `axiam_core::permission_scope::ORGANIZATION_LEVEL_ACTIONS` tells the
//!    seeder in `axiam-db` which actions to withhold from an ordinary tenant's
//!    roles — and, since the B-04 follow-up, which to *revoke* from tenants an
//!    older version granted them to.
//!
//! Both directions of disagreement fail silently:
//!
//! * A **new organization-level handler** whose action is not in the list gets
//!   the guard but leaves every tenant `super-admin` still holding the grant.
//!   Nothing breaks — the guard covers it — so nobody notices the second layer
//!   quietly stopped covering that action.
//! * An **action in the list that no guarded handler names**, or that an
//!   *unguarded* handler also names, silently removes a capability from every
//!   tenant administrator in every deployment on the next boot. That one is
//!   worse, and it is precisely what would happen if `email_config:write` were
//!   added: the organization handlers are guarded, but the tenant-level ones
//!   are not, and withholding the action would take a tenant administrator's
//!   own mail configuration with it.
//!
//! So this file reads the handler sources rather than trusting a comment, and
//! pins one rule:
//!
//! > An action belongs in `ORGANIZATION_LEVEL_ACTIONS` **exactly when every
//! > handler that requires it also carries the scope guard** — and at least one
//! > handler requires it.
//!
//! Reading the source is deliberate. The alternative — a hand-maintained table
//! of "these handlers are organization-level" — is a third thing to keep in
//! sync, and it would go stale in the same invisible direction as the first
//! two.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_core::permission_scope::ORGANIZATION_LEVEL_ACTIONS;

/// One handler function as read out of the source.
#[derive(Debug)]
struct Handler {
    file: String,
    name: String,
    /// The action from the first `RequirePermission::new("…")` in the body.
    /// `None` for helpers and for handlers that authorize some other way.
    action: Option<String>,
    /// Whether the body calls `require_organization_principal`.
    scope_guarded: bool,
    /// Whether the body calls the whole-organization form,
    /// `require_organization_principal(…)`.
    org_guard: bool,
    /// Whether the body calls the per-tenant form,
    /// `require_organization_principal_for_tenant(…)`.
    tenant_guard: bool,
}

fn handlers_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers")
}

/// Split a handler module into `async fn` bodies.
///
/// Deliberately crude: a function starts at an `async fn` at column zero and
/// ends at the closing `}` at column zero. Every handler in this crate is
/// written that way, and `handler_scan_finds_the_handlers` fails loudly if a
/// reformat ever makes this read nothing — a parser that silently matches
/// nothing would turn every assertion below into a vacuous pass.
fn parse_handlers(file: &str, source: &str) -> Vec<Handler> {
    let mut out = Vec::new();
    let mut current: Option<Handler> = None;

    for line in source.lines() {
        let starts_fn = line.starts_with("async fn ") || line.starts_with("pub async fn ");
        if starts_fn {
            if let Some(h) = current.take() {
                out.push(h);
            }
            let name = line
                .trim_start_matches("pub ")
                .trim_start_matches("async fn ")
                .split(['(', '<'])
                .next()
                .unwrap_or("")
                .to_string();
            current = Some(Handler {
                file: file.to_string(),
                name,
                action: None,
                scope_guarded: false,
                org_guard: false,
                tenant_guard: false,
            });
            continue;
        }

        let Some(h) = current.as_mut() else { continue };

        if line == "}" {
            out.push(current.take().expect("just checked"));
            continue;
        }
        if h.action.is_none()
            && let Some(rest) = line.split_once("RequirePermission::new(")
            && let Some(action) = rest.1.split('"').nth(1)
        {
            h.action = Some(action.to_string());
        }
        if line.contains("require_organization_principal") {
            h.scope_guarded = true;
        }
        if line.contains("require_organization_principal(") {
            h.org_guard = true;
        }
        if line.contains("require_organization_principal_for_tenant(") {
            h.tenant_guard = true;
        }
    }
    if let Some(h) = current {
        out.push(h);
    }
    out
}

fn all_handlers() -> Vec<Handler> {
    let dir = handlers_dir();
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("handlers directory should be readable") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default()
            .to_string();
        // The guard's own module defines the function; it declares no handler.
        if file == "org_scope.rs" {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("handler source should be readable");
        out.extend(parse_handlers(&file, &source));
    }
    out
}

/// For each action: how many handlers require it, and how many of those also
/// carry the scope guard.
fn action_guard_tally() -> BTreeMap<String, (Vec<String>, Vec<String>)> {
    let mut tally: BTreeMap<String, (Vec<String>, Vec<String>)> = BTreeMap::new();
    for h in all_handlers() {
        let Some(action) = h.action.clone() else {
            continue;
        };
        let site = format!("{}::{}", h.file.trim_end_matches(".rs"), h.name);
        let entry = tally.entry(action).or_default();
        if h.scope_guarded {
            entry.0.push(site);
        } else {
            entry.1.push(site);
        }
    }
    tally
}

/// The parser must actually find things. Without this, a rename or a reformat
/// turns every other assertion in this file into a pass that measures nothing.
#[test]
fn handler_scan_finds_the_handlers() {
    let handlers = all_handlers();
    let with_permission = handlers.iter().filter(|h| h.action.is_some()).count();
    let guarded = handlers.iter().filter(|h| h.scope_guarded).count();

    assert!(
        with_permission > 100,
        "only {with_permission} handlers with a RequirePermission were found — \
         the source scan is broken, not the codebase"
    );
    assert!(
        guarded >= 16,
        "only {guarded} handlers carry require_organization_principal; the \
         B-04 fix applied it to at least 16 — the source scan is broken, or \
         the guard was removed"
    );
}

/// The rule, in the direction that leaves a hole: a handler is
/// organization-scoped but its action is still seeded to tenant roles.
#[test]
fn every_scope_guarded_action_is_declared_organization_level() {
    let mut missing = Vec::new();
    for (action, (guarded, unguarded)) in action_guard_tally() {
        if guarded.is_empty() {
            continue;
        }
        // An action shared with an unguarded handler cannot be withheld — see
        // the module docs. That case is asserted the other way round below.
        if !unguarded.is_empty() {
            continue;
        }
        // A plain `:list`/`:get` action can never be in the list: the seeded
        // `viewer` role is granted every such action and is not filtered
        // against it (`axiam_core::permission_scope`'s
        // `the_list_holds_no_read_action`). `tenants:get` is the case — its
        // only handler binds the path tenant to the caller's reach (SA-02,
        // N9), and that guard is what refuses a tenant administrator.
        if action.ends_with(":list") || action.ends_with(":get") {
            continue;
        }
        if !ORGANIZATION_LEVEL_ACTIONS.contains(&action.as_str()) {
            missing.push(format!(
                "`{action}` — every handler requiring it is scope-guarded \
                 ({}), but it is absent from ORGANIZATION_LEVEL_ACTIONS, so \
                 every tenant's super-admin is still seeded with it",
                guarded.join(", ")
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "organization-level actions missing from \
         axiam_core::permission_scope::ORGANIZATION_LEVEL_ACTIONS:\n  - {}",
        missing.join("\n  - ")
    );
}

/// The rule, in the direction that removes a capability: an action is declared
/// organization-level but some handler needs it at tenant level, or no handler
/// needs it at all.
#[test]
fn every_declared_organization_level_action_is_exclusively_organization_level() {
    let tally = action_guard_tally();
    let mut wrong = Vec::new();

    for action in ORGANIZATION_LEVEL_ACTIONS {
        match tally.get(*action) {
            None => wrong.push(format!(
                "`{action}` is declared organization-level but no handler \
                 requires it — withholding it removes a capability nothing \
                 grants back"
            )),
            Some((guarded, unguarded)) if !unguarded.is_empty() => wrong.push(format!(
                "`{action}` is declared organization-level but is ALSO \
                 required by handler(s) with no scope guard ({}) — withholding \
                 it from tenant roles takes that tenant-level capability away \
                 too. Either guard those handlers or drop the action from the \
                 list. (scope-guarded sites: {})",
                unguarded.join(", "),
                if guarded.is_empty() {
                    "none".to_string()
                } else {
                    guarded.join(", ")
                }
            )),
            Some(_) => {}
        }
    }

    assert!(
        wrong.is_empty(),
        "ORGANIZATION_LEVEL_ACTIONS disagrees with the handlers:\n  - {}",
        wrong.join("\n  - ")
    );
}

/// A typo in the list is invisible from either side: it matches no permission,
/// so nothing is withheld and nothing complains.
#[test]
fn every_declared_organization_level_action_exists_in_the_registry() {
    let registry: BTreeSet<&str> = PERMISSION_REGISTRY.iter().map(|(a, _)| *a).collect();
    let unknown: Vec<&&str> = ORGANIZATION_LEVEL_ACTIONS
        .iter()
        .filter(|a| !registry.contains(**a))
        .collect();
    assert!(
        unknown.is_empty(),
        "ORGANIZATION_LEVEL_ACTIONS names actions absent from \
         PERMISSION_REGISTRY (typo?): {unknown:?}"
    );
}

// ---------------------------------------------------------------------------
// SA-02: every `/organizations/{org_id}/**` route, and the guard it must reach
// ---------------------------------------------------------------------------
//
// The tests above reason from the *actions*, so they cannot see a handler that
// lacks the guard altogether: an unguarded organization-level handler is simply
// "an action required by an unguarded handler", which is also what an ordinary
// tenant handler looks like. That is how `set_org_settings`, `get_org_settings`
// and `export_audit` shipped without it (N8, N9).
//
// So the routes are listed here explicitly, each with the guard its handler
// must call. The list is checked against `server.rs` in both directions: a
// route registered there and missing here fails, so a new organization route
// cannot arrive without someone deciding how it is guarded.

/// How a route under `/organizations/{org_id}` is kept inside the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Guard {
    /// `require_organization_principal`: an act on the organization as a whole.
    Organization,
    /// `require_organization_principal_for_tenant`: an organization-level act on
    /// the one tenant the path names, which the caller's reach must cover.
    OrganizationForTenant,
    /// A read that carries neither guard, with the reason it may not. Only a
    /// `GET` may be exempt.
    Exempt(&'static str),
}

/// Every route under `/organizations/{org_id}` as `(method, path, handler,
/// guard)`, `handler` being `module::function` under `src/handlers`.
const ORGANIZATION_ROUTES: &[(&str, &str, &str, Guard)] = &[
    (
        "GET",
        "/organizations/{org_id}",
        "organizations::get",
        Guard::Exempt(
            "the caller's own organization record (path bound to user.org_id); \
             the tenant switcher reads it",
        ),
    ),
    (
        "PUT",
        "/organizations/{org_id}",
        "organizations::update",
        Guard::Organization,
    ),
    (
        "DELETE",
        "/organizations/{org_id}",
        "organizations::delete",
        Guard::Organization,
    ),
    (
        "GET",
        "/organizations/{org_id}/settings",
        "settings::get_org_settings",
        Guard::Organization,
    ),
    (
        "PUT",
        "/organizations/{org_id}/settings",
        "settings::set_org_settings",
        Guard::Organization,
    ),
    (
        "GET",
        "/organizations/{org_id}/email-config",
        "email_config::get_org_email_config",
        Guard::Organization,
    ),
    (
        "PUT",
        "/organizations/{org_id}/email-config",
        "email_config::set_org_email_config",
        Guard::Organization,
    ),
    (
        "DELETE",
        "/organizations/{org_id}/email-config",
        "email_config::delete_org_email_config",
        Guard::Organization,
    ),
    (
        "POST",
        "/organizations/{org_id}/email-config/test",
        "email_config::test_org_email_config",
        Guard::Organization,
    ),
    (
        "POST",
        "/organizations/{org_id}/tenants",
        "tenants::create",
        Guard::Organization,
    ),
    (
        "GET",
        "/organizations/{org_id}/tenants",
        "tenants::list",
        Guard::Exempt(
            "the roster is filtered to the caller's own reach \
             (`reachable_tenants`): an ordinary tenant principal sees its own tenant",
        ),
    ),
    (
        "POST",
        "/organizations/{org_id}/tenants/{tenant_id}/audit-export",
        "tenants::export_audit",
        Guard::OrganizationForTenant,
    ),
    (
        "GET",
        "/organizations/{org_id}/tenants/{tenant_id}",
        "tenants::get",
        Guard::OrganizationForTenant,
    ),
    (
        "PUT",
        "/organizations/{org_id}/tenants/{tenant_id}",
        "tenants::update",
        Guard::Organization,
    ),
    (
        "DELETE",
        "/organizations/{org_id}/tenants/{tenant_id}",
        "tenants::delete",
        Guard::Organization,
    ),
    (
        "POST",
        "/organizations/{org_id}/ca-certificates",
        "ca_certificates::generate",
        Guard::Organization,
    ),
    (
        "GET",
        "/organizations/{org_id}/ca-certificates",
        "ca_certificates::list",
        Guard::Exempt(
            "organization CA certificates are the public trust material every \
             tenant of the organization chains to; no private key is returned",
        ),
    ),
    (
        "POST",
        "/organizations/{org_id}/ca-certificates/import",
        "ca_certificates::import",
        Guard::Organization,
    ),
    (
        "GET",
        "/organizations/{org_id}/ca-certificates/{id}",
        "ca_certificates::get",
        Guard::Exempt("as for the list: one public organization CA certificate"),
    ),
    (
        "POST",
        "/organizations/{org_id}/ca-certificates/{id}/revoke",
        "ca_certificates::revoke",
        Guard::Organization,
    ),
    (
        "PUT",
        "/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor",
        "ca_certificates::set_mtls_trust_anchor",
        Guard::Organization,
    ),
    (
        "POST",
        "/organizations/{org_id}/ca-certificates/{id}/migrate-custody",
        "ca_certificates::migrate_custody",
        Guard::Organization,
    ),
    (
        "POST",
        "/organizations/{org_id}/tenants/{tenant_id}/signing-cas",
        "ca_certificates::generate_intermediate",
        Guard::OrganizationForTenant,
    ),
    (
        "GET",
        "/organizations/{org_id}/tenants/{tenant_id}/signing-cas",
        "ca_certificates::list_intermediates",
        Guard::Exempt(
            "public signing-CA certificates of the named tenant, bound only to \
             user.org_id. Not bound to the caller's reach: noted as a follow-up \
             in SA-02, not changed by it",
        ),
    ),
    (
        "POST",
        "/organizations/{org_id}/tenants/{tenant_id}/signing-cas/sign-csr",
        "ca_certificates::sign_intermediate_csr",
        Guard::OrganizationForTenant,
    ),
];

/// The `(method, path, handler)` of every route `server.rs` registers under
/// `/organizations/{org_id}`.
///
/// Read with whitespace removed, one `web::resource(` at a time: the first
/// string literal is the path, and every `web::<method>().to(handlers::…::<C>`
/// after it, up to the next resource, is a route on it. Paths contain no
/// whitespace, so removing it changes no literal this reads.
fn registered_organization_routes() -> BTreeSet<(String, String, String)> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/server.rs");
    let source: String = std::fs::read_to_string(&path)
        .expect("server.rs should be readable")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();

    let mut out = BTreeSet::new();
    for chunk in source.split("web::resource(").skip(1) {
        let Some(route_path) = chunk.split('"').nth(1) else {
            continue;
        };
        if route_path != "/organizations/{org_id}"
            && !route_path.starts_with("/organizations/{org_id}/")
        {
            continue;
        }
        for method in ["get", "post", "put", "patch", "delete"] {
            let needle = format!("web::{method}().to(handlers::");
            for rest in chunk.split(needle.as_str()).skip(1) {
                let handler = rest.split("::<").next().unwrap_or_default();
                out.insert((
                    method.to_uppercase(),
                    route_path.to_string(),
                    handler.to_string(),
                ));
            }
        }
    }
    out
}

/// The scan must find the routes; an empty set would make the next test a
/// comparison of two lists that both say nothing.
#[test]
fn organization_route_scan_finds_the_routes() {
    let routes = registered_organization_routes();
    assert!(
        routes.len() >= ORGANIZATION_ROUTES.len(),
        "only {} organization routes were read out of server.rs — the scan is \
         broken, not the router: {routes:?}",
        routes.len()
    );
}

/// The list is the router: a route registered under `/organizations/{org_id}`
/// and absent here fails, and so does a listed route the router no longer has.
#[test]
fn every_organization_route_is_on_the_guard_list() {
    let registered = registered_organization_routes();
    let listed: BTreeSet<(String, String, String)> = ORGANIZATION_ROUTES
        .iter()
        .map(|(m, p, h, _)| (m.to_string(), p.to_string(), h.to_string()))
        .collect();

    let unlisted: Vec<_> = registered.difference(&listed).collect();
    let stale: Vec<_> = listed.difference(&registered).collect();
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "ORGANIZATION_ROUTES disagrees with server.rs.\n  \
         registered but not listed (decide its guard and add it): {unlisted:?}\n  \
         listed but not registered (remove it): {stale:?}"
    );
}

/// The rule itself: a listed route reaches a handler that calls the guard the
/// list names, and only a read is exempt.
#[test]
fn every_listed_organization_route_reaches_its_guard() {
    let handlers = all_handlers();
    let mut wrong = Vec::new();

    for (method, path, handler, guard) in ORGANIZATION_ROUTES {
        let (module, function) = handler
            .split_once("::")
            .expect("handler is `module::function`");
        let file = format!("{module}.rs");
        let Some(h) = handlers
            .iter()
            .find(|h| h.file == file && h.name == function)
        else {
            wrong.push(format!(
                "{method} {path}: handler `{handler}` not found in src/handlers"
            ));
            continue;
        };
        match guard {
            Guard::Organization if !h.org_guard => wrong.push(format!(
                "{method} {path} reaches `{handler}`, which does not call \
                 require_organization_principal"
            )),
            Guard::OrganizationForTenant if !h.tenant_guard => wrong.push(format!(
                "{method} {path} reaches `{handler}`, which does not call \
                 require_organization_principal_for_tenant"
            )),
            Guard::Exempt(reason) if *method != "GET" => wrong.push(format!(
                "{method} {path} is exempt ({reason}), but only a GET may be"
            )),
            Guard::Exempt(reason) if reason.trim().is_empty() => {
                wrong.push(format!("{method} {path} is exempt without a reason"))
            }
            _ => {}
        }
    }

    assert!(
        wrong.is_empty(),
        "organization routes without their guard:\n  - {}",
        wrong.join("\n  - ")
    );
}

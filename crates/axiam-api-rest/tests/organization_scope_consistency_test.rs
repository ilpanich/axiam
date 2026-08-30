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

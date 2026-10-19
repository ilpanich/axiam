//! Every `RateLimitShared` bucket name in the workspace is registered once,
//! except for the few that several routes deliberately share.
//!
//! # Why a repeat is a bug
//!
//! The shared counter keys a request `"{endpoint}:{ip}"`. Two registrations
//! under one name are therefore **one counter**, not two: a flood on either
//! route spends the other's allowance, and the two registrations can disagree
//! about the limit and about the cold-entry seeding rule (`new` seeds a key the
//! counter has not seen pro-rata, `browser_preset` gives it the whole budget),
//! so which of them the counter obeys depends on which request reached it
//! first. #614 added five authenticated federation flow routes and gave two of
//! them the names the public first-time-SSO routes already used
//! (`federation_saml_acs`, `federation_oidc_callback`) while T-474 said "each in
//! a bucket of its own"; nothing noticed (R101W2-03, #632).
//!
//! # How the names are collected
//!
//! By reading the source, as `organization_scope_consistency_test.rs` does for
//! its handlers: this crate has no registration table to ask, because the names
//! are literals at the `.wrap(RateLimitShared::<C>::…)` call sites, and a table
//! kept beside them would be a second thing to keep in step. The scan covers
//! `crates/*/src` (so a bucket registered from another crate, like
//! `axiam-scim`'s, is seen), reads the first argument of `new`,
//! `browser_preset`, `admin_preset` and `new_client_identity_aware`, and resolves a `const`
//! name in the same file. It refuses, rather than skips, a constructor it does
//! not know and a name it cannot resolve, and
//! `the_scan_finds_the_registrations` fails if a reformat ever makes it read
//! nothing: a scan that silently matches nothing would turn the real assertion
//! into a vacuous pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The constructors whose first argument is the shared-counter endpoint name.
const CONSTRUCTORS: [&str; 4] = [
    "new",
    "browser_preset",
    "admin_preset",
    "new_client_identity_aware",
];

/// Buckets that are registered more than once **on purpose**: several routes of
/// one API deliberately spend a single allowance. Each entry names the exact
/// number of registrations, so neither a stale entry (a name that no longer
/// repeats) nor one more registration under the same name passes unnoticed.
/// Adding a name here is a decision about the allowance, not a way to silence
/// the test: say which routes share it and why one allowance is the intent.
const SHARED_ON_PURPOSE: &[(&str, usize, &str)] = &[
    (
        "directory_config",
        3,
        // `PUT`, `PATCH` and `DELETE` on `/api/v1/tenants/{tenant_id}/directory`
        // — three methods of one resource, each wrapped on its own `Route`
        // (`Route::wrap` is per method), counting in one bucket. The comment
        // above the registration in `server.rs` states it: "The three methods
        // of the configuration resource count in one shared bucket
        // (`directory_config`), the link route in its own (`directory_link`)".
        "the PUT, PATCH and DELETE of the one directory configuration resource",
    ),
    (
        "uma_rreg",
        2,
        // `/rreg/resource_set` and `/rreg/resource_set/{id}` — the one UMA
        // resource-registration API (FedAuthz §2.2), registered as two
        // resources because of the path parameter. It has a counter of its own,
        // apart from `uma_perm`, on purpose (the comment above the
        // registration: registration is administrative traffic and must not
        // consume the permission endpoint's allowance); within the API the
        // collection and the item routes share it.
        "the collection and the item routes of the UMA resource-registration API",
    ),
    // `login` is deliberately absent. `/auth/login` is registered once; the
    // other `"login"` the tree spells is the doc example in
    // `middleware/rate_limit_shared.rs`, which this scan skips (below). The
    // OPAQUE start/finish routes share `/login`'s *limit* but each has a
    // bucket name of its own.
];

/// One `RateLimitShared` registration read out of the source.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Registration {
    /// Path relative to `crates/`.
    file: String,
    line: usize,
    name: String,
}

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/axiam-api-rest has a parent")
        .to_path_buf()
}

/// Every `.rs` file under `crates/*/src`, except the file that *defines*
/// `RateLimitShared`. That file holds only a doc example of the constructor and
/// its own unit tests, which build throwaway middlewares (`"revoke"`,
/// `"oauth2_authorize"`) to test the type; none is a route's bucket.
fn source_files() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("readable source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    for krate in std::fs::read_dir(crates_dir()).expect("crates directory") {
        let src = krate.expect("crate entry").path().join("src");
        if src.is_dir() {
            walk(&src, &mut files);
        }
    }
    files.retain(|p| !p.ends_with("middleware/rate_limit_shared.rs"));
    files.sort();
    files
}

/// The source with every whole-line comment (`//`, `///`, `//!`) blanked, line
/// count preserved, so a doc example does not read as a registration and line
/// numbers still point into the real file.
fn without_comment_lines(source: &str) -> String {
    source
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("//") {
                ""
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The value of `const NAME: &str = "…";` in `source`, if there is one.
fn resolve_const(source: &str, ident: &str) -> Option<String> {
    let needle = format!("const {ident}: &str =");
    let rest = &source[source.find(&needle)? + needle.len()..];
    let rest = rest.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

/// Every registration in one file. Panics on a constructor it does not know or
/// a name it cannot resolve: a registration the scan cannot read is one the
/// uniqueness rule would silently not cover.
fn registrations_in(file: &str, raw: &str) -> Vec<Registration> {
    const MARK: &str = "RateLimitShared::<";
    let text = without_comment_lines(raw);
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find(MARK).map(|i| i + from) {
        from = at + MARK.len();
        // `RateLimitShared::<C>::ctor(` — a type in a type position (no `>::`
        // right after the generics) is not a registration.
        let Some(close) = text[from..].find('>').map(|i| i + from) else {
            continue;
        };
        let Some(after) = text[close..].strip_prefix(">::") else {
            continue;
        };
        let line = text[..at].matches('\n').count() + 1;
        let ctor: String = after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        assert!(
            CONSTRUCTORS.contains(&ctor.as_str()),
            "{file}:{line}: `RateLimitShared::<…>::{ctor}` is not a constructor this scan knows \
             ({CONSTRUCTORS:?}); teach the scan about it so its bucket name is counted"
        );
        let args = after[ctor.len()..]
            .strip_prefix('(')
            .unwrap_or_else(|| panic!("{file}:{line}: `{ctor}` is not called here"))
            .trim_start();
        let name = if let Some(literal) = args.strip_prefix('"') {
            literal[..literal.find('"').expect("closed literal")].to_string()
        } else {
            let ident: String = args
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            resolve_const(raw, &ident).unwrap_or_else(|| {
                panic!(
                    "{file}:{line}: the bucket name `{ident}` is neither a string literal nor a \
                     `const {ident}: &str = \"…\"` in this file, so the duplicate-name scan \
                     cannot read it; pass a literal or a const"
                )
            })
        };
        out.push(Registration {
            file: file.to_string(),
            line,
            name,
        });
    }
    out
}

fn all_registrations() -> Vec<Registration> {
    let root = crates_dir();
    source_files()
        .iter()
        .flat_map(|path| {
            let raw = std::fs::read_to_string(path).expect("readable source file");
            let rel = path.strip_prefix(&root).unwrap().display().to_string();
            registrations_in(&rel, &raw)
        })
        .collect()
}

fn by_name(registrations: &[Registration]) -> BTreeMap<&str, Vec<&Registration>> {
    let mut map: BTreeMap<&str, Vec<&Registration>> = BTreeMap::new();
    for r in registrations {
        map.entry(r.name.as_str()).or_default().push(r);
    }
    map
}

/// The names that break the rule: any name registered more than once that the
/// allow-list does not cover, any allow-listed name whose registration count is
/// not the stated one.
fn violations(registrations: &[Registration], allowed: &[(&str, usize, &str)]) -> Vec<String> {
    let mut out = Vec::new();
    for (name, regs) in by_name(registrations) {
        let places = || {
            regs.iter()
                .map(|r| format!("{}:{}", r.file, r.line))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match allowed.iter().find(|(n, _, _)| *n == name) {
            None if regs.len() > 1 => out.push(format!(
                "bucket `{name}` is registered {} times ({}); the shared counter keys \
                 `{{endpoint}}:{{ip}}`, so these routes spend one allowance. Rename all but one, \
                 or — if several routes of one API are meant to share an allowance — add it to \
                 SHARED_ON_PURPOSE with the reason",
                regs.len(),
                places()
            )),
            Some((_, expected, _)) if regs.len() != *expected => out.push(format!(
                "bucket `{name}` is allowed to be shared by exactly {expected} registrations but \
                 has {} ({}); update SHARED_ON_PURPOSE only if the sharing is still intended",
                regs.len(),
                places()
            )),
            _ => {}
        }
    }
    for (name, _, _) in allowed {
        if !registrations.iter().any(|r| r.name == *name) {
            out.push(format!(
                "SHARED_ON_PURPOSE names `{name}`, which no route registers; remove the stale entry"
            ));
        }
    }
    out
}

/// The rule: no endpoint name is passed to `RateLimitShared` twice, bar the
/// allow-list. Reads every real registration in the workspace.
#[test]
fn every_rate_limit_bucket_name_is_registered_once_bar_the_deliberately_shared() {
    let registrations = all_registrations();
    let found = violations(&registrations, SHARED_ON_PURPOSE);
    assert!(found.is_empty(), "\n{}\n", found.join("\n"));
}

/// R101W2-03 (#632): the two authenticated federation callbacks are named apart
/// from the public first-time-SSO routes that use the unprefixed names.
#[test]
fn the_authenticated_federation_buckets_are_apart_from_the_public_ones() {
    let registrations = all_registrations();
    let names = by_name(&registrations);
    for (public, authenticated) in [
        ("federation_saml_acs", "federation_link_saml_acs"),
        ("federation_oidc_callback", "federation_link_oidc_callback"),
    ] {
        assert_eq!(names.get(public).map(Vec::len), Some(1), "{public}");
        assert_eq!(
            names.get(authenticated).map(Vec::len),
            Some(1),
            "{authenticated}"
        );
    }
}

/// The scan reads the tree it is meant to: a parser that matched nothing, or
/// lost a whole file, would make the rule above vacuous.
#[test]
fn the_scan_finds_the_registrations() {
    let registrations = all_registrations();
    let names = by_name(&registrations);
    assert!(
        registrations.len() >= 80,
        "only {} registrations read; the scan has stopped finding them",
        registrations.len()
    );
    for known in [
        "login",                     // a literal in `axiam-api-rest/src/server.rs`
        "oauth2_token",              // `new_client_identity_aware`
        "federation_oidc_authorize", // `browser_preset`
        "scim",                      // a `const` in another crate (`axiam-scim`)
        "saml_idp_sso",              // behind `#[cfg(feature = "saml")]`
    ] {
        assert!(names.contains_key(known), "`{known}` was not found");
    }
}

/// The detector, on synthetic sources: it flags a repeat, resolves a `const`,
/// ignores a doc example, honours the allow-list's count, and flags a stale
/// entry. This is what makes the real rule fail when it should.
#[test]
fn the_detector_flags_a_repeat_and_honours_the_allow_list() {
    let source = r#"
        const BUCKET: &str = "from_a_const";
        /// .wrap(RateLimitShared::<C>::new("doc_example", 1))
        fn routes() {
            a.wrap(RateLimitShared::<C>::new("dup", 1));
            b.wrap(RateLimitShared::<C>::browser_preset(
                "dup",
                cfg,
            ));
            c.wrap(RateLimitShared::<C>::new(BUCKET, 1));
            d.wrap(RateLimitShared::<C>::new_client_identity_aware("solo", 1, mode));
            let _ty: Option<RateLimitShared<C>> = None;
        }
    "#;
    let regs = registrations_in("synthetic.rs", source);
    let names: Vec<_> = regs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["dup", "dup", "from_a_const", "solo"]);

    let found = violations(&regs, &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("`dup` is registered 2 times"),
        "{found:?}"
    );

    assert!(violations(&regs, &[("dup", 2, "test")]).is_empty());
    let found = violations(&regs, &[("dup", 3, "test")]);
    assert!(found[0].contains("exactly 3"), "{found:?}");
    let found = violations(&regs, &[("dup", 2, "test"), ("gone", 2, "test")]);
    assert!(found[0].contains("stale entry"), "{found:?}");
}

/// A name the scan cannot read is refused, never skipped.
#[test]
#[should_panic(expected = "neither a string literal nor a `const")]
fn a_bucket_name_the_scan_cannot_read_is_refused() {
    registrations_in(
        "synthetic.rs",
        "x.wrap(RateLimitShared::<C>::new(format!(\"a\"), 1));",
    );
}

/// `admin_preset` registers a bucket like `browser_preset` does, so its name
/// enters the uniqueness check (#718).
#[test]
fn an_admin_preset_registration_is_read() {
    let regs = registrations_in(
        "synthetic.rs",
        "a.wrap(RateLimitShared::<C>::admin_preset(\"admin_x\", 5));",
    );
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].name, "admin_x");
}

/// A constructor the scan does not know is refused, never skipped.
#[test]
#[should_panic(expected = "is not a constructor this scan knows")]
fn an_unknown_constructor_is_refused() {
    registrations_in(
        "synthetic.rs",
        "a.wrap(RateLimitShared::<C>::mystery_preset(\"x\", 5));",
    );
}

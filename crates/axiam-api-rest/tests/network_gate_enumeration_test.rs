//! Every write that can create a reply profile, a segment, a network-sensitive
//! grant or assignment, or a certificate binding goes through the network
//! gate first (RADIUS D4, W6.2; `claude_dev/radius-reply-profile-design.md`
//! §5.1 — the T-429 lesson applied to a write surface).
//!
//! # Two halves
//!
//! * **Type-level, for segments and profiles.** Every write method of
//!   `NetworkSegmentRepository` and `ReplyProfileRepository` takes a
//!   `NetworkWriteClearance`, which only `axiam_authz::network_gate` mints. A
//!   segment or profile write without the function does not compile; what this
//!   file pins is the other half of that claim — that nothing else in
//!   production code mints one ([`only_the_gate_mints_a_clearance`]).
//! * **By source scan, for everything older.** Role assignment, permission
//!   grants, certificate binding and the generic resource and permission
//!   writes go through repository methods shared with the seeder and the
//!   erasure paths, so their signatures cannot demand a clearance without
//!   making those paths lie. This file reads every production source in the
//!   workspace, finds every call of those writes, and fails unless the
//!   function containing it calls `network_gate::authorize` (or
//!   `authorize_as`) **before** the write, or is one of the named exemptions
//!   below, each with the reason it is not a path around the gate.
//!
//! Adding a new caller of any of these writes therefore fails this test until
//! it either calls the gate or argues its exemption here, in review.
//!
//! # How the scan reads
//!
//! Deliberately crude, like `organization_scope_consistency_test.rs`: test
//! modules (`#[cfg(test)] mod …`) are dropped, functions are found by their
//! `fn` line and brace-matched, and whitespace is removed so that a call split
//! over lines (`state\n.role_repo\n.assign_to_user(`) reads as one token.
//! `the_scan_finds_the_known_write_sites` fails loudly if a reformat makes it
//! read nothing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Calls that write an edge or a row the gate decides on. Matched against
/// whitespace-free source.
const GUARDED_WRITES: &[&str] = &[
    // Role assignment (§5.3 rows 1–4, §4.2 rules 2 and 3).
    ".assign_to_user(",
    ".assign_to_service_account(",
    ".assign_to_group(",
    ".unassign_from_user(",
    ".unassign_from_service_account(",
    ".unassign_from_group(",
    // Grants on a role (§5.3 row 5, §4.2 rules 1–3).
    ".grant_to_role(",
    ".grant_to_role_with_scopes(",
    ".grant_to_role_with_effect(",
    ".revoke_from_role(",
    // Certificate binding (§5.3 binding rows, H6).
    ".bind_to_service_account(",
    // Role update and delete (§4.2 rule 1, §5.3 row 6).
    "role_repo.update(",
    "role_repo.delete(",
    // The reserved permission namespace (§4.2).
    "permission_repo.create(",
    "permission_repo.update(",
    "permission_repo.delete(",
    "perm_repo.create(",
    "perm_repo.update(",
    "perm_repo.delete(",
    // The reserved resource subtree (§4.1).
    "resource_repo.create(",
    "resource_repo.create_uma_registered(",
    "resource_repo.update(",
    "resource_repo.delete(",
    // Segment and reply-profile writes (the W6.3 routes). These also cannot
    // compile without a `NetworkWriteClearance`; naming them here pins the
    // other half, that the handler asked the gate *before* it reached the
    // repository, and that a new caller of any of them is argued in review.
    "segment_repo.create(",
    "segment_repo.update(",
    "segment_repo.delete(",
    "profile_repo.create(",
    "profile_repo.replace(",
    "profile_repo.delete(",
    // The tenant's Session-Timeout cap (plan 13.6): H3 reads it as the envelope.
    "network_policy_repo.set(",
    // The same edges written as SurrealQL, outside a repository.
    "->has_role->",
    "->grants->",
    "->cert_bound_to->",
];

/// The gate, as a handler calls it.
const GATE_CALLS: &[&str] = &["network_gate::authorize(", "network_gate::authorize_as("];

/// Directories whose files are the writes themselves, not paths to them.
const IMPLEMENTATION_DIRS: &[&str] = &["crates/axiam-db/src/repository/"];

/// Functions that reach one of the writes without the gate, and why that is
/// not a path around it. `(path suffix, function, reason)`.
const EXEMPT: &[(&str, &str, &str)] = &[
    (
        "crates/axiam-db/src/seeder.rs",
        "grant_to_role_idempotent",
        "the seeder makes the three default roles before any principal exists; its \
         network: grants are limited to SEEDED_SUPER_ADMIN_NETWORK_ACTIONS on super-admin \
         (pinned by seeder_default_data_test)",
    ),
    (
        "crates/axiam-db/src/seeder.rs",
        "reconcile_default_role_grants",
        "boot-time reconcile of the same three roles to the same rule; it also revokes \
         the network: grants the seeded roles must not hold",
    ),
    (
        "crates/axiam-api-rest/src/handlers/bootstrap.rs",
        "bootstrap",
        "the one-shot bootstrap assigns the seeded super-admin to the first user under \
         bootstrap_lock; no principal exists yet to hold anything, and the role carries no \
         network:join",
    ),
    (
        "crates/axiam-api-rest/src/handlers/users.rs",
        "delete",
        "a deleted user's assignments are removed; a user is never a device (certificates \
         bind to service accounts only, design note §2), so this only narrows",
    ),
    (
        "crates/axiam-server/src/cleanup.rs",
        "purge_single_user_inner",
        "erasure purge of a user's edges; as for users::delete",
    ),
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/axiam-api-rest sits two levels below the workspace root")
        .to_path_buf()
}

/// Every `.rs` file under some crate's `src/`, as a workspace-relative path.
fn production_sources() -> Vec<(String, String)> {
    let root = workspace_root();
    let mut out = Vec::new();
    let mut stack = vec![root.join("crates")];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable directory") {
            let path = entry.expect("readable entry").path();
            if path.is_dir() {
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // Integration tests, benches, examples and build output are
                // not production code.
                if matches!(name, "tests" | "benches" | "examples" | "target") {
                    continue;
                }
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let rel = path
                    .strip_prefix(&root)
                    .expect("under the root")
                    .to_string_lossy()
                    .replace('\\', "/");
                if !rel.contains("/src/") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("readable source");
                out.push((rel, source));
            }
        }
    }
    out.sort();
    out
}

/// Drop `#[cfg(test)] mod … { … }` blocks.
fn strip_test_modules(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let next_is_mod = lines.get(i + 1).is_some_and(|l| {
            let t = l.trim_start();
            (t.starts_with("mod ") || t.starts_with("pub mod ")) && t.ends_with('{')
        });
        if lines[i].trim() == "#[cfg(test)]" && next_is_mod {
            let mut depth: i64 = 0;
            let mut j = i + 1;
            while j < lines.len() {
                depth += lines[j].matches('{').count() as i64;
                depth -= lines[j].matches('}').count() as i64;
                if depth == 0 {
                    break;
                }
                j += 1;
            }
            i = j + 1;
            continue;
        }
        out.push(lines[i]);
        i += 1;
    }
    out.join("\n")
}

/// The name of a function declared on `line`, if it declares one with a body
/// opening on that line or later.
fn fn_name(line: &str) -> Option<String> {
    let mut t = line.trim_start();
    for prefix in ["pub(crate) ", "pub(super) ", "pub "] {
        if let Some(rest) = t.strip_prefix(prefix) {
            t = rest;
        }
    }
    for prefix in ["const ", "async ", "unsafe "] {
        if let Some(rest) = t.strip_prefix(prefix) {
            t = rest;
        }
    }
    let rest = t.strip_prefix("fn ")?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// One function: its name and its body, whitespace removed.
struct Function {
    name: String,
    flat: String,
}

/// Every function with a body, innermost bodies included (a function nested
/// in an `impl` is found as itself).
fn functions(source: &str) -> Vec<Function> {
    let lines: Vec<&str> = source.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let Some(name) = fn_name(line) else { continue };
        // From the declaration to the brace that closes its body. A trait
        // method declaration (`;` before any `{`) has no body.
        let text = lines[i..].join("\n");
        // The body opens at the first `{` outside the parameter list and any
        // array type (`[u8; 32]`); a `;` there first means no body.
        let mut nesting = 0i64;
        let mut open = None;
        for (k, ch) in text.char_indices() {
            match ch {
                '(' | '[' => nesting += 1,
                ')' | ']' => nesting -= 1,
                ';' if nesting == 0 => break,
                '{' if nesting == 0 => {
                    open = Some(k);
                    break;
                }
                _ => {}
            }
        }
        let Some(open) = open else { continue };
        let mut depth = 0i64;
        let mut end = text.len();
        for (k, ch) in text[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + k + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        let flat: String = text[..end].chars().filter(|c| !c.is_whitespace()).collect();
        out.push(Function { name, flat });
    }
    out
}

/// A call of a guarded write, and whether the gate ran before it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    function: String,
    write: String,
    gated: bool,
}

fn sites() -> Vec<Site> {
    let mut out = BTreeSet::new();
    for (file, source) in production_sources() {
        if IMPLEMENTATION_DIRS.iter().any(|d| file.starts_with(d)) {
            continue;
        }
        let source = strip_test_modules(&source);
        let fns = functions(&source);
        let whole: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        for write in GUARDED_WRITES {
            for (at, _) in whole.match_indices(write) {
                // The innermost function containing this occurrence: the
                // shortest body that holds the surrounding text.
                let window =
                    &whole[at.saturating_sub(80)..(at + write.len() + 40).min(whole.len())];
                let owner = fns
                    .iter()
                    .filter(|f| f.flat.contains(window))
                    .min_by_key(|f| f.flat.len());
                let Some(owner) = owner else {
                    out.insert(Site {
                        file: file.clone(),
                        function: "<outside any function>".into(),
                        write: (*write).into(),
                        gated: false,
                    });
                    continue;
                };
                let write_at = owner.flat.find(window).unwrap_or(0) + 80.min(at);
                let gated = GATE_CALLS
                    .iter()
                    .filter_map(|g| owner.flat.find(g))
                    .any(|g| g < write_at);
                out.insert(Site {
                    file: file.clone(),
                    function: owner.name.clone(),
                    write: (*write).into(),
                    gated,
                });
            }
        }
    }
    out.into_iter().collect()
}

fn exemption(site: &Site) -> Option<&'static str> {
    EXEMPT
        .iter()
        .find(|(file, function, _)| site.file.ends_with(file) && site.function == *function)
        .map(|(_, _, reason)| *reason)
}

/// The oracle of W6.2's enumeration (extended by W6.3 to the segment and
/// profile routes): no write of the kinds the gate decides
/// reaches its repository from a function that has not asked the gate first.
#[test]
fn every_network_relevant_write_is_gated_or_exempt_with_a_reason() {
    let ungated: Vec<String> = sites()
        .into_iter()
        .filter(|s| !s.gated && exemption(s).is_none())
        .map(|s| format!("{}::{} calls {}", s.file, s.function, s.write))
        .collect();
    assert!(
        ungated.is_empty(),
        "these writes reach the repository without network_gate::authorize \
         (design note §5.1); call it before the write, or add an exemption with \
         its reason to EXEMPT:\n  {}",
        ungated.join("\n  ")
    );
}

/// An exemption that no longer matches a site is a hole waiting for a
/// function of that name to be written.
#[test]
fn every_exemption_still_names_a_real_ungated_site() {
    let all = sites();
    for (file, function, _) in EXEMPT {
        assert!(
            all.iter()
                .any(|s| s.file.ends_with(file) && s.function == *function && !s.gated),
            "exemption {file}::{function} matches no ungated write; remove it"
        );
    }
}

/// The scan must actually find things. Every route the design note names
/// (§5.1: `roles.rs`, `permissions.rs`, `certificates.rs` `bind`) and every
/// generic surface W6.2 closed is found, and found gated.
#[test]
fn the_scan_finds_the_known_write_sites() {
    let all = sites();
    let gated: BTreeSet<(String, String)> = all
        .iter()
        .filter(|s| s.gated)
        .map(|s| {
            (
                s.file
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .trim_end_matches(".rs")
                    .to_owned(),
                s.function.clone(),
            )
        })
        .collect();
    for (file, function) in [
        ("roles", "assign_to_user"),
        ("roles", "unassign_from_user"),
        ("roles", "assign_to_service_account"),
        ("roles", "unassign_from_service_account"),
        ("roles", "assign_to_group"),
        ("roles", "unassign_from_group"),
        ("roles", "update"),
        ("roles", "delete"),
        ("permissions", "create"),
        ("permissions", "update"),
        ("permissions", "delete"),
        ("permissions", "grant_to_role"),
        ("permissions", "revoke_from_role"),
        ("certificates", "bind"),
        ("resources", "create"),
        ("resources", "update"),
        ("resources", "delete"),
        ("uma", "register_resource_set"),
        ("uma", "update_resource_set"),
        ("uma", "delete_resource_set"),
        // W6.3: the ten-operation network surface's six writes.
        ("network", "create_segment"),
        ("network", "replace_segment"),
        ("network", "delete_segment"),
        ("network", "create_profile"),
        ("network", "replace_profile"),
        ("network", "delete_profile"),
        // W6.3b: the tenant's Session-Timeout cap.
        ("network", "replace_policy"),
    ] {
        assert!(
            gated.contains(&(file.to_owned(), function.to_owned())),
            "{file}::{function} was not found as a gated write site; found {gated:?}"
        );
    }
}

/// The type-level half: `NetworkWriteClearance` is minted only by the gate.
/// Its constructor has to be public (the gate lives in `axiam-authz`, the type
/// in `axiam-core`), so this is what makes "only the function can mint it"
/// true. Tests may mint one to exercise a repository on its own.
#[test]
fn only_the_gate_mints_a_clearance() {
    const MINT: &str = "issued_by_the_network_gate(";
    let minting: Vec<String> = production_sources()
        .into_iter()
        .filter(|(_, src)| strip_test_modules(src).contains(MINT))
        .map(|(file, _)| file)
        .collect();
    assert_eq!(
        minting,
        vec![
            // The definition.
            "crates/axiam-authz/src/network_gate.rs".to_owned(),
            "crates/axiam-core/src/models/network.rs".to_owned(),
        ],
        "a NetworkWriteClearance is minted outside the gate"
    );
}

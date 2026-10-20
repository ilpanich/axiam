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
//! are literals at the call sites, and a table kept beside them would be a
//! second thing to keep in step. The scan covers `crates/*/src` (so a bucket
//! registered from another crate, like `axiam-scim`'s, is seen) and reads every
//! writer of the counter's `{endpoint}:{key}` space (R110W2-04, #672):
//!
//! * the `RateLimitShared` constructors (`new`, `browser_preset`, `admin_preset`,
//!   `new_client_identity_aware`), called with or without the turbofish. A `const`
//!   name is resolved in the same file. Outside the file that defines the type, an
//!   alias (`use … as`, `type …`) and an `impl` (whose `Self::…` calls cannot be
//!   attributed) are refused. The defining file is read too: its doc text and its
//!   `#[cfg(test)]` module are skipped, nothing else;
//! * the handlers' direct `….check_at(key, …)` / `….check_at_human(key, …)`, whose
//!   prefix is the text before the first `:` of the key's `format!` string
//!   (directly, through a function of the file, or a local `let`);
//! * the four gRPC families, the literals of `shared_endpoint` in
//!   `axiam-api-grpc`.
//!
//! All of them enter one uniqueness check. The scan refuses, rather than skips,
//! a constructor it does not know and a name or prefix it cannot read, and
//! `the_scan_finds_the_registrations` fails if a reformat ever makes it read
//! nothing: a scan that silently matches nothing would turn the real assertion
//! into a vacuous pass. Not read: `increment_by` on the store (the CIBA hint
//! cap's `ciba_hint_cap:` keys) and `check(` on the counter, which no handler
//! calls today.

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

/// The writers of the shared counter's `{endpoint}:{key}` space this scan reads.
const WRITER_MIDDLEWARE: &str = "RateLimitShared";
const WRITER_HANDLER: &str = "check_at";
const WRITER_GRPC: &str = "gRPC family";

/// The counter methods a handler spends a bucket with. `check_at*` on the
/// counter is the only way a handler reaches it; any other `check_at…` call is
/// refused rather than guessed at.
const COUNTER_CALLS: [&str; 2] = ["check_at", "check_at_human"];

/// `check_at…` methods that are not the counter's: the authorisation engine's
/// write-time check (`axiam-authz`), which takes no bucket key.
const NOT_COUNTER_CALLS: [&str; 1] = ["check_at_write_time"];

/// The file that defines `RateLimitShared`, relative to `crates/`.
const DEFINING_FILE: &str = "axiam-api-rest/src/middleware/rate_limit_shared.rs";

/// The file that implements the counter: its `check_at*` methods forward to one
/// another with the caller's key, and take none of their own.
const COUNTER_FILE: &str = "axiam-db/src/rate_limit_counter.rs";

/// The file that maps a gRPC method family to its bucket name, relative to
/// `crates/`.
const GRPC_FILE: &str = "axiam-api-grpc/src/middleware/rate_limit.rs";

/// One writer of the shared counter's endpoint space read out of the source.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Registration {
    /// Path relative to `crates/`.
    file: String,
    line: usize,
    name: String,
    /// Which kind of writer it is (`WRITER_*`).
    writer: &'static str,
}

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/axiam-api-rest has a parent")
        .to_path_buf()
}

/// Every `.rs` file under `crates/*/src`, the defining file included: that file
/// is read too, with its test module and doc text left out (see
/// [`registrations_in_defining_file`]).
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

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The index just past the string literal that opens at `open` (a `"`), plain
/// or raw (`r"…"`, `r#"…"#`).
fn skip_string(b: &[u8], open: usize) -> usize {
    let mut hashes = 0;
    while hashes < open && b[open - 1 - hashes] == b'#' {
        hashes += 1;
    }
    let raw = open > hashes && b[open - 1 - hashes] == b'r';
    let mut i = open + 1;
    while i < b.len() {
        match b[i] {
            b'\\' if !raw => i += 2,
            b'"' if !raw => return i + 1,
            b'"' if b.len() >= i + 1 + hashes
                && b[i + 1..i + 1 + hashes].iter().all(|c| *c == b'#') =>
            {
                return i + 1 + hashes;
            }
            _ => i += 1,
        }
    }
    b.len()
}

/// The index of the bracket closing the one at `open`, skipping string and
/// character literals.
fn matching_close(text: &str, open: usize) -> Option<usize> {
    let b = text.as_bytes();
    let (mut depth, mut i) = (0i32, open);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = skip_string(b, i);
                continue;
            }
            b'\'' if b.get(i + 2) == Some(&b'\'') => {
                i += 3;
                continue;
            }
            b'\'' if b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'') => {
                i += 4;
                continue;
            }
            b'{' | b'(' | b'[' => depth += 1,
            b'}' | b')' | b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The index of the `>` closing a turbofish whose `<` was just consumed.
fn angle_close(after_open: &str) -> Option<usize> {
    let mut depth = 1;
    for (i, c) in after_open.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The source with every `#[cfg(test)]` item blanked (newlines kept), so a test
/// module's throwaway middlewares and counter keys are not routes' buckets.
/// Only the exact `#[cfg(test)]` form is recognised; any other test gate is
/// read as code, which fails closed.
fn without_cfg_test_items(text: &str) -> String {
    const GATE: &str = "#[cfg(test)]";
    let mut bytes = text.as_bytes().to_vec();
    let mut from = 0;
    while let Some(at) = text[from..].find(GATE).map(|i| i + from) {
        let after = at + GATE.len();
        let end = match text[after..].find(['{', ';']).map(|j| j + after) {
            Some(j) if text.as_bytes()[j] == b'{' => {
                matching_close(text, j).unwrap_or(text.len() - 1)
            }
            Some(j) => j,
            None => text.len() - 1,
        };
        for byte in &mut bytes[at..=end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        from = end + 1;
    }
    String::from_utf8(bytes).expect("only whole runs of bytes were replaced by spaces")
}

/// The value of `const NAME: &str = "…";` in `source`, if there is one.
fn resolve_const(source: &str, ident: &str) -> Option<String> {
    let needle = format!("const {ident}: &str =");
    let rest = &source[source.find(&needle)? + needle.len()..];
    let rest = rest.trim_start().strip_prefix('"')?;
    Some(rest[..rest.find('"')?].to_string())
}

/// The statement a token ends: the text since the last `;`, `{` or `}`.
fn statement_before(before: &str) -> &str {
    let start = before.rfind([';', '{', '}']).map_or(0, |i| i + 1);
    before[start..].trim_start()
}

/// Whether `statement` is `[pub] type Alias = …`.
fn declares_type_alias(statement: &str) -> bool {
    let statement = match statement.strip_prefix("pub") {
        Some(rest) => {
            let rest = rest.trim_start();
            match rest.strip_prefix('(') {
                Some(r) => r.split_once(')').map_or(rest, |(_, r)| r).trim_start(),
                None => rest,
            }
        }
        None => statement,
    };
    statement.starts_with("type ")
}

/// Every `RateLimitShared` registration in one file. Panics on a constructor
/// it does not know, a name it cannot resolve, and — outside the file that
/// defines the type — on an alias or an `impl` (whose `Self::…` calls it cannot
/// attribute): a registration the scan cannot read is one the uniqueness rule
/// would silently not cover.
fn registrations_in(file: &str, raw: &str) -> Vec<Registration> {
    scan_middleware(file, raw, &without_comment_lines(raw), false)
}

/// The defining file's registrations: its doc text is blanked as everywhere,
/// and its `#[cfg(test)]` module (throwaway middlewares like `"revoke"`, built
/// to test the type) is left out. Anything else in it counts.
fn registrations_in_defining_file(file: &str, raw: &str) -> Vec<Registration> {
    let text = without_cfg_test_items(&without_comment_lines(raw));
    scan_middleware(file, raw, &text, true)
}

fn scan_middleware(file: &str, raw: &str, text: &str, defining: bool) -> Vec<Registration> {
    const TYPE: &str = "RateLimitShared";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find(TYPE).map(|i| i + from) {
        from = at + TYPE.len();
        // `RateLimitSharedService` and `MyRateLimitShared` are other names.
        if text[..at].chars().next_back().is_some_and(is_ident)
            || text[from..].chars().next().is_some_and(is_ident)
        {
            continue;
        }
        let line = text[..at].matches('\n').count() + 1;
        let tail = text[from..].trim_start();
        if !defining {
            let statement = statement_before(&text[..at]);
            assert!(
                !tail.starts_with("as ") && !declares_type_alias(statement),
                "{file}:{line}: an alias of `RateLimitShared` outside the file that defines it \
                 hides its constructor calls from the duplicate-name scan; call it by its name"
            );
            assert!(
                !statement.starts_with("impl"),
                "{file}:{line}: an `impl` of `RateLimitShared` outside the file that defines it: \
                 its `Self::…` constructor calls cannot be attributed by the duplicate-name scan; \
                 define constructors beside the type"
            );
        }
        // `RateLimitShared::<C>::ctor(` or, with the type inferred,
        // `RateLimitShared::ctor(`. A type in a type position (`RateLimitShared<C>`),
        // an import, or a bare mention is not a registration.
        let after = if let Some(generics) = tail.strip_prefix("::<") {
            let Some(close) = angle_close(generics) else {
                continue;
            };
            let Some(after) = generics[close + 1..].strip_prefix("::") else {
                continue;
            };
            after
        } else if let Some(after) = tail.strip_prefix("::") {
            after
        } else {
            continue;
        };
        let ctor: String = after.chars().take_while(|c| is_ident(*c)).collect();
        if ctor.is_empty() {
            continue;
        }
        assert!(
            CONSTRUCTORS.contains(&ctor.as_str()),
            "{file}:{line}: `RateLimitShared::…::{ctor}` is not a constructor this scan knows \
             ({CONSTRUCTORS:?}); teach the scan about it so its bucket name is counted"
        );
        let args = after[ctor.len()..]
            .strip_prefix('(')
            .unwrap_or_else(|| panic!("{file}:{line}: `{ctor}` is not called here"))
            .trim_start();
        let name = if let Some(literal) = args.strip_prefix('"') {
            literal[..literal.find('"').expect("closed literal")].to_string()
        } else {
            let ident: String = args.chars().take_while(|c| is_ident(*c)).collect();
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
            writer: WRITER_MIDDLEWARE,
        });
    }
    out
}

/// The text of the first argument of a call, given the text after its `(`.
fn first_argument(args: &str) -> &str {
    let b = args.as_bytes();
    let (mut depth, mut i) = (0, 0);
    while i < b.len() {
        match b[i] {
            b'"' => {
                i = skip_string(b, i);
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return args[..i].trim(),
            b')' | b']' | b'}' => depth -= 1,
            b',' if depth == 0 => return args[..i].trim(),
            _ => {}
        }
        i += 1;
    }
    args.trim()
}

/// The contents of the string literal at the start of `text`, if one is there.
fn literal_at(text: &str) -> Option<String> {
    let rest = text.trim_start().strip_prefix('"')?;
    let mut escaped = false;
    for (i, c) in rest.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some(rest[..i].to_string()),
            _ => {}
        }
    }
    None
}

/// The format string a bucket-key expression is built from: `format!("…")`
/// itself, a call to a function of this file whose body formats the key, or a
/// local `let` bound to `format!("…")`.
fn key_format_string(text: &str, at: usize, expr: &str) -> Option<String> {
    let expr = expr.trim_start_matches('&').trim();
    if let Some(rest) = expr.strip_prefix("format!(") {
        return literal_at(rest);
    }
    let ident: String = expr.chars().take_while(|c| is_ident(*c)).collect();
    if ident.is_empty() {
        return None;
    }
    let after_ident = &expr[ident.len()..];
    if after_ident.starts_with('(') {
        // `fn ident(` — the first `format!(` of its body.
        let needle = format!("fn {ident}");
        let mut search = 0;
        while let Some(pos) = text[search..].find(&needle).map(|i| i + search) {
            search = pos + needle.len();
            if text[search..].starts_with(['(', '<']) {
                let body = &text[search..];
                return literal_at(&body[body.find("format!(")? + "format!(".len()..]);
            }
        }
        None
    } else if after_ident.is_empty() {
        // `let ident = format!(…);` — the last binding before the call.
        let needle = format!("let {ident}");
        let mut found = None;
        let mut search = 0;
        while let Some(pos) = text[search..].find(&needle).map(|i| i + search) {
            search = pos + needle.len();
            if pos < at && !text[search..].starts_with(is_ident) {
                found = Some(search);
            }
        }
        let binding = &text[found?..at];
        let rest = &binding[binding.find('=')? + 1..];
        let fmt = rest.trim_start().strip_prefix("format!(")?;
        literal_at(fmt)
    } else {
        None
    }
}

/// Every handler-side `….check_at(key, …)` / `….check_at_human(key, …)` in one
/// file, outside `#[cfg(test)]`, with the endpoint prefix of its key (the text
/// before the first `:` of the key's format string). Refuses a key whose prefix
/// it cannot read as a literal or a `const` of this file.
fn check_at_registrations_in(file: &str, raw: &str) -> Vec<Registration> {
    let text = without_cfg_test_items(&without_comment_lines(raw));
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = text[from..].find("check_at").map(|i| i + from) {
        let name: String = text[at..].chars().take_while(|c| is_ident(*c)).collect();
        from = at + name.len();
        if text[..at].chars().next_back().is_some_and(is_ident)
            || !text[..at].trim_end().ends_with('.')
            || !text[from..].starts_with('(')
            || NOT_COUNTER_CALLS.contains(&name.as_str())
        {
            continue;
        }
        let line = text[..at].matches('\n').count() + 1;
        assert!(
            COUNTER_CALLS.contains(&name.as_str()),
            "{file}:{line}: `.{name}(` is not a counter call this scan knows ({COUNTER_CALLS:?}); \
             teach the scan about it so its bucket prefix is counted"
        );
        let expr = first_argument(&text[from + 1..]);
        let unreadable = || -> ! {
            panic!(
                "{file}:{line}: the key `{expr}` is not a `format!(\"prefix:…\")`, a call to a \
                 function of this file that formats one, or a `let` bound to one, with a literal \
                 prefix before the first `:`; the duplicate-name scan cannot read it"
            )
        };
        let format = key_format_string(&text, at, expr).unwrap_or_else(|| unreadable());
        let head = format.split(':').next().unwrap_or_default();
        let prefix = match head.strip_prefix('{').and_then(|h| h.strip_suffix('}')) {
            Some(constant) => resolve_const(raw, constant).unwrap_or_else(|| unreadable()),
            None => head.to_string(),
        };
        if !format.contains(':') || prefix.is_empty() || prefix.contains(['{', '}']) {
            unreadable();
        }
        out.push(Registration {
            file: file.to_string(),
            line,
            name: prefix,
            writer: WRITER_HANDLER,
        });
    }
    out
}

/// The gRPC bucket names: the literals of `shared_endpoint`'s arms. Refuses an
/// arm that is not a literal, and a file without the function.
fn grpc_families_in(file: &str, raw: &str) -> Vec<Registration> {
    let text = without_cfg_test_items(&without_comment_lines(raw));
    let start = text.find("fn shared_endpoint").unwrap_or_else(|| {
        panic!("{file}: no `fn shared_endpoint`; the gRPC families cannot be read")
    });
    let open = text[start..].find('{').map(|i| i + start).expect("a body");
    let close = matching_close(&text, open).expect("a closed body");
    let body = &text[open..close];
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(arrow) = body[from..].find("=>").map(|i| i + from) {
        from = arrow + 2;
        let line = text[..open + arrow].matches('\n').count() + 1;
        let name = literal_at(&body[from..]).unwrap_or_else(|| {
            panic!(
                "{file}:{line}: a gRPC family whose bucket name is not a string literal; the \
                 duplicate-name scan cannot read it"
            )
        });
        out.push(Registration {
            file: file.to_string(),
            line,
            name,
            writer: WRITER_GRPC,
        });
    }
    out
}

/// Every writer of the counter's endpoint space in the workspace.
fn all_registrations() -> Vec<Registration> {
    let root = crates_dir();
    let mut out = Vec::new();
    for path in source_files() {
        let raw = std::fs::read_to_string(&path).expect("readable source file");
        let rel = path.strip_prefix(&root).unwrap().display().to_string();
        if rel == DEFINING_FILE {
            // Its `check_at` is the middleware's own, keyed by the bucket
            // names collected from the registrations.
            out.extend(registrations_in_defining_file(&rel, &raw));
            continue;
        }
        out.extend(registrations_in(&rel, &raw));
        if rel == GRPC_FILE || rel == COUNTER_FILE {
            // The gRPC middleware's own `check_at` (keyed by the families
            // read below) and the counter's own forwarding methods.
            continue;
        }
        out.extend(check_at_registrations_in(&rel, &raw));
    }
    let raw = std::fs::read_to_string(root.join(GRPC_FILE)).expect("the gRPC rate-limit file");
    out.extend(grpc_families_in(GRPC_FILE, &raw));
    out
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
                .map(|r| format!("{}:{} [{}]", r.file, r.line, r.writer))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match allowed.iter().find(|(n, _, _)| *n == name) {
            None if regs.len() > 1 => out.push(format!(
                "bucket `{name}` is registered {} times ({}); the shared counter keys \
                 `{{endpoint}}:{{key}}`, so these writers spend one allowance. Rename all but one, \
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
        "oauth2_par",                // a `check_at` key, built inline
        "ciba_notify",               // a `check_at` key, through a local `let`
        "ciba_approval_list",        // a `check_at_human` key, through a function
        "network_decide",            // a `check_at` key, through a function and a `const`
        "grpc_authz",                // a gRPC family
        "grpc_infra",                // the last gRPC family
    ] {
        assert!(names.contains_key(known), "`{known}` was not found");
    }
    let writers = |kind| registrations.iter().filter(|r| r.writer == kind).count();
    assert!(
        writers(WRITER_HANDLER) >= 7,
        "the `check_at` keys were not all found"
    );
    assert_eq!(writers(WRITER_GRPC), 4, "the four gRPC families");
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

// ---- the escapes of R110W2-04 (#672), on synthetic sources -----------------

/// A call without the turbofish is a registration: it collides with a
/// turbofish one.
#[test]
fn a_call_without_the_turbofish_is_read() {
    let mut regs = registrations_in(
        "a.rs",
        "x.wrap(RateLimitShared::new(\"dup\", 1)); y.wrap(RateLimitShared::browser_preset(\"dup\", c));",
    );
    regs.extend(registrations_in(
        "b.rs",
        "z.wrap(RateLimitShared::<C>::new(\"dup\", 1));",
    ));
    assert_eq!(regs.len(), 3);
    let found = violations(&regs, &[]);
    assert!(
        found[0].contains("`dup` is registered 3 times"),
        "{found:?}"
    );
}

/// `Self::` constructors cannot be attributed outside the defining file, so an
/// `impl` there is refused.
#[test]
#[should_panic(expected = "an `impl` of `RateLimitShared` outside the file that defines it")]
fn a_self_constructor_outside_the_defining_file_is_refused() {
    registrations_in(
        "other.rs",
        "impl<C> RateLimitShared<C> { fn twin() -> Self { Self::new(\"x\", 1) } }",
    );
}

/// `use … as` and `type` aliases hide the constructor calls and are refused.
#[test]
#[should_panic(expected = "an alias of `RateLimitShared` outside the file that defines it")]
fn a_use_alias_outside_the_defining_file_is_refused() {
    registrations_in(
        "other.rs",
        "use crate::middleware::RateLimitShared as Limiter;\nLimiter::<C>::new(\"x\", 1);",
    );
}

#[test]
#[should_panic(expected = "an alias of `RateLimitShared` outside the file that defines it")]
fn a_type_alias_outside_the_defining_file_is_refused() {
    registrations_in(
        "other.rs",
        "pub(crate) type Limiter<C> = RateLimitShared<C>;",
    );
}

/// A mention of the type that is not a call is not a registration.
#[test]
fn imports_and_type_positions_are_not_registrations() {
    let regs = registrations_in(
        "other.rs",
        "use crate::middleware::RateLimitShared;\nfn f(_: RateLimitSharedService<S, C>, _: Option<RateLimitShared<C>>) {}",
    );
    assert!(regs.is_empty(), "{regs:?}");
}

/// In the defining file, only doc text and the `#[cfg(test)]` module are
/// skipped: a registration anywhere else counts.
#[test]
fn the_defining_file_is_read_outside_its_test_module_and_docs() {
    let source = r#"
        /// .wrap(RateLimitShared::<C>::new("doc_example", 1))
        pub fn real<C>() {
            let _ = RateLimitShared::<C>::new("in_the_type_file", 1);
        }
        #[cfg(test)]
        mod tests {
            fn t() {
                let s = "}{";
                let _ = RateLimitShared::<Db>::new("revoke", 30);
            }
        }
        pub fn after_the_tests<C>() {
            let _ = RateLimitShared::<C>::admin_preset("after", 1);
        }
    "#;
    let regs = registrations_in_defining_file("def.rs", source);
    let names: Vec<_> = regs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["in_the_type_file", "after"]);
    // Everywhere else the test module counts, as before: fail closed.
    let names: Vec<_> = registrations_in("x.rs", source)
        .into_iter()
        .map(|r| r.name)
        .collect();
    assert_eq!(names, ["in_the_type_file", "revoke", "after"]);
}

/// A handler's `check_at*` prefix enters the check, in each form the tree uses.
#[test]
fn a_check_at_prefix_is_read_and_collides_with_a_middleware_name() {
    let source = r#"
        const BUCKET: &str = "via_const";
        fn key(t: Uuid) -> String { format!("via_fn:{t}") }
        fn named(t: Uuid) -> String { format!("{BUCKET}:{t}") }
        async fn h() {
            if !state.shared_rate_limit.check_at(&format!("inline:{}:{}", a, b), now, 5) {}
            let bucket = format!("via_let:{}", u);
            if state.shared_rate_limit
                .check_at(&bucket, now, 5) {}
            state.shared_rate_limit.check_at_human(&key(t), now, 5);
            state.shared_rate_limit.check_at(&named(t), now, 5);
        }
        #[cfg(test)]
        mod tests { fn t() { c.check_at(&k, now, 1); } }
    "#;
    let regs = check_at_registrations_in("h.rs", source);
    let names: Vec<_> = regs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["inline", "via_let", "via_fn", "via_const"]);
    assert!(regs.iter().all(|r| r.writer == WRITER_HANDLER));

    let mut all = regs;
    all.extend(registrations_in(
        "r.rs",
        "x.wrap(RateLimitShared::<C>::new(\"inline\", 1));",
    ));
    let found = violations(&all, &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("`inline` is registered 2 times"),
        "{found:?}"
    );
    assert!(found[0].contains("[check_at]") && found[0].contains("[RateLimitShared]"));
}

/// A key the scan cannot read is refused, never skipped.
#[test]
#[should_panic(expected = "the duplicate-name scan cannot read it")]
fn a_check_at_key_the_scan_cannot_read_is_refused() {
    check_at_registrations_in("h.rs", "state.shared_rate_limit.check_at(&key, now, 5);");
}

#[test]
#[should_panic(expected = "the duplicate-name scan cannot read it")]
fn a_check_at_key_without_a_prefix_is_refused() {
    check_at_registrations_in(
        "h.rs",
        "state.shared_rate_limit.check_at(&format!(\"{}\", x), now, 5);",
    );
}

#[test]
#[should_panic(expected = "is not a counter call this scan knows")]
fn an_unknown_check_at_call_is_refused() {
    check_at_registrations_in("h.rs", "c.check_at_sneaky(&format!(\"x:{}\", y), now, 5);");
}

/// A gRPC family is a writer of the same space: one named like a middleware
/// bucket collides with it.
#[test]
fn a_grpc_family_collides_with_a_middleware_name() {
    let grpc = r#"
        impl Family {
            pub const fn shared_endpoint(self) -> &'static str {
                match self {
                    Self::AuthzCheck => "grpc_authz",
                    Self::Admin => "grpc_admin",
                }
            }
        }
    "#;
    let mut regs = grpc_families_in("grpc.rs", grpc);
    let names: Vec<_> = regs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["grpc_authz", "grpc_admin"]);
    regs.extend(registrations_in(
        "r.rs",
        "x.wrap(RateLimitShared::<C>::new(\"grpc_authz\", 1));",
    ));
    let found = violations(&regs, &[]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("`grpc_authz` is registered 2 times"),
        "{found:?}"
    );
}

#[test]
#[should_panic(expected = "a gRPC family whose bucket name is not a string literal")]
fn a_grpc_family_that_is_not_a_literal_is_refused() {
    grpc_families_in(
        "grpc.rs",
        "fn shared_endpoint(self) -> &'static str { match self { Self::A => NAME } }",
    );
}

//! Audit log domain model.
//!
//! Audit logs are append-only — no UPDATE or DELETE operations are permitted.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum ActorType {
    User,
    ServiceAccount,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum AuditOutcome {
    Success,
    Failure,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: ActorType,
    pub action: String,
    pub resource_id: Option<Uuid>,
    pub outcome: AuditOutcome,
    pub ip_address: Option<String>,
    pub metadata: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuditLogEntry {
    pub tenant_id: Uuid,
    pub actor_id: Uuid,
    pub actor_type: ActorType,
    pub action: String,
    pub resource_id: Option<Uuid>,
    pub outcome: AuditOutcome,
    pub ip_address: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// The action namespaces the server reserves for its own **control records**
/// (R101W3-03, #637).
///
/// Rows in these namespaces are evidence the server writes and later reads
/// back to decide what it may do: the `tenants.audit_exported` receipt that
/// authorises a tenant's deletion (T-118), the `tenants.deleted` record whose
/// export time bounds what the tenant purge deletes (T-472), `tenants.purged`,
/// and the GDPR records (`gdpr.*`). Only the server writes them. The AMQP audit
/// ingestion (`axiam_amqp::audit_consumer::process_audit_event`), whose
/// messages a tenant's own producers sign, refuses any action in them; every
/// action constant of a control record must fall in one of them (tests in
/// `axiam-amqp` and `axiam-db` pin the ones the purge and the deletion read).
pub const RESERVED_ACTION_NAMESPACES: &[&str] = &["tenants.", "gdpr."];

/// The namespace of [`RESERVED_ACTION_NAMESPACES`] that `action` falls in, or
/// `None` when the action is open to external producers.
///
/// The comparison ignores ASCII case, so `Tenants.audit_exported` is reserved
/// as `tenants.audit_exported` is, although the server's own readers match the
/// exact spelling.
pub fn reserved_action_namespace(action: &str) -> Option<&'static str> {
    RESERVED_ACTION_NAMESPACES.iter().copied().find(|ns| {
        action
            .get(..ns.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(ns))
    })
}

/// Whether `action` is within the grammar an external producer may write
/// (R110W3-09, #682): printable ASCII (`0x21..=0x7e`) with at most one space,
/// neither first nor last — the one space of the middleware's `METHOD /path`.
///
/// Anything else (a leading space, a Cyrillic or full-width lookalike, a
/// zero-width joiner, a control character, the empty string) reads in the
/// console like a reserved action while escaping [`reserved_action_namespace`],
/// so the AMQP audit ingestion refuses it before that check.
pub fn is_valid_audit_action(action: &str) -> bool {
    !action.is_empty()
        && action.bytes().filter(|b| *b == b' ').count() <= 1
        && !action.starts_with(' ')
        && !action.ends_with(' ')
        && action
            .bytes()
            .all(|b| b == b' ' || (0x21..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_action_grammar_is_printable_ascii_with_one_inner_space() {
        for action in [
            "user.login",
            "tenants.audit_exported",
            "GET /api/v1/users",
            "~",
        ] {
            assert!(is_valid_audit_action(action), "{action}");
        }
        for action in [
            "",
            " tenants.audit_exported",
            "tenants.audit_exported ",
            "GET /a b",
            "t\u{435}nants.audit_exported",
            "tenants\u{ff0e}audit_exported",
            "tenants.\u{200d}audit_exported",
            "tenants.audit\u{0}_exported",
            "tenants.audit\n_exported",
            "tenants.audit\t_exported",
            "\u{7f}",
        ] {
            assert!(!is_valid_audit_action(action), "{action:?}");
        }
    }

    /// Whether a constant's name says it holds an audit action: `AUDIT_…`,
    /// `…_AUDIT_…` or `…_ACTION` (`AUDIT_EXPORT_ACTION`, `TENANT_DELETED_ACTION`,
    /// `CIBA_APPROVED_AUDIT_ACTION`, `SCIM_DEAD_LETTER_AUDIT_ACTION`).
    fn names_an_audit_action(name: &str) -> bool {
        // Settings and patterns that mention the audit log are not actions.
        const NOT_AN_ACTION: [&str; 4] = ["_ENV", "_VAR", "_REGEX", "_FILE"];
        !NOT_AN_ACTION.iter().any(|tail| name.ends_with(tail))
            && (name.starts_with("AUDIT_") || name.contains("_AUDIT_") || name.ends_with("_ACTION"))
    }

    fn rust_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("readable source directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_sources(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Every `const NAME: &str = "literal";` in the workspace's `crates/*/src`
    /// whose name [`names_an_audit_action`], as `(file, NAME, literal)`.
    ///
    /// A source scan rather than a list: a constant added later in any crate is
    /// found by its name alone, so it is held to the grammar without anyone
    /// remembering to register it. An alias of another constant is skipped
    /// (its definition is scanned); any other value that is not one plain
    /// string literal (`concat!`) fails the test rather than slipping past it.
    fn audit_action_constants() -> Vec<(String, String, String)> {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        for krate in std::fs::read_dir(&crates).expect("crates directory") {
            let src = krate.expect("crate entry").path().join("src");
            if src.is_dir() {
                rust_sources(&src, &mut files);
            }
        }
        files.sort();
        let mut found = Vec::new();
        for file in files {
            let text = std::fs::read_to_string(&file).expect("utf-8 source");
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let Some(decl) = line
                    .trim_start()
                    .strip_prefix("pub const ")
                    .or_else(|| line.trim_start().strip_prefix("const "))
                else {
                    continue;
                };
                let Some((name, rest)) = decl.split_once(": &str =") else {
                    continue;
                };
                if !names_an_audit_action(name) {
                    continue;
                }
                // The value may start on the next line (rustfmt wraps a long one).
                let value = if rest.trim().is_empty() {
                    lines.get(i + 1).copied().unwrap_or("")
                } else {
                    rest
                };
                let value = value.trim();
                // An alias of another constant (`pub const A: &str = b::A;`) is
                // held to the grammar at its definition.
                let alias = value.strip_suffix(';').is_some_and(|path| {
                    path.split("::").all(|seg| {
                        !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_')
                    })
                });
                if alias {
                    continue;
                }
                let literal = value
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix("\";"))
                    .filter(|v| !v.contains('"') && !v.contains('\\'));
                let literal = literal.unwrap_or_else(|| {
                    panic!(
                        "{}: `{name}` is not one plain string literal ({value}); \
                         make it one, or rename it so it does not claim to be an audit action",
                        file.display()
                    )
                });
                found.push((
                    file.display().to_string(),
                    name.to_owned(),
                    literal.to_owned(),
                ));
            }
        }
        found
    }

    /// W2.9 (#758 (d)): every server action constant is within the grammar the
    /// AMQP ingestion enforces on producers, W4's network constants
    /// (`network_gate.rs`, `handlers/network.rs`, the seeder) and the reserved
    /// control records among them. A server constant outside it would be a row
    /// the server itself could write but no producer could replay or filter by.
    #[test]
    fn every_server_action_constant_is_within_the_action_grammar() {
        let constants = audit_action_constants();
        let bad: Vec<String> = constants
            .iter()
            .filter(|(_, _, action)| !is_valid_audit_action(action))
            .map(|(file, name, action)| format!("{file}: {name} = {action:?}"))
            .collect();
        assert!(
            bad.is_empty(),
            "outside the action grammar:\n{}",
            bad.join("\n")
        );

        // The scan must still be seeing the workspace: these are a core file's,
        // an authz file's, a db file's (reserved) and an api-rest file's.
        for anchor in [
            "directory.account_updated",
            "network_role.unassigned",
            "tenants.purged",
            "gdpr.user_pseudonymized",
            "network_segment.created",
            "ciba.approved",
        ] {
            assert!(
                constants.iter().any(|(_, _, action)| action == anchor),
                "the scan no longer finds {anchor}"
            );
        }
        assert!(
            constants.len() >= 40,
            "the scan found only {} constants",
            constants.len()
        );
        // A reserved control record is a constant like any other here.
        for (_, name, action) in &constants {
            if reserved_action_namespace(action).is_some() {
                assert!(is_valid_audit_action(action), "{name}");
            }
        }
    }

    #[test]
    fn the_scan_names_constants_by_their_audit_naming_convention() {
        for name in [
            "AUDIT_ROLE_ASSIGNED",
            "CIBA_APPROVED_AUDIT_ACTION",
            "TENANT_PURGED_ACTION",
        ] {
            assert!(names_an_audit_action(name), "{name}");
        }
        for name in [
            "SSF_MANAGE_SCOPE",
            "NETWORK_ACTION_REGEX",
            "TOKEN_PRE_ISSUE",
        ] {
            assert!(!names_an_audit_action(name), "{name}");
        }
    }

    #[test]
    fn the_control_namespaces_are_reserved_whatever_their_case() {
        for action in [
            "tenants.audit_exported",
            "tenants.deleted",
            "tenants.purged",
            "TENANTS.Audit_Exported",
            "gdpr.user_pseudonymized",
            "Gdpr.erasure_requested",
        ] {
            assert!(reserved_action_namespace(action).is_some(), "{action}");
        }
        for action in [
            "user.login",
            "tenant.audit_exported",
            "tenantsx.deleted",
            "gdpr",
            "",
            "DELETE /api/v1/organizations/x/tenants/y",
            "é",
        ] {
            assert_eq!(reserved_action_namespace(action), None, "{action}");
        }
    }
}

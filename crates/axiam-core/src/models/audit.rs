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

#[cfg(test)]
mod tests {
    use super::*;

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

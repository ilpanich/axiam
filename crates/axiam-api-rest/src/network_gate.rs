//! The REST side of the network write gate (RADIUS D4, W6.2).
//!
//! Every handler that can create a reply profile, a segment, a
//! network-sensitive grant or assignment, or a certificate binding — and every
//! generic handler that could reach into the reserved `network:` namespace or
//! `/network` subtree — calls [`authorize`] **before** its repository write.
//! The decision itself is `axiam_authz::network_gate::authorize_network_write`
//! (design note §5.1: one domain function, not handler logic); this module
//! only supplies its reads from [`AppState`], writes the audit row of a
//! refusal (§5.4) and turns the refusal into the response.
//!
//! `tests/network_gate_enumeration_test.rs` reads the sources and fails if a
//! write of that kind reaches its repository from a function that does not call
//! [`authorize`] first (the T-429 lesson); segment and profile writes cannot
//! even compile without the clearance [`authorize`] returns.

use axiam_authz::network_gate::{
    GateClearance, GateRefusal, GateWriter, NetworkWrite, RefusalStatus, RepositoryGateStore,
    authorize_network_write,
};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;
use axiam_db::repository::{
    SurrealNetworkPolicyRepository, SurrealNetworkSegmentRepository, SurrealReplyProfileRepository,
};
use surrealdb::Connection;

use crate::authz::AuthzChecker;
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedPrincipal;
use crate::state::AppState;

/// Who is writing, for the gate and for the audit row.
#[derive(Debug, Clone)]
pub struct GateActor {
    /// The gate's view of the writer.
    pub writer: GateWriter,
    /// The audit row's actor type.
    pub actor_type: ActorType,
    /// A label for a writer without a subject id (a UMA resource server's
    /// `client_id`), recorded in the audit row.
    pub label: Option<String>,
}

impl GateActor {
    /// The writer behind an authenticated user or service-account token.
    #[must_use]
    pub fn principal(principal: &AuthenticatedPrincipal) -> Self {
        Self {
            writer: GateWriter {
                tenant_id: principal.tenant_id,
                subject_id: principal.subject_id,
                subject_scope: principal.subject_scope(),
            },
            actor_type: principal.actor_type(),
            label: None,
        }
    }
}

/// Run the gate for `write` as `principal`; on a refusal, audit it and answer
/// `403` or `400`.
///
/// # Errors
///
/// The refusal as an [`AxiamApiError`] (`403` naming the missing permission
/// and node, or `400`), or whatever the gate's reads return (`404` for a role,
/// permission or segment that is not the tenant's).
pub async fn authorize<C: Connection + Clone>(
    principal: &AuthenticatedPrincipal,
    authz: &(dyn AuthzChecker + 'static),
    state: &AppState<C>,
    write: NetworkWrite<'_>,
) -> Result<GateClearance, AxiamApiError> {
    authorize_as(&GateActor::principal(principal), authz, state, write).await
}

/// [`authorize`] for a writer that is not an [`AuthenticatedPrincipal`].
///
/// # Errors
///
/// As [`authorize`].
pub async fn authorize_as<C: Connection + Clone>(
    actor: &GateActor,
    authz: &(dyn AuthzChecker + 'static),
    state: &AppState<C>,
    write: NetworkWrite<'_>,
) -> Result<GateClearance, AxiamApiError> {
    let segments = SurrealNetworkSegmentRepository::new(state.db.clone());
    let profiles = SurrealReplyProfileRepository::new(state.db.clone());
    let policy = SurrealNetworkPolicyRepository::new(state.db.clone());
    let store = RepositoryGateStore {
        roles: &state.role_repo,
        groups: &state.group_repo,
        permissions: &state.permission_repo,
        resources: &state.resource_repo,
        segments: &segments,
        profiles: &profiles,
        policy: &policy,
        certificates: &state.pki.cert_repo,
    };
    match authorize_network_write(authz, &store, actor.writer, write).await? {
        Ok(clearance) => Ok(clearance),
        Err(refusal) => {
            audit_refusal(state, actor, write_kind(&write), &refusal).await;
            Err(into_error(refusal))
        }
    }
}

/// A short name for the write, for the audit row.
fn write_kind(write: &NetworkWrite<'_>) -> &'static str {
    match write {
        NetworkWrite::ProfileWrite { .. } => "profile_write",
        NetworkWrite::ProfileDelete { .. } => "profile_delete",
        NetworkWrite::SegmentCreate { .. } => "segment_create",
        NetworkWrite::SegmentUpdate { .. } => "segment_update",
        NetworkWrite::SegmentDelete { .. } => "segment_delete",
        NetworkWrite::RoleAssign { .. } => "role_assign",
        NetworkWrite::RoleUnassign { .. } => "role_unassign",
        NetworkWrite::RoleUpdate { .. } => "role_update",
        NetworkWrite::RoleDelete { .. } => "role_delete",
        NetworkWrite::PermissionGrant { .. } => "permission_grant",
        NetworkWrite::PermissionRevoke { .. } => "permission_revoke",
        NetworkWrite::PermissionCreate { .. } => "permission_create",
        NetworkWrite::PermissionUpdate { .. } => "permission_update",
        NetworkWrite::PermissionDelete { .. } => "permission_delete",
        NetworkWrite::PolicyWrite { .. } => "policy_write",
        NetworkWrite::CertificateBind { .. } => "certificate_bind",
        NetworkWrite::ResourceCreate { .. } => "resource_create",
        NetworkWrite::ResourceUpdate { .. } => "resource_update",
        NetworkWrite::ResourceDelete { .. } => "resource_delete",
    }
}

fn values(pairs: &[(&'static str, String)]) -> serde_json::Value {
    serde_json::Value::Object(
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), serde_json::Value::String(v.clone())))
            .collect(),
    )
}

/// One append-only row per refusal (§5.4): the actor, the tenant, the write,
/// the values before and after, and the **internal** reason. Refusals are
/// audited because an escalation attempt is exactly what a reviewer looks for.
///
/// A failure to write the row is logged and does not turn the refusal into a
/// success: the write stays refused either way.
async fn audit_refusal<C: Connection + Clone>(
    state: &AppState<C>,
    actor: &GateActor,
    write: &'static str,
    refusal: &GateRefusal,
) {
    let mut metadata = serde_json::json!({
        "write": write,
        "rule": refusal.rule,
        "reason": refusal.message,
        "status": match refusal.status {
            RefusalStatus::Forbidden => 403,
            RefusalStatus::Invalid => 400,
        },
        "before": values(&refusal.before),
        "after": values(&refusal.after),
    });
    if let Some(missing) = &refusal.missing {
        metadata["missing_permission"] = serde_json::json!(missing.action);
        metadata["node"] = serde_json::json!(missing.node);
    }
    if let Some(label) = &actor.label {
        metadata["actor_label"] = serde_json::json!(label);
    }
    let entry = CreateAuditLogEntry {
        tenant_id: actor.writer.tenant_id,
        actor_id: actor.writer.subject_id,
        actor_type: actor.actor_type.clone(),
        action: refusal.audit_action.to_owned(),
        resource_id: refusal.missing.as_ref().map(|m| m.node),
        outcome: AuditOutcome::Denied,
        ip_address: None,
        metadata: Some(metadata),
    };
    if let Err(error) = state.audit_repo.append(entry).await {
        tracing::error!(
            target: "axiam::network_gate",
            tenant_id = %actor.writer.tenant_id,
            action = refusal.audit_action,
            %error,
            "a network write refusal could not be audited; the write stays refused"
        );
    }
}

fn into_error(refusal: GateRefusal) -> AxiamApiError {
    match refusal.status {
        RefusalStatus::Forbidden => {
            let (action, resource_id) = refusal
                .missing
                .map_or((None, None), |m| (Some(m.action), Some(m.node.to_string())));
            AxiamApiError(AxiamError::AuthorizationDenied {
                reason: refusal.message,
                action,
                resource_id,
            })
        }
        RefusalStatus::Invalid => AxiamApiError(AxiamError::Validation {
            message: refusal.message,
        }),
    }
}

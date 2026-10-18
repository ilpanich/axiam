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

use actix_web::HttpResponse;
use axiam_authz::network_gate::{
    AUDIT_ROLE_ASSIGN_REFUSED, AUDIT_ROLE_GRANT_REFUSED, AUDIT_ROLE_UNASSIGN_REFUSED,
    AUDIT_ROLE_WRITE_REFUSED, GateClearance, GateRefusal, GateWriter, Grantee, NetworkWrite,
    RefusalStatus, RepositoryGateStore, authorize_network_write,
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
use crate::handlers::network::NetworkConflictReason;
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

/// Answer a role write that the gate cleared and **its own transaction then
/// refused** because what the gate read had changed by the time it ran
/// (R110W6-04, #701).
///
/// The gate decides a role write — a grant or revoke, an assignment or
/// unassignment, an `is_global` update, a delete — on the role's grants,
/// holders and scope, read before the write. Two writes to one role can each
/// pass it on a state the other is about to change (a `network:join` grant and
/// the writer assigning itself the role; a grant and a group assignment; …).
/// So the gate hands the write a claim on the role's epochs
/// ([`GateClearance::role_claim`]), the `*_claimed` repository writes compare
/// it inside their transaction, and a write that lost comes back as
/// `AxiamError::Conflict` ("the role changed since it was read …"). That
/// answers `409` with `reason_code` `stale_version` — the network routes'
/// sub-code for "read again, decide again" (contract §36.3 rule 2): sent again,
/// the request goes back through the gate, which decides on the role as it now
/// is. It is audited as the gate audits its own refusals: one
/// `network_role.*_refused` row, outcome denied, with the internal rule
/// (`version:stale`, as the network routes record a stale write), the reason
/// and the values.
///
/// Any other error is returned unchanged, unaudited, as it was before.
///
/// # Errors
///
/// `error` itself, when it is not that conflict or `write` is not a role
/// write.
pub async fn refused_after_clearance<C: Connection + Clone>(
    principal: &AuthenticatedPrincipal,
    state: &AppState<C>,
    write: NetworkWrite<'_>,
    error: AxiamError,
) -> Result<HttpResponse, AxiamApiError> {
    if NetworkConflictReason::of(&error) != Some(NetworkConflictReason::StaleVersion) {
        return Err(AxiamApiError(error));
    }
    let grantee = |g: Grantee| match g {
        Grantee::User(id) => ("user", id.to_string()),
        Grantee::ServiceAccount(id) => ("service_account", id.to_string()),
        Grantee::Group(id) => ("group", id.to_string()),
    };
    let node = |r: Option<uuid::Uuid>| r.map_or_else(|| "none".to_owned(), |r| r.to_string());
    let (audit_action, before, after) = match write {
        NetworkWrite::PermissionGrant {
            role_id,
            permission_id,
            effect,
            ..
        } => (
            AUDIT_ROLE_GRANT_REFUSED,
            vec![("role_id", role_id.to_string())],
            vec![
                ("permission_id", permission_id.to_string()),
                ("effect", effect.as_str().to_owned()),
            ],
        ),
        NetworkWrite::PermissionRevoke {
            role_id,
            permission_id,
        } => (
            AUDIT_ROLE_GRANT_REFUSED,
            vec![
                ("role_id", role_id.to_string()),
                ("permission_id", permission_id.to_string()),
            ],
            vec![("grant", "revoked".to_owned())],
        ),
        NetworkWrite::RoleAssign {
            role_id,
            grantee: g,
            resource_id,
            inherit,
        } => {
            let (kind, who) = grantee(g);
            (
                AUDIT_ROLE_ASSIGN_REFUSED,
                vec![("role_id", role_id.to_string())],
                vec![
                    (kind, who),
                    ("resource_id", node(resource_id)),
                    ("inherit", inherit.to_string()),
                ],
            )
        }
        NetworkWrite::RoleUnassign {
            role_id,
            grantee: g,
            resource_id,
        } => {
            let (kind, who) = grantee(g);
            (
                AUDIT_ROLE_UNASSIGN_REFUSED,
                vec![
                    ("role_id", role_id.to_string()),
                    (kind, who),
                    ("resource_id", node(resource_id)),
                ],
                vec![("assignment", "removed".to_owned())],
            )
        }
        NetworkWrite::RoleUpdate { role_id, is_global } => (
            AUDIT_ROLE_WRITE_REFUSED,
            vec![("role_id", role_id.to_string())],
            vec![(
                "is_global",
                is_global.map_or_else(|| "unchanged".to_owned(), |g| g.to_string()),
            )],
        ),
        NetworkWrite::RoleDelete { role_id } => (
            AUDIT_ROLE_WRITE_REFUSED,
            vec![("role_id", role_id.to_string())],
            vec![("role", "deleted".to_owned())],
        ),
        _ => return Err(AxiamApiError(error)),
    };
    let AxiamError::Conflict { reason } = &error else {
        return Err(AxiamApiError(error));
    };
    let actor = GateActor::principal(principal);
    let entry = CreateAuditLogEntry {
        tenant_id: actor.writer.tenant_id,
        actor_id: actor.writer.subject_id,
        actor_type: actor.actor_type,
        action: audit_action.to_owned(),
        resource_id: None,
        outcome: AuditOutcome::Denied,
        ip_address: None,
        metadata: Some(serde_json::json!({
            "write": write_kind(&write),
            "rule": "version:stale",
            "reason": reason,
            "status": 409,
            "before": values(&before),
            "after": values(&after),
        })),
    };
    if let Err(audit_error) = state.audit_repo.append(entry).await {
        tracing::error!(
            target: "axiam::network_gate",
            tenant_id = %principal.tenant_id,
            action = audit_action,
            error = %audit_error,
            "a network write refusal could not be audited; the write stays refused"
        );
    }
    Ok(AxiamApiError(error)
        .error_response_with_reason_code(Some(NetworkConflictReason::StaleVersion.as_str())))
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

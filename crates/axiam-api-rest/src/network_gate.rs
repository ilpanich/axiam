//! The REST side of the network write gate (RADIUS Live profile, W6.2).
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
use std::future::Future;

use axiam_authz::network_gate::{
    AUDIT_BINDING_BOUND, AUDIT_ROLE_ASSIGN_REFUSED, AUDIT_ROLE_ASSIGNED, AUDIT_ROLE_DELETED,
    AUDIT_ROLE_GRANT_REFUSED, AUDIT_ROLE_GRANTED, AUDIT_ROLE_REVOKED, AUDIT_ROLE_UNASSIGN_REFUSED,
    AUDIT_ROLE_UNASSIGNED, AUDIT_ROLE_WRITE_REFUSED, ClearedRole, GateClearance, GateRefusal,
    GateWriter, Grantee, NetworkWrite, RefusalStatus, RepositoryGateStore, authorize_network_write,
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
    let reason = error.to_string();
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

/// Run the repository write of a network-sensitive write that the gate
/// cleared, and record it once it landed (R110W6-06, #703, T-484): one
/// `network_role.assigned` / `.unassigned` / `.granted` / `.revoked` or
/// `certificate_binding.bound` row, with the role, the grantee, the node and the
/// `network:` permissions the write conferred (or removed); an assignment's row
/// also carries `exemption`, the named exemption it cleared under
/// (`organization-bootstrap`) or `null`. Without it a cleared write is visible
/// only in the route's generic request row, which says neither that it touched
/// the network namespace nor where a join landed.
///
/// **The row cannot be separated from the write (R111W4-02, #726).** It is
/// built here, before the write, from what the gate read
/// ([`GateClearance::role`], [`GateClearance::permission`]) — not from reads
/// after the write, which a concurrent role delete made fail and a concurrent
/// regrant made lie. Then `repository_write` and the append run as **one
/// spawned task**, which this function awaits through its `JoinHandle`. Actix
/// drops a handler's future when its client goes away; dropping the handle
/// does not cancel the task, so a write that commits is appended whether or not
/// anyone still waits for the answer. The task is spawned on the worker's local
/// runtime (`actix_web::rt::spawn`), so the write need not be `Send`; it must
/// own what it uses (`'static`).
///
/// No row is written when the clearance is not network-sensitive, when the
/// write fails (the caller answers that error — `refused_after_clearance` for
/// a stale claim), or when the write is not one of the five (a role update, a resource write, a segment or profile write — those keep their own
/// rows).
///
/// A failure to describe the write or to append the row is logged and does not
/// undo or fail the write that already landed — the convention of
/// [`audit_refusal`], and of every other audit append in the handlers. The row
/// carries ids, names and actions only; never a certificate, key or token.
///
/// # Errors
///
/// Whatever `repository_write` returns; `AxiamError::Internal` if the runtime
/// cancels the task (it shuts down). A panic in the task is resumed here.
pub async fn write_and_record<C, T, W>(
    state: &AppState<C>,
    actor: &GateActor,
    write: NetworkWrite<'_>,
    cleared: &GateClearance,
    repository_write: W,
) -> Result<T, AxiamError>
where
    C: Connection + Clone,
    T: 'static,
    W: Future<Output = Result<T, AxiamError>> + 'static,
{
    let row = cleared_row(actor, write, cleared);
    let audit = state.audit_repo.clone();
    let tenant_id = actor.writer.tenant_id;
    let task = actix_web::rt::spawn(async move {
        let written = repository_write.await?;
        match row {
            Ok(None) => {}
            Ok(Some(entry)) => {
                let action = entry.action.clone();
                if let Err(error) = audit.append(entry).await {
                    tracing::error!(
                        target: "axiam::network_gate",
                        %tenant_id,
                        %action,
                        %error,
                        "a cleared network write could not be audited; the write stands"
                    );
                }
            }
            Err(missing) => tracing::error!(
                target: "axiam::network_gate",
                %tenant_id,
                missing,
                "a cleared network write could not be described for the audit; the write stands"
            ),
        }
        Ok(written)
    });
    match task.await {
        Ok(result) => result,
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        Err(join) => Err(AxiamError::Internal(format!(
            "a cleared network write was cancelled by the runtime: {join}"
        ))),
    }
}

/// The success row of a cleared write, built from the clearance alone
/// (R111W4-02): `Ok(None)` when the write gets no row, `Err` naming what the
/// clearance lacks when it cannot be described.
fn cleared_row(
    actor: &GateActor,
    write: NetworkWrite<'_>,
    cleared: &GateClearance,
) -> Result<Option<CreateAuditLogEntry>, &'static str> {
    if !cleared.is_network_sensitive() {
        return Ok(None);
    }
    let node = |r: Option<uuid::Uuid>| r.map_or_else(|| "none".to_owned(), |r| r.to_string());
    let grantee = |g: Grantee| match g {
        Grantee::User(id) => serde_json::json!({ "kind": "user", "id": id }),
        Grantee::ServiceAccount(id) => serde_json::json!({ "kind": "service_account", "id": id }),
        Grantee::Group(id) => serde_json::json!({ "kind": "group", "id": id }),
    };
    let role = || cleared.role().ok_or("the role the gate read");
    let permission = || cleared.permission().ok_or("the permission the gate read");
    let network_permissions = |role: &ClearedRole| {
        role.network_grants
            .iter()
            .map(|g| {
                serde_json::json!({
                    "action": g.permission.action,
                    "effect": g.effect.as_str(),
                    "scope_ids": g.scope_ids,
                })
            })
            .collect::<Vec<_>>()
    };
    let (audit_action, resource_id, mut metadata) = match write {
        NetworkWrite::RoleAssign {
            role_id,
            grantee: g,
            resource_id,
            inherit,
        } => {
            let role = role()?;
            (
                AUDIT_ROLE_ASSIGNED,
                resource_id,
                serde_json::json!({
                    "role_id": role_id,
                    "role": role.name,
                    "grantee": grantee(g),
                    "node": node(resource_id),
                    "inherit": inherit,
                    "permissions": network_permissions(role),
                    "exemption": cleared.exemption(),
                }),
            )
        }
        NetworkWrite::RoleUnassign {
            role_id,
            grantee: g,
            resource_id,
        } => {
            let role = role()?;
            (
                AUDIT_ROLE_UNASSIGNED,
                resource_id,
                serde_json::json!({
                    "role_id": role_id,
                    "role": role.name,
                    "grantee": grantee(g),
                    "node": node(resource_id),
                    "permissions": network_permissions(role),
                }),
            )
        }
        NetworkWrite::PermissionGrant {
            role_id,
            permission_id,
            effect,
            scope_ids,
        } => (
            AUDIT_ROLE_GRANTED,
            None,
            serde_json::json!({
                "role_id": role_id,
                "role": role()?.name,
                "permissions": [{
                    "action": permission()?.action,
                    "permission_id": permission_id,
                    "effect": effect.as_str(),
                    "scope_ids": scope_ids,
                }],
            }),
        ),
        NetworkWrite::PermissionRevoke {
            role_id,
            permission_id,
        } => {
            let effect = cleared
                .revoked_effect()
                .flatten()
                .map_or("none", |e| e.as_str());
            (
                AUDIT_ROLE_REVOKED,
                None,
                serde_json::json!({
                    "role_id": role_id,
                    "role": role()?.name,
                    "permissions": [{
                        "action": permission()?.action,
                        "permission_id": permission_id,
                        "effect": effect,
                    }],
                }),
            )
        }
        NetworkWrite::RoleDelete { role_id } => {
            let role = role()?;
            (
                AUDIT_ROLE_DELETED,
                None,
                serde_json::json!({
                    "role_id": role_id,
                    "role": role.name,
                    "permissions": network_permissions(role),
                }),
            )
        }
        NetworkWrite::CertificateBind {
            certificate_id,
            service_account_id,
        } => (
            AUDIT_BINDING_BOUND,
            None,
            serde_json::json!({
                "certificate_id": certificate_id,
                "grantee": { "kind": "service_account", "id": service_account_id },
            }),
        ),
        _ => return Ok(None),
    };
    metadata["write"] = serde_json::json!(write_kind(&write));
    Ok(Some(CreateAuditLogEntry {
        tenant_id: actor.writer.tenant_id,
        actor_id: actor.writer.subject_id,
        actor_type: actor.actor_type.clone(),
        action: audit_action.to_owned(),
        resource_id,
        outcome: AuditOutcome::Success,
        ip_address: None,
        metadata: Some(metadata),
    }))
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

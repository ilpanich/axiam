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
use std::sync::Arc;

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
/// `AxiamError::Network(NetworkConflict::StaleRole { .. })` ("the role changed
/// since it was read …"). That
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
    let Some(refusal) = StaleRefusal::of(&GateActor::principal(principal), write) else {
        return Err(AxiamApiError(error));
    };
    refusal.append(&state.audit_repo, &error).await;
    Ok(AxiamApiError(error)
        .error_response_with_reason_code(Some(NetworkConflictReason::StaleVersion.as_str())))
}

/// The answer to a [`write_and_record`] error: a stale claim is `409` with
/// `reason_code` `stale_version`, as [`refused_after_clearance`] answers it —
/// its `network_role.*_refused` row is already appended, by the write's own
/// task (R112W4-01) — and any other error is returned unchanged.
///
/// # Errors
///
/// `error` itself, when it is not a stale claim.
pub fn refused_in_task(error: AxiamError) -> Result<HttpResponse, AxiamApiError> {
    if NetworkConflictReason::of(&error) != Some(NetworkConflictReason::StaleVersion) {
        return Err(AxiamApiError(error));
    }
    Ok(AxiamApiError(error)
        .error_response_with_reason_code(Some(NetworkConflictReason::StaleVersion.as_str())))
}

/// The `network_role.*_refused` row of a stale claim, described before the
/// write runs: everything but the reason, which only the refusal carries.
struct StaleRefusal {
    tenant_id: uuid::Uuid,
    actor_id: uuid::Uuid,
    actor_type: ActorType,
    action: &'static str,
    write: &'static str,
    before: serde_json::Value,
    after: serde_json::Value,
}

impl StaleRefusal {
    /// `None` for a write that is not a role write (it holds no claim).
    fn of(actor: &GateActor, write: NetworkWrite<'_>) -> Option<Self> {
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
            _ => return None,
        };
        Some(Self {
            tenant_id: actor.writer.tenant_id,
            actor_id: actor.writer.subject_id,
            actor_type: actor.actor_type.clone(),
            action: audit_action,
            write: write_kind(&write),
            before: values(&before),
            after: values(&after),
        })
    }

    /// Append the row for `error`; a failed append is logged, and the write
    /// stays refused.
    async fn append<A: AuditLogRepository>(self, audit: &A, error: &AxiamError) {
        let (tenant_id, action) = (self.tenant_id, self.action);
        let entry = CreateAuditLogEntry {
            tenant_id,
            actor_id: self.actor_id,
            actor_type: self.actor_type,
            action: action.to_owned(),
            resource_id: None,
            outcome: AuditOutcome::Denied,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "write": self.write,
                "rule": "version:stale",
                "reason": error.to_string(),
                "status": 409,
                "before": self.before,
                "after": self.after,
            })),
        };
        if let Err(audit_error) = audit.append(entry).await {
            tracing::error!(
                target: "axiam::network_gate",
                %tenant_id,
                action,
                error = %audit_error,
                "a network write refusal could not be audited; the write stays refused"
            );
        }
    }
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
/// **What follows the commit rides the same task (R112W4-01, #775).** The D7
/// decision-cache flush the write needs (`flush`: the grantee for a user or
/// service-account assignment, the tenant for a group assignment, a role
/// delete, a grant or a revoke; local **and** broadcast, through
/// `AuthzChecker::invalidate_*`) runs after the write and **before** the row,
/// so a revocation's row is never readable while the allow it revokes is
/// still served from the cache of the replica that wrote it. A failed flush
/// (the broadcast was not confirmed) does not drop the row of a write that
/// landed: the row is appended and the flush's error returned (`503`, the
/// handlers' convention for an unconfirmed revocation). On a stale claim the
/// `network_role.*_refused` row is appended in the task too (the caller then
/// answers with [`refused_in_task`]). Before this, both ran in the handler's
/// future, after the task: a client gone after the spawn left a committed
/// revocation whose cached allow outlived it, on every replica, until the TTL.
///
/// No success row is written when the clearance is not network-sensitive,
/// when the write fails, or when the write is not one of those named above (a
/// role update, a resource write, a segment or profile write — those keep
/// their own rows).
///
/// A failure to describe the write or to append the row is logged and does not
/// undo or fail the write that already landed — the convention of
/// [`audit_refusal`], and of every other audit append in the handlers. The row
/// carries ids, names and actions only; never a certificate, key or token.
///
/// # Errors
///
/// Whatever `repository_write` returns; the flush's error once the write
/// landed; `AxiamError::Internal` if the runtime cancels the task (it shuts
/// down). A panic in the task is resumed here.
pub async fn write_and_record<C, T, W>(
    state: &AppState<C>,
    authz: &Arc<dyn AuthzChecker>,
    actor: &GateActor,
    write: NetworkWrite<'_>,
    cleared: &GateClearance,
    flush: CacheFlush,
    repository_write: W,
) -> Result<T, AxiamError>
where
    C: Connection + Clone,
    T: 'static,
    W: Future<Output = Result<T, AxiamError>> + 'static,
{
    let row = cleared_row(actor, write, cleared);
    let stale = StaleRefusal::of(actor, write);
    let audit = state.audit_repo.clone();
    let authz = Arc::clone(authz);
    let tenant_id = actor.writer.tenant_id;
    let task = actix_web::rt::spawn(async move {
        let written = match repository_write.await {
            Ok(written) => written,
            Err(error) => {
                if let Some(refusal) = stale.filter(|_| {
                    NetworkConflictReason::of(&error) == Some(NetworkConflictReason::StaleVersion)
                }) {
                    refusal.append(&audit, &error).await;
                }
                return Err(error);
            }
        };
        let flushed = match flush {
            CacheFlush::None => Ok(()),
            CacheFlush::Subject(subject_id) => {
                authz.invalidate_subject(tenant_id, subject_id).await
            }
            CacheFlush::Tenant => authz.invalidate_tenant(tenant_id).await,
        };
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
        flushed.map(|()| written)
    });
    match task.await {
        Ok(result) => result,
        Err(join) if join.is_panic() => std::panic::resume_unwind(join.into_panic()),
        Err(join) => Err(AxiamError::Internal(format!(
            "a cleared network write was cancelled by the runtime: {join}"
        ))),
    }
}

/// The D7 decision-cache flush a cleared write needs once it landed
/// ([`write_and_record`], R112W4-01), in the writer's tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheFlush {
    /// No cached decision reads what the write changes (a certificate
    /// binding).
    None,
    /// Exactly this subject's decisions changed (a user or service-account
    /// assignment or unassignment).
    Subject(uuid::Uuid),
    /// The affected subjects are not known without a query (a group
    /// assignment, a role delete, a grant or a revoke): every decision of the
    /// tenant.
    Tenant,
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
    // The node the gate decided the assignment at — `/network`'s id for a
    // tenant-wide assignment and for every assignment of a global role — not
    // the resource the caller named (#730 g).
    let node = || cleared.node().ok_or("the node the gate checked");
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
                    "node": node()?,
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
                    "node": node()?,
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
        } => {
            let binding = cleared
                .cleared_binding()
                .ok_or("the binding the gate read")?;
            (
                AUDIT_BINDING_BOUND,
                None,
                serde_json::json!({
                    "certificate_id": certificate_id,
                    "grantee": { "kind": "service_account", "id": service_account_id },
                    // The account the certificate was taken from on a re-bind
                    // (`null` when it was unbound), and the nodes at which the
                    // gate required the binder to hold `network:grant`.
                    "before": binding.before,
                    "nodes": binding.nodes,
                }),
            )
        }
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

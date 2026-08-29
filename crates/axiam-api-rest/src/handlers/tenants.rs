//! Tenant management endpoints (nested under organizations).
//!
//! # Deleting a tenant destroys its audit trail (T-118)
//!
//! Tenant data is tenant-scoped all the way down, and `audit_log` is no
//! exception: the rows that record what happened inside a tenant carry that
//! tenant's id and go when it goes. That is the evidence disappearing at
//! exactly the moment it matters, and until beta03 the threat model resolved
//! it by telling operators to "export to a WORM sink first" — a rule nothing
//! checked.
//!
//! It is now checked. [`export_audit`] streams a tenant's complete audit trail
//! and records that it did so *in that tenant's own audit log*; [`delete`]
//! refuses with `409` unless such a record exists and is less than
//! [`AUDIT_EXPORT_MAX_AGE_HOURS`] hours old. The window is deliberately short
//! and deliberately not configurable: the point is that the export is
//! contemporaneous with the deletion, not that one was taken at some time in
//! the tenant's history.
//!
//! ## What this does and does not prove
//!
//! It proves that a named principal asked this server for the whole trail, and
//! that the server produced it, minutes before the deletion. It does **not**
//! prove the bytes were kept — an operator can stream the export to
//! `/dev/null`. Nothing in-product can prove custody of a file it handed to
//! someone else; what changes is that destroying a tenant's audit trail is now
//! a deliberate two-step act by an identified principal, recorded twice (the
//! export receipt, and the deletion record written to the *system* audit log,
//! which survives the tenant).
//!
//! ## GDPR Art. 17
//!
//! The gate delays an erasure by the length of one export, and does not block
//! it: there is no `?force` and no configuration that turns the requirement
//! off, because the export is the thing that makes erasure safe rather than an
//! obstacle to it. Art. 17(3)(b)/(e) already permit retention where processing
//! is necessary for legal obligations or the defence of legal claims, which is
//! what an exported audit trail is for; and the export contains no more
//! personal data than the tenant already held. A deployment whose lawful basis
//! does not permit keeping the export simply deletes the file — the receipt
//! records that an export happened, never its contents.

use actix_web::http::header;
use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::tenant::{CreateTenant, Tenant, TenantKind, UpdateTenant};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination, TenantRepository,
};
use axiam_db::seeder::{seed_default_roles, seed_permissions};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::handlers::gdpr::write_erasure_audit_with_dlq;
use crate::permissions::PERMISSION_REGISTRY;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// T-118: the audit-export gate on tenant deletion
// ---------------------------------------------------------------------------

/// Audit action recorded by [`export_audit`], and the one [`delete`] looks for.
///
/// Namespaced under `tenants.` like the rest of the management surface. It is
/// written with `outcome = Success` only after the whole trail has been
/// streamed, so a half-finished download leaves no receipt behind.
pub const AUDIT_EXPORT_ACTION: &str = "tenants.audit_exported";

/// Audit action recorded — in the **system** log, not the tenant's — when a
/// tenant is deleted. The tenant's own entries are gone by then; this is what
/// is left to say the deletion happened, who did it, and which export receipt
/// authorised it.
pub const TENANT_DELETED_ACTION: &str = "tenants.deleted";

/// How recent the export receipt must be for [`delete`] to accept it.
///
/// Six hours: long enough that an operator can export, verify the file landed
/// in their archive, and get an approval before deleting; short enough that
/// the export is unmistakably *about this deletion* rather than a routine dump
/// from last quarter. Not configurable — a deployment that could set this to a
/// year would have the rule without the property the rule exists for.
pub const AUDIT_EXPORT_MAX_AGE_HOURS: i64 = 6;

/// Rows fetched from the datastore per round trip while streaming an export.
///
/// The export is streamed rather than assembled because a tenant's audit trail
/// has no upper bound — the retention sweep (T-119) bounds its *age*, not its
/// size — and materialising one in the response buffer would make a large
/// tenant's export an out-of-memory condition on the server.
const AUDIT_EXPORT_PAGE_SIZE: u64 = 500;

/// One step of the export stream.
enum ExportPhase {
    /// Still draining `audit_log`, `offset` rows in.
    Rows {
        offset: u64,
        count: u64,
        hasher: Sha256,
    },
    /// Rows exhausted: write the receipt and emit the trailing manifest line.
    Manifest { count: u64, digest: String },
    /// Nothing further to emit.
    Done,
}

/// The most recent successful export receipt for `tenant_id`, if one falls
/// inside the freshness window.
///
/// Reads the tenant's own audit log — the receipt is an ordinary append-only
/// entry, so this needs no new table, no new retention rule and no second
/// source of truth that could disagree with the trail it is about.
async fn recent_export_receipt<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<(Uuid, DateTime<Utc>)>, AxiamError> {
    let cutoff = now - chrono::Duration::hours(AUDIT_EXPORT_MAX_AGE_HOURS);
    let page = state
        .audit_repo
        .list(
            tenant_id,
            AuditLogFilter {
                action: Some(AUDIT_EXPORT_ACTION.to_string()),
                outcome: Some(AuditOutcome::Success),
                from: Some(cutoff),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                // `list` orders by timestamp DESC, so one row is the newest.
                limit: 1,
                search: None,
            },
        )
        .await?;
    Ok(page
        .items
        .into_iter()
        .next()
        .map(|entry| (entry.id, entry.timestamp)))
}

/// Request body for tenant creation (organization_id comes from the URL path).
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateTenantRequest {
    pub name: String,
    pub slug: String,
    pub metadata: Option<serde_json::Value>,
}

/// Path parameters for tenant collection endpoints.
#[derive(Debug, Deserialize)]
pub struct OrgPath {
    pub org_id: Uuid,
}

/// Path parameters for single-tenant endpoints.
#[derive(Debug, Deserialize)]
pub struct TenantPath {
    pub org_id: Uuid,
    pub tenant_id: Uuid,
}

/// `POST /api/v1/organizations/{org_id}/tenants`
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/tenants",
    tag = "tenants",
    params(("org_id" = Uuid, Path, description = "Organization ID")),
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created", body = Tenant),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<OrgPath>,
    body: web::Json<CreateTenantRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    // Authorization: only allow creating tenants under the caller's own org.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let req = body.into_inner();

    // The organization scope is created with its organization, never through
    // this endpoint. Refusing the reserved slug here turns what would be an
    // opaque unique-index violation into a message that says which name is
    // taken and why.
    if req.slug == axiam_core::models::tenant::ORGANIZATION_TENANT_SLUG {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!(
                "`{}` is reserved for the organization's own scope, which is created \
                 with the organization; choose another slug",
                axiam_core::models::tenant::ORGANIZATION_TENANT_SLUG
            ),
        }));
    }

    let input = CreateTenant {
        organization_id: path.org_id,
        name: req.name,
        slug: req.slug,
        // Always an ordinary tenant: `CreateTenant::kind` is
        // `skip_deserializing`, so a caller cannot ask for anything else, and
        // saying so explicitly here keeps that visible at the one call site
        // that matters.
        kind: TenantKind::Standard,
        metadata: req.metadata,
    };
    let tenant = state.tenant_repo.create(input).await?;

    // Auto-seed permissions for the new tenant so RBAC works immediately.
    seed_permissions(&state.db.current(), tenant.id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to seed permissions for new tenant {}: {}",
                tenant.id,
                e
            );
            AxiamApiError(AxiamError::Internal(
                "Failed to seed permissions for tenant".into(),
            ))
        })?;

    // …and its roles. Seeding permissions alone left the tenant holding a set
    // of actions with nothing to attach them to: no roles, no grants, no
    // assignments. The authorization engine filters every lookup by tenant, so
    // the first question anyone asked about the new tenant — including the
    // person who had just created it — resolved to `no roles assigned` and was
    // denied. A tenant nobody can administer is not a tenant.
    //
    // Not best-effort, unlike the permission seed's sibling failure paths
    // elsewhere: a tenant with permissions and no roles is exactly the
    // unreachable state this repairs, so failing here has to be visible rather
    // than leaving one behind for someone to find later.
    seed_default_roles(&state.db.current(), tenant.id, PERMISSION_REGISTRY)
        .await
        .map_err(|e| {
            tracing::error!(
                tenant_id = %tenant.id,
                error = %e,
                "Failed to seed default roles for new tenant"
            );
            AxiamApiError(AxiamError::Internal(
                "Failed to seed default roles for tenant".into(),
            ))
        })?;

    // Nothing is assigned to anyone here, deliberately. Organization-level
    // principals already reach this tenant — their global grants live in the
    // organization tenant and carry across by the rule in
    // `AuthorizationEngine::evaluate` — so fanning assignments out at creation
    // time would write rows that grant nothing new, would miss every
    // organization-level principal created afterwards, and would have to be
    // undone in every tenant to revoke. See
    // `claude_dev/organization-scope-design.md`.

    Ok(HttpResponse::Created().json(tenant))
}

/// `GET /api/v1/organizations/{org_id}/tenants`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/tenants",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        Pagination,
    ),
    responses(
        (status = 200, description = "List of tenants", body = inline(PaginatedResult<Tenant>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<OrgPath>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: only allow listing tenants under the caller's own org.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let result = state
        .tenant_repo
        .list_by_organization(path.org_id, query.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/organizations/{org_id}/tenants/{tenant_id}`
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Tenant found", body = Tenant),
        (status = 404, description = "Tenant not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: reject cross-org probing before touching the DB.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let tenant = state.tenant_repo.get_by_id(path.tenant_id).await?;
    if tenant.organization_id != path.org_id {
        return Err(AxiamError::NotFound {
            entity: "Tenant".into(),
            id: path.tenant_id.to_string(),
        }
        .into());
    }
    Ok(HttpResponse::Ok().json(tenant))
}

/// `PUT /api/v1/organizations/{org_id}/tenants/{tenant_id}`
#[utoipa::path(
    put,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = UpdateTenant,
    responses(
        (status = 200, description = "Tenant updated", body = Tenant),
        (status = 404, description = "Tenant not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<TenantPath>,
    body: web::Json<UpdateTenant>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    // Authorization: reject cross-org probing before touching the DB.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let existing = state.tenant_repo.get_by_id(path.tenant_id).await?;
    if existing.organization_id != path.org_id {
        return Err(AxiamError::NotFound {
            entity: "Tenant".into(),
            id: path.tenant_id.to_string(),
        }
        .into());
    }
    let tenant = state
        .tenant_repo
        .update(path.tenant_id, body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(tenant))
}

/// `DELETE /api/v1/organizations/{org_id}/tenants/{tenant_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 204, description = "Tenant deleted"),
        (status = 404, description = "Tenant not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // Organization-level action: the caller must live in the organization
    // scope, not merely belong to the organization. See `handlers::org_scope`.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    // Authorization: reject cross-org probing before touching the DB.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthorizationDenied {
                reason: "cannot access a different organization".into(),
                action: None,
                resource_id: None,
            },
        ));
    }

    let existing = state.tenant_repo.get_by_id(path.tenant_id).await?;
    if existing.organization_id != path.org_id {
        return Err(AxiamError::NotFound {
            entity: "Tenant".into(),
            id: path.tenant_id.to_string(),
        }
        .into());
    }

    // T-118: refuse unless the trail about to be destroyed was exported
    // recently. Checked BEFORE the delete, so a refusal leaves the tenant
    // exactly as it was.
    let now = Utc::now();
    let Some((receipt_id, exported_at)) =
        recent_export_receipt(state.get_ref(), path.tenant_id, now).await?
    else {
        return Err(AxiamError::Conflict {
            reason: format!(
                "deleting this tenant destroys its audit trail. Export it first with \
                 POST /api/v1/organizations/{}/tenants/{}/audit-export, then retry \
                 within {AUDIT_EXPORT_MAX_AGE_HOURS} hours.",
                path.org_id, path.tenant_id
            ),
        }
        .into());
    };

    state.tenant_repo.delete(path.tenant_id).await?;

    // The tenant's own audit entries — including the export receipt just
    // checked — went with it, so this record goes to the SYSTEM log (nil
    // tenant), which is the only part of the trail that outlives the tenant.
    // Written through the dead-lettering sink for the same reason the erasure
    // records are: this is the last chance to record it, and a transient
    // datastore failure must not be how it gets lost.
    write_erasure_audit_with_dlq(
        &state.audit_repo,
        CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: user.user_id,
            actor_type: ActorType::User,
            action: TENANT_DELETED_ACTION.to_string(),
            resource_id: Some(path.tenant_id),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "organization_id": path.org_id,
                "tenant_slug": existing.slug,
                "audit_export_receipt_id": receipt_id,
                "audit_exported_at": exported_at,
            })),
        },
    )
    .await;

    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/audit-export`
///
/// Streams the tenant's complete audit trail as newline-delimited JSON, one
/// [`axiam_core::models::audit::AuditLogEntry`] per line, newest first, and
/// records the export in that tenant's audit log — which is what
/// [`delete`] then requires (T-118).
///
/// The last line is not an entry but a manifest object carrying
/// `record_count`, the SHA-256 `digest` over the entry lines that precede it,
/// and `receipt_id` — the id of the audit entry this export wrote. An archive
/// can therefore be tied back to the receipt that authorised the deletion, and
/// re-hashing the file proves it is the export the receipt describes.
///
/// `POST` rather than `GET`: it is not safe and not idempotent — every call
/// appends a receipt.
#[utoipa::path(
    post,
    path = "/api/v1/organizations/{org_id}/tenants/{tenant_id}/audit-export",
    tag = "tenants",
    params(
        ("org_id" = Uuid, Path, description = "Organization ID"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Newline-delimited audit entries, then a \
             manifest line", content_type = "application/x-ndjson"),
        (status = 404, description = "Tenant not found"),
    ),
    security(("bearer" = []))
)]
pub async fn export_audit<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<TenantPath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("tenants:export_audit", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    // Authorization: reject cross-org probing before touching the DB.
    if path.org_id != user.org_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot access a different organization".into(),
            action: None,
            resource_id: None,
        }));
    }

    let existing = state.tenant_repo.get_by_id(path.tenant_id).await?;
    if existing.organization_id != path.org_id {
        return Err(AxiamError::NotFound {
            entity: "Tenant".into(),
            id: path.tenant_id.to_string(),
        }
        .into());
    }

    let tenant_id = path.tenant_id;
    let actor_id = user.user_id;
    let audit_repo = state.audit_repo.clone();
    // Fix the upper bound of the export at the moment it starts. Without it,
    // rows appended while the stream is draining would shift the offsets of
    // every page after them and the export would skip entries.
    let started_at = Utc::now();

    let stream = futures::stream::unfold(
        ExportPhase::Rows {
            offset: 0,
            count: 0,
            hasher: Sha256::new(),
        },
        move |phase| {
            let audit_repo = audit_repo.clone();
            async move {
                match phase {
                    ExportPhase::Rows {
                        offset,
                        count,
                        mut hasher,
                    } => {
                        let page = audit_repo
                            .list(
                                tenant_id,
                                AuditLogFilter {
                                    to: Some(started_at),
                                    ..Default::default()
                                },
                                Pagination {
                                    offset,
                                    limit: AUDIT_EXPORT_PAGE_SIZE,
                                    search: None,
                                },
                            )
                            .await;
                        let page = match page {
                            Ok(page) => page,
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    %tenant_id,
                                    "tenants: audit export failed mid-stream"
                                );
                                // Ending the body with an error truncates the
                                // transfer, so the caller sees a failure rather
                                // than a short file that looks complete. No
                                // receipt is written, so `delete` still refuses.
                                return Some((
                                    Err(actix_web::error::ErrorInternalServerError(
                                        "audit export failed",
                                    )),
                                    ExportPhase::Done,
                                ));
                            }
                        };

                        if page.items.is_empty() {
                            let digest = hex::encode(hasher.finalize());
                            return Some((
                                Ok(web::Bytes::new()),
                                ExportPhase::Manifest { count, digest },
                            ));
                        }

                        let fetched = page.items.len() as u64;
                        let mut chunk = String::new();
                        for entry in &page.items {
                            match serde_json::to_string(entry) {
                                Ok(line) => {
                                    chunk.push_str(&line);
                                    chunk.push('\n');
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        %tenant_id,
                                        "tenants: audit entry could not be serialized"
                                    );
                                    return Some((
                                        Err(actix_web::error::ErrorInternalServerError(
                                            "audit export failed",
                                        )),
                                        ExportPhase::Done,
                                    ));
                                }
                            }
                        }
                        hasher.update(chunk.as_bytes());
                        Some((
                            Ok(web::Bytes::from(chunk)),
                            ExportPhase::Rows {
                                offset: offset + fetched,
                                count: count + fetched,
                                hasher,
                            },
                        ))
                    }

                    ExportPhase::Manifest { count, digest } => {
                        // The receipt is written HERE — after the last row has
                        // been handed to the client — so that an export which
                        // dies half way leaves nothing behind that would let a
                        // tenant be deleted.
                        let receipt = audit_repo
                            .append(CreateAuditLogEntry {
                                tenant_id,
                                actor_id,
                                actor_type: ActorType::User,
                                action: AUDIT_EXPORT_ACTION.to_string(),
                                resource_id: Some(tenant_id),
                                outcome: AuditOutcome::Success,
                                ip_address: None,
                                metadata: Some(serde_json::json!({
                                    "record_count": count,
                                    "digest": format!("sha256:{digest}"),
                                    "exported_through": started_at,
                                })),
                            })
                            .await;
                        let receipt = match receipt {
                            Ok(entry) => entry,
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    %tenant_id,
                                    "tenants: audit export receipt could not be written"
                                );
                                // Without a receipt the export did not happen as
                                // far as `delete` is concerned, so the caller
                                // must be told rather than handed a manifest
                                // that claims otherwise.
                                return Some((
                                    Err(actix_web::error::ErrorInternalServerError(
                                        "audit export receipt could not be written",
                                    )),
                                    ExportPhase::Done,
                                ));
                            }
                        };

                        let manifest = serde_json::json!({
                            "axiam_export": "tenant_audit",
                            "tenant_id": tenant_id,
                            "exported_by": actor_id,
                            "exported_through": started_at,
                            "record_count": count,
                            "digest": format!("sha256:{digest}"),
                            "receipt_id": receipt.id,
                            "receipt_valid_for_hours": AUDIT_EXPORT_MAX_AGE_HOURS,
                        });
                        Some((
                            Ok(web::Bytes::from(format!("{manifest}\n"))),
                            ExportPhase::Done,
                        ))
                    }

                    ExportPhase::Done => None,
                }
            }
        },
    );

    let filename = format!(
        "axiam-audit-{tenant_id}-{}.ndjson",
        started_at.format("%Y%m%dT%H%M%SZ")
    );
    Ok(HttpResponse::Ok()
        .content_type("application/x-ndjson")
        .insert_header((
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        ))
        .streaming(Box::pin(stream)))
}

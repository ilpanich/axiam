use actix_web::{HttpResponse, web};
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::state::AppState;

/// `GET /api/v1/audit-logs`
#[utoipa::path(
    get,
    path = "/api/v1/audit-logs",
    tag = "audit",
    params(Pagination, AuditLogFilter),
    responses(
        (status = 200, description = "Paginated audit log entries",
         body = inline(PaginatedResult<AuditLogEntry>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
    filter: web::Query<AuditLogFilter>,
) -> Result<HttpResponse, AxiamApiError> {
    // Self-service: always allowed. Backend already filters by tenant_id.
    // Admins with audit_logs:list can see all entries; others see only their own.
    let authz_result = RequirePermission::new("audit_logs:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await;
    let mut f = filter.into_inner();
    if authz_result.is_err() {
        // Not an admin — restrict to the caller's own entries via actor_id.
        f.actor_id = Some(user.user_id);
    }
    let result = state
        .audit_repo
        .list(user.tenant_id, f, pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/audit-logs/system`
///
/// Returns audit entries for unauthenticated/system requests (nil tenant_id).
///
/// Of the caller's organization only (SA-02, N1): the partition is
/// deployment-wide, and this returns the entries whose recorded
/// `organization_id` is the caller's own. The server records one on a new
/// entry only where it resolved it with certainty — a deleted tenant's
/// organization, a verified SCIM token's tenant's, an organization or tenant
/// the request's path names and that exists. An entry with none, every entry
/// written before the field existed among them, is returned to nobody.
///
/// Organization-level: requires `audit_logs:list_system` and a caller whose
/// own record lives in the organization's scope tenant; a tenant
/// administrator is refused `403` whatever its role holds.
#[utoipa::path(
    get,
    path = "/api/v1/audit-logs/system",
    tag = "audit",
    params(Pagination, AuditLogFilter),
    responses(
        (status = 200, description = "Paginated system audit log entries of the caller's \
                                      organization",
         body = inline(PaginatedResult<AuditLogEntry>)),
        (status = 403, description = "The caller is not an organization-level principal, or \
                                      lacks `audit_logs:list_system`"),
    ),
    security(("bearer" = []))
)]
pub async fn list_system<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    pagination: web::Query<Pagination>,
    filter: web::Query<AuditLogFilter>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("audit_logs:list_system", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // SA-02 (N1): the nil-tenant partition is deployment-wide — it holds the
    // unattributed request rows (client IP, method and path) of every tenant,
    // other organizations' included. Reading it is an organization-level act,
    // never a tenant administrator's, whatever its role carries. See
    // `handlers::org_scope`.
    //
    // And only the rows of the caller's own organization (review Q-3/S-2):
    // the organization of the caller's own record, as the datastore has it —
    // read from the scope tenant the guard has just loaded (QR2-10).
    let organization_id =
        crate::handlers::org_scope::require_organization_principal(&user, state.get_ref())
            .await?
            .organization_id;
    let result = state
        .audit_repo
        .list_system(
            organization_id,
            filter.into_inner(),
            pagination.into_inner(),
        )
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

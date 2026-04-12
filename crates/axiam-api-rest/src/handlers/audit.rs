use actix_web::{HttpResponse, web};
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use axiam_db::SurrealAuditLogRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;

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
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealAuditLogRepository<C>>,
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
    let result = repo
        .list(user.tenant_id, f, pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/audit-logs/system`
///
/// Returns audit entries for unauthenticated/system requests (nil tenant_id).
/// Requires authentication — only logged-in users can query system audit logs.
#[utoipa::path(
    get,
    path = "/api/v1/audit-logs/system",
    tag = "audit",
    params(Pagination, AuditLogFilter),
    responses(
        (status = 200, description = "Paginated system audit log entries",
         body = inline(PaginatedResult<AuditLogEntry>)),
    ),
    security(("bearer" = []))
)]
pub async fn list_system<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealAuditLogRepository<C>>,
    pagination: web::Query<Pagination>,
    filter: web::Query<AuditLogFilter>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("audit_logs:list_system", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = repo
        .list_system(filter.into_inner(), pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

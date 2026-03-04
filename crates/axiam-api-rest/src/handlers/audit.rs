use actix_web::{HttpResponse, web};
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use axiam_db::SurrealAuditLogRepository;
use surrealdb::Connection;

use crate::AuthenticatedUser;
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
    repo: web::Data<SurrealAuditLogRepository<C>>,
    pagination: web::Query<Pagination>,
    filter: web::Query<AuditLogFilter>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo
        .list(user.tenant_id, filter.into_inner(), pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

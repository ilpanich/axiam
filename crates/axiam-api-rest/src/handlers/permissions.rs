//! Permission management and role-permission grant endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::permission::{
    CreatePermission, Permission, PermissionGrant, UpdatePermission,
};
use axiam_core::repository::{PaginatedResult, Pagination, PermissionRepository};
use axiam_db::SurrealPermissionRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreatePermissionRequest {
    pub action: String,
    pub description: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct GrantPermissionRequest {
    pub permission_id: Uuid,
    #[serde(default)]
    pub scope_ids: Vec<Uuid>,
}

// -----------------------------------------------------------------------
// Path extractors
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RolePermissionPath {
    pub role_id: Uuid,
    pub permission_id: Uuid,
}

// -----------------------------------------------------------------------
// Handlers — CRUD
// -----------------------------------------------------------------------

/// `POST /api/v1/permissions`
#[utoipa::path(
    post,
    path = "/api/v1/permissions",
    tag = "permissions",
    request_body = CreatePermissionRequest,
    responses(
        (status = 201, description = "Permission created", body = Permission),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    body: web::Json<CreatePermissionRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let input = CreatePermission {
        tenant_id: user.tenant_id,
        action: req.action,
        description: req.description,
    };
    let permission = repo.create(input).await?;
    Ok(HttpResponse::Created().json(permission))
}

/// `GET /api/v1/permissions`
#[utoipa::path(
    get,
    path = "/api/v1/permissions",
    tag = "permissions",
    params(Pagination),
    responses(
        (status = 200, description = "List of permissions", body = inline(PaginatedResult<Permission>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/permissions/{permission_id}`
#[utoipa::path(
    get,
    path = "/api/v1/permissions/{permission_id}",
    tag = "permissions",
    params(("permission_id" = Uuid, Path, description = "Permission ID")),
    responses(
        (status = 200, description = "Permission found", body = Permission),
        (status = 404, description = "Permission not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let permission = repo.get_by_id(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(permission))
}

/// `PUT /api/v1/permissions/{permission_id}`
#[utoipa::path(
    put,
    path = "/api/v1/permissions/{permission_id}",
    tag = "permissions",
    params(("permission_id" = Uuid, Path, description = "Permission ID")),
    request_body = UpdatePermission,
    responses(
        (status = 200, description = "Permission updated", body = Permission),
        (status = 404, description = "Permission not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdatePermission>,
) -> Result<HttpResponse, AxiamApiError> {
    let permission = repo
        .update(user.tenant_id, path.into_inner(), body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(permission))
}

/// `DELETE /api/v1/permissions/{permission_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/permissions/{permission_id}",
    tag = "permissions",
    params(("permission_id" = Uuid, Path, description = "Permission ID")),
    responses(
        (status = 204, description = "Permission deleted"),
        (status = 404, description = "Permission not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

// -----------------------------------------------------------------------
// Handlers — Role ↔ Permission grants
// -----------------------------------------------------------------------

/// `POST /api/v1/roles/{role_id}/permissions`
#[utoipa::path(
    post,
    path = "/api/v1/roles/{role_id}/permissions",
    tag = "permissions",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    request_body = GrantPermissionRequest,
    responses(
        (status = 204, description = "Permission granted to role"),
    ),
    security(("bearer" = []))
)]
pub async fn grant_to_role<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<GrantPermissionRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    repo.grant_to_role_with_scopes(
        user.tenant_id,
        path.into_inner(),
        req.permission_id,
        req.scope_ids,
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /api/v1/roles/{role_id}/permissions`
#[utoipa::path(
    get,
    path = "/api/v1/roles/{role_id}/permissions",
    tag = "permissions",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 200, description = "Permission grants for role", body = Vec<PermissionGrant>),
    ),
    security(("bearer" = []))
)]
pub async fn list_role_permissions<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let grants = repo
        .get_role_permission_grants(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(grants))
}

/// `DELETE /api/v1/roles/{role_id}/permissions/{permission_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/roles/{role_id}/permissions/{permission_id}",
    tag = "permissions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("permission_id" = Uuid, Path, description = "Permission ID"),
    ),
    responses(
        (status = 204, description = "Permission revoked from role"),
    ),
    security(("bearer" = []))
)]
pub async fn revoke_from_role<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    path: web::Path<RolePermissionPath>,
) -> Result<HttpResponse, AxiamApiError> {
    let p = path.into_inner();
    repo.revoke_from_role(user.tenant_id, p.role_id, p.permission_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

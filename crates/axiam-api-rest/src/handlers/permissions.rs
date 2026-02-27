//! Permission management and role-permission grant endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::permission::{CreatePermission, UpdatePermission};
use axiam_core::repository::{Pagination, PermissionRepository};
use axiam_db::SurrealPermissionRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreatePermissionRequest {
    pub action: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
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
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/permissions/{permission_id}`
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealPermissionRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let permission = repo.get_by_id(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(permission))
}

/// `PUT /api/v1/permissions/{permission_id}`
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

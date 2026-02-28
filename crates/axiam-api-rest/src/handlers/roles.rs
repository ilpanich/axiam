//! Role management and role-assignment endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::role::{CreateRole, Role, UpdateRole};
use axiam_core::repository::{PaginatedResult, Pagination, RoleRepository};
use axiam_db::SurrealRoleRepository;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: String,
    pub is_global: bool,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssignRoleToUserRequest {
    pub user_id: Uuid,
    pub resource_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssignRoleToGroupRequest {
    pub group_id: Uuid,
    pub resource_id: Option<Uuid>,
}

// -----------------------------------------------------------------------
// Path extractors
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RoleUserPath {
    pub role_id: Uuid,
    pub user_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct RoleGroupPath {
    pub role_id: Uuid,
    pub group_id: Uuid,
}

// -----------------------------------------------------------------------
// Handlers — CRUD
// -----------------------------------------------------------------------

/// `POST /api/v1/roles`
#[utoipa::path(
    post,
    path = "/api/v1/roles",
    tag = "roles",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created", body = Role),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    body: web::Json<CreateRoleRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let input = CreateRole {
        tenant_id: user.tenant_id,
        name: req.name,
        description: req.description,
        is_global: req.is_global,
    };
    let role = repo.create(input).await?;
    Ok(HttpResponse::Created().json(role))
}

/// `GET /api/v1/roles`
#[utoipa::path(
    get,
    path = "/api/v1/roles",
    tag = "roles",
    params(Pagination),
    responses(
        (status = 200, description = "List of roles", body = inline(PaginatedResult<Role>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/roles/{role_id}`
#[utoipa::path(
    get,
    path = "/api/v1/roles/{role_id}",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 200, description = "Role found", body = Role),
        (status = 404, description = "Role not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let role = repo.get_by_id(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(role))
}

/// `PUT /api/v1/roles/{role_id}`
#[utoipa::path(
    put,
    path = "/api/v1/roles/{role_id}",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    request_body = UpdateRole,
    responses(
        (status = 200, description = "Role updated", body = Role),
        (status = 404, description = "Role not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateRole>,
) -> Result<HttpResponse, AxiamApiError> {
    let role = repo
        .update(user.tenant_id, path.into_inner(), body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(role))
}

/// `DELETE /api/v1/roles/{role_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/roles/{role_id}",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 204, description = "Role deleted"),
        (status = 404, description = "Role not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

// -----------------------------------------------------------------------
// Handlers — Role ↔ User assignment
// -----------------------------------------------------------------------

/// `POST /api/v1/roles/{role_id}/users`
#[utoipa::path(
    post,
    path = "/api/v1/roles/{role_id}/users",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    request_body = AssignRoleToUserRequest,
    responses(
        (status = 204, description = "Role assigned to user"),
    ),
    security(("bearer" = []))
)]
pub async fn assign_to_user<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<AssignRoleToUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    repo.assign_to_user(
        user.tenant_id,
        req.user_id,
        path.into_inner(),
        req.resource_id,
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /api/v1/roles/{role_id}/users/{user_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/roles/{role_id}/users/{user_id}",
    tag = "roles",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("user_id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 204, description = "Role unassigned from user"),
    ),
    security(("bearer" = []))
)]
pub async fn unassign_from_user<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    path: web::Path<RoleUserPath>,
) -> Result<HttpResponse, AxiamApiError> {
    let p = path.into_inner();
    repo.unassign_from_user(user.tenant_id, p.user_id, p.role_id, None)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

// -----------------------------------------------------------------------
// Handlers — Role ↔ Group assignment
// -----------------------------------------------------------------------

/// `POST /api/v1/roles/{role_id}/groups`
#[utoipa::path(
    post,
    path = "/api/v1/roles/{role_id}/groups",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    request_body = AssignRoleToGroupRequest,
    responses(
        (status = 204, description = "Role assigned to group"),
    ),
    security(("bearer" = []))
)]
pub async fn assign_to_group<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<AssignRoleToGroupRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    repo.assign_to_group(
        user.tenant_id,
        req.group_id,
        path.into_inner(),
        req.resource_id,
    )
    .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /api/v1/roles/{role_id}/groups/{group_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/roles/{role_id}/groups/{group_id}",
    tag = "roles",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("group_id" = Uuid, Path, description = "Group ID"),
    ),
    responses(
        (status = 204, description = "Role unassigned from group"),
    ),
    security(("bearer" = []))
)]
pub async fn unassign_from_group<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealRoleRepository<C>>,
    path: web::Path<RoleGroupPath>,
) -> Result<HttpResponse, AxiamApiError> {
    let p = path.into_inner();
    repo.unassign_from_group(user.tenant_id, p.group_id, p.role_id, None)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

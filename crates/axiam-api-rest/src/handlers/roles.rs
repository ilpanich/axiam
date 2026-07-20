//! Role management and role-assignment endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::group::Group;
use axiam_core::models::role::{CreateRole, Role, UpdateRole};
use axiam_core::repository::{
    GroupRepository, PaginatedResult, Pagination, RoleRepository, UserRepository,
};

use super::users::UserResponse;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

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

/// Optional query parameter for scoped role unassignment.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct UnassignQuery {
    /// If provided, only removes the assignment for this specific resource.
    /// If omitted, removes the global (unscoped) assignment.
    pub resource_id: Option<Uuid>,
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
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateRoleRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = CreateRole {
        tenant_id: user.tenant_id,
        name: req.name,
        description: req.description,
        is_global: req.is_global,
    };
    let role = state.role_repo.create(input).await?;
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
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .role_repo
        .list(user.tenant_id, query.into_inner())
        .await?;
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
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let role = state
        .role_repo
        .get_by_id(user.tenant_id, path.into_inner())
        .await?;
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
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateRole>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let role = state
        .role_repo
        .update(user.tenant_id, path.into_inner(), body.into_inner())
        .await?;
    // D7: a role change (e.g. is_global, name) can narrow effective access for
    // an unknown set of subjects — flush the whole tenant so no stale allow
    // can survive. No-op when the decision cache is disabled.
    authz.get_ref().as_ref().invalidate_tenant(user.tenant_id);
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
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    state
        .role_repo
        .delete(user.tenant_id, path.into_inner())
        .await?;
    // D7: deleting a role revokes it from every subject holding it — flush the
    // tenant so no cached allow granted through this role can survive.
    authz.get_ref().as_ref().invalidate_tenant(user.tenant_id);
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
pub async fn assign_to_user<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<AssignRoleToUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:assign", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let target_user = req.user_id;
    state
        .role_repo
        .assign_to_user(
            user.tenant_id,
            req.user_id,
            path.into_inner(),
            req.resource_id,
        )
        .await?;
    // D7: only this subject's effective permissions change — targeted flush.
    // (Assignment widens access, the safe direction, but we invalidate anyway
    // so the new grant is visible immediately rather than after the TTL.)
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, target_user);
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
        UnassignQuery,
    ),
    responses(
        (status = 204, description = "Role unassigned from user"),
    ),
    security(("bearer" = []))
)]
pub async fn unassign_from_user<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<RoleUserPath>,
    query: web::Query<UnassignQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:unassign", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let p = path.into_inner();
    state
        .role_repo
        .unassign_from_user(user.tenant_id, p.user_id, p.role_id, query.resource_id)
        .await?;
    // D7 (REVOCATION — security critical): unassigning a role removes access
    // for exactly this subject. Invalidate immediately so a cached allow cannot
    // survive; the additive allow-wins model makes this stale-allow the only
    // dangerous staleness direction.
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, p.user_id);
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
pub async fn assign_to_group<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<AssignRoleToGroupRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:assign", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    state
        .role_repo
        .assign_to_group(
            user.tenant_id,
            req.group_id,
            path.into_inner(),
            req.resource_id,
        )
        .await?;
    // D7: the affected subjects are every member of the group (set unknown
    // without a query) — conservative per-tenant flush.
    authz.get_ref().as_ref().invalidate_tenant(user.tenant_id);
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
        UnassignQuery,
    ),
    responses(
        (status = 204, description = "Role unassigned from group"),
    ),
    security(("bearer" = []))
)]
pub async fn unassign_from_group<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<RoleGroupPath>,
    query: web::Query<UnassignQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:unassign", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let p = path.into_inner();
    state
        .role_repo
        .unassign_from_group(user.tenant_id, p.group_id, p.role_id, query.resource_id)
        .await?;
    // D7 (REVOCATION — security critical): unassigning a role from a group
    // revokes it from every member. The member set isn't known here without a
    // query, so flush the whole tenant — this must never leave a stale allow.
    authz.get_ref().as_ref().invalidate_tenant(user.tenant_id);
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /api/v1/roles/{role_id}/users`
///
/// Lists the users directly assigned this role (the inverse of
/// `GET /users/{id}/roles`). Used by the role detail page's members panel.
#[utoipa::path(
    get,
    path = "/api/v1/roles/{role_id}/users",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 200, description = "Users assigned this role", body = [UserResponse]),
    ),
    security(("bearer" = []))
)]
pub async fn list_users<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let role_id = path.into_inner();
    let ids = state
        .role_repo
        .get_role_user_ids(user.tenant_id, role_id)
        .await?;
    let mut users = Vec::with_capacity(ids.len());
    for id in ids {
        users.push(UserResponse::from(
            state.user_repo.get_by_id(user.tenant_id, id).await?,
        ));
    }
    Ok(HttpResponse::Ok().json(users))
}

/// `GET /api/v1/roles/{role_id}/groups`
///
/// Lists the groups directly assigned this role.
#[utoipa::path(
    get,
    path = "/api/v1/roles/{role_id}/groups",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 200, description = "Groups assigned this role", body = [Group]),
    ),
    security(("bearer" = []))
)]
pub async fn list_groups<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let role_id = path.into_inner();
    let ids = state
        .role_repo
        .get_role_group_ids(user.tenant_id, role_id)
        .await?;
    let mut groups: Vec<Group> = Vec::with_capacity(ids.len());
    for id in ids {
        groups.push(state.group_repo.get_by_id(user.tenant_id, id).await?);
    }
    Ok(HttpResponse::Ok().json(groups))
}

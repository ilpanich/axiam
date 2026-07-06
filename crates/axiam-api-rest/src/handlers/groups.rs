//! Group management and membership endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::group::{CreateGroup, Group, UpdateGroup};
use axiam_core::repository::{GroupRepository, PaginatedResult, Pagination};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::handlers::users::UserResponse;
use crate::state::AppState;

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
}

// -----------------------------------------------------------------------
// Path extractors
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MemberPath {
    pub group_id: Uuid,
    pub user_id: Uuid,
}

// -----------------------------------------------------------------------
// Handlers — CRUD
// -----------------------------------------------------------------------

/// `POST /api/v1/groups`
#[utoipa::path(
    post,
    path = "/api/v1/groups",
    tag = "groups",
    request_body = CreateGroupRequest,
    responses(
        (status = 201, description = "Group created", body = Group),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateGroupRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = CreateGroup {
        tenant_id: user.tenant_id,
        name: req.name,
        description: req.description,
        metadata: req.metadata,
    };
    let group = state.group_repo.create(input).await?;
    Ok(HttpResponse::Created().json(group))
}

/// `GET /api/v1/groups`
#[utoipa::path(
    get,
    path = "/api/v1/groups",
    tag = "groups",
    params(Pagination),
    responses(
        (status = 200, description = "List of groups", body = inline(PaginatedResult<Group>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .group_repo
        .list(user.tenant_id, query.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/groups/{group_id}`
#[utoipa::path(
    get,
    path = "/api/v1/groups/{group_id}",
    tag = "groups",
    params(("group_id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Group found", body = Group),
        (status = 404, description = "Group not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let group = state
        .group_repo
        .get_by_id(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(group))
}

/// `PUT /api/v1/groups/{group_id}`
#[utoipa::path(
    put,
    path = "/api/v1/groups/{group_id}",
    tag = "groups",
    params(("group_id" = Uuid, Path, description = "Group ID")),
    request_body = UpdateGroup,
    responses(
        (status = 200, description = "Group updated", body = Group),
        (status = 404, description = "Group not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateGroup>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let group = state
        .group_repo
        .update(user.tenant_id, path.into_inner(), body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(group))
}

/// `DELETE /api/v1/groups/{group_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/groups/{group_id}",
    tag = "groups",
    params(("group_id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 204, description = "Group deleted"),
        (status = 404, description = "Group not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    state
        .group_repo
        .delete(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

// -----------------------------------------------------------------------
// Handlers — Membership
// -----------------------------------------------------------------------

/// `POST /api/v1/groups/{group_id}/members`
#[utoipa::path(
    post,
    path = "/api/v1/groups/{group_id}/members",
    tag = "groups",
    params(("group_id" = Uuid, Path, description = "Group ID")),
    request_body = AddMemberRequest,
    responses(
        (status = 204, description = "Member added"),
    ),
    security(("bearer" = []))
)]
pub async fn add_member<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<AddMemberRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:add_member", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    state
        .group_repo
        .add_member(user.tenant_id, body.user_id, path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /api/v1/groups/{group_id}/members`
#[utoipa::path(
    get,
    path = "/api/v1/groups/{group_id}/members",
    tag = "groups",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        Pagination,
    ),
    responses(
        (status = 200, description = "List of group members", body = inline(PaginatedResult<UserResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list_members<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:list_members", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .group_repo
        .get_members(user.tenant_id, path.into_inner(), query.into_inner())
        .await?;
    let items: Vec<UserResponse> = result.items.into_iter().map(UserResponse::from).collect();
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items,
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
}

/// `DELETE /api/v1/groups/{group_id}/members/{user_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/groups/{group_id}/members/{user_id}",
    tag = "groups",
    params(
        ("group_id" = Uuid, Path, description = "Group ID"),
        ("user_id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 204, description = "Member removed"),
    ),
    security(("bearer" = []))
)]
pub async fn remove_member<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<MemberPath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("groups:remove_member", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let p = path.into_inner();
    state
        .group_repo
        .remove_member(user.tenant_id, p.user_id, p.group_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

//! Role management and role-assignment endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::group::Group;
use axiam_core::models::role::{CreateRole, Role, RoleAssignment, UpdateRole};
use axiam_core::repository::{
    GroupRepository, PaginatedResult, Pagination, RoleRepository, ServiceAccountRepository,
    UserRepository,
};

use super::service_accounts::ServiceAccountResponse;
use super::users::UserResponse;
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct AssignRoleToServiceAccountRequest {
    pub service_account_id: Uuid,
    pub resource_id: Option<Uuid>,
}

// -----------------------------------------------------------------------
// Response types
//
// The two member listings return assignments, not bare subjects. `resource_id`
// separates a grant that applies everywhere from one that applies only under a
// resource, and it is the field `DELETE .../users/{user_id}?resource_id=`
// needs: an unassign that omits it deletes the edge whose `resource_id` is
// `NONE`, so a revoke button rendered next to a scoped grant without it
// silently deletes nothing.
// -----------------------------------------------------------------------

/// A user together with the resource scope of their assignment of this role.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleUserAssignment {
    /// The assigned user.
    pub user: UserResponse,
    /// `None` means the role was assigned globally (no resource scope).
    pub resource_id: Option<Uuid>,
}

/// A group together with the resource scope of its assignment of this role.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleGroupAssignment {
    /// The assigned group.
    pub group: Group,
    /// `None` means the role was assigned globally (no resource scope).
    pub resource_id: Option<Uuid>,
}

/// A service account together with the resource scope of its assignment.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RoleServiceAccountAssignment {
    /// The assigned service account. Carries no secret — the client secret is
    /// returned once, at creation, and never again.
    pub service_account: ServiceAccountResponse,
    /// `None` means the role was assigned globally (no resource scope).
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

#[derive(Debug, Deserialize)]
pub struct RoleServiceAccountPath {
    pub role_id: Uuid,
    pub service_account_id: Uuid,
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
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
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
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
        .await?;
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
    let role_id = path.into_inner();

    // X1 `grant.pre_assign` — the four-eyes hook, veto-only. Before the write:
    // an approval workflow that ran after the grant existed would be reviewing
    // access the subject already has.
    crate::reactor_hooks::grant_pre_assign(
        &state.events.reactor_gate,
        user.tenant_id,
        serde_json::json!({
            "grantee_kind": "user",
            "user_id": target_user,
            "role_id": role_id,
            "resource_id": req.resource_id,
            "tenant_id": user.tenant_id,
            // Who is asking — the half a four-eyes rule is actually about.
            "actor_id": user.user_id,
        }),
    )
    .await?;

    state
        .role_repo
        .assign_to_user(user.tenant_id, req.user_id, role_id, req.resource_id)
        .await?;
    // D7: only this subject's effective permissions change — targeted flush.
    // (Assignment widens access, the safe direction, but we invalidate anyway
    // so the new grant is visible immediately rather than after the TTL.)
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, target_user)
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
    // survive — a stale allow is the dangerous staleness direction, because a
    // deny is the restrictive outcome and costs only a redundant re-check.
    //
    // (Pre-B1 this was justified by the engine being allow-wins. Under
    // deny-override that premise no longer holds, but the conclusion does:
    // see the decision_cache module docs for why, and for the addition that
    // *can* narrow.)
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, p.user_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

// -----------------------------------------------------------------------
// Handlers — Role ↔ Service account assignment
//
// A service account is a principal like any other, and the authorization engine
// has always treated it as one: `RequirePermission::check_subject` applies RBAC
// identically to a machine and a person, and `has_role` is declared
// `User/ServiceAccount/Group -> Role`. What did not exist was any way to create
// the edge — so a service account could authenticate and then do nothing, and
// the only workaround was to give a machine a human's account.
// -----------------------------------------------------------------------

/// `POST /api/v1/roles/{role_id}/service-accounts`
#[utoipa::path(
    post,
    path = "/api/v1/roles/{role_id}/service-accounts",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    request_body = AssignRoleToServiceAccountRequest,
    responses(
        (status = 204, description = "Role assigned to service account"),
        (status = 404, description = "Role or service account not found in this tenant"),
    ),
    security(("bearer" = []))
)]
pub async fn assign_to_service_account<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<AssignRoleToServiceAccountRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:assign", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let role_id = path.into_inner();

    // X1 `grant.pre_assign` — the same veto-only four-eyes hook the user and
    // group paths fire, with `grantee_kind` naming which. A rule that reviews
    // human grants and silently ignores machine ones reviews the easier half.
    crate::reactor_hooks::grant_pre_assign(
        &state.events.reactor_gate,
        user.tenant_id,
        serde_json::json!({
            "grantee_kind": "service_account",
            "service_account_id": req.service_account_id,
            "role_id": role_id,
            "resource_id": req.resource_id,
            "tenant_id": user.tenant_id,
            "actor_id": user.user_id,
        }),
    )
    .await?;

    state
        .role_repo
        .assign_to_service_account(
            user.tenant_id,
            req.service_account_id,
            role_id,
            req.resource_id,
        )
        .await?;
    // D7: the machine's own effective permissions changed — targeted flush, on
    // the same terms as the user path. The engine caches by `(tenant, subject)`
    // and does not care which table the subject came from.
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, req.service_account_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `DELETE /api/v1/roles/{role_id}/service-accounts/{service_account_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/roles/{role_id}/service-accounts/{service_account_id}",
    tag = "roles",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("service_account_id" = Uuid, Path, description = "Service account ID"),
        UnassignQuery,
    ),
    responses(
        (status = 204, description = "Role unassigned from service account"),
    ),
    security(("bearer" = []))
)]
pub async fn unassign_from_service_account<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<RoleServiceAccountPath>,
    query: web::Query<UnassignQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:unassign", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let p = path.into_inner();
    state
        .role_repo
        .unassign_from_service_account(
            user.tenant_id,
            p.service_account_id,
            p.role_id,
            query.resource_id,
        )
        .await?;
    // D7 (REVOCATION — security critical): a cached allow must not outlive the
    // grant. See `unassign_from_user` for why this direction of staleness is the
    // dangerous one.
    authz
        .get_ref()
        .as_ref()
        .invalidate_subject(user.tenant_id, p.service_account_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /api/v1/roles/{role_id}/service-accounts`
#[utoipa::path(
    get,
    path = "/api/v1/roles/{role_id}/service-accounts",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 200, description = "Service-account assignments of this role",
         body = [RoleServiceAccountAssignment]),
    ),
    security(("bearer" = []))
)]
pub async fn list_service_accounts<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let role_id = path.into_inner();
    let assignments = state
        .role_repo
        .get_role_service_account_assignments(user.tenant_id, role_id)
        .await?;
    let mut rows = Vec::with_capacity(assignments.len());
    for a in assignments {
        rows.push(RoleServiceAccountAssignment {
            service_account: ServiceAccountResponse::from(
                state
                    .service_account_repo
                    .get_by_id(user.tenant_id, a.subject_id)
                    .await?,
            ),
            resource_id: a.resource_id,
        });
    }
    Ok(HttpResponse::Ok().json(rows))
}

/// `GET /api/v1/service-accounts/{service_account_id}/roles`
#[utoipa::path(
    get,
    path = "/api/v1/service-accounts/{service_account_id}/roles",
    tag = "roles",
    params(("service_account_id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Role assignments of this service account, \
                                      direct and inherited through groups",
         body = [RoleAssignment]),
        (status = 404, description = "Service account not found in this tenant"),
    ),
    security(("bearer" = []))
)]
pub async fn list_service_account_roles<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let target = path.into_inner();
    // Confine the lookup to the caller's tenant first, for the same reason
    // `list_user_roles` does: a missing account must read as 404 rather than as
    // an empty role list, which would say "this account has no roles" about an
    // account belonging to some other tenant.
    state
        .service_account_repo
        .get_by_id(user.tenant_id, target)
        .await?;
    let assignments = state
        .role_repo
        .get_user_role_assignments(user.tenant_id, target)
        .await?;
    Ok(HttpResponse::Ok().json(assignments))
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
    let role_id = path.into_inner();

    // X1 `grant.pre_assign` — the group half. A role assigned to a group is
    // inherited by every member, so it is the *wider* of the two assignment
    // paths and the one a four-eyes rule most needs to see.
    crate::reactor_hooks::grant_pre_assign(
        &state.events.reactor_gate,
        user.tenant_id,
        serde_json::json!({
            "grantee_kind": "group",
            "group_id": req.group_id,
            "role_id": role_id,
            "resource_id": req.resource_id,
            "tenant_id": user.tenant_id,
            "actor_id": user.user_id,
        }),
    )
    .await?;

    state
        .role_repo
        .assign_to_group(user.tenant_id, req.group_id, role_id, req.resource_id)
        .await?;
    // D7: the affected subjects are every member of the group (set unknown
    // without a query) — conservative per-tenant flush.
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
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
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `GET /api/v1/roles/{role_id}/users`
///
/// Lists this role's user assignments (the inverse of
/// `GET /users/{user_id}/roles`). Used by the role detail page's members panel.
///
/// Directly-assigned users only — a user who reaches this role through a group
/// is not a member of it and has no grant here to revoke. `resource_id` says
/// whether the grant is global or applies only under one resource; `has_role`
/// is `UNIQUE(in, out)`, so each user appears at most once.
#[utoipa::path(
    get,
    path = "/api/v1/roles/{role_id}/users",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 200, description = "User assignments of this role",
         body = [RoleUserAssignment]),
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
    let assignments = state
        .role_repo
        .get_role_user_assignments(user.tenant_id, role_id)
        .await?;
    let mut rows = Vec::with_capacity(assignments.len());
    for a in assignments {
        rows.push(RoleUserAssignment {
            user: UserResponse::from(
                state
                    .user_repo
                    .get_by_id(user.tenant_id, a.subject_id)
                    .await?,
            ),
            resource_id: a.resource_id,
        });
    }
    Ok(HttpResponse::Ok().json(rows))
}

/// `GET /api/v1/roles/{role_id}/groups`
///
/// Lists this role's group assignments (the inverse of
/// `GET /groups/{group_id}/roles`), each with the resource it is scoped to —
/// see [`list_users`] for why that field is here.
#[utoipa::path(
    get,
    path = "/api/v1/roles/{role_id}/groups",
    tag = "roles",
    params(("role_id" = Uuid, Path, description = "Role ID")),
    responses(
        (status = 200, description = "Group assignments of this role",
         body = [RoleGroupAssignment]),
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
    let assignments = state
        .role_repo
        .get_role_group_assignments(user.tenant_id, role_id)
        .await?;
    let mut rows = Vec::with_capacity(assignments.len());
    for a in assignments {
        rows.push(RoleGroupAssignment {
            group: state
                .group_repo
                .get_by_id(user.tenant_id, a.subject_id)
                .await?,
            resource_id: a.resource_id,
        });
    }
    Ok(HttpResponse::Ok().json(rows))
}

/// `GET /api/v1/users/{user_id}/roles`
///
/// Lists a user's role assignments with the resource each is scoped to.
///
/// Includes roles reaching the user **through group membership**, not only the
/// ones assigned to them directly — that is what a user's effective role list
/// is, and splitting the two would give a caller a list that disagrees with the
/// authorization decision. Anything the role detail page's members panel shows
/// as a group assignment therefore also appears here for each member.
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}/roles",
    tag = "roles",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "Role assignments of this user",
         body = [RoleAssignment]),
    ),
    security(("bearer" = []))
)]
pub async fn list_user_roles<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let target = path.into_inner();
    // Confine the lookup to the caller's tenant before touching the edges: the
    // repository predicate does the same, but a missing user must read as 404
    // rather than as an empty role list, which would say "this user has no
    // roles" about a user of some other tenant.
    state.user_repo.get_by_id(user.tenant_id, target).await?;
    let assignments = state
        .role_repo
        .get_user_role_assignments(user.tenant_id, target)
        .await?;
    Ok(HttpResponse::Ok().json(assignments))
}

/// `GET /api/v1/groups/{group_id}/roles`
///
/// Lists a group's role assignments with the resource each is scoped to. Every
/// member of the group inherits these.
#[utoipa::path(
    get,
    path = "/api/v1/groups/{group_id}/roles",
    tag = "roles",
    params(("group_id" = Uuid, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Role assignments of this group",
         body = [RoleAssignment]),
    ),
    security(("bearer" = []))
)]
pub async fn list_group_roles<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("roles:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let group_id = path.into_inner();
    // Same reason as `list_user_roles`: 404 for a group of another tenant, not
    // an empty list.
    state.group_repo.get_by_id(user.tenant_id, group_id).await?;
    let assignments = state
        .role_repo
        .get_group_role_assignments(user.tenant_id, group_id)
        .await?;
    Ok(HttpResponse::Ok().json(assignments))
}

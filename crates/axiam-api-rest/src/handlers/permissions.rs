//! Permission management and role-permission grant endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::permission::{
    CreatePermission, Permission, PermissionEffect, PermissionGrant, UpdatePermission,
};
use axiam_core::repository::{PaginatedResult, Pagination, PermissionRepository};
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
pub struct CreatePermissionRequest {
    pub action: String,
    pub description: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdatePermissionRequest {
    pub action: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct GrantPermissionRequest {
    pub permission_id: Uuid,
    #[serde(default)]
    pub scope_ids: Vec<Uuid>,
    /// B1: `"allow"` (the default) or `"deny"`.
    ///
    /// A deny grant **overrides every allow**, at any depth of the resource
    /// hierarchy and at equal specificity — it is not most-specific-wins. See
    /// `claude_dev/deny-override-design.md` for the precedence table and for
    /// why that trade was made.
    ///
    /// Omitting the field means `"allow"`, so every existing client keeps
    /// working unchanged and no migration is required.
    #[serde(default)]
    pub effect: PermissionEffect,
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
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreatePermissionRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = CreatePermission {
        tenant_id: user.tenant_id,
        action: req.action,
        description: req.description,
    };
    let permission = state.permission_repo.create(input).await?;
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
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = state
        .permission_repo
        .list(user.tenant_id, query.into_inner())
        .await?;
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
pub async fn get<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let permission = state
        .permission_repo
        .get_by_id(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(permission))
}

/// `PUT /api/v1/permissions/{permission_id}`
#[utoipa::path(
    put,
    path = "/api/v1/permissions/{permission_id}",
    tag = "permissions",
    params(("permission_id" = Uuid, Path, description = "Permission ID")),
    request_body = UpdatePermissionRequest,
    responses(
        (status = 200, description = "Permission updated", body = Permission),
        (status = 404, description = "Permission not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdatePermissionRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = UpdatePermission {
        action: req.action,
        description: req.description,
    };
    let permission = state
        .permission_repo
        .update(user.tenant_id, path.into_inner(), input)
        .await?;
    // D7 (REVOCATION — security critical): changing a permission's `action`
    // narrows access (a subject allowed for the old action is now denied).
    // Flush the tenant.
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
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
pub async fn delete<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    state
        .permission_repo
        .delete(user.tenant_id, path.into_inner())
        .await?;
    // D7 (REVOCATION — security critical): deleting a permission removes it
    // from every role/subject that was granted it. Flush the tenant.
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
        .await?;
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
pub async fn grant_to_role<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<GrantPermissionRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:grant", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    state
        .permission_repo
        .grant_to_role_with_effect(
            user.tenant_id,
            path.into_inner(),
            req.permission_id,
            req.scope_ids,
            req.effect,
        )
        .await?;
    // D7: an ALLOW grant widens access (safe direction) for every subject
    // holding the role (set unknown here) — flush the tenant so the new grant
    // is visible immediately.
    //
    // B1: a DENY grant *narrows* access, which is the direction where a stale
    // cache is a security problem rather than an inconvenience. The same
    // tenant flush covers it, on the same event path and with the same
    // measured 262 ms contract — a deny rule is a grant, not a special case.
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
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
        (status = 200, description = "Permission grants for role, with scopes resolved",
         body = Vec<ResolvedPermissionGrant>),
    ),
    security(("bearer" = []))
)]
pub async fn list_role_permissions<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let grants = state
        .permission_repo
        .get_role_permission_grants(user.tenant_id, path.into_inner())
        .await?;

    // Resolve each grant's `scope_ids` to the scopes they name.
    //
    // The grant edge stores scope UUIDs and nothing else, so the admin UI could
    // only ever render "3 scopes" — a number with no way to find out which
    // three. Answering "which scopes does this grant cover?" from the client
    // would have meant listing every resource in the tenant and then every
    // resource's scopes, just to turn three UUIDs into three names. The ids are
    // resolved here instead, where one lookup answers it.
    let resolved = resolve_grant_scopes(&state, user.tenant_id, grants).await;
    Ok(HttpResponse::Ok().json(resolved))
}

/// A scope named by a grant, resolved to something a human can read.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct GrantedScope {
    /// The scope's id, as it appears in the grant's `scope_ids`.
    pub id: Uuid,
    /// The scope's name, e.g. `invoices`.
    pub name: String,
    /// The resource the scope belongs to.
    pub resource_id: Uuid,
}

/// A permission grant with its scopes resolved.
///
/// A superset of [`PermissionGrant`]: `scope_ids` is still present and still
/// authoritative, so a client written before `scopes` existed is unaffected.
#[derive(Debug, Clone, serde::Serialize, utoipa::ToSchema)]
pub struct ResolvedPermissionGrant {
    /// The permission this grant is about.
    pub permission: Permission,
    /// The scope ids the grant is constrained to. Empty is the wildcard.
    pub scope_ids: Vec<Uuid>,
    /// Whether the grant permits or refuses.
    pub effect: PermissionEffect,
    /// The scopes `scope_ids` names, in the same order where resolvable.
    ///
    /// A scope that cannot be resolved is **omitted** rather than represented
    /// by a placeholder, so this can be shorter than `scope_ids`. That happens
    /// when a scope was deleted while a grant still referenced it, and showing
    /// a name for something that no longer exists would be worse than showing
    /// one fewer chip beside a count that still says how many ids the grant
    /// carries.
    pub scopes: Vec<GrantedScope>,
}

/// Turn each grant's `scope_ids` into [`GrantedScope`]s.
///
/// One lookup per distinct scope across the whole response, not per grant:
/// several grants on the same role commonly name the same scopes, and issuing
/// the same read once per grant would make a role page's cost quadratic in how
/// carefully its grants were narrowed — penalising exactly the operators doing
/// the right thing.
///
/// A failed lookup drops the scope and logs; it never fails the request. The
/// caller asked for the role's grants, and `scope_ids` — the authoritative
/// part — is already in hand.
async fn resolve_grant_scopes<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    grants: Vec<PermissionGrant>,
) -> Vec<ResolvedPermissionGrant> {
    use axiam_core::repository::ScopeRepository as _;
    use std::collections::HashMap;

    let mut cache: HashMap<Uuid, Option<GrantedScope>> = HashMap::new();
    for grant in &grants {
        for scope_id in &grant.scope_ids {
            if cache.contains_key(scope_id) {
                continue;
            }
            let resolved = match state.scope_repo.get_by_id(tenant_id, *scope_id).await {
                Ok(scope) => Some(GrantedScope {
                    id: scope.id,
                    name: scope.name,
                    resource_id: scope.resource_id,
                }),
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        %tenant_id,
                        %scope_id,
                        "a grant names a scope that no longer resolves"
                    );
                    None
                }
            };
            cache.insert(*scope_id, resolved);
        }
    }

    grants
        .into_iter()
        .map(|grant| {
            let scopes = grant
                .scope_ids
                .iter()
                .filter_map(|id| cache.get(id).and_then(|s| s.clone()))
                .collect();
            ResolvedPermissionGrant {
                permission: grant.permission,
                scope_ids: grant.scope_ids,
                effect: grant.effect,
                scopes,
            }
        })
        .collect()
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
pub async fn revoke_from_role<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<RolePermissionPath>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("permissions:revoke", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let p = path.into_inner();
    state
        .permission_repo
        .revoke_from_role(user.tenant_id, p.role_id, p.permission_id)
        .await?;
    // D7 (REVOCATION — security critical): revoking a grant removes access for
    // every subject holding this role. The subject set isn't known here without
    // a query, so flush the whole tenant — this must never leave a stale allow.
    authz
        .get_ref()
        .as_ref()
        .invalidate_tenant(user.tenant_id)
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

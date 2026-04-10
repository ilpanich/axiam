//! User management endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{PaginatedResult, Pagination, UserRepository};
use axiam_db::SurrealUserRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission, is_own_resource};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub status: Option<UserStatus>,
    pub metadata: Option<serde_json::Value>,
}

/// Public-safe user representation (no password_hash, no mfa_secret).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub status: UserStatus,
    pub mfa_enabled: bool,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Number of consecutive failed login attempts.
    pub failed_login_attempts: u32,
    /// Timestamp until which the account is locked, if any.
    pub locked_until: Option<DateTime<Utc>>,
    /// Whether the account is currently locked (locked_until is in the future).
    pub is_locked: bool,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        let is_locked = u
            .locked_until
            .map(|t| t > chrono::Utc::now())
            .unwrap_or(false);
        Self {
            id: u.id,
            tenant_id: u.tenant_id,
            username: u.username,
            email: u.email,
            status: u.status,
            mfa_enabled: u.mfa_enabled,
            metadata: u.metadata,
            created_at: u.created_at,
            updated_at: u.updated_at,
            failed_login_attempts: u.failed_login_attempts,
            locked_until: u.locked_until,
            is_locked,
        }
    }
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/users`
#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    body: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let req = body.into_inner();
    let input = CreateUser {
        tenant_id: user.tenant_id,
        username: req.username,
        email: req.email,
        password: req.password,
        metadata: req.metadata,
    };
    let created = repo.create(input).await?;
    Ok(HttpResponse::Created().json(UserResponse::from(created)))
}

/// `GET /api/v1/users`
#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "users",
    params(Pagination),
    responses(
        (status = 200, description = "List of users", body = inline(PaginatedResult<UserResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    let items: Vec<UserResponse> = result.items.into_iter().map(UserResponse::from).collect();
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items,
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
}

/// `GET /api/v1/users/{user_id}`
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User found", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let target_id = path.into_inner();
    if !is_own_resource(&user, target_id) {
        RequirePermission::new("users:get", Uuid::nil())
            .check(&user, authz.get_ref().as_ref())
            .await?;
    }
    let target = repo.get_by_id(user.tenant_id, target_id).await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(target)))
}

/// `PUT /api/v1/users/{user_id}`
#[utoipa::path(
    put,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let target_id = path.into_inner();
    if !is_own_resource(&user, target_id) {
        RequirePermission::new("users:update", Uuid::nil())
            .check(&user, authz.get_ref().as_ref())
            .await?;
    }
    let req = body.into_inner();
    let input = UpdateUser {
        username: req.username,
        email: req.email,
        status: req.status,
        metadata: req.metadata,
        ..Default::default()
    };
    let updated = repo
        .update(user.tenant_id, target_id, input)
        .await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(updated)))
}

/// `DELETE /api/v1/users/{user_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 204, description = "User deleted"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/users/{user_id}/unlock`
///
/// Resets a locked user account: clears `locked_until`, resets
/// `failed_login_attempts` to 0, and sets status back to `Active`.
#[utoipa::path(
    post,
    path = "/api/v1/users/{user_id}/unlock",
    tag = "users",
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User unlocked", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn unlock<C: Connection>(
    auth_user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("users:admin", Uuid::nil())
        .check(&auth_user, authz.get_ref().as_ref())
        .await?;
    let user_id = path.into_inner();
    let tenant_id = auth_user.tenant_id;

    let update = UpdateUser {
        failed_login_attempts: Some(0),
        locked_until: Some(None),
        last_failed_login_at: Some(None),
        status: Some(UserStatus::Active),
        ..Default::default()
    };

    let user = repo.update(tenant_id, user_id, update).await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(user)))
}

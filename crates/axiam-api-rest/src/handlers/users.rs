//! User management endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{Pagination, UserRepository};
use axiam_db::SurrealUserRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request / response types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub status: Option<UserStatus>,
    pub metadata: Option<serde_json::Value>,
}

/// Public-safe user representation (no password_hash, no mfa_secret).
#[derive(Debug, Serialize)]
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
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
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
        }
    }
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/users`
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealUserRepository<C>>,
    body: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
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
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealUserRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    let items: Vec<UserResponse> = result.items.into_iter().map(UserResponse::from).collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": items,
        "total": result.total,
        "offset": result.offset,
        "limit": result.limit,
    })))
}

/// `GET /api/v1/users/{user_id}`
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let target = repo.get_by_id(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(target)))
}

/// `PUT /api/v1/users/{user_id}`
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let input = UpdateUser {
        username: req.username,
        email: req.email,
        status: req.status,
        metadata: req.metadata,
        ..Default::default()
    };
    let updated = repo
        .update(user.tenant_id, path.into_inner(), input)
        .await?;
    Ok(HttpResponse::Ok().json(UserResponse::from(updated)))
}

/// `DELETE /api/v1/users/{user_id}`
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealUserRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

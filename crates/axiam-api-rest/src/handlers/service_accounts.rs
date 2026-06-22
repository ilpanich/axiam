//! Service account management endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::service_account::{
    CreateServiceAccount, ServiceAccount, UpdateServiceAccount,
};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{PaginatedResult, Pagination, ServiceAccountRepository};
use axiam_db::SurrealServiceAccountRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateServiceAccountRequest {
    pub name: String,
}

// -----------------------------------------------------------------------
// Response DTOs (strip client_secret_hash)
// -----------------------------------------------------------------------

/// Public-safe service account representation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ServiceAccountResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub client_id: String,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<ServiceAccount> for ServiceAccountResponse {
    fn from(sa: ServiceAccount) -> Self {
        Self {
            id: sa.id,
            tenant_id: sa.tenant_id,
            name: sa.name,
            client_id: sa.client_id,
            status: sa.status,
            created_at: sa.created_at,
            updated_at: sa.updated_at,
        }
    }
}

/// Response for service account creation — includes the one-time plaintext secret.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ServiceAccountCreatedResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub client_id: String,
    pub client_secret: String,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Response for secret rotation.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct RotateSecretResponse {
    pub client_secret: String,
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/service-accounts`
#[utoipa::path(
    post,
    path = "/api/v1/service-accounts",
    tag = "service-accounts",
    request_body = CreateServiceAccountRequest,
    responses(
        (status = 201, description = "Service account created (secret shown once)", body = ServiceAccountCreatedResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    body: web::Json<CreateServiceAccountRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("service_accounts:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let input = CreateServiceAccount {
        tenant_id: user.tenant_id,
        name: body.into_inner().name,
    };
    let (sa, raw_secret) = repo.create(input).await?;
    Ok(HttpResponse::Created().json(ServiceAccountCreatedResponse {
        id: sa.id,
        tenant_id: sa.tenant_id,
        name: sa.name,
        client_id: sa.client_id,
        client_secret: raw_secret,
        status: sa.status,
        created_at: sa.created_at,
        updated_at: sa.updated_at,
    }))
}

/// `GET /api/v1/service-accounts`
#[utoipa::path(
    get,
    path = "/api/v1/service-accounts",
    tag = "service-accounts",
    params(Pagination),
    responses(
        (status = 200, description = "List of service accounts", body = inline(PaginatedResult<ServiceAccountResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("service_accounts:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    let items: Vec<ServiceAccountResponse> = result
        .items
        .into_iter()
        .map(ServiceAccountResponse::from)
        .collect();
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items,
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    }))
}

/// `GET /api/v1/service-accounts/{sa_id}`
#[utoipa::path(
    get,
    path = "/api/v1/service-accounts/{sa_id}",
    tag = "service-accounts",
    params(("sa_id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Service account found", body = ServiceAccountResponse),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("service_accounts:get", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let sa = repo.get_by_id(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ServiceAccountResponse::from(sa)))
}

/// `PUT /api/v1/service-accounts/{sa_id}`
#[utoipa::path(
    put,
    path = "/api/v1/service-accounts/{sa_id}",
    tag = "service-accounts",
    params(("sa_id" = Uuid, Path, description = "Service account ID")),
    request_body = UpdateServiceAccount,
    responses(
        (status = 200, description = "Service account updated", body = ServiceAccountResponse),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateServiceAccount>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("service_accounts:update", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let sa = repo
        .update(user.tenant_id, path.into_inner(), body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(ServiceAccountResponse::from(sa)))
}

/// `DELETE /api/v1/service-accounts/{sa_id}`
#[utoipa::path(
    delete,
    path = "/api/v1/service-accounts/{sa_id}",
    tag = "service-accounts",
    params(("sa_id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 204, description = "Service account deleted"),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("service_accounts:delete", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/service-accounts/{sa_id}/rotate-secret`
#[utoipa::path(
    post,
    path = "/api/v1/service-accounts/{sa_id}/rotate-secret",
    tag = "service-accounts",
    params(("sa_id" = Uuid, Path, description = "Service account ID")),
    responses(
        (status = 200, description = "Secret rotated", body = RotateSecretResponse),
        (status = 404, description = "Service account not found"),
    ),
    security(("bearer" = []))
)]
pub async fn rotate_secret<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("service_accounts:rotate_secret", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let raw_secret = repo
        .rotate_secret(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(RotateSecretResponse {
        client_secret: raw_secret,
    }))
}

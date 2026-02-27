//! Service account management endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::service_account::{
    CreateServiceAccount, ServiceAccount, UpdateServiceAccount,
};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{Pagination, ServiceAccountRepository};
use axiam_db::SurrealServiceAccountRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// -----------------------------------------------------------------------
// Request types
// -----------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateServiceAccountRequest {
    pub name: String,
}

// -----------------------------------------------------------------------
// Response DTOs (strip client_secret_hash)
// -----------------------------------------------------------------------

/// Public-safe service account representation.
#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
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
#[derive(Debug, Serialize)]
pub struct RotateSecretResponse {
    pub client_secret: String,
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/service-accounts`
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    body: web::Json<CreateServiceAccountRequest>,
) -> Result<HttpResponse, AxiamApiError> {
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
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, query.into_inner()).await?;
    let items: Vec<ServiceAccountResponse> = result
        .items
        .into_iter()
        .map(ServiceAccountResponse::from)
        .collect();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "items": items,
        "total": result.total,
        "offset": result.offset,
        "limit": result.limit,
    })))
}

/// `GET /api/v1/service-accounts/{sa_id}`
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let sa = repo.get_by_id(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ServiceAccountResponse::from(sa)))
}

/// `PUT /api/v1/service-accounts/{sa_id}`
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
    body: web::Json<UpdateServiceAccount>,
) -> Result<HttpResponse, AxiamApiError> {
    let sa = repo
        .update(user.tenant_id, path.into_inner(), body.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(ServiceAccountResponse::from(sa)))
}

/// `DELETE /api/v1/service-accounts/{sa_id}`
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    repo.delete(user.tenant_id, path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

/// `POST /api/v1/service-accounts/{sa_id}/rotate-secret`
pub async fn rotate_secret<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealServiceAccountRepository<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let raw_secret = repo
        .rotate_secret(user.tenant_id, path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(RotateSecretResponse {
        client_secret: raw_secret,
    }))
}

//! Webhook management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::webhook::{CreateWebhook, RetryPolicy, UpdateWebhook, Webhook};
use axiam_core::repository::{PaginatedResult, Pagination, WebhookRepository};
use axiam_db::SurrealWebhookRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::error::AxiamApiError;

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateWebhookRequest {
    /// The HTTPS URL to deliver events to.
    pub url: String,
    /// Event types to subscribe to (e.g. `["user.created", "auth.login"]`).
    pub events: Vec<String>,
    /// HMAC-SHA256 shared secret for signing payloads.
    pub secret: String,
    /// Optional retry policy override.
    pub retry_policy: Option<RetryPolicy>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateWebhookRequest {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub retry_policy: Option<RetryPolicy>,
}

/// Webhook response — omits the shared secret.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WebhookResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub url: String,
    pub events: Vec<String>,
    pub enabled: bool,
    pub retry_policy: RetryPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Webhook> for WebhookResponse {
    fn from(w: Webhook) -> Self {
        Self {
            id: w.id,
            tenant_id: w.tenant_id,
            url: w.url,
            events: w.events,
            enabled: w.enabled,
            retry_policy: w.retry_policy,
            created_at: w.created_at,
            updated_at: w.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/webhooks`
#[utoipa::path(
    post,
    path = "/api/v1/webhooks",
    tag = "webhooks",
    request_body = CreateWebhookRequest,
    responses(
        (status = 201, description = "Webhook created",
         body = WebhookResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealWebhookRepository<C>>,
    body: web::Json<CreateWebhookRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    if req.url.is_empty() {
        return Err(axiam_core::error::AxiamError::Validation {
            message: "url must not be empty".into(),
        }
        .into());
    }
    if req.events.is_empty() {
        return Err(axiam_core::error::AxiamError::Validation {
            message: "events must not be empty".into(),
        }
        .into());
    }
    if req.secret.is_empty() {
        return Err(axiam_core::error::AxiamError::Validation {
            message: "secret must not be empty".into(),
        }
        .into());
    }

    let webhook = repo
        .create(CreateWebhook {
            tenant_id: user.tenant_id,
            url: req.url,
            events: req.events,
            secret: req.secret,
            retry_policy: req.retry_policy,
        })
        .await?;
    Ok(HttpResponse::Created().json(WebhookResponse::from(webhook)))
}

/// `GET /api/v1/webhooks`
#[utoipa::path(
    get,
    path = "/api/v1/webhooks",
    tag = "webhooks",
    params(Pagination),
    responses(
        (status = 200, description = "List of webhooks",
         body = inline(PaginatedResult<WebhookResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealWebhookRepository<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, pagination.into_inner()).await?;
    let response = PaginatedResult {
        items: result
            .items
            .into_iter()
            .map(WebhookResponse::from)
            .collect(),
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    };
    Ok(HttpResponse::Ok().json(response))
}

/// `GET /api/v1/webhooks/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/webhooks/{id}",
    tag = "webhooks",
    params(("id" = Uuid, Path, description = "Webhook ID")),
    responses(
        (status = 200, description = "Webhook found",
         body = WebhookResponse),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    repo: web::Data<SurrealWebhookRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let webhook = repo.get_by_id(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(WebhookResponse::from(webhook)))
}

/// `PUT /api/v1/webhooks/{id}`
#[utoipa::path(
    put,
    path = "/api/v1/webhooks/{id}",
    tag = "webhooks",
    params(("id" = Uuid, Path, description = "Webhook ID")),
    request_body = UpdateWebhookRequest,
    responses(
        (status = 200, description = "Webhook updated",
         body = WebhookResponse),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    repo: web::Data<SurrealWebhookRepository<C>>,
    body: web::Json<UpdateWebhookRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let req = body.into_inner();
    let webhook = repo
        .update(
            user.tenant_id,
            id,
            UpdateWebhook {
                url: req.url,
                events: req.events,
                enabled: req.enabled,
                retry_policy: req.retry_policy,
            },
        )
        .await?;
    Ok(HttpResponse::Ok().json(WebhookResponse::from(webhook)))
}

/// `DELETE /api/v1/webhooks/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/webhooks/{id}",
    tag = "webhooks",
    params(("id" = Uuid, Path, description = "Webhook ID")),
    responses(
        (status = 204, description = "Webhook deleted"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    repo: web::Data<SurrealWebhookRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    repo.delete(user.tenant_id, id).await?;
    Ok(HttpResponse::NoContent().finish())
}

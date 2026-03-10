//! Webhook management endpoints.

use std::net::IpAddr;

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

    validate_webhook_url(&req.url)?;
    validate_webhook_events(&req.events)?;
    if req.secret.is_empty() {
        return Err(validation_err("secret must not be empty"));
    }
    if let Some(ref rp) = req.retry_policy {
        validate_retry_policy(rp)?;
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
    if let Some(ref url) = req.url {
        validate_webhook_url(url)?;
    }
    if let Some(ref events) = req.events {
        validate_webhook_events(events)?;
    }
    if let Some(ref rp) = req.retry_policy {
        validate_retry_policy(rp)?;
    }
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

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

/// Validate a webhook URL: must be a valid HTTPS URL pointing to a public host.
fn validate_webhook_url(url: &str) -> Result<(), AxiamApiError> {
    let parsed: url::Url = url
        .parse()
        .map_err(|_| validation_err("url is not a valid URL"))?;

    if parsed.scheme() != "https" {
        return Err(validation_err("url must use the https scheme"));
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| validation_err("url must contain a host"))?;

    // Block private/internal IP ranges (SSRF protection).
    if let Ok(ip) = host.parse::<IpAddr>()
        && !is_global_ip(ip)
    {
        return Err(validation_err(
            "url must not point to a private or loopback address",
        ));
    }

    // Block common internal hostnames.
    let lower = host.to_lowercase();
    if lower == "localhost" || lower.ends_with(".local") || lower.ends_with(".internal") {
        return Err(validation_err(
            "url must not point to a local or internal host",
        ));
    }

    Ok(())
}

/// Validate that the events list is non-empty.
fn validate_webhook_events(events: &[String]) -> Result<(), AxiamApiError> {
    if events.is_empty() {
        return Err(validation_err("events must not be empty"));
    }
    Ok(())
}

/// Validate retry policy bounds to prevent panics and abuse.
fn validate_retry_policy(rp: &RetryPolicy) -> Result<(), AxiamApiError> {
    if rp.max_retries > 10 {
        return Err(validation_err("max_retries must be at most 10"));
    }
    if rp.initial_delay_secs < 1 || rp.initial_delay_secs > 3600 {
        return Err(validation_err(
            "initial_delay_secs must be between 1 and 3600",
        ));
    }
    if !(0.0..=10.0).contains(&rp.backoff_multiplier) {
        return Err(validation_err(
            "backoff_multiplier must be between 0.0 and 10.0",
        ));
    }
    Ok(())
}

/// Returns `true` if the IP address is globally routable (not private,
/// loopback, link-local, or other reserved range).
fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                // 100.64.0.0/10 (Carrier-grade NAT)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64))
        }
        IpAddr::V6(v6) => {
            // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_global_ip(IpAddr::V4(mapped));
            }
            !v6.is_loopback()
                && !v6.is_unspecified()
                // Unique local (fc00::/7)
                && (v6.segments()[0] & 0xFE00) != 0xFC00
                // Link-local (fe80::/10)
                && (v6.segments()[0] & 0xFFC0) != 0xFE80
        }
    }
}

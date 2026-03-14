//! OAuth2 client management endpoints (tenant-scoped via JWT).

use actix_web::{HttpResponse, web};
use axiam_core::models::oauth2_client::{CreateOAuth2Client, OAuth2Client, UpdateOAuth2Client};
use axiam_core::repository::{OAuth2ClientRepository, PaginatedResult, Pagination};
use axiam_db::SurrealOAuth2ClientRepository;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// ---------------------------------------------------------------------------
// Request / response DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateOAuth2ClientRequest {
    /// Human-readable name for the client.
    pub name: String,
    /// Allowed redirect URIs (must be HTTPS, except localhost for dev).
    pub redirect_uris: Vec<String>,
    /// Grant types this client is authorized to use.
    pub grant_types: Vec<String>,
    /// Scopes the client may request.
    pub scopes: Vec<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateOAuth2ClientRequest {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
}

/// OAuth2 client response -- omits client_secret_hash.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OAuth2ClientResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<OAuth2Client> for OAuth2ClientResponse {
    fn from(c: OAuth2Client) -> Self {
        Self {
            id: c.id,
            tenant_id: c.tenant_id,
            client_id: c.client_id,
            name: c.name,
            redirect_uris: c.redirect_uris,
            grant_types: c.grant_types,
            scopes: c.scopes,
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
    }
}

/// Response for client creation -- includes the one-time plaintext secret.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OAuth2ClientCreatedResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const KNOWN_GRANT_TYPES: &[&str] = &["authorization_code", "client_credentials", "refresh_token"];

fn validation_err(msg: impl Into<String>) -> AxiamApiError {
    axiam_core::error::AxiamError::Validation {
        message: msg.into(),
    }
    .into()
}

fn validate_redirect_uris(uris: &[String]) -> Result<(), AxiamApiError> {
    if uris.is_empty() {
        return Err(validation_err("redirect_uris must not be empty"));
    }
    for uri in uris {
        let parsed: url::Url = uri
            .parse()
            .map_err(|_| validation_err(format!("invalid redirect_uri: {uri}")))?;
        // Allow http for localhost/loopback only, require HTTPS otherwise
        let is_localhost = parsed
            .host_str()
            .map(|h| h == "localhost" || h == "127.0.0.1" || h == "::1")
            .unwrap_or(false);
        if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_localhost) {
            return Err(validation_err(format!(
                "redirect_uri must use https (http is only allowed for localhost/127.0.0.1/::1): {uri}"
            )));
        }
        // RFC 6749 §3.1.2: redirect URIs must not include a fragment
        if parsed.fragment().is_some() {
            return Err(validation_err(format!(
                "redirect_uri must not contain a fragment: {uri}"
            )));
        }
    }
    Ok(())
}

fn validate_grant_types(grant_types: &[String]) -> Result<(), AxiamApiError> {
    if grant_types.is_empty() {
        return Err(validation_err("grant_types must not be empty"));
    }
    for gt in grant_types {
        if !KNOWN_GRANT_TYPES.contains(&gt.as_str()) {
            return Err(validation_err(format!(
                "unknown grant_type: {gt} (allowed: {})",
                KNOWN_GRANT_TYPES.join(", ")
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/oauth2-clients`
#[utoipa::path(
    post,
    path = "/api/v1/oauth2-clients",
    tag = "oauth2-clients",
    request_body = CreateOAuth2ClientRequest,
    responses(
        (status = 201, description = "OAuth2 client created (secret shown once)",
         body = OAuth2ClientCreatedResponse),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealOAuth2ClientRepository<C>>,
    body: web::Json<CreateOAuth2ClientRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    if req.name.is_empty() {
        return Err(validation_err("name must not be empty"));
    }
    validate_redirect_uris(&req.redirect_uris)?;
    validate_grant_types(&req.grant_types)?;

    let (client, raw_secret) = repo
        .create(CreateOAuth2Client {
            tenant_id: user.tenant_id,
            name: req.name,
            redirect_uris: req.redirect_uris,
            grant_types: req.grant_types,
            scopes: req.scopes,
        })
        .await?;

    Ok(HttpResponse::Created().json(OAuth2ClientCreatedResponse {
        id: client.id,
        tenant_id: client.tenant_id,
        client_id: client.client_id,
        client_secret: raw_secret,
        name: client.name,
        redirect_uris: client.redirect_uris,
        grant_types: client.grant_types,
        scopes: client.scopes,
        created_at: client.created_at,
        updated_at: client.updated_at,
    }))
}

/// `GET /api/v1/oauth2-clients`
#[utoipa::path(
    get,
    path = "/api/v1/oauth2-clients",
    tag = "oauth2-clients",
    params(Pagination),
    responses(
        (status = 200, description = "List of OAuth2 clients",
         body = inline(PaginatedResult<OAuth2ClientResponse>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    repo: web::Data<SurrealOAuth2ClientRepository<C>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = repo.list(user.tenant_id, pagination.into_inner()).await?;
    let response = PaginatedResult {
        items: result
            .items
            .into_iter()
            .map(OAuth2ClientResponse::from)
            .collect(),
        total: result.total,
        offset: result.offset,
        limit: result.limit,
    };
    Ok(HttpResponse::Ok().json(response))
}

/// `GET /api/v1/oauth2-clients/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/oauth2-clients/{id}",
    tag = "oauth2-clients",
    params(("id" = Uuid, Path, description = "OAuth2 client ID")),
    responses(
        (status = 200, description = "OAuth2 client found",
         body = OAuth2ClientResponse),
        (status = 404, description = "OAuth2 client not found"),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    repo: web::Data<SurrealOAuth2ClientRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let client = repo.get_by_id(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(OAuth2ClientResponse::from(client)))
}

/// `PUT /api/v1/oauth2-clients/{id}`
#[utoipa::path(
    put,
    path = "/api/v1/oauth2-clients/{id}",
    tag = "oauth2-clients",
    params(("id" = Uuid, Path, description = "OAuth2 client ID")),
    request_body = UpdateOAuth2ClientRequest,
    responses(
        (status = 200, description = "OAuth2 client updated",
         body = OAuth2ClientResponse),
        (status = 404, description = "OAuth2 client not found"),
    ),
    security(("bearer" = []))
)]
pub async fn update<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    repo: web::Data<SurrealOAuth2ClientRepository<C>>,
    body: web::Json<UpdateOAuth2ClientRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let req = body.into_inner();

    if let Some(ref name) = req.name
        && name.is_empty()
    {
        return Err(validation_err("name must not be empty"));
    }
    if let Some(ref uris) = req.redirect_uris {
        validate_redirect_uris(uris)?;
    }
    if let Some(ref gts) = req.grant_types {
        validate_grant_types(gts)?;
    }

    let client = repo
        .update(
            user.tenant_id,
            id,
            UpdateOAuth2Client {
                name: req.name,
                redirect_uris: req.redirect_uris,
                grant_types: req.grant_types,
                scopes: req.scopes,
            },
        )
        .await?;
    Ok(HttpResponse::Ok().json(OAuth2ClientResponse::from(client)))
}

/// `DELETE /api/v1/oauth2-clients/{id}`
#[utoipa::path(
    delete,
    path = "/api/v1/oauth2-clients/{id}",
    tag = "oauth2-clients",
    params(("id" = Uuid, Path, description = "OAuth2 client ID")),
    responses(
        (status = 204, description = "OAuth2 client deleted"),
        (status = 404, description = "OAuth2 client not found"),
    ),
    security(("bearer" = []))
)]
pub async fn delete<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    repo: web::Data<SurrealOAuth2ClientRepository<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    repo.delete(user.tenant_id, id).await?;
    Ok(HttpResponse::NoContent().finish())
}

//! Admin endpoints for SCIM provisioning tokens.
//!
//! See `claude_dev/scim-provisioning-token-design.md`. These mint, list and
//! revoke the long-lived credential an IdP pastes into its SCIM connector;
//! the credential itself is consumed in `axiam_scim`, never here.
//!
//! Gated on `scim_tokens:*`, deliberately separate from `scim:provision`:
//! minting a credential for a provisioner is an administrative act, and the
//! provisioner should not be able to mint more of itself.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::scim_token::{
    CreateScimToken, DEFAULT_MAX_LIFETIME_DAYS, SCIM_TOKEN_PREFIX, ScimToken, ScimTokenStatus,
};
use axiam_core::repository::{ScimTokenRepository, UserRepository};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateScimTokenRequest {
    /// Operator-facing label, e.g. `"okta-production"`.
    pub name: String,
    /// The tenant user the token authenticates as. Must already hold
    /// `scim:provision` — see [`create`].
    pub user_id: Uuid,
    /// Lifetime in days. Defaults to the deployment maximum, and is refused
    /// above it.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

/// Metadata only. The handle is never in a list response — it exists in
/// plaintext exactly once, in [`CreateScimTokenResponse`].
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ScimTokenResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub created_by: Uuid,
    pub status: ScimTokenStatus,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ScimTokenResponse {
    fn from_token(t: ScimToken, now: DateTime<Utc>) -> Self {
        Self {
            status: t.status(now),
            id: t.id,
            tenant_id: t.tenant_id,
            user_id: t.user_id,
            name: t.name,
            created_by: t.created_by,
            expires_at: t.expires_at,
            last_used_at: t.last_used_at,
            revoked_at: t.revoked_at,
            created_at: t.created_at,
        }
    }
}

/// The one-time reveal. Same shape as service-account creation: the secret is
/// returned once and only its hash is kept.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateScimTokenResponse {
    #[serde(flatten)]
    pub token: ScimTokenResponse,
    /// The plaintext handle — shown once, never retrievable again.
    pub provisioning_token: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Deployment ceiling on a token's lifetime.
///
/// Read from `AXIAM__SCIM_TOKEN_MAX_LIFETIME_DAYS`, falling back to
/// [`DEFAULT_MAX_LIFETIME_DAYS`]. An unparseable or non-positive value falls
/// back rather than failing the request: a malformed env var should not take
/// provisioning offline, and the fallback is the conservative direction.
fn max_lifetime_days() -> i64 {
    std::env::var("AXIAM__SCIM_TOKEN_MAX_LIFETIME_DAYS")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|d| *d > 0)
        .unwrap_or(DEFAULT_MAX_LIFETIME_DAYS)
}

/// `POST /api/v1/scim-tokens`
#[utoipa::path(
    post,
    path = "/api/v1/scim-tokens",
    tag = "scim-tokens",
    request_body = CreateScimTokenRequest,
    responses(
        (status = 201, description = "Token minted; the handle is returned once",
         body = CreateScimTokenResponse),
        (status = 400, description = "Invalid lifetime, or the named user cannot use SCIM"),
    ),
    security(("bearer" = []))
)]
pub async fn create<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<CreateScimTokenRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_tokens:create", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    let input = body.into_inner();
    let name = input.name.trim().to_string();
    if name.is_empty() {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "name must not be empty".into(),
        }));
    }

    let max_days = max_lifetime_days();
    let days = input.expires_in_days.unwrap_or(max_days);
    if days <= 0 || days > max_days {
        return Err(AxiamApiError(AxiamError::Validation {
            message: format!("expires_in_days must be between 1 and {max_days}"),
        }));
    }

    // The bound user must exist in this tenant. Checked before the RBAC check
    // below so a typo'd UUID answers "no such user" rather than the more
    // confusing "that user cannot use SCIM".
    state
        .user_repo
        .get_by_id(user.tenant_id, input.user_id)
        .await?;

    // ...and must actually hold `scim:provision`. A token that authenticates
    // as somebody who cannot use SCIM only ever produces 403s; minting one
    // silently is a trap that costs an operator an afternoon.
    RequirePermission::new(
        axiam_core::models::scim_token::SCIM_PROVISION_ACTION,
        Uuid::nil(),
    )
    .check_subject(user.tenant_id, input.user_id, authz.get_ref().as_ref())
    .await
    .map_err(|_| {
        AxiamApiError(AxiamError::Validation {
            message: "the named user does not hold scim:provision, so a token bound to \
                          them could not provision anything. Grant the permission first."
                .into(),
        })
    })?;

    let raw = format!(
        "{SCIM_TOKEN_PREFIX}{}",
        axiam_auth::token::generate_refresh_token()
    );
    let token_hash = axiam_auth::token::hash_refresh_token(&raw);

    let created = state
        .scim_token_repo
        .create(CreateScimToken {
            tenant_id: user.tenant_id,
            user_id: input.user_id,
            name,
            token_hash,
            created_by: user.user_id,
            expires_at: Utc::now() + Duration::days(days),
        })
        .await?;

    tracing::info!(
        target: "axiam::audit",
        event = "scim.token_created",
        tenant_id = %user.tenant_id,
        token_id = %created.id,
        bound_user_id = %created.user_id,
        created_by = %user.user_id,
        expires_at = %created.expires_at,
        "SCIM provisioning token minted"
    );

    Ok(HttpResponse::Created().json(CreateScimTokenResponse {
        token: ScimTokenResponse::from_token(created, Utc::now()),
        provisioning_token: raw,
    }))
}

/// `GET /api/v1/scim-tokens`
#[utoipa::path(
    get,
    path = "/api/v1/scim-tokens",
    tag = "scim-tokens",
    responses((status = 200, description = "Tokens for this tenant (metadata only)",
               body = Vec<ScimTokenResponse>)),
    security(("bearer" = []))
)]
pub async fn list<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_tokens:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    let now = Utc::now();
    let tokens: Vec<ScimTokenResponse> = state
        .scim_token_repo
        .list_for_tenant(user.tenant_id)
        .await?
        .into_iter()
        .map(|t| ScimTokenResponse::from_token(t, now))
        .collect();

    Ok(HttpResponse::Ok().json(tokens))
}

/// `DELETE /api/v1/scim-tokens/{id}`
///
/// Revokes rather than deletes: the row is what lets an operator later answer
/// "was this credential still live on the day of the incident?", and a
/// deleted row answers nothing.
#[utoipa::path(
    delete,
    path = "/api/v1/scim-tokens/{id}",
    tag = "scim-tokens",
    params(("id" = Uuid, Path, description = "Token ID")),
    responses((status = 204, description = "Token revoked")),
    security(("bearer" = []))
)]
pub async fn revoke<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("scim_tokens:revoke", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    let id = path.into_inner();
    // Read first so an unknown id answers 404 rather than a silent 204.
    state.scim_token_repo.get_by_id(user.tenant_id, id).await?;
    state.scim_token_repo.revoke(user.tenant_id, id).await?;

    tracing::info!(
        target: "axiam::audit",
        event = "scim.token_revoked",
        tenant_id = %user.tenant_id,
        token_id = %id,
        revoked_by = %user.user_id,
        "SCIM provisioning token revoked"
    );

    Ok(HttpResponse::NoContent().finish())
}

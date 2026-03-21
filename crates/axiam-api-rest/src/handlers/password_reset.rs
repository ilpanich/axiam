//! Password reset endpoints (unauthenticated).
//!
//! These endpoints allow users to request a password reset via email
//! and confirm the reset with a new password.

use actix_web::{HttpResponse, web};
use axiam_auth::PasswordResetService;
use axiam_core::error::AxiamError;
use axiam_db::{
    SurrealFederationLinkRepository, SurrealPasswordHistoryRepository,
    SurrealPasswordResetTokenRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Body for the request-reset endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RequestResetBody {
    pub tenant_id: Uuid,
    pub email: String,
}

/// Body for the confirm-reset endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ConfirmResetBody {
    pub tenant_id: Uuid,
    pub token: String,
    pub new_password: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /auth/reset`
///
/// Initiates a password reset. Always returns `{"sent": true}` to
/// prevent email enumeration — regardless of whether the email
/// exists, the user is federated, or the rate limit is exceeded.
#[utoipa::path(
    post,
    path = "/auth/reset",
    tag = "auth",
    request_body = RequestResetBody,
    responses(
        (status = 200, description = "Reset email sent (or silently ignored)"),
    )
)]
pub async fn request_reset<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    token_repo: web::Data<SurrealPasswordResetTokenRepository<C>>,
    federation_repo: web::Data<SurrealFederationLinkRepository<C>>,
    history_repo: web::Data<SurrealPasswordHistoryRepository<C>>,
    auth_config: web::Data<axiam_auth::AuthConfig>,
    body: web::Json<RequestResetBody>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let svc = PasswordResetService::new(
        user_repo.as_ref().clone(),
        token_repo.as_ref().clone(),
        federation_repo.as_ref().clone(),
        history_repo.as_ref().clone(),
    );

    let expiry_hours = auth_config.password_reset_token_expiry_hours;

    match svc
        .initiate_reset(req.tenant_id, &req.email, expiry_hours)
        .await
    {
        Ok(Some((_raw_token, _user_id, _expires_at))) => {
            // TODO(T19): wire up actual email sending via EmailService
            // with the password-reset template.
            tracing::debug!(email = %req.email, "password reset token created");
        }
        Ok(None) => {
            // User not found or federated — silently ignore.
            tracing::debug!(
                email = %req.email,
                "password-reset: no action (unknown or federated)"
            );
        }
        Err(AxiamError::RateLimited) => {
            // Swallow rate-limit to prevent user enumeration via
            // differential 429 responses.
            tracing::debug!(
                email = %req.email,
                "password-reset: rate-limited (suppressed)"
            );
        }
        Err(e) => return Err(e.into()),
    }

    // Always return identical 200 regardless of outcome.
    Ok(HttpResponse::Ok().json(serde_json::json!({ "sent": true })))
}

/// `POST /auth/reset/confirm`
///
/// Confirms a password reset using a one-time token and a new
/// password. The token is consumed atomically.
///
/// Returns `{"reset": true}` on success, or 400 with policy
/// violations if the new password is too weak.
#[utoipa::path(
    post,
    path = "/auth/reset/confirm",
    tag = "auth",
    request_body = ConfirmResetBody,
    responses(
        (status = 200, description = "Password reset successfully"),
        (status = 400, description = "Invalid token or password policy violation"),
    )
)]
pub async fn confirm_reset<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    token_repo: web::Data<SurrealPasswordResetTokenRepository<C>>,
    federation_repo: web::Data<SurrealFederationLinkRepository<C>>,
    history_repo: web::Data<SurrealPasswordHistoryRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    settings_repo: web::Data<SurrealSettingsRepository<C>>,
    auth_config: web::Data<axiam_auth::AuthConfig>,
    http_client: web::Data<reqwest::Client>,
    body: web::Json<ConfirmResetBody>,
) -> Result<HttpResponse, AxiamApiError> {
    use axiam_core::repository::{SettingsRepository, TenantRepository};

    let req = body.into_inner();

    // Resolve the tenant to get its org_id for settings.
    let tenant = tenant_repo.get_by_id(req.tenant_id).await?;

    // Resolve effective password policy.
    let settings = settings_repo
        .get_effective_settings(tenant.organization_id, req.tenant_id)
        .await?;

    let svc = PasswordResetService::new(
        user_repo.as_ref().clone(),
        token_repo.as_ref().clone(),
        federation_repo.as_ref().clone(),
        history_repo.as_ref().clone(),
    );

    svc.confirm_reset(
        req.tenant_id,
        &req.token,
        &req.new_password,
        &settings.password,
        auth_config.pepper.as_deref(),
        Some(http_client.as_ref()),
    )
    .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "reset": true })))
}

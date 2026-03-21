//! Email verification endpoints (unauthenticated).
//!
//! These endpoints allow users to verify their email address using a
//! one-time token sent during registration, and to request a new
//! verification email if the original expired or was lost.

use actix_web::{HttpResponse, web};
use axiam_auth::EmailVerificationService;
use axiam_core::error::AxiamError;
use axiam_db::{
    SurrealEmailVerificationTokenRepository, SurrealFederationLinkRepository, SurrealUserRepository,
};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Body for the verify-email endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct VerifyEmailRequest {
    pub tenant_id: Uuid,
    pub token: String,
}

/// Body for the resend-verification endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ResendVerificationRequest {
    pub tenant_id: Uuid,
    pub email: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /auth/verify-email`
///
/// Verifies a user's email using a one-time token. The token is
/// consumed atomically — replaying the same token returns an error.
#[utoipa::path(
    post,
    path = "/auth/verify-email",
    tag = "auth",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified successfully"),
        (status = 400, description = "Invalid or expired token"),
    )
)]
pub async fn verify_email<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    token_repo: web::Data<SurrealEmailVerificationTokenRepository<C>>,
    federation_repo: web::Data<SurrealFederationLinkRepository<C>>,
    body: web::Json<VerifyEmailRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let svc = EmailVerificationService::new(
        user_repo.as_ref().clone(),
        token_repo.as_ref().clone(),
        federation_repo.as_ref().clone(),
    );

    svc.verify_email(req.tenant_id, &req.token).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "verified": true })))
}

/// `POST /auth/resend-verification`
///
/// Creates a new email verification token for the given user. Always
/// returns 200 to prevent email enumeration — regardless of whether
/// the email exists, is already verified, or has hit a rate limit.
///
/// **Note:** Token creation and storage is implemented. Actual email
/// delivery will be wired in a future phase (T19) via `EmailService`.
#[utoipa::path(
    post,
    path = "/auth/resend-verification",
    tag = "auth",
    request_body = ResendVerificationRequest,
    responses(
        (status = 200, description = "Verification token created (email delivery pending T19)"),
    )
)]
pub async fn resend_verification<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    token_repo: web::Data<SurrealEmailVerificationTokenRepository<C>>,
    federation_repo: web::Data<SurrealFederationLinkRepository<C>>,
    body: web::Json<ResendVerificationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let svc = EmailVerificationService::new(
        user_repo.as_ref().clone(),
        token_repo.as_ref().clone(),
        federation_repo.as_ref().clone(),
    );

    match svc.resend_verification(req.tenant_id, &req.email).await {
        Ok(Some((_raw_token, _user_id, _expires_at))) => {
            // TODO(T19): wire up actual email sending via EmailService
            // with the activation template. The token is generated and
            // stored; email delivery will be integrated when the server
            // composition layer wires EmailService.
            tracing::debug!(email = %req.email, "verification email resent");
        }
        Ok(None) => {
            // User not found or already verified — silently ignore.
            tracing::debug!(
                email = %req.email,
                "resend-verification: no action (unknown or verified)"
            );
        }
        Err(AxiamError::RateLimited) => {
            // Swallow rate-limit to prevent user enumeration via
            // differential 429 responses.
            tracing::debug!(
                email = %req.email,
                "resend-verification: rate-limited (suppressed)"
            );
        }
        Err(e) => return Err(e.into()),
    }

    // Always return identical 200 regardless of outcome.
    Ok(HttpResponse::Ok().json(serde_json::json!({ "sent": true })))
}

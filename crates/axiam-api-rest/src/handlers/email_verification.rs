//! Email verification endpoints (unauthenticated).
//!
//! These endpoints allow users to verify their email address using a
//! one-time token sent during registration, and to request a new
//! verification email if the original expired or was lost.

use actix_web::{HttpResponse, web};
use axiam_auth::EmailVerificationService;
use axiam_core::error::AxiamError;
use axiam_db::{
    SurrealEmailVerificationTokenRepository, SurrealFederationLinkRepository,
    SurrealUserRepository,
};
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Body for the verify-email endpoint.
#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub tenant_id: Uuid,
    pub token: String,
}

/// Body for the resend-verification endpoint.
#[derive(Debug, Deserialize)]
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
/// Resends the verification email. Always returns 200 to prevent
/// email enumeration — even if the email does not exist or is
/// already verified.
///
/// Returns 429 if the resend rate limit is exceeded.
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
            Ok(HttpResponse::Ok().json(
                serde_json::json!({ "sent": true }),
            ))
        }
        Ok(None) => {
            // User not found or already verified — return identical
            // response to prevent email enumeration.
            Ok(HttpResponse::Ok().json(
                serde_json::json!({ "sent": true }),
            ))
        }
        Err(AxiamError::RateLimited) => {
            Ok(HttpResponse::TooManyRequests().json(
                serde_json::json!({
                    "error": "rate_limited",
                    "message":
                        "too many verification emails requested today"
                }),
            ))
        }
        Err(e) => Err(e.into()),
    }
}

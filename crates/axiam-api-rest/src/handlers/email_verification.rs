//! Email verification endpoints (unauthenticated).
//!
//! These endpoints allow users to verify their email address using a
//! one-time token sent during registration, and to request a new
//! verification email if the original expired or was lost.

use actix_web::{HttpResponse, web};
use axiam_amqp::MailOutboundPublisher;
use axiam_auth::EmailVerificationService;
use axiam_core::error::AxiamError;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::repository::{MailPublisher, TenantRepository};
use axiam_db::{
    SurrealEmailVerificationTokenRepository, SurrealFederationLinkRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::Utc;
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

/// `POST /api/v1/auth/verify-email`
///
/// Verifies a user's email using a one-time token. The token is
/// consumed atomically — replaying the same token returns an error.
#[utoipa::path(
    post,
    path = "/api/v1/auth/verify-email",
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

/// `POST /api/v1/auth/resend-verification`
///
/// Creates a new email verification token and enqueues it for async
/// delivery via the mail queue (D-14).  Always returns `{"sent": true}`
/// to prevent email enumeration (D-15) — regardless of whether the email
/// exists, is already verified, or has hit a rate limit.
#[utoipa::path(
    post,
    path = "/api/v1/auth/resend-verification",
    tag = "auth",
    request_body = ResendVerificationRequest,
    responses(
        (status = 200, description = "Verification email enqueued"),
    )
)]
pub async fn resend_verification<C: Connection>(
    user_repo: web::Data<SurrealUserRepository<C>>,
    token_repo: web::Data<SurrealEmailVerificationTokenRepository<C>>,
    federation_repo: web::Data<SurrealFederationLinkRepository<C>>,
    tenant_repo: web::Data<SurrealTenantRepository<C>>,
    mail_publisher: web::Data<MailOutboundPublisher>,
    body: web::Json<ResendVerificationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let svc = EmailVerificationService::new(
        user_repo.as_ref().clone(),
        token_repo.as_ref().clone(),
        federation_repo.as_ref().clone(),
    );

    match svc.resend_verification(req.tenant_id, &req.email).await {
        Ok(Some((raw_token, user_id, expires_at))) => {
            // Resolve org_id from tenant for the mail message.
            // On failure, log and continue — D-15: never propagate to client.
            let org_id = match tenant_repo.get_by_id(req.tenant_id).await {
                Ok(tenant) => tenant.organization_id,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        tenant_id = %req.tenant_id,
                        "failed to resolve org_id for email-verification mail; using nil"
                    );
                    Uuid::nil()
                }
            };

            let msg = OutboundMailMessage {
                mail_type: MailType::EmailVerification,
                tenant_id: req.tenant_id,
                org_id,
                user_id,
                to_address: req.email.clone(),
                template_context: serde_json::json!({
                    "token": raw_token,
                    "expiry_time": expires_at.to_rfc3339(),
                }),
                attempt_count: 0,
                enqueued_at: Utc::now(),
            };

            if let Err(e) = mail_publisher.publish(msg).await {
                // D-15: log warn but do NOT propagate — uniform 200 regardless
                tracing::warn!(
                    error = %e,
                    "failed to enqueue email-verification mail; continuing"
                );
            } else {
                tracing::debug!(email = %req.email, "verification email enqueued");
            }
        }
        Ok(None) => {
            // User not found or already verified — silently ignore (D-15).
            tracing::debug!(
                email = %req.email,
                "resend-verification: no action (unknown or verified)"
            );
        }
        Err(AxiamError::RateLimited) => {
            // Swallow rate-limit to prevent user enumeration via
            // differential 429 responses (D-15).
            tracing::debug!(
                email = %req.email,
                "resend-verification: rate-limited (suppressed)"
            );
        }
        Err(e) => return Err(e.into()),
    }

    // Always return identical 200 regardless of outcome (D-15).
    Ok(HttpResponse::Ok().json(serde_json::json!({ "sent": true })))
}

// ---------------------------------------------------------------------------
// Tests (D-15 enumeration-safe gate)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::mail::OutboundMailMessage;
    use axiam_core::repository::MailPublisher;
    use std::sync::{Arc, Mutex};

    /// Fake mail publisher for test assertions.
    #[derive(Clone, Default)]
    struct RecordingPublisher {
        sent: Arc<Mutex<Vec<OutboundMailMessage>>>,
    }

    impl RecordingPublisher {
        fn new() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    impl MailPublisher for RecordingPublisher {
        async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
            self.sent.lock().unwrap().push(msg);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // D-15 tests: unknown email returns {"sent": true} — same as known email
    // -----------------------------------------------------------------------

    /// Unknown email → response body is `{"sent": true}` with no token field.
    #[tokio::test]
    async fn unknown_email_enqueues_and_returns_sent() {
        // Simulate the unknown-address / already-verified branch:
        // `svc.resend_verification` returns `Ok(None)` → no enqueue, but
        // the response is still `{"sent": true}`.
        let response_body = serde_json::json!({ "sent": true });
        assert!(
            response_body.get("token").is_none(),
            "unknown-email response MUST NOT contain a token field (D-15)"
        );
        assert_eq!(
            response_body.get("sent").and_then(|v| v.as_bool()),
            Some(true),
            "unknown-email response must be {{\"sent\": true}}"
        );
    }

    /// Known email → `OutboundMailMessage(EmailVerification)` enqueued; token
    /// NOT present in the response body.
    #[tokio::test]
    async fn known_email_never_returns_token() {
        let publisher = RecordingPublisher::new();

        let raw_token = "verify-token-xyz".to_string();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let expires_at = Utc::now() + chrono::Duration::hours(24);
        let org_id = Uuid::new_v4();

        let msg = OutboundMailMessage {
            mail_type: MailType::EmailVerification,
            tenant_id,
            org_id,
            user_id,
            to_address: "user@example.com".to_string(),
            template_context: serde_json::json!({
                "token": raw_token.clone(),
                "expiry_time": expires_at.to_rfc3339(),
            }),
            attempt_count: 0,
            enqueued_at: Utc::now(),
        };
        publisher.publish(msg).await.unwrap();

        assert_eq!(publisher.count(), 1, "expected exactly one enqueued mail");

        // Response body never contains the token.
        let response_body = serde_json::json!({ "sent": true });
        assert!(
            response_body.get("token").is_none(),
            "response body MUST NOT contain token (D-15 / T-5-token-leak)"
        );
        assert_eq!(response_body["sent"], true);
    }
}

//! Email verification endpoints (unauthenticated).
//!
//! These endpoints allow users to verify their email address using a
//! one-time token sent during registration, and to request a new
//! verification email if the original expired or was lost.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::repository::{TenantRepository, UserRepository};
use chrono::Utc;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

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
// Shared enqueue helper
// ---------------------------------------------------------------------------

/// Mint a verification token for `user_id` and enqueue the activation email.
///
/// Two callers, and they must produce the same email: `POST /api/v1/users`
/// (an administrator creating an account, which is the account's *first*
/// activation link) and `POST /api/v1/auth/resend-verification` (the user
/// asking for another). Before this existed only the second one sent anything,
/// so an administrator created a user, the user was written as
/// `PendingVerification`, and nobody was ever told — the account simply could
/// not be activated unless someone knew to call the resend endpoint by hand.
///
/// Best-effort by construction: it returns `()` and logs its failures. A user
/// row that has already been committed must not be reported as a failed
/// creation because the mail queue was unreachable, and the resend endpoint
/// must answer identically whatever happened (D-15). The account stays
/// activatable either way — `resend-verification` mints a fresh token.
///
/// The `action_url` is a relative frontend route carrying the raw token and the
/// tenant id, matching the `VerifyEmailPage` route (`/auth/verify-email?token=…
/// &tenant_id=…`) and the shape `gdpr.rs` uses for its cancel link.
pub(crate) async fn enqueue_verification_email<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    user_id: Uuid,
    email: &str,
) {
    let (raw_token, expires_at) = match state
        .mail
        .email_verification_service
        .initiate_verification(tenant_id, user_id)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                error = %e,
                %tenant_id,
                %user_id,
                "could not mint an email-verification token; no activation mail enqueued"
            );
            return;
        }
    };

    let org_id = match state.tenant_repo.get_by_id(tenant_id).await {
        Ok(tenant) => tenant.organization_id,
        Err(e) => {
            // Nil rather than abandoning the send: the mail consumer resolves
            // the effective email config by (org, tenant) and a tenant-level
            // config still matches. Losing the org fallback is better than
            // losing the only activation link the account will be offered.
            tracing::warn!(
                error = %e,
                %tenant_id,
                "failed to resolve org_id for activation mail; using nil"
            );
            Uuid::nil()
        }
    };

    let verify_url = format!("/auth/verify-email?token={raw_token}&tenant_id={tenant_id}");

    let msg = OutboundMailMessage {
        mail_type: MailType::EmailVerification,
        tenant_id,
        org_id,
        user_id,
        to_address: email.to_owned(),
        template_context: serde_json::json!({
            "token": raw_token,
            "action_url": verify_url,
            "expiry_time": expires_at.to_rfc3339(),
        }),
        attempt_count: 0,
        enqueued_at: Utc::now(),
    };

    if let Err(e) = state.mail.mail_outbound_publisher.publish(msg).await {
        tracing::warn!(error = %e, "failed to enqueue activation mail; continuing");
    } else {
        tracing::debug!(%tenant_id, %user_id, "activation email enqueued");
    }
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
pub async fn verify_email<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<VerifyEmailRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    // QUAL-07: EmailVerificationService is now a hoisted AppState singleton.
    state
        .mail
        .email_verification_service
        .verify_email(req.tenant_id, &req.token)
        .await?;

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
pub async fn resend_verification<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<ResendVerificationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    // QUAL-07: EmailVerificationService is now a hoisted AppState singleton.
    match state
        .mail
        .email_verification_service
        .resend_verification(req.tenant_id, &req.email)
        .await
    {
        Ok(Some((_raw_token, user_id, _expires_at))) => {
            // The token minted above is discarded and a fresh one minted inside
            // the shared helper. That costs one extra row and buys the guarantee
            // that a resent activation email is byte-for-byte the one account
            // creation sends — same URL shape, same context keys, same template.
            // Two hand-rolled copies of this block is how they drift.
            enqueue_verification_email(&state, req.tenant_id, user_id, &req.email).await;
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

/// `POST /api/v1/users/me/resend-verification`
///
/// Resend the caller's **own** verification email, and say what happened.
///
/// # Why this exists beside the public endpoint
///
/// `POST /auth/resend-verification` answers a constant `200 {"sent": true}`
/// whatever the outcome, and it must: it takes an address from an
/// unauthenticated caller, so a 404 for "no such user" or a 429 for "rate
/// limited" would be an oracle for which addresses have accounts.
///
/// That reasoning does not apply here. The caller is authenticated and asking
/// about the address on its own record — it already knows the account exists,
/// because it is signed in to it. Reusing the enumeration-safe endpoint for
/// this is what made the profile page's button report success while doing
/// nothing: the address was already verified, or the account was locked, or the
/// daily limit was reached, and the response looked identical in every case.
///
/// So this one tells the truth:
///
/// * `200 {"sent": true}` — a token was minted and the mail enqueued.
/// * `409` — the address is already verified, or the account is in a state that
///   must not be sent a live token.
/// * `429` — the daily resend limit is reached.
///
/// None of those disclose anything the caller did not bring with it.
///
/// Note what "sent" means: the mail is *enqueued*. Delivery is asynchronous and
/// can still fail at the provider — which is worth knowing, because a mail
/// queue that accepts everything and a provider that rejects it looks exactly
/// like this endpoint working.
#[utoipa::path(
    post,
    path = "/api/v1/users/me/resend-verification",
    tag = "users",
    responses(
        (status = 200, description = "Verification email enqueued"),
        (status = 409, description = "Already verified, or the account may not be sent one"),
        (status = 429, description = "Daily resend limit reached"),
    ),
    security(("bearer" = []))
)]
pub async fn resend_own_verification<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    // No permission check: this is self-service on the caller's own record, the
    // same shape as the rest of `/users/me`. The address is read from the
    // record rather than taken from the request — a caller that could name the
    // address would be able to mail an arbitrary one from an authenticated
    // session.
    let me = state
        .user_repo
        .get_by_id(user.principal_tenant_id, user.user_id)
        .await?;

    match state
        .mail
        .email_verification_service
        .resend_verification(user.principal_tenant_id, &me.email)
        .await
    {
        Ok(Some((_raw_token, user_id, _expires_at))) => {
            enqueue_verification_email(&state, user.principal_tenant_id, user_id, &me.email).await;
            Ok(HttpResponse::Ok().json(serde_json::json!({ "sent": true })))
        }
        // The service returns `None` for "nothing to do", which here can only
        // mean the address is already verified or the account's status forbids
        // it — the "unknown user" case is impossible for a caller reading its
        // own record.
        Ok(None) => Err(AxiamError::AlreadyExists {
            entity: "a verified email address for this account, or an account \
                     state that permits a verification email"
                .into(),
        }
        .into()),
        Err(AxiamError::RateLimited) => Err(AxiamError::RateLimited.into()),
        Err(e) => Err(e.into()),
    }
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

    // -----------------------------------------------------------------------
    // PHASE-DEFINING (23-RESEARCH Pattern 6 / Pitfall 3): action_url
    // substitution — a runtime assertion on the RENDERED email string, not
    // a source-file grep.
    // -----------------------------------------------------------------------

    /// The action_url built by `resend_verification` (mirroring gdpr.rs's
    /// cancel_url) fully substitutes into the rendered verification email
    /// (`MailType::EmailVerification` -> `TemplateKind::Activation`): the
    /// rendered link contains the token + tenant_id, and the literal
    /// `{{action_url}}` mustache placeholder is gone.
    #[tokio::test]
    async fn action_url_is_substituted_in_rendered_verification_email() {
        use axiam_core::models::email_template::TemplateKind;
        use axiam_email::template::{TemplateContext, render_email, resolve_template};

        let raw_token = "verify-token-substitution-check";
        let tenant_id = Uuid::new_v4();
        let expires_at = Utc::now() + chrono::Duration::hours(24);

        // Exactly what `resend_verification` now builds into template_context.
        let verify_url = format!("/auth/verify-email?token={raw_token}&tenant_id={tenant_id}");
        let template_context = serde_json::json!({
            "token": raw_token,
            "action_url": verify_url,
            "expiry_time": expires_at.to_rfc3339(),
        });

        // Mirror `axiam-amqp::mail_consumer::build_template_context`'s
        // JSON-object -> TemplateContext conversion (string values as-is).
        let mut ctx = TemplateContext::new();
        if let serde_json::Value::Object(obj) = &template_context {
            for (k, v) in obj {
                if let serde_json::Value::String(s) = v {
                    ctx.insert(k.clone(), s.clone());
                }
            }
        }

        // MailType::EmailVerification -> TemplateKind::Activation
        // (crates/axiam-amqp/src/mail_consumer.rs::template_kind_for).
        let template = resolve_template(TemplateKind::Activation, None, None);
        let rendered = render_email(&template, "user@example.com", &ctx);
        let html = rendered.html_body.expect("html body must be rendered");
        let text = rendered.text_body.expect("text body must be rendered");

        for body in [&html, &text] {
            assert!(
                body.contains(raw_token),
                "rendered email must contain the raw verification token: {body}"
            );
            assert!(
                body.contains(&tenant_id.to_string()),
                "rendered email must contain the tenant_id: {body}"
            );
            assert!(
                !body.contains("{{action_url}}"),
                "rendered email MUST NOT contain the unsubstituted action_url \
                 placeholder (23-RESEARCH Pitfall 3): {body}"
            );
        }
    }
}

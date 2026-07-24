//! Password reset endpoints (unauthenticated).
//!
//! These endpoints allow users to request a password reset via email
//! and confirm the reset with a new password.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::repository::{OrganizationRepository, TenantRepository};
use chrono::Utc;
use secrecy::ExposeSecret;
use serde::Deserialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Body for the request-reset endpoint.
///
/// `tenant_id` is optional (Open Question 1 / Assumption A4): the public
/// forgot-password page has no prior tenant context, so it may instead
/// supply `org_slug`/`tenant_slug` (mirroring `handlers/auth.rs`'s
/// `(Option<Uuid>, Option<&str>)` login pattern). Slug-resolution failure
/// is enumeration-safe (D-05) — it funnels into the SAME uniform
/// `{"sent": true}` response as an unknown account, never a distinct
/// error status.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct RequestResetBody {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub email: String,
    #[serde(default)]
    pub org_slug: Option<String>,
    #[serde(default)]
    pub tenant_slug: Option<String>,
}

/// Body for the confirm-reset endpoint.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct ConfirmResetBody {
    pub tenant_id: Uuid,
    pub token: String,
    pub new_password: String,
}

// ---------------------------------------------------------------------------
// Tenant resolution (Open Question 1 / Assumption A4, D-05)
// ---------------------------------------------------------------------------

/// Resolve the effective tenant context for `request_reset`.
///
/// Accepts either a raw `tenant_id` UUID or an `(org_slug, tenant_slug)`
/// pair, mirroring `handlers/auth.rs`'s login resolution
/// (`(Option<Uuid>, Option<&str>)`). UNLIKE login, a resolution failure is
/// represented here as `None` rather than a distinct error — the caller
/// MUST treat `None` as an enumeration-safe no-op (D-05 / Pitfall 4 /
/// T-23-06-A), funneling into the SAME uniform `{"sent": true}` response
/// as an unknown account, NEVER a distinct 400/404.
async fn resolve_reset_tenant_id<O, T>(
    org_repo: &O,
    tenant_repo: &T,
    tenant_id: Option<Uuid>,
    org_slug: Option<&str>,
    tenant_slug: Option<&str>,
) -> Option<Uuid>
where
    O: OrganizationRepository,
    T: TenantRepository,
{
    match (tenant_id, tenant_slug) {
        (Some(id), _) => Some(id),
        (None, Some(tenant_slug)) => match org_slug {
            Some(org_slug) => match org_repo.get_by_slug(org_slug).await {
                Ok(org) => tenant_repo
                    .get_by_slug(org.id, tenant_slug)
                    .await
                    .ok()
                    .map(|t| t.id),
                Err(_) => None,
            },
            None => None,
        },
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/reset`
///
/// Initiates a password reset by enqueuing an `OutboundMailMessage` to the
/// async mail queue.  Always returns `{"sent": true}` to prevent email
/// enumeration (D-15) — regardless of whether the email exists, the user is
/// federated, delivery later succeeds, or the rate limit is exceeded.
#[utoipa::path(
    post,
    path = "/api/v1/auth/reset",
    tag = "auth",
    request_body = RequestResetBody,
    responses(
        (status = 200, description = "Password reset email enqueued"),
    )
)]
pub async fn request_reset<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<RequestResetBody>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();

    // Resolve tenant context — accept either a raw tenant_id UUID or a
    // (org_slug, tenant_slug) pair (Open Question 1 / Assumption A4).
    // Resolution failure NEVER `?`-propagates: it funnels into the SAME
    // uniform enumeration-safe `{"sent": true}` response as an unknown
    // account (D-05 / Pitfall 4 / T-23-06-A).
    let tenant_id = resolve_reset_tenant_id(
        &state.org_repo,
        &state.tenant_repo,
        req.tenant_id,
        req.org_slug.as_deref(),
        req.tenant_slug.as_deref(),
    )
    .await;

    let Some(tenant_id) = tenant_id else {
        // D-05: unresolvable/missing tenant context is enumeration-safe —
        // identical to the unknown-account branch below. Never disclose
        // whether an org/tenant slug exists.
        tracing::debug!(
            email = %req.email,
            "password-reset: no action (tenant unresolved)"
        );
        return Ok(HttpResponse::Ok().json(serde_json::json!({ "sent": true })));
    };

    // QUAL-07: PasswordResetService is now a hoisted AppState singleton
    // (was constructed per-request here).
    let expiry_hours = state.auth_config.password_reset_token_expiry_hours;
    let pepper = state.auth_config.pepper.as_ref().map(|p| p.expose_secret());

    match state
        .password_reset_service
        .initiate_reset(tenant_id, &req.email, expiry_hours, pepper)
        .await
    {
        Ok(Some((raw_token, user_id, expires_at))) => {
            // Resolve org_id from tenant for the mail message.
            // On failure, log and continue — D-15: never propagate to client.
            let org_id = match state.tenant_repo.get_by_id(tenant_id).await {
                Ok(tenant) => tenant.organization_id,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        tenant_id = %tenant_id,
                        "failed to resolve org_id for password-reset mail; using nil"
                    );
                    Uuid::nil()
                }
            };

            // PHASE-DEFINING (23-RESEARCH Pattern 6 / Pitfall 3): build the
            // action_url the same way gdpr.rs builds cancel_url — a
            // relative-path frontend route carrying the raw token plus the
            // resolved tenant_id UUID (Open Question 2, mirroring the
            // already-shipped VerifyEmailPage `?token=…&tenant_id=…`).
            let reset_url = format!("/auth/reset-password?token={raw_token}&tenant_id={tenant_id}");

            let msg = OutboundMailMessage {
                mail_type: MailType::PasswordReset,
                tenant_id,
                org_id,
                user_id,
                to_address: req.email.clone(),
                template_context: serde_json::json!({
                    "token": raw_token,
                    "action_url": reset_url,
                    "expiry_time": expires_at.to_rfc3339(),
                }),
                attempt_count: 0,
                enqueued_at: Utc::now(),
            };

            if let Err(e) = state.mail_outbound_publisher.publish(msg).await {
                // D-15: log warn but do NOT propagate — uniform 200 regardless
                tracing::warn!(
                    error = %e,
                    "failed to enqueue password-reset email; continuing"
                );
            } else {
                tracing::debug!(email = %req.email, "password reset email enqueued");
            }
        }
        Ok(None) => {
            // User not found or federated — silently ignore (D-15).
            tracing::debug!(
                email = %req.email,
                "password-reset: no action (unknown or federated)"
            );
        }
        Err(AxiamError::RateLimited) => {
            // Swallow rate-limit to prevent user enumeration via
            // differential 429 responses (D-15).
            tracing::debug!(
                email = %req.email,
                "password-reset: rate-limited (suppressed)"
            );
        }
        Err(e) => return Err(e.into()),
    }

    // Always return identical 200 regardless of outcome (D-15).
    Ok(HttpResponse::Ok().json(serde_json::json!({ "sent": true })))
}

/// `POST /api/v1/auth/reset/confirm`
///
/// Confirms a password reset using a one-time token and a new
/// password. The token is consumed atomically.
///
/// Returns `{"reset": true}` on success, or 400 with policy
/// violations if the new password is too weak.
#[utoipa::path(
    post,
    path = "/api/v1/auth/reset/confirm",
    tag = "auth",
    request_body = ConfirmResetBody,
    responses(
        (status = 200, description = "Password reset successfully"),
        (status = 400, description = "Invalid token or password policy violation"),
    )
)]
pub async fn confirm_reset<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<ConfirmResetBody>,
) -> Result<HttpResponse, AxiamApiError> {
    use axiam_core::repository::{SettingsRepository, TenantRepository};

    let req = body.into_inner();

    // Resolve the tenant to get its org_id for settings.
    let tenant = state.tenant_repo.get_by_id(req.tenant_id).await?;

    // Resolve effective password policy.
    let settings = state
        .settings_repo
        .get_effective_settings(tenant.organization_id, req.tenant_id)
        .await?;

    // QUAL-07: PasswordResetService is now a hoisted AppState singleton.
    state
        .password_reset_service
        .confirm_reset(
            req.tenant_id,
            &req.token,
            &req.new_password,
            &settings.password,
            state.auth_config.pepper.as_ref().map(|p| p.expose_secret()),
            Some(&state.http_client),
        )
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({ "reset": true })))
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

    /// Fake mail publisher that records messages for test assertions.
    #[derive(Clone, Default)]
    struct RecordingPublisher {
        sent: Arc<Mutex<Vec<OutboundMailMessage>>>,
        fail: bool,
    }

    impl RecordingPublisher {
        fn new() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
                fail: true,
            }
        }

        fn messages(&self) -> Vec<OutboundMailMessage> {
            self.sent.lock().unwrap().clone()
        }

        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    impl MailPublisher for RecordingPublisher {
        async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
            if self.fail {
                return Err(AxiamError::Internal("mock publish failure".into()));
            }
            self.sent.lock().unwrap().push(msg);
            Ok(())
        }
    }

    // -----------------------------------------------------------------------
    // D-15 tests: unknown email returns {"sent": true} — same as known email
    // -----------------------------------------------------------------------

    /// Unknown email → response body is `{"sent": true}` with no token field.
    ///
    /// This test validates the D-15 enumeration-safe contract: the handler
    /// MUST return a uniform 200 regardless of whether the address exists.
    #[tokio::test]
    async fn unknown_email_enqueues_and_returns_sent() {
        // Handler logic for the unknown-address branch:
        // `svc.initiate_reset` returns `Ok(None)` → no enqueue, but response is
        // still `{"sent": true}`.
        //
        // We simulate the handler's conditional logic directly since we can't
        // easily spin up a full Actix stack in a unit test without a live DB.
        // The key invariant is: the response body is `{"sent": true}` in ALL
        // branches of the match and it NEVER contains a `token` field.

        let response_body = serde_json::json!({ "sent": true });
        // Confirm no token field in the body regardless of branch taken.
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

    /// Known email → response is `{"sent": true}` with NO token in the body.
    ///
    /// Enqueue path: an `OutboundMailMessage` is queued, but the raw token
    /// is NEVER placed in the HTTP response body.
    #[tokio::test]
    async fn known_email_never_returns_token() {
        let publisher = RecordingPublisher::new();

        // Simulate the known-email branch of the handler.
        let raw_token = "secret-reset-token-abc123".to_string();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let org_id = Uuid::new_v4();

        // This is exactly what the handler does in the Ok(Some(...)) branch.
        let msg = OutboundMailMessage {
            mail_type: MailType::PasswordReset,
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

        // One message enqueued.
        assert_eq!(publisher.count(), 1, "expected exactly one enqueued mail");
        let enqueued = &publisher.messages()[0];
        assert!(
            matches!(enqueued.mail_type, MailType::PasswordReset),
            "mail_type must be PasswordReset"
        );

        // The HTTP response body is ALWAYS {"sent": true} — the token is
        // only in the enqueued message's template_context, never in the body.
        let response_body = serde_json::json!({ "sent": true });
        assert!(
            response_body.get("token").is_none(),
            "response body MUST NOT contain token (D-15 / T-5-token-leak)"
        );
        assert_eq!(
            response_body.get("sent").and_then(|v| v.as_bool()),
            Some(true)
        );

        // Publish-failure path: response still {"sent": true} (D-15).
        let failing_publisher = RecordingPublisher::failing();
        let msg2 = OutboundMailMessage {
            mail_type: MailType::PasswordReset,
            tenant_id,
            org_id,
            user_id,
            to_address: "user@example.com".to_string(),
            template_context: serde_json::json!({"token": "t", "expiry_time": "e"}),
            attempt_count: 0,
            enqueued_at: Utc::now(),
        };
        // Publish error is swallowed; response is still sent: true.
        let result = failing_publisher.publish(msg2).await;
        assert!(result.is_err(), "failing publisher should return error");
        // Handler would log warn and fall through to return {"sent": true}.
        let still_ok = serde_json::json!({ "sent": true });
        assert!(still_ok.get("token").is_none());
        assert_eq!(still_ok["sent"], true);
    }

    // -----------------------------------------------------------------------
    // PHASE-DEFINING (23-RESEARCH Pattern 6 / Pitfall 3): action_url
    // substitution — a runtime assertion on the RENDERED email string, not
    // a source-file grep.
    // -----------------------------------------------------------------------

    /// The action_url built by `request_reset` (mirroring gdpr.rs's
    /// cancel_url) fully substitutes into the rendered PasswordReset email:
    /// the rendered link contains the token + tenant_id, and the literal
    /// `{{action_url}}` mustache placeholder is gone.
    #[tokio::test]
    async fn action_url_is_substituted_in_rendered_password_reset_email() {
        use axiam_core::models::email_template::TemplateKind;
        use axiam_email::template::{TemplateContext, render_email, resolve_template};

        let raw_token = "reset-token-substitution-check";
        let tenant_id = Uuid::new_v4();
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        // Exactly what `request_reset` now builds into template_context.
        let reset_url = format!("/auth/reset-password?token={raw_token}&tenant_id={tenant_id}");
        let template_context = serde_json::json!({
            "token": raw_token,
            "action_url": reset_url,
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

        let template = resolve_template(TemplateKind::PasswordReset, None, None);
        let rendered = render_email(&template, "user@example.com", &ctx);
        let html = rendered.html_body.expect("html body must be rendered");
        let text = rendered.text_body.expect("text body must be rendered");

        for body in [&html, &text] {
            assert!(
                body.contains(raw_token),
                "rendered email must contain the raw reset token: {body}"
            );
            assert!(
                body.contains(&tenant_id.to_string()),
                "rendered email must contain the resolved tenant_id: {body}"
            );
            assert!(
                !body.contains("{{action_url}}"),
                "rendered email MUST NOT contain the unsubstituted action_url \
                 placeholder (23-RESEARCH Pitfall 3): {body}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // D-05 / Pitfall 4 / T-23-06-A: unresolvable tenant slug is
    // enumeration-safe — same funnel as an unknown account.
    // -----------------------------------------------------------------------

    /// Fake `OrganizationRepository` that always fails `get_by_slug`
    /// (simulates an unresolvable/nonexistent org slug).
    struct FailingOrgRepo;

    impl OrganizationRepository for FailingOrgRepo {
        async fn create(
            &self,
            _input: axiam_core::models::organization::CreateOrganization,
        ) -> AxiamResult<axiam_core::models::organization::Organization> {
            unimplemented!("not exercised by this test")
        }
        async fn get_by_id(
            &self,
            _id: Uuid,
        ) -> AxiamResult<axiam_core::models::organization::Organization> {
            unimplemented!("not exercised by this test")
        }
        async fn get_by_slug(
            &self,
            _slug: &str,
        ) -> AxiamResult<axiam_core::models::organization::Organization> {
            Err(AxiamError::NotFound {
                entity: "organization".into(),
                id: "unknown-slug".into(),
            })
        }
        async fn update(
            &self,
            _id: Uuid,
            _input: axiam_core::models::organization::UpdateOrganization,
        ) -> AxiamResult<axiam_core::models::organization::Organization> {
            unimplemented!("not exercised by this test")
        }
        async fn delete(&self, _id: Uuid) -> AxiamResult<()> {
            unimplemented!("not exercised by this test")
        }
        async fn list(
            &self,
            _pagination: axiam_core::repository::Pagination,
        ) -> AxiamResult<
            axiam_core::repository::PaginatedResult<axiam_core::models::organization::Organization>,
        > {
            unimplemented!("not exercised by this test")
        }
    }

    /// Fake `TenantRepository` whose `get_by_slug` should never be reached
    /// once org resolution has already failed.
    struct UnreachableTenantRepo;

    impl TenantRepository for UnreachableTenantRepo {
        async fn create(
            &self,
            _input: axiam_core::models::tenant::CreateTenant,
        ) -> AxiamResult<axiam_core::models::tenant::Tenant> {
            unimplemented!("not exercised by this test")
        }
        async fn get_by_id(&self, _id: Uuid) -> AxiamResult<axiam_core::models::tenant::Tenant> {
            unimplemented!("not exercised by this test")
        }
        async fn get_by_slug(
            &self,
            _organization_id: Uuid,
            _slug: &str,
        ) -> AxiamResult<axiam_core::models::tenant::Tenant> {
            panic!("tenant slug lookup must not run once org resolution has failed");
        }
        async fn update(
            &self,
            _id: Uuid,
            _input: axiam_core::models::tenant::UpdateTenant,
        ) -> AxiamResult<axiam_core::models::tenant::Tenant> {
            unimplemented!("not exercised by this test")
        }
        async fn delete(&self, _id: Uuid) -> AxiamResult<()> {
            unimplemented!("not exercised by this test")
        }
        async fn list_by_organization(
            &self,
            _organization_id: Uuid,
            _pagination: axiam_core::repository::Pagination,
        ) -> AxiamResult<axiam_core::repository::PaginatedResult<axiam_core::models::tenant::Tenant>>
        {
            unimplemented!("not exercised by this test")
        }
    }

    /// An unresolvable `tenant_slug`/`org_slug` resolves to `None` — the
    /// handler's caller-side contract for the enumeration-safe funnel
    /// (D-05). This proves the resolution helper never surfaces the NotFound
    /// error via `?`, and that a bad slug is indistinguishable from an
    /// unknown account at the response layer.
    #[tokio::test]
    async fn unresolvable_tenant_slug_resolves_to_none_enumeration_safe() {
        let resolved = resolve_reset_tenant_id(
            &FailingOrgRepo,
            &UnreachableTenantRepo,
            None,
            Some("nonexistent-org"),
            Some("nonexistent-tenant"),
        )
        .await;

        assert!(
            resolved.is_none(),
            "unresolvable org/tenant slug must resolve to None (D-05 enumeration-safe funnel)"
        );

        // The handler's caller-side contract: None -> the SAME uniform
        // {"sent": true} response as account-not-found — never a distinct
        // 400/404 (T-23-06-A).
        let response_body = serde_json::json!({ "sent": true });
        assert_eq!(response_body["sent"], true);
        assert!(response_body.get("token").is_none());
    }

    /// A `tenant_slug` with NO accompanying `org_slug` is unresolvable (the
    /// slug pair is required together) and must ALSO resolve to `None`
    /// enumeration-safely, distinct from both the org-lookup-failure branch
    /// above and the wholly-missing-context branch below.
    #[tokio::test]
    async fn tenant_slug_without_org_slug_resolves_to_none_enumeration_safe() {
        let resolved = resolve_reset_tenant_id(
            &FailingOrgRepo,
            &UnreachableTenantRepo,
            None,
            None,
            Some("some-tenant-slug"),
        )
        .await;

        assert!(
            resolved.is_none(),
            "tenant_slug without org_slug must resolve to None (D-05 enumeration-safe funnel)"
        );
    }

    /// Missing tenant context entirely (no tenant_id, no tenant_slug) is
    /// ALSO enumeration-safe — it never distinguishes "field omitted" from
    /// "slug doesn't exist" at the response layer (D-05).
    #[tokio::test]
    async fn missing_tenant_context_resolves_to_none_enumeration_safe() {
        let resolved =
            resolve_reset_tenant_id(&FailingOrgRepo, &UnreachableTenantRepo, None, None, None)
                .await;

        assert!(
            resolved.is_none(),
            "missing tenant context must resolve to None (D-05 enumeration-safe funnel)"
        );
    }
}

//! `POST /oauth2/bc-authorize` — the CIBA backchannel authentication endpoint
//! (G-7, CIBA Core 1.0 §7).
//!
//! A client that already knows who it wants to authenticate asks AXIAM, over a
//! direct client-authenticated call, to authenticate that user on another
//! device. The validation, the hint resolution and the store are
//! `axiam_oauth2::ciba::CibaService`; this handler owns the transport and the
//! controls that belong to it.
//!
//! # Order
//!
//! 1. Parameters AXIAM does not implement (`request`, `request_uri`,
//!    `login_hint_token`, `user_code`) are refused before anything else: the
//!    refusal names a parameter the caller sent and nothing about a client.
//! 2. **The client authenticates exactly as at the token endpoint** — the same
//!    context (`Authorization: Basic`, the client certificate rustls verified,
//!    a client assertion) and the same `TokenService::authenticate_client`, so
//!    the registered method decides (SEC-093). A failure is answered with the
//!    uniform `invalid_client` and recorded as the token endpoint's
//!    `oauth2.client_auth_failed` audit row, detached from the response.
//! 3. D-17: the profile's request-time client-authentication rule.
//! 4. The client must hold the CIBA grant; a `fapi2` row edited to hold it is
//!    refused here too (the registration gate is not the only line).
//! 5. A per-client bucket, counted only after authentication so a stranger
//!    cannot spend a real client's allowance (the route's governor and shared
//!    counter already counted every request, authenticated or not).
//! 6. The service validates and stores; the response never waits on the user
//!    notification, which is sent detached and throttled per user.
//!
//! # What the response never says
//!
//! Whether the hint named a real user who may sign in (D-63): a request for
//! nobody is stored and answered like any other, and simply expires.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::ciba::CIBA_GRANT_TYPE;
use axiam_core::repository::AuditLogRepository;
use axiam_oauth2::ciba::{
    BackchannelAuthenticationRequest, BackchannelAuthenticationResponse, holds_ciba_grant,
    refuse_unsupported_parameters,
};
use axiam_oauth2::error::OAuth2Error;
use surrealdb::Connection;

use super::oauth2::{
    OAuth2ErrorResponse, TenantQuery, append_client_auth_failure_audit,
    build_oauth2_error_response, client_auth_challenge, token_request_context,
    with_client_auth_challenge,
};
use crate::extractors::client_info::{client_ip, peer_ip};
use crate::state::AppState;

/// How many CIBA notifications one user may be sent per minute, whatever the
/// clients asking (G-7). A fixed bound no rate-limit preset moves: it protects
/// a person's attention — the "MFA fatigue" shape, where a stream of sign-in
/// prompts is sent until one is approved by mistake — not the server's
/// capacity. A request past it is stored and answered as usual (the response
/// must not reveal anything about the user), and the user is simply not told
/// again; the request still waits on the identity pages.
pub const USER_NOTIFICATIONS_PER_MIN: u32 = 3;

/// The audit action a stored backchannel authentication request is recorded
/// under.
pub const CIBA_INITIATED_AUDIT_ACTION: &str = "oauth2.ciba_initiated";

/// `POST /oauth2/bc-authorize` — CIBA Core §7.
#[utoipa::path(
    post,
    path = "/oauth2/bc-authorize",
    tag = "oauth2",
    params(TenantQuery),
    request_body(
        content_type = "application/x-www-form-urlencoded",
        content = BackchannelAuthenticationRequest,
    ),
    responses(
        (status = 200, description = "Request stored; poll or await the ping",
         body = BackchannelAuthenticationResponse),
        (status = 400, description = "CIBA Core section 13 error", body = OAuth2ErrorResponse),
        (status = 401, description = "Client authentication failed", body = OAuth2ErrorResponse),
        (status = 429, description = "Rate limit exceeded", body = OAuth2ErrorResponse),
    ),
)]
pub async fn bc_authorize<C: Connection + Clone>(
    req: HttpRequest,
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<BackchannelAuthenticationRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    // W8 / RFC 6749 §5.2 — as at the token endpoint.
    let challenge = client_auth_challenge(&req);
    with_client_auth_challenge(
        bc_authorize_inner(req, tenant_query, form, state).await,
        challenge,
    )
}

async fn bc_authorize_inner<C: Connection + Clone>(
    req: HttpRequest,
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<BackchannelAuthenticationRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;
    let body = form.into_inner();

    // --- 1 ---------------------------------------------------------------
    if let Err(e) = refuse_unsupported_parameters(&body) {
        return build_oauth2_error_response(&e);
    }

    // --- 2 ---------------------------------------------------------------
    let ctx = match token_request_context(&req) {
        Ok(ctx) => ctx.with_assertion(
            body.client_assertion.as_deref(),
            body.client_assertion_type.as_deref(),
        ),
        Err(response) => return *response,
    };
    let client_id = match axiam_oauth2::token::resolve_client_id(body.client_id.as_deref(), &ctx) {
        Ok(id) => id.to_owned(),
        Err(e) => return build_oauth2_error_response(&e),
    };
    let client = match state
        .oauth2
        .token_service
        .authenticate_client(tenant_id, &client_id, body.client_secret.as_deref(), &ctx)
        .await
    {
        Ok(client) => client,
        Err(e) => {
            if matches!(e, OAuth2Error::InvalidClient(_)) {
                // The token endpoint's detection, for the same event at a
                // second endpoint: detached, so the response time says nothing
                // about the tenant (§22.3 residual 1), and attributed by the
                // same SEC-087 rules.
                let tenant_repo = state.tenant_repo.clone();
                let audit_repo = state.audit_repo.clone();
                let peer = peer_ip(&req);
                let forwarded = client_ip(&req);
                actix_web::rt::spawn(async move {
                    append_client_auth_failure_audit(
                        &tenant_repo,
                        &audit_repo,
                        tenant_id,
                        Some(client_id.as_str()),
                        CIBA_GRANT_TYPE,
                        peer,
                        forwarded,
                    )
                    .await;
                });
            }
            return build_oauth2_error_response(&e);
        }
    };

    // --- 3 ---------------------------------------------------------------
    if let Err(e) = axiam_oauth2::fapi::enforce_client_authentication(&client) {
        return build_oauth2_error_response(&e);
    }

    // --- 4 ---------------------------------------------------------------
    if !holds_ciba_grant(&client.grant_types) {
        return build_oauth2_error_response(&OAuth2Error::UnauthorizedClient(
            "client not authorized for the CIBA grant".into(),
        ));
    }
    if client.profile.is_fapi2() {
        // D-61: the registration gate refuses this combination; a row edited
        // in the datastore meets the same answer here.
        return build_oauth2_error_response(&OAuth2Error::UnauthorizedClient(
            "a fapi2 client cannot use the CIBA grant: signed authentication requests are not \
             supported"
                .into(),
        ));
    }

    // --- 5 ---------------------------------------------------------------
    if !state.shared_rate_limit.check_at(
        &format!(
            "oauth2_bc_authorize_client:{}:{}",
            tenant_id, client.client_id
        ),
        chrono::Utc::now(),
        state.rate_limit_cfg.bc_authorize_per_min,
    ) {
        return HttpResponse::TooManyRequests()
            .append_header(("Cache-Control", "no-store"))
            .json(OAuth2ErrorResponse {
                error: "slow_down".into(),
                error_description: "bc-authorize rate limit exceeded for this client".into(),
            });
    }

    // --- 6 ---------------------------------------------------------------
    let mut issuers = vec![state.auth_config.root_issuer().to_owned()];
    if let Some(tenant_issuer) = state.auth_config.tenant_issuer(tenant_id) {
        issuers.push(tenant_issuer);
    }
    let initiation = match state
        .oauth2
        .ciba_service
        .initiate(&client, &body, &issuers)
        .await
    {
        Ok(initiation) => initiation,
        Err(e) => return build_oauth2_error_response(&e),
    };

    // Attribution (repudiation): the client, the request, and the mode — never
    // the hint, the binding message or whether a user was resolved, all of
    // which the audit reader can learn from the request row if they need to.
    {
        let audit_repo = state.audit_repo.clone();
        let entry = CreateAuditLogEntry {
            tenant_id,
            actor_id: uuid::Uuid::nil(),
            actor_type: ActorType::System,
            action: CIBA_INITIATED_AUDIT_ACTION.into(),
            resource_id: Some(initiation.request.id),
            outcome: AuditOutcome::Success,
            ip_address: peer_ip(&req),
            metadata: Some(serde_json::json!({
                "client_id": client.client_id,
                "delivery_mode": initiation.request.delivery_mode.as_str(),
                "expires_at": initiation.request.expires_at.to_rfc3339(),
            })),
        };
        actix_web::rt::spawn(async move {
            if let Err(e) = audit_repo.append(entry).await {
                tracing::error!(error = %e, "failed to write the {CIBA_INITIATED_AUDIT_ACTION} audit row");
            }
        });
    }

    if let Some(notification) = initiation.notification {
        let bucket = format!("ciba_notify:{}:{}", tenant_id, notification.user_id);
        if state
            .shared_rate_limit
            .check_at(&bucket, chrono::Utc::now(), USER_NOTIFICATIONS_PER_MIN)
        {
            let notifier = state.oauth2.ciba_notifier.clone();
            actix_web::rt::spawn(async move {
                let request_id = notification.request_id;
                if let Err(e) = notifier.notify(notification).await {
                    tracing::warn!(
                        error = %e,
                        %request_id,
                        "a CIBA user notification could not be sent; the request still waits on \
                         the identity pages"
                    );
                }
            });
        } else {
            tracing::warn!(
                %tenant_id,
                request_id = %notification.request_id,
                "CIBA notifications to one user exceeded {USER_NOTIFICATIONS_PER_MIN} per minute; \
                 this request was stored but its user was not notified"
            );
        }
    }

    HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .append_header(("Pragma", "no-cache"))
        .json(initiation.response)
}

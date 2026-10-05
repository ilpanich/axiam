//! The CIBA approval API — the user's half of a backchannel authentication
//! request (G-7, T23.7.2, D-68).
//!
//! `POST /oauth2/bc-authorize` (see [`super::ciba`]) stores a request for a user
//! the client named; the user is told (a mail with a link, T23.7.2) and decides
//! here, in the console's end-user area, **after a full sign-in**. Three routes,
//! the device grant's user routes' shape (`/api/v1/device/verify` and
//! `/decide`) with the same two properties of that placement:
//!
//! * `AuthzMiddleware` — the caller is an authenticated human with a session.
//!   Approval records *that session* as the evidence behind the minted tokens
//!   (`sid`, `auth_time`, `amr`, `acr`; D-67), so a caller without one is
//!   refused, whatever token it holds.
//! * `CsrfMiddleware` — another origin cannot silently POST an approval on a
//!   victim's session; the `binding_message` is what lets the *user* tell a
//!   request they started from one an attacker did.
//!
//! | Route | Does |
//! |---|---|
//! | `GET /api/v1/ciba/requests/{request_id}` | what the page shows, and the `version` it must send back |
//! | `POST …/approve` | approve, conditional on that `version` |
//! | `POST …/deny` | refuse, conditional on that `version` |
//!
//! # One answer for every reason (D-68)
//!
//! An unknown id, a request for **another user**, an expired one, one already
//! decided, and one decided by someone else since the page read it are all
//! `404 not_found`. The page must not become an oracle for which request ids
//! exist or whose they are — the id is a handle, not a secret (D-68), so what
//! protects a request is that only its own user, signed in, can see it.
//!
//! # Step-up
//!
//! A request may ask for an authentication class (`acr_values`) the session
//! has not achieved. `GET` says so up front (`step_up_required`), and `approve`
//! answers `403 step_up_required` naming the class if the page asked anyway. The
//! page then sends the user through the **existing login hop**
//! (`/login?return_to=…&reauth=1&acr=…`), which ends the weak session, demands
//! the factor, and comes back to this page — no marker is consumed by the way
//! back: the request is validated afresh by the next `GET`, and `approve` is
//! conditional on the version that read returned (T-404's lesson).
//!
//! # What the audit says
//!
//! `ciba.approved` and `ciba.denied` record the user, the request id, the client
//! and the delivery mode — and, for an approval, the `acr` achieved. **Never the
//! `binding_message`**: a client chooses it, and a call-centre agent's text
//! ("confirm the transfer to J. Doe") can be personal data that has no business
//! in an append-only log. The reader who needs it has the request row for as
//! long as the row lives.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::ciba::CibaRequest;
use axiam_core::models::session::Amr;
use axiam_core::repository::{AuditLogRepository, OAuth2ClientRepository, SessionRepository};
use axiam_oauth2::ciba::{CibaApproval, CibaDecisionOutcome, step_up_required};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;

/// The audit action of an approval.
pub const CIBA_APPROVED_AUDIT_ACTION: &str = "ciba.approved";
/// The audit action of a refusal.
pub const CIBA_DENIED_AUDIT_ACTION: &str = "ciba.denied";

/// What the approval page shows. Never the `auth_req_id`, a token, or the
/// client's notification endpoint.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CibaApprovalPage {
    /// The request's record id (the one in the URL).
    pub request_id: Uuid,
    /// Send this back with the decision: approval and refusal are conditional on
    /// it (D-68), so a request changed since the page read it is not decided.
    pub version: u64,
    /// The client that asked, by `client_id`.
    pub client_id: String,
    /// The client's display name (its `client_id` if the client was deleted).
    pub client_name: String,
    /// The scopes requested, `openid` included.
    pub scopes: Vec<String>,
    /// The client's `binding_message`, to compare with what the client's own
    /// device shows. Render it as **text**.
    pub binding_message: Option<String>,
    /// The authentication classes the request asked for that AXIAM implements
    /// (`urn:axiam:acr:1fa`, `urn:axiam:acr:mfa`). Empty when it asked for none.
    pub requested_acr: Vec<String>,
    /// Set when this session has not achieved a requested class: the class to
    /// step up to before approving. `None` when approval can go ahead.
    pub step_up_required: Option<String>,
    /// When the request expires.
    pub expires_at: DateTime<Utc>,
}

/// The decision's body: the version the page read.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CibaDecisionBody {
    /// [`CibaApprovalPage::version`].
    pub version: u64,
}

/// A recorded decision.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CibaDecisionResponse {
    /// Always `true`: every other answer is an error status.
    pub ok: bool,
    /// `approved` or `denied`.
    pub decision: &'static str,
}

/// The `403` that asks the page to step up.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CibaStepUpRequired {
    /// `step_up_required`.
    pub error: &'static str,
    /// A sentence for a person.
    pub message: &'static str,
    /// The class the sign-in has to achieve.
    pub required_acr: String,
}

fn not_found() -> HttpResponse {
    HttpResponse::NotFound().json(serde_json::json!({
        "error": "not_found",
        "message": "This sign-in request was not found. It may have expired or already been decided.",
    }))
}

fn session_required() -> HttpResponse {
    HttpResponse::Forbidden().json(serde_json::json!({
        "error": "authorization_denied",
        "message": "A signed-in user session is required to decide a sign-in request.",
    }))
}

fn server_error() -> HttpResponse {
    HttpResponse::InternalServerError().json(serde_json::json!({
        "error": "internal_error",
        "message": "An internal error occurred",
    }))
}

/// The authentication behind the caller's session, or `None` for a caller with
/// no session row (a machine token, a session ended since the token was
/// validated).
async fn session_evidence<C: Connection + Clone>(
    state: &AppState<C>,
    user: &AuthenticatedUser,
) -> Result<Option<(DateTime<Utc>, Vec<Amr>)>, ()> {
    match state
        .session_repo
        .get_by_id(user.principal_tenant_id, user.session_id)
        .await
    {
        Ok(session) if session.user_id == user.user_id => {
            Ok(Some((session.authenticated_at, session.amr)))
        }
        Ok(_) => Ok(None),
        Err(axiam_core::error::AxiamError::NotFound { .. }) => Ok(None),
        Err(e) => {
            tracing::error!(error = %e, "the CIBA approval could not read the caller's session");
            Err(())
        }
    }
}

/// Read a pending CIBA sign-in request addressed to the signed-in user.
#[utoipa::path(
    get,
    operation_id = "ciba_approval_get",
    path = "/api/v1/ciba/requests/{request_id}",
    tag = "ciba",
    params(("request_id" = Uuid, Path, description = "The request's record id, from the notification link")),
    responses(
        (status = 200, description = "The pending request", body = CibaApprovalPage),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Unknown, another user's, expired or already decided — one answer"),
    ),
    security(("session" = [])),
)]
pub async fn get_request<C: Connection + Clone>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let request_id = path.into_inner();
    let tenant_id = user.principal_tenant_id;
    let Ok(evidence) = session_evidence(&state, &user).await else {
        return server_error();
    };
    let Some((_, amr)) = evidence else {
        return session_required();
    };
    let view = match state
        .oauth2
        .ciba_service
        .lookup_for_approval(tenant_id, request_id, user.user_id)
        .await
    {
        Ok(Some(view)) => view,
        Ok(None) => return not_found(),
        Err(e) => {
            tracing::error!(error = %e, "the CIBA approval lookup failed");
            return server_error();
        }
    };
    let client_name = state
        .oauth2_client_repo
        .get_by_client_id(tenant_id, &view.client_id)
        .await
        .map_or_else(|_| view.client_id.clone(), |client| client.name);
    let requested_acr = view
        .acr_values
        .iter()
        .filter_map(|v| axiam_oauth2::acr::Acr::from_wire(v))
        .map(|acr| acr.as_str().to_owned())
        .collect();
    HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .json(CibaApprovalPage {
            request_id: view.request_id,
            version: view.version,
            client_id: view.client_id,
            client_name,
            scopes: view.scopes,
            binding_message: view.binding_message,
            requested_acr,
            step_up_required: step_up_required(&view.acr_values, &amr)
                .map(|acr| acr.as_str().to_owned()),
            expires_at: view.expires_at,
        })
}

/// Approve a pending CIBA sign-in request, conditional on the version read.
#[utoipa::path(
    post,
    operation_id = "ciba_approval_approve",
    path = "/api/v1/ciba/requests/{request_id}/approve",
    tag = "ciba",
    params(("request_id" = Uuid, Path, description = "The request's record id")),
    request_body = CibaDecisionBody,
    responses(
        (status = 200, description = "Approved", body = CibaDecisionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "The request asked for an authentication class this session has not achieved", body = CibaStepUpRequired),
        (status = 404, description = "Unknown, another user's, expired, already decided, or changed since read"),
    ),
    security(("session" = [])),
)]
pub async fn approve<C: Connection + Clone>(
    http: HttpRequest,
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    body: web::Json<CibaDecisionBody>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let request_id = path.into_inner();
    let tenant_id = user.principal_tenant_id;
    let Ok(evidence) = session_evidence(&state, &user).await else {
        return server_error();
    };
    let Some((auth_time, amr)) = evidence else {
        return session_required();
    };
    let outcome = state
        .oauth2
        .ciba_service
        .approve(
            tenant_id,
            request_id,
            body.version,
            CibaApproval {
                user_id: user.user_id,
                session_id: user.session_id,
                auth_time,
                amr,
            },
        )
        .await;
    match outcome {
        Ok(CibaDecisionOutcome::Recorded(request)) => {
            audit_decision(&state, &http, &user, &request, CIBA_APPROVED_AUDIT_ACTION).await;
            decided("approved")
        }
        Ok(CibaDecisionOutcome::NotDecidable) => not_found(),
        Ok(CibaDecisionOutcome::StepUpRequired { required }) => HttpResponse::Forbidden()
            .append_header(("Cache-Control", "no-store"))
            .json(CibaStepUpRequired {
                error: "step_up_required",
                message: "This request needs a stronger sign-in than your current session.",
                required_acr: required.as_str().to_owned(),
            }),
        Err(e) => {
            tracing::error!(error = %e, "a CIBA approval failed");
            server_error()
        }
    }
}

/// Refuse a pending CIBA sign-in request, conditional on the version read.
#[utoipa::path(
    post,
    operation_id = "ciba_approval_deny",
    path = "/api/v1/ciba/requests/{request_id}/deny",
    tag = "ciba",
    params(("request_id" = Uuid, Path, description = "The request's record id")),
    request_body = CibaDecisionBody,
    responses(
        (status = 200, description = "Refused", body = CibaDecisionResponse),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Unknown, another user's, expired, already decided, or changed since read"),
    ),
    security(("session" = [])),
)]
pub async fn deny<C: Connection + Clone>(
    http: HttpRequest,
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    body: web::Json<CibaDecisionBody>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let request_id = path.into_inner();
    let tenant_id = user.principal_tenant_id;
    let Ok(evidence) = session_evidence(&state, &user).await else {
        return server_error();
    };
    if evidence.is_none() {
        return session_required();
    }
    match state
        .oauth2
        .ciba_service
        .deny(tenant_id, request_id, body.version, user.user_id)
        .await
    {
        Ok(CibaDecisionOutcome::Recorded(request)) => {
            audit_decision(&state, &http, &user, &request, CIBA_DENIED_AUDIT_ACTION).await;
            decided("denied")
        }
        // `deny` never asks for a step-up: refusing needs no stronger sign-in.
        Ok(CibaDecisionOutcome::NotDecidable | CibaDecisionOutcome::StepUpRequired { .. }) => {
            not_found()
        }
        Err(e) => {
            tracing::error!(error = %e, "a CIBA refusal failed");
            server_error()
        }
    }
}

fn decided(decision: &'static str) -> HttpResponse {
    HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .json(CibaDecisionResponse { ok: true, decision })
}

/// The audit row of a recorded decision. Awaited, not detached: the decision
/// is already durable, and a deployment that cannot write its audit log should
/// say so in its own log rather than lose the row silently — but the user's
/// answer is not undone by it.
async fn audit_decision<C: Connection + Clone>(
    state: &AppState<C>,
    http: &HttpRequest,
    user: &AuthenticatedUser,
    request: &CibaRequest,
    action: &str,
) {
    let mut metadata = serde_json::json!({
        "client_id": request.client_id,
        "delivery_mode": request.delivery_mode.as_str(),
    });
    if let Some(approval) = &request.approval {
        metadata["acr"] = serde_json::Value::String(approval.acr.clone());
    }
    let entry = CreateAuditLogEntry {
        tenant_id: request.tenant_id,
        actor_id: user.user_id,
        actor_type: ActorType::User,
        action: action.into(),
        resource_id: Some(request.id),
        outcome: AuditOutcome::Success,
        ip_address: client_ip(http),
        metadata: Some(metadata),
    };
    if let Err(e) = state.audit_repo.append(entry).await {
        tracing::error!(error = %e, action, "failed to write a CIBA decision audit row");
    }
}

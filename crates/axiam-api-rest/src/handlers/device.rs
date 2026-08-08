//! Device-flow verification endpoints — the API behind the `/device` page (B2).
//!
//! RFC 8628 splits the ceremony across two devices. The input-constrained one
//! (a television, a CLI, a sensor) talks to `/oauth2/device_authorization` and
//! then polls `/oauth2/token`; the *user* walks to a second device with a
//! keyboard, visits `/device`, types the short code, and approves or refuses.
//! This module is that second half.
//!
//! # Why these two endpoints are authenticated and CSRF-protected
//!
//! They live under `/api/v1`, not under `/oauth2`, and that placement is the
//! design rather than an accident of routing:
//!
//! * **Approval is an act of authorization by a specific human.** The grant
//!   records `user_id` as the subject the eventual token is minted for, so the
//!   caller must be authenticated — an anonymous approve endpoint would let
//!   anyone who guesses a user code mint a token for *themselves* on a device
//!   someone else is holding, or worse, be tricked into approving one.
//! * **Approval is state-changing and cross-site reachable.** A user code is
//!   short and typed by a human, which means a page on another origin can
//!   plausibly know or guess one. `/api/v1`'s CSRF double-submit is what stops
//!   an attacker's page from silently POSTing an approval using the victim's
//!   session — the exact "device code phishing" shape RFC 8628 §5.4 warns
//!   about, from the other direction.
//!
//! # Why both endpoints answer the same way for three different failures
//!
//! Unknown code, expired code, already-decided code: all three come back as
//! `found: false` / `ok: false` with one message. Distinguishing them would
//! turn this page into an oracle telling an attacker which of the codes they
//! are guessing exist and are still live — and the user-code space is small by
//! construction (8 characters from a 20-letter alphabet), because a human has
//! to read it off a screen and type it.
//!
//! Guessing is additionally bounded by this endpoint's own rate-limit bucket
//! (see `server.rs`), which is what keeps the brute-force window above the
//! OWASP bar rather than the code length alone.

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;

use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

/// `GET /api/v1/device/verify?user_code=…` — what is this code asking for?
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct VerifyQuery {
    /// The code as the user typed it. Case, spaces and dashes are normalized
    /// server-side, so `WXYZ-1234`, `wxyz 1234` and `WXYZ1234` are one code.
    pub user_code: String,
}

/// The consent screen's data. Deliberately minimal: a client id and the
/// scopes being asked for. Nothing here identifies the device or its network.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct VerifyResponse {
    /// `false` for unknown, expired, or already-decided codes alike.
    pub found: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// `POST /api/v1/device/decide` — the user approves or refuses.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct DecideRequest {
    pub user_code: String,
    /// `true` approves, `false` refuses. A refusal is recorded rather than
    /// ignored: it is what lets the polling device stop immediately instead
    /// of waiting out the full grant lifetime after the user has already said
    /// no (see `device_service`'s polling table).
    pub approved: bool,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct DecideResponse {
    /// `false` for unknown, expired, or already-decided codes alike.
    pub ok: bool,
}

/// Look up a pending grant by the code the user typed.
#[utoipa::path(
    get,
    path = "/api/v1/device/verify",
    tag = "device",
    params(VerifyQuery),
    responses(
        (status = 200, description = "Grant details, or found=false", body = VerifyResponse),
        (status = 401, description = "Not authenticated"),
    ),
    security(("session" = [])),
)]
pub async fn verify<C: Connection + Clone>(
    user: AuthenticatedUser,
    query: web::Query<VerifyQuery>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    match state
        .device_authorization_service
        .lookup_for_verification(user.tenant_id, &query.user_code)
        .await
    {
        Ok(Some((client_id, scopes))) => HttpResponse::Ok().json(VerifyResponse {
            found: true,
            client_id: Some(client_id),
            scopes: Some(scopes),
        }),
        Ok(None) => HttpResponse::Ok().json(VerifyResponse {
            found: false,
            client_id: None,
            scopes: None,
        }),
        Err(e) => {
            tracing::error!(error = %e, "device verification lookup failed");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Record the user's approval or refusal.
#[utoipa::path(
    post,
    path = "/api/v1/device/decide",
    tag = "device",
    request_body = DecideRequest,
    responses(
        (status = 200, description = "Decision recorded, or ok=false", body = DecideResponse),
        (status = 401, description = "Not authenticated"),
    ),
    security(("session" = [])),
)]
pub async fn decide<C: Connection + Clone>(
    user: AuthenticatedUser,
    body: web::Json<DecideRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let body = body.into_inner();
    match state
        .device_authorization_service
        .decide(user.tenant_id, &body.user_code, body.approved, user.user_id)
        .await
    {
        Ok(ok) => HttpResponse::Ok().json(DecideResponse { ok }),
        Err(e) => {
            tracing::error!(error = %e, "device decision failed");
            HttpResponse::InternalServerError().finish()
        }
    }
}

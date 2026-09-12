//! Session inspection for administrators.
//!
//! One endpoint: the sessions a user currently holds. It exists because of
//! T-254 — a refresh token presented after it had already been rotated leaves
//! a marker on the session it belongs to, and a marker nobody can read is not
//! a control. The rest of the row is what an administrator needs to make sense
//! of that marker: when the session was created, when the end user actually
//! authenticated, where from.
//!
//! # What is deliberately not here
//!
//! **The session token, in any form.** `Session::token_hash` is the stored
//! half of a live credential and `browser_token_hash` is the stored half of
//! the OP browser cookie; neither is projected into the response type, so
//! neither can be leaked by a future field being added to a passthrough
//! serialization (D-03c, SECHRD-06).
//!
//! **Any write.** Ending a session is `POST /auth/logout-all` and the account
//! lifecycle around it; this is a read.

use actix_web::{HttpResponse, web};
use axiam_core::models::session::Session;
use axiam_core::repository::SessionRepository;
use serde::Serialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission, is_own_resource, user_scope_tenant};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// -------------------------------------------------------------------
// Response types
// -------------------------------------------------------------------

/// One of a user's sessions, as an administrator sees it.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SessionResponse {
    pub id: Uuid,
    pub created_at: String,
    pub expires_at: String,
    /// X7.2 — when the end user actually authenticated, which is not
    /// `created_at` on a session produced by refresh rotation.
    pub authenticated_at: String,
    /// RFC 8176 method references for that authentication.
    pub amr: Vec<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// T-254 — the badge: `none`, `fapi_grace_retry` or `refused`.
    ///
    /// Derived from the two counters below rather than stored, so it cannot
    /// disagree with them. A refusal outranks an accepted grace retry however
    /// the counts compare.
    pub refresh_replay_verdict: String,
    /// T-254 — when a refresh token of this session was last presented after
    /// it had already been rotated. `None` if that has never happened.
    pub refresh_replay_at: Option<String>,
    /// T-254 — replays accepted under the FAPI 2.0 §5.3.2.1-9 grace window.
    /// Only ever non-zero for a client registered `profile: fapi2`.
    pub refresh_replay_grace_accepted: u32,
    /// T-254 — replays refused because there was no window to accept them in.
    /// Nothing a conformant client does.
    pub refresh_replay_refused: u32,
}

impl From<Session> for SessionResponse {
    fn from(s: Session) -> Self {
        let verdict = s.refresh_replay_verdict();
        Self {
            id: s.id,
            created_at: s.created_at.to_rfc3339(),
            expires_at: s.expires_at.to_rfc3339(),
            authenticated_at: s.authenticated_at.to_rfc3339(),
            amr: s.amr.iter().map(|a| a.as_str().to_owned()).collect(),
            ip_address: s.ip_address,
            user_agent: s.user_agent,
            refresh_replay_verdict: verdict.as_str().to_owned(),
            refresh_replay_at: s.refresh_replay_at.map(|t| t.to_rfc3339()),
            refresh_replay_grace_accepted: s.refresh_replay_grace_accepted,
            refresh_replay_refused: s.refresh_replay_refused,
        }
    }
}

// -------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------

/// `GET /api/v1/users/{user_id}/sessions`
///
/// List the sessions a user currently holds, with the T-254 refresh-replay
/// marker on each.
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}/sessions",
    tag = "users",
    params(
        ("user_id" = Uuid, Path, description = "Target user ID"),
    ),
    responses(
        (status = 200, description = "Session list", body = Vec<SessionResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot view another user's sessions"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer" = []))
)]
pub async fn list_sessions<C: Connection + Clone>(
    caller: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let user_id = path.into_inner();

    // The same gate the sibling `/users/{user_id}/mfa-methods` applies: a
    // principal may always read its own, and reading anybody else's needs
    // `users:admin`.
    if !is_own_resource(&caller, user_id) {
        RequirePermission::new("users:admin", Uuid::nil())
            .check(&caller, authz.get_ref().as_ref())
            .await?;
    }

    let sessions = state
        .session_repo
        .list_by_user(user_scope_tenant(&caller, user_id), user_id)
        .await?;

    // Newest first: an administrator opening this after an alert is looking
    // for what just happened, not for what happened in March.
    let mut sessions: Vec<SessionResponse> = sessions.into_iter().map(Into::into).collect();
    sessions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(HttpResponse::Ok().json(sessions))
}

//! OAuth2 client domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Client {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    /// HMAC-SHA256 hashed client secret.
    pub client_secret_hash: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    /// B5 — allow-list for RP-initiated logout's `post_logout_redirect_uri`.
    ///
    /// Deliberately separate from [`Self::redirect_uris`] rather than a reuse
    /// of it: one list receives an authorization code, the other receives a
    /// browser after a session has ended, and a deployment routinely wants the
    /// second to be a marketing page that must never be a code destination.
    ///
    /// `serde(default)` because rows written before schema v27 have no such
    /// field, and an empty allow-list is the correct reading of a client that
    /// never registered one — it means "no post-logout redirect is permitted",
    /// which is what the endpoint already does for an unrecognised URI.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// B5 — where OIDC Back-Channel Logout tokens are POSTed for this client.
    /// `None` means the client does not participate; it is skipped rather than
    /// retried.
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    /// B5 — refuse a direct authorization request from this client, requiring
    /// it to push its parameters to `/oauth2/par` first (RFC 9126 §5). This is
    /// the per-client switch the FAPI profile turns on.
    #[serde(default)]
    pub require_par: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOAuth2Client {
    pub tenant_id: Uuid,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub require_par: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateOAuth2Client {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
    pub post_logout_redirect_uris: Option<Vec<String>>,
    /// `None` leaves the URI unchanged; `Some("")` clears it.
    ///
    /// The empty string is the sentinel rather than a nested `Option` because
    /// the latter needs a `double_option` serde helper (a new dependency) to
    /// survive a JSON round-trip, and an empty string is not a valid URI so it
    /// cannot collide with a real value. Without *some* way to say "clear it",
    /// a client could be given a back-channel logout URI and never have it
    /// removed — which is the one edit an operator makes when an RP is
    /// decommissioned.
    pub backchannel_logout_uri: Option<String>,
    pub require_par: Option<bool>,
}

/// Represents a stored OAuth2 authorization code (short-lived, single-use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub code_hash: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// OIDC nonce — echoed back in the ID token.
    pub nonce: Option<String>,
    /// B5 — the AXIAM session this code was issued from, carried through to
    /// the token endpoint so the ID token can assert `sid`.
    ///
    /// `Option` because codes predating schema v28 have none, and because the
    /// value is genuinely absent on paths with no browser session behind them.
    #[serde(default)]
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new authorization code.
#[derive(Debug, Clone)]
pub struct CreateAuthorizationCode {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub code_hash: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// OIDC nonce — stored with the code so it can be echoed in the ID token.
    pub nonce: Option<String>,
    /// B5 — the AXIAM session this code was issued from.
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

/// Persisted refresh token (OAuth2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    /// B5 — the AXIAM session this token descends from.
    ///
    /// Carried so that an ID token minted on refresh asserts the *same* `sid`
    /// the RP stored at login. Dropping it on refresh would leave an RP that
    /// only ever sees refreshed ID tokens unable to match a back-channel
    /// logout token to the session it holds.
    #[serde(default)]
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new refresh token.
#[derive(Debug, Clone)]
pub struct CreateRefreshToken {
    pub tenant_id: Uuid,
    pub token_hash: String,
    pub client_id: String,
    pub user_id: Option<Uuid>,
    pub scopes: Vec<String>,
    /// B5 — see [`RefreshToken::session_id`].
    pub session_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Device Authorization Grant (RFC 8628) — B2
// ---------------------------------------------------------------------------

/// Where a device-authorization request has got to.
///
/// The transitions are `Pending → Approved | Denied → Redeemed`, and they are
/// one-way. `Redeemed` exists as a distinct state rather than being modelled by
/// deleting the row, because the difference between "this code was already
/// used" and "this code never existed" is what lets the token endpoint answer
/// a replay with `invalid_grant` instead of silently issuing a second token
/// set for one approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeviceGrantStatus {
    /// Issued; the user has not acted yet. The token endpoint answers
    /// `authorization_pending`.
    Pending,
    /// The user approved. The next token poll redeems it.
    Approved,
    /// The user explicitly refused. Distinct from `Pending` so the device can
    /// stop polling immediately (`access_denied`) rather than waiting out the
    /// expiry.
    Denied,
    /// Already exchanged for tokens. Terminal.
    Redeemed,
}

impl DeviceGrantStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Redeemed => "redeemed",
        }
    }

    /// Parse a stored value. `None` for anything unrecognised — the caller
    /// must fail closed rather than default to a state that grants access.
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "redeemed" => Some(Self::Redeemed),
            _ => None,
        }
    }
}

/// A pending device authorization (RFC 8628 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGrant {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    /// SHA-256 of the device code. The raw code is returned once and never
    /// stored — same posture as refresh tokens and authorization codes.
    pub device_code_hash: String,
    /// The short code the human types. Stored in normalised form (see
    /// `axiam_oauth2::device`), because a user typing `WXYZ-1234` and
    /// `wxyz1234` means the same thing and must not be a lookup miss.
    pub user_code: String,
    pub scopes: Vec<String>,
    pub status: DeviceGrantStatus,
    /// The user who approved. `None` while pending or denied.
    pub user_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    /// Minimum seconds the device must wait between polls (RFC 8628 §3.5).
    /// Raised by `slow_down`.
    pub interval_secs: u64,
    /// When the device last polled, for interval enforcement.
    pub last_polled_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a device grant.
#[derive(Debug, Clone)]
pub struct CreateDeviceGrant {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub device_code_hash: String,
    pub user_code: String,
    pub scopes: Vec<String>,
    pub expires_at: DateTime<Utc>,
    pub interval_secs: u64,
}

/// A pushed authorization request (RFC 9126, B5).
///
/// The client POSTs its authorization parameters to `/oauth2/par` — where it
/// authenticates — and receives an opaque `request_uri` to hand to the
/// browser in place of them. The parameters never travel through the user
/// agent, so they cannot be tampered with in transit or logged by anything
/// between the browser and AXIAM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushedAuthRequest {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    /// SHA-256 of the `request_uri`'s random component. The plaintext is a
    /// bearer credential for the 60 s it lives, so it is never stored — the
    /// same posture as device codes and refresh tokens.
    pub request_uri_hash: String,
    /// The pushed authorization parameters, verbatim.
    pub params: PushedAuthParams,
    /// Set on first use. The row is marked rather than deleted so that
    /// "already used" and "never existed" stay distinguishable in an audit
    /// trail, even though both answer `invalid_request` on the wire.
    pub consumed: bool,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// The authorization parameters carried by a pushed request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PushedAuthParams {
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// Input for creating a pushed authorization request.
#[derive(Debug, Clone)]
pub struct CreatePushedAuthRequest {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub request_uri_hash: String,
    pub params: PushedAuthParams,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Session/client participation — back-channel logout (B5)
// ---------------------------------------------------------------------------

/// A record that `client_id` participated in `session_id`.
///
/// Written when an authorization code is issued, which is the moment a client
/// actually joins the session. Back-channel logout iterates these rather than
/// every client in the tenant: broadcasting to clients that were never part of
/// the session would tell them a session they had no involvement in just
/// ended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClient {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Input for recording participation.
#[derive(Debug, Clone)]
pub struct CreateSessionClient {
    pub tenant_id: Uuid,
    pub session_id: Uuid,
    pub client_id: String,
    pub user_id: Uuid,
}

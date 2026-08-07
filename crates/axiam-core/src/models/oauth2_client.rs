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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateOAuth2Client {
    pub name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
    pub grant_types: Option<Vec<String>>,
    pub scopes: Option<Vec<String>>,
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

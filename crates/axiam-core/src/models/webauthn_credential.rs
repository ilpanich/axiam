//! WebAuthn credential domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Type of WebAuthn authenticator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum WebauthnCredentialType {
    /// Discoverable / platform authenticator
    /// (1Password, Bitwarden, iCloud Keychain, Android).
    Passkey,
    /// Roaming / cross-platform authenticator (YubiKey, NitroKey).
    SecurityKey,
}

impl WebauthnCredentialType {
    /// Stable string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Passkey => "Passkey",
            Self::SecurityKey => "SecurityKey",
        }
    }
}

/// A registered WebAuthn credential for a user.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct WebauthnCredential {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    /// Base64url-encoded credential ID from the authenticator.
    pub credential_id: String,
    /// User-assigned friendly name (e.g., "My YubiKey", "iCloud Passkey").
    pub name: String,
    pub credential_type: WebauthnCredentialType,
    /// JSON-serialized `webauthn_rs::prelude::Passkey`, AES-256-GCM
    /// encrypted.
    pub passkey_json: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,

    // -----------------------------------------------------------------
    // Attestation metadata (D6, X3) — additive, no migration. All four
    // fields are `#[serde(default)]` so rows written before X3 shipped
    // deserialize unchanged (absent JSON keys -> `None`/`false`).
    // -----------------------------------------------------------------
    /// The authenticator's AAGUID, when the registration ceremony resolved
    /// one. `None` for credentials registered before X3, and for
    /// authenticators that legitimately report no AAGUID.
    #[serde(default)]
    pub aaguid: Option<Uuid>,
    /// The WebAuthn attestation statement format (`"packed"`, `"none"`,
    /// `"tpm"`, …) recorded at registration time.
    #[serde(default)]
    pub attestation_format: Option<String>,
    /// `true` if this credential was registered through the attested
    /// ceremony (`finish_attested_passkey_registration`) and passed the
    /// tenant's attestation policy at the time. `false` for every
    /// credential registered under `mode: none` (today's default) or
    /// before X3 shipped.
    #[serde(default)]
    pub attested: bool,
    /// The MDS `metadataStatement.description` friendly name captured at
    /// registration time (e.g. "YubiKey 5 NFC"), for display in credential
    /// lists. `None` when MDS had no entry for the AAGUID, or attestation
    /// was not requested.
    #[serde(default)]
    pub authenticator_name: Option<String>,
}

/// Input for creating a new WebAuthn credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWebauthnCredential {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub credential_id: String,
    pub name: String,
    pub credential_type: WebauthnCredentialType,
    /// JSON-serialized and encrypted passkey data.
    pub passkey_json: String,

    /// See [`WebauthnCredential::aaguid`] (D6). `#[serde(default)]` so
    /// existing callers that construct this via JSON without the new
    /// fields keep working.
    #[serde(default)]
    pub aaguid: Option<Uuid>,
    /// See [`WebauthnCredential::attestation_format`].
    #[serde(default)]
    pub attestation_format: Option<String>,
    /// See [`WebauthnCredential::attested`].
    #[serde(default)]
    pub attested: bool,
    /// See [`WebauthnCredential::authenticator_name`].
    #[serde(default)]
    pub authenticator_name: Option<String>,
}

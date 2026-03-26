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
}

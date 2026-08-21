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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_type_strings_are_the_stored_representation() {
        // These strings are persisted, so changing one silently orphans every
        // row already written with the old value.
        assert_eq!(WebauthnCredentialType::Passkey.as_str(), "Passkey");
        assert_eq!(WebauthnCredentialType::SecurityKey.as_str(), "SecurityKey");
    }

    #[test]
    fn credential_type_round_trips_through_serde() {
        for kind in [
            WebauthnCredentialType::Passkey,
            WebauthnCredentialType::SecurityKey,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
            let back: WebauthnCredentialType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn a_pre_x3_row_without_the_attestation_fields_still_deserializes() {
        // The stated reason those four fields carry `#[serde(default)]`: rows
        // written before X3 shipped must load unchanged. Without this test the
        // claim is a comment, and dropping a `#[serde(default)]` would fail
        // only at runtime against real stored data.
        let json = serde_json::json!({
            "id": Uuid::nil(),
            "tenant_id": Uuid::nil(),
            "user_id": Uuid::nil(),
            "credential_id": "Y3JlZA",
            "name": "My YubiKey",
            "credential_type": "SecurityKey",
            "passkey_json": "{}",
            "created_at": "2026-01-01T00:00:00Z",
            "last_used_at": null
        });
        let cred: WebauthnCredential = serde_json::from_value(json).unwrap();
        assert_eq!(cred.aaguid, None);
        assert_eq!(cred.attestation_format, None);
        assert!(
            !cred.attested,
            "an un-attested legacy row must not read as attested"
        );
        assert_eq!(cred.authenticator_name, None);
    }

    #[test]
    fn a_create_input_without_the_attestation_fields_still_deserializes() {
        let json = serde_json::json!({
            "tenant_id": Uuid::nil(),
            "user_id": Uuid::nil(),
            "credential_id": "Y3JlZA",
            "name": "iCloud Passkey",
            "credential_type": "Passkey",
            "passkey_json": "{}"
        });
        let input: CreateWebauthnCredential = serde_json::from_value(json).unwrap();
        assert!(!input.attested);
        assert_eq!(input.aaguid, None);
    }
}

//! Unified MFA method view model.
//!
//! Provides a single type that represents any registered MFA method
//! (TOTP, passkey, or hardware security key) without exposing secrets.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Type of MFA method.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub enum MfaMethodType {
    Totp,
    Passkey,
    SecurityKey,
}

/// A registered MFA method — unified view across TOTP and WebAuthn.
///
/// No secrets are exposed; this is safe to return in API responses.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MfaMethod {
    /// `"totp"` for TOTP, or a UUID string for WebAuthn credentials.
    pub method_id: String,
    pub method_type: MfaMethodType,
    /// Human-readable name (e.g. "TOTP Authenticator", "My YubiKey").
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

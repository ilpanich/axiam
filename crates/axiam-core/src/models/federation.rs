//! Federation configuration domain model.
//!
//! Supports external OIDC identity providers (including social login)
//! and SAML service provider integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum FederationProtocol {
    OidcConnect,
    Saml,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// Display name for the identity provider (e.g., `Google`, `Okta`).
    pub provider: String,
    pub protocol: FederationProtocol,
    /// OIDC discovery URL or SAML metadata URL.
    pub metadata_url: Option<String>,
    pub client_id: String,
    /// Legacy plaintext client secret (kept for back-compat; nulled by plan 04-02 backfill).
    pub client_secret: String,
    /// Maps external IdP attributes to AXIAM user fields.
    pub attribute_map: serde_json::Value,
    pub enabled: bool,
    // ------------------------------------------------------------------
    // Phase 4 additions (D-10 / D-11)
    // ------------------------------------------------------------------
    /// JWT signing algorithms accepted from this IdP's ID tokens.
    ///
    /// Default: `["RS256"]` for OIDC configs; empty for SAML configs.
    pub allowed_algorithms: Vec<String>,
    /// PEM-encoded X.509 certificate used to verify this IdP's SAML assertions
    /// or fallback OIDC signatures (when JWKS is unavailable).
    pub idp_signing_cert_pem: Option<String>,
    /// AES-256-GCM ciphertext of the OAuth2 client secret (base64, no nonce prefix).
    /// Stored separately from `client_secret_nonce` — see `axiam_auth::crypto::encrypt_separate`.
    pub client_secret_ciphertext: Option<String>,
    /// Base64-encoded 12-byte AES-256-GCM nonce corresponding to `client_secret_ciphertext`.
    pub client_secret_nonce: Option<String>,
    /// Key version used when encrypting `client_secret_ciphertext`.
    /// Enables key rotation without re-encrypting all secrets at once.
    pub client_secret_key_version: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFederationConfig {
    pub tenant_id: Uuid,
    pub provider: String,
    pub protocol: FederationProtocol,
    pub metadata_url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub attribute_map: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateFederationConfig {
    pub provider: Option<String>,
    pub metadata_url: Option<Option<String>>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub attribute_map: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}

/// Tracks the link between an AXIAM user and their external IdP identity.
///
/// Each link binds a local user to an external subject identifier (the `sub`
/// claim from the external OIDC provider), scoped to a specific federation
/// configuration within a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationLink {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub federation_config_id: Uuid,
    /// The `sub` claim from the external IdP's ID token.
    pub external_subject: String,
    /// The email claim from the external IdP, if available.
    pub external_email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFederationLink {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub federation_config_id: Uuid,
    pub external_subject: String,
    pub external_email: Option<String>,
}

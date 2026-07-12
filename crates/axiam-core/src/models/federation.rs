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

#[derive(Clone, Serialize, Deserialize)]
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
    #[serde(skip_serializing)]
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
    #[serde(skip_serializing)]
    pub client_secret_ciphertext: Option<String>,
    /// Base64-encoded 12-byte AES-256-GCM nonce corresponding to `client_secret_ciphertext`.
    #[serde(skip_serializing)]
    pub client_secret_nonce: Option<String>,
    /// Key version used when encrypting `client_secret_ciphertext`.
    /// Enables key rotation without re-encrypting all secrets at once.
    #[serde(skip_serializing)]
    pub client_secret_key_version: Option<i64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Manual `Debug` impl (SECHRD-09 / D-06): redacts the four secret-bearing
/// fields so `{:?}` never prints the plaintext or encrypted client secret,
/// while keeping all other fields human-readable for logs/traces.
impl std::fmt::Debug for FederationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederationConfig")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("provider", &self.provider)
            .field("protocol", &self.protocol)
            .field("metadata_url", &self.metadata_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("attribute_map", &self.attribute_map)
            .field("enabled", &self.enabled)
            .field("allowed_algorithms", &self.allowed_algorithms)
            .field("idp_signing_cert_pem", &self.idp_signing_cert_pem)
            .field("client_secret_ciphertext", &"[REDACTED]")
            .field("client_secret_nonce", &"[REDACTED]")
            .field("client_secret_key_version", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
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
    /// PEM-encoded X.509 cert used to verify SAML assertions (CQ-B40/REQ-14 AC-5).
    pub idp_signing_cert_pem: Option<String>,
    /// JWT signing algorithms accepted from this IdP (CQ-B40/REQ-14 AC-5).
    pub allowed_algorithms: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateFederationConfig {
    pub provider: Option<String>,
    pub metadata_url: Option<Option<String>>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub attribute_map: Option<serde_json::Value>,
    pub enabled: Option<bool>,
    /// PEM-encoded X.509 cert used to verify SAML assertions (CQ-B40/REQ-14 AC-5).
    pub idp_signing_cert_pem: Option<Option<String>>,
    /// JWT signing algorithms accepted from this IdP (CQ-B40/REQ-14 AC-5).
    pub allowed_algorithms: Option<Vec<String>>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::certificate::{CaCertificate, CertificateStatus, KeyAlgorithm};

    /// SECHRD-09 / D-06 / SC #4b: neither the serialized JSON nor the Debug
    /// output of a `FederationConfig` may contain a plaintext or encrypted
    /// secret substring — proves `skip_serializing` + the manual redacting
    /// `Debug` impl actually close the leak (not just compile).
    #[test]
    fn federation_config_secret_not_serialized() {
        const PLAINTEXT_SECRET: &str = "super-secret-oauth-client-value-do-not-leak";
        const CIPHERTEXT: &str = "cGxhY2Vob2xkZXItY2lwaGVydGV4dC1kby1ub3QtbGVhaw==";
        const NONCE: &str = "bm9uY2UtZG8tbm90LWxlYWs=";

        let config = FederationConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: "Okta".to_string(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some("https://example.com/.well-known/openid-configuration".into()),
            client_id: "client-123".to_string(),
            client_secret: PLAINTEXT_SECRET.to_string(),
            attribute_map: serde_json::json!({}),
            enabled: true,
            allowed_algorithms: vec!["RS256".to_string()],
            idp_signing_cert_pem: None,
            client_secret_ciphertext: Some(CIPHERTEXT.to_string()),
            client_secret_nonce: Some(NONCE.to_string()),
            client_secret_key_version: Some(1),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&config).expect("serialization must succeed");
        assert!(
            !json.contains(PLAINTEXT_SECRET),
            "serialized JSON must not contain the plaintext client secret"
        );
        assert!(
            !json.contains(CIPHERTEXT),
            "serialized JSON must not contain the encrypted client secret ciphertext"
        );
        assert!(
            !json.contains(NONCE),
            "serialized JSON must not contain the client secret nonce"
        );

        let debug_output = format!("{config:?}");
        assert!(
            !debug_output.contains(PLAINTEXT_SECRET),
            "Debug output must not contain the plaintext client secret"
        );
        assert!(
            !debug_output.contains(CIPHERTEXT),
            "Debug output must not contain the encrypted client secret ciphertext"
        );
        assert!(
            !debug_output.contains(NONCE),
            "Debug output must not contain the client secret nonce"
        );
    }

    /// Companion assertion (SECHRD-09 / D-06): `CaCertificate`'s manual
    /// `Debug` impl redacts `encrypted_private_key`, closing the residual
    /// leak that `#[serde(skip_serializing)]` alone (Serialize-only) missed.
    #[test]
    fn ca_certificate_debug_redacts_private_key() {
        const KEY_MARKER: &[u8] = b"do-not-leak-private-key-bytes";

        let cert = CaCertificate {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            subject: "CN=Test Root CA".to_string(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                .to_string(),
            fingerprint: "aa:bb:cc".to_string(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now(),
            not_after: Utc::now(),
            status: CertificateStatus::Active,
            encrypted_private_key: Some(KEY_MARKER.to_vec()),
            created_at: Utc::now(),
        };

        let debug_output = format!("{cert:?}");
        assert!(
            !debug_output.contains("do-not-leak-private-key-bytes"),
            "Debug output must not contain the encrypted private key bytes"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output must show a redaction marker for encrypted_private_key"
        );
    }
}

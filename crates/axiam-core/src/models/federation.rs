//! Federation configuration domain model.
//!
//! Supports external OIDC identity providers (including social login)
//! and SAML service provider integration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    /// Encrypted client secret.
    pub client_secret: String,
    /// Maps external IdP attributes to AXIAM user fields.
    pub attribute_map: serde_json::Value,
    pub enabled: bool,
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

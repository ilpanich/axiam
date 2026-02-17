//! Federation configuration domain model.

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
    pub provider: String,
    pub protocol: FederationProtocol,
    pub metadata_url: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub attribute_map: serde_json::Value,
    pub enabled: bool,
}

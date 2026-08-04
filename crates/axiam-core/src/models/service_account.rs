//! Service account domain model.
//!
//! Service accounts are used for machine-to-machine authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::user::UserStatus;

/// Prefix on every service-account `client_id`.
///
/// Defined here — beside the model — because **two** places depend on it and
/// they must never drift: `axiam-db` generates ids with it, and the OAuth2
/// client-credentials handler uses it to decide which table to look a
/// `client_id` up in. It is disjoint from the `oauth2_client` prefix (`oa_`),
/// which is what makes that dispatch unambiguous.
pub const SERVICE_ACCOUNT_CLIENT_ID_PREFIX: &str = "sa_";

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ServiceAccount {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    /// Optional human-readable description of the account's purpose.
    pub description: Option<String>,
    pub client_id: String,
    /// HMAC-SHA256 hashed client secret.
    pub client_secret_hash: String,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateServiceAccount {
    pub tenant_id: Uuid,
    pub name: String,
    /// Optional human-readable description of the account's purpose.
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateServiceAccount {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<UserStatus>,
}

//! Organization domain model.
//!
//! Organizations are the top-level entity in AXIAM's multi-tenancy hierarchy.
//! They contain tenants and hold CA certificates for signing tenant certificates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// An organization groups multiple tenants under a single administrative entity.
///
/// Organizations represent companies, departments, or business units.
/// CA certificates are registered at the organization level, enabling
/// a hierarchical trust model across all tenants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// URL-safe unique identifier (e.g., `acme-corp`).
    pub slug: String,
    /// Arbitrary key-value metadata.
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Fields required to create a new organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrganization {
    pub name: String,
    pub slug: String,
    pub metadata: Option<serde_json::Value>,
}

/// Fields that can be updated on an existing organization.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateOrganization {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

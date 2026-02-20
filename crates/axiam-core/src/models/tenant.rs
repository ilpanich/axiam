//! Tenant domain model.
//!
//! Tenants provide full data isolation within an organization.
//! All domain entities (users, roles, resources, etc.) are scoped to a tenant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A tenant is an isolated context within an organization.
///
/// Each tenant has its own set of users, roles, permissions, resources,
/// certificates, and configuration. Tenants can represent environments
/// (dev/staging/prod) or separate business contexts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub id: Uuid,
    /// The organization this tenant belongs to.
    pub organization_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// URL-safe unique identifier within the organization (e.g., `production`).
    pub slug: String,
    /// Arbitrary key-value metadata.
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Fields required to create a new tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTenant {
    pub organization_id: Uuid,
    pub name: String,
    pub slug: String,
    pub metadata: Option<serde_json::Value>,
}

/// Fields that can be updated on an existing tenant.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateTenant {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

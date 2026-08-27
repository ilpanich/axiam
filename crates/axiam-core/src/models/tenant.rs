//! Tenant domain model.
//!
//! Tenants provide full data isolation within an organization.
//! All domain entities (users, roles, resources, etc.) are scoped to a tenant.
//!
//! Exactly one tenant per organization is reserved: the **organization
//! tenant**, flagged [`TenantKind::Organization`]. It is where
//! organization-level users, groups, roles and service accounts live — the
//! principals whose grants apply to every tenant in the organization rather
//! than to one. See `claude_dev/organization-scope-design.md` for why an
//! organization scope is modelled as a tenant rather than as an
//! `Option<Uuid>` on every scoped entity.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Lifecycle status of a tenant.
///
/// A `Suspended` tenant remains stored and its data isolated, but is treated as
/// administratively disabled. New tenants are `Active` by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub enum TenantStatus {
    /// The tenant is operational.
    #[default]
    Active,
    /// The tenant is administratively disabled.
    Suspended,
}

/// What a tenant *is*, as distinct from what state it is in.
///
/// Reserved rather than inferred: an organization has exactly one tenant of
/// kind [`Self::Organization`], enforced by a unique index rather than by
/// convention. Deriving it from a magic slug or from "the oldest tenant" would
/// make the organization scope something an operator could rename or delete by
/// accident, and it is the scope the super-admin lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TenantKind {
    /// An ordinary tenant: an isolated context holding its own users, roles,
    /// resources and certificates. What every tenant was before organization
    /// scope existed, and therefore the default — so every row written by an
    /// older version reads back as exactly what it is.
    #[default]
    Standard,
    /// The organization's own scope, one per organization.
    ///
    /// Holds the principals that operate across every tenant in the
    /// organization. Its grants are evaluated against other tenants under one
    /// added rule — only *global* grants cross a tenant boundary — which is
    /// stated once, in the authorization engine.
    ///
    /// Created with the organization and not by hand: `POST .../tenants`
    /// refuses to create a second one, and deleting it would strand every
    /// organization-level principal in it.
    Organization,
}

impl TenantKind {
    /// Whether this is the organization's own scope.
    pub const fn is_organization(self) -> bool {
        matches!(self, Self::Organization)
    }
}

impl std::fmt::Display for TenantKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Standard => write!(f, "standard"),
            Self::Organization => write!(f, "organization"),
        }
    }
}

/// The slug given to an organization tenant when it is created.
///
/// Slugs are unique per organization, so this is a reserved name: creating an
/// ordinary tenant with it is refused. Fixed rather than derived from the
/// organization's own slug because it appears in login URLs and operator
/// muscle memory, and it should read the same in every deployment.
pub const ORGANIZATION_TENANT_SLUG: &str = "organization";

/// A tenant is an isolated context within an organization.
///
/// Each tenant has its own set of users, roles, permissions, resources,
/// certificates, and configuration. Tenants can represent environments
/// (dev/staging/prod) or separate business contexts.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Tenant {
    pub id: Uuid,
    /// The organization this tenant belongs to.
    pub organization_id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// URL-safe unique identifier within the organization (e.g., `production`).
    pub slug: String,
    /// Lifecycle status. New tenants default to [`TenantStatus::Active`].
    pub status: TenantStatus,
    /// Whether this is an ordinary tenant or the organization's own scope.
    ///
    /// `#[serde(default)]` so every row written before organization scope
    /// existed reads back as [`TenantKind::Standard`], which is what it is.
    #[serde(default)]
    pub kind: TenantKind,
    /// Arbitrary key-value metadata.
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    /// Whether this tenant is the organization's own scope.
    ///
    /// The question asked on the authorization path — a principal whose home
    /// tenant answers `true` is an organization-level principal — so it is a
    /// method rather than a field comparison spelled out at each call site.
    pub const fn is_organization_scope(&self) -> bool {
        self.kind.is_organization()
    }
}

/// Fields required to create a new tenant.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateTenant {
    pub organization_id: Uuid,
    pub name: String,
    pub slug: String,
    /// What kind of tenant to create.
    ///
    /// Not part of the public create request: the REST layer always sends
    /// [`TenantKind::Standard`], and the organization tenant is created
    /// alongside its organization. An API that let a caller ask for a second
    /// organization scope would be an API whose refusal is the interesting
    /// case.
    #[serde(default, skip_deserializing)]
    pub kind: TenantKind,
    pub metadata: Option<serde_json::Value>,
}

impl CreateTenant {
    /// The organization tenant for `organization_id`.
    ///
    /// One constructor rather than three call sites setting `kind` by hand —
    /// bootstrap, the migration that backfills existing organizations, and
    /// organization creation must all produce the same row, and a tenant that
    /// is *nearly* the organization scope is one that the unique index will
    /// reject at the worst possible moment.
    pub fn organization_scope(organization_id: Uuid) -> Self {
        Self {
            organization_id,
            name: "Organization".to_string(),
            slug: ORGANIZATION_TENANT_SLUG.to_string(),
            kind: TenantKind::Organization,
            metadata: None,
        }
    }
}

/// Fields that can be updated on an existing tenant.
#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateTenant {
    pub name: Option<String>,
    pub slug: Option<String>,
    /// Change the tenant's lifecycle status (e.g. suspend/reactivate).
    pub status: Option<TenantStatus>,
    pub metadata: Option<serde_json::Value>,
}

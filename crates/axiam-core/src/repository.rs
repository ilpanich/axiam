//! Repository trait definitions for data access abstraction.
//!
//! All repository operations are async. Tenant-scoped repositories
//! require a `tenant_id` parameter to enforce data isolation.

use uuid::Uuid;

use crate::error::AxiamResult;
use crate::models::{
    audit::{AuditLogEntry, CreateAuditLogEntry},
    certificate::{CaCertificate, Certificate, CreateCaCertificate, CreateCertificate},
    federation::{CreateFederationConfig, FederationConfig, UpdateFederationConfig},
    group::{CreateGroup, Group, UpdateGroup},
    oauth2_client::{CreateOAuth2Client, OAuth2Client, UpdateOAuth2Client},
    organization::{CreateOrganization, Organization, UpdateOrganization},
    permission::{CreatePermission, Permission, UpdatePermission},
    resource::{CreateResource, Resource, UpdateResource},
    role::{CreateRole, Role, UpdateRole},
    scope::{CreateScope, Scope, UpdateScope},
    service_account::{CreateServiceAccount, ServiceAccount, UpdateServiceAccount},
    session::{CreateSession, Session},
    tenant::{CreateTenant, Tenant, UpdateTenant},
    user::{CreateUser, UpdateUser, User},
    webhook::{CreateWebhook, UpdateWebhook, Webhook},
};

/// Pagination parameters for list queries.
#[derive(Debug, Clone)]
pub struct Pagination {
    pub offset: u64,
    pub limit: u64,
}

impl Default for Pagination {
    fn default() -> Self {
        Self {
            offset: 0,
            limit: 50,
        }
    }
}

/// A paginated result set.
#[derive(Debug, Clone)]
pub struct PaginatedResult<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub offset: u64,
    pub limit: u64,
}

// ---------------------------------------------------------------------------
// Organization & Tenant (global scope)
// ---------------------------------------------------------------------------

pub trait OrganizationRepository: Send + Sync {
    fn create(
        &self,
        input: CreateOrganization,
    ) -> impl Future<Output = AxiamResult<Organization>> + Send;
    fn get_by_id(&self, id: Uuid) -> impl Future<Output = AxiamResult<Organization>> + Send;
    fn get_by_slug(&self, slug: &str) -> impl Future<Output = AxiamResult<Organization>> + Send;
    fn update(
        &self,
        id: Uuid,
        input: UpdateOrganization,
    ) -> impl Future<Output = AxiamResult<Organization>> + Send;
    fn delete(&self, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Organization>>> + Send;
}

pub trait TenantRepository: Send + Sync {
    fn create(&self, input: CreateTenant) -> impl Future<Output = AxiamResult<Tenant>> + Send;
    fn get_by_id(&self, id: Uuid) -> impl Future<Output = AxiamResult<Tenant>> + Send;
    fn get_by_slug(
        &self,
        organization_id: Uuid,
        slug: &str,
    ) -> impl Future<Output = AxiamResult<Tenant>> + Send;
    fn update(
        &self,
        id: Uuid,
        input: UpdateTenant,
    ) -> impl Future<Output = AxiamResult<Tenant>> + Send;
    fn delete(&self, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list_by_organization(
        &self,
        organization_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Tenant>>> + Send;
}

// ---------------------------------------------------------------------------
// Tenant-scoped repositories
// ---------------------------------------------------------------------------

pub trait UserRepository: Send + Sync {
    fn create(&self, input: CreateUser) -> impl Future<Output = AxiamResult<User>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<User>> + Send;
    fn get_by_username(
        &self,
        tenant_id: Uuid,
        username: &str,
    ) -> impl Future<Output = AxiamResult<User>> + Send;
    fn get_by_email(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> impl Future<Output = AxiamResult<User>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateUser,
    ) -> impl Future<Output = AxiamResult<User>> + Send;
    /// Soft-delete: sets status to Inactive.
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<User>>> + Send;
}

pub trait RoleRepository: Send + Sync {
    fn create(&self, input: CreateRole) -> impl Future<Output = AxiamResult<Role>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Role>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateRole,
    ) -> impl Future<Output = AxiamResult<Role>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Role>>> + Send;

    /// Assign a role to a user, optionally scoped to a resource.
    fn assign_to_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Remove a role assignment from a user.
    fn unassign_from_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Get all roles assigned to a user (direct + via group membership).
    fn get_user_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Role>>> + Send;

    /// Assign a role to a group, optionally scoped to a resource.
    fn assign_to_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Remove a role assignment from a group.
    fn unassign_from_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Get all roles assigned to a group.
    fn get_group_roles(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Role>>> + Send;
}

pub trait PermissionRepository: Send + Sync {
    fn create(
        &self,
        input: CreatePermission,
    ) -> impl Future<Output = AxiamResult<Permission>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Permission>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdatePermission,
    ) -> impl Future<Output = AxiamResult<Permission>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Permission>>> + Send;

    /// Grant a permission to a role (creates a `grants` edge).
    fn grant_to_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Revoke a permission from a role.
    fn revoke_from_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Get all permissions granted to a role.
    fn get_role_permissions(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Permission>>> + Send;
}

pub trait ResourceRepository: Send + Sync {
    fn create(&self, input: CreateResource) -> impl Future<Output = AxiamResult<Resource>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Resource>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateResource,
    ) -> impl Future<Output = AxiamResult<Resource>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Resource>>> + Send;

    /// Get direct children of a resource.
    fn get_children(
        &self,
        tenant_id: Uuid,
        parent_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Resource>>> + Send;

    /// Get all ancestors of a resource (walking up the tree).
    fn get_ancestors(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Resource>>> + Send;
}

pub trait ScopeRepository: Send + Sync {
    fn create(&self, input: CreateScope) -> impl Future<Output = AxiamResult<Scope>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Scope>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateScope,
    ) -> impl Future<Output = AxiamResult<Scope>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list_by_resource(
        &self,
        tenant_id: Uuid,
        resource_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Scope>>> + Send;
}

pub trait ServiceAccountRepository: Send + Sync {
    fn create(
        &self,
        input: CreateServiceAccount,
    ) -> impl Future<Output = AxiamResult<(ServiceAccount, String)>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<ServiceAccount>> + Send;
    fn get_by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> impl Future<Output = AxiamResult<ServiceAccount>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateServiceAccount,
    ) -> impl Future<Output = AxiamResult<ServiceAccount>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<ServiceAccount>>> + Send;
    /// Regenerate client credentials; returns the new raw secret.
    fn rotate_secret(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<String>> + Send;
}

pub trait SessionRepository: Send + Sync {
    fn create(&self, input: CreateSession) -> impl Future<Output = AxiamResult<Session>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Session>> + Send;
    fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<Session>> + Send;
    /// Invalidate a single session.
    fn invalidate(&self, tenant_id: Uuid, id: Uuid)
    -> impl Future<Output = AxiamResult<()>> + Send;
    /// Invalidate all sessions for a user (e.g., on password change).
    fn invalidate_user_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
    /// Remove all expired sessions.
    fn cleanup_expired(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<u64>> + Send;
}

// ---------------------------------------------------------------------------
// Groups (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait GroupRepository: Send + Sync {
    fn create(&self, input: CreateGroup) -> impl Future<Output = AxiamResult<Group>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Group>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateGroup,
    ) -> impl Future<Output = AxiamResult<Group>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Group>>> + Send;

    /// Add a user to a group (creates a `member_of` edge).
    fn add_member(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Remove a user from a group.
    fn remove_member(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        group_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Get all members of a group.
    fn get_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<User>>> + Send;

    /// Get all groups a user belongs to.
    fn get_user_groups(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Group>>> + Send;
}

// ---------------------------------------------------------------------------
// Audit (append-only, tenant-scoped)
// ---------------------------------------------------------------------------

/// Query filters for audit log entries.
#[derive(Debug, Clone, Default)]
pub struct AuditLogFilter {
    pub actor_id: Option<Uuid>,
    pub action: Option<String>,
    pub resource_id: Option<Uuid>,
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
}

pub trait AuditLogRepository: Send + Sync {
    /// Append a new audit log entry. No update or delete operations exist.
    fn append(
        &self,
        input: CreateAuditLogEntry,
    ) -> impl Future<Output = AxiamResult<AuditLogEntry>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<AuditLogEntry>>> + Send;
}

// ---------------------------------------------------------------------------
// OAuth2 & Federation (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait OAuth2ClientRepository: Send + Sync {
    fn create(
        &self,
        input: CreateOAuth2Client,
    ) -> impl Future<Output = AxiamResult<(OAuth2Client, String)>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<OAuth2Client>> + Send;
    fn get_by_client_id(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> impl Future<Output = AxiamResult<OAuth2Client>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateOAuth2Client,
    ) -> impl Future<Output = AxiamResult<OAuth2Client>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<OAuth2Client>>> + Send;
}

pub trait FederationConfigRepository: Send + Sync {
    fn create(
        &self,
        input: CreateFederationConfig,
    ) -> impl Future<Output = AxiamResult<FederationConfig>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<FederationConfig>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateFederationConfig,
    ) -> impl Future<Output = AxiamResult<FederationConfig>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<FederationConfig>>> + Send;
}

// ---------------------------------------------------------------------------
// PKI / Certificates
// ---------------------------------------------------------------------------

pub trait CaCertificateRepository: Send + Sync {
    fn create(
        &self,
        input: CreateCaCertificate,
    ) -> impl Future<Output = AxiamResult<CaCertificate>> + Send;
    fn get_by_id(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<CaCertificate>> + Send;
    fn revoke(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list_by_organization(
        &self,
        organization_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<CaCertificate>>> + Send;
}

pub trait CertificateRepository: Send + Sync {
    fn create(
        &self,
        input: CreateCertificate,
    ) -> impl Future<Output = AxiamResult<Certificate>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Certificate>> + Send;
    fn get_by_fingerprint(
        &self,
        tenant_id: Uuid,
        fingerprint: &str,
    ) -> impl Future<Output = AxiamResult<Certificate>> + Send;
    fn revoke(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Certificate>>> + Send;
}

// ---------------------------------------------------------------------------
// Webhooks (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait WebhookRepository: Send + Sync {
    fn create(&self, input: CreateWebhook) -> impl Future<Output = AxiamResult<Webhook>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Webhook>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateWebhook,
    ) -> impl Future<Output = AxiamResult<Webhook>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Webhook>>> + Send;
    /// Get all enabled webhooks subscribed to a given event type.
    fn get_by_event(
        &self,
        tenant_id: Uuid,
        event_type: &str,
    ) -> impl Future<Output = AxiamResult<Vec<Webhook>>> + Send;
}

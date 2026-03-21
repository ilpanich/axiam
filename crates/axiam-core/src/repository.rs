//! Repository trait definitions for data access abstraction.
//!
//! All repository operations are async. Tenant-scoped repositories
//! require a `tenant_id` parameter to enforce data isolation.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AxiamResult;
use crate::models::{
    audit::{AuditLogEntry, CreateAuditLogEntry},
    certificate::{CaCertificate, Certificate, StoreCaCertificate, StoreCertificate},
    email::{EmailConfig, EmailConfigOverride, SetOrgEmailConfig, SetTenantEmailOverride},
    email_template::{EmailTemplate, SetEmailTemplate, TemplateKind},
    email_verification::{CreateEmailVerificationToken, EmailVerificationToken},
    federation::{
        CreateFederationConfig, CreateFederationLink, FederationConfig, FederationLink,
        UpdateFederationConfig,
    },
    group::{CreateGroup, Group, UpdateGroup},
    notification_rule::{CreateNotificationRule, NotificationRule, UpdateNotificationRule},
    oauth2_client::{
        AuthorizationCode, CreateAuthorizationCode, CreateOAuth2Client, CreateRefreshToken,
        OAuth2Client, RefreshToken, UpdateOAuth2Client,
    },
    organization::{CreateOrganization, Organization, UpdateOrganization},
    password_history::{CreatePasswordHistoryEntry, PasswordHistoryEntry},
    password_reset::{CreatePasswordResetToken, PasswordResetToken},
    permission::{CreatePermission, Permission, PermissionGrant, UpdatePermission},
    pgp_key::{PgpKey, StorePgpKey},
    resource::{CreateResource, Resource, UpdateResource},
    role::{CreateRole, Role, RoleAssignment, UpdateRole},
    scope::{CreateScope, Scope, UpdateScope},
    service_account::{CreateServiceAccount, ServiceAccount, UpdateServiceAccount},
    session::{CreateSession, Session},
    settings::{SecuritySettings, SetOrgSettings, SetTenantOverride, TenantSettingsOverride},
    tenant::{CreateTenant, Tenant, UpdateTenant},
    user::{CreateUser, UpdateUser, User},
    webhook::{CreateWebhook, UpdateWebhook, Webhook},
};

/// Pagination parameters for list queries.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(default)]
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
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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

    /// Get all role assignments for a user (direct + via group membership)
    /// including the resource scope of each assignment.
    fn get_user_role_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<RoleAssignment>>> + Send;

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

    /// Grant a permission to a role with optional scope constraints.
    /// Empty `scope_ids` means the grant covers all scopes (wildcard).
    fn grant_to_role_with_scopes(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
        scope_ids: Vec<Uuid>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Get all permission grants for a role, including scope constraints.
    fn get_role_permission_grants(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<PermissionGrant>>> + Send;
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
#[derive(Debug, Clone, Default, serde::Deserialize, utoipa::IntoParams)]
pub struct AuditLogFilter {
    pub actor_id: Option<Uuid>,
    pub action: Option<String>,
    pub outcome: Option<crate::models::audit::AuditOutcome>,
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
    /// List audit logs scoped to a specific tenant.
    fn list(
        &self,
        tenant_id: Uuid,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<AuditLogEntry>>> + Send;
    /// List audit logs for unauthenticated/system requests (nil tenant_id).
    fn list_system(
        &self,
        filter: AuditLogFilter,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<AuditLogEntry>>> + Send;
    /// Fetch multiple audit log entries by their IDs.
    fn get_by_ids(
        &self,
        tenant_id: Uuid,
        ids: &[Uuid],
    ) -> impl Future<Output = AxiamResult<Vec<AuditLogEntry>>> + Send;
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

pub trait AuthorizationCodeRepository: Send + Sync {
    /// Store a new authorization code.
    fn create(
        &self,
        input: CreateAuthorizationCode,
    ) -> impl Future<Output = AxiamResult<AuthorizationCode>> + Send;

    /// Look up a valid (unused, non-expired) authorization code by hash
    /// without marking it as used.  Use this to validate PKCE before
    /// calling [`consume`].  `client_id` and `redirect_uri` are checked
    /// to prevent code-burning by unrelated clients.
    fn get_by_hash(
        &self,
        tenant_id: Uuid,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> impl Future<Output = AxiamResult<AuthorizationCode>> + Send;

    /// Atomically consume a code (mark as used). Returns the code if it
    /// was valid, unused, and not expired; otherwise returns NotFound.
    /// `client_id` and `redirect_uri` are verified atomically in the
    /// WHERE clause to prevent code-burning attacks.
    fn consume(
        &self,
        tenant_id: Uuid,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> impl Future<Output = AxiamResult<AuthorizationCode>> + Send;

    /// Delete expired and already-used codes (garbage collection).
    fn delete_expired(&self) -> impl Future<Output = AxiamResult<u64>> + Send;
}

pub trait RefreshTokenRepository: Send + Sync {
    /// Store a new refresh token.
    fn create(
        &self,
        input: CreateRefreshToken,
    ) -> impl Future<Output = AxiamResult<RefreshToken>> + Send;

    /// Look up a non-revoked, non-expired refresh token by its hash.
    fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<RefreshToken>> + Send;

    /// Revoke a single refresh token by hash.
    fn revoke(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Revoke all refresh tokens for a given client within a tenant.
    fn revoke_all_for_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Delete expired and revoked refresh tokens (garbage collection).
    fn delete_expired(&self) -> impl Future<Output = AxiamResult<u64>> + Send;
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

pub trait FederationLinkRepository: Send + Sync {
    /// Create a new federation link binding a local user to an external subject.
    fn create(
        &self,
        input: CreateFederationLink,
    ) -> impl Future<Output = AxiamResult<FederationLink>> + Send;

    /// Find a federation link by the external subject identifier.
    fn get_by_external_subject(
        &self,
        tenant_id: Uuid,
        federation_config_id: Uuid,
        external_subject: &str,
    ) -> impl Future<Output = AxiamResult<FederationLink>> + Send;

    /// Get all federation links for a given user.
    fn get_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<FederationLink>>> + Send;

    /// Delete a federation link.
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
}

// ---------------------------------------------------------------------------
// PKI / Certificates
// ---------------------------------------------------------------------------

pub trait CaCertificateRepository: Send + Sync {
    fn create(
        &self,
        input: StoreCaCertificate,
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
        input: StoreCertificate,
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
    fn get_by_fingerprint_global(
        &self,
        fingerprint: &str,
    ) -> impl Future<Output = AxiamResult<Certificate>> + Send;
    fn revoke(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Certificate>>> + Send;
    fn bind_to_service_account(
        &self,
        tenant_id: Uuid,
        cert_id: Uuid,
        sa_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
    fn get_bound_service_account(
        &self,
        cert_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<Uuid>>> + Send;
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

// ---------------------------------------------------------------------------
// Notification Rules (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait NotificationRuleRepository: Send + Sync {
    fn create(
        &self,
        input: CreateNotificationRule,
    ) -> impl Future<Output = AxiamResult<NotificationRule>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<NotificationRule>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateNotificationRule,
    ) -> impl Future<Output = AxiamResult<NotificationRule>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<NotificationRule>>> + Send;
    /// Get all enabled rules subscribed to a given event type.
    fn get_by_event(
        &self,
        tenant_id: Uuid,
        event_type: &str,
    ) -> impl Future<Output = AxiamResult<Vec<NotificationRule>>> + Send;

    /// Get all enabled rules matching any of the given event types.
    ///
    /// This is the batched variant of [`get_by_event`] — it issues a
    /// single query instead of one per event type, avoiding N+1.
    fn get_by_events(
        &self,
        tenant_id: Uuid,
        event_types: &[String],
    ) -> impl Future<Output = AxiamResult<Vec<NotificationRule>>> + Send;
}

// ---------------------------------------------------------------------------
// PGP Keys (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait PgpKeyRepository: Send + Sync {
    fn create(&self, input: StorePgpKey) -> impl Future<Output = AxiamResult<PgpKey>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<PgpKey>> + Send;
    /// Returns the active AuditSigning key for a tenant.
    fn get_signing_key(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<PgpKey>> + Send;
    fn revoke(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<PgpKey>>> + Send;
}

// ---------------------------------------------------------------------------
// Password History (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait PasswordHistoryRepository: Send + Sync {
    /// Store a new password hash in history.
    fn create(
        &self,
        input: CreatePasswordHistoryEntry,
    ) -> impl Future<Output = AxiamResult<PasswordHistoryEntry>> + Send;

    /// Get the last N password hashes for a user (most recent first).
    fn get_recent(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        count: u32,
    ) -> impl Future<Output = AxiamResult<Vec<PasswordHistoryEntry>>> + Send;

    /// Prune old history entries, keeping only the most recent `keep_count`.
    fn prune(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        keep_count: u32,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;
}

// ---------------------------------------------------------------------------
// Security Settings (org/tenant scope)
// ---------------------------------------------------------------------------

pub trait SettingsRepository: Send + Sync {
    /// Get organization-level settings (returns system defaults if none set).
    fn get_org_settings(
        &self,
        org_id: Uuid,
    ) -> impl Future<Output = AxiamResult<SecuritySettings>> + Send;

    /// Set (create or replace) organization-level settings.
    fn set_org_settings(
        &self,
        org_id: Uuid,
        input: SetOrgSettings,
    ) -> impl Future<Output = AxiamResult<SecuritySettings>> + Send;

    /// Get tenant-level overrides (only fields that differ from org).
    fn get_tenant_override(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<TenantSettingsOverride>>> + Send;

    /// Set tenant-level overrides.
    fn set_tenant_override(
        &self,
        tenant_id: Uuid,
        input: SetTenantOverride,
    ) -> impl Future<Output = AxiamResult<TenantSettingsOverride>> + Send;

    /// Store a fully merged, pre-validated tenant settings row.
    ///
    /// Used by the API layer after performing inheritance validation.
    /// The caller is responsible for merging org baseline + overrides
    /// and validating constraints before calling this method.
    fn store_effective_tenant_settings(
        &self,
        tenant_id: Uuid,
        settings: SecuritySettings,
    ) -> impl Future<Output = AxiamResult<SecuritySettings>> + Send;

    /// Delete all tenant-level overrides (revert to org baseline).
    fn delete_tenant_override(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Get the effective (merged) settings for a tenant.
    fn get_effective_settings(
        &self,
        org_id: Uuid,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<SecuritySettings>> + Send;
}

// ---------------------------------------------------------------------------
// Email Configuration (org/tenant scope)
// ---------------------------------------------------------------------------

pub trait EmailConfigRepository: Send + Sync {
    /// Get org-level email config (returns None if not configured).
    fn get_org_config(
        &self,
        org_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<EmailConfig>>> + Send;

    /// Set (create or replace) org-level email config.
    fn set_org_config(
        &self,
        org_id: Uuid,
        input: SetOrgEmailConfig,
    ) -> impl Future<Output = AxiamResult<EmailConfig>> + Send;

    /// Get tenant-level overrides.
    fn get_tenant_override(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<EmailConfigOverride>>> + Send;

    /// Set tenant-level overrides.
    fn set_tenant_override(
        &self,
        tenant_id: Uuid,
        input: SetTenantEmailOverride,
    ) -> impl Future<Output = AxiamResult<EmailConfigOverride>> + Send;

    /// Delete all tenant-level overrides (revert to org config).
    fn delete_tenant_override(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Get the effective (merged) email config for a tenant.
    fn get_effective_config(
        &self,
        org_id: Uuid,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<EmailConfig>>> + Send;
}

// ---------------------------------------------------------------------------
// Email Templates (org/tenant scope)
// ---------------------------------------------------------------------------

pub trait EmailTemplateRepository: Send + Sync {
    /// Get a custom template by kind at org level.
    fn get_org_template(
        &self,
        org_id: Uuid,
        kind: TemplateKind,
    ) -> impl Future<Output = AxiamResult<Option<EmailTemplate>>> + Send;

    /// Set (create or replace) an org-level custom template.
    fn set_org_template(
        &self,
        org_id: Uuid,
        input: SetEmailTemplate,
    ) -> impl Future<Output = AxiamResult<EmailTemplate>> + Send;

    /// Delete an org-level custom template (revert to built-in).
    fn delete_org_template(
        &self,
        org_id: Uuid,
        kind: TemplateKind,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// List all custom templates for an org.
    fn list_org_templates(
        &self,
        org_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<EmailTemplate>>> + Send;

    /// Get a custom template by kind at tenant level.
    fn get_tenant_template(
        &self,
        tenant_id: Uuid,
        kind: TemplateKind,
    ) -> impl Future<Output = AxiamResult<Option<EmailTemplate>>> + Send;

    /// Set (create or replace) a tenant-level custom template.
    fn set_tenant_template(
        &self,
        tenant_id: Uuid,
        input: SetEmailTemplate,
    ) -> impl Future<Output = AxiamResult<EmailTemplate>> + Send;

    /// Delete a tenant-level custom template (revert to org/built-in).
    fn delete_tenant_template(
        &self,
        tenant_id: Uuid,
        kind: TemplateKind,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// List all custom templates for a tenant.
    fn list_tenant_templates(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<EmailTemplate>>> + Send;
}

// ---------------------------------------------------------------------------
// Email Verification Tokens (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait EmailVerificationTokenRepository: Send + Sync {
    /// Store a new verification token.
    fn create(
        &self,
        input: CreateEmailVerificationToken,
    ) -> impl Future<Output = AxiamResult<EmailVerificationToken>> + Send;

    /// Look up a valid (unconsumed, non-expired) token by hash.
    fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<EmailVerificationToken>> + Send;

    /// Atomically consume a token (set consumed_at). Returns error if
    /// already consumed or expired.
    fn consume(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<EmailVerificationToken>> + Send;

    /// Count tokens created for a user today (for resend rate limiting).
    fn count_today(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;

    /// Delete expired and consumed tokens (garbage collection).
    fn delete_expired(&self) -> impl Future<Output = AxiamResult<u64>> + Send;
}

// ---------------------------------------------------------------------------
// Password Reset Tokens (tenant-scoped)
// ---------------------------------------------------------------------------

pub trait PasswordResetTokenRepository: Send + Sync {
    /// Store a new password reset token.
    fn create(
        &self,
        input: CreatePasswordResetToken,
    ) -> impl Future<Output = AxiamResult<PasswordResetToken>> + Send;

    /// Look up a valid (unconsumed, non-expired) token by hash.
    fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<PasswordResetToken>> + Send;

    /// Atomically consume a token (set consumed_at). Returns error if
    /// already consumed or expired.
    fn consume(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<PasswordResetToken>> + Send;

    /// Count tokens created for a user today (for rate limiting).
    fn count_today(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;

    /// Delete expired and consumed tokens (garbage collection).
    fn delete_expired(&self) -> impl Future<Output = AxiamResult<u64>> + Send;

    /// Invalidate unconsumed tokens for a user (mark as consumed so
    /// they cannot be used, while preserving rate-limit counters).
    fn delete_unconsumed_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;
}

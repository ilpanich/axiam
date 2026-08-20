//! Repository trait definitions for data access abstraction.
//!
//! All repository operations are async. Tenant-scoped repositories
//! require a `tenant_id` parameter to enforce data isolation.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::error::AxiamResult;
use crate::models::mail::OutboundMailMessage;
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
    gdpr::{
        AccountDeletion, Consent, CreateAccountDeletion, CreateConsent, CreateErasureProof,
        CreateExportJob, ErasureProof, ExportJob,
    },
    group::{CreateGroup, Group, UpdateGroup},
    mds::{MdsBlobMeta, MdsEntry},
    notification_rule::{CreateNotificationRule, NotificationRule, UpdateNotificationRule},
    oauth2_client::{
        AuthorizationCode, CreateAuthorizationCode, CreateDeviceGrant, CreateOAuth2Client,
        CreatePushedAuthRequest, CreateRefreshToken, CreateSessionClient, DeviceGrant,
        OAuth2Client, PushedAuthRequest, RefreshToken, SessionClient, UpdateOAuth2Client,
    },
    organization::{CreateOrganization, Organization, UpdateOrganization},
    password_history::{CreatePasswordHistoryEntry, PasswordHistoryEntry},
    password_reset::{CreatePasswordResetToken, PasswordResetToken},
    permission::{
        CreatePermission, Permission, PermissionEffect, PermissionGrant, UpdatePermission,
    },
    pgp_key::{PgpKey, StorePgpKey},
    reactor::{CreateReactor, Reactor, UpdateReactor},
    resource::{CreateResource, Resource, UpdateResource},
    role::{CreateRole, Role, RoleAssignment, UpdateRole},
    scim_token::{CreateScimToken, ScimToken},
    scope::{CreateScope, Scope, UpdateScope},
    service_account::{CreateServiceAccount, ServiceAccount, UpdateServiceAccount},
    session::{CreateSession, Session},
    settings::{SecuritySettings, SetOrgSettings, SetTenantOverride, TenantSettingsOverride},
    srp::{CreateSrpCredential, SrpCredential},
    tenant::{CreateTenant, Tenant, UpdateTenant},
    uma::{CreatePermissionTicket, PermissionTicket},
    user::{CreateUser, UpdateUser, User},
    webauthn_credential::{CreateWebauthnCredential, WebauthnCredential},
    webauthn_policy::WebauthnAttestationPolicy,
    webhook::{CreateWebhook, UpdateWebhook, Webhook},
};

/// Clamp a pagination limit to [1, 200] at deserialization time.
///
/// Prevents resource exhaustion from unbounded page requests (SEC-010/CQ-B30).
/// Direct struct construction is unaffected — only the serde path clamps.
fn clamp_pagination_limit<'de, D>(de: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = u64::deserialize(de)?;
    Ok(raw.clamp(1, 200))
}

/// Pagination parameters for list queries.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema, utoipa::IntoParams)]
#[serde(default)]
pub struct Pagination {
    pub offset: u64,
    #[serde(deserialize_with = "clamp_pagination_limit")]
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

    /// Atomically persist the last-used TOTP step after a successful
    /// verification, guarded by a compare-and-set on the stored step.
    ///
    /// Called by `AuthService` after a TOTP code is accepted to prevent replay
    /// within the same time window (SEC-008 / SECHRD-01 / REQ-14 AC-5).
    ///
    /// The advance only applies `WHERE totp_last_used_step = NONE OR
    /// totp_last_used_step < step`, so N concurrent submissions of one valid
    /// code succeed at most once: returns `Ok(true)` if this call won the
    /// CAS (the step advanced), `Ok(false)` if the guard did not match
    /// (replay, or a concurrent caller already won). Callers MUST treat
    /// `Ok(false)` as a rejected verification (e.g. `MfaInvalidCode`), not a
    /// silent no-op.
    fn update_totp_step(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        step: u64,
    ) -> impl Future<Output = AxiamResult<bool>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<User>>> + Send;

    /// Atomically increment the failed-login counter (SEC-032).
    ///
    /// Avoids read-modify-write TOCTOU by delegating the increment to the DB
    /// layer via a single `UPDATE ... SET field += 1` statement.
    ///
    /// When the new attempt count reaches `lockout_threshold`, the account is
    /// locked until `now + d`, where `d` grows exponentially with each lockout
    /// beyond the threshold (brute-force protection, design-document §Security):
    ///
    /// ```text
    /// d = min(base_lockout_secs * backoff_multiplier ^ (new_count - threshold),
    ///         max_lockout_secs)
    /// ```
    ///
    /// so the first lockout lasts `base_lockout_secs`, the next
    /// `base * multiplier`, and so on, capped at `max_lockout_secs`.
    fn increment_failed_logins(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        lockout_threshold: u32,
        base_lockout_secs: i64,
        backoff_multiplier: f64,
        max_lockout_secs: i64,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Anonymize a user row in-place for GDPR Art. 17 erasure (D-05).
    ///
    /// Implementations MUST scrub every PII column (email, username,
    /// password_hash, mfa_secret, metadata, lockout state) and clear
    /// `deletion_pending`/`scheduled_purge_at` — this is the step that
    /// clears the re-selection anchor `find_due_for_purge` keys on, so a
    /// purge pipeline that fails before reaching this call leaves the user
    /// due for a retry (SECHRD-06 / D-03a).
    fn anonymize_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        email_hash: &str,
        pseudonym: &str,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
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

    /// Get the IDs of all users directly assigned this role.
    fn get_role_user_ids(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Uuid>>> + Send;

    /// Get the IDs of all groups directly assigned this role.
    fn get_role_group_ids(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Uuid>>> + Send;
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
    /// Grant a permission to a role with an explicit [`PermissionEffect`]
    /// (B1, deny-override).
    ///
    /// `PermissionEffect::Allow` is exactly what `grant_to_role_with_scopes`
    /// does, so that method delegates here. `PermissionEffect::Deny` writes a
    /// deny rule, which the engine treats as overriding **every** allow —
    /// see `claude_dev/deny-override-design.md`.
    fn grant_to_role_with_effect(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
        scope_ids: Vec<Uuid>,
        effect: PermissionEffect,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
    fn get_role_permission_grants(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<PermissionGrant>>> + Send;

    /// Batch variant of [`Self::get_role_permission_grants`]: fetch the permission
    /// grants for many roles in a single query, grouped by role id. Roles with no
    /// grants are simply absent from the returned map. Used on the hot authorization
    /// path to avoid an N+1 query per applicable role.
    fn get_role_permission_grants_for_roles(
        &self,
        tenant_id: Uuid,
        role_ids: &[Uuid],
    ) -> impl Future<Output = AxiamResult<HashMap<Uuid, Vec<PermissionGrant>>>> + Send;
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

/// Storage for SCIM provisioning tokens.
///
/// See `axiam_core::models::scim_token` for what a token is and is not. The
/// lookup below is the whole authentication path for `/scim/v2/*` when the
/// caller presents a provisioning handle rather than a JWT.
pub trait ScimTokenRepository: Send + Sync {
    fn create(&self, input: CreateScimToken)
    -> impl Future<Output = AxiamResult<ScimToken>> + Send;

    /// Resolve a presented handle by its hash, **without** filtering on
    /// revocation or expiry.
    ///
    /// The caller applies [`ScimToken::is_usable`] instead, for the same
    /// reason `consume_by_token_hash` does not filter expiry: the row is
    /// needed in order to record *why* a request was refused, and a query that
    /// returned `None` for "revoked" and for "never existed" alike would make
    /// the two indistinguishable in the audit trail even though only one of
    /// them is somebody using a credential that was taken away from them.
    ///
    /// Tenant-free by construction: a presented handle is the only thing the
    /// caller knows at this point — there is no authenticated tenant yet to
    /// scope by. The row's own `tenant_id` is what establishes it, which is
    /// why the hash must be the full-entropy lookup key and not a prefix.
    fn get_by_token_hash(
        &self,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<ScimToken>>> + Send;

    fn list_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<ScimToken>>> + Send;

    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<ScimToken>> + Send;

    /// Mark a token revoked. Idempotent — revoking an already-revoked token
    /// keeps the original `revoked_at`, so the audit trail records when
    /// authority was actually withdrawn rather than when somebody last clicked.
    fn revoke(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Best-effort `last_used_at` stamp. Errors are the caller's to swallow:
    /// failing a provisioning request because a usage timestamp could not be
    /// written would turn an observability feature into an outage.
    fn touch_last_used(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Remove every token bound to a user. Called when the user is deleted, so
    /// a deprovisioned administrator does not leave live credentials behind.
    fn delete_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
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

    /// Migrate a stored `client_secret_hash` to the current scheme (§13.4
    /// observation 4), after a **successful** verification.
    ///
    /// This mirrors [`OAuth2ClientRepository::upgrade_client_secret_hash`],
    /// which service accounts were missing: `create`/`rotate_secret` write the
    /// current scheme, but nothing migrated an existing row, so a legacy v1
    /// service-account hash stayed v1 forever no matter how often it
    /// authenticated. The consequence was structural rather than immediate —
    /// the v1 arm of the verifier could never be retired on the strength of "no
    /// v1 `oauth2_client` rows remain", because the service-account table was
    /// silently accumulating rows the migration never reached. The same seam now
    /// also carries pepper-rotation rewrites (§13.4 observation 3).
    ///
    /// Implementations MUST compare-and-swap on `expected_hash`, so a secret
    /// rotation racing this upgrade is not clobbered into resurrecting the
    /// previous secret. Returns `true` when a row was updated, `false` when the
    /// CAS did not match. Callers MUST NOT turn a failure here into an
    /// authentication failure: authentication has already succeeded.
    fn upgrade_client_secret_hash(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        expected_hash: &str,
        new_hash: &str,
    ) -> impl Future<Output = AxiamResult<bool>> + Send;

    /// Count service accounts whose `client_secret_hash` is still in a **legacy
    /// (v1)** scheme (§15.2).
    ///
    /// ## Why this exists, stated plainly
    ///
    /// [`Self::upgrade_client_secret_hash`] can only fire on a *successful
    /// verification*. When this count was introduced there was **no such path**
    /// for a service account — the secret was issued at create/rotate and no
    /// flow accepted it — so these rows could not drain lazily at all.
    ///
    /// The OAuth2 **client-credentials** grant now accepts a service account's
    /// `client_id`/`client_secret`, so legacy rows *do* migrate on first use,
    /// exactly as `oauth2_client` rows do. This count remains useful for the
    /// case that migration cannot reach: a service account that never
    /// authenticates. Its backlog is what decides whether the legacy hash arm
    /// can be retired, and **rotation** clears a row that will never
    /// authenticate on its own.
    ///
    /// **This counts the hash *scheme* only.** A row already in the current
    /// scheme but keyed to a superseded pepper is indistinguishable on disk —
    /// the stored format is identical — so it is not counted. That is correct
    /// for the question this answers (can the legacy *arm* be retired?), and
    /// such rows migrate on the same first authentication.
    ///
    /// That has one concrete consequence: the v1 arm of the verifier cannot be
    /// retired on the strength of "no v1 `oauth2_client` rows remain", because
    /// this table is invisible to that reasoning. This count makes the question
    /// answerable, and the migration route is **rotation** — `rotate_secret`
    /// writes the current scheme under the current pepper.
    fn count_legacy_secret_hashes(
        &self,
        tenant_id: Option<Uuid>,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;
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
    /// Atomically consume (delete) a single session, returning `true` iff this
    /// call removed the row. Unlike [`Self::invalidate`] (idempotent, always
    /// `Ok(())`), this is the single-use gate for refresh-token rotation
    /// (NEW-3): two concurrent refreshes racing on the same token both pass the
    /// prior SELECT, but only one wins this delete — the loser gets `false` and
    /// must abort before minting a new session, preserving single-use rotation
    /// and stolen-token reuse detection.
    fn consume(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<bool>> + Send;
    /// Atomically look up **and** consume a session by its refresh-token hash,
    /// returning the row as it was immediately before deletion (`None` when no
    /// live session matched).
    ///
    /// This is [`Self::get_by_token_hash`] followed by [`Self::consume`],
    /// collapsed into one statement — and it is the shape refresh rotation
    /// should use, for two independent reasons.
    ///
    /// **Correctness.** The read-then-delete pair has a window between the
    /// SELECT and the DELETE. `consume`'s `RETURN BEFORE` already closes the
    /// *outcome* (only one racer sees a non-empty before-image), so the pair is
    /// safe — but it is safe by a second mechanism layered on top of a race,
    /// rather than by not having the race. One `DELETE ... WHERE token_hash =
    /// $h RETURN BEFORE` has no window at all: the row is selected and removed
    /// by the same statement, and the before-image *is* the session.
    ///
    /// **Cost.** It halves the rotation path's datastore round trips. Refresh
    /// is the one hot endpoint that is round-trip-bound rather than CPU-bound
    /// (run 5: p50 88.8 ms at 545/s, a whole distribution shifted right, i.e.
    /// added serialized work — `claude_dev/improvement-after-run5-benchmark.md`
    /// A2/J2), so a round trip removed from it is worth more than anywhere else
    /// in the codebase.
    ///
    /// Expiry is deliberately NOT filtered here. An expired token must be
    /// consumed too — leaving the row behind would let it be replayed until
    /// cleanup ran — so the caller receives the expired session and rejects it,
    /// which is what the read-then-delete path did (it invalidated on the
    /// expiry branch) with one fewer statement.
    fn consume_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<Session>>> + Send;
    /// Invalidate all sessions for a user (e.g., on password change).
    fn invalidate_user_sessions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
    /// Invalidate all sessions for a user except one (e.g., on password
    /// change — preserve the caller's current session).
    ///
    /// Returns the number of sessions deleted.
    fn invalidate_user_sessions_except(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;
    /// Remove all expired sessions.
    fn cleanup_expired(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<u64>> + Send;

    /// List all sessions for a user, tenant-scoped.
    ///
    /// Returns complete `Session` rows (including `token_hash`) — this method
    /// is a raw metadata read; redacting the token/hash before surfacing the
    /// rows to a caller (e.g. the GDPR export) is the caller's responsibility
    /// (D-03c, SECHRD-06).
    fn list_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Session>>> + Send;
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

    /// Pseudonymize audit entries for a deleted user (D-03/D-04).
    ///
    /// This is the ONLY non-INSERT write permitted on `audit_log`.
    /// It runs under the `gdpr_pseudonymizer` schema permission (v15).
    ///
    /// Full D-03 scrub:
    /// - `actor_id` → nil UUID
    /// - `metadata.actor_pseudonym` → `pseudonym` string
    /// - `ip_address` → NULL
    /// - known PII metadata keys (`email`, `username`, `name`, etc.) → `[redacted]`
    /// - `resource_id` → nil UUID where it equals `user_id`
    ///
    /// Returns the count of updated rows.
    fn pseudonymize_actor(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        pseudonym: &str,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;
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

    /// Migrate a stored `client_secret_hash` from a legacy scheme to the
    /// current one (OBS-1), after a **successful** verification of the
    /// presented secret.
    ///
    /// Legacy hashes are unsalted SHA-256 digests and cannot be re-derived
    /// offline — the secret was never stored — so migration is necessarily
    /// lazy and happens on the authentication path.
    ///
    /// Implementations MUST compare-and-swap on `expected_hash`: a secret
    /// rotation racing this upgrade would otherwise be clobbered, silently
    /// resurrecting the previous secret. Returns `true` when a row was
    /// actually updated, `false` when the CAS did not match (a concurrent
    /// write won — nothing to do). Callers MUST NOT turn a failure here into
    /// an authentication failure: authentication has already succeeded.
    fn upgrade_client_secret_hash(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        expected_hash: &str,
        new_hash: &str,
    ) -> impl Future<Output = AxiamResult<bool>> + Send;
}

/// Storage for RFC 8628 device-authorization grants (B2).
///
/// Every method is tenant-scoped, and the state transitions are enforced in
/// the datastore's own WHERE clauses rather than by a read-then-write in the
/// service. That is what makes them atomic: two concurrent polls of the same
/// approved grant must not both redeem it.
pub trait DeviceGrantRepository: Send + Sync {
    /// Store a newly issued grant.
    fn create(
        &self,
        input: CreateDeviceGrant,
    ) -> impl Future<Output = AxiamResult<DeviceGrant>> + Send;

    /// Look up a grant by the **user code** the human typed.
    ///
    /// `user_code` must already be normalised by the caller — the stored form
    /// is normalised, so a raw `WXYZ-1234` would simply miss.
    fn get_by_user_code(
        &self,
        tenant_id: Uuid,
        user_code: &str,
    ) -> impl Future<Output = AxiamResult<Option<DeviceGrant>>> + Send;

    /// Look up a grant by the hash of the device code the device polls with.
    fn get_by_device_code_hash(
        &self,
        tenant_id: Uuid,
        device_code_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<DeviceGrant>>> + Send;

    /// Record the user's decision.
    ///
    /// Only a `pending` grant may transition, which is checked in the same
    /// statement: approving an already-denied (or already-redeemed) grant must
    /// not succeed, and a lost race must be visible to the caller as `false`
    /// rather than silently overwriting the earlier decision.
    fn decide(
        &self,
        tenant_id: Uuid,
        user_code: &str,
        approved: bool,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<bool>> + Send;

    /// Atomically redeem an **approved** grant, returning it exactly once.
    ///
    /// `None` means it was not approved, or another poll already redeemed it.
    /// The single-use guarantee lives here, in one statement, for the same
    /// reason refresh-token rotation does: a read-then-write would let two
    /// concurrent polls both mint a token set from one approval.
    fn redeem(
        &self,
        tenant_id: Uuid,
        device_code_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<DeviceGrant>>> + Send;

    /// Record a poll and return the interval the device must now honour.
    ///
    /// Polling faster than `interval_secs` raises the interval (RFC 8628 §3.5
    /// `slow_down`), which is what makes the enforcement self-correcting: a
    /// device that ignores the interval is progressively slowed rather than
    /// cut off. Returns `(interval_secs, too_fast)`.
    fn record_poll(
        &self,
        tenant_id: Uuid,
        device_code_hash: &str,
    ) -> impl Future<Output = AxiamResult<(u64, bool)>> + Send;

    /// Remove expired grants. Returns the number deleted.
    fn cleanup_expired(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<u64>> + Send;
}

/// Storage for session/client participation (B5, back-channel logout).
///
/// One AXIAM session serves many relying parties — that is what SSO is — so
/// participation is a set, not a field on the session.
pub trait SessionClientRepository: Send + Sync {
    /// Record that a client participated in a session.
    ///
    /// Idempotence is NOT promised: a client legitimately re-authorizes within
    /// one session (a second tab, a refreshed consent), and making that a
    /// constraint violation would turn a normal flow into an error. Callers
    /// deduplicate at fan-out time instead, where the cost is a small
    /// in-memory set rather than a failed write.
    fn record(
        &self,
        input: CreateSessionClient,
    ) -> impl Future<Output = AxiamResult<SessionClient>> + Send;

    /// Every participation record for a session, in insertion order.
    fn list_for_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<SessionClient>>> + Send;

    /// Drop a session's participation records. Returns the number deleted.
    ///
    /// Called after the logout fan-out has been dispatched, not before: the
    /// list is what the fan-out iterates.
    fn delete_for_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;
}

/// Storage for UMA 2.0 permission tickets (X2).
///
/// A resource server posts the `(resource, scopes)` tuples it requires to
/// `/uma2/perm` and gets back an opaque ticket; the client redeems it at the
/// token endpoint for an RPT. The ticket is a server-side row rather than a
/// signed JWT because UMA 2.0 §3.3 makes it single-use, and single-use is not
/// a property a stateless token can have — see `models::uma`.
pub trait PermissionTicketRepository: Send + Sync {
    /// Store a newly minted ticket.
    fn create(
        &self,
        input: CreatePermissionTicket,
    ) -> impl Future<Output = AxiamResult<PermissionTicket>> + Send;

    /// Atomically consume an unexpired, unconsumed ticket **belonging to
    /// `client_id`**, returning it as it was immediately before being marked
    /// consumed (`None` when nothing matched).
    ///
    /// Single-use lives here in one statement for the same reason PAR's does:
    /// a read-then-write would let two concurrent redemptions both spend one
    /// ticket, and a replayable ticket is a replayable authorization.
    ///
    /// `client_id` is part of the WHERE clause rather than a check the service
    /// makes on the returned row. If it were checked afterwards, a ticket
    /// leaked to another client would be *burned* by that client's failed
    /// attempt — a denial of service against the resource server that owns it.
    /// Matching it in the statement means a wrong-client attempt changes
    /// nothing and the rightful holder can still redeem.
    fn consume(
        &self,
        tenant_id: Uuid,
        ticket_hash: &str,
        client_id: &str,
    ) -> impl Future<Output = AxiamResult<Option<PermissionTicket>>> + Send;

    /// Read a ticket without consuming it, to classify why a redemption
    /// failed for the audit trail.
    ///
    /// Every rejection is `invalid_grant` on the wire, so this exists only so
    /// the audit record can say *which* — expired, replayed, or presented by
    /// the wrong client. It must never be used to shape the client's response.
    fn find_by_hash(
        &self,
        tenant_id: Uuid,
        ticket_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<PermissionTicket>>> + Send;

    /// Remove expired tickets. Returns the number deleted.
    fn cleanup_expired(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<u64>> + Send;
}

/// Storage for RFC 9126 pushed authorization requests (B5).
///
/// The client POSTs its authorization parameters to `/oauth2/par` — where it
/// authenticates — and gets back an opaque `request_uri` to put in the browser
/// redirect instead. The parameters therefore never travel through the user
/// agent.
pub trait PushedAuthRequestRepository: Send + Sync {
    /// Store a newly pushed request.
    fn create(
        &self,
        input: CreatePushedAuthRequest,
    ) -> impl Future<Output = AxiamResult<PushedAuthRequest>> + Send;

    /// Atomically consume an unexpired, unconsumed request, returning it as it
    /// was immediately before being marked consumed (`None` when nothing
    /// matched).
    ///
    /// Single-use lives here, in one statement, for the same reason
    /// refresh-token rotation does: a read-then-write would let two concurrent
    /// authorize requests both spend one pushed request. RFC 9126 §2.2 makes
    /// `request_uri` one-time-use precisely because a replayable one is a
    /// replayable authorization request.
    ///
    /// Expiry is part of the same WHERE clause rather than a check in the
    /// service, so a request cannot be consumed in the window between the
    /// service reading it and writing it back.
    fn consume(
        &self,
        tenant_id: Uuid,
        request_uri_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<PushedAuthRequest>>> + Send;

    /// Remove expired requests. Returns the number deleted.
    fn cleanup_expired(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<u64>> + Send;
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

    /// Revoke all refresh tokens for a user within a tenant (e.g., on
    /// password change or reset). Idempotent — already-revoked tokens are
    /// skipped and do not count toward the returned total.
    ///
    /// Returns the number of tokens newly revoked.
    fn revoke_all_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;

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

    /// Every enabled OIDC provider of this tenant that has X4 external token
    /// exchange switched on.
    ///
    /// A dedicated method rather than a filtered `list()` because it runs on
    /// the exchange path: it is index-backed
    /// (`idx_federation_config_tenant_tx`), it never hydrates the encrypted
    /// secret columns, and — the part that matters for review — the "enabled
    /// AND token-exchange-enabled" predicate lives in exactly one place
    /// instead of being restated by every caller that could get it wrong.
    fn list_token_exchange_enabled(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<FederationConfig>>> + Send;

    /// Return all `federation_config` rows where the legacy plaintext
    /// `client_secret` is present and the encrypted columns are absent.
    ///
    /// Used by the boot backfill task (D-12) to find rows that have not yet
    /// been encrypted with AES-256-GCM.
    fn list_with_legacy_plaintext_secret(
        &self,
    ) -> impl Future<Output = AxiamResult<Vec<FederationConfig>>> + Send;

    /// Persist the AES-256-GCM encrypted client secret split-column values
    /// (D-11) and clear the legacy plaintext column.
    ///
    /// Writes `client_secret_nonce`, `client_secret_ciphertext`,
    /// `client_secret_key_version`, and sets `client_secret = NONE`.
    fn set_encrypted_secret(
        &self,
        tenant_id: Uuid,
        config_id: Uuid,
        nonce_b64: String,
        ciphertext_b64: String,
        key_version: i64,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
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
// Federation Login State (D-24) — first-time SSO state + nonce correlation
// ---------------------------------------------------------------------------

/// A pending first-time SSO login state row.
///
/// Created by `oidc_start_public` / `saml_login_public` and consumed atomically
/// by the corresponding callback. Rows have a 10-minute TTL enforced at
/// consume time (expires_at check) and swept by `cleanup_expired`.
#[derive(Debug, Clone)]
pub struct FederationLoginState {
    /// Random 32-byte base64url value used as CSRF state and as the DB key.
    pub state: String,
    /// Random 32-byte base64url nonce (OIDC only; empty string for SAML).
    pub nonce: String,
    pub tenant_id: uuid::Uuid,
    pub federation_config_id: uuid::Uuid,
    /// SPA post-login destination (NOT the AXIAM ACS/callback URL).
    pub redirect_uri: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// SAML AuthnRequest ID (SAML only; empty string for OIDC).
    ///
    /// Stored at SAML login-start time so the ACS handler can verify
    /// `Response.InResponseTo` matches the request ID (SEC-005/REQ-14 AC-5).
    pub request_id: String,
}

/// Repository for first-time SSO login state rows.
pub trait FederationLoginStateRepository: Send + Sync {
    /// Persist a new login state row. Returns `Err(Conflict)` if the same
    /// `state` value already exists (UNIQUE index violation).
    fn insert(&self, row: &FederationLoginState) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Atomically consume a state row: SELECT + DELETE in one transaction.
    ///
    /// Returns `Ok(Some(row))` if the row was found and has not expired.
    /// Returns `Ok(None)` if the row was not found or was expired — the
    /// caller MUST treat both as `401 state not found or expired` to avoid
    /// distinguishing between the two cases (timing side-channel).
    ///
    /// The row is always deleted if found, regardless of expiry — this
    /// prevents a second consume from succeeding on an expired row.
    fn consume_by_state(
        &self,
        state: &str,
    ) -> impl Future<Output = AxiamResult<Option<FederationLoginState>>> + Send;

    /// Delete all rows where `expires_at < now()`. Returns the count deleted.
    fn cleanup_expired(&self) -> impl Future<Output = AxiamResult<u64>> + Send;
}

// ---------------------------------------------------------------------------
// SAML Assertion Replay (D-09)
// ---------------------------------------------------------------------------

/// Repository for tracking consumed SAML assertion IDs.
///
/// Provides insert-or-conflict semantics: inserting an assertion ID that has
/// already been recorded for the same tenant returns
/// `Err(AxiamError::ReplayDetected)`.  The replay table rows live until the
/// assertion's `NotOnOrAfter` time; `cleanup_expired` removes them.
pub trait AssertionReplayRepository: Send + Sync {
    /// Record a consumed assertion ID.
    ///
    /// Returns `Ok(())` on first insertion.  Returns
    /// `Err(AxiamError::ReplayDetected)` if an identical `(tenant_id,
    /// assertion_id)` pair already exists (UNIQUE constraint violation).
    fn insert_assertion(
        &self,
        tenant_id: Uuid,
        assertion_id: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Delete expired assertion replay rows across all tenants.
    ///
    /// Returns the number of rows deleted.
    fn cleanup_expired(&self) -> impl Future<Output = AxiamResult<u64>> + Send;
}

// ---------------------------------------------------------------------------
// AMQP Nonce Replay (NEW-4)
// ---------------------------------------------------------------------------

/// Repository for tracking consumed AMQP message nonces (NEW-4 replay
/// protection).
///
/// Provides the same insert-or-conflict semantics as
/// [`AssertionReplayRepository`]: inserting a `(tenant_id, nonce)` pair that
/// has already been recorded returns `Err(AxiamError::ReplayDetected)`. The
/// AMQP consumers call this AFTER a valid HMAC signature + a fresh `issued_at`
/// so a replayed message (same signed nonce within the freshness window) is
/// rejected. Rows live until the message's freshness window closes
/// (`issued_at + skew`); `cleanup_expired` removes them.
pub trait AmqpNonceRepository: Send + Sync {
    /// Record a consumed AMQP message nonce.
    ///
    /// Returns `Ok(())` on first insertion. Returns
    /// `Err(AxiamError::ReplayDetected)` if an identical `(tenant_id, nonce)`
    /// pair already exists (UNIQUE constraint violation) — that is a replay.
    fn insert_nonce(
        &self,
        tenant_id: Uuid,
        nonce: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Delete expired AMQP nonce rows across all tenants.
    ///
    /// Returns the number of rows deleted.
    fn cleanup_expired(&self) -> impl Future<Output = AxiamResult<u64>> + Send;
}

// ---------------------------------------------------------------------------
// OAuth2 proof-of-possession replay (X5.1)
// ---------------------------------------------------------------------------

/// Repository for the single-use `jti` values that make RFC 7523 client
/// assertions and RFC 9449 DPoP proofs non-replayable.
///
/// Structurally the same guarantee [`AssertionReplayRepository`] and
/// [`AmqpNonceRepository`] provide, and deliberately the same mechanism: a
/// `CREATE` against a table carrying a `UNIQUE` index, where the index
/// violation **is** the "already seen" answer. Nothing here reads before it
/// writes.
///
/// That matters more here than anywhere else in the tree. A read-then-write
/// replay check has a window between the two in which a second copy of the same
/// proof passes the read — which is precisely the race #316 and #318 spent real
/// effort closing for authorization codes. A proof-of-possession credential
/// that can be replayed once concurrently is not a proof of anything.
///
/// # Two scopes, one mechanism
///
/// The two kinds are separated by their `scope` rather than by two tables,
/// because the uniqueness key differs only in what the second component means:
///
/// | Kind | Scope | Why |
/// |---|---|---|
/// | client assertion | `client_id` | RFC 7523 §3 scopes `jti` uniqueness to the issuer, and the issuer of a client assertion *is* the client. Two clients that both pick `jti: "1"` have not replayed anything. |
/// | DPoP proof | `jkt` | RFC 9449 §11.1 scopes it to the proof key. The same reasoning: the key is the issuer. |
///
/// Both are further scoped by tenant, like everything else in AXIAM.
pub trait ProofReplayRepository: Send + Sync {
    /// Record a consumed `jti`.
    ///
    /// Returns `Ok(())` the first time a `(tenant_id, kind, scope, jti)` tuple
    /// is seen and `Err(AxiamError::ReplayDetected)` on every subsequent
    /// attempt — decided by the UNIQUE index, not by a preceding read.
    fn insert_proof_jti(
        &self,
        tenant_id: Uuid,
        kind: ProofKind,
        scope: &str,
        jti: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Delete expired rows across all tenants. Returns the number deleted.
    ///
    /// A row is only useful until the credential it records could no longer be
    /// accepted anyway: past that point replaying it fails on `exp` (assertions)
    /// or `iat` freshness (DPoP proofs) without consulting this table at all.
    fn cleanup_expired_proofs(&self) -> impl Future<Output = AxiamResult<u64>> + Send;
}

/// Which proof-of-possession credential a replay row records.
///
/// An explicit discriminator rather than two tables because the two rows are
/// identical in shape and lifetime, and one table means one cleanup job and one
/// index to reason about. It is *not* merely cosmetic: without it, a client
/// whose `client_id` happened to equal some key's `jkt` would share a
/// uniqueness namespace with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// RFC 7523 §2.2 `client_assertion`, scoped by `client_id`.
    ClientAssertion,
    /// RFC 9449 DPoP proof, scoped by the proof key's `jkt`.
    DpopProof,
}

impl ProofKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientAssertion => "client_assertion",
            Self::DpopProof => "dpop_proof",
        }
    }
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
    /// Look up a CA certificate by its record ID without requiring the
    /// organization ID. Used internally by mTLS chain verification
    /// (SEC-024) where the issuer_ca_id is already known from the leaf cert.
    fn get_by_issuer_id(&self, id: Uuid)
    -> impl Future<Output = AxiamResult<CaCertificate>> + Send;
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
// Reactors (tenant-scoped) — X1
// ---------------------------------------------------------------------------

pub trait ReactorRepository: Send + Sync {
    fn create(&self, input: CreateReactor) -> impl Future<Output = AxiamResult<Reactor>> + Send;
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<Reactor>> + Send;
    fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateReactor,
    ) -> impl Future<Output = AxiamResult<Reactor>> + Send;
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
    fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> impl Future<Output = AxiamResult<PaginatedResult<Reactor>>> + Send;

    /// Every ENABLED reactor in the tenant subscribed to `event`, ordered by
    /// `priority` ascending then `id`, which is the order interceptors run in.
    ///
    /// The secondary sort on `id` is not cosmetic: two reactors at the same
    /// priority would otherwise chain in whatever order the storage engine
    /// returned them, so the same rule set could produce different tokens on
    /// different replicas. A total order makes the chain reproducible.
    fn get_enabled_by_event(
        &self,
        tenant_id: Uuid,
        event: &str,
    ) -> impl Future<Output = AxiamResult<Vec<Reactor>>> + Send;

    /// Record that a reactor consumed from its queue.
    ///
    /// Separated from `update` because it is written on the *consumer's*
    /// heartbeat rather than by an administrator, and it must not bump
    /// `updated_at` — an operator reading "last modified" wants the last
    /// configuration change, not the last heartbeat.
    fn touch_last_seen(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
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
// SRP credentials (tenant scope)
// ---------------------------------------------------------------------------

/// Repository for Secure Remote Password verifiers.
///
/// One row per user at most. A verifier is written only where the plaintext
/// password is legitimately in hand (registration, authenticated password
/// change, reset completion), so `upsert` replaces rather than versions:
/// keeping historical verifiers would keep historical passwords crackable for
/// no operational benefit.
pub trait SrpCredentialRepository: Send + Sync {
    /// Create or replace the verifier for a user.
    fn upsert(
        &self,
        input: CreateSrpCredential,
    ) -> impl Future<Output = AxiamResult<SrpCredential>> + Send;

    /// Fetch a user's verifier. `NotFound` means the user has never set a
    /// password under an SRP-enabled policy — which is a normal state, not an
    /// error, and callers must treat it as "fall back to password login"
    /// rather than as a failure.
    fn get_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<SrpCredential>> + Send;

    /// Remove a user's verifier — used by account deletion and by an admin
    /// forcing a user back onto password login.
    fn delete_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<bool>> + Send;

    /// Count users in a tenant that have a verifier. Backs the admin-facing
    /// SRP coverage figure, which is what tells an operator whether
    /// [`SrpMode::Required`] would strand anyone.
    ///
    /// [`SrpMode::Required`]: crate::models::srp::SrpMode::Required
    fn count_for_tenant(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<u64>> + Send;
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

    /// Delete the org-level email config (D-13).
    ///
    /// Note (D-13-org-delete-orphaning): this does NOT cascade-delete tenant
    /// overrides that depend on this org baseline. After deletion,
    /// `get_effective_config` returns `None` for tenants without a full
    /// override of their own, which surfaces as a clear "no email config"
    /// condition at send time rather than silently sending broken mail.
    fn delete_org_config(&self, org_id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;

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

// -------------------------------------------------------------------
// WebAuthn Credentials (tenant-scoped)
// -------------------------------------------------------------------

/// Repository for WebAuthn/FIDO2 credential storage.
pub trait WebauthnCredentialRepository: Send + Sync {
    /// Store a new WebAuthn credential.
    fn create(
        &self,
        input: CreateWebauthnCredential,
    ) -> impl Future<Output = AxiamResult<WebauthnCredential>> + Send;

    /// Get a credential by ID.
    fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<WebauthnCredential>> + Send;

    /// Get all WebAuthn credentials for a user.
    fn list_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<WebauthnCredential>>> + Send;

    /// Update the `last_used_at` timestamp after successful
    /// authentication.
    fn update_last_used(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Delete a WebAuthn credential.
    fn delete(&self, tenant_id: Uuid, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Count how many WebAuthn credentials a user has registered.
    fn count_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<u64>> + Send;

    /// List every WebAuthn credential registered in a tenant, across all
    /// users (X3 wave 3, D9 compliance report — "for every credential in
    /// the tenant").
    ///
    /// Default implementation returns an empty list so the pre-existing
    /// test-double implementations of this trait (which never exercise
    /// tenant-wide listing) keep compiling unmodified; the real
    /// SurrealDB-backed repository overrides this.
    fn list_by_tenant(
        &self,
        _tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<WebauthnCredential>>> + Send {
        async { Ok(Vec::new()) }
    }
}

// ---------------------------------------------------------------------------
// Per-tenant WebAuthn attestation policy (X3, D5)
// ---------------------------------------------------------------------------

pub trait WebauthnAttestationPolicyRepository: Send + Sync {
    /// `None` means no row exists for the tenant — callers treat that as
    /// `WebauthnAttestationPolicy::default()`, which is today's behavior
    /// unchanged (D5: "an absent row means the defaults below").
    fn get_by_tenant(
        &self,
        tenant_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<WebauthnAttestationPolicy>>> + Send;

    /// Create or replace the tenant's policy row. Callers are responsible
    /// for running `webauthn_policy::validate_attestation_policy` first —
    /// this method stores whatever it is given.
    fn set(
        &self,
        tenant_id: Uuid,
        policy: WebauthnAttestationPolicy,
    ) -> impl Future<Output = AxiamResult<WebauthnAttestationPolicy>> + Send;

    /// Delete the tenant's policy row (revert to the default — `mode: none`).
    fn delete(&self, tenant_id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
}

// ---------------------------------------------------------------------------
// FIDO MDS3 metadata — server-global, NOT tenant-scoped (X3, D10)
// ---------------------------------------------------------------------------
//
// Trust-anchor/authenticator metadata is a platform-wide concern, not a
// per-tenant one — every tenant looks up the same AAGUID against the same
// FIDO Alliance BLOB, so there is exactly one `mds_entry` table and one
// `mds_blob_meta` row for the whole server (D10), not one per tenant.

pub trait MdsRepository: Send + Sync {
    /// Atomically replace the entire entry set with a freshly verified
    /// BLOB's entries and store its metadata.
    ///
    /// The D4-step-8 rollback/no-op-refresh decision
    /// (`axiam_pki::mds::decide_ingest_outcome`) is the **caller's**
    /// responsibility, using [`Self::get_meta`] to read the currently
    /// stored `no` first — this method assumes that decision already
    /// concluded "replace" by the time it is called.
    fn replace_entries(
        &self,
        entries: Vec<MdsEntry>,
        meta: MdsBlobMeta,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Look up a single entry by AAGUID — the registration-time policy
    /// lookup (D7/D8). `None` means FIDO Alliance has no metadata for this
    /// AAGUID (not necessarily malicious — MDS coverage is incomplete).
    fn get_by_aaguid(
        &self,
        aaguid: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<MdsEntry>>> + Send;

    /// Every stored entry (X3 wave 2, added beyond the wave-1 trait — see the
    /// `axiam-auth::attestation` module docs for why: building an
    /// `AttestationCaList` that accepts *any* FIDO-certified authenticator
    /// (a tenant with `mode != none` but no `allowed_aaguids` allowlist) needs
    /// every attestation root MDS knows, not a bounded set of point lookups).
    /// Ordering is unspecified; callers that need a stable order sort it
    /// themselves.
    fn list_all(&self) -> impl Future<Output = AxiamResult<Vec<MdsEntry>>> + Send;

    /// Current BLOB metadata (`no`, `nextUpdate`, staleness, entry count).
    /// `None` before the first successful ingestion.
    fn get_meta(&self) -> impl Future<Output = AxiamResult<Option<MdsBlobMeta>>> + Send;

    /// Bump only `last_refreshed_at` on the stored metadata — the D4-step-8
    /// "equal `no` is a no-op refresh" case, where the entries themselves
    /// are already up to date and do not need replacing.
    fn touch_refreshed_at(&self, at: DateTime<Utc>)
    -> impl Future<Output = AxiamResult<()>> + Send;
}

// ---------------------------------------------------------------------------
// Attestation metadata source (X3 wave 2, W2-D4)
// ---------------------------------------------------------------------------
//
// `axiam-auth` needs three things to enforce the attestation policy: the
// effective policy (resolved by its caller from `WebauthnAttestationPolicyRepository`
// before calling into `WebauthnService`), an AAGUID -> `MdsEntry` lookup, and
// the DER attestation roots needed to build a `webauthn-rs` `AttestationCaList`.
// This trait covers the last two, deliberately returning **plain data** (no
// `webauthn-rs` or `axiam-pki` types) so `axiam-auth` can depend on it without
// pulling in `axiam-pki` (the module doc on `axiam_auth::attestation` explains
// which choice was made and why — see W2-D4). It is implemented in `axiam-db`
// over `MdsRepository`.

/// One MDS-sourced attestation root: the owning AAGUID, the root certificate's
/// raw DER bytes (as `AttestationCaListBuilder::insert_device_der` wants them),
/// and the human-readable description to record alongside it.
#[derive(Debug, Clone)]
pub struct AttestationRootMaterial {
    pub aaguid: Uuid,
    pub der: Vec<u8>,
    pub description: String,
}

pub trait AttestationMetadataSource: Send + Sync {
    /// Look up a single MDS entry by AAGUID (the registration-time policy
    /// lookup, D7/D8). `None` means FIDO Alliance has no metadata for this
    /// AAGUID.
    fn get_entry(&self, aaguid: Uuid)
    -> impl Future<Output = AxiamResult<Option<MdsEntry>>> + Send;

    /// Every attestation root certificate known to MDS, one entry per
    /// `(aaguid, root certificate)` pair — an authenticator model can be
    /// covered by more than one root, and a root can cover more than one
    /// model, so the flattened list is the right shape for
    /// `AttestationCaListBuilder::insert_device_der`, which is called once
    /// per pair.
    ///
    /// `allowed_aaguids: Some(list)` restricts the result to those AAGUIDs
    /// only (W2-D3: "the cryptographic layer and the policy layer agree").
    /// `None` returns every root for every AAGUID MDS has metadata for.
    fn attestation_roots(
        &self,
        allowed_aaguids: Option<&[Uuid]>,
    ) -> impl Future<Output = AxiamResult<Vec<AttestationRootMaterial>>> + Send;
}

// ---------------------------------------------------------------------------
// GDPR — Consent (REQ-8)
// ---------------------------------------------------------------------------

pub trait ConsentRepository: Send + Sync {
    /// Record a new consent (immutable — no update/delete).
    fn create(&self, input: CreateConsent) -> impl Future<Output = AxiamResult<Consent>> + Send;

    /// List all consent records for a user in a tenant.
    fn list_by_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<Consent>>> + Send;
}

// ---------------------------------------------------------------------------
// GDPR — Account Deletion (D-08/D-09)
// ---------------------------------------------------------------------------

pub trait AccountDeletionRepository: Send + Sync {
    /// Create a deletion request; stores only the cancel_token_hash.
    fn create(
        &self,
        input: CreateAccountDeletion,
    ) -> impl Future<Output = AxiamResult<AccountDeletion>> + Send;

    /// Find by cancel-token hash (for the cancel-link endpoint).
    fn find_by_token_hash(
        &self,
        tenant_id: Uuid,
        cancel_token_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<AccountDeletion>>> + Send;

    /// Mark as cancelled (user clicked cancel link in time).
    fn mark_cancelled(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Mark as completed (purge ran successfully).
    fn mark_completed(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> impl Future<Output = AxiamResult<()>> + Send;
}

// ---------------------------------------------------------------------------
// GDPR — Export Job (D-12/D-13)
// ---------------------------------------------------------------------------

pub trait ExportJobRepository: Send + Sync {
    /// Create a new queued export job.
    fn create(&self, input: CreateExportJob)
    -> impl Future<Output = AxiamResult<ExportJob>> + Send;

    /// Find queued jobs (for the export worker).
    fn find_queued(&self) -> impl Future<Output = AxiamResult<Vec<ExportJob>>> + Send;

    /// Mark job as ready with encrypted blob and single-use download token hash.
    fn set_ready(
        &self,
        id: Uuid,
        download_token_hash: String,
        encrypted_blob: Option<String>,
        file_path: Option<String>,
        blob_nonce: Option<String>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Find a ready job by its download token hash (single-use).
    fn find_by_download_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> impl Future<Output = AxiamResult<Option<ExportJob>>> + Send;

    /// Mark a job as downloaded (single-use consumed).
    fn mark_downloaded(&self, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Atomically consume a Ready export job: update status to 'downloaded'
    /// only if the current status is 'ready', then delete the row.
    ///
    /// Returns `true` if the job was successfully consumed (status was 'ready'),
    /// `false` if it was already consumed or in a different state (TOCTTOU-safe,
    /// CQ-B38 / REQ-14 AC-5).
    fn consume_ready_and_delete(&self, id: Uuid) -> impl Future<Output = AxiamResult<bool>> + Send;

    /// Mark a job as failed (processing error; may be retried — CQ-B38/REQ-14 AC-5).
    fn mark_failed(&self, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;

    /// Delete an expired or downloaded job and its file.
    fn delete(&self, id: Uuid) -> impl Future<Output = AxiamResult<()>> + Send;
}

// ---------------------------------------------------------------------------
// GDPR — Erasure Proof (D-06)
// ---------------------------------------------------------------------------

pub trait ErasureProofRepository: Send + Sync {
    /// Append a PII-free erasure proof record (INSERT-only).
    fn create(
        &self,
        input: CreateErasureProof,
    ) -> impl Future<Output = AxiamResult<ErasureProof>> + Send;
}

// ---------------------------------------------------------------------------
// Mail Publisher (D-14 — thin trait for async mail enqueue)
// ---------------------------------------------------------------------------

/// Trait for publishing outbound mail messages to the async delivery queue.
///
/// Implemented by `axiam-amqp`'s `MailOutboundPublisher`.  The thin trait
/// lives in `axiam-core` so that `axiam-audit` (which must not depend on
/// `axiam-amqp` due to the circular-dep constraint) can accept a generic
/// publisher without coupling to the AMQP infrastructure layer.
pub trait MailPublisher: Send + Sync {
    /// Enqueue a single outbound mail message.
    ///
    /// Implementations MUST be fire-and-forget at the call site: callers
    /// log a warning on error but do **not** propagate it to the client.
    fn publish(
        &self,
        msg: OutboundMailMessage,
    ) -> impl Future<Output = crate::error::AxiamResult<()>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    // -----------------------------------------------------------------------
    // Pagination (SEC-010 / CQ-B30)
    //
    // `clamp_pagination_limit` is a resource-exhaustion control, not a
    // convenience: it is the only thing standing between `?limit=100000000`
    // and a query that tries to materialise the whole table. It runs on the
    // SERDE path only — direct struct construction is deliberately unaffected,
    // because internal callers that ask for a large page have already been
    // reasoned about, while a query string has not.
    //
    // Both halves of that split are asserted below. A refactor that moved the
    // clamp into the struct would break internal callers silently; one that
    // dropped it from serde would reopen the DoS with no visible change.
    // -----------------------------------------------------------------------

    fn from_query(json: &str) -> Pagination {
        serde_json::from_str(json).expect("deserialises")
    }

    #[test]
    fn a_deserialised_limit_is_clamped_to_the_documented_bounds() {
        assert_eq!(from_query(r#"{"offset":0,"limit":100000000}"#).limit, 200);
        assert_eq!(from_query(r#"{"offset":0,"limit":201}"#).limit, 200);
        assert_eq!(from_query(r#"{"offset":0,"limit":200}"#).limit, 200);
        // A zero-size page is not a page; it would loop forever in any caller
        // that pages until it sees fewer rows than it asked for.
        assert_eq!(from_query(r#"{"offset":0,"limit":0}"#).limit, 1);
        assert_eq!(from_query(r#"{"offset":0,"limit":1}"#).limit, 1);
        // Anything already inside the range passes through untouched.
        assert_eq!(from_query(r#"{"offset":0,"limit":50}"#).limit, 50);
        assert_eq!(from_query(r#"{"offset":0,"limit":199}"#).limit, 199);
        // u64::MAX is the value an attacker actually sends.
        let max = format!(r#"{{"offset":0,"limit":{}}}"#, u64::MAX);
        assert_eq!(from_query(&max).limit, 200);
    }

    #[test]
    fn the_offset_is_not_clamped_because_it_bounds_no_work() {
        // Only `limit` decides how many rows come back, so only `limit` is a
        // DoS lever. A huge offset returns an empty page cheaply, and clamping
        // it would silently hand back page 1 to a caller that asked for page
        // 10 000 — a correctness bug in service of no security gain.
        assert_eq!(
            from_query(r#"{"offset":100000000,"limit":10}"#).offset,
            100_000_000
        );
    }

    #[test]
    fn direct_construction_bypasses_the_clamp_on_purpose() {
        // The doc comment says "direct struct construction is unaffected".
        // Internal callers rely on it — an export or a reconciliation job asks
        // for a big page knowingly, and it has not come from a query string.
        let p = Pagination {
            offset: 0,
            limit: 100_000,
        };
        assert_eq!(p.limit, 100_000);
    }

    #[test]
    fn the_default_page_is_the_documented_one() {
        let p = Pagination::default();
        assert_eq!(p.offset, 0);
        assert_eq!(p.limit, 50);
        // `#[serde(default)]` on the struct means an absent field falls back
        // here rather than to u64's zero — and a zero limit would be the
        // infinite-loop page described above.
        let empty = from_query("{}");
        assert_eq!(empty.offset, 0);
        assert_eq!(empty.limit, 50);
        // One field present, the other defaulted.
        assert_eq!(from_query(r#"{"offset":20}"#).limit, 50);
        assert_eq!(from_query(r#"{"limit":10}"#).offset, 0);
    }

    // -----------------------------------------------------------------------
    // ProofKind
    // -----------------------------------------------------------------------

    #[test]
    fn proof_kind_wire_names_are_stable() {
        // These strings are a storage format: the replay table is keyed on
        // them, so renaming one would silently split the namespace and let a
        // proof that was already spent be replayed once more under its new
        // name.
        assert_eq!(ProofKind::ClientAssertion.as_str(), "client_assertion");
        assert_eq!(ProofKind::DpopProof.as_str(), "dpop_proof");
        assert_ne!(
            ProofKind::ClientAssertion.as_str(),
            ProofKind::DpopProof.as_str()
        );
    }

    // -----------------------------------------------------------------------
    // The provided `list_by_tenant` default
    // -----------------------------------------------------------------------

    #[test]
    fn list_by_tenant_defaults_to_empty_so_test_doubles_keep_compiling() {
        // The default exists so pre-existing test doubles did not all have to
        // grow a method when D9 added tenant-wide listing. Its contract is
        // "empty", and that must stay true: a double that silently returned
        // something would make a compliance report look complete when the
        // repository behind it had never been asked.
        struct Double;
        impl WebauthnCredentialRepository for Double {
            async fn create(
                &self,
                _input: CreateWebauthnCredential,
            ) -> AxiamResult<WebauthnCredential> {
                unreachable!("not exercised by this test")
            }
            async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<WebauthnCredential> {
                unreachable!("not exercised by this test")
            }
            async fn list_by_user(
                &self,
                _t: Uuid,
                _u: Uuid,
            ) -> AxiamResult<Vec<WebauthnCredential>> {
                unreachable!("not exercised by this test")
            }
            async fn update_last_used(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
                unreachable!("not exercised by this test")
            }
            async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
                unreachable!("not exercised by this test")
            }
            async fn count_by_user(&self, _t: Uuid, _u: Uuid) -> AxiamResult<u64> {
                unreachable!("not exercised by this test")
            }
            // list_by_tenant deliberately NOT overridden — the default is
            // what is under test.
        }

        // Polled by hand rather than through an executor: axiam-core is
        // layer 0 and depends on no runtime, and a dev-dependency on one just
        // to drive a future that never yields would be a dependency the
        // layering check has to reason about forever.
        let mut fut = std::pin::pin!(Double.list_by_tenant(Uuid::new_v4()));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let got = match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(r) => r.expect("the default never fails"),
            std::task::Poll::Pending => panic!("the default must not yield"),
        };
        assert!(got.is_empty());
    }
}

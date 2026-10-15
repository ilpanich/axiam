//! The authorization function of the network write surface (RADIUS D4, W6.2;
//! `claude_dev/radius-reply-profile-design.md` §5.1–§5.3).
//!
//! # What it decides
//!
//! One function, [`authorize_network_write`], answers for every write that can
//! create or change **who may be placed on a network segment, and what being
//! placed there gives**:
//!
//! * a reply-profile write, against H1–H6 of §5.2;
//! * a segment write (`network:segments_write` at the parent or the node);
//! * a role assignment, unassignment, permission grant or revoke, role update
//!   or delete that touches a **network-sensitive** role, against the §5.3
//!   table and the three write-time rules of §4.2;
//! * a certificate **bind** to a service account, against §5.3's binding rows
//!   and H6 (correction R101W6-03 of the note);
//! * a write of the generic surfaces that could reach into the reserved
//!   namespace: a permission whose action is in `network:` (create, rename,
//!   delete), and a resource of a reserved `network_*` type, or under one, or
//!   re-parented into or out of the subtree (§4.1).
//!
//! Every "holds" is a [`WriteTimeAccess::check_at_write_time`] — the engine's
//! own evaluation, uncached, deny-override in full force, with the **writer's**
//! subject scope, so an organization-level writer carries only its global
//! grants (§2). A deny at the node or an ancestor is "does not hold".
//!
//! # What it returns
//!
//! A [`GateClearance`] or a [`GateRefusal`]. A refusal carries the HTTP class
//! (`403` for a permission the writer lacks, `400` for a write no permission
//! makes legal), the **internal** rule that refused (`H2`, `4.2:rule-2`, …), the
//! permission and node a `403` names, and the before and after values the audit
//! row records (§5.4). The caller writes that row; the function does no I/O
//! besides its reads.
//!
//! A clearance for a segment or profile write carries the
//! [`NetworkWriteClearance`] the repositories demand, so those writes cannot
//! reach the datastore without this function at all (a compile error, not a
//! review finding). The other writes go through repository methods older than
//! this module and shared with the seeder; `network_gate_enumeration_test` in
//! `axiam-api-rest` pins every call site of them to a function that calls this
//! one first, or to a named exemption with its reason.
//!
//! # What it is not
//!
//! It is a **namespace-limited** delegation bound. Outside `network:`,
//! `roles:assign` stays unbounded and so does `certificates:bind` for an
//! account that holds no `network:join` (the note's residual 7). "Holds" is a
//! write-time condition: a profile or an assignment does not lapse when its
//! writer later loses the permission (residual 1).
//!
//! The route-level permission (`roles:assign`, `permissions:grant`,
//! `certificates:bind`, …) is the caller's to check first; this function adds
//! to it and never replaces it.

use std::collections::BTreeSet;
use std::future::Future;

use axiam_core::error::AxiamResult;
use axiam_core::models::network::{
    NETWORK_ADMIN, NETWORK_ADMIN_CLASS_ACTIONS, NETWORK_GRANT, NETWORK_GRANT_ADMIN, NETWORK_JOIN,
    NETWORK_META_ACTIONS, NETWORK_PROFILES_WRITE, NETWORK_SEGMENTS_WRITE, NetworkSegment,
    NetworkSegmentKind, NetworkSegmentPath, NetworkSegmentUpdate, NetworkWriteClearance,
    NetworkWriteTarget, NewNetworkSegment, ReplyProfile, branch_node_id, is_network_action,
    is_reserved_resource_type, network_root_id, site_node_id,
};
use axiam_core::models::permission::{Permission, PermissionEffect, PermissionGrant};
use axiam_core::models::radius_reply::ReplyProfileInput;
use axiam_core::models::resource::Resource;
use axiam_core::models::role::{Role, RoleAssignment, RoleSubjectAssignment};
use axiam_core::repository::{
    CertificateRepository, NetworkPolicyRepository, NetworkSegmentRepository, PermissionRepository,
    ReplyProfileRepository, ResourceRepository, RoleRepository,
};
use uuid::Uuid;

use crate::AuthorizationEngine;
use crate::types::{AccessDecision, AccessRequest, SubjectScope};

// ---------------------------------------------------------------------------
// Audit vocabulary (design note §5.4)
// ---------------------------------------------------------------------------

/// A reply-profile write refused.
pub const AUDIT_PROFILE_WRITE_REFUSED: &str = "reply_profile.write_refused";
/// A segment write refused.
pub const AUDIT_SEGMENT_WRITE_REFUSED: &str = "network_segment.write_refused";
/// An assignment of a network-sensitive role refused.
pub const AUDIT_ROLE_ASSIGN_REFUSED: &str = "network_role.assign_refused";
/// An unassignment of a network-sensitive role refused.
pub const AUDIT_ROLE_UNASSIGN_REFUSED: &str = "network_role.unassign_refused";
/// A grant or revoke of a `network:` permission on a role refused.
pub const AUDIT_ROLE_GRANT_REFUSED: &str = "network_role.grant_refused";
/// An update or delete of a network-sensitive role refused.
pub const AUDIT_ROLE_WRITE_REFUSED: &str = "network_role.write_refused";
/// A create, rename or delete of a permission in the reserved namespace
/// refused.
pub const AUDIT_PERMISSION_WRITE_REFUSED: &str = "network_permission.write_refused";
/// A generic resource write into, under or out of the reserved subtree refused.
pub const AUDIT_RESOURCE_WRITE_REFUSED: &str = "network_resource.write_refused";
/// A certificate bind refused (§5.3's binding rows, H6).
pub const AUDIT_BINDING_REFUSED: &str = "certificate_binding.refused";

// ---------------------------------------------------------------------------
// What the function reads
// ---------------------------------------------------------------------------

/// The authorization check the function asks, at write time.
///
/// The engine's evaluation, **uncached** (see
/// [`AuthorizationEngine::check_access_uncached`]). Implemented here for the
/// engine; the REST layer implements it for its type-erased checker, whose
/// test doubles answer from a fixed rule.
pub trait WriteTimeAccess: Send + Sync {
    /// Evaluate `request` as it stands now, deny-override in force.
    fn check_at_write_time(
        &self,
        request: &AccessRequest,
    ) -> impl Future<Output = AxiamResult<AccessDecision>> + Send;
}

impl<R, P, Res, S, G> WriteTimeAccess for AuthorizationEngine<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: axiam_core::repository::ScopeRepository,
    G: axiam_core::repository::GroupRepository,
{
    fn check_at_write_time(
        &self,
        request: &AccessRequest,
    ) -> impl Future<Output = AxiamResult<AccessDecision>> + Send {
        self.check_access_uncached(request)
    }
}

/// Who holds a role, by kind of subject.
#[derive(Debug, Clone, Default)]
pub struct RoleHolders {
    /// Users holding it directly.
    pub users: Vec<RoleSubjectAssignment>,
    /// Service accounts holding it directly.
    pub service_accounts: Vec<RoleSubjectAssignment>,
    /// Groups holding it.
    pub groups: Vec<RoleSubjectAssignment>,
}

impl RoleHolders {
    fn all(&self) -> impl Iterator<Item = &RoleSubjectAssignment> {
        self.users
            .iter()
            .chain(&self.service_accounts)
            .chain(&self.groups)
    }
}

/// The reads the function makes. Tenant-scoped like the repositories it is
/// built over ([`RepositoryGateStore`]).
pub trait NetworkGateStore: Send + Sync {
    /// One role. `NotFound` when it is not this tenant's.
    fn role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Role>> + Send;
    /// A role's grants, with their effect and scopes.
    fn role_grants(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<PermissionGrant>>> + Send;
    /// Who holds a role.
    fn role_holders(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> impl Future<Output = AxiamResult<RoleHolders>> + Send;
    /// A subject's role assignments, direct and through groups.
    fn subject_assignments(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<RoleAssignment>>> + Send;
    /// A group's role assignments.
    fn group_assignments(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Vec<RoleAssignment>>> + Send;
    /// One permission. `NotFound` when it is not this tenant's.
    fn permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Permission>> + Send;
    /// One resource, or `None` when it does not exist in this tenant.
    fn resource(
        &self,
        tenant_id: Uuid,
        resource_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<Resource>>> + Send;
    /// One segment. `NotFound` when it is not this tenant's.
    fn segment(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
    ) -> impl Future<Output = AxiamResult<NetworkSegment>> + Send;
    /// A segment's profile, or `None`.
    fn profile(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<ReplyProfile>>> + Send;
    /// The tenant's current `Session-Timeout` cap.
    fn session_timeout_cap(&self, tenant_id: Uuid)
    -> impl Future<Output = AxiamResult<u32>> + Send;
    /// The service account a certificate is bound to now, if any.
    fn bound_service_account(
        &self,
        certificate_id: Uuid,
    ) -> impl Future<Output = AxiamResult<Option<Uuid>>> + Send;
}

/// [`NetworkGateStore`] over `axiam-core`'s repository traits.
pub struct RepositoryGateStore<'a, R, P, Res, Seg, Pro, Pol, Cert> {
    /// Roles and assignments.
    pub roles: &'a R,
    /// Permissions and grants.
    pub permissions: &'a P,
    /// The resource tree.
    pub resources: &'a Res,
    /// Network segments.
    pub segments: &'a Seg,
    /// Reply profiles.
    pub profiles: &'a Pro,
    /// The tenant's network policy.
    pub policy: &'a Pol,
    /// Certificates and their bindings.
    pub certificates: &'a Cert,
}

fn not_found_is_none<T>(r: AxiamResult<T>) -> AxiamResult<Option<T>> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(axiam_core::error::AxiamError::NotFound { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

impl<R, P, Res, Seg, Pro, Pol, Cert> NetworkGateStore
    for RepositoryGateStore<'_, R, P, Res, Seg, Pro, Pol, Cert>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    Seg: NetworkSegmentRepository,
    Pro: ReplyProfileRepository,
    Pol: NetworkPolicyRepository,
    Cert: CertificateRepository,
{
    async fn role(&self, tenant_id: Uuid, role_id: Uuid) -> AxiamResult<Role> {
        self.roles.get_by_id(tenant_id, role_id).await
    }
    async fn role_grants(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Vec<PermissionGrant>> {
        self.permissions
            .get_role_permission_grants(tenant_id, role_id)
            .await
    }
    async fn role_holders(&self, tenant_id: Uuid, role_id: Uuid) -> AxiamResult<RoleHolders> {
        Ok(RoleHolders {
            users: self
                .roles
                .get_role_user_assignments(tenant_id, role_id)
                .await?,
            service_accounts: self
                .roles
                .get_role_service_account_assignments(tenant_id, role_id)
                .await?,
            groups: self
                .roles
                .get_role_group_assignments(tenant_id, role_id)
                .await?,
        })
    }
    async fn subject_assignments(
        &self,
        tenant_id: Uuid,
        subject_id: Uuid,
    ) -> AxiamResult<Vec<RoleAssignment>> {
        self.roles
            .get_user_role_assignments(tenant_id, subject_id)
            .await
    }
    async fn group_assignments(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> AxiamResult<Vec<RoleAssignment>> {
        self.roles
            .get_group_role_assignments(tenant_id, group_id)
            .await
    }
    async fn permission(&self, tenant_id: Uuid, permission_id: Uuid) -> AxiamResult<Permission> {
        self.permissions.get_by_id(tenant_id, permission_id).await
    }
    async fn resource(&self, tenant_id: Uuid, resource_id: Uuid) -> AxiamResult<Option<Resource>> {
        not_found_is_none(self.resources.get_by_id(tenant_id, resource_id).await)
    }
    async fn segment(&self, tenant_id: Uuid, segment_id: Uuid) -> AxiamResult<NetworkSegment> {
        self.segments.get(tenant_id, segment_id).await
    }
    async fn profile(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
    ) -> AxiamResult<Option<ReplyProfile>> {
        not_found_is_none(self.profiles.get_by_segment(tenant_id, segment_id).await)
    }
    async fn session_timeout_cap(&self, tenant_id: Uuid) -> AxiamResult<u32> {
        Ok(self.policy.get(tenant_id).await?.session_timeout_max_secs)
    }
    async fn bound_service_account(&self, certificate_id: Uuid) -> AxiamResult<Option<Uuid>> {
        self.certificates
            .get_bound_service_account(certificate_id)
            .await
    }
}

// ---------------------------------------------------------------------------
// The question
// ---------------------------------------------------------------------------

/// The writer: the authenticated principal asking for the write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateWriter {
    /// The tenant being acted upon.
    pub tenant_id: Uuid,
    /// The writer's subject id (a user or a service account).
    pub subject_id: Uuid,
    /// Where the writer's grants live. An organization-level writer acting on
    /// a tenant carries only its global grants.
    pub subject_scope: SubjectScope,
}

/// Who a role is assigned to or unassigned from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grantee {
    /// A user.
    User(Uuid),
    /// A service account (a device, for `network:join`).
    ServiceAccount(Uuid),
    /// A group. Never for a network-sensitive role (§4.2 rule 2).
    Group(Uuid),
}

impl Grantee {
    fn describe(self) -> (&'static str, String) {
        match self {
            Self::User(id) => ("user", id.to_string()),
            Self::ServiceAccount(id) => ("service_account", id.to_string()),
            Self::Group(id) => ("group", id.to_string()),
        }
    }
}

/// One write the function decides. Each variant is one route's write.
#[derive(Debug, Clone, Copy)]
pub enum NetworkWrite<'a> {
    /// Create or replace a segment's reply profile (H1–H6).
    ProfileWrite {
        /// The owning segment.
        segment_id: Uuid,
        /// The profile as it would be stored.
        input: &'a ReplyProfileInput,
    },
    /// Delete a segment's reply profile (H1 only: it narrows).
    ProfileDelete {
        /// The owning segment.
        segment_id: Uuid,
    },
    /// Create a segment (`network:segments_write` at its parent).
    SegmentCreate {
        /// The segment as it would be created.
        input: &'a NewNetworkSegment,
    },
    /// Rewrite a segment's envelope (`network:segments_write` at the node).
    SegmentUpdate {
        /// The segment.
        segment_id: Uuid,
        /// The new envelope.
        update: &'a NetworkSegmentUpdate,
    },
    /// Delete a segment (`network:segments_write` at the node).
    SegmentDelete {
        /// The segment.
        segment_id: Uuid,
    },
    /// Assign a role (§5.3 rows 1, 2 and 4; §4.2 rules 2 and 3).
    RoleAssign {
        /// The role.
        role_id: Uuid,
        /// Who receives it.
        grantee: Grantee,
        /// The node it is assigned at; `None` is tenant-wide.
        resource_id: Option<Uuid>,
        /// The assignment's `inherit` flag, as it will be stored.
        inherit: bool,
    },
    /// Unassign a role (§5.3 row 3).
    RoleUnassign {
        /// The role.
        role_id: Uuid,
        /// Who loses it.
        grantee: Grantee,
        /// The node of the assignment removed; `None` is the tenant-wide one.
        resource_id: Option<Uuid>,
    },
    /// Update a role (§4.2 rule 1 on `is_global`).
    RoleUpdate {
        /// The role.
        role_id: Uuid,
        /// The requested `is_global`, when the update names one.
        is_global: Option<bool>,
    },
    /// Delete a role (§5.3 row 6).
    RoleDelete {
        /// The role.
        role_id: Uuid,
    },
    /// Grant a permission to a role (§5.3 row 5; §4.2 rules 1–3).
    PermissionGrant {
        /// The role.
        role_id: Uuid,
        /// The permission.
        permission_id: Uuid,
        /// Allow or deny.
        effect: PermissionEffect,
        /// The grant's scope constraints.
        scope_ids: &'a [Uuid],
    },
    /// Revoke a permission from a role (§5.3 row 5).
    PermissionRevoke {
        /// The role.
        role_id: Uuid,
        /// The permission.
        permission_id: Uuid,
    },
    /// Create a permission (§4.2: the namespace is reserved).
    PermissionCreate {
        /// The requested action.
        action: &'a str,
    },
    /// Update a permission (no rename into or out of the namespace).
    PermissionUpdate {
        /// The permission.
        permission_id: Uuid,
        /// The requested new action, when the update names one.
        action: Option<&'a str>,
    },
    /// Delete a permission (none of the reserved catalogue).
    PermissionDelete {
        /// The permission.
        permission_id: Uuid,
    },
    /// Bind a certificate to a service account (§5.3 binding rows, H6).
    CertificateBind {
        /// The certificate.
        certificate_id: Uuid,
        /// The service account it would authenticate as.
        service_account_id: Uuid,
    },
    /// Create a resource through a generic route (§4.1).
    ResourceCreate {
        /// The requested `resource_type`.
        resource_type: &'a str,
        /// The requested parent.
        parent_id: Option<Uuid>,
    },
    /// Update a resource through a generic route (§4.1).
    ResourceUpdate {
        /// The resource.
        resource_id: Uuid,
        /// The requested new `resource_type`, when named.
        resource_type: Option<&'a str>,
        /// The requested new parent, when named (`Some(None)` detaches).
        parent_id: Option<Option<Uuid>>,
    },
    /// Delete a resource through a generic route (§4.1).
    ResourceDelete {
        /// The resource.
        resource_id: Uuid,
    },
}

// ---------------------------------------------------------------------------
// The answer
// ---------------------------------------------------------------------------

/// A write the function allows.
#[derive(Debug)]
#[must_use = "a clearance is the proof the gate ran; drop it only after the write"]
pub struct GateClearance {
    network_sensitive: bool,
    token: Option<NetworkWriteClearance>,
}

impl GateClearance {
    fn plain(network_sensitive: bool) -> Self {
        Self {
            network_sensitive,
            token: None,
        }
    }

    fn with_token(token: NetworkWriteClearance) -> Self {
        Self {
            network_sensitive: true,
            token: Some(token),
        }
    }

    /// Whether the write touched the network namespace at all. `false` for a
    /// role, permission or resource write the function had nothing to add to.
    #[must_use]
    pub fn is_network_sensitive(&self) -> bool {
        self.network_sensitive
    }

    /// The clearance a segment or profile repository write demands; `None`
    /// for every other kind of write.
    #[must_use]
    pub fn into_write_clearance(self) -> Option<NetworkWriteClearance> {
        self.token
    }
}

/// How a refusal reaches the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalStatus {
    /// `403`: the writer lacks a permission at a node, or the write is one no
    /// permission allows this writer to make (H6).
    Forbidden,
    /// `400`: the write is not legal for anyone (a reserved name, a global or
    /// group-held network role, a deny with `inherit: false`, …).
    Invalid,
}

/// The permission the writer lacks, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingPermission {
    /// The action, e.g. `network:grant`.
    pub action: String,
    /// The node it was checked on.
    pub node: Uuid,
}

/// A write the function refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateRefusal {
    /// `403` or `400`.
    pub status: RefusalStatus,
    /// The internal reason, for the audit row: `H1` … `H6`, `H3:envelope:…`,
    /// `4.1:reserved-subtree`, `4.2:rule-1` … `4.2:rule-3`,
    /// `4.2:reserved-namespace`, `4.2:not-grantable`, `4.2:scoped-grant`,
    /// `5.3:assign`, `5.3:unassign`, `5.3:permission`, `5.3:role-delete`,
    /// `5.3:bind`.
    pub rule: &'static str,
    /// For a `403`, the permission and node the response names.
    pub missing: Option<MissingPermission>,
    /// A message for the response body. Names no other subject's grants.
    pub message: String,
    /// The audit action the refusal is recorded under (§5.4).
    pub audit_action: &'static str,
    /// The values the write would have replaced.
    pub before: Vec<(&'static str, String)>,
    /// The values the write asked for.
    pub after: Vec<(&'static str, String)>,
}

/// The function's verdict: a clearance or a refusal. Infrastructure failures
/// are the outer `AxiamResult`.
pub type GateVerdict = Result<GateClearance, GateRefusal>;

// ---------------------------------------------------------------------------
// The function
// ---------------------------------------------------------------------------

/// Decide one network-relevant write, at write time (design note §5.1).
///
/// See the module documentation for what each [`NetworkWrite`] is checked
/// against. A write that touches nothing in the `network:` namespace is
/// cleared with [`GateClearance::is_network_sensitive`] `false` and costs the
/// reads needed to know that (the role's grants, the permission's action, the
/// resource's type).
///
/// # Errors
///
/// Only what the reads return: `NotFound` for a segment that is not the
/// tenant's, and datastore failures. A role or permission that is not the
/// tenant's is cleared, not refused: the write cannot confer anything, and the
/// repository answers it as it did before this function existed. A refusal is
/// not an error.
pub async fn authorize_network_write<A, S>(
    access: &A,
    store: &S,
    writer: GateWriter,
    write: NetworkWrite<'_>,
) -> AxiamResult<GateVerdict>
where
    A: WriteTimeAccess + ?Sized,
    S: NetworkGateStore + ?Sized,
{
    let gate = Gate {
        access,
        store,
        writer,
    };
    match write {
        NetworkWrite::ProfileWrite { segment_id, input } => {
            gate.profile_write(segment_id, input).await
        }
        NetworkWrite::ProfileDelete { segment_id } => gate.profile_delete(segment_id).await,
        NetworkWrite::SegmentCreate { input } => gate.segment_create(input).await,
        NetworkWrite::SegmentUpdate { segment_id, update } => {
            gate.segment_update(segment_id, update).await
        }
        NetworkWrite::SegmentDelete { segment_id } => gate.segment_delete(segment_id).await,
        NetworkWrite::RoleAssign {
            role_id,
            grantee,
            resource_id,
            inherit,
        } => {
            gate.role_assign(role_id, grantee, resource_id, inherit)
                .await
        }
        NetworkWrite::RoleUnassign {
            role_id,
            grantee,
            resource_id,
        } => gate.role_unassign(role_id, grantee, resource_id).await,
        NetworkWrite::RoleUpdate { role_id, is_global } => {
            gate.role_update(role_id, is_global).await
        }
        NetworkWrite::RoleDelete { role_id } => gate.role_delete(role_id).await,
        NetworkWrite::PermissionGrant {
            role_id,
            permission_id,
            effect,
            scope_ids,
        } => {
            gate.permission_grant(role_id, permission_id, effect, scope_ids)
                .await
        }
        NetworkWrite::PermissionRevoke {
            role_id,
            permission_id,
        } => gate.permission_revoke(role_id, permission_id).await,
        NetworkWrite::PermissionCreate { action } => gate.permission_create(action),
        NetworkWrite::PermissionUpdate {
            permission_id,
            action,
        } => gate.permission_update(permission_id, action).await,
        NetworkWrite::PermissionDelete { permission_id } => {
            gate.permission_delete(permission_id).await
        }
        NetworkWrite::CertificateBind {
            certificate_id,
            service_account_id,
        } => {
            gate.certificate_bind(certificate_id, service_account_id)
                .await
        }
        NetworkWrite::ResourceCreate {
            resource_type,
            parent_id,
        } => gate.resource_create(resource_type, parent_id).await,
        NetworkWrite::ResourceUpdate {
            resource_id,
            resource_type,
            parent_id,
        } => {
            gate.resource_update(resource_id, resource_type, parent_id)
                .await
        }
        NetworkWrite::ResourceDelete { resource_id } => gate.resource_delete(resource_id).await,
    }
}

// ---------------------------------------------------------------------------
// What a role's grants say about the network
// ---------------------------------------------------------------------------

/// A role's grants in the `network:` namespace.
#[derive(Debug, Default)]
struct NetworkGrants {
    /// Any `network:` grant at all: the role is network-sensitive (§4.2).
    any: bool,
    /// Any `network:` grant with effect deny.
    any_deny: bool,
    /// An allow of `network:join`.
    join_allow: bool,
    /// A deny of `network:join` (quarantine).
    join_deny: bool,
    /// Allows of a meta permission or of the administrative class: what an
    /// assigner must hold to confer.
    delegated: BTreeSet<String>,
}

impl NetworkGrants {
    fn of(grants: &[PermissionGrant]) -> Self {
        let mut out = Self::default();
        for g in grants {
            let action = g.permission.action.as_str();
            if !is_network_action(action) {
                continue;
            }
            out.any = true;
            let deny = g.effect == PermissionEffect::Deny;
            out.any_deny |= deny;
            if action == NETWORK_JOIN {
                if deny {
                    out.join_deny = true;
                } else {
                    out.join_allow = true;
                }
            } else if !deny
                && (NETWORK_META_ACTIONS.contains(&action)
                    || NETWORK_ADMIN_CLASS_ACTIONS.contains(&action))
            {
                out.delegated.insert(action.to_owned());
            }
        }
        out
    }
}

struct Gate<'g, A: ?Sized, S: ?Sized> {
    access: &'g A,
    store: &'g S,
    writer: GateWriter,
}

fn refuse(
    status: RefusalStatus,
    rule: &'static str,
    audit_action: &'static str,
    message: impl Into<String>,
) -> GateRefusal {
    GateRefusal {
        status,
        rule,
        missing: None,
        message: message.into(),
        audit_action,
        before: Vec::new(),
        after: Vec::new(),
    }
}

fn describe_profile(p: &ReplyProfileInput) -> Vec<(&'static str, String)> {
    vec![
        ("dictionary", p.dictionary.clone()),
        ("session_timeout_secs", p.session_timeout_secs.to_string()),
        (
            "termination_action",
            p.termination_action.as_str().to_owned(),
        ),
        (
            "idle_timeout_secs",
            p.idle_timeout_secs
                .map_or_else(|| "none".to_owned(), |v| v.to_string()),
        ),
        (
            "filter_id",
            p.filter_id.clone().unwrap_or_else(|| "none".to_owned()),
        ),
        (
            "service_type",
            p.service_type
                .map_or_else(|| "none".to_owned(), |s| s.as_str().to_owned()),
        ),
    ]
}

fn describe_stored_profile(p: Option<&ReplyProfile>) -> Vec<(&'static str, String)> {
    let Some(p) = p else {
        return vec![("profile", "none".to_owned())];
    };
    vec![
        ("dictionary", p.dictionary.clone()),
        ("session_timeout_secs", p.session_timeout_secs.to_string()),
        (
            "termination_action",
            p.termination_action.as_str().to_owned(),
        ),
        (
            "idle_timeout_secs",
            p.idle_timeout_secs
                .map_or_else(|| "none".to_owned(), |v| v.to_string()),
        ),
        (
            "filter_id",
            p.filter_id.clone().unwrap_or_else(|| "none".to_owned()),
        ),
        (
            "service_type",
            p.service_type
                .map_or_else(|| "none".to_owned(), |s| s.as_str().to_owned()),
        ),
        ("version", p.version.to_string()),
    ]
}

fn describe_segment(s: &NetworkSegment) -> Vec<(&'static str, String)> {
    vec![
        ("segment_id", s.id.to_string()),
        ("path", s.path()),
        ("kind", s.kind.as_str().to_owned()),
        ("vlan_id", s.vlan_id.to_string()),
        ("filter_ids", s.filter_ids.join(",")),
        (
            "rank",
            s.rank.map_or_else(|| "none".to_owned(), |r| r.to_string()),
        ),
        ("enabled", s.enabled.to_string()),
        ("version", s.version.to_string()),
    ]
}

fn describe_assignments(role_id: Uuid, held: &[RoleAssignment]) -> Vec<(&'static str, String)> {
    let nodes: Vec<String> = held
        .iter()
        .filter(|a| a.role.id == role_id)
        .map(|a| {
            format!(
                "{}{}",
                a.resource_id
                    .map_or_else(|| "tenant-wide".to_owned(), |r| r.to_string()),
                if a.inherit { "" } else { " (inherit: false)" }
            )
        })
        .collect();
    vec![(
        "assignments",
        if nodes.is_empty() {
            "none".to_owned()
        } else {
            nodes.join(",")
        },
    )]
}

impl<A, S> Gate<'_, A, S>
where
    A: WriteTimeAccess + ?Sized,
    S: NetworkGateStore + ?Sized,
{
    fn tenant(&self) -> Uuid {
        self.writer.tenant_id
    }

    fn root(&self) -> Uuid {
        network_root_id(self.tenant())
    }

    /// A role or permission that is not the tenant's is not this function's
    /// to refuse: the write names nothing that could confer a network grant,
    /// and the repository answers it as it always has (`404`, or the
    /// cross-tenant `403` of CQ-B07). Clearing it keeps those answers
    /// unchanged.
    fn found<T>(&self, read: AxiamResult<T>) -> AxiamResult<Option<T>> {
        not_found_is_none(read)
    }

    /// Whether `subject` holds `action` on `node` now, with `scope`.
    async fn subject_holds(
        &self,
        subject_id: Uuid,
        scope: SubjectScope,
        action: &str,
        node: Uuid,
    ) -> AxiamResult<bool> {
        let request = AccessRequest {
            tenant_id: self.tenant(),
            subject_scope: scope,
            subject_id,
            action: action.to_owned(),
            resource_id: node,
            scope: None,
        };
        Ok(self
            .access
            .check_at_write_time(&request)
            .await?
            .is_allowed())
    }

    /// Whether the writer holds `action` on `node` now.
    async fn holds(&self, action: &str, node: Uuid) -> AxiamResult<bool> {
        self.subject_holds(
            self.writer.subject_id,
            self.writer.subject_scope,
            action,
            node,
        )
        .await
    }

    /// `Some(refusal)` naming the first of `actions` the writer does not hold
    /// at `node`.
    async fn require_all(
        &self,
        actions: &[&str],
        node: Uuid,
        rule: &'static str,
        audit_action: &'static str,
    ) -> AxiamResult<Option<GateRefusal>> {
        for action in actions {
            if !self.holds(action, node).await? {
                let mut r = refuse(
                    RefusalStatus::Forbidden,
                    rule,
                    audit_action,
                    format!("this write needs {action} on resource {node}"),
                );
                r.missing = Some(MissingPermission {
                    action: (*action).to_owned(),
                    node,
                });
                return Ok(Some(r));
            }
        }
        Ok(None)
    }

    /// The node a role assignment confers its grants at: the resource it
    /// names, or `/network` for a tenant-wide assignment or a global role
    /// (design note §5.3, row 1: "with no resource: then N = /network").
    fn assignment_node(&self, role: &Role, resource_id: Option<Uuid>) -> Uuid {
        if role.is_global {
            self.root()
        } else {
            resource_id.unwrap_or_else(|| self.root())
        }
    }

    fn clearance(&self, target: NetworkWriteTarget) -> GateClearance {
        GateClearance::with_token(NetworkWriteClearance::issued_by_the_network_gate(
            self.tenant(),
            self.writer.subject_id,
            target,
        ))
    }

    // -- profiles (H1–H6) --------------------------------------------------

    async fn profile_write(
        &self,
        segment_id: Uuid,
        input: &ReplyProfileInput,
    ) -> AxiamResult<GateVerdict> {
        let seg = self.store.segment(self.tenant(), segment_id).await?;
        let stored = self.store.profile(self.tenant(), segment_id).await?;
        let with_values = |mut r: GateRefusal| {
            r.before = describe_stored_profile(stored.as_ref());
            r.before.extend(describe_segment(&seg));
            r.after = describe_profile(input);
            r
        };
        let audit = AUDIT_PROFILE_WRITE_REFUSED;

        // H1: the profile's own permission. H2: writing it is a grant.
        for (rule, action) in [("H1", NETWORK_PROFILES_WRITE), ("H2", NETWORK_GRANT)] {
            if let Some(r) = self.require_all(&[action], seg.id, rule, audit).await? {
                return Ok(Err(with_values(r)));
            }
        }

        // H3: inside the envelope. The VLAN is derived from the segment and
        // cannot be named; the filter id must be one the segment declares and
        // the timeout within the tenant's cap.
        if let Some(filter_id) = input.filter_id.as_deref()
            && !seg.filter_ids.iter().any(|f| f == filter_id)
        {
            return Ok(Err(with_values(refuse(
                RefusalStatus::Forbidden,
                "H3:envelope:filter_id",
                audit,
                "filter_id is not one of the segment's declared filter_ids",
            ))));
        }
        let cap = self.store.session_timeout_cap(self.tenant()).await?;
        if input.session_timeout_secs > cap {
            return Ok(Err(with_values(refuse(
                RefusalStatus::Forbidden,
                "H3:envelope:session_timeout",
                audit,
                format!("session_timeout_secs is above the tenant's cap of {cap}"),
            ))));
        }

        // H4: conferring administrative login needs holding it, and the right
        // to confer it. Vacuous under option B, where the repository refuses
        // the class anyway; checked so that option A inherits the rule.
        if input.service_type.is_some_and(|s| s.is_admin_class())
            && let Some(r) = self
                .require_all(&[NETWORK_GRANT_ADMIN, NETWORK_ADMIN], seg.id, "H4", audit)
                .await?
        {
            return Ok(Err(with_values(r)));
        }

        // H5: the quarantine profile reaches every quarantined device of the
        // site; shaping it is a grant to all of them. (A profile write cannot
        // change the segment's kind: the input has no such field.)
        if seg.kind == NetworkSegmentKind::Quarantine {
            let site = site_node_id(self.tenant(), NetworkSegmentKind::Quarantine, &seg.site_key);
            if let Some(r) = self
                .require_all(&[NETWORK_GRANT], site, "H5", audit)
                .await?
            {
                return Ok(Err(with_values(r)));
            }
        }

        // H6: a subject that may join the segment does not shape what joining
        // gives, whatever it holds.
        if self.holds(NETWORK_JOIN, seg.id).await? {
            return Ok(Err(with_values(refuse(
                RefusalStatus::Forbidden,
                "H6",
                audit,
                "a subject that may be placed on this segment cannot write its profile",
            ))));
        }

        Ok(Ok(self.clearance(NetworkWriteTarget::ProfileWrite {
            segment_id,
        })))
    }

    async fn profile_delete(&self, segment_id: Uuid) -> AxiamResult<GateVerdict> {
        let seg = self.store.segment(self.tenant(), segment_id).await?;
        if let Some(mut r) = self
            .require_all(
                &[NETWORK_PROFILES_WRITE],
                seg.id,
                "H1",
                AUDIT_PROFILE_WRITE_REFUSED,
            )
            .await?
        {
            let stored = self.store.profile(self.tenant(), segment_id).await?;
            r.before = describe_stored_profile(stored.as_ref());
            r.after = vec![("profile", "deleted".to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(self.clearance(NetworkWriteTarget::ProfileDelete {
            segment_id,
        })))
    }

    // -- segments ----------------------------------------------------------

    async fn segment_create(&self, input: &NewNetworkSegment) -> AxiamResult<GateVerdict> {
        let audit = AUDIT_SEGMENT_WRITE_REFUSED;
        let after = || {
            vec![
                ("path", input.path.clone()),
                ("kind", input.kind.as_str().to_owned()),
                ("vlan_id", input.vlan_id.to_string()),
                ("filter_ids", input.filter_ids.join(",")),
                (
                    "rank",
                    input
                        .rank
                        .map_or_else(|| "none".to_owned(), |r| r.to_string()),
                ),
                ("enabled", input.enabled.to_string()),
            ]
        };
        let path = match NetworkSegmentPath::parse(&input.path) {
            Ok(p) => p,
            Err(e) => {
                let mut r = refuse(
                    RefusalStatus::Invalid,
                    "4.1:reserved-subtree",
                    audit,
                    e.to_string(),
                );
                r.after = after();
                return Ok(Err(r));
            }
        };
        // The parent is the site; one that does not exist yet is created by
        // this write under its own parent, so the check climbs to the nearest
        // node that exists (and to `/network` itself, which answers only to
        // tenant-wide grants until the first segment makes it).
        let site = site_node_id(self.tenant(), path.kind, &path.site_key);
        let branch = branch_node_id(self.tenant(), path.kind);
        let mut parent = self.root();
        for node in [site, branch] {
            if self.store.resource(self.tenant(), node).await?.is_some() {
                parent = node;
                break;
            }
        }
        if let Some(mut r) = self
            .require_all(
                &[NETWORK_SEGMENTS_WRITE],
                parent,
                "4.2:segments_write",
                audit,
            )
            .await?
        {
            r.before = vec![("segment", "none".to_owned())];
            r.after = after();
            return Ok(Err(r));
        }
        Ok(Ok(self.clearance(NetworkWriteTarget::SegmentCreate {
            path: input.path.clone(),
        })))
    }

    async fn segment_update(
        &self,
        segment_id: Uuid,
        update: &NetworkSegmentUpdate,
    ) -> AxiamResult<GateVerdict> {
        let seg = self.store.segment(self.tenant(), segment_id).await?;
        let audit = AUDIT_SEGMENT_WRITE_REFUSED;
        let with_values = |mut r: GateRefusal| {
            r.before = describe_segment(&seg);
            r.after = vec![
                ("vlan_id", update.vlan_id.to_string()),
                ("filter_ids", update.filter_ids.join(",")),
                (
                    "rank",
                    update
                        .rank
                        .map_or_else(|| "none".to_owned(), |r| r.to_string()),
                ),
                ("enabled", update.enabled.to_string()),
                ("expected_version", update.expected_version.to_string()),
            ];
            r
        };
        if let Some(r) = self
            .require_all(
                &[NETWORK_SEGMENTS_WRITE],
                seg.id,
                "4.2:segments_write",
                audit,
            )
            .await?
        {
            return Ok(Err(with_values(r)));
        }
        // H6's reasoning applies to the envelope as much as to the profile: the
        // VLAN is what joining the segment gives.
        if self.holds(NETWORK_JOIN, seg.id).await? {
            return Ok(Err(with_values(refuse(
                RefusalStatus::Forbidden,
                "H6",
                audit,
                "a subject that may be placed on this segment cannot rewrite its envelope",
            ))));
        }
        Ok(Ok(self.clearance(NetworkWriteTarget::SegmentUpdate {
            segment_id,
        })))
    }

    async fn segment_delete(&self, segment_id: Uuid) -> AxiamResult<GateVerdict> {
        let seg = self.store.segment(self.tenant(), segment_id).await?;
        if let Some(mut r) = self
            .require_all(
                &[NETWORK_SEGMENTS_WRITE],
                seg.id,
                "4.2:segments_write",
                AUDIT_SEGMENT_WRITE_REFUSED,
            )
            .await?
        {
            r.before = describe_segment(&seg);
            r.after = vec![("segment", "deleted".to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(self.clearance(NetworkWriteTarget::SegmentDelete {
            segment_id,
        })))
    }

    // -- role assignment (§5.3, §4.2) --------------------------------------

    async fn role_assign(
        &self,
        role_id: Uuid,
        grantee: Grantee,
        resource_id: Option<Uuid>,
        inherit: bool,
    ) -> AxiamResult<GateVerdict> {
        let Some(role) = self.found(self.store.role(self.tenant(), role_id).await)? else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        let grants = NetworkGrants::of(&self.store.role_grants(self.tenant(), role_id).await?);
        if !grants.any {
            return Ok(Ok(GateClearance::plain(false)));
        }
        let audit = AUDIT_ROLE_ASSIGN_REFUSED;
        let node = self.assignment_node(&role, resource_id);
        let held = match grantee {
            Grantee::Group(id) => self.store.group_assignments(self.tenant(), id).await?,
            Grantee::User(id) | Grantee::ServiceAccount(id) => {
                self.store.subject_assignments(self.tenant(), id).await?
            }
        };
        let (kind, who) = grantee.describe();
        let with_values = |mut r: GateRefusal| {
            r.before = describe_assignments(role_id, &held);
            r.after = vec![
                ("role_id", role_id.to_string()),
                ("role", role.name.clone()),
                (kind, who.clone()),
                ("node", node.to_string()),
                ("inherit", inherit.to_string()),
            ];
            r
        };

        // Rule 2: never through a group. Membership is written by
        // `groups:add_member`, SCIM and directory sync, and each would become a
        // network grant.
        if matches!(grantee, Grantee::Group(_)) {
            return Ok(Err(with_values(refuse(
                RefusalStatus::Invalid,
                "4.2:rule-2",
                audit,
                "a role carrying a network: permission is never assigned to a group",
            ))));
        }
        // Rule 3: a network deny with `inherit: false` is a quarantine that
        // silently reaches nothing below its node.
        if grants.any_deny && !inherit {
            return Ok(Err(with_values(refuse(
                RefusalStatus::Invalid,
                "4.2:rule-3",
                audit,
                "a role carrying a network: deny cannot be assigned with inherit: false",
            ))));
        }

        // §5.3: joining (allow or deny) needs network:grant at N; every meta
        // permission conferred needs holding it at N.
        let mut needed: Vec<&str> = Vec::new();
        if grants.join_allow || grants.join_deny {
            needed.push(NETWORK_GRANT);
        }
        for a in &grants.delegated {
            if !needed.contains(&a.as_str()) {
                needed.push(a.as_str());
            }
        }
        if let Some(r) = self.require_all(&needed, node, "5.3:assign", audit).await? {
            return Ok(Err(with_values(r)));
        }
        Ok(Ok(GateClearance::plain(true)))
    }

    async fn role_unassign(
        &self,
        role_id: Uuid,
        grantee: Grantee,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<GateVerdict> {
        let Some(role) = self.found(self.store.role(self.tenant(), role_id).await)? else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        let grants = NetworkGrants::of(&self.store.role_grants(self.tenant(), role_id).await?);
        if !grants.any {
            return Ok(Ok(GateClearance::plain(false)));
        }
        // Removing a deny widens access (a quarantine released): it takes
        // network:grant where the deny was. Removing an allow only narrows.
        if grants.any_deny {
            let node = self.assignment_node(&role, resource_id);
            if let Some(mut r) = self
                .require_all(
                    &[NETWORK_GRANT],
                    node,
                    "5.3:unassign",
                    AUDIT_ROLE_UNASSIGN_REFUSED,
                )
                .await?
            {
                let (kind, who) = grantee.describe();
                r.before = vec![
                    ("role_id", role_id.to_string()),
                    ("role", role.name.clone()),
                    (kind, who),
                    ("node", node.to_string()),
                ];
                r.after = vec![("assignment", "removed".to_owned())];
                return Ok(Err(r));
            }
        }
        Ok(Ok(GateClearance::plain(true)))
    }

    async fn role_update(
        &self,
        role_id: Uuid,
        is_global: Option<bool>,
    ) -> AxiamResult<GateVerdict> {
        let Some(role) = self.found(self.store.role(self.tenant(), role_id).await)? else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        let grants = NetworkGrants::of(&self.store.role_grants(self.tenant(), role_id).await?);
        if !grants.any {
            return Ok(Ok(GateClearance::plain(false)));
        }
        // Rule 1: a global role is everywhere by definition, and global grants
        // are what an organization-level subject carries across tenants.
        if is_global == Some(true) && !role.is_global {
            let mut r = refuse(
                RefusalStatus::Invalid,
                "4.2:rule-1",
                AUDIT_ROLE_WRITE_REFUSED,
                "a role carrying a network: permission cannot be made global",
            );
            r.before = vec![
                ("role_id", role_id.to_string()),
                ("is_global", "false".into()),
            ];
            r.after = vec![("is_global", "true".into())];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(true)))
    }

    async fn role_delete(&self, role_id: Uuid) -> AxiamResult<GateVerdict> {
        let Some(role) = self.found(self.store.role(self.tenant(), role_id).await)? else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        let grants = NetworkGrants::of(&self.store.role_grants(self.tenant(), role_id).await?);
        if !grants.any {
            return Ok(Ok(GateClearance::plain(false)));
        }
        // Deleting a role that carries a deny releases every assignment of it
        // at once: as an unassignment, at /network.
        if grants.any_deny
            && let Some(mut r) = self
                .require_all(
                    &[NETWORK_GRANT],
                    self.root(),
                    "5.3:role-delete",
                    AUDIT_ROLE_WRITE_REFUSED,
                )
                .await?
        {
            r.before = vec![("role_id", role_id.to_string()), ("role", role.name)];
            r.after = vec![("role", "deleted".to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(true)))
    }

    // -- grants on a role (§5.3 row 5, §4.2) ---------------------------------

    async fn permission_grant(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
        effect: PermissionEffect,
        scope_ids: &[Uuid],
    ) -> AxiamResult<GateVerdict> {
        let Some(permission) =
            self.found(self.store.permission(self.tenant(), permission_id).await)?
        else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        if !is_network_action(&permission.action) {
            return Ok(Ok(GateClearance::plain(false)));
        }
        let Some(role) = self.found(self.store.role(self.tenant(), role_id).await)? else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        let current = self.store.role_grants(self.tenant(), role_id).await?;
        let audit = AUDIT_ROLE_GRANT_REFUSED;
        let action = permission.action.as_str();
        let effect_name = match effect {
            PermissionEffect::Allow => "allow",
            PermissionEffect::Deny => "deny",
        };
        let with_values = |mut r: GateRefusal| {
            r.before = vec![
                ("role_id", role_id.to_string()),
                ("role", role.name.clone()),
                (
                    "grant",
                    current
                        .iter()
                        .find(|g| g.permission.id == permission_id)
                        .map_or_else(
                            || "none".to_owned(),
                            |g| match g.effect {
                                PermissionEffect::Allow => "allow".to_owned(),
                                PermissionEffect::Deny => "deny".to_owned(),
                            },
                        ),
                ),
            ];
            r.after = vec![
                ("permission", action.to_owned()),
                ("effect", effect_name.to_owned()),
                ("scope_ids", scope_ids.len().to_string()),
            ];
            r
        };
        let invalid = |rule: &'static str, msg: &str| {
            Ok(Err(with_values(refuse(
                RefusalStatus::Invalid,
                rule,
                audit,
                msg,
            ))))
        };

        if effect == PermissionEffect::Allow && NETWORK_ADMIN_CLASS_ACTIONS.contains(&action) {
            return invalid(
                "4.2:not-grantable",
                "network:admin and network:grant_admin are not grantable under option B",
            );
        }
        if !scope_ids.is_empty() {
            // A scoped network grant matches only scoped checks, and the
            // placement check is unscoped: a scoped deny would be a quarantine
            // that reaches nothing.
            return invalid(
                "4.2:scoped-grant",
                "a network: permission is granted without scopes",
            );
        }
        if role.is_global {
            return invalid(
                "4.2:rule-1",
                "a network: permission cannot be granted to a global role",
            );
        }
        let holders = self.store.role_holders(self.tenant(), role_id).await?;
        if !holders.groups.is_empty() {
            return invalid(
                "4.2:rule-2",
                "a network: permission cannot be granted to a role a group holds",
            );
        }
        if effect == PermissionEffect::Deny && holders.all().any(|h| !h.inherit) {
            return invalid(
                "4.2:rule-3",
                "a network: deny cannot be granted to a role assigned with inherit: false",
            );
        }

        // It changes every existing assignment of the role at once.
        let mut needed = vec![NETWORK_GRANT];
        if effect == PermissionEffect::Allow
            && NETWORK_META_ACTIONS.contains(&action)
            && action != NETWORK_GRANT
        {
            needed.push(action);
        }
        if let Some(r) = self
            .require_all(&needed, self.root(), "5.3:permission", audit)
            .await?
        {
            return Ok(Err(with_values(r)));
        }
        Ok(Ok(GateClearance::plain(true)))
    }

    async fn permission_revoke(
        &self,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> AxiamResult<GateVerdict> {
        let Some(permission) =
            self.found(self.store.permission(self.tenant(), permission_id).await)?
        else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        if !is_network_action(&permission.action) {
            return Ok(Ok(GateClearance::plain(false)));
        }
        if let Some(mut r) = self
            .require_all(
                &[NETWORK_GRANT],
                self.root(),
                "5.3:permission",
                AUDIT_ROLE_GRANT_REFUSED,
            )
            .await?
        {
            let current = self.store.role_grants(self.tenant(), role_id).await?;
            r.before = vec![
                ("role_id", role_id.to_string()),
                ("permission", permission.action.clone()),
                (
                    "grant",
                    current
                        .iter()
                        .find(|g| g.permission.id == permission_id)
                        .map_or_else(
                            || "none".to_owned(),
                            |g| match g.effect {
                                PermissionEffect::Allow => "allow".to_owned(),
                                PermissionEffect::Deny => "deny".to_owned(),
                            },
                        ),
                ),
            ];
            r.after = vec![("grant", "revoked".to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(true)))
    }

    // -- the reserved namespace ----------------------------------------------

    fn permission_create(&self, action: &str) -> AxiamResult<GateVerdict> {
        if is_network_action(action) {
            let mut r = refuse(
                RefusalStatus::Invalid,
                "4.2:reserved-namespace",
                AUDIT_PERMISSION_WRITE_REFUSED,
                "the network: permission namespace is reserved",
            );
            r.after = vec![("action", action.to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(false)))
    }

    async fn permission_update(
        &self,
        permission_id: Uuid,
        action: Option<&str>,
    ) -> AxiamResult<GateVerdict> {
        let Some(current) =
            self.found(self.store.permission(self.tenant(), permission_id).await)?
        else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        let into = action.is_some_and(is_network_action);
        if is_network_action(&current.action) || into {
            let mut r = refuse(
                RefusalStatus::Invalid,
                "4.2:reserved-namespace",
                AUDIT_PERMISSION_WRITE_REFUSED,
                "a permission is not renamed into or out of the reserved network: namespace, \
                 and none of its permissions is changed",
            );
            r.before = vec![("action", current.action)];
            r.after = vec![("action", action.unwrap_or("unchanged").to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(false)))
    }

    async fn permission_delete(&self, permission_id: Uuid) -> AxiamResult<GateVerdict> {
        let Some(current) =
            self.found(self.store.permission(self.tenant(), permission_id).await)?
        else {
            return Ok(Ok(GateClearance::plain(false)));
        };
        if is_network_action(&current.action) {
            // Deleting `network:join` would drop every quarantine deny in one
            // write.
            let mut r = refuse(
                RefusalStatus::Invalid,
                "4.2:reserved-namespace",
                AUDIT_PERMISSION_WRITE_REFUSED,
                "the network: permissions are a seeded catalogue and are not deleted",
            );
            r.before = vec![("action", current.action)];
            r.after = vec![("permission", "deleted".to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(false)))
    }

    // -- certificate binding (§5.3, H6) ---------------------------------------

    async fn certificate_bind(
        &self,
        certificate_id: Uuid,
        service_account_id: Uuid,
    ) -> AxiamResult<GateVerdict> {
        let audit = AUDIT_BINDING_REFUSED;
        let before = self.store.bound_service_account(certificate_id).await?;
        let with_values = |mut r: GateRefusal| {
            r.before = vec![
                ("certificate_id", certificate_id.to_string()),
                (
                    "service_account_id",
                    before.map_or_else(|| "unbound".to_owned(), |s| s.to_string()),
                ),
            ];
            r.after = vec![("service_account_id", service_account_id.to_string())];
            r
        };

        // H6: a subject does not bind a certificate to itself, nor (the same
        // thing) through a certificate bound to the account being written: a
        // certificate-authenticated caller *is* that account.
        if self.writer.subject_id == service_account_id {
            return Ok(Err(with_values(refuse(
                RefusalStatus::Forbidden,
                "H6",
                audit,
                "a service account cannot bind a certificate to itself",
            ))));
        }

        // Placement is the pair (the account's joins, the binding). Every node
        // at which the account holds an effective `network:join` allow needs
        // the binder to hold `network:grant` there.
        let assignments = self
            .store
            .subject_assignments(self.tenant(), service_account_id)
            .await?;
        let mut nodes: BTreeSet<Uuid> = BTreeSet::new();
        let mut seen_roles: BTreeSet<Uuid> = BTreeSet::new();
        let mut join_roles: BTreeSet<Uuid> = BTreeSet::new();
        for a in assignments
            .iter()
            .filter(|a| a.reaches_tenant(self.tenant()))
        {
            if seen_roles.insert(a.role.id) {
                let grants =
                    NetworkGrants::of(&self.store.role_grants(self.tenant(), a.role.id).await?);
                if grants.join_allow {
                    join_roles.insert(a.role.id);
                }
            }
            if join_roles.contains(&a.role.id) {
                nodes.insert(self.assignment_node(&a.role, a.resource_id));
            }
        }
        for node in nodes {
            // Read with the engine's own evaluation: an allow a deny already
            // beats at the node is not one the binder must hold. Sound because
            // a network deny is never assigned with `inherit: false` (§4.2
            // rule 3), so a deny that beats the allow at its node beats it at
            // every node below.
            if !self
                .subject_holds(service_account_id, SubjectScope::Tenant, NETWORK_JOIN, node)
                .await?
            {
                continue;
            }
            if let Some(r) = self
                .require_all(&[NETWORK_GRANT], node, "5.3:bind", audit)
                .await?
            {
                return Ok(Err(with_values(r)));
            }
        }
        Ok(Ok(GateClearance::plain(true)))
    }

    // -- generic resources (§4.1) --------------------------------------------

    async fn is_reserved_node(&self, id: Uuid) -> AxiamResult<bool> {
        Ok(self
            .store
            .resource(self.tenant(), id)
            .await?
            .is_some_and(|r| is_reserved_resource_type(&r.resource_type)))
    }

    fn reserved_refusal(message: &str) -> GateRefusal {
        refuse(
            RefusalStatus::Invalid,
            "4.1:reserved-subtree",
            AUDIT_RESOURCE_WRITE_REFUSED,
            message,
        )
    }

    async fn resource_create(
        &self,
        resource_type: &str,
        parent_id: Option<Uuid>,
    ) -> AxiamResult<GateVerdict> {
        let after = vec![
            ("resource_type", resource_type.to_owned()),
            (
                "parent_id",
                parent_id.map_or_else(|| "none".to_owned(), |p| p.to_string()),
            ),
        ];
        if is_reserved_resource_type(resource_type) {
            let mut r = Self::reserved_refusal(
                "network_* resource types are written only through the network routes",
            );
            r.after = after;
            return Ok(Err(r));
        }
        if let Some(parent) = parent_id
            && self.is_reserved_node(parent).await?
        {
            let mut r = Self::reserved_refusal(
                "nothing is created under the reserved /network subtree through this route",
            );
            r.after = after;
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(false)))
    }

    async fn resource_update(
        &self,
        resource_id: Uuid,
        resource_type: Option<&str>,
        parent_id: Option<Option<Uuid>>,
    ) -> AxiamResult<GateVerdict> {
        let current = self.store.resource(self.tenant(), resource_id).await?;
        let mut refusal = None;
        if current
            .as_ref()
            .is_some_and(|r| is_reserved_resource_type(&r.resource_type))
        {
            refusal = Some(
                "a node of the reserved /network subtree is changed only through the network routes",
            );
        } else if resource_type.is_some_and(is_reserved_resource_type) {
            refusal = Some("a resource cannot take a network_* type");
        } else if let Some(Some(parent)) = parent_id
            && self.is_reserved_node(parent).await?
        {
            refusal = Some("a resource cannot be moved under the reserved /network subtree");
        }
        if let Some(message) = refusal {
            let mut r = Self::reserved_refusal(message);
            r.before = current.map_or_else(Vec::new, |c| {
                vec![
                    ("resource_type", c.resource_type),
                    (
                        "parent_id",
                        c.parent_id
                            .map_or_else(|| "none".to_owned(), |p| p.to_string()),
                    ),
                ]
            });
            r.after = vec![
                (
                    "resource_type",
                    resource_type.unwrap_or("unchanged").to_owned(),
                ),
                (
                    "parent_id",
                    match parent_id {
                        None => "unchanged".to_owned(),
                        Some(None) => "none".to_owned(),
                        Some(Some(p)) => p.to_string(),
                    },
                ),
            ];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(false)))
    }

    async fn resource_delete(&self, resource_id: Uuid) -> AxiamResult<GateVerdict> {
        if self.is_reserved_node(resource_id).await? {
            let mut r = Self::reserved_refusal(
                "a node of the reserved /network subtree is deleted only through the network routes",
            );
            r.before = vec![("resource_id", resource_id.to_string())];
            r.after = vec![("resource", "deleted".to_owned())];
            return Ok(Err(r));
        }
        Ok(Ok(GateClearance::plain(false)))
    }
}

#[cfg(test)]
mod tests;

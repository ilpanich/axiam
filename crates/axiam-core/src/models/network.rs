//! Network segments, their reply profiles and the tenant's session cap (RADIUS
//! D4, `claude_dev/radius-reply-profile-design.md` §3.5 and §4).
//!
//! # Segments are resources
//!
//! A segment is a node of the existing resource tree, in a **reserved
//! subtree**, so that RBAC, the hierarchy cascade and deny-override apply to it
//! unchanged (§4.1, maintainer decision D-5):
//!
//! ```text
//! /network                       network_root     (one per tenant, made on first use)
//! ├── /network/zones             network_branch   (kind = access)
//! │   └── /network/zones/hq      network_site     site_key = "hq"
//! │       └── …/hq/corp          network_segment  vlan 10, rank 10
//! └── /network/quarantine        network_branch   (kind = quarantine)
//!     └── /network/quarantine/hq network_site
//!         └── …/hq/q             network_segment  vlan 999
//! ```
//!
//! Quarantine is a **sibling branch**, never a descendant of `zones`:
//! deny-override cannot express "deny the subtree except this leaf", so a
//! quarantine segment under `zones` would be denied by the very rule that
//! quarantines. The fixed two-branch shape makes the correct placement the only
//! placement, and [`NetworkSegmentPath`] refuses every other.
//!
//! The segment's own row (a *sidecar* of its `resource` row, sharing its id)
//! holds what the tree cannot: the kind, the VLAN, the `Filter-Id` names the
//! segment's profile may choose from (its **envelope**) and the `rank` that
//! orders placement.
//!
//! # Two writers, one version
//!
//! Segments, profiles and the tenant policy are written conditionally on the
//! `version` read (plan §10, the two-writer rule). A profile write is also
//! conditional on the **owning segment's** version, so a concurrent change to
//! its `filter_ids` cannot slip a profile past an envelope that no longer holds.
//!
//! # What this module is not
//!
//! Who may write any of this (the H1 to H6 rule, §5.2) is the authorization
//! function's, not the repository's. The repository refuses only what it can
//! decide from the data: a path outside `/network`, a value outside the
//! dictionary, a `filter_id` outside the envelope.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AxiamError, AxiamResult};
use crate::models::radius_reply::{
    DEFAULT_SESSION_TIMEOUT_MAX_SECS, MAX_FILTER_IDS, ReplyProfileInput,
    SESSION_TIMEOUT_CAP_CEILING_SECS, SESSION_TIMEOUT_FLOOR_SECS, ServiceType, TerminationAction,
    is_valid_identifier, is_valid_vlan,
};

/// The name of the reserved root: `/network`.
pub const NETWORK_ROOT_NAME: &str = "network";
/// The branch that holds `kind = access` segments: `/network/zones`.
pub const ZONES_BRANCH: &str = "zones";
/// The branch that holds `kind = quarantine` segments: `/network/quarantine`.
pub const QUARANTINE_BRANCH: &str = "quarantine";

/// `resource_type` of `/network`.
pub const RESOURCE_TYPE_NETWORK_ROOT: &str = "network_root";
/// `resource_type` of `/network/zones` and `/network/quarantine`.
pub const RESOURCE_TYPE_NETWORK_BRANCH: &str = "network_branch";
/// `resource_type` of a site.
pub const RESOURCE_TYPE_NETWORK_SITE: &str = "network_site";
/// `resource_type` of a segment.
pub const RESOURCE_TYPE_NETWORK_SEGMENT: &str = "network_segment";

/// Whether `resource_type` is one of the reserved `network_*` types.
///
/// The generic resource routes refuse these (design note §4.1): moving a
/// resource is the one way to change access under deny-override without
/// changing a rule, so the tree under `/network` is written only through the
/// network repositories.
#[must_use]
pub fn is_reserved_resource_type(resource_type: &str) -> bool {
    resource_type.starts_with("network_")
}

/// What a segment is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSegmentKind {
    /// A segment a device may be placed on in normal operation. Lives under
    /// `/network/zones`.
    Access,
    /// The segment a quarantined device is placed on, and only when no access
    /// segment remains. Lives under `/network/quarantine`.
    Quarantine,
}

impl NetworkSegmentKind {
    /// The stored and wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Quarantine => "quarantine",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "access" => Some(Self::Access),
            "quarantine" => Some(Self::Quarantine),
            _ => None,
        }
    }

    /// The branch of the reserved subtree this kind lives under.
    #[must_use]
    pub const fn branch(self) -> &'static str {
        match self {
            Self::Access => ZONES_BRANCH,
            Self::Quarantine => QUARANTINE_BRANCH,
        }
    }
}

/// A segment's place in the reserved subtree, parsed from
/// `/network/{zones|quarantine}/<site>/<segment>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSegmentPath {
    /// The kind the branch implies.
    pub kind: NetworkSegmentKind,
    /// The site key. A site is a key, not a location: VLAN numbers are
    /// per-site facts. A single-site tenant uses `default`.
    pub site_key: String,
    /// The segment's name, unique within its site.
    pub name: String,
}

impl NetworkSegmentPath {
    /// Parse a segment path. Anything outside `/network`, anything but the
    /// four-level shape, and any component that is not a plain identifier
    /// (`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`) is `Validation`.
    pub fn parse(path: &str) -> AxiamResult<Self> {
        let outside = || AxiamError::Validation {
            message: "a network segment lives at /network/{zones|quarantine}/<site>/<segment>"
                .into(),
        };
        let rest = path.strip_prefix('/').ok_or_else(outside)?;
        let parts: Vec<&str> = rest.split('/').collect();
        let [root, branch, site, name] = parts[..] else {
            return Err(outside());
        };
        if root != NETWORK_ROOT_NAME {
            return Err(outside());
        }
        let kind = match branch {
            ZONES_BRANCH => NetworkSegmentKind::Access,
            QUARANTINE_BRANCH => NetworkSegmentKind::Quarantine,
            _ => return Err(outside()),
        };
        if !is_valid_identifier(site) || !is_valid_identifier(name) {
            return Err(AxiamError::Validation {
                message: "a site key and a segment name are letters, digits, '.', '_' and '-', \
                          at most 63 characters, starting with a letter or digit"
                    .into(),
            });
        }
        Ok(Self {
            kind,
            site_key: site.to_owned(),
            name: name.to_owned(),
        })
    }

    /// The path in its written form.
    #[must_use]
    pub fn render(&self) -> String {
        render_path(self.kind, &self.site_key, &self.name)
    }
}

/// `/network/<branch of kind>/<site>/<name>`.
#[must_use]
pub fn render_path(kind: NetworkSegmentKind, site_key: &str, name: &str) -> String {
    format!("/{NETWORK_ROOT_NAME}/{}/{site_key}/{name}", kind.branch())
}

/// A network segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSegment {
    /// The segment's id: also the id of its `resource` row, which is what
    /// `check_access` is asked about.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// The segment's name, unique within its site.
    pub name: String,
    /// The site key.
    pub site_key: String,
    /// Access or quarantine; fixed by the branch the segment lives under.
    pub kind: NetworkSegmentKind,
    /// The VLAN the tunnel attributes carry (1 to 4094), unique per
    /// `(tenant, site_key)`.
    pub vlan_id: u16,
    /// The `Filter-Id` names the segment's profile may choose from: its
    /// envelope. At most [`MAX_FILTER_IDS`], each a plain identifier.
    pub filter_ids: Vec<String>,
    /// Placement order among `kind = access` segments of a site (lowest wins),
    /// unique per `(tenant, site_key)`. `None` for a quarantine segment.
    pub rank: Option<u32>,
    /// Whether the segment is a placement candidate.
    pub enabled: bool,
    /// The version the next write must name. Starts at 1.
    pub version: u64,
    /// The administrator who created it.
    pub created_by: Uuid,
    /// The administrator who last wrote it.
    pub updated_by: Uuid,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last write time.
    pub updated_at: DateTime<Utc>,
}

impl NetworkSegment {
    /// The segment's path in the resource tree.
    #[must_use]
    pub fn path(&self) -> String {
        render_path(self.kind, &self.site_key, &self.name)
    }
}

/// What creating a segment takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewNetworkSegment {
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// Where the segment lives: `/network/{zones|quarantine}/<site>/<segment>`.
    /// The root, branch and site nodes are made on first use.
    pub path: String,
    /// The kind; must agree with the branch of `path`.
    pub kind: NetworkSegmentKind,
    /// The VLAN (1 to 4094).
    pub vlan_id: u16,
    /// The envelope's `Filter-Id` names.
    pub filter_ids: Vec<String>,
    /// The placement rank: required for `access`, absent for `quarantine`.
    pub rank: Option<u32>,
    /// Whether the segment starts as a candidate.
    pub enabled: bool,
    /// The writing administrator.
    pub actor: Uuid,
}

/// What rewriting a segment's envelope takes. The kind and the place in the
/// tree do not change here: moving a node is the one way to change access
/// under deny-override without changing a rule, and belongs to the route that
/// checks both parents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSegmentUpdate {
    /// The version the writer read. A stale one is `Conflict`.
    pub expected_version: u64,
    /// The VLAN (1 to 4094).
    pub vlan_id: u16,
    /// The envelope's `Filter-Id` names. Removing the name a stored profile
    /// uses is `Conflict`, naming the profile (design note §5.2).
    pub filter_ids: Vec<String>,
    /// The placement rank, as for [`NewNetworkSegment::rank`].
    pub rank: Option<u32>,
    /// Whether the segment is a candidate.
    pub enabled: bool,
    /// The writing administrator.
    pub actor: Uuid,
}

/// Check the data of a segment write that does not depend on the datastore.
///
/// `kind` is the segment's kind: access needs a rank, quarantine none.
pub fn validate_segment_fields(
    kind: NetworkSegmentKind,
    vlan_id: u16,
    filter_ids: &[String],
    rank: Option<u32>,
) -> AxiamResult<()> {
    let invalid = |message: &str| AxiamError::Validation {
        message: message.into(),
    };
    if !is_valid_vlan(vlan_id) {
        return Err(invalid("vlan_id must be between 1 and 4094"));
    }
    if filter_ids.len() > MAX_FILTER_IDS {
        return Err(invalid("a segment declares at most 32 filter_ids"));
    }
    for (i, id) in filter_ids.iter().enumerate() {
        if !is_valid_identifier(id) {
            return Err(invalid("a filter_id is not a valid Filter-Id name"));
        }
        if filter_ids[..i].contains(id) {
            return Err(invalid("filter_ids must not repeat a name"));
        }
    }
    match (kind, rank) {
        (NetworkSegmentKind::Access, None) => Err(invalid("an access segment needs a rank")),
        (NetworkSegmentKind::Quarantine, Some(_)) => {
            Err(invalid("a quarantine segment has no rank"))
        }
        _ => Ok(()),
    }
}

/// A segment's reply profile as read: **the effective one**, with the
/// `Session-Timeout` already clamped to the tenant's current cap (design note
/// §3.4) and `Idle-Timeout` kept within it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyProfile {
    /// The owning segment, which is also this profile's id: one profile per
    /// segment, at most.
    pub segment_id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// The dictionary version the profile was validated against.
    pub dictionary: String,
    /// `Session-Timeout`, seconds: the stored value lowered to the tenant's
    /// current cap. This is the value a reply carries.
    pub session_timeout_secs: u32,
    /// Whether the stored value was above the cap and has been lowered.
    pub session_timeout_clamped: bool,
    /// `Termination-Action`.
    pub termination_action: TerminationAction,
    /// `Idle-Timeout`, seconds, never above the effective `Session-Timeout`.
    pub idle_timeout_secs: Option<u32>,
    /// `Filter-Id`, one of the segment's declared names.
    pub filter_id: Option<String>,
    /// `Service-Type`.
    pub service_type: Option<ServiceType>,
    /// The version the next replace or delete must name. Starts at 1.
    pub version: u64,
    /// The administrator who created it.
    pub created_by: Uuid,
    /// The administrator who last wrote it.
    pub updated_by: Uuid,
    /// Creation time.
    pub created_at: DateTime<Utc>,
    /// Last write time.
    pub updated_at: DateTime<Utc>,
}

/// What creating a segment's profile takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewReplyProfile {
    /// The segment version the writer read: the envelope the profile was
    /// checked against. A segment written since is `Conflict`.
    pub expected_segment_version: u64,
    /// The profile.
    pub profile: ReplyProfileInput,
    /// The writing administrator.
    pub actor: Uuid,
}

/// What replacing a segment's profile takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyProfileReplace {
    /// The profile version the writer read. A stale one is `Conflict`.
    pub expected_version: u64,
    /// The segment version the writer read, as for [`NewReplyProfile`].
    pub expected_segment_version: u64,
    /// The profile.
    pub profile: ReplyProfileInput,
    /// The writing administrator.
    pub actor: Uuid,
}

/// The tenant's network policy: today, the cap on `Session-Timeout`.
///
/// The tenant setting `network.session_timeout_max_secs` of the design note
/// (§3.4). A tenant that never wrote one has [`Self::default_for`]: a cap of
/// [`DEFAULT_SESSION_TIMEOUT_MAX_SECS`] at version 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// `network.session_timeout_max_secs`: [`SESSION_TIMEOUT_FLOOR_SECS`] to
    /// [`SESSION_TIMEOUT_CAP_CEILING_SECS`]; default 3600.
    pub session_timeout_max_secs: u32,
    /// The version the next write must name; 0 until the tenant first writes.
    pub version: u64,
    /// The administrator who last wrote it; `None` while it is the default.
    pub updated_by: Option<Uuid>,
    /// Last write time; `None` while it is the default.
    pub updated_at: Option<DateTime<Utc>>,
}

impl NetworkPolicy {
    /// The policy of a tenant that has not written one.
    #[must_use]
    pub const fn default_for(tenant_id: Uuid) -> Self {
        Self {
            tenant_id,
            session_timeout_max_secs: DEFAULT_SESSION_TIMEOUT_MAX_SECS,
            version: 0,
            updated_by: None,
            updated_at: None,
        }
    }
}

/// What writing the tenant's network policy takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetNetworkPolicy {
    /// The new cap, [`SESSION_TIMEOUT_FLOOR_SECS`] to
    /// [`SESSION_TIMEOUT_CAP_CEILING_SECS`]. Lowering it is allowed even below
    /// stored profiles: reads clamp, and that only narrows.
    pub session_timeout_max_secs: u32,
    /// The version the writer read (0 for a tenant on the default). A stale
    /// one is `Conflict`.
    pub expected_version: u64,
    /// The writing administrator.
    pub actor: Uuid,
}

impl SetNetworkPolicy {
    /// Refuse a cap outside the settable range.
    pub fn validate(&self) -> AxiamResult<()> {
        if !(SESSION_TIMEOUT_FLOOR_SECS..=SESSION_TIMEOUT_CAP_CEILING_SECS)
            .contains(&self.session_timeout_max_secs)
        {
            return Err(AxiamError::Validation {
                message: format!(
                    "network.session_timeout_max_secs must be between \
                     {SESSION_TIMEOUT_FLOOR_SECS} and {SESSION_TIMEOUT_CAP_CEILING_SECS}"
                ),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The reserved nodes' ids
// ---------------------------------------------------------------------------

/// The path of the reserved root.
pub const NETWORK_ROOT_PATH: &str = "/network";

/// The id of a reserved node of the `/network` subtree: a v5 UUID of the tenant
/// and the node's path.
///
/// Deterministic so that two first writers race for one key (the repository's
/// reason) and so that the authorization function can name `/network`, a
/// branch or a site **before it exists**: a role assigned tenant-wide is a
/// grant at `/network` (design note §5.3), and a segment's first writer must be
/// checked at the site it is about to create.
#[must_use]
pub fn reserved_node_id(tenant_id: Uuid, path: &str) -> Uuid {
    Uuid::new_v5(&tenant_id, path.as_bytes())
}

/// The id of the tenant's `/network` root.
#[must_use]
pub fn network_root_id(tenant_id: Uuid) -> Uuid {
    reserved_node_id(tenant_id, NETWORK_ROOT_PATH)
}

/// The id of the branch that holds segments of `kind`.
#[must_use]
pub fn branch_node_id(tenant_id: Uuid, kind: NetworkSegmentKind) -> Uuid {
    reserved_node_id(tenant_id, &format!("{NETWORK_ROOT_PATH}/{}", kind.branch()))
}

/// The id of the site `site_key` under the branch of `kind`.
#[must_use]
pub fn site_node_id(tenant_id: Uuid, kind: NetworkSegmentKind, site_key: &str) -> Uuid {
    reserved_node_id(
        tenant_id,
        &format!("{NETWORK_ROOT_PATH}/{}/{site_key}", kind.branch()),
    )
}

// ---------------------------------------------------------------------------
// The reserved permission namespace (design note §4.2)
// ---------------------------------------------------------------------------

/// The reserved permission namespace. `permissions:create` and
/// `permissions:update` refuse an action in it, so a tenant cannot mint a
/// look-alike or rename one of the nine.
pub const NETWORK_PERMISSION_PREFIX: &str = "network:";
/// May be placed on a segment. Held by a device's service account.
pub const NETWORK_JOIN: &str = "network:join";
/// Administrative login to a segment's NAS devices. Defined, not grantable
/// under option B.
pub const NETWORK_ADMIN: &str = "network:admin";
/// Read segments and profiles.
pub const NETWORK_READ: &str = "network:read";
/// Write the tree and each segment's envelope.
pub const NETWORK_SEGMENTS_WRITE: &str = "network:segments_write";
/// Write a segment's reply profile.
pub const NETWORK_PROFILES_WRITE: &str = "network:profiles_write";
/// Confer `network:join` at a node.
pub const NETWORK_GRANT: &str = "network:grant";
/// Confer the administrative class. Option A only.
pub const NETWORK_GRANT_ADMIN: &str = "network:grant_admin";
/// Ask for placement decisions for a site (D4's caller).
pub const NETWORK_DECIDE: &str = "network:decide";
/// Read the rendered export for a site.
pub const NETWORK_EXPORT: &str = "network:export";

/// The meta permissions of design note §5.3: assigning a role that carries one
/// of these at a node needs the assigner to hold it there ("you delegate only
/// what you hold").
pub const NETWORK_META_ACTIONS: &[&str] = &[
    NETWORK_GRANT,
    NETWORK_PROFILES_WRITE,
    NETWORK_SEGMENTS_WRITE,
    NETWORK_DECIDE,
    NETWORK_EXPORT,
];

/// The administrative class (§3.3, H4): defined so that option A inherits the
/// rule, and not grantable as an allow under option B.
pub const NETWORK_ADMIN_CLASS_ACTIONS: &[&str] = &[NETWORK_ADMIN, NETWORK_GRANT_ADMIN];

/// The `network:*` actions the seeded **super-admin** role holds: the meta
/// permissions and `network:read`, never `network:join` or the administrative
/// class.
///
/// # Why the bootstrap role is exempt from §4.2 rule 1, and only this far
///
/// Rule 1 forbids a network-sensitive role to be global. The seeded
/// super-admin is global, and it is the **one** role that must be: with the
/// §5.3 bound in force a network administrator can only be made by someone who
/// already holds `network:grant` (and every meta permission conferred) at the
/// node, so a tenant whose bootstrap role held none of them could never
/// administer its network at all. The exemption is narrow:
///
/// * it carries no `network:join`, so no device lands on every segment by
///   holding the super-admin role, which is what rule 1's "global defeats
///   segment scoping" is about;
/// * it carries neither `network:admin` nor `network:grant_admin`, which are
///   not grantable under option B;
/// * it does **not** bypass §5.3: assigning the super-admin role is a
///   tenant-wide assignment of a role carrying meta permissions, so the
///   assigner must hold every one of them at `/network`;
/// * it is made only by the seeder (`seed_default_roles`, and
///   `reconcile_default_role_grants` on boot). The API refuses a `network:`
///   grant to any global role, this one included.
///
/// The seeded `admin` and `viewer` roles hold no `network:` permission.
pub const SEEDED_SUPER_ADMIN_NETWORK_ACTIONS: &[&str] = &[
    NETWORK_READ,
    NETWORK_SEGMENTS_WRITE,
    NETWORK_PROFILES_WRITE,
    NETWORK_GRANT,
    NETWORK_DECIDE,
    NETWORK_EXPORT,
];

/// Whether `action` is in the reserved `network:` namespace.
///
/// Case-insensitive and blind to surrounding whitespace, so that a look-alike
/// (`Network:join`, ` network:grant`) counts as reserved: the engine matches
/// actions exactly and such a permission would grant nothing, but it would
/// read as one of the nine in every listing an administrator looks at.
#[must_use]
pub fn is_network_action(action: &str) -> bool {
    action
        .trim_start()
        .get(..NETWORK_PERMISSION_PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(NETWORK_PERMISSION_PREFIX))
}

// ---------------------------------------------------------------------------
// The write clearance (design note §5.1)
// ---------------------------------------------------------------------------

/// Which segment or profile write a [`NetworkWriteClearance`] was issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkWriteTarget {
    /// Create the segment at this path.
    SegmentCreate {
        /// The path of the segment to create.
        path: String,
    },
    /// Rewrite this segment's envelope.
    SegmentUpdate {
        /// The segment.
        segment_id: Uuid,
    },
    /// Delete this segment.
    SegmentDelete {
        /// The segment.
        segment_id: Uuid,
    },
    /// Create or replace this segment's reply profile.
    ProfileWrite {
        /// The owning segment.
        segment_id: Uuid,
    },
    /// Delete this segment's reply profile.
    ProfileDelete {
        /// The owning segment.
        segment_id: Uuid,
    },
}

/// Proof that the authorization function of design note §5.1 cleared one
/// segment or profile write.
///
/// Every write method of [`crate::repository::NetworkSegmentRepository`] and
/// [`crate::repository::ReplyProfileRepository`] takes one, and refuses a
/// clearance issued for another tenant, another actor or another write. That
/// makes "a write reaches the repository without the function" a **compile
/// error** rather than a review finding (the T-429 lesson).
///
/// The constructor is public because the function lives in `axiam-authz`,
/// which this crate cannot name; it is hidden from the documentation and its
/// call sites are pinned by `network_gate_enumeration_test` in `axiam-api-rest`
/// to the function's own module and to tests. The type is neither `Clone` nor
/// `Default`, so a clearance cannot be copied into a second write.
#[derive(Debug, PartialEq, Eq)]
pub struct NetworkWriteClearance {
    tenant_id: Uuid,
    actor: Uuid,
    target: NetworkWriteTarget,
}

impl NetworkWriteClearance {
    /// Mint a clearance. **Only** `axiam_authz::network_gate` calls this in
    /// production code; anything else is caught by the enumeration test.
    #[doc(hidden)]
    #[must_use]
    pub fn issued_by_the_network_gate(
        tenant_id: Uuid,
        actor: Uuid,
        target: NetworkWriteTarget,
    ) -> Self {
        Self {
            tenant_id,
            actor,
            target,
        }
    }

    /// The tenant the write was cleared in.
    #[must_use]
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// The writer the write was cleared for.
    #[must_use]
    pub fn actor(&self) -> Uuid {
        self.actor
    }

    /// The write that was cleared.
    #[must_use]
    pub fn target(&self) -> &NetworkWriteTarget {
        &self.target
    }

    /// Refuse unless this clearance is for exactly this write, in this tenant,
    /// by this actor. A mismatch is a programming error in the caller, so it is
    /// reported as `AuthorizationDenied` and the write does not happen.
    pub fn check(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        target: &NetworkWriteTarget,
    ) -> AxiamResult<()> {
        if self.tenant_id == tenant_id && self.actor == actor && &self.target == target {
            Ok(())
        } else {
            Err(AxiamError::AuthorizationDenied {
                reason: "the network write was not cleared by the authorization function \
                         for this tenant, actor and target"
                    .into(),
                action: None,
                resource_id: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_node_ids_are_per_tenant_and_per_path() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(network_root_id(a), reserved_node_id(a, "/network"));
        assert_ne!(network_root_id(a), network_root_id(b));
        assert_eq!(
            branch_node_id(a, NetworkSegmentKind::Quarantine),
            reserved_node_id(a, "/network/quarantine")
        );
        assert_eq!(
            site_node_id(a, NetworkSegmentKind::Access, "hq"),
            reserved_node_id(a, "/network/zones/hq")
        );
        assert_ne!(
            site_node_id(a, NetworkSegmentKind::Access, "hq"),
            site_node_id(a, NetworkSegmentKind::Quarantine, "hq")
        );
    }

    #[test]
    fn the_reserved_namespace_catches_look_alikes() {
        for reserved in [
            "network:join",
            "Network:join",
            "NETWORK:grant",
            "  network:anything",
            "network:",
        ] {
            assert!(is_network_action(reserved), "{reserved}");
        }
        for free in ["networks:join", "net:join", "users:list", "", "network"] {
            assert!(!is_network_action(free), "{free}");
        }
    }

    #[test]
    fn the_seeded_super_admin_holds_no_join_and_no_admin_class() {
        assert!(!SEEDED_SUPER_ADMIN_NETWORK_ACTIONS.contains(&NETWORK_JOIN));
        for a in NETWORK_ADMIN_CLASS_ACTIONS {
            assert!(!SEEDED_SUPER_ADMIN_NETWORK_ACTIONS.contains(a));
        }
        for meta in NETWORK_META_ACTIONS {
            assert!(SEEDED_SUPER_ADMIN_NETWORK_ACTIONS.contains(meta), "{meta}");
        }
    }

    #[test]
    fn a_clearance_covers_one_write_only() {
        let t = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let seg = Uuid::new_v4();
        let c = NetworkWriteClearance::issued_by_the_network_gate(
            t,
            actor,
            NetworkWriteTarget::ProfileWrite { segment_id: seg },
        );
        assert!(
            c.check(
                t,
                actor,
                &NetworkWriteTarget::ProfileWrite { segment_id: seg }
            )
            .is_ok()
        );
        for (tenant, who, target) in [
            (
                Uuid::new_v4(),
                actor,
                NetworkWriteTarget::ProfileWrite { segment_id: seg },
            ),
            (
                t,
                Uuid::new_v4(),
                NetworkWriteTarget::ProfileWrite { segment_id: seg },
            ),
            (
                t,
                actor,
                NetworkWriteTarget::ProfileDelete { segment_id: seg },
            ),
            (
                t,
                actor,
                NetworkWriteTarget::ProfileWrite {
                    segment_id: Uuid::new_v4(),
                },
            ),
        ] {
            assert!(matches!(
                c.check(tenant, who, &target),
                Err(AxiamError::AuthorizationDenied { .. })
            ));
        }
    }

    #[test]
    fn a_segment_path_has_exactly_the_reserved_shape() {
        let p = NetworkSegmentPath::parse("/network/zones/hq/corp").unwrap();
        assert_eq!(p.kind, NetworkSegmentKind::Access);
        assert_eq!((p.site_key.as_str(), p.name.as_str()), ("hq", "corp"));
        assert_eq!(p.render(), "/network/zones/hq/corp");
        let q = NetworkSegmentPath::parse("/network/quarantine/hq/q").unwrap();
        assert_eq!(q.kind, NetworkSegmentKind::Quarantine);
    }

    #[test]
    fn a_path_outside_network_or_off_shape_is_refused() {
        for bad in [
            "",
            "/",
            "/network",
            "/network/zones",
            "/network/zones/hq",
            "/network/zones/hq/corp/extra",
            "/networks/zones/hq/corp",
            "/Network/zones/hq/corp",
            "network/zones/hq/corp",
            "/other/zones/hq/corp",
            "/network/other/hq/corp",
            "/network/zones//corp",
            "/network/zones/hq/",
            "/network/zones/../hq/corp",
            "/network/zones/hq/..",
            "/network/zones/hq/co rp",
            "/network/zones/hq/corp/",
            "/network/zones/hq/-corp",
        ] {
            assert!(
                matches!(
                    NetworkSegmentPath::parse(bad),
                    Err(AxiamError::Validation { .. })
                ),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn reserved_types_are_the_network_prefix() {
        for t in [
            RESOURCE_TYPE_NETWORK_ROOT,
            RESOURCE_TYPE_NETWORK_BRANCH,
            RESOURCE_TYPE_NETWORK_SITE,
            RESOURCE_TYPE_NETWORK_SEGMENT,
        ] {
            assert!(is_reserved_resource_type(t));
        }
        assert!(!is_reserved_resource_type("project"));
        assert!(!is_reserved_resource_type("net_work"));
    }

    #[test]
    fn segment_fields_are_checked_without_the_datastore() {
        let ok = |kind, vlan, filters: &[&str], rank| {
            let f: Vec<String> = filters.iter().map(|s| (*s).to_owned()).collect();
            validate_segment_fields(kind, vlan, &f, rank)
        };
        use NetworkSegmentKind::{Access, Quarantine};
        assert!(ok(Access, 10, &["a", "b"], Some(10)).is_ok());
        assert!(ok(Quarantine, 999, &[], None).is_ok());
        assert!(ok(Access, 0, &[], Some(1)).is_err());
        assert!(ok(Access, 4095, &[], Some(1)).is_err());
        assert!(ok(Access, 10, &["a", "a"], Some(1)).is_err());
        assert!(ok(Access, 10, &["bad name"], Some(1)).is_err());
        assert!(ok(Access, 10, &[], None).is_err());
        assert!(ok(Quarantine, 10, &[], Some(1)).is_err());
        let many: Vec<String> = (0..33).map(|i| format!("f{i}")).collect();
        assert!(validate_segment_fields(Access, 10, &many, Some(1)).is_err());
    }

    #[test]
    fn the_policy_cap_has_a_settable_range() {
        let set = |secs| SetNetworkPolicy {
            session_timeout_max_secs: secs,
            expected_version: 0,
            actor: Uuid::nil(),
        };
        assert!(set(299).validate().is_err());
        assert!(set(300).validate().is_ok());
        assert!(set(86_400).validate().is_ok());
        assert!(set(86_401).validate().is_err());
        assert_eq!(
            NetworkPolicy::default_for(Uuid::nil()).session_timeout_max_secs,
            3600
        );
    }
}

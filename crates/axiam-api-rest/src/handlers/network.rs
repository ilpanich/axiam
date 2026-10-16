//! The network-segment and RADIUS reply-profile management routes (RADIUS D4,
//! W6.3; `claude_dev/radius-reply-profile-design.md` §4, §5).
//!
//! Ten operations under `/api/v1/network`, in the `network` OpenAPI tag and the
//! management registry:
//!
//! | | segments | profiles |
//! |---|---|---|
//! | list | `GET /network/segments` | `GET /network/profiles` |
//! | get | `GET /network/segments/{id}` | `GET /network/profiles/{segment_id}` |
//! | create | `POST /network/segments` | `POST /network/profiles` |
//! | replace | `PUT /network/segments/{id}` | `PUT /network/profiles/{segment_id}` |
//! | delete | `DELETE /network/segments/{id}?version=` | `DELETE /network/profiles/{segment_id}?version=` |
//!
//! A segment is a node of the reserved `/network` subtree of the resource tree
//! (§4.1); its reply profile is **owned by the segment** and keyed by its id (one
//! per segment, at most), which is why the profile routes are addressed by
//! `segment_id`. The routes are **human-only** (`network:*` is a
//! [`HUMAN_ONLY_FAMILIES`](crate::permissions::HUMAN_ONLY_FAMILIES) family): a
//! network administrator is a person, and a service-account token is `401` at
//! the extractor. The tenant is the token's; a segment or profile of another
//! tenant is `404`, exactly as one that does not exist.
//!
//! # Permissions
//!
//! * a read needs `network:read` — at the `/network` root for a list, at the
//!   segment for a get (§4.2: "`/network` or below");
//! * a write needs what the **write gate** asks for, not a route-level guess:
//!   `network:segments_write` at the parent (create) or the node (replace,
//!   delete) and H6 — and for a replace that changes `vlan_id`, `rank` or
//!   `enabled` of a segment that has a profile, `network:grant` at the segment
//!   and, on a quarantine segment, at its quarantine site (R110W6-03: that
//!   replace re-places every device that may join it);
//!   `network:profiles_write` **and** `network:grant` on the
//!   segment, the envelope, the quarantine site's `network:grant` and H6 for a
//!   profile write (§5.2 H1–H6). `axiam_authz::network_gate` is the one place
//!   that logic lives.
//!
//! # What every write does, in this order
//!
//! 1. the body (`400`; an unknown key is refused naming it — a profile is a typed
//!    record, not an attribute list, §3.4);
//! 2. **the gate** ([`crate::network_gate::authorize`]): `403` or `400`, each with
//!    an audit row of its own carrying the internal rule (`H2`, `4.2:segments_write`,
//!    …) and the values before and after (§5.4). It returns the
//!    [`NetworkWriteClearance`](axiam_core::models::network::NetworkWriteClearance)
//!    the repositories demand, so a write cannot reach the datastore without it;
//! 3. the reactor's veto hook (`network.pre_segment_write` /
//!    `network.pre_profile_write`, X1): a four-eyes rule on network policy. It is
//!    asked only about a write the gate cleared;
//! 4. the write, **conditional on the `version` the caller read** — `409` when it
//!    is stale. Every `409` of these routes carries a closed `reason_code`
//!    beside `error` ([`NetworkConflictReason`]: `stale_version`,
//!    `strands_profile`, `has_children`, …; §36.4), so that no client parses
//!    `message`. A profile write is also conditional on the owning segment's
//!    `version` (the envelope it was checked against), and an envelope write that
//!    would strand the segment's profile outside its new `filter_ids` is `409`
//!    naming the profile;
//! 5. one audit row: the write (`network_segment.created` / `.updated` / `.deleted`,
//!    `reply_profile.created` / `.replaced` / `.deleted`) with the values before
//!    and after and the versions — **or**, when step 3 or 4 refused, a
//!    `*.write_refused` row with the internal reason. Every write and every
//!    refusal leaves exactly one row.
//!
//! Writes are metered by [`RateLimitConfig::network_admin_per_min`](
//! crate::config::rate_limit::RateLimitConfig::network_admin_per_min), one bucket
//! per route (`network_segment_create` … `network_profile_delete`); reads are not
//! separately limited.
//!
//! # The tenant's `Session-Timeout` cap
//!
//! Two more operations, beside the ten, on the one row of tenant policy the
//! network surface has (`network.session_timeout_max_secs`, 300 to 86 400,
//! default 3600; design note §3.4):
//!
//! | | |
//! |---|---|
//! | read | `GET /network/policy` — `network:read` at the `/network` root |
//! | write | `PUT /network/policy` — [`NETWORK_SEGMENTS_WRITE`](axiam_core::models::network::NETWORK_SEGMENTS_WRITE) (`network:segments_write`) at the `/network` root, through the write gate |
//!
//! The maintainer's decision of 2026-10-15 (plan §13.6), corrected the same day:
//! the cap is the `Session-Timeout` envelope every profile is clamped to, so its
//! write is `network:segments_write`'s (envelopes), not `network:admin`'s (which
//! is administrative login to a NAS device and is not grantable). A holder of
//! `network:profiles_write` alone cannot write it (H3), and only a grant at the
//! `/network` root counts. The write is a
//! replacement conditional on the row's `version` (`0` = never written, the
//! first write; a stale one is `409`), in a bucket of its own
//! (`network_policy_replace`). **Lowering is always allowed; raising is allowed
//! and audited** (`network_policy.lowered` / `network_policy.raised`, each with
//! the cap before and after and the versions). The gate asks no more of a raise
//! than of a lowering — see
//! [`NetworkWrite::PolicyWrite`](axiam_authz::network_gate::NetworkWrite::PolicyWrite)
//! for why. No reactor hook: the design note names `network.pre_profile_write`
//! and `network.pre_segment_write` and no third.
//!
//! Lowering the cap below an existing profile's `session_timeout_secs` is fine:
//! the stored value is untouched, every read that produces a reply clamps it to
//! the cap, and the profile says so (`session_timeout_clamped`). Raising the cap
//! again restores the stored value — unless the profile was replaced while
//! clamped: a replace stores what it carries, and the gate refuses one above
//! the current cap (H3), so a read-modify-write of a clamped profile stores the
//! clamped value and cannot restore the old one (§36.3 rule 6).

use actix_web::error::{JsonPayloadError, QueryPayloadError};
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_authz::network_gate::{
    AUDIT_POLICY_WRITE_REFUSED, AUDIT_PROFILE_WRITE_REFUSED, AUDIT_SEGMENT_WRITE_REFUSED,
    NetworkWrite,
};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::network::{
    CapChange, NETWORK_READ, NetworkPolicy, NetworkSegment, NetworkSegmentKind,
    NetworkSegmentUpdate, NewNetworkSegment, NewReplyProfile, ReplyProfile, ReplyProfileReplace,
    SetNetworkPolicy, network_root_id, render_path,
};
use axiam_core::models::radius_reply::ReplyProfileInput;
use axiam_core::repository::{
    AuditLogRepository, NetworkPolicyRepository, NetworkSegmentRepository, PaginatedResult,
    Pagination, ReplyProfileRepository,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use surrealdb::Connection;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::{AuthenticatedPrincipal, AuthenticatedUser};
use crate::extractors::client_info::client_ip;
use crate::network_gate;
use crate::reactor_hooks;
use crate::state::AppState;
use axiam_db::repository::{
    SurrealNetworkPolicyRepository, SurrealNetworkSegmentRepository, SurrealReplyProfileRepository,
};

/// Audit action: a segment was created.
pub const AUDIT_SEGMENT_CREATED: &str = "network_segment.created";
/// Audit action: a segment's envelope was replaced.
pub const AUDIT_SEGMENT_UPDATED: &str = "network_segment.updated";
/// Audit action: a segment (and its profile) was deleted.
pub const AUDIT_SEGMENT_DELETED: &str = "network_segment.deleted";
/// Audit action: a segment's reply profile was created.
pub const AUDIT_PROFILE_CREATED: &str = "reply_profile.created";
/// Audit action: a segment's reply profile was replaced.
pub const AUDIT_PROFILE_REPLACED: &str = "reply_profile.replaced";
/// Audit action: a segment's reply profile was deleted.
pub const AUDIT_PROFILE_DELETED: &str = "reply_profile.deleted";

/// Audit action: the tenant's `Session-Timeout` cap was raised.
pub const AUDIT_POLICY_RAISED: &str = "network_policy.raised";
/// Audit action: the tenant's `Session-Timeout` cap was lowered.
pub const AUDIT_POLICY_LOWERED: &str = "network_policy.lowered";
/// Audit action: the tenant's `Session-Timeout` cap was written to the value it
/// already had (the version moves, the cap does not).
pub const AUDIT_POLICY_UNCHANGED: &str = "network_policy.unchanged";

const BODY_LIMIT: usize = 16_384;

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

/// A network segment, as the management API returns it.
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkSegmentResponse {
    /// The segment id; also the id of its resource node, which `check_access`
    /// is asked about, and of its reply profile.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// The segment's place in the reserved subtree,
    /// `/network/{zones|quarantine}/<site_key>/<name>`.
    pub path: String,
    /// The segment's name, unique within its site.
    pub name: String,
    /// The site key.
    pub site_key: String,
    /// `access` (under `/network/zones`) or `quarantine` (under
    /// `/network/quarantine`); fixed for the segment's life.
    pub kind: NetworkSegmentKind,
    /// The VLAN the tunnel attributes carry (1 to 4094), unique per site.
    pub vlan_id: u16,
    /// The `Filter-Id` names the segment's profile may choose from.
    pub filter_ids: Vec<String>,
    /// The placement rank among a site's `access` segments (lowest wins);
    /// absent for a quarantine segment.
    pub rank: Option<u32>,
    /// Whether the segment is a placement candidate.
    pub enabled: bool,
    /// The version the next replace or delete must name.
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

impl From<NetworkSegment> for NetworkSegmentResponse {
    fn from(s: NetworkSegment) -> Self {
        Self {
            path: s.path(),
            id: s.id,
            tenant_id: s.tenant_id,
            name: s.name,
            site_key: s.site_key,
            kind: s.kind,
            vlan_id: s.vlan_id,
            filter_ids: s.filter_ids,
            rank: s.rank,
            enabled: s.enabled,
            version: s.version,
            created_by: s.created_by,
            updated_by: s.updated_by,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

/// The body of `POST /api/v1/network/segments`.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateNetworkSegmentRequest {
    /// `access` or `quarantine`. Decides the branch the segment lives under.
    pub kind: NetworkSegmentKind,
    /// The site key (`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`). A single-site tenant
    /// uses `default`.
    pub site_key: String,
    /// The segment's name, same pattern, unique within the site.
    pub name: String,
    /// The VLAN (1 to 4094), unique within the site.
    pub vlan_id: u16,
    /// The `Filter-Id` names the segment's profile may choose from: its
    /// envelope. At most 32, each matching the pattern above.
    #[serde(default)]
    pub filter_ids: Vec<String>,
    /// The placement rank (unique within the site): required for `access`,
    /// absent for `quarantine`.
    #[serde(default)]
    pub rank: Option<u32>,
    /// Whether the segment starts as a placement candidate. Defaults to `true`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// The body of `PUT /api/v1/network/segments/{id}`: a **replacement** of the
/// envelope. The kind and the place in the tree do not change.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplaceNetworkSegmentRequest {
    /// The segment's `version` as the caller read it. A stale one is `409`.
    pub version: u64,
    /// The VLAN (1 to 4094).
    pub vlan_id: u16,
    /// The `Filter-Id` names the segment's profile may choose from. Removing
    /// the one the profile uses is `409`, naming the profile.
    pub filter_ids: Vec<String>,
    /// The placement rank: required for an `access` segment, absent for a
    /// `quarantine` one.
    #[serde(default)]
    pub rank: Option<u32>,
    /// Whether the segment is a placement candidate.
    pub enabled: bool,
}

/// The body of `POST /api/v1/network/profiles`.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = CreateNetworkReplyProfileRequest)]
#[serde(deny_unknown_fields)]
pub struct CreateReplyProfileRequest {
    /// The segment the profile belongs to (at most one profile per segment).
    pub segment_id: Uuid,
    /// The segment's `version` as the caller read it: the envelope the profile
    /// was written against. A segment written since is `409`.
    pub segment_version: u64,
    /// The profile: a typed record of the `axiam-radius-reply/1` dictionary.
    /// The VLAN is never a field; it is the segment's.
    pub profile: ReplyProfileInput,
}

/// The body of `PUT /api/v1/network/profiles/{segment_id}`.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = ReplaceNetworkReplyProfileRequest)]
#[serde(deny_unknown_fields)]
pub struct ReplaceReplyProfileRequest {
    /// The profile's `version` as the caller read it. A stale one is `409`.
    pub version: u64,
    /// The segment's `version` as the caller read it, as for
    /// [`CreateReplyProfileRequest::segment_version`].
    pub segment_version: u64,
    /// The profile.
    pub profile: ReplyProfileInput,
}

/// The `version` a delete is conditional on.
#[derive(Debug, Deserialize, IntoParams)]
pub struct VersionQuery {
    /// The `version` of the segment (or profile) as the caller read it. A stale
    /// one is `409`.
    pub version: u64,
}

/// Narrows a segment list to one site.
#[derive(Debug, Deserialize, IntoParams)]
pub struct SiteQuery {
    /// Only the segments of this site key.
    pub site: Option<String>,
}

/// The tenant's network policy, as the management API returns it.
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkPolicyResponse {
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// `network.session_timeout_max_secs`: the most a reply profile's
    /// `Session-Timeout` may be, in seconds (300 to 86 400; 3600 until the
    /// tenant writes one). A stored profile above it is clamped at read.
    pub session_timeout_max_secs: u32,
    /// The version the next `PUT` must name; `0` until the tenant first writes.
    pub version: u64,
    /// The administrator who last wrote it; absent while it is the default.
    pub updated_by: Option<Uuid>,
    /// Last write time; absent while it is the default.
    pub updated_at: Option<DateTime<Utc>>,
}

impl From<NetworkPolicy> for NetworkPolicyResponse {
    fn from(p: NetworkPolicy) -> Self {
        Self {
            tenant_id: p.tenant_id,
            session_timeout_max_secs: p.session_timeout_max_secs,
            version: p.version,
            updated_by: p.updated_by,
            updated_at: p.updated_at,
        }
    }
}

/// The body of `PUT /api/v1/network/policy`: a **replacement** of the policy.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplaceNetworkPolicyRequest {
    /// The new cap on a reply profile's `Session-Timeout`, in seconds: 300 to
    /// 86 400. Lowering it below an existing profile's value is fine (reads
    /// clamp); raising it is allowed and audited as a raise.
    pub session_timeout_max_secs: u32,
    /// The policy's `version` as the caller read it (`0` for a tenant that has
    /// never written one). A stale one is `409`.
    pub version: u64,
}

// ---------------------------------------------------------------------------
// The 409 sub-code (§36.4)
// ---------------------------------------------------------------------------

/// Why a network route answered `409`: the `reason_code` member of the body,
/// beside `error` (`sdks/CONTRACT.md` §36.3 rule 2, §36.4).
///
/// The vocabulary a client branches on, so that it never has to parse
/// `message` (which stays for a human); open for decoding (§27.13), so a
/// client surfaces a value it does not know. The `error` slug is unchanged:
/// `conflict` for a state conflict, `already_exists` for a uniqueness clash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkConflictReason {
    /// The segment, profile or policy changed since `version` (or
    /// `segment_version`) was read — including a reply profile written on a
    /// segment between the gate's read and the write (R110W6-03). Read again
    /// and decide again.
    StaleVersion,
    /// A segment replace whose `filter_ids` would leave its profile's
    /// `filter_id` outside the envelope (the message names the profile).
    StrandsProfile,
    /// A segment delete while the segment has child resources.
    HasChildren,
    /// The site already has a segment of this name (`already_exists`).
    DuplicateName,
    /// The site already has a segment with this VLAN (`already_exists`).
    DuplicateVlan,
    /// The site already has a segment with this rank (`already_exists`).
    DuplicateRank,
    /// The segment already has a reply profile (`already_exists`).
    ProfileExists,
    /// The site node was removed while the segment was being created.
    SiteGone,
    /// A `409` none of the above names. None is raised today; a client treats
    /// it, and any value it does not know, as a conflict to show the
    /// `message` of.
    Other,
}

impl NetworkConflictReason {
    /// The wire value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleVersion => "stale_version",
            Self::StrandsProfile => "strands_profile",
            Self::HasChildren => "has_children",
            Self::DuplicateName => "duplicate_name",
            Self::DuplicateVlan => "duplicate_vlan",
            Self::DuplicateRank => "duplicate_rank",
            Self::ProfileExists => "profile_exists",
            Self::SiteGone => "site_gone",
            Self::Other => "other",
        }
    }

    /// The reason of a `409`; `None` for every other error.
    ///
    /// Read off the fixed sentences the network repositories and
    /// [`name_the_stranded_profile`] write — the server's own words, matched
    /// in one place on the server, so no client has to. Every value is pinned
    /// end to end by `network_routes_test::every_network_409_carries_its_reason_code`.
    #[must_use]
    pub fn of(error: &AxiamError) -> Option<Self> {
        match error {
            AxiamError::Conflict { reason } => {
                Some(if reason.contains("changed since it was read") {
                    Self::StaleVersion
                } else if reason.contains("change or delete the profile first") {
                    Self::StrandsProfile
                } else if reason.contains("child resources") {
                    Self::HasChildren
                } else if reason.contains("network site was removed") {
                    Self::SiteGone
                } else {
                    Self::Other
                })
            }
            AxiamError::AlreadyExists { entity } => Some(if entity.contains("this vlan_id") {
                Self::DuplicateVlan
            } else if entity.contains("this rank") {
                Self::DuplicateRank
            } else if entity.contains("of this name") {
                Self::DuplicateName
            } else if entity.contains("reply_profile") {
                Self::ProfileExists
            } else {
                Self::Other
            }),
            _ => None,
        }
    }

    /// The internal rule a refusal's audit row records for it (§5.4).
    fn audit_rule(self) -> &'static str {
        match self {
            Self::StaleVersion => "version:stale",
            Self::StrandsProfile => "5.2:strands-profile",
            Self::HasChildren => "conflict:children",
            Self::DuplicateName
            | Self::DuplicateVlan
            | Self::DuplicateRank
            | Self::ProfileExists => "exists",
            Self::SiteGone | Self::Other => "conflict",
        }
    }
}

/// The body of a network route's `409`, as the OpenAPI document shows it.
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkConflictResponse {
    /// `conflict` for a state conflict, `already_exists` for a uniqueness
    /// clash — the crate's slugs, unchanged.
    pub error: String,
    /// A sentence for a human. Never parsed: `reason_code` is what to branch on.
    pub message: String,
    /// Why the write conflicts.
    pub reason_code: NetworkConflictReason,
}

/// The error every network route answers with: the crate's body, plus
/// `reason_code` on a `409` (§36.4). Everything that is not a `409` renders
/// exactly as [`AxiamApiError`] does.
#[derive(Debug)]
pub struct NetworkApiError(pub AxiamApiError);

impl std::fmt::Display for NetworkApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<AxiamApiError> for NetworkApiError {
    fn from(error: AxiamApiError) -> Self {
        Self(error)
    }
}

impl From<AxiamError> for NetworkApiError {
    fn from(error: AxiamError) -> Self {
        Self(AxiamApiError(error))
    }
}

impl actix_web::ResponseError for NetworkApiError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        self.0.status_code()
    }

    fn error_response(&self) -> HttpResponse {
        self.0.error_response_with_reason_code(
            NetworkConflictReason::of(&self.0.0).map(NetworkConflictReason::as_str),
        )
    }
}

// ---------------------------------------------------------------------------
// Extractor configuration
// ---------------------------------------------------------------------------

/// The JSON extractor of the write routes: a body limit and a `400` that names
/// the offending key.
///
/// Unlike the registries that hold a credential, nothing here is secret (a
/// segment and a profile are policy, with no secret and no personal data,
/// design note §3.5), and the note asks for exactly this: an unknown key is a
/// `400` **naming it** (§3.4).
pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default().limit(BODY_LIMIT).error_handler(
        |err: JsonPayloadError, _req: &HttpRequest| {
            let message = match err {
                JsonPayloadError::Deserialize(inner) => {
                    format!("the request body is not a valid network request: {inner}")
                }
                JsonPayloadError::ContentType => {
                    "the request body must be application/json".to_string()
                }
                JsonPayloadError::Overflow { .. }
                | JsonPayloadError::OverflowKnownLength { .. } => {
                    "the request body is too large".to_string()
                }
                _ => "the request body could not be read".to_string(),
            };
            AxiamApiError(AxiamError::Validation { message }).into()
        },
    )
}

/// The query extractor of the routes: a JSON `400` naming the parameter.
pub fn query_config() -> web::QueryConfig {
    web::QueryConfig::default().error_handler(|err: QueryPayloadError, _req: &HttpRequest| {
        AxiamApiError(AxiamError::Validation {
            message: format!("the query string is not valid: {err}"),
        })
        .into()
    })
}

// ---------------------------------------------------------------------------
// Values for the audit rows and the reactor payloads
// ---------------------------------------------------------------------------

fn segment_values(s: &NetworkSegment) -> Value {
    json!({
        "segment_id": s.id,
        "path": s.path(),
        "kind": s.kind.as_str(),
        "vlan_id": s.vlan_id,
        "filter_ids": s.filter_ids,
        "rank": s.rank,
        "enabled": s.enabled,
        "version": s.version,
    })
}

fn new_segment_values(i: &NewNetworkSegment) -> Value {
    json!({
        "path": i.path,
        "kind": i.kind.as_str(),
        "vlan_id": i.vlan_id,
        "filter_ids": i.filter_ids,
        "rank": i.rank,
        "enabled": i.enabled,
    })
}

fn update_values(u: &NetworkSegmentUpdate) -> Value {
    json!({
        "vlan_id": u.vlan_id,
        "filter_ids": u.filter_ids,
        "rank": u.rank,
        "enabled": u.enabled,
        "expected_version": u.expected_version,
    })
}

/// The effective profile (what a decision would render), with the version.
fn profile_values(p: &ReplyProfile) -> Value {
    json!({
        "segment_id": p.segment_id,
        "dictionary": p.dictionary,
        "session_timeout_secs": p.session_timeout_secs,
        "session_timeout_clamped": p.session_timeout_clamped,
        "termination_action": p.termination_action.as_str(),
        "idle_timeout_secs": p.idle_timeout_secs,
        "filter_id": p.filter_id,
        "service_type": p.service_type.map(|s| s.as_str()),
        "version": p.version,
    })
}

fn input_values(segment_id: Uuid, p: &ReplyProfileInput) -> Value {
    json!({
        "segment_id": segment_id,
        "dictionary": p.dictionary,
        "session_timeout_secs": p.session_timeout_secs,
        "termination_action": p.termination_action.as_str(),
        "idle_timeout_secs": p.idle_timeout_secs,
        "filter_id": p.filter_id,
        "service_type": p.service_type.map(|s| s.as_str()),
    })
}

fn policy_values(p: &NetworkPolicy) -> Value {
    json!({
        "session_timeout_max_secs": p.session_timeout_max_secs,
        "version": p.version,
    })
}

// ---------------------------------------------------------------------------
// Audit (design note §5.4)
// ---------------------------------------------------------------------------

/// One append-only row for a write that happened.
async fn audit_success<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    principal: &AuthenticatedPrincipal,
    action: &str,
    resource_id: Uuid,
    before: Value,
    after: Value,
) {
    append(
        state,
        CreateAuditLogEntry {
            tenant_id: principal.tenant_id,
            actor_id: principal.subject_id,
            actor_type: principal.actor_type(),
            action: action.to_owned(),
            resource_id: Some(resource_id),
            outcome: AuditOutcome::Success,
            ip_address: client_ip(http_req),
            metadata: Some(json!({ "before": before, "after": after })),
        },
    )
    .await;
}

async fn append<C: Connection + Clone>(state: &AppState<C>, entry: CreateAuditLogEntry) {
    let (tenant_id, action) = (entry.tenant_id, entry.action.clone());
    if let Err(error) = state.audit_repo.append(entry).await {
        tracing::error!(
            target: "axiam::network_admin",
            %tenant_id,
            action,
            %error,
            "a network management audit row could not be written"
        );
    }
}

/// What a refused write knows, for its audit row.
struct Refusal {
    /// The `*.write_refused` audit action.
    action: &'static str,
    /// The write, as the gate names it (`segment_create`, `profile_write`, …).
    write: &'static str,
    /// The segment concerned, when the request names one.
    resource_id: Option<Uuid>,
    before: Value,
    after: Value,
}

/// Record the refusal of a write that got past the body check and return the
/// error unchanged.
///
/// The gate audits its own refusals (`403`/`400`, with the rule and the missing
/// permission); what reaches here is everything after it — the reactor's veto,
/// a stale version, a profile that would be stranded, a value the dictionary
/// refuses, a uniqueness clash, a segment that is not the tenant's — each with
/// the **internal** reason, which the response does not carry. A failure of the
/// datastore is not a refusal and leaves no row.
async fn refused<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    principal: &AuthenticatedPrincipal,
    refusal: Refusal,
    error: AxiamApiError,
) -> NetworkApiError {
    let conflict = NetworkConflictReason::of(&error.0);
    let (rule, status, reason) = match &error.0 {
        AxiamError::NotFound { .. } => ("not_found", 404, error.0.to_string()),
        AxiamError::AlreadyExists { entity } => (
            conflict.map_or("exists", NetworkConflictReason::audit_rule),
            409,
            entity.clone(),
        ),
        AxiamError::Conflict { reason } => (
            conflict.map_or("conflict", NetworkConflictReason::audit_rule),
            409,
            reason.clone(),
        ),
        AxiamError::Validation { message } => ("validation", 400, message.clone()),
        AxiamError::AuthorizationDenied { reason, .. } => {
            let rule = if reason.starts_with("refused by a reactor") {
                "reactor:veto"
            } else {
                "clearance"
            };
            (rule, 403, reason.clone())
        }
        _ => return error.into(),
    };
    append(
        state,
        CreateAuditLogEntry {
            tenant_id: principal.tenant_id,
            actor_id: principal.subject_id,
            actor_type: principal.actor_type(),
            action: refusal.action.to_owned(),
            resource_id: refusal.resource_id,
            outcome: AuditOutcome::Denied,
            ip_address: client_ip(http_req),
            metadata: Some(json!({
                "write": refusal.write,
                "rule": rule,
                "reason": reason,
                "status": status,
                "before": refusal.before,
                "after": refusal.after,
            })),
        },
    )
    .await;
    error.into()
}

/// What the gate returned instead of a clearance.
///
/// The gate has already audited its own refusals (`403`, `400`) with the rule
/// and the missing permission; the one thing it cannot audit is a segment that
/// is not the tenant's (`404`), which is recorded here so that a write aimed at
/// another tenant's segment, or at one that does not exist, is not silent.
async fn after_gate<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    principal: &AuthenticatedPrincipal,
    refusal: Refusal,
    error: AxiamApiError,
) -> NetworkApiError {
    if matches!(error.0, AxiamError::NotFound { .. }) {
        refused(state, http_req, principal, refusal, error).await
    } else {
        error.into()
    }
}

/// `return Err(refused(..))` for an `Err`, the value for an `Ok`.
macro_rules! or_refuse {
    ($result:expr, $state:expr, $req:expr, $principal:expr, $refusal:expr) => {
        match $result {
            Ok(value) => value,
            Err(error) => {
                return Err(refused($state, $req, $principal, $refusal, error.into()).await);
            }
        }
    };
}

/// The gate's clearance for a segment or profile write.
fn write_clearance(
    cleared: axiam_authz::network_gate::GateClearance,
) -> Result<axiam_core::models::network::NetworkWriteClearance, AxiamApiError> {
    cleared.into_write_clearance().ok_or_else(|| {
        AxiamApiError(AxiamError::Internal(
            "the network gate cleared a segment or profile write without a clearance".into(),
        ))
    })
}

fn segments<C: Connection + Clone>(state: &AppState<C>) -> SurrealNetworkSegmentRepository<C> {
    SurrealNetworkSegmentRepository::new(state.db.clone())
}

fn profiles<C: Connection + Clone>(state: &AppState<C>) -> SurrealReplyProfileRepository<C> {
    SurrealReplyProfileRepository::new(state.db.clone())
}

fn policies<C: Connection + Clone>(state: &AppState<C>) -> SurrealNetworkPolicyRepository<C> {
    SurrealNetworkPolicyRepository::new(state.db.clone())
}

fn hook_payload(
    principal: &AuthenticatedPrincipal,
    operation: &str,
    segment_id: Option<Uuid>,
    before: &Value,
    after: &Value,
) -> Value {
    json!({
        "operation": operation,
        "tenant_id": principal.tenant_id,
        "segment_id": segment_id,
        "before": before,
        "after": after,
        // Who is asking, and which kind of principal: the half a four-eyes
        // rule is about.
        "actor_id": principal.subject_id,
        "actor_type": principal.actor_kind(),
    })
}

// ---------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------

/// `GET /api/v1/network/segments`
#[utoipa::path(
    get,
    path = "/api/v1/network/segments",
    tag = "network",
    params(Pagination, SiteQuery),
    responses(
        (status = 200, description = "A page of the tenant's network segments, by site, then \
                                      rank, then name. `search` matches name, site key and id, \
                                      before paging",
         body = inline(PaginatedResult<NetworkSegmentResponse>)),
        (status = 401, description = "Not authenticated, or a service-account token (the \
                                      network routes are human-only)"),
        (status = 403, description = "The caller lacks `network:read` on `/network`"),
    ),
    security(("bearer" = []))
)]
pub async fn list_segments<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<Pagination>,
    site: web::Query<SiteQuery>,
) -> Result<HttpResponse, NetworkApiError> {
    RequirePermission::new(NETWORK_READ, network_root_id(user.tenant_id))
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let page = segments(&state)
        .list_page(
            user.tenant_id,
            site.site.as_deref().filter(|s| !s.is_empty()),
            query.into_inner(),
        )
        .await?;
    Ok(HttpResponse::Ok().json(PaginatedResult {
        items: page
            .items
            .into_iter()
            .map(NetworkSegmentResponse::from)
            .collect::<Vec<_>>(),
        total: page.total,
        offset: page.offset,
        limit: page.limit,
    }))
}

/// `GET /api/v1/network/segments/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/network/segments/{id}",
    tag = "network",
    params(("id" = Uuid, Path, description = "Segment ID")),
    responses(
        (status = 200, description = "The segment", body = NetworkSegmentResponse),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:read` on the segment"),
        (status = 404, description = "No such segment in this tenant"),
    ),
    security(("bearer" = []))
)]
pub async fn get_segment<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, NetworkApiError> {
    let id = path.into_inner();
    RequirePermission::new(NETWORK_READ, id)
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let segment = segments(&state).get(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(NetworkSegmentResponse::from(segment)))
}

/// `POST /api/v1/network/segments`
#[utoipa::path(
    post,
    path = "/api/v1/network/segments",
    tag = "network",
    request_body = CreateNetworkSegmentRequest,
    responses(
        (status = 201, description = "The segment was created, with the `/network`, branch and \
                                      site nodes it needed",
         body = NetworkSegmentResponse),
        (status = 400, description = "A value rule — the message names the field — or a path \
                                      outside `/network/{zones|quarantine}/<site>/<segment>`"),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:segments_write` at the parent \
                                      node (the response names the permission and the node), or \
                                      a reactor vetoed the write"),
        (status = 409, description = "`already_exists` with `reason_code` `duplicate_name`, \
                                      `duplicate_vlan` or `duplicate_rank`: the site already has \
                                      a segment with this name, VLAN or rank; or `conflict` with \
                                      `site_gone`: the site node was removed while the segment \
                                      was being created",
         body = NetworkConflictResponse),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn create_segment<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<CreateNetworkSegmentRequest>,
) -> Result<HttpResponse, NetworkApiError> {
    let principal = AuthenticatedPrincipal::from(user);
    let req = body.into_inner();
    let input = NewNetworkSegment {
        tenant_id: principal.tenant_id,
        path: render_path(req.kind, &req.site_key, &req.name),
        kind: req.kind,
        vlan_id: req.vlan_id,
        filter_ids: req.filter_ids,
        rank: req.rank,
        enabled: req.enabled,
        actor: principal.subject_id,
    };
    let after = new_segment_values(&input);
    let refusal = || Refusal {
        action: AUDIT_SEGMENT_WRITE_REFUSED,
        write: "segment_create",
        resource_id: None,
        before: json!({ "segment": "none" }),
        after: after.clone(),
    };

    let cleared = network_gate::authorize(
        &principal,
        authz.get_ref().as_ref(),
        &state,
        NetworkWrite::SegmentCreate { input: &input },
    )
    .await?;
    let clearance = write_clearance(cleared)?;
    let segment_repo = segments(&state);

    or_refuse!(
        reactor_hooks::network_pre_segment_write(
            &state.events.reactor_gate,
            principal.tenant_id,
            hook_payload(&principal, "create", None, &Value::Null, &after),
        )
        .await,
        &state,
        &http_req,
        &principal,
        refusal()
    );

    let created = or_refuse!(
        segment_repo.create(input, &clearance).await,
        &state,
        &http_req,
        &principal,
        refusal()
    );
    audit_success(
        &state,
        &http_req,
        &principal,
        AUDIT_SEGMENT_CREATED,
        created.id,
        Value::Null,
        segment_values(&created),
    )
    .await;
    Ok(HttpResponse::Created().json(NetworkSegmentResponse::from(created)))
}

/// `PUT /api/v1/network/segments/{id}`
///
/// A **replacement** of the envelope, conditional on `version`. The kind and the
/// segment's place in the tree do not change.
#[utoipa::path(
    put,
    path = "/api/v1/network/segments/{id}",
    tag = "network",
    params(("id" = Uuid, Path, description = "Segment ID")),
    request_body = ReplaceNetworkSegmentRequest,
    responses(
        (status = 200, description = "The segment's new envelope", body = NetworkSegmentResponse),
        (status = 400, description = "A value rule — the message names the field"),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:segments_write` on the segment; \
                                      or the segment has a reply profile, the replace changes \
                                      `vlan_id`, `rank` or `enabled`, and the caller lacks \
                                      `network:grant` on the segment (and, for a quarantine \
                                      segment, on `/network/quarantine/<site>`) — that change \
                                      re-places every device that may join it; or the caller \
                                      holds `network:join` on it (H6); or a reactor vetoed the \
                                      write. The response names the missing permission and \
                                      node"),
        (status = 404, description = "No such segment in this tenant"),
        (status = 409, description = "`reason_code` says which: `stale_version` — the segment \
                                      changed since `version` was read, or a reply profile was \
                                      written on it since; `strands_profile` — the new \
                                      `filter_ids` would leave its reply profile outside the \
                                      envelope (the message names the profile); \
                                      `duplicate_vlan` / `duplicate_rank` (`already_exists`) — \
                                      the site already has a segment with this VLAN or rank",
         body = NetworkConflictResponse),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn replace_segment<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<ReplaceNetworkSegmentRequest>,
) -> Result<HttpResponse, NetworkApiError> {
    let principal = AuthenticatedPrincipal::from(user);
    let id = path.into_inner();
    let req = body.into_inner();
    let update = NetworkSegmentUpdate {
        expected_version: req.version,
        vlan_id: req.vlan_id,
        filter_ids: req.filter_ids,
        rank: req.rank,
        enabled: req.enabled,
        actor: principal.subject_id,
    };
    let after = update_values(&update);
    let refusal = |before: Value| Refusal {
        action: AUDIT_SEGMENT_WRITE_REFUSED,
        write: "segment_update",
        resource_id: Some(id),
        before,
        after: after.clone(),
    };

    let cleared = match network_gate::authorize(
        &principal,
        authz.get_ref().as_ref(),
        &state,
        NetworkWrite::SegmentUpdate {
            segment_id: id,
            update: &update,
        },
    )
    .await
    {
        Ok(cleared) => cleared,
        Err(error) => {
            return Err(
                after_gate(&state, &http_req, &principal, refusal(Value::Null), error).await,
            );
        }
    };
    let clearance = write_clearance(cleared)?;

    let segment_repo = segments(&state);
    let stored = or_refuse!(
        segment_repo.get(principal.tenant_id, id).await,
        &state,
        &http_req,
        &principal,
        refusal(Value::Null)
    );
    let before = segment_values(&stored);

    or_refuse!(
        reactor_hooks::network_pre_segment_write(
            &state.events.reactor_gate,
            principal.tenant_id,
            hook_payload(&principal, "replace", Some(id), &before, &after),
        )
        .await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );

    let updated = match segment_repo
        .update(principal.tenant_id, id, update, &clearance)
        .await
    {
        Ok(updated) => updated,
        Err(error) => {
            let error = name_the_stranded_profile(&state, principal.tenant_id, id, error).await;
            return Err(
                refused(&state, &http_req, &principal, refusal(before), error.into()).await,
            );
        }
    };
    audit_success(
        &state,
        &http_req,
        &principal,
        AUDIT_SEGMENT_UPDATED,
        id,
        before,
        segment_values(&updated),
    )
    .await;
    Ok(HttpResponse::Ok().json(NetworkSegmentResponse::from(updated)))
}

/// The repository refuses an envelope that would strand the segment's profile
/// with a generic `Conflict` (it cannot name what the segment's id already
/// does): add the profile's id (it is the segment's) and the `filter_id` it uses.
async fn name_the_stranded_profile<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    segment_id: Uuid,
    error: AxiamError,
) -> AxiamError {
    let AxiamError::Conflict { reason } = &error else {
        return error;
    };
    if !reason.contains("outside its envelope") {
        return error;
    }
    let used = profiles(state)
        .get_by_segment(tenant_id, segment_id)
        .await
        .ok()
        .and_then(|p| p.filter_id);
    AxiamError::Conflict {
        reason: match used {
            Some(filter_id) => format!(
                "the segment's reply profile {segment_id} uses filter_id '{filter_id}', which \
                 the new filter_ids remove; change or delete the profile first"
            ),
            None => format!(
                "the new filter_ids would leave the segment's reply profile {segment_id} \
                 outside its envelope; change or delete the profile first"
            ),
        },
    }
}

/// `DELETE /api/v1/network/segments/{id}?version=`
///
/// The segment, **its reply profile** and its resource node, in one
/// transaction. Role assignments and grants naming the node are not touched;
/// the node is simply gone.
#[utoipa::path(
    delete,
    path = "/api/v1/network/segments/{id}",
    tag = "network",
    params(("id" = Uuid, Path, description = "Segment ID"), VersionQuery),
    responses(
        (status = 204, description = "The segment and its profile were deleted"),
        (status = 400, description = "`version` is missing or not a number"),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:segments_write` on the segment, \
                                      or a reactor vetoed the write"),
        (status = 404, description = "No such segment in this tenant"),
        (status = 409, description = "`reason_code` `stale_version`: the segment changed since \
                                      `version` was read; or `has_children`: it has child \
                                      resources",
         body = NetworkConflictResponse),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_segment<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    query: web::Query<VersionQuery>,
) -> Result<HttpResponse, NetworkApiError> {
    let principal = AuthenticatedPrincipal::from(user);
    let id = path.into_inner();
    let expected_version = query.version;
    let after = json!({ "segment": "deleted", "expected_version": expected_version });
    let refusal = |before: Value| Refusal {
        action: AUDIT_SEGMENT_WRITE_REFUSED,
        write: "segment_delete",
        resource_id: Some(id),
        before,
        after: after.clone(),
    };

    let cleared = match network_gate::authorize(
        &principal,
        authz.get_ref().as_ref(),
        &state,
        NetworkWrite::SegmentDelete { segment_id: id },
    )
    .await
    {
        Ok(cleared) => cleared,
        Err(error) => {
            return Err(
                after_gate(&state, &http_req, &principal, refusal(Value::Null), error).await,
            );
        }
    };
    let clearance = write_clearance(cleared)?;

    let segment_repo = segments(&state);
    let stored = or_refuse!(
        segment_repo.get(principal.tenant_id, id).await,
        &state,
        &http_req,
        &principal,
        refusal(Value::Null)
    );
    let before = segment_values(&stored);

    or_refuse!(
        reactor_hooks::network_pre_segment_write(
            &state.events.reactor_gate,
            principal.tenant_id,
            hook_payload(&principal, "delete", Some(id), &before, &after),
        )
        .await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );

    or_refuse!(
        segment_repo
            .delete(principal.tenant_id, id, expected_version, &clearance)
            .await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );
    audit_success(
        &state,
        &http_req,
        &principal,
        AUDIT_SEGMENT_DELETED,
        id,
        before,
        after,
    )
    .await;
    Ok(HttpResponse::NoContent().finish())
}

// ---------------------------------------------------------------------------
// Reply profiles
// ---------------------------------------------------------------------------

/// `GET /api/v1/network/profiles`
#[utoipa::path(
    get,
    path = "/api/v1/network/profiles",
    tag = "network",
    params(Pagination),
    responses(
        (status = 200, description = "A page of the tenant's reply profiles, by owning segment \
                                      id. Each is the effective profile: `session_timeout_secs` \
                                      already lowered to the tenant's current cap \
                                      (`session_timeout_clamped` says so). `search` matches \
                                      `filter_id` and the segment id, before paging",
         body = inline(PaginatedResult<ReplyProfile>)),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:read` on `/network`"),
    ),
    security(("bearer" = []))
)]
pub async fn list_profiles<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    query: web::Query<Pagination>,
) -> Result<HttpResponse, NetworkApiError> {
    RequirePermission::new(NETWORK_READ, network_root_id(user.tenant_id))
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let page = profiles(&state)
        .list_page(user.tenant_id, query.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(page))
}

/// `GET /api/v1/network/profiles/{segment_id}`
#[utoipa::path(
    get,
    path = "/api/v1/network/profiles/{segment_id}",
    tag = "network",
    params(("segment_id" = Uuid, Path, description = "ID of the segment that owns the profile")),
    responses(
        (status = 200, description = "The segment's effective reply profile: \
                                      `session_timeout_secs` is the stored value lowered to the \
                                      tenant's current cap, and `session_timeout_clamped` says \
                                      when it was. A replace above the cap is refused (H3), so \
                                      writing back a clamped read cannot restore the stored \
                                      value; raising the cap first restores it at read",
         body = ReplyProfile),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:read` on the segment"),
        (status = 404, description = "The segment does not exist in this tenant, or has no \
                                      profile"),
    ),
    security(("bearer" = []))
)]
pub async fn get_profile<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, NetworkApiError> {
    let segment_id = path.into_inner();
    RequirePermission::new(NETWORK_READ, segment_id)
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let profile = profiles(&state)
        .get_by_segment(user.tenant_id, segment_id)
        .await?;
    Ok(HttpResponse::Ok().json(profile))
}

/// `POST /api/v1/network/profiles`
#[utoipa::path(
    post,
    path = "/api/v1/network/profiles",
    tag = "network",
    request_body = CreateReplyProfileRequest,
    responses(
        (status = 201, description = "The profile was created; the body is the effective \
                                      profile", body = ReplyProfile),
        (status = 400, description = "A value outside the dictionary (an unknown key is named), \
                                      or `idle_timeout_secs` / `session_timeout_secs` outside \
                                      their bounds"),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The write gate refused it (§5.2): the caller lacks \
                                      `network:profiles_write` (H1) or `network:grant` (H2) on \
                                      the segment, the `filter_id` is outside the segment's \
                                      envelope or `session_timeout_secs` above the tenant cap \
                                      (H3), the caller can itself join the segment (H6) — the \
                                      response names the permission and the node when one is \
                                      missing — or a reactor vetoed the write"),
        (status = 404, description = "No such segment in this tenant"),
        (status = 409, description = "`reason_code` `profile_exists` (`already_exists`): the \
                                      segment already has a profile; or `stale_version`: the \
                                      segment changed since `segment_version` was read",
         body = NetworkConflictResponse),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn create_profile<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<CreateReplyProfileRequest>,
) -> Result<HttpResponse, NetworkApiError> {
    let principal = AuthenticatedPrincipal::from(user);
    let req = body.into_inner();
    let segment_id = req.segment_id;
    let after = input_values(segment_id, &req.profile);
    let refusal = || Refusal {
        action: AUDIT_PROFILE_WRITE_REFUSED,
        write: "profile_write",
        resource_id: Some(segment_id),
        before: json!({ "profile": "none" }),
        after: after.clone(),
    };

    let cleared = match network_gate::authorize(
        &principal,
        authz.get_ref().as_ref(),
        &state,
        NetworkWrite::ProfileWrite {
            segment_id,
            input: &req.profile,
        },
    )
    .await
    {
        Ok(cleared) => cleared,
        Err(error) => return Err(after_gate(&state, &http_req, &principal, refusal(), error).await),
    };
    let clearance = write_clearance(cleared)?;
    let profile_repo = profiles(&state);

    or_refuse!(
        reactor_hooks::network_pre_profile_write(
            &state.events.reactor_gate,
            principal.tenant_id,
            hook_payload(&principal, "create", Some(segment_id), &Value::Null, &after),
        )
        .await,
        &state,
        &http_req,
        &principal,
        refusal()
    );

    let created = or_refuse!(
        profile_repo
            .create(
                principal.tenant_id,
                segment_id,
                NewReplyProfile {
                    expected_segment_version: req.segment_version,
                    profile: req.profile,
                    actor: principal.subject_id,
                },
                &clearance,
            )
            .await,
        &state,
        &http_req,
        &principal,
        refusal()
    );
    audit_success(
        &state,
        &http_req,
        &principal,
        AUDIT_PROFILE_CREATED,
        segment_id,
        Value::Null,
        profile_values(&created),
    )
    .await;
    Ok(HttpResponse::Created().json(created))
}

/// `PUT /api/v1/network/profiles/{segment_id}`
///
/// A **replacement** of the segment's profile, conditional on the profile's
/// `version` and the segment's.
#[utoipa::path(
    put,
    path = "/api/v1/network/profiles/{segment_id}",
    tag = "network",
    params(("segment_id" = Uuid, Path, description = "ID of the segment that owns the profile")),
    request_body = ReplaceReplyProfileRequest,
    responses(
        (status = 200, description = "The new effective profile", body = ReplyProfile),
        (status = 400, description = "A value outside the dictionary or its bounds"),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The write gate refused it (H1 … H6, as for create), or a \
                                      reactor vetoed the write"),
        (status = 404, description = "No such segment in this tenant, or it has no profile"),
        (status = 409, description = "`reason_code` `stale_version`: the profile changed since \
                                      `version` was read, or the segment since `segment_version`",
         body = NetworkConflictResponse),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn replace_profile<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    body: web::Json<ReplaceReplyProfileRequest>,
) -> Result<HttpResponse, NetworkApiError> {
    let principal = AuthenticatedPrincipal::from(user);
    let segment_id = path.into_inner();
    let req = body.into_inner();
    let mut after = input_values(segment_id, &req.profile);
    after["expected_version"] = json!(req.version);
    after["expected_segment_version"] = json!(req.segment_version);
    let refusal = |before: Value| Refusal {
        action: AUDIT_PROFILE_WRITE_REFUSED,
        write: "profile_write",
        resource_id: Some(segment_id),
        before,
        after: after.clone(),
    };

    let cleared = match network_gate::authorize(
        &principal,
        authz.get_ref().as_ref(),
        &state,
        NetworkWrite::ProfileWrite {
            segment_id,
            input: &req.profile,
        },
    )
    .await
    {
        Ok(cleared) => cleared,
        Err(error) => {
            return Err(
                after_gate(&state, &http_req, &principal, refusal(Value::Null), error).await,
            );
        }
    };
    let clearance = write_clearance(cleared)?;

    let profile_repo = profiles(&state);
    let stored = or_refuse!(
        profile_repo
            .get_by_segment(principal.tenant_id, segment_id)
            .await,
        &state,
        &http_req,
        &principal,
        refusal(Value::Null)
    );
    let before = profile_values(&stored);

    or_refuse!(
        reactor_hooks::network_pre_profile_write(
            &state.events.reactor_gate,
            principal.tenant_id,
            hook_payload(&principal, "replace", Some(segment_id), &before, &after),
        )
        .await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );

    let replaced = or_refuse!(
        profile_repo
            .replace(
                principal.tenant_id,
                segment_id,
                ReplyProfileReplace {
                    expected_version: req.version,
                    expected_segment_version: req.segment_version,
                    profile: req.profile,
                    actor: principal.subject_id,
                },
                &clearance,
            )
            .await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );
    audit_success(
        &state,
        &http_req,
        &principal,
        AUDIT_PROFILE_REPLACED,
        segment_id,
        before,
        profile_values(&replaced),
    )
    .await;
    Ok(HttpResponse::Ok().json(replaced))
}

/// `DELETE /api/v1/network/profiles/{segment_id}?version=`
///
/// No profile means the segment is not a placement candidate, which only
/// narrows; the write gate asks `network:profiles_write` alone (H1).
#[utoipa::path(
    delete,
    path = "/api/v1/network/profiles/{segment_id}",
    tag = "network",
    params(
        ("segment_id" = Uuid, Path, description = "ID of the segment that owns the profile"),
        VersionQuery,
    ),
    responses(
        (status = 204, description = "The profile was deleted"),
        (status = 400, description = "`version` is missing or not a number"),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:profiles_write` on the segment, \
                                      or a reactor vetoed the write"),
        (status = 404, description = "No such segment in this tenant, or it has no profile"),
        (status = 409, description = "`reason_code` `stale_version`: the profile changed since \
                                      `version` was read",
         body = NetworkConflictResponse),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn delete_profile<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    path: web::Path<Uuid>,
    query: web::Query<VersionQuery>,
) -> Result<HttpResponse, NetworkApiError> {
    let principal = AuthenticatedPrincipal::from(user);
    let segment_id = path.into_inner();
    let expected_version = query.version;
    let after = json!({ "profile": "deleted", "expected_version": expected_version });
    let refusal = |before: Value| Refusal {
        action: AUDIT_PROFILE_WRITE_REFUSED,
        write: "profile_delete",
        resource_id: Some(segment_id),
        before,
        after: after.clone(),
    };

    let cleared = match network_gate::authorize(
        &principal,
        authz.get_ref().as_ref(),
        &state,
        NetworkWrite::ProfileDelete { segment_id },
    )
    .await
    {
        Ok(cleared) => cleared,
        Err(error) => {
            return Err(
                after_gate(&state, &http_req, &principal, refusal(Value::Null), error).await,
            );
        }
    };
    let clearance = write_clearance(cleared)?;

    let profile_repo = profiles(&state);
    let stored = or_refuse!(
        profile_repo
            .get_by_segment(principal.tenant_id, segment_id)
            .await,
        &state,
        &http_req,
        &principal,
        refusal(Value::Null)
    );
    let before = profile_values(&stored);

    or_refuse!(
        reactor_hooks::network_pre_profile_write(
            &state.events.reactor_gate,
            principal.tenant_id,
            hook_payload(&principal, "delete", Some(segment_id), &before, &after),
        )
        .await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );

    or_refuse!(
        profile_repo
            .delete(
                principal.tenant_id,
                segment_id,
                expected_version,
                &clearance
            )
            .await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );
    audit_success(
        &state,
        &http_req,
        &principal,
        AUDIT_PROFILE_DELETED,
        segment_id,
        before,
        after,
    )
    .await;
    Ok(HttpResponse::NoContent().finish())
}

// ---------------------------------------------------------------------------
// The tenant's Session-Timeout cap
// ---------------------------------------------------------------------------

/// `GET /api/v1/network/policy`
///
/// The tenant's `Session-Timeout` cap. A tenant that never wrote one reads the
/// default (3600 seconds, `version` 0).
#[utoipa::path(
    get,
    path = "/api/v1/network/policy",
    tag = "network",
    responses(
        (status = 200, description = "The tenant's network policy: the cap on a reply \
                                      profile's `Session-Timeout` (3600 and `version` 0 until \
                                      the tenant first writes one)",
         body = NetworkPolicyResponse),
        (status = 401, description = "Not authenticated, or a service-account token (the \
                                      network routes are human-only)"),
        (status = 403, description = "The caller lacks `network:read` on `/network`"),
    ),
    security(("bearer" = []))
)]
pub async fn get_policy<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, NetworkApiError> {
    RequirePermission::new(NETWORK_READ, network_root_id(user.tenant_id))
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let policy = policies(&state).get(user.tenant_id).await?;
    Ok(HttpResponse::Ok().json(NetworkPolicyResponse::from(policy)))
}

/// `PUT /api/v1/network/policy`
///
/// A **replacement** of the tenant's `Session-Timeout` cap, conditional on
/// `version`. Needs `network:segments_write` at the `/network` root (the cap is
/// the envelope every profile is clamped to); `network:profiles_write` alone
/// does not suffice, nor does a grant at a site below the root.
#[utoipa::path(
    put,
    path = "/api/v1/network/policy",
    tag = "network",
    request_body = ReplaceNetworkPolicyRequest,
    responses(
        (status = 200, description = "The new policy. Lowering the cap is always allowed, \
                                      even below an existing profile's `session_timeout_secs`: \
                                      the stored value is untouched and every read clamps it \
                                      to the cap (`session_timeout_clamped`), so raising the \
                                      cap again restores it — unless the profile was replaced \
                                      meanwhile: a replace stores what it carries and is \
                                      refused above the cap (H3), so one written back from a \
                                      clamped read stores the clamped value. Raising the cap is \
                                      allowed and \
                                      audited as `network_policy.raised`; lowering as \
                                      `network_policy.lowered`, each with the cap before and \
                                      after",
         body = NetworkPolicyResponse),
        (status = 400, description = "`session_timeout_max_secs` outside 300 to 86 400, or an \
                                      unknown field"),
        (status = 401, description = "Not authenticated, or a service-account token"),
        (status = 403, description = "The caller lacks `network:segments_write` on `/network` (the \
                                      response names the permission and the node)"),
        (status = 409, description = "`reason_code` `stale_version`: the policy changed since \
                                      `version` was read",
         body = NetworkConflictResponse),
        (status = 429, description = "Rate limit"),
    ),
    security(("bearer" = []))
)]
pub async fn replace_policy<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    http_req: HttpRequest,
    body: web::Json<ReplaceNetworkPolicyRequest>,
) -> Result<HttpResponse, NetworkApiError> {
    let principal = AuthenticatedPrincipal::from(user);
    let req = body.into_inner();
    let tenant_id = principal.tenant_id;
    let input = SetNetworkPolicy {
        session_timeout_max_secs: req.session_timeout_max_secs,
        expected_version: req.version,
        actor: principal.subject_id,
    };
    let requested = json!({
        "session_timeout_max_secs": input.session_timeout_max_secs,
        "expected_version": input.expected_version,
    });
    let refusal = |before: Value| Refusal {
        action: AUDIT_POLICY_WRITE_REFUSED,
        write: "policy_replace",
        resource_id: Some(tenant_id),
        before,
        after: requested.clone(),
    };

    let cleared = network_gate::authorize(
        &principal,
        authz.get_ref().as_ref(),
        &state,
        NetworkWrite::PolicyWrite {
            session_timeout_max_secs: input.session_timeout_max_secs,
        },
    )
    .await?;
    let clearance = write_clearance(cleared)?;

    let network_policy_repo = policies(&state);
    let stored = network_policy_repo.get(tenant_id).await?;
    let before = policy_values(&stored);
    // The write is conditional on the version the caller read; if that is the
    // version read just now, the cap compared here is the one the write
    // replaces, and if it is not the write is a `409` and the direction moot.
    let change = CapChange::between(
        stored.session_timeout_max_secs,
        input.session_timeout_max_secs,
    );

    if let Err(error) = input.validate() {
        return Err(refused(&state, &http_req, &principal, refusal(before), error.into()).await);
    }

    let written = or_refuse!(
        network_policy_repo.set(tenant_id, input, &clearance).await,
        &state,
        &http_req,
        &principal,
        refusal(before.clone())
    );
    let after = policy_values(&written);
    append(
        &state,
        CreateAuditLogEntry {
            tenant_id,
            actor_id: principal.subject_id,
            actor_type: principal.actor_type(),
            action: match change {
                CapChange::Raised => AUDIT_POLICY_RAISED,
                CapChange::Lowered => AUDIT_POLICY_LOWERED,
                CapChange::Unchanged => AUDIT_POLICY_UNCHANGED,
            }
            .to_owned(),
            resource_id: Some(tenant_id),
            outcome: AuditOutcome::Success,
            ip_address: client_ip(&http_req),
            metadata: Some(json!({
                "direction": change.as_str(),
                "before": before,
                "after": after,
            })),
        },
    )
    .await;
    Ok(HttpResponse::Ok().json(NetworkPolicyResponse::from(written)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conflict(reason: &str) -> AxiamError {
        AxiamError::Conflict {
            reason: reason.into(),
        }
    }

    fn exists(entity: &str) -> AxiamError {
        AxiamError::AlreadyExists {
            entity: entity.into(),
        }
    }

    /// The sentences the network repositories and this module write, each to
    /// its value; the route test pins the paths that reach them end to end,
    /// and this pins the two a route test cannot provoke on demand (a site
    /// removed mid-create, a profile written between the gate and the write).
    #[test]
    fn each_409_sentence_has_its_reason_code() {
        use NetworkConflictReason as R;
        for (error, want) in [
            (
                conflict("the network segment changed since it was read; read it again and retry"),
                R::StaleVersion,
            ),
            (
                conflict(
                    "the network segment changed since it was read (a reply profile was \
                     written on it); read it again and retry",
                ),
                R::StaleVersion,
            ),
            (
                conflict("the reply profile changed since it was read; read it again and retry"),
                R::StaleVersion,
            ),
            (
                conflict("the network policy changed since it was read; read it again and retry"),
                R::StaleVersion,
            ),
            (
                conflict(
                    "the segment's reply profile 1 uses filter_id 'a', which the new \
                     filter_ids remove; change or delete the profile first",
                ),
                R::StrandsProfile,
            ),
            (
                conflict(
                    "the new filter_ids would leave the segment's reply profile outside its \
                     envelope; change or delete the profile first",
                ),
                R::StrandsProfile,
            ),
            (
                conflict("the network segment has child resources"),
                R::HasChildren,
            ),
            (
                conflict("the network site was removed while the segment was being written; retry"),
                R::SiteGone,
            ),
            (conflict("something new"), R::Other),
            (
                exists("network_segment: the site already has a segment with this vlan_id"),
                R::DuplicateVlan,
            ),
            (
                exists("network_segment: the site already has a segment with this rank"),
                R::DuplicateRank,
            ),
            (
                exists("network_segment: the site already has a segment of this name"),
                R::DuplicateName,
            ),
            (exists("reply_profile"), R::ProfileExists),
            (exists("network_segment"), R::Other),
        ] {
            assert_eq!(NetworkConflictReason::of(&error), Some(want), "{error}");
        }
        assert_eq!(
            NetworkConflictReason::of(&AxiamError::Validation {
                message: "x".into()
            }),
            None
        );
    }

    #[test]
    fn the_wire_values_are_snake_case_and_match_as_str() {
        use NetworkConflictReason as R;
        for r in [
            R::StaleVersion,
            R::StrandsProfile,
            R::HasChildren,
            R::DuplicateName,
            R::DuplicateVlan,
            R::DuplicateRank,
            R::ProfileExists,
            R::SiteGone,
            R::Other,
        ] {
            assert_eq!(serde_json::to_value(r).unwrap(), r.as_str());
        }
    }
}

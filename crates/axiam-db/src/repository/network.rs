//! SurrealDB implementations of [`NetworkSegmentRepository`],
//! [`ReplyProfileRepository`] and [`NetworkPolicyRepository`] (RADIUS D4, W6.1,
//! schema v100; `claude_dev/radius-reply-profile-design.md` §3.5 and §4).
//!
//! # Segments are resources
//!
//! A segment is a `resource` row in the reserved `/network` subtree plus a
//! `network_segment` sidecar that shares its id. The two are written in **one
//! transaction**, together with whichever of the `/network`, branch and site
//! nodes do not exist yet. Those reserved nodes have **deterministic ids**
//! (a v5 UUID of the tenant and the node's path), so two writers that both find
//! a node missing both try to create the same record, and the engine's key
//! conflict decides the race — instead of each making a node of its own and the
//! tree growing two `/network` roots.
//!
//! Nothing in this module writes outside the reserved subtree, and a path that
//! is not `/network/{zones|quarantine}/<site>/<segment>` is refused before the
//! datastore is touched ([`NetworkSegmentPath::parse`]).
//!
//! # Two writers, one version
//!
//! Every write names the version it read and is conditional on it **inside the
//! write's own transaction**: the check runs against the row the write replaces.
//!
//! A profile is also written under the **segment's** version, and the profile
//! transaction writes the segment row (it bumps `profile_epoch`, a counter whose
//! value is never read). That is what makes the two writers conflict: the
//! engine detects two transactions writing the same key, not a read that a later
//! write invalidates, so without the shared write a segment's `filter_ids` could
//! change between the profile's envelope check and its commit (the T-416
//! lesson, design note §3.5). For the same reason the segment's own update
//! re-reads the stored profile inside its transaction. The shared write follows
//! `resource`'s `claim_parent` (#308); the racing-writers test pins the invariant
//! on the engine production deploys, and did not distinguish this write from a
//! plain read of the version on that engine, so it is the precedent's
//! belt-and-braces rather than a measured necessity.
//!
//! # Clamped at read
//!
//! [`ReplyProfileRepository`] returns the **effective** profile: its
//! `Session-Timeout` is lowered to the tenant's *current* cap on every read
//! (design note §3.4), so lowering the cap narrows every stored profile at once
//! and nothing has to be rewritten.

use std::collections::HashMap;
use std::fmt;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::network::{
    NETWORK_ROOT_NAME, NetworkPolicy, NetworkSegment, NetworkSegmentKind, NetworkSegmentPath,
    NetworkSegmentUpdate, NetworkWriteClearance, NetworkWriteTarget, NewNetworkSegment,
    NewReplyProfile, RESOURCE_TYPE_NETWORK_BRANCH, RESOURCE_TYPE_NETWORK_ROOT,
    RESOURCE_TYPE_NETWORK_SEGMENT, RESOURCE_TYPE_NETWORK_SITE, ReplyProfile, ReplyProfileReplace,
    SetNetworkPolicy, StoredReplyProfile, reserved_node_id, validate_segment_fields,
};
use axiam_core::models::radius_reply::{
    DEFAULT_SESSION_TIMEOUT_MAX_SECS, ReplyProfileInput, SESSION_TIMEOUT_CAP_CEILING_SECS,
    SESSION_TIMEOUT_FLOOR_SECS, ServiceType, TerminationAction, clamp_session_timeout,
};
use axiam_core::repository::{
    NetworkPolicyRepository, NetworkSegmentRepository, PaginatedResult, Pagination,
    ReplyProfileRepository,
};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_write_error, paginate, parse_uuid, retry_on_write_conflict, search_bind,
    search_filter, take_first_or_not_found,
};

const SEGMENT_ENTITY: &str = "network_segment";
const PROFILE_ENTITY: &str = "reply_profile";
const POLICY_ENTITY: &str = "network_policy";

// The messages the write transactions `THROW`. Matched on the way out, so the
// caller sees `Conflict` rather than an opaque database error.
const STALE_SEGMENT: &str = "axiam:network_segment_version_stale";
const STALE_PROFILE: &str = "axiam:reply_profile_version_stale";
const STRANDS_PROFILE: &str = "axiam:segment_update_strands_profile";
const HAS_CHILDREN: &str = "axiam:network_segment_has_children";
const SITE_GONE: &str = "axiam:network_site_gone";

// ---------------------------------------------------------------------------
// Errors out of a write transaction
// ---------------------------------------------------------------------------

/// What a write transaction came back with: an answer for the caller, or the
/// datastore's own error (which may be a retryable write conflict).
///
/// `Display` renders the datastore's text for a database error, which is what
/// [`retry_on_write_conflict`] reads to decide whether to run the attempt again.
#[derive(Debug)]
enum TxFail {
    Refused(AxiamError),
    Db(DbError),
}

impl fmt::Display for TxFail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(e) => write!(f, "{e}"),
            Self::Db(e) => write!(f, "{e}"),
        }
    }
}

impl From<TxFail> for AxiamError {
    fn from(fail: TxFail) -> Self {
        match fail {
            TxFail::Refused(e) => e,
            TxFail::Db(e) => e.into(),
        }
    }
}

impl From<DbError> for TxFail {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}

impl From<surrealdb::Error> for TxFail {
    fn from(e: surrealdb::Error) -> Self {
        Self::Db(DbError::from(e))
    }
}

fn conflict(reason: &str) -> TxFail {
    TxFail::Refused(AxiamError::Conflict {
        reason: reason.into(),
    })
}

/// Turn a transaction's statement errors into the right answer.
///
/// Every statement's error is scanned rather than only the first: a `THROW`
/// fires on its own slot while the statements after it report the generic "not
/// executed due to a failed transaction", and `check()` can surface either.
fn tx_outcome(errors: HashMap<usize, surrealdb::Error>, entity: &str) -> Result<(), TxFail> {
    if errors.is_empty() {
        return Ok(());
    }
    let combined = errors
        .into_values()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if combined.contains(STALE_SEGMENT) {
        return Err(conflict(
            "the network segment changed since it was read; read it again and retry",
        ));
    }
    if combined.contains(STALE_PROFILE) {
        return Err(conflict(
            "the reply profile changed since it was read; read it again and retry",
        ));
    }
    if combined.contains(STRANDS_PROFILE) {
        return Err(conflict(
            "the new filter_ids would leave the segment's reply profile outside its envelope; \
             change or delete the profile first",
        ));
    }
    if combined.contains(HAS_CHILDREN) {
        return Err(conflict("the network segment has child resources"));
    }
    if combined.contains(SITE_GONE) {
        return Err(conflict(
            "the network site was removed while the segment was being written; retry",
        ));
    }
    match classify_write_error(&combined, entity) {
        DbError::AlreadyExists { .. } => {
            // Which uniqueness was broken, by the index that says so.
            let what = if combined.contains("idx_network_segment_site_vlan") {
                "network_segment: the site already has a segment with this vlan_id"
            } else if combined.contains("idx_network_segment_site_rank") {
                "network_segment: the site already has a segment with this rank"
            } else if combined.contains("idx_network_segment_site_name") {
                "network_segment: the site already has a segment of this name"
            } else {
                entity
            };
            Err(TxFail::Refused(AxiamError::AlreadyExists {
                entity: what.into(),
            }))
        }
        other => Err(TxFail::Db(other)),
    }
}

/// The id of a reserved node: the same for the same tenant and path, so a race
/// to make it is a race for one key.
fn node_id(tenant_id: Uuid, path: &str) -> Uuid {
    // One derivation, shared with the authorization function, which must name
    // these nodes before they exist (`axiam_core::models::network`).
    reserved_node_id(tenant_id, path)
}

fn to_u32(value: i64, what: &str) -> Result<u32, DbError> {
    u32::try_from(value).map_err(|_| DbError::Serialization(format!("{what} out of range")))
}

fn to_u64(value: i64, what: &str) -> Result<u64, DbError> {
    u64::try_from(value).map_err(|_| DbError::Serialization(format!("{what} out of range")))
}

// ---------------------------------------------------------------------------
// Segments
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct SegmentRow {
    tenant_id: String,
    resource_id: String,
    name: String,
    site_key: String,
    kind: String,
    vlan_id: i64,
    filter_ids: Vec<String>,
    #[surreal(default)]
    rank: Option<i64>,
    enabled: bool,
    version: i64,
    created_by: String,
    updated_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl SegmentRow {
    fn into_domain(self) -> Result<NetworkSegment, DbError> {
        Ok(NetworkSegment {
            id: parse_uuid(&self.resource_id, SEGMENT_ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            name: self.name,
            site_key: self.site_key,
            kind: NetworkSegmentKind::parse(&self.kind)
                .ok_or_else(|| DbError::Serialization("unknown segment kind".into()))?,
            vlan_id: u16::try_from(self.vlan_id)
                .map_err(|_| DbError::Serialization("vlan_id out of range".into()))?,
            filter_ids: self.filter_ids,
            rank: self.rank.map(|r| to_u32(r, "rank")).transpose()?,
            enabled: self.enabled,
            version: to_u64(self.version, "version")?,
            created_by: parse_uuid(&self.created_by, "actor")?,
            updated_by: parse_uuid(&self.updated_by, "actor")?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of the network segment repository.
#[derive(Clone)]
pub struct SurrealNetworkSegmentRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealNetworkSegmentRepository<C> {
    /// A repository over `db`.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// The segment's own row, tenant-scoped; `NotFound` otherwise.
    async fn fetch(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<NetworkSegment> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('network_segment', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SegmentRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, SEGMENT_ENTITY, &id.to_string())?;
        Ok(row.into_domain()?)
    }

    /// One attempt at the create transaction.
    #[allow(clippy::too_many_arguments)]
    async fn create_tx(
        &self,
        input: &NewNetworkSegment,
        path: &NetworkSegmentPath,
        seg_id: Uuid,
    ) -> Result<(), TxFail> {
        let tenant = input.tenant_id;
        let root = node_id(tenant, "/network");
        let branch = node_id(tenant, &format!("/network/{}", path.kind.branch()));
        let site = node_id(
            tenant,
            &format!("/network/{}/{}", path.kind.branch(), path.site_key),
        );

        // The three reserved nodes are made only when missing, each with its
        // `child_of` edge; the segment's parent (the site) is then claimed, as
        // `resource`'s own child creation does (#308), so a concurrent delete
        // of it has a key to conflict on.
        let query = format!(
            "BEGIN TRANSACTION; \
             IF array::len((SELECT VALUE id FROM type::record('resource', $root_id))) = 0 {{ \
                 CREATE type::record('resource', $root_id) SET tenant_id = $tenant_id, \
                     name = $root_name, resource_type = $root_type; \
             }}; \
             IF array::len((SELECT VALUE id FROM type::record('resource', $branch_id))) = 0 {{ \
                 CREATE type::record('resource', $branch_id) SET tenant_id = $tenant_id, \
                     name = $branch_name, resource_type = $branch_type, parent_id = $root_id; \
                 RELATE resource:`{branch}` -> child_of -> resource:`{root}`; \
             }}; \
             IF array::len((SELECT VALUE id FROM type::record('resource', $site_id))) = 0 {{ \
                 CREATE type::record('resource', $site_id) SET tenant_id = $tenant_id, \
                     name = $site_key, resource_type = $site_type, parent_id = $branch_id; \
                 RELATE resource:`{site}` -> child_of -> resource:`{branch}`; \
             }}; \
             LET $claimed = (UPDATE type::record('resource', $site_id) \
                 SET child_epoch = (child_epoch ?? 0) + 1 \
                 WHERE tenant_id = $tenant_id RETURN VALUE id); \
             IF array::len($claimed) = 0 {{ THROW '{SITE_GONE}'; }}; \
             CREATE type::record('resource', $seg_id) SET tenant_id = $tenant_id, \
                 name = $name, resource_type = $segment_type, parent_id = $site_id; \
             RELATE resource:`{seg_id}` -> child_of -> resource:`{site}`; \
             CREATE type::record('network_segment', $seg_id) SET tenant_id = $tenant_id, \
                 resource_id = $seg_id, name = $name, site_key = $site_key, kind = $kind, \
                 vlan_id = $vlan_id, filter_ids = $filter_ids, rank = $rank, \
                 enabled = $enabled, version = 1, created_by = $actor, updated_by = $actor; \
             COMMIT TRANSACTION"
        );

        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("tenant_id", tenant.to_string()))
            .bind(("root_id", root.to_string()))
            .bind(("branch_id", branch.to_string()))
            .bind(("site_id", site.to_string()))
            .bind(("seg_id", seg_id.to_string()))
            .bind(("root_name", NETWORK_ROOT_NAME.to_owned()))
            .bind(("root_type", RESOURCE_TYPE_NETWORK_ROOT.to_owned()))
            .bind(("branch_name", path.kind.branch().to_owned()))
            .bind(("branch_type", RESOURCE_TYPE_NETWORK_BRANCH.to_owned()))
            .bind(("site_key", path.site_key.clone()))
            .bind(("site_type", RESOURCE_TYPE_NETWORK_SITE.to_owned()))
            .bind(("name", path.name.clone()))
            .bind(("segment_type", RESOURCE_TYPE_NETWORK_SEGMENT.to_owned()))
            .bind(("kind", path.kind.as_str().to_owned()))
            .bind(("vlan_id", i64::from(input.vlan_id)))
            .bind(("filter_ids", input.filter_ids.clone()))
            .bind(("rank", input.rank.map(i64::from)))
            .bind(("enabled", input.enabled))
            .bind(("actor", input.actor.to_string()))
            .await?;
        tx_outcome(result.take_errors(), SEGMENT_ENTITY)
    }

    /// One attempt at the update transaction.
    async fn update_tx(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        update: &NetworkSegmentUpdate,
    ) -> Result<(), TxFail> {
        // The profile is read inside the transaction, and the segment row is
        // written by it: a profile writer bumps the same row (`profile_epoch`),
        // so the two cannot both commit (module documentation).
        let query = format!(
            "BEGIN TRANSACTION; \
             LET $current = (SELECT VALUE version FROM type::record('network_segment', $id) \
                 WHERE tenant_id = $tenant_id AND version = $expected); \
             IF array::len($current) = 0 {{ THROW '{STALE_SEGMENT}'; }}; \
             LET $used = (SELECT VALUE filter_id FROM type::record('reply_profile', $id) \
                 WHERE tenant_id = $tenant_id); \
             IF array::len($used) > 0 AND $used[0] != NONE \
                 AND !($used[0] IN $filter_ids) {{ THROW '{STRANDS_PROFILE}'; }}; \
             UPDATE type::record('network_segment', $id) SET \
                 vlan_id = $vlan_id, filter_ids = $filter_ids, rank = $rank, \
                 enabled = $enabled, version = version + 1, updated_by = $actor, \
                 updated_at = time::now() \
                 WHERE tenant_id = $tenant_id AND version = $expected; \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind((
                "expected",
                i64::try_from(update.expected_version).unwrap_or(i64::MAX),
            ))
            .bind(("vlan_id", i64::from(update.vlan_id)))
            .bind(("filter_ids", update.filter_ids.clone()))
            .bind(("rank", update.rank.map(i64::from)))
            .bind(("enabled", update.enabled))
            .bind(("actor", update.actor.to_string()))
            .await?;
        tx_outcome(result.take_errors(), SEGMENT_ENTITY)
    }

    /// One attempt at the delete transaction.
    async fn delete_tx(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_version: u64,
    ) -> Result<(), TxFail> {
        // Edges are matched by the exact record id: the segment was shown to be
        // this tenant's by `$current`, in the same transaction.
        let query = format!(
            "BEGIN TRANSACTION; \
             LET $current = (SELECT VALUE version FROM type::record('network_segment', $id) \
                 WHERE tenant_id = $tenant_id AND version = $expected); \
             IF array::len($current) = 0 {{ THROW '{STALE_SEGMENT}'; }}; \
             LET $children = (SELECT VALUE id FROM child_of WHERE out = resource:`{id}`); \
             IF array::len($children) > 0 {{ THROW '{HAS_CHILDREN}'; }}; \
             DELETE reply_profile WHERE segment_id = $id AND tenant_id = $tenant_id; \
             DELETE child_of WHERE in = resource:`{id}`; \
             DELETE on_resource WHERE out = resource:`{id}`; \
             DELETE scope WHERE resource_id = $id AND tenant_id = $tenant_id; \
             DELETE type::record('resource', $id) WHERE tenant_id = $tenant_id; \
             DELETE type::record('network_segment', $id) \
                 WHERE tenant_id = $tenant_id AND version = $expected; \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind((
                "expected",
                i64::try_from(expected_version).unwrap_or(i64::MAX),
            ))
            .await?;
        tx_outcome(result.take_errors(), SEGMENT_ENTITY)
    }
}

impl<C: Connection> NetworkSegmentRepository for SurrealNetworkSegmentRepository<C> {
    async fn create(
        &self,
        input: NewNetworkSegment,
        clearance: &NetworkWriteClearance,
    ) -> AxiamResult<NetworkSegment> {
        // Cleared by the authorization function for exactly this write, or
        // nothing happens (design note §5.1).
        clearance.check(
            input.tenant_id,
            input.actor,
            &NetworkWriteTarget::SegmentCreate {
                path: input.path.clone(),
            },
        )?;
        // Everything the data decides, before the datastore is touched.
        let path = NetworkSegmentPath::parse(&input.path)?;
        if path.kind != input.kind {
            return Err(AxiamError::Validation {
                message: format!(
                    "a {} segment lives under /network/{}, not under /network/{}",
                    input.kind.as_str(),
                    input.kind.branch(),
                    path.kind.branch()
                ),
            });
        }
        validate_segment_fields(path.kind, input.vlan_id, &input.filter_ids, input.rank)?;

        let seg_id = new_id();
        retry_on_write_conflict(|| self.create_tx(&input, &path, seg_id))
            .await
            .map_err(AxiamError::from)?;
        self.fetch(input.tenant_id, seg_id).await
    }

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<NetworkSegment> {
        self.fetch(tenant_id, id).await
    }

    async fn get_by_path(&self, tenant_id: Uuid, path: &str) -> AxiamResult<NetworkSegment> {
        let path = NetworkSegmentPath::parse(path)?;
        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM network_segment WHERE tenant_id = $tenant_id \
                 AND site_key = $site_key AND kind = $kind AND name = $name",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("site_key", path.site_key.clone()))
            .bind(("kind", path.kind.as_str().to_owned()))
            .bind(("name", path.name.clone()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SegmentRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, SEGMENT_ENTITY, &path.render())?;
        Ok(row.into_domain()?)
    }

    async fn list_page(
        &self,
        tenant_id: Uuid,
        site_key: Option<&str>,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<NetworkSegment>> {
        let search = search_filter(&pagination, &["name", "site_key"]);
        let search_term = search_bind(&pagination);
        let site = if site_key.is_some() {
            " AND site_key = $site_key"
        } else {
            ""
        };
        let site_value = site_key.unwrap_or_default().to_owned();

        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM network_segment \
                 WHERE tenant_id = $tenant_id{site}{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("site_key", site_value.clone()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT * FROM network_segment \
                 WHERE tenant_id = $tenant_id{site}{search} \
                 ORDER BY site_key ASC, kind ASC, rank ASC, name ASC \
                 LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("site_key", site_value))
            .bind(("search", search_term))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SegmentRow> = result.take(0).map_err(DbError::from)?;
        let items = rows
            .into_iter()
            .map(|row| row.into_domain().map_err(AxiamError::from))
            .collect::<AxiamResult<Vec<_>>>()?;
        Ok(paginate(items, count_rows, &pagination))
    }

    async fn list_site(&self, tenant_id: Uuid, site_key: &str) -> AxiamResult<Vec<NetworkSegment>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM network_segment \
                 WHERE tenant_id = $tenant_id AND site_key = $site_key \
                 ORDER BY kind ASC, rank ASC, name ASC",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("site_key", site_key.to_owned()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SegmentRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| match row.into_domain() {
                Ok(segment) => Some(segment),
                Err(error) => {
                    // Fail closed: a segment that does not read is no
                    // placement candidate, and the decision goes on without it.
                    tracing::warn!(
                        target: "axiam::network_decide",
                        %tenant_id,
                        %error,
                        "a network segment row does not read back and is not a candidate"
                    );
                    None
                }
            })
            .collect())
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        update: NetworkSegmentUpdate,
        clearance: &NetworkWriteClearance,
    ) -> AxiamResult<NetworkSegment> {
        clearance.check(
            tenant_id,
            update.actor,
            &NetworkWriteTarget::SegmentUpdate { segment_id: id },
        )?;
        // `NotFound` for a segment that is not this tenant's; the kind is the
        // stored one, because it does not change here.
        let stored = self.fetch(tenant_id, id).await?;
        validate_segment_fields(stored.kind, update.vlan_id, &update.filter_ids, update.rank)?;
        retry_on_write_conflict(|| self.update_tx(tenant_id, id, &update))
            .await
            .map_err(AxiamError::from)?;
        self.fetch(tenant_id, id).await
    }

    async fn delete(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_version: u64,
        clearance: &NetworkWriteClearance,
    ) -> AxiamResult<()> {
        // A delete names no actor of its own: the clearance's is the writer.
        clearance.check(
            tenant_id,
            clearance.actor(),
            &NetworkWriteTarget::SegmentDelete { segment_id: id },
        )?;
        self.fetch(tenant_id, id).await?;
        retry_on_write_conflict(|| self.delete_tx(tenant_id, id, expected_version))
            .await
            .map_err(AxiamError::from)
    }
}

// ---------------------------------------------------------------------------
// The tenant's cap
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct PolicyRow {
    tenant_id: String,
    session_timeout_max_secs: i64,
    version: i64,
    updated_by: String,
    updated_at: DateTime<Utc>,
}

impl PolicyRow {
    fn into_domain(self) -> Result<NetworkPolicy, DbError> {
        // A row edited behind the API cannot widen the cap past what the API
        // would have accepted: read as the nearest bound.
        let cap = u32::try_from(self.session_timeout_max_secs)
            .unwrap_or(DEFAULT_SESSION_TIMEOUT_MAX_SECS)
            .clamp(SESSION_TIMEOUT_FLOOR_SECS, SESSION_TIMEOUT_CAP_CEILING_SECS);
        Ok(NetworkPolicy {
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            session_timeout_max_secs: cap,
            version: to_u64(self.version, "version")?,
            updated_by: Some(parse_uuid(&self.updated_by, "actor")?),
            updated_at: Some(self.updated_at),
        })
    }
}

/// SurrealDB implementation of the network policy repository.
#[derive(Clone)]
pub struct SurrealNetworkPolicyRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealNetworkPolicyRepository<C> {
    /// A repository over `db`.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    async fn write_tx(&self, tenant_id: Uuid, input: &SetNetworkPolicy) -> Result<(), TxFail> {
        let cap = i64::from(input.session_timeout_max_secs);
        let mut result = if input.expected_version == 0 {
            // First write: the record must not exist yet.
            self.db
                .current()
                .query(
                    "CREATE type::record('network_policy', $tenant_id) SET \
                     tenant_id = $tenant_id, session_timeout_max_secs = $cap, version = 1, \
                     updated_by = $actor, updated_at = time::now()",
                )
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("cap", cap))
                .bind(("actor", input.actor.to_string()))
                .await?
        } else {
            self.db
                .current()
                .query(format!(
                    "BEGIN TRANSACTION; \
                     LET $written = (UPDATE type::record('network_policy', $tenant_id) SET \
                         session_timeout_max_secs = $cap, version = version + 1, \
                         updated_by = $actor, updated_at = time::now() \
                         WHERE tenant_id = $tenant_id AND version = $expected \
                         RETURN VALUE version); \
                     IF array::len($written) = 0 {{ THROW '{STALE_SEGMENT}'; }}; \
                     COMMIT TRANSACTION"
                ))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("cap", cap))
                .bind(("actor", input.actor.to_string()))
                .bind((
                    "expected",
                    i64::try_from(input.expected_version).unwrap_or(i64::MAX),
                ))
                .await?
        };
        match tx_outcome(result.take_errors(), POLICY_ENTITY) {
            // A first write that finds the record there is a stale read.
            Err(TxFail::Refused(AxiamError::AlreadyExists { .. })) => Err(conflict(
                "the network policy changed since it was read; read it again and retry",
            )),
            Err(TxFail::Refused(AxiamError::Conflict { .. })) => Err(conflict(
                "the network policy changed since it was read; read it again and retry",
            )),
            other => other,
        }
    }
}

impl<C: Connection> NetworkPolicyRepository for SurrealNetworkPolicyRepository<C> {
    async fn get(&self, tenant_id: Uuid) -> AxiamResult<NetworkPolicy> {
        let mut result = self
            .db
            .current()
            .query("SELECT * FROM network_policy WHERE tenant_id = $tenant_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<PolicyRow> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(row.into_domain()?),
            None => Ok(NetworkPolicy::default_for(tenant_id)),
        }
    }

    async fn set(
        &self,
        tenant_id: Uuid,
        input: SetNetworkPolicy,
        clearance: &NetworkWriteClearance,
    ) -> AxiamResult<NetworkPolicy> {
        // Cleared by the authorization function for exactly this write, or
        // nothing happens (design note §5.1).
        clearance.check(tenant_id, input.actor, &NetworkWriteTarget::PolicyWrite)?;
        input.validate()?;
        retry_on_write_conflict(|| self.write_tx(tenant_id, &input))
            .await
            .map_err(AxiamError::from)?;
        self.get(tenant_id).await
    }
}

// ---------------------------------------------------------------------------
// Reply profiles
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct ProfileRow {
    tenant_id: String,
    segment_id: String,
    dictionary: String,
    session_timeout_secs: i64,
    termination_action: String,
    #[surreal(default)]
    idle_timeout_secs: Option<i64>,
    #[surreal(default)]
    filter_id: Option<String>,
    #[surreal(default)]
    service_type: Option<String>,
    version: i64,
    created_by: String,
    updated_by: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ProfileRow {
    /// The row as stored, for the decision path to re-validate.
    fn into_stored(self) -> Result<StoredReplyProfile, DbError> {
        Ok(StoredReplyProfile {
            segment_id: parse_uuid(&self.segment_id, SEGMENT_ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            dictionary: self.dictionary,
            session_timeout_secs: self.session_timeout_secs,
            termination_action: self.termination_action,
            idle_timeout_secs: self.idle_timeout_secs,
            filter_id: self.filter_id,
            service_type: self.service_type,
            version: to_u64(self.version, "version")?,
        })
    }

    /// The effective profile under `cap`: `Session-Timeout` lowered to it, and
    /// `Idle-Timeout` kept within the result.
    fn into_effective(self, cap: u32) -> Result<ReplyProfile, DbError> {
        let stored = to_u32(self.session_timeout_secs, "session_timeout_secs")?;
        let effective = clamp_session_timeout(stored, cap);
        let idle = self
            .idle_timeout_secs
            .map(|i| to_u32(i, "idle_timeout_secs"))
            .transpose()?
            .map(|i| i.min(effective));
        Ok(ReplyProfile {
            segment_id: parse_uuid(&self.segment_id, SEGMENT_ENTITY)?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            dictionary: self.dictionary,
            session_timeout_secs: effective,
            session_timeout_clamped: effective != stored,
            termination_action: TerminationAction::parse(&self.termination_action)
                .ok_or_else(|| DbError::Serialization("unknown termination_action".into()))?,
            idle_timeout_secs: idle,
            filter_id: self.filter_id,
            service_type: self
                .service_type
                .map(|s| {
                    ServiceType::parse(&s)
                        .ok_or_else(|| DbError::Serialization("unknown service_type".into()))
                })
                .transpose()?,
            version: to_u64(self.version, "version")?,
            created_by: parse_uuid(&self.created_by, "actor")?,
            updated_by: parse_uuid(&self.updated_by, "actor")?,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of the reply profile repository.
#[derive(Clone)]
pub struct SurrealReplyProfileRepository<C: Connection> {
    db: DbHandle<C>,
    segments: SurrealNetworkSegmentRepository<C>,
    policy: SurrealNetworkPolicyRepository<C>,
}

impl<C: Connection> SurrealReplyProfileRepository<C> {
    /// A repository over `db`.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self {
            segments: SurrealNetworkSegmentRepository::new(db.clone()),
            policy: SurrealNetworkPolicyRepository::new(db.clone()),
            db,
        }
    }

    /// The segment the write is about, checked against the version the writer
    /// read and the profile against that segment's envelope and the tenant cap.
    /// Returns nothing: the transaction re-checks the version against the row it
    /// writes, this is the value half and the early, precise answer.
    async fn check_write(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        expected_segment_version: u64,
        profile: &ReplyProfileInput,
    ) -> AxiamResult<()> {
        let segment = self.segments.fetch(tenant_id, segment_id).await?;
        if segment.version != expected_segment_version {
            return Err(AxiamError::Conflict {
                reason: "the network segment changed since it was read; read it again and retry"
                    .into(),
            });
        }
        let cap = self.policy.get(tenant_id).await?.session_timeout_max_secs;
        profile.validate(&segment.filter_ids, cap)
    }

    async fn fetch_stored(&self, tenant_id: Uuid, segment_id: Uuid) -> Result<ProfileRow, DbError> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('reply_profile', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", segment_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await?;
        let rows: Vec<ProfileRow> = result.take(0)?;
        take_first_or_not_found(rows, PROFILE_ENTITY, &segment_id.to_string())
    }

    /// One attempt at a profile write. `expected_version` is `None` for a
    /// create.
    #[allow(clippy::too_many_arguments)]
    async fn write_tx(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        expected_segment_version: u64,
        expected_version: Option<u64>,
        profile: &ReplyProfileInput,
        actor: Uuid,
    ) -> Result<(), TxFail> {
        // The segment row is written (and its version checked in the same
        // statement) so that a concurrent segment write conflicts with this one.
        let write = if expected_version.is_some() {
            format!(
                "LET $written = (UPDATE type::record('reply_profile', $segment_id) SET \
                     dictionary = $dictionary, session_timeout_secs = $session_timeout_secs, \
                     termination_action = $termination_action, \
                     idle_timeout_secs = $idle_timeout_secs, filter_id = $filter_id, \
                     service_type = $service_type, version = version + 1, \
                     updated_by = $actor, updated_at = time::now() \
                     WHERE tenant_id = $tenant_id AND version = $expected_version \
                     RETURN VALUE version); \
                 IF array::len($written) = 0 {{ THROW '{STALE_PROFILE}'; }};"
            )
        } else {
            "CREATE type::record('reply_profile', $segment_id) SET \
                 tenant_id = $tenant_id, segment_id = $segment_id, dictionary = $dictionary, \
                 session_timeout_secs = $session_timeout_secs, \
                 termination_action = $termination_action, \
                 idle_timeout_secs = $idle_timeout_secs, filter_id = $filter_id, \
                 service_type = $service_type, version = 1, \
                 created_by = $actor, updated_by = $actor;"
                .to_owned()
        };
        let query = format!(
            "BEGIN TRANSACTION; \
             LET $claimed = (UPDATE type::record('network_segment', $segment_id) \
                 SET profile_epoch = (profile_epoch ?? 0) + 1 \
                 WHERE tenant_id = $tenant_id AND version = $segment_version \
                 RETURN VALUE id); \
             IF array::len($claimed) = 0 {{ THROW '{STALE_SEGMENT}'; }}; \
             {write} \
             COMMIT TRANSACTION"
        );
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("segment_id", segment_id.to_string()))
            .bind((
                "segment_version",
                i64::try_from(expected_segment_version).unwrap_or(i64::MAX),
            ))
            .bind((
                "expected_version",
                expected_version.map(|v| i64::try_from(v).unwrap_or(i64::MAX)),
            ))
            .bind(("dictionary", profile.dictionary.clone()))
            .bind((
                "session_timeout_secs",
                i64::from(profile.session_timeout_secs),
            ))
            .bind((
                "termination_action",
                profile.termination_action.as_str().to_owned(),
            ))
            .bind((
                "idle_timeout_secs",
                profile.idle_timeout_secs.map(i64::from),
            ))
            .bind(("filter_id", profile.filter_id.clone()))
            .bind((
                "service_type",
                profile.service_type.map(|s| s.as_str().to_owned()),
            ))
            .bind(("actor", actor.to_string()))
            .await?;
        tx_outcome(result.take_errors(), PROFILE_ENTITY)
    }

    async fn effective(&self, tenant_id: Uuid, segment_id: Uuid) -> AxiamResult<ReplyProfile> {
        let row = self.fetch_stored(tenant_id, segment_id).await?;
        let cap = self.policy.get(tenant_id).await?.session_timeout_max_secs;
        Ok(row.into_effective(cap)?)
    }
}

impl<C: Connection> ReplyProfileRepository for SurrealReplyProfileRepository<C> {
    async fn create(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        input: NewReplyProfile,
        clearance: &NetworkWriteClearance,
    ) -> AxiamResult<ReplyProfile> {
        clearance.check(
            tenant_id,
            input.actor,
            &NetworkWriteTarget::ProfileWrite { segment_id },
        )?;
        self.check_write(
            tenant_id,
            segment_id,
            input.expected_segment_version,
            &input.profile,
        )
        .await?;
        retry_on_write_conflict(|| {
            self.write_tx(
                tenant_id,
                segment_id,
                input.expected_segment_version,
                None,
                &input.profile,
                input.actor,
            )
        })
        .await
        .map_err(AxiamError::from)?;
        self.effective(tenant_id, segment_id).await
    }

    async fn get_by_segment(&self, tenant_id: Uuid, segment_id: Uuid) -> AxiamResult<ReplyProfile> {
        self.effective(tenant_id, segment_id).await
    }

    async fn list_stored(
        &self,
        tenant_id: Uuid,
        segment_ids: &[Uuid],
    ) -> AxiamResult<Vec<StoredReplyProfile>> {
        let ids: Vec<String> = segment_ids.iter().map(Uuid::to_string).collect();
        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM reply_profile \
                 WHERE tenant_id = $tenant_id AND segment_id IN $ids",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("ids", ids))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<ProfileRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows
            .into_iter()
            .filter_map(|row| match row.into_stored() {
                Ok(profile) => Some(profile),
                Err(error) => {
                    tracing::warn!(
                        target: "axiam::network_decide",
                        %tenant_id,
                        %error,
                        "a reply profile row does not read back and is not rendered"
                    );
                    None
                }
            })
            .collect())
    }

    async fn list_page(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<ReplyProfile>> {
        let search = search_filter(&pagination, &["filter_id", "segment_id"]);
        let search_term = search_bind(&pagination);
        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM reply_profile \
                 WHERE tenant_id = $tenant_id{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT * FROM reply_profile \
                 WHERE tenant_id = $tenant_id{search} \
                 ORDER BY segment_id ASC LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("search", search_term))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<ProfileRow> = result.take(0).map_err(DbError::from)?;
        let cap = self.policy.get(tenant_id).await?.session_timeout_max_secs;
        let items = rows
            .into_iter()
            .map(|row| row.into_effective(cap).map_err(AxiamError::from))
            .collect::<AxiamResult<Vec<_>>>()?;
        Ok(paginate(items, count_rows, &pagination))
    }

    async fn replace(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        input: ReplyProfileReplace,
        clearance: &NetworkWriteClearance,
    ) -> AxiamResult<ReplyProfile> {
        clearance.check(
            tenant_id,
            input.actor,
            &NetworkWriteTarget::ProfileWrite { segment_id },
        )?;
        // `NotFound` for a segment without a profile, before anything else.
        self.fetch_stored(tenant_id, segment_id).await?;
        self.check_write(
            tenant_id,
            segment_id,
            input.expected_segment_version,
            &input.profile,
        )
        .await?;
        retry_on_write_conflict(|| {
            self.write_tx(
                tenant_id,
                segment_id,
                input.expected_segment_version,
                Some(input.expected_version),
                &input.profile,
                input.actor,
            )
        })
        .await
        .map_err(AxiamError::from)?;
        self.effective(tenant_id, segment_id).await
    }

    async fn delete(
        &self,
        tenant_id: Uuid,
        segment_id: Uuid,
        expected_version: u64,
        clearance: &NetworkWriteClearance,
    ) -> AxiamResult<()> {
        clearance.check(
            tenant_id,
            clearance.actor(),
            &NetworkWriteTarget::ProfileDelete { segment_id },
        )?;
        self.fetch_stored(tenant_id, segment_id).await?;
        retry_on_write_conflict(|| async {
            let mut result = self
                .db
                .current()
                .query(format!(
                    "BEGIN TRANSACTION; \
                     LET $deleted = (DELETE type::record('reply_profile', $segment_id) \
                         WHERE tenant_id = $tenant_id AND version = $expected \
                         RETURN BEFORE); \
                     IF array::len($deleted) = 0 {{ THROW '{STALE_PROFILE}'; }}; \
                     COMMIT TRANSACTION"
                ))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("segment_id", segment_id.to_string()))
                .bind((
                    "expected",
                    i64::try_from(expected_version).unwrap_or(i64::MAX),
                ))
                .await?;
            tx_outcome(result.take_errors(), PROFILE_ENTITY)
        })
        .await
        .map_err(AxiamError::from)
    }
}

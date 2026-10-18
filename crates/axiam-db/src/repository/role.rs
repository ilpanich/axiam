//! SurrealDB implementation of [`RoleRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::role::{
    AssignmentScope, CreateRole, Role, RoleAssignment, RoleClaim, RoleEpochs,
    RoleSubjectAssignment, UpdateRole, default_inherit,
};
use axiam_core::repository::{PaginatedResult, Pagination, RoleRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_write_error, parse_uuid, retry_on_write_conflict, search_bind, search_filter,
};

#[derive(Debug, SurrealValue)]
struct RoleRow {
    tenant_id: String,
    name: String,
    description: String,
    is_global: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct RoleRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    description: String,
    is_global: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl RoleRowWithId {
    fn try_into_role(self) -> Result<Role, DbError> {
        let id = parse_uuid(&self.record_id, "record_id")?;
        let tenant_id = parse_uuid(&self.tenant_id, "tenant_id")?;
        Ok(Role {
            id,
            tenant_id,
            name: self.name,
            description: self.description,
            is_global: self.is_global,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Row for querying has_role edges with the role data joined in.
#[derive(Debug, SurrealValue)]
struct RoleAssignmentRow {
    record_id: String,
    tenant_id: String,
    name: String,
    description: String,
    is_global: bool,
    resource_id: Option<String>,
    /// The tenants this assignment reaches (schema v51). `None` on every edge
    /// written before the field existed, which is what unrestricted means.
    tenant_scope: Option<Vec<String>>,
    /// Whether the assignment reaches the resource's descendants (schema v66).
    /// `None` on every edge written before the field existed, read as `true`.
    inherit: Option<bool>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// Parse a `tenant_scope` list off an edge row.
///
/// Whether the list is absent and whether it is empty are different facts and
/// stay different: `None` is an unrestricted assignment, and an empty `Some`
/// would be one that reaches nothing. The write path refuses to create the
/// second, but a row that somehow holds one must read back as itself rather
/// than be silently widened to "everywhere".
fn parse_tenant_scope(raw: Option<Vec<String>>) -> Result<Option<Vec<Uuid>>, DbError> {
    raw.map(|ids| {
        ids.iter()
            .map(|s| parse_uuid(s, "tenant_scope"))
            .collect::<Result<Vec<_>, _>>()
    })
    .transpose()
}

impl RoleAssignmentRow {
    fn try_into_assignment(self) -> Result<RoleAssignment, DbError> {
        let id = parse_uuid(&self.record_id, "record_id")?;
        let tenant_id = parse_uuid(&self.tenant_id, "tenant_id")?;
        let resource_id = self
            .resource_id
            .as_deref()
            .map(|s| parse_uuid(s, "resource_id"))
            .transpose()?;
        let tenant_scope = parse_tenant_scope(self.tenant_scope)?;
        Ok(RoleAssignment {
            role: Role {
                id,
                tenant_id,
                name: self.name,
                description: self.description,
                is_global: self.is_global,
                created_at: self.created_at,
                updated_at: self.updated_at,
            },
            resource_id,
            tenant_scope,
            inherit: self.inherit.unwrap_or_else(default_inherit),
        })
    }
}

/// Row for querying `has_role` edges from the role's side: the subject holding
/// the assignment plus the resource it is scoped to.
#[derive(Debug, SurrealValue)]
struct RoleSubjectAssignmentRow {
    subject_id: String,
    resource_id: Option<String>,
    tenant_scope: Option<Vec<String>>,
    inherit: Option<bool>,
}

impl RoleSubjectAssignmentRow {
    fn try_into_subject_assignment(self) -> Result<RoleSubjectAssignment, DbError> {
        let subject_id = parse_uuid(&self.subject_id, "subject_id")?;
        let resource_id = self
            .resource_id
            .as_deref()
            .map(|s| parse_uuid(s, "resource_id"))
            .transpose()?;
        Ok(RoleSubjectAssignment {
            subject_id,
            resource_id,
            tenant_scope: parse_tenant_scope(self.tenant_scope)?,
            inherit: self.inherit.unwrap_or_else(default_inherit),
        })
    }
}

// ---------------------------------------------------------------------------
// The role row's epochs: the network gate's reads and the write as one
// transaction (R110W6-04, #701; schema v101)
// ---------------------------------------------------------------------------
//
// The network gate (`axiam_authz::network_gate`) decides a role write on reads
// it makes before the write: the role's `network:` grants, who holds it, its
// `is_global`. Two writes to one role can each pass the gate on a state the
// other is about to change, and the engine will not notice — SurrealDB 3.3.4
// is snapshot-isolated with **write-write** conflict detection only (on
// `surrealkv`, the engine production runs, a plain read is never validated at
// commit), so two transactions that write disjoint keys — one `grants` edge,
// one `has_role` edge — both commit. That is how, before this, a `network:`
// grant and a group assignment of one role could both land (rule 2), a writer
// could grant `network:join` to a role while assigning the role to itself
// (H6), a role could be made global while gaining a `network:` grant (rule 1),
// assigned with `inherit: false` while gaining a deny (rule 3), or a revoke
// could delete a deny committed after its gate read none (§5.3 row 5).
//
// So every write that can change what those decisions read moves an epoch on
// the role row, and every write the gate cleared **claims** the epochs the gate
// read before anything else, inside its own transaction:
//
// * `grant_epoch` moves with a `network:` grant or revoke and an `is_global`
//   write; `holder_epoch` with every assignment and unassignment.
// * An assignment or unassignment claims `grant_epoch` (its rules read the
//   role's grants; two assignments of one role do not invalidate each other).
//   A `network:` grant or revoke, and a role delete, claim both. An `is_global`
//   update claims `grant_epoch`.
// * The claim is a compare inside the transaction (`THROW` → `409`, "the role
//   changed since it was read"), and every claiming write also writes the row,
//   so two overlapping transactions conflict on the key and the loser is
//   retried on a fresh snapshot ([`retry_on_write_conflict`]), where the compare
//   fails. A write that starts after the other committed fails the compare at
//   once.
//
// A write the gate did not claim for (the seeder, a role or permission that is
// not the tenant's) still moves its epoch, so a claimed write racing it loses.
// Rule 2 is also re-asserted inside the grant and group-assignment
// transactions themselves, for the writers that make no claim (the seeder's
// reconcile, `seeder.rs`).

/// `THROW`n when an epoch the write claimed has moved since the gate read it.
pub(crate) const ROLE_EPOCH_STALE: &str = "axiam:role_epoch_stale";

/// `THROW`n by a `network:` grant whose role a group holds when the
/// transaction runs.
pub(crate) const NETWORK_GRANT_TO_GROUP_HELD_ROLE: &str =
    "axiam:network_grant_to_a_group_held_role";

/// `THROW`n by a group assignment of a role that carries a `network:`
/// permission when the transaction runs.
pub(crate) const GROUP_ASSIGNMENT_OF_NETWORK_ROLE: &str =
    "axiam:group_assignment_of_a_network_role";

/// The SurrealQL regex of an action in the reserved `network:` namespace:
/// exactly `axiam_core::models::network::is_network_action` — leading
/// whitespace skipped, the prefix compared ASCII case-insensitively (`-u`, so
/// that U+212A KELVIN SIGN is not a `k`, as it is not for the gate).
pub(crate) const NETWORK_ACTION_REGEX: &str = r"/^\s*(?i-u:network:)/";

/// The `409` a write refused by its claim or by the in-transaction rule 2
/// answers.
///
/// "changed since it was read" is the sentence `NetworkConflictReason::of`
/// reads as `stale_version`: the gate read the role before the other write
/// landed, and a request sent again goes back through the gate, which decides
/// on the role as it now is.
pub(crate) fn network_role_raced(what_landed: &str) -> AxiamError {
    AxiamError::Conflict {
        reason: format!(
            "the role changed since it was read ({what_landed}); read it again and retry"
        ),
    }
}

/// Which epochs a write compares against its claim.
#[derive(Clone, Copy)]
pub(crate) struct Claims {
    pub(crate) grants: bool,
    pub(crate) holders: bool,
}

/// The statements that check `claim` inside a transaction, for the role whose
/// id is `role_id` (a UUID the caller rendered, never caller text). They read
/// `$tid`, `$claimed`, `$claim_grants` and `$claim_holders` ([`claim_binds`]).
///
/// A role that is not the tenant's is not refused here: the write's own guard
/// answers it as it always has.
pub(crate) fn claim_statements(role_id: &str, claims: Claims) -> String {
    let mut out = format!(
        "LET $epochs = (SELECT VALUE [grant_epoch ?? 0, holder_epoch ?? 0] \
             FROM role:`{role_id}` WHERE tenant_id = $tid); "
    );
    if claims.grants {
        out.push_str(&format!(
            "IF $claimed AND array::len($epochs) > 0 AND $epochs[0][0] != $claim_grants \
                 {{ THROW '{ROLE_EPOCH_STALE}'; }}; "
        ));
    }
    if claims.holders {
        out.push_str(&format!(
            "IF $claimed AND array::len($epochs) > 0 AND $epochs[0][1] != $claim_holders \
                 {{ THROW '{ROLE_EPOCH_STALE}'; }}; "
        ));
    }
    out
}

/// The values [`claim_statements`] reads: `(claimed, grants, holders)`.
pub(crate) fn claim_binds(claim: Option<&RoleClaim>) -> (bool, i64, i64) {
    claim.map_or((false, 0, 0), |c| {
        (
            true,
            i64::try_from(c.epochs.grants).unwrap_or(i64::MAX),
            i64::try_from(c.epochs.holders).unwrap_or(i64::MAX),
        )
    })
}

/// One of the role row's two epochs.
#[derive(Clone, Copy)]
pub(crate) enum Epoch {
    /// `grant_epoch`: `network:` grants and revokes, `is_global` writes.
    Grants,
    /// `holder_epoch`: assignments and unassignments.
    Holders,
}

impl Epoch {
    /// The role row's field.
    pub(crate) fn field(self) -> &'static str {
        match self {
            Self::Grants => "grant_epoch",
            Self::Holders => "holder_epoch",
        }
    }

    /// The statement that leaves the epoch's next value in `$next_epoch`,
    /// read from the `$epochs` pair [`claim_statements`] read earlier in the
    /// same transaction (and block): the same snapshot an in-place
    /// `x = (x ?? 0) + 1` would read. A role that is not the tenant's reads no
    /// pair, and its UPDATE matches nothing.
    pub(crate) fn next_statement(self) -> &'static str {
        match self {
            Self::Grants => "LET $next_epoch = ($epochs[0][0] ?? 0) + 1; ",
            Self::Holders => "LET $next_epoch = ($epochs[0][1] ?? 0) + 1; ",
        }
    }
}

/// The statements that move `epoch` on the role row. Must follow
/// [`claim_statements`] in the same block, whose `$epochs` they read.
///
/// The arithmetic is a `LET` of its own, so the `UPDATE` only assigns a
/// parameter: the embedded engine evaluates an expression in a `SET` inside
/// its per-document write pipeline, nested several frames below the statement
/// that runs it, and in a debug build that nesting alone took the seeder's
/// grant past a 2 MiB thread stack (`directory_e2e`, PR #716). The values
/// written are the same.
pub(crate) fn bump_statement(role_id: &str, epoch: Epoch) -> String {
    format!(
        "{next}UPDATE role:`{role_id}` SET {field} = $next_epoch WHERE tenant_id = $tid; ",
        next = epoch.next_statement(),
        field = epoch.field(),
    )
}

/// A transaction's statement errors, read for the refusals every role write
/// shares. `Ok(None)`: nothing failed. `Ok(Some(e))`: a refusal to answer with.
/// `Err`: what is left, classified (a duplicate is `AlreadyExists`, an engine
/// conflict is retried by the caller's [`retry_on_write_conflict`]).
///
/// Every slot is read: a `THROW` fires on its own statement while the rest
/// report "not executed due to a failed transaction", which is also a
/// write-conflict marker — so the refusals are matched first.
pub(crate) fn role_tx_outcome(
    errors: std::collections::HashMap<usize, surrealdb::Error>,
    entity: &str,
    id: &str,
    cross_tenant: &str,
) -> Result<Option<AxiamError>, DbError> {
    if errors.is_empty() {
        return Ok(None);
    }
    let combined = errors
        .into_values()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    if combined.contains(ROLE_EPOCH_STALE) {
        return Ok(Some(network_role_raced(
            "another write to its grants, holders or scope landed first",
        )));
    }
    if combined.contains(NETWORK_GRANT_TO_GROUP_HELD_ROLE) {
        return Ok(Some(network_role_raced("a group was assigned it")));
    }
    if combined.contains(GROUP_ASSIGNMENT_OF_NETWORK_ROLE) {
        return Ok(Some(network_role_raced(
            "a network: permission was granted to it",
        )));
    }
    if combined.contains("cross-tenant edge denied") {
        return Ok(Some(AxiamError::AuthorizationDenied {
            reason: cross_tenant.to_owned(),
            action: None,
            resource_id: None,
        }));
    }
    if combined.contains(crate::helpers::DELETE_TARGET_MISSING) {
        return Err(DbError::NotFound {
            entity: entity.to_owned(),
            id: id.to_owned(),
        });
    }
    Err(classify_write_error(combined, entity))
}

/// SurrealDB implementation of the Role repository.
#[derive(Clone)]
pub struct SurrealRoleRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealRoleRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }

    /// Look up a single role by name within a tenant (CQ-B42: replaces list()+scan pattern).
    pub async fn get_by_name(&self, tenant_id: Uuid, name: &str) -> AxiamResult<Option<Role>> {
        let tenant_str = tenant_id.to_string();
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id AND name = $name LIMIT 1",
            )
            .bind(("tenant_id", tenant_str))
            .bind(("name", name.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RoleRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|row| row.try_into_role().map_err(AxiamError::from))
            .transpose()
    }

    /// [`RoleRepository::update`], claiming `claim`.
    ///
    /// A write of `is_global` moves `grant_epoch` and, with a claim, compares
    /// it (rule 1 reads the role's grants; a `network:` grant reads
    /// `is_global`). A write of `name` or `description` alone concerns no
    /// network decision and compares nothing — but it writes the row, so a
    /// claimed write racing it is retried, never mistaken.
    ///
    /// # Errors
    ///
    /// As the trait method, plus `Conflict` ("the role changed since it was
    /// read") when the claim's `grant_epoch` has moved.
    pub async fn update_claimed(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateRole,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<Role> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.description.is_some() {
            sets.push("description = $description");
        }
        let claim_check = if input.is_global.is_some() {
            sets.push("is_global = $is_global");
            // The next value is a `LET` of its own (`Epoch::next_statement`),
            // for the reason `bump_statement` gives.
            sets.push("grant_epoch = $next_epoch");
            let mut statements = claim_statements(
                &id_str,
                Claims {
                    grants: true,
                    holders: false,
                },
            );
            statements.push_str(Epoch::Grants.next_statement());
            statements
        } else {
            String::new()
        };
        sets.push("updated_at = time::now()");
        // Result slots: BEGIN, then — when `is_global` is written — the
        // claim's LET and IF and the next epoch's LET, then the UPDATE.
        let update_slot = if claim_check.is_empty() { 1 } else { 4 };

        let query = format!(
            "BEGIN TRANSACTION; \
             {claim_check}\
             UPDATE type::record('role', $id) SET {} \
             WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION",
            sets.join(", ")
        );
        let (claimed, claim_grants, claim_holders) = claim_binds(claim.as_ref());

        let outcome = retry_on_write_conflict(|| async {
            let db = self.db.current();
            let mut builder = db
                .query(query.as_str())
                .bind(("id", id_str.clone()))
                .bind(("tenant_id", tenant_id_str.clone()))
                .bind(("tid", tenant_id_str.clone()))
                .bind(("claimed", claimed))
                .bind(("claim_grants", claim_grants))
                .bind(("claim_holders", claim_holders));
            if let Some(name) = &input.name {
                builder = builder.bind(("name", name.clone()));
            }
            if let Some(description) = &input.description {
                builder = builder.bind(("description", description.clone()));
            }
            if let Some(is_global) = input.is_global {
                builder = builder.bind(("is_global", is_global));
            }
            let mut result = builder.await.map_err(DbError::from)?;
            if let Some(refusal) = role_tx_outcome(result.take_errors(), "role", &id_str, "")? {
                return Ok(Err(refusal));
            }
            let rows: Vec<RoleRow> = result.take(update_slot).map_err(DbError::from)?;
            Ok::<_, DbError>(Ok(rows))
        })
        .await;
        let rows = outcome.map_err(AxiamError::from)??;

        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "role".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Role {
            id,
            tenant_id,
            name: row.name,
            description: row.description,
            is_global: row.is_global,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    /// [`RoleRepository::delete`], claiming `claim` (both epochs: the gate's
    /// rule reads the role's grants and whether the writer holds it).
    ///
    /// # Errors
    ///
    /// As the trait method, plus `Conflict` ("the role changed since it was
    /// read") when an epoch the claim names has moved.
    pub async fn delete_claimed(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<()> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        // D-13/CQ-B07/SEC-058: has_role/grants edge tables carry no
        // tenant_id field of their own (schema v19 defines
        // idx_has_role_unique / idx_grants_unique on (in, out) only), so
        // tenant scoping on these two DELETEs is expressed as a
        // node-tenant subquery guard on the edge's out/in endpoint record
        // (out.tenant_id / in.tenant_id — dereferencing the linked
        // record's field via graph traversal, the same syntax already used
        // by get_user_role_assignments above) rather than a flat WHERE
        // clause. Without this guard, a caller supplying a foreign-tenant
        // role id could strip another tenant's has_role/grants edges even
        // though the final record DELETE (which does carry a flat
        // tenant_id predicate) would simply no-op for not matching the
        // caller's tenant.
        //
        // All three deletes run inside one transaction so a concurrent
        // reader never observes a partially-deleted role; the claim is
        // compared in the same transaction, and the role row it deletes is
        // the row every other role write moves an epoch on.
        // SEC-104 — see `helpers::delete_existence_guard`.
        let guard = crate::helpers::delete_existence_guard("role");
        let claim_check = claim_statements(
            &id_str,
            Claims {
                grants: true,
                holders: true,
            },
        );
        let query = format!(
            "BEGIN TRANSACTION; \
             {guard} \
             {claim_check}\
             DELETE has_role WHERE out = role:`{id_str}` AND out.tenant_id = $tenant_id; \
             DELETE grants WHERE in = role:`{id_str}` AND in.tenant_id = $tenant_id; \
             DELETE type::record('role', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );
        let (claimed, claim_grants, claim_holders) = claim_binds(claim.as_ref());

        let outcome = retry_on_write_conflict(|| async {
            let mut result = self
                .db
                .current()
                .query(query.as_str())
                .bind(("id", id_str.clone()))
                .bind(("tenant_id", tenant_id_str.clone()))
                .bind(("tid", tenant_id_str.clone()))
                .bind(("claimed", claimed))
                .bind(("claim_grants", claim_grants))
                .bind(("claim_holders", claim_holders))
                .await
                .map_err(DbError::from)?;
            role_tx_outcome(result.take_errors(), "role", &id_str, "")
        })
        .await;
        match outcome.map_err(AxiamError::from)? {
            None => Ok(()),
            Some(refusal) => Err(refusal),
        }
    }

    /// The role's two epochs, `None` when it is not the tenant's (the
    /// [`RoleRepository::get_role_epochs`] override).
    async fn read_role_epochs(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Option<RoleEpochs>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT VALUE [grant_epoch ?? 0, holder_epoch ?? 0] \
                 FROM type::record('role', $id) WHERE tenant_id = $tenant_id",
            )
            .bind(("id", role_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<Vec<i64>> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|epochs| RoleEpochs {
            grants: epochs
                .first()
                .copied()
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(0),
            holders: epochs
                .get(1)
                .copied()
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(0),
        }))
    }

    // -- the writes the network gate clears, with its claim (R110W6-04) -----
    //
    // `RoleRepository`'s assignment methods are these with no claim. The REST
    // handlers call these, with `GateClearance::role_claim()`.

    /// [`RoleRepository::assign_to_user`], claiming `claim`.
    ///
    /// # Errors
    ///
    /// As the trait method, plus `Conflict` ("the role changed since it was
    /// read") when an epoch the claim names has moved.
    pub async fn assign_to_user_claimed(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        scope: AssignmentScope,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<()> {
        self.relate_subject_to_role(
            "user",
            "user",
            tenant_id,
            user_id,
            role_id,
            scope,
            claim.as_ref(),
        )
        .await
    }

    /// [`RoleRepository::unassign_from_user`], claiming `claim`.
    ///
    /// # Errors
    ///
    /// As [`Self::assign_to_user_claimed`].
    pub async fn unassign_from_user_claimed(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<()> {
        self.unrelate_subject_from_role(
            "user",
            "user",
            tenant_id,
            user_id,
            role_id,
            resource_id,
            claim.as_ref(),
        )
        .await
    }

    /// [`RoleRepository::assign_to_service_account`], claiming `claim`.
    ///
    /// # Errors
    ///
    /// As [`Self::assign_to_user_claimed`].
    pub async fn assign_to_service_account_claimed(
        &self,
        tenant_id: Uuid,
        service_account_id: Uuid,
        role_id: Uuid,
        scope: AssignmentScope,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<()> {
        self.relate_subject_to_role(
            "service_account",
            "service account",
            tenant_id,
            service_account_id,
            role_id,
            scope,
            claim.as_ref(),
        )
        .await
    }

    /// [`RoleRepository::unassign_from_service_account`], claiming `claim`.
    ///
    /// # Errors
    ///
    /// As [`Self::assign_to_user_claimed`].
    pub async fn unassign_from_service_account_claimed(
        &self,
        tenant_id: Uuid,
        service_account_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<()> {
        self.unrelate_subject_from_role(
            "service_account",
            "service account",
            tenant_id,
            service_account_id,
            role_id,
            resource_id,
            claim.as_ref(),
        )
        .await
    }

    /// [`RoleRepository::assign_to_group`], claiming `claim`. Rule 2 is
    /// re-asserted inside the transaction whatever the claim.
    ///
    /// # Errors
    ///
    /// As [`Self::assign_to_user_claimed`]; `Conflict` too when the role
    /// carries a `network:` permission by the time the transaction runs.
    pub async fn assign_to_group_claimed(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        scope: AssignmentScope,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<()> {
        self.relate_subject_to_role(
            "group",
            "group",
            tenant_id,
            group_id,
            role_id,
            scope,
            claim.as_ref(),
        )
        .await
    }

    /// [`RoleRepository::unassign_from_group`], claiming `claim`.
    ///
    /// # Errors
    ///
    /// As [`Self::assign_to_user_claimed`].
    pub async fn unassign_from_group_claimed(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
        claim: Option<RoleClaim>,
    ) -> AxiamResult<()> {
        self.unrelate_subject_from_role(
            "group",
            "group",
            tenant_id,
            group_id,
            role_id,
            resource_id,
            claim.as_ref(),
        )
        .await
    }

    /// Shared body of `get_role_user_assignments` / `get_role_group_assignments`.
    ///
    /// `subject_table` is one of the two literals those methods pass — it is
    /// never caller input, which is why it can be interpolated into the query
    /// text. It has to be: a table name is not a bindable value in SurrealQL,
    /// and `type::table()` cannot appear in a `FROM` clause here.
    ///
    /// Anchoring the subject set on its own table is what discriminates a user
    /// edge from a group edge — `has_role` carries both, and `in` is the only
    /// thing that tells them apart. That is the same idiom `get_role_user_ids`
    /// uses; the difference is that the second statement reads `resource_id`
    /// off the edge instead of throwing it away.
    ///
    /// The `LET` matters for the same reason it does in
    /// `get_user_role_assignments`: evaluated inline, the planner cannot see a
    /// constant on the right-hand side of `in IN (...)` and walks every
    /// `has_role` edge in the database. Bound first, the set is a constant and
    /// the predicate is an index lookup. Note the subject set is bounded by the
    /// role's own assignees, not by the tenant's whole user table.
    ///
    /// Statement indices: 0 = LET, 1 = SELECT.
    /// Every role a principal holds — assigned directly, or inherited through a
    /// group it belongs to.
    ///
    /// `subject_table` is `user` or `service_account`. Both traverse
    /// `member_of` the same way, because a group is a collection of principals
    /// and a machine identity in one inherits its roles exactly as a person
    /// does. That is the whole reason to put a fleet of devices in a group: it
    /// is granted and revoked as one thing.
    async fn subject_roles(
        &self,
        subject_table: &str,
        tenant_id: Uuid,
        subject_id: Uuid,
    ) -> AxiamResult<Vec<Role>> {
        let tenant_id_str = tenant_id.to_string();
        let subject_id_str = subject_id.to_string();

        // Two queries: direct roles + roles inherited through group membership.
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE out FROM has_role \
                     WHERE in = type::record('{subject_table}', $subject_id)\
                 ); \
                 SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE out FROM has_role \
                     WHERE in IN (\
                         SELECT VALUE out FROM member_of \
                         WHERE in = type::record('{subject_table}', $subject_id)\
                     )\
                 );"
            ))
            .bind(("tenant_id", tenant_id_str))
            .bind(("subject_id", subject_id_str))
            .await
            .map_err(DbError::from)?;

        let direct: Vec<RoleRowWithId> = result.take(0).map_err(DbError::from)?;
        let inherited: Vec<RoleRowWithId> = result.take(1).map_err(DbError::from)?;

        // Merge and deduplicate by record_id.
        let mut seen = std::collections::HashSet::new();
        let mut roles = Vec::new();
        for row in direct.into_iter().chain(inherited) {
            if seen.insert(row.record_id.clone()) {
                roles.push(row.try_into_role()?);
            }
        }

        Ok(roles)
    }

    /// Create a `has_role` edge from any principal table.
    ///
    /// `subject_table` is `user`, `group` or `service_account`. The three were
    /// three near-identical copies of this query, and adding service accounts
    /// would have made a fourth — which is how the tenant guard, the duplicate
    /// classification and the resource scoping drift apart between principal
    /// kinds. `has_role` has always been declared `User/ServiceAccount/Group ->
    /// Role`; nothing about the edge itself distinguishes them.
    ///
    /// One transaction (R110W6-04, the notes above [`ROLE_EPOCH_STALE`]): the
    /// tenant guard, the `claim` on `grant_epoch` when the gate made one, for a
    /// group the rule-2 re-check, the `holder_epoch` move and the edge.
    ///
    /// `subject_label` only names the subject in the denial message.
    #[allow(clippy::too_many_arguments)]
    async fn relate_subject_to_role(
        &self,
        subject_table: &str,
        subject_label: &str,
        tenant_id: Uuid,
        subject_id: Uuid,
        role_id: Uuid,
        scope: AssignmentScope,
        claim: Option<&RoleClaim>,
    ) -> AxiamResult<()> {
        let subject_id_str = subject_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = scope.resource_id.map(|r| r.to_string());
        // Bound as `Option<Vec<String>>` so an absent scope lands as SurrealDB
        // `NONE` and not as an empty array: those are the two different answers
        // "reaches everywhere the role does" and "reaches nothing", and the
        // read path keeps them apart too (see `parse_tenant_scope`).
        let tenant_scope_strs = scope
            .tenant_scope
            .map(|ids| ids.iter().map(Uuid::to_string).collect::<Vec<_>>());
        // §4.2 rule 2, re-asserted for a group whatever the claim: a role
        // carrying a `network:` permission is never held by a group.
        let rule_2 = if subject_table == "group" {
            format!(
                "LET $network = (SELECT VALUE id FROM grants \
                     WHERE in = role:`{role_id_str}` \
                     AND string::matches(out.action ?? '', {NETWORK_ACTION_REGEX}) LIMIT 1); \
                 IF array::len($network) > 0 {{ THROW '{GROUP_ASSIGNMENT_OF_NETWORK_ROLE}'; }}; "
            )
        } else {
            String::new()
        };
        let claim_check = claim_statements(
            &role_id_str,
            Claims {
                grants: true,
                holders: false,
            },
        );
        let bump = bump_statement(&role_id_str, Epoch::Holders);

        // CQ-B07: verify both endpoints belong to the same tenant before RELATE.
        let query = format!(
            "BEGIN TRANSACTION; \
             LET $s = (SELECT id FROM {subject_table}:`{subject_id_str}` WHERE tenant_id = $tid); \
             LET $r = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid); \
             IF array::len($s) = 0 OR array::len($r) = 0 {{ \
                 THROW 'cross-tenant edge denied'; \
             }}; \
             {claim_check}{rule_2}{bump}\
             RELATE {subject_table}:`{subject_id_str}` -> has_role -> role:`{role_id_str}` \
             SET resource_id = $resource_id, tenant_scope = $tenant_scope, inherit = $inherit; \
             COMMIT TRANSACTION"
        );
        let (claimed, claim_grants, claim_holders) = claim_binds(claim);
        let cross_tenant = format!("cross-tenant {subject_label} role assignment denied");

        let outcome = retry_on_write_conflict(|| async {
            let mut result = self
                .db
                .current()
                .query(query.as_str())
                .bind(("tid", tenant_id.to_string()))
                .bind(("resource_id", resource_id_str.clone()))
                .bind(("tenant_scope", tenant_scope_strs.clone()))
                // Written only when it departs from the default, so an ordinary
                // assignment lands exactly as it did before v66 — NONE, read back
                // as `true` — and a pre-v66 edge and a post-v66 one are
                // indistinguishable unless the caller asked for the difference.
                .bind(("inherit", (!scope.inherit).then_some(false)))
                .bind(("claimed", claimed))
                .bind(("claim_grants", claim_grants))
                .bind(("claim_holders", claim_holders))
                .await
                .map_err(DbError::from)?;
            // QUAL-03/D-09: a duplicate has_role edge violates the
            // idx_has_role_unique UNIQUE(in,out) index — classified (and only
            // that) as 409.
            role_tx_outcome(
                result.take_errors(),
                "role_assignment",
                &role_id_str,
                &cross_tenant,
            )
        })
        .await;
        match outcome.map_err(AxiamError::from)? {
            None => Ok(()),
            Some(refusal) => Err(refusal),
        }
    }

    /// Remove a `has_role` edge from any principal table.
    ///
    /// The inverse of [`Self::relate_subject_to_role`], and scoped the same way:
    /// a `None` resource removes the *global* grant specifically, not every
    /// grant of that role, so revoking one resource-scoped assignment cannot
    /// silently take the others with it. In one transaction with the `claim` on
    /// `grant_epoch` and the `holder_epoch` move, as the assignment is.
    #[allow(clippy::too_many_arguments)]
    async fn unrelate_subject_from_role(
        &self,
        subject_table: &str,
        subject_label: &str,
        tenant_id: Uuid,
        subject_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
        claim: Option<&RoleClaim>,
    ) -> AxiamResult<()> {
        let subject_id_str = subject_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = resource_id.map(|r| r.to_string());

        let scope_clause = if resource_id_str.is_some() {
            "resource_id = $resource_id"
        } else {
            "resource_id = NONE"
        };
        let claim_check = claim_statements(
            &role_id_str,
            Claims {
                grants: true,
                holders: false,
            },
        );
        let bump = bump_statement(&role_id_str, Epoch::Holders);

        // CQ-B07: verify both endpoints belong to the same tenant before DELETE.
        let query = format!(
            "BEGIN TRANSACTION; \
             LET $s = (SELECT id FROM {subject_table}:`{subject_id_str}` WHERE tenant_id = $tid); \
             LET $r = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid); \
             IF array::len($s) = 0 OR array::len($r) = 0 {{ \
                 THROW 'cross-tenant edge denied'; \
             }}; \
             {claim_check}{bump}\
             DELETE has_role WHERE \
             in = {subject_table}:`{subject_id_str}` AND \
             out = role:`{role_id_str}` AND \
             {scope_clause}; \
             COMMIT TRANSACTION"
        );
        let (claimed, claim_grants, claim_holders) = claim_binds(claim);
        let cross_tenant = format!("cross-tenant {subject_label} role unassignment denied");

        let outcome = retry_on_write_conflict(|| async {
            let mut result = self
                .db
                .current()
                .query(query.as_str())
                .bind(("tid", tenant_id.to_string()))
                .bind(("resource_id", resource_id_str.clone()))
                .bind(("claimed", claimed))
                .bind(("claim_grants", claim_grants))
                .bind(("claim_holders", claim_holders))
                .await
                .map_err(DbError::from)?;
            role_tx_outcome(
                result.take_errors(),
                "role_assignment",
                &role_id_str,
                &cross_tenant,
            )
        })
        .await;
        match outcome.map_err(AxiamError::from)? {
            None => Ok(()),
            Some(refusal) => Err(refusal),
        }
    }

    async fn role_subject_assignments(
        &self,
        subject_table: &'static str,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Vec<RoleSubjectAssignment>> {
        let query = format!(
            "LET $subjects = (\
                 SELECT VALUE id FROM {subject_table} \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE in FROM has_role \
                     WHERE out = type::record('role', $role_id)\
                 )\
             ); \
             SELECT meta::id(in.id) AS subject_id, resource_id, tenant_scope, inherit \
             FROM has_role \
             WHERE out = type::record('role', $role_id) \
             AND in IN $subjects;"
        );

        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("role_id", role_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RoleSubjectAssignmentRow> = result.take(1).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_subject_assignment().map_err(Into::into))
            .collect()
    }
}

impl<C: Connection> RoleRepository for SurrealRoleRepository<C> {
    async fn create(&self, input: CreateRole) -> AxiamResult<Role> {
        let id = new_id();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('role', $id) SET \
                 tenant_id = $tenant_id, \
                 name = $name, description = $description, \
                 is_global = $is_global",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("name", input.name))
            .bind(("description", input.description))
            .bind(("is_global", input.is_global))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e.to_string(), "role"))?;

        let rows: Vec<RoleRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "role".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Role {
            id,
            tenant_id,
            name: row.name,
            description: row.description,
            is_global: row.is_global,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Role> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('role', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RoleRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "role".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Role {
            id,
            tenant_id,
            name: row.name,
            description: row.description,
            is_global: row.is_global,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn update(&self, tenant_id: Uuid, id: Uuid, input: UpdateRole) -> AxiamResult<Role> {
        self.update_claimed(tenant_id, id, input, None).await
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.delete_claimed(tenant_id, id, None).await
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Role>> {
        let tenant_id_str = tenant_id.to_string();

        // Free-text filter, applied to BOTH queries below so the
        // total counts matches rather than rows — a pager whose page
        // count belongs to a different result set than the page it
        // shows is worse than no pager. Empty when unsearched, so an
        // unfiltered list runs exactly the query it always ran.
        let search = search_filter(&pagination, &["name", "description"]);
        let search_term = search_bind(&pagination);

        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM role \
                 WHERE tenant_id = $tenant_id{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id_str.clone()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id{search} \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset"
            ))
            .bind(("tenant_id", tenant_id_str))
            .bind(("search", search_term))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RoleRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_role())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }

    async fn assign_to_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        scope: AssignmentScope,
    ) -> AxiamResult<()> {
        self.assign_to_user_claimed(tenant_id, user_id, role_id, scope, None)
            .await
    }

    async fn unassign_from_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        self.unassign_from_user_claimed(tenant_id, user_id, role_id, resource_id, None)
            .await
    }

    async fn get_user_roles(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Role>> {
        self.subject_roles("user", tenant_id, user_id).await
    }

    async fn get_user_role_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<RoleAssignment>> {
        let tenant_id_str = tenant_id.to_string();
        let user_id_str = user_id.to_string();

        // Query has_role edges (direct + via groups) and join with role data.
        // Each result row contains role fields + the resource_id from the edge.
        //
        // I7(a) — the group-inherited half MUST hoist the membership sub-select
        // into a `LET` binding.
        //
        // Written inline as `WHERE in IN (SELECT VALUE out FROM member_of …)`
        // the planner cannot see a constant on the right-hand side; it reports
        // `TableScan { predicate: "in INSIDE (ProjectValue) …",
        // pre_decode_filter: "no (unsupported predicate)" }` and walks **every**
        // `has_role` edge in the database — every role assignment of every user
        // of every tenant — on every authorization check. Evaluating the
        // membership set first and binding it to `$group_records` turns the same
        // predicate into an `IndexScan` over the `(in, out)` composite index
        // `idx_has_role_unique` (schema v19). Rows returned are identical; only
        // the plan changes. Pinned by
        // `crates/axiam-db/tests/authz_query_plan_test.rs`.
        //
        // Defence in depth (security re-verification 2026-08-03, residual 1):
        // the `member_of` traversal carries its own `out.tenant_id =
        // $tenant_id` predicate. It is not reachable today — `group.rs`
        // validates BOTH endpoints against the tenant before writing a
        // `member_of` edge, and the outer `has_role` predicate still confines
        // the resulting role to the tenant — but without it this was the one
        // authorization edge with no read-time tenant check, so a migration or
        // bulk import writing `member_of` directly would have bypassed it.
        // `out` is a `group` record and `idx_member_of_unique` still serves the
        // `in =` half, so the added predicate is a post-filter on an already
        // index-selected row set: no plan change (pinned by
        // `authz_query_plan_test::group_membership_lookup_is_index_satisfied`).
        //
        // A subject id is looked up in BOTH principal tables. `AccessRequest`
        // carries no principal kind on purpose — `RequirePermission::check_subject`
        // states that RBAC applies identically to a service account and a user —
        // so the query resolves whichever record exists. Ids are v4 UUIDs, so a
        // subject is never both.
        //
        // Without this a service account resolved zero grants no matter what was
        // assigned to it, which is why a machine identity could hold no
        // permissions at all.
        let mut result = self
            .db
            .current()
            .query(
                "LET $subject_records = [\
                     type::record('user', $user_id), \
                     type::record('service_account', $user_id)\
                 ]; \
                 SELECT meta::id(out.id) AS record_id, \
                        out.tenant_id AS tenant_id, \
                        out.name AS name, \
                        out.description AS description, \
                        out.is_global AS is_global, \
                        out.created_at AS created_at, \
                        out.updated_at AS updated_at, \
                        resource_id, \
                        tenant_scope, \
                        inherit \
                 FROM has_role \
                 WHERE in IN $subject_records \
                 AND out.tenant_id = $tenant_id; \
                 LET $group_records = (\
                     SELECT VALUE out FROM member_of \
                     WHERE in IN $subject_records \
                     AND out.tenant_id = $tenant_id\
                 ); \
                 SELECT meta::id(out.id) AS record_id, \
                        out.tenant_id AS tenant_id, \
                        out.name AS name, \
                        out.description AS description, \
                        out.is_global AS is_global, \
                        out.created_at AS created_at, \
                        out.updated_at AS updated_at, \
                        resource_id, \
                        tenant_scope, \
                        inherit \
                 FROM has_role \
                 WHERE in IN $group_records \
                 AND out.tenant_id = $tenant_id;",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("user_id", user_id_str))
            .await
            .map_err(DbError::from)?;

        // Statement indices: 0 = LET $subject_records, 1 = direct SELECT,
        // 2 = LET $group_records, 3 = group-inherited SELECT.
        let direct: Vec<RoleAssignmentRow> = result.take(1).map_err(DbError::from)?;
        let inherited: Vec<RoleAssignmentRow> = result.take(3).map_err(DbError::from)?;

        let mut assignments = Vec::new();
        for row in direct.into_iter().chain(inherited) {
            assignments.push(row.try_into_assignment()?);
        }

        Ok(assignments)
    }

    async fn assign_to_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        scope: AssignmentScope,
    ) -> AxiamResult<()> {
        self.assign_to_group_claimed(tenant_id, group_id, role_id, scope, None)
            .await
    }

    async fn unassign_from_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        self.unassign_from_group_claimed(tenant_id, group_id, role_id, resource_id, None)
            .await
    }

    async fn assign_to_service_account(
        &self,
        tenant_id: Uuid,
        service_account_id: Uuid,
        role_id: Uuid,
        scope: AssignmentScope,
    ) -> AxiamResult<()> {
        self.assign_to_service_account_claimed(tenant_id, service_account_id, role_id, scope, None)
            .await
    }

    async fn unassign_from_service_account(
        &self,
        tenant_id: Uuid,
        service_account_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        self.unassign_from_service_account_claimed(
            tenant_id,
            service_account_id,
            role_id,
            resource_id,
            None,
        )
        .await
    }

    async fn get_service_account_roles(
        &self,
        tenant_id: Uuid,
        service_account_id: Uuid,
    ) -> AxiamResult<Vec<Role>> {
        self.subject_roles("service_account", tenant_id, service_account_id)
            .await
    }

    async fn get_role_service_account_assignments(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Vec<RoleSubjectAssignment>> {
        self.role_subject_assignments("service_account", tenant_id, role_id)
            .await
    }

    async fn get_group_roles(&self, tenant_id: Uuid, group_id: Uuid) -> AxiamResult<Vec<Role>> {
        let tenant_id_str = tenant_id.to_string();
        let group_id_str = group_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE out FROM has_role \
                     WHERE in = type::record('group', $group_id)\
                 )",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("group_id", group_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RoleRowWithId> = result.take(0).map_err(DbError::from)?;

        let roles = rows
            .into_iter()
            .map(|row| row.try_into_role())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(roles)
    }

    async fn get_role_user_ids(&self, tenant_id: Uuid, role_id: Uuid) -> AxiamResult<Vec<Uuid>> {
        // Select user IDs directly assigned this role. Selecting FROM `user`
        // naturally excludes group edges (group links never match a user id).
        let mut result = self
            .db
            .current()
            .query(
                "SELECT VALUE meta::id(id) FROM user \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE in FROM has_role \
                     WHERE out = type::record('role', $role_id)\
                 )",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("role_id", role_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let ids: Vec<String> = result.take(0).map_err(DbError::from)?;
        ids.iter()
            .map(|s| parse_uuid(s, "user_id").map_err(Into::into))
            .collect()
    }

    async fn get_role_group_ids(&self, tenant_id: Uuid, role_id: Uuid) -> AxiamResult<Vec<Uuid>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT VALUE meta::id(id) FROM group \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE in FROM has_role \
                     WHERE out = type::record('role', $role_id)\
                 )",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("role_id", role_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let ids: Vec<String> = result.take(0).map_err(DbError::from)?;
        ids.iter()
            .map(|s| parse_uuid(s, "group_id").map_err(Into::into))
            .collect()
    }

    async fn get_group_role_assignments(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> AxiamResult<Vec<RoleAssignment>> {
        // The direct half of `get_user_role_assignments`, anchored on a group
        // instead of a user. A group has no membership graph to walk — a role
        // reaches a user *through* a group, never the other way round — so this
        // is a single statement rather than that method's three.
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(out.id) AS record_id, \
                        out.tenant_id AS tenant_id, \
                        out.name AS name, \
                        out.description AS description, \
                        out.is_global AS is_global, \
                        out.created_at AS created_at, \
                        out.updated_at AS updated_at, \
                        resource_id, \
                        tenant_scope, \
                        inherit \
                 FROM has_role \
                 WHERE in = type::record('group', $group_id) \
                 AND out.tenant_id = $tenant_id;",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("group_id", group_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RoleAssignmentRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|row| row.try_into_assignment().map_err(Into::into))
            .collect()
    }

    async fn get_role_user_assignments(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Vec<RoleSubjectAssignment>> {
        self.role_subject_assignments("user", tenant_id, role_id)
            .await
    }

    async fn get_role_group_assignments(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Vec<RoleSubjectAssignment>> {
        self.role_subject_assignments("group", tenant_id, role_id)
            .await
    }

    async fn get_role_epochs(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Option<RoleEpochs>> {
        self.read_role_epochs(tenant_id, role_id).await
    }
}

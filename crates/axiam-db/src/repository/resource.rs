//! SurrealDB implementation of [`ResourceRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::resource::{CreateResource, Resource, UpdateResource};
use axiam_core::repository::{PaginatedResult, Pagination, ResourceRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, paginate, take_first_or_not_found};

#[derive(Debug, SurrealValue)]
struct ResourceRow {
    tenant_id: String,
    name: String,
    resource_type: String,
    parent_id: Option<String>,
    metadata: serde_json::Value,
    /// X2 provenance. `Option` at the row level too, because rows written
    /// before schema v33 simply do not carry the field.
    #[surreal(default)]
    uma_registered_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct ResourceRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    resource_type: String,
    parent_id: Option<String>,
    metadata: serde_json::Value,
    #[surreal(default)]
    uma_registered_by: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ResourceRowWithId {
    fn try_into_resource(self) -> Result<Resource, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let parent_id = self
            .parent_id
            .map(|p| Uuid::parse_str(&p))
            .transpose()
            .map_err(|e| DbError::Migration(format!("invalid parent UUID: {e}")))?;
        Ok(Resource {
            id,
            tenant_id,
            name: self.name,
            resource_type: self.resource_type,
            parent_id,
            metadata: self.metadata,
            uma_registered_by: self.uma_registered_by,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

fn row_to_resource(row: ResourceRow, id: Uuid) -> Result<Resource, DbError> {
    let tenant_id = Uuid::parse_str(&row.tenant_id)
        .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
    let parent_id = row
        .parent_id
        .map(|p| Uuid::parse_str(&p))
        .transpose()
        .map_err(|e| DbError::Migration(format!("invalid parent UUID: {e}")))?;
    Ok(Resource {
        id,
        tenant_id,
        name: row.name,
        resource_type: row.resource_type,
        parent_id,
        metadata: row.metadata,
        uma_registered_by: row.uma_registered_by,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Maximum depth for ancestor traversal to prevent infinite loops.
const MAX_ANCESTOR_DEPTH: usize = 50;

/// SurrealDB implementation of the Resource repository.
#[derive(Clone)]
pub struct SurrealResourceRepository<C: Connection> {
    db: DbHandle<C>,
}

/// The message `claim_parent` throws when the parent is gone. Matched on the
/// way back out, so the caller sees `NotFound` rather than an opaque error.
const PARENT_GONE: &str = "parent resource not found";

/// SQL that claims `parent_id` for a child about to be attached to it (#308).
///
/// # Why a write, and why it must be this write
///
/// `resource.delete` guards itself by reading the `child_of` range for the
/// resource being deleted and refusing if it is non-empty. That read cannot see
/// an edge a concurrent transaction has not written yet, and snapshot isolation
/// does not turn a range read into a conflict against a later insert — that is
/// a phantom, and it needs serialisable isolation. So the guard alone loses the
/// race, reproducibly (#308: trial 0 of every run on surrealkv).
///
/// What these engines DO detect reliably is two transactions writing the same
/// key; `tools/surreal-race-probe` measures them doing it 21613 times in 40000
/// contended attempts. `delete` already writes the parent's key — it deletes
/// the row. So every path that attaches a child writes it too, and the engine's
/// existing conflict detection decides the race instead of a query that cannot.
///
/// Two things here are load-bearing and easy to strip by accident:
///
/// 1. **The `THROW` is not an error-message nicety.** If the parent has already
///    been deleted, the `UPDATE` matches nothing, and *nothing matching is not
///    a conflict* — the create would sail past and write an edge to a row that
///    no longer exists, which is precisely the orphan being prevented. Losing
///    the race has to be an error, so it throws.
/// 2. **It must be in the same transaction as the `RELATE`.** Split across two
///    transactions, the parent could be deleted in the gap.
///
/// The counter's value is never read. Bumping it is the entire point.
///
/// Reads the already-bound `$parent_id` and `$tenant_id`, so callers add no
/// bindings; the tenant guard is what stops a child being attached under
/// another tenant's node.
fn claim_parent() -> String {
    format!(
        "LET $parent = (UPDATE type::record('resource', $parent_id) \
             SET child_epoch = (child_epoch ?? 0) + 1 \
             WHERE tenant_id = $tenant_id RETURN VALUE id); \
         IF array::len($parent) = 0 {{ THROW '{PARENT_GONE}'; }};"
    )
}

/// Turns a `claim_parent` throw into `NotFound`, and anything else into a
/// database error.
///
/// Mirrors `delete`'s handling and for the same reason: a `THROW` fires on its
/// own statement slot while the trailing statements report the generic "not
/// executed due to a failed transaction", and `Response::check()` may surface
/// either — so every statement error is scanned rather than just the first.
fn parent_claim_error(errors: Vec<String>, parent_id: &str) -> AxiamError {
    let combined = errors.join("; ");
    if combined.contains(PARENT_GONE) {
        return AxiamError::NotFound {
            entity: "resource".into(),
            id: parent_id.to_string(),
        };
    }
    DbError::Migration(combined).into()
}

impl<C: Connection> SurrealResourceRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }

    /// Create a resource and stamp the UMA client that registered it (X2).
    ///
    /// # Why this is an inherent method and not on `ResourceRepository`
    ///
    /// Provenance has exactly one writer — the resource-registration handler —
    /// and putting it on the trait would offer it to every caller that holds
    /// any `impl ResourceRepository`, which is the opposite of the point. The
    /// handler reaches this repository concretely through `AppState`, so the
    /// narrower home costs nothing and keeps `uma_registered_by` unreachable
    /// from `create`/`update`.
    ///
    /// One statement rather than create-then-mark: a crash between two writes
    /// would leave a resource that the Protection API registered but that
    /// claims it did not, and an unmarked resource is indistinguishable from
    /// one an administrator made by hand.
    pub async fn create_uma_registered(
        &self,
        input: CreateResource,
        client_id: &str,
    ) -> AxiamResult<Resource> {
        let id = new_id();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();
        let parent_id_str = input.parent_id.map(|p| p.to_string());
        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        let base = "CREATE type::record('resource', $id) SET \
                    tenant_id = $tenant_id, \
                    name = $name, resource_type = $resource_type, \
                    parent_id = $parent_id, \
                    metadata = $metadata, \
                    uma_registered_by = $uma_registered_by";

        // Same #308 parent claim as `create` — the Protection API attaches
        // children through this path too, and an orphan made here is
        // indistinguishable from one made there.
        let (query, row_slot) = match parent_id_str.as_deref() {
            Some(pid) => (
                format!(
                    "BEGIN TRANSACTION; {claim} {base}; \
                     RELATE resource:`{id_str}` -> child_of -> resource:`{pid}`; \
                     COMMIT TRANSACTION",
                    claim = claim_parent(),
                ),
                3,
            ),
            None => (base.to_string(), 0),
        };

        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("name", input.name))
            .bind(("resource_type", input.resource_type))
            .bind(("parent_id", parent_id_str.clone()))
            .bind(("metadata", metadata))
            .bind(("uma_registered_by", client_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let errors = result.take_errors();
        if !errors.is_empty() {
            let msgs: Vec<String> = errors.into_values().map(|e| e.to_string()).collect();
            return Err(match parent_id_str.as_deref() {
                Some(pid) => parent_claim_error(msgs, pid),
                None => DbError::Migration(msgs.join("; ")).into(),
            });
        }

        let rows: Vec<ResourceRow> = result.take(row_slot).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "resource", &id_str)?;

        row_to_resource(row, id).map_err(Into::into)
    }
}

impl<C: Connection> ResourceRepository for SurrealResourceRepository<C> {
    async fn create(&self, input: CreateResource) -> AxiamResult<Resource> {
        let id = new_id();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();
        let parent_id_str = input.parent_id.map(|p| p.to_string());

        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        // Create resource + optional child_of edge in one query.
        let base = "CREATE type::record('resource', $id) SET \
                    tenant_id = $tenant_id, \
                    name = $name, resource_type = $resource_type, \
                    parent_id = $parent_id, \
                    metadata = $metadata";

        // #308: attaching a child claims the parent inside the same
        // transaction as the RELATE, so a concurrent `delete` of that parent
        // has a key to conflict on. See `claim_parent` for why the range guard
        // in `delete` cannot do this on its own. Without a parent there is no
        // edge, nothing to race, and no transaction needed.
        //
        // Slots with a parent: BEGIN=0, LET $parent=1, IF/THROW=2, CREATE=3,
        // RELATE=4, COMMIT=5. Without: CREATE=0.
        let (query, row_slot) = match parent_id_str.as_deref() {
            Some(pid) => (
                format!(
                    "BEGIN TRANSACTION; {claim} {base}; \
                     RELATE resource:`{id_str}` -> child_of -> resource:`{pid}`; \
                     COMMIT TRANSACTION",
                    claim = claim_parent(),
                ),
                3,
            ),
            None => (base.to_string(), 0),
        };

        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("name", input.name))
            .bind(("resource_type", input.resource_type))
            .bind(("parent_id", parent_id_str.clone()))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        // Every statement's error is scanned rather than only the first: a
        // THROW fires on its own slot while the statements after it report the
        // generic "not executed due to a failed transaction", and `check()` can
        // surface either. Same reasoning as `delete`.
        let errors = result.take_errors();
        if !errors.is_empty() {
            let msgs: Vec<String> = errors.into_values().map(|e| e.to_string()).collect();
            return Err(match parent_id_str.as_deref() {
                Some(pid) => parent_claim_error(msgs, pid),
                None => DbError::Migration(msgs.join("; ")).into(),
            });
        }

        let rows: Vec<ResourceRow> = result.take(row_slot).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "resource", &id_str)?;

        row_to_resource(row, id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Resource> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('resource', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ResourceRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "resource", &id_str)?;

        row_to_resource(row, id).map_err(Into::into)
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateResource,
    ) -> AxiamResult<Resource> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.resource_type.is_some() {
            sets.push("resource_type = $resource_type");
        }
        if input.parent_id.is_some() {
            sets.push("parent_id = $parent_id");
        }
        if input.metadata.is_some() {
            sets.push("metadata = $metadata");
        }
        sets.push("updated_at = time::now()");

        let mut query = format!(
            "UPDATE type::record('resource', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            sets.join(", ")
        );

        // If parent_id is being changed, update the child_of edge.
        let parent_id_changed = input.parent_id.is_some();
        if parent_id_changed {
            // CQ-B08: cycle check — walk ancestors of the new parent;
            // if we visit the current resource id, this re-parent would form a cycle.
            if let Some(Some(new_parent)) = &input.parent_id {
                // Self-parent is always a cycle.
                if *new_parent == id {
                    return Err(AxiamError::Validation {
                        message: "cycle detected in resource hierarchy".into(),
                    });
                }
                // Validate the new parent exists within the caller's tenant, so
                // a re-parent cannot attach this resource under another tenant's
                // node (get_by_id is tenant-scoped and returns NotFound
                // otherwise).
                self.get_by_id(tenant_id, *new_parent).await?;
                // Walk the new parent's ancestors: if any equals `id`, it's a cycle.
                let ancestors = self.get_ancestors(tenant_id, *new_parent).await?;
                if ancestors.iter().any(|a| a.id == id) {
                    return Err(AxiamError::Validation {
                        message: "cycle detected in resource hierarchy".into(),
                    });
                }
            }

            // Re-parenting mutates two-to-three statements (DELETE the old
            // child_of edge, UPDATE the record, optionally RELATE the new
            // edge). Wrap them in one transaction so a failure after the
            // DELETE (e.g. the RELATE hitting a UNIQUE violation) cannot leave
            // the resource orphaned with no rollback — the same class the
            // resource.delete transaction closed. The child_of edge carries no
            // flat tenant_id column, so the DELETE is tenant-scoped via a
            // node-tenant guard on its `in` endpoint (in.tenant_id); without
            // it a foreign-tenant resource id could strip another tenant's
            // parent edge.
            //
            // #308: re-parenting inserts into the NEW parent's `child_of`
            // range, which is the same phantom the `create` path had, so the
            // new parent is claimed here too. Only the new one: detaching a
            // child removes an edge, and a delete racing that either sees the
            // child and refuses or does not and has nothing to orphan.
            //
            // The `get_by_id` existence check above does NOT cover this — it is
            // a read, outside the transaction, and a read cannot conflict with
            // the delete. The claim is a write, and it throws if the parent
            // went away, which is what makes losing the race an error rather
            // than an orphan.
            //
            // Result slots become: BEGIN=0, DELETE child_of=1, then either
            // [LET $parent=2, IF/THROW=3, UPDATE=4, RELATE=5] when a new parent
            // is claimed, or [UPDATE=2] when the child is being detached.
            let claim = match &input.parent_id {
                Some(Some(_)) => claim_parent(),
                _ => String::new(),
            };
            query = format!(
                "BEGIN TRANSACTION; \
                 DELETE child_of WHERE in = resource:`{id_str}` AND in.tenant_id = $tenant_id; \
                 {claim} {query}"
            );

            // If new parent is Some, create new child_of edge.
            if let Some(Some(new_parent)) = &input.parent_id {
                let new_parent_str = new_parent.to_string();
                query = format!(
                    "{query}; RELATE resource:`{id_str}` -> child_of -> resource:`{new_parent_str}`"
                );
            }

            query = format!("{query}; COMMIT TRANSACTION");
        }

        let parent_id_str: Option<String> = input
            .parent_id
            .map(|opt| opt.map(|u| u.to_string()))
            .unwrap_or(None);

        let db = self.db.current();
        let mut builder = db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(resource_type) = input.resource_type {
            builder = builder.bind(("resource_type", resource_type));
        }
        if input.parent_id.is_some() {
            builder = builder.bind(("parent_id", parent_id_str));
        }
        if let Some(metadata) = input.metadata {
            builder = builder.bind(("metadata", metadata));
        }

        let mut result = builder.await.map_err(DbError::from)?;

        let errors = result.take_errors();
        if !errors.is_empty() {
            let msgs: Vec<String> = errors.into_values().map(|e| e.to_string()).collect();
            return Err(match &input.parent_id {
                Some(Some(new_parent)) => parent_claim_error(msgs, &new_parent.to_string()),
                _ => DbError::Migration(msgs.join("; ")).into(),
            });
        }

        // The UPDATE statement index depends on whether we wrapped the
        // re-parent in a transaction, and on whether that re-parent claimed a
        // new parent: BEGIN=0, DELETE child_of=1, then [LET=2, IF=3, UPDATE=4]
        // when attaching or [UPDATE=2] when detaching.
        let stmt_idx = match (parent_id_changed, &input.parent_id) {
            (true, Some(Some(_))) => 4,
            (true, _) => 2,
            (false, _) => 0,
        };
        let rows: Vec<ResourceRow> = result.take(stmt_idx).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "resource", &id_str)?;

        row_to_resource(row, id).map_err(Into::into)
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        // D-13/CQ-B46: fold the child-count guard into the SAME
        // transaction as the deletes via a LET-capture (mirroring
        // federation_login_state.rs's `LET $row = (...)` idiom). Before
        // this fix, the guard ran as a separate `.query()` round-trip
        // BEFORE the deletes — a classic TOCTOU: a concurrent child-create
        // could commit in the gap between the count-check and the delete,
        // leaving both a successful parent delete AND an orphaned child.
        // Now the read-then-decide-then-delete happens atomically: either
        // the transaction observes children and aborts before any DELETE
        // runs, or it observes none and every DELETE below commits
        // together.
        //
        // D-13/CQ-B07/SEC-058: child_of/on_resource edge tables carry no
        // tenant_id field of their own (schema v19 defines
        // idx_child_of_unique / idx_on_resource_unique on (in, out) only),
        // so tenant scoping on those two DELETEs is expressed as a
        // node-tenant subquery guard on the edge's in/out endpoint
        // (in.tenant_id / out.tenant_id via graph-traversal dereference),
        // not a flat WHERE clause. `scope` and the resource record itself
        // DO carry their own tenant_id field, so those two keep their
        // pre-existing flat predicates.
        //
        // Result slots: BEGIN=0, LET children=1, IF/THROW=2,
        // DELETE child_of=3, DELETE on_resource=4, DELETE scope=5,
        // DELETE resource=6, COMMIT=7. delete() returns Ok(()) — no row
        // data to extract, .check() alone proves the transaction
        // committed (or surfaces the child-guard THROW).
        // SEC-104: the existence guard runs before the child-count guard, so a
        // delete against a foreign or unknown id answers `NotFound` rather
        // than "no children, deleted nothing, 204".
        let guard = crate::helpers::delete_existence_guard("resource");
        let query = format!(
            "BEGIN TRANSACTION; \
             {guard} \
             LET $children = (SELECT VALUE id FROM child_of WHERE out = resource:`{id_str}`); \
             IF array::len($children) > 0 {{ \
                 THROW 'cannot delete resource with children'; \
             }}; \
             DELETE child_of WHERE \
                 (in = resource:`{id_str}` AND in.tenant_id = $tenant_id) OR \
                 (out = resource:`{id_str}` AND out.tenant_id = $tenant_id); \
             DELETE on_resource WHERE out = resource:`{id_str}` AND out.tenant_id = $tenant_id; \
             DELETE scope WHERE resource_id = $resource_id AND tenant_id = $tenant_id; \
             DELETE type::record('resource', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );

        let id_str_for_error = id_str.clone();
        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("resource_id", id_str))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        // The child-guard THROW fires on its own statement slot, but the
        // trailing DELETE/COMMIT slots report the generic "not executed due
        // to a failed transaction" error, and Response::check() can surface
        // one of those instead of the THROW text — which silently downgraded
        // the child-guard rejection to an opaque Migration error
        // (req14_tenant_isolation_test::resource_delete_with_children_rejected
        // regressed when 29-02 moved the guard from a Rust pre-check into the
        // transaction). Scan every statement error so the THROW message is
        // reliably detected regardless of which slot check() would return.
        let errors = result.take_errors();
        if !errors.is_empty() {
            let combined = errors
                .into_values()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            if combined.contains("cannot delete resource with children") {
                return Err(AxiamError::Validation {
                    message: "cannot delete resource with children".into(),
                });
            }
            // SEC-104: checked after the child guard, because a resource that
            // both exists and has children must keep answering with the more
            // specific refusal.
            if combined.contains(crate::helpers::DELETE_TARGET_MISSING) {
                return Err(DbError::NotFound {
                    entity: "resource".into(),
                    id: id_str_for_error,
                }
                .into());
            }
            return Err(DbError::Migration(combined).into());
        }

        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Resource>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM resource \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM resource \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ResourceRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_resource())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn get_children(&self, tenant_id: Uuid, parent_id: Uuid) -> AxiamResult<Vec<Resource>> {
        let tenant_id_str = tenant_id.to_string();
        let parent_id_str = parent_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM resource \
                 WHERE tenant_id = $tenant_id AND parent_id = $parent_id",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("parent_id", parent_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ResourceRowWithId> = result.take(0).map_err(DbError::from)?;

        rows.into_iter()
            .map(|row| row.try_into_resource())
            .collect::<Result<Vec<_>, DbError>>()
            .map_err(Into::into)
    }

    async fn get_ancestors(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Vec<Resource>> {
        let tenant_id_str = tenant_id.to_string();
        let id_str = id.to_string();

        // CQ-B13: walk the hierarchy in a SINGLE recursive graph query instead of
        // one SELECT per level. The `child_of` edge points child -> parent, so
        // `->child_of->resource` climbs one level; `.{..N+path}` follows that edge
        // up to N times and yields the ordered path of ancestor records
        // (nearest-first, EXCLUDING the starting resource — matching the previous
        // loop's output). The `(resource WHERE tenant_id = $tenant_id)` node filter
        // enforces tenant scoping: an ancestor in another tenant terminates the
        // walk, exactly like the old per-level `WHERE tenant_id` guard.
        //
        // CQ-B08 preserved: `+path` does NOT deduplicate, so both a
        // pathologically deep chain AND a cycle traverse until the depth cap and
        // return exactly MAX_ANCESTOR_DEPTH records. The original loop errored as
        // soon as it would step onto the MAX_ANCESTOR_DEPTH-th ancestor (i.e. when
        // there are >= MAX_ANCESTOR_DEPTH ancestors), so we recurse to
        // MAX_ANCESTOR_DEPTH and treat a result of that length as an
        // overflow/cycle — surfacing the same error rather than silently
        // truncating.
        let query = format!(
            "SELECT meta::id(id) AS record_id, tenant_id, name, resource_type, \
                    parent_id, metadata, created_at, updated_at \
             FROM array::flatten(\
                 type::record('resource', $id).{{..{depth}+path}}(\
                     ->child_of->(resource WHERE tenant_id = $tenant_id)));",
            depth = MAX_ANCESTOR_DEPTH,
        );

        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ResourceRowWithId> = result.take(0).map_err(DbError::from)?;

        if rows.len() >= MAX_ANCESTOR_DEPTH {
            return Err(DbError::Migration(
                "resource hierarchy exceeds maximum depth — possible cycle".into(),
            )
            .into());
        }

        rows.into_iter()
            .map(|row| row.try_into_resource())
            .collect::<Result<Vec<_>, DbError>>()
            .map_err(Into::into)
    }
}

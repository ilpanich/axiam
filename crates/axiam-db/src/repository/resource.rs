//! SurrealDB implementation of [`ResourceRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::resource::{CreateResource, Resource, UpdateResource};
use axiam_core::repository::{PaginatedResult, Pagination, ResourceRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::helpers::{CountRow, paginate, take_first_or_not_found};

#[derive(Debug, SurrealValue)]
struct ResourceRow {
    tenant_id: String,
    name: String,
    resource_type: String,
    parent_id: Option<String>,
    metadata: serde_json::Value,
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
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Maximum depth for ancestor traversal to prevent infinite loops.
const MAX_ANCESTOR_DEPTH: usize = 50;

/// SurrealDB implementation of the Resource repository.
#[derive(Clone)]
pub struct SurrealResourceRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealResourceRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> ResourceRepository for SurrealResourceRepository<C> {
    async fn create(&self, input: CreateResource) -> AxiamResult<Resource> {
        let id = Uuid::new_v4();
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

        let query = if let Some(ref pid) = parent_id_str {
            format!("{base}; RELATE resource:`{id_str}` -> child_of -> resource:`{pid}`;")
        } else {
            base.to_string()
        };

        let result = self
            .db
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("name", input.name))
            .bind(("resource_type", input.resource_type))
            .bind(("parent_id", parent_id_str))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ResourceRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "resource", &id_str)?;

        row_to_resource(row, id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Resource> {
        let id_str = id.to_string();

        let mut result = self
            .db
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
            // Result slots become: BEGIN=0, DELETE child_of=1, UPDATE=2,
            // [RELATE=3], COMMIT=last — so the UPDATE row lands at slot 2.
            query = format!(
                "BEGIN TRANSACTION; \
                 DELETE child_of WHERE in = resource:`{id_str}` AND in.tenant_id = $tenant_id; \
                 {query}"
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

        let mut builder = self
            .db
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

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        // The UPDATE statement index depends on whether we wrapped the
        // re-parent in a transaction: BEGIN=0, DELETE child_of=1, UPDATE=2.
        let stmt_idx = if parent_id_changed { 2 } else { 0 };
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
        let query = format!(
            "BEGIN TRANSACTION; \
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

        let mut result = self
            .db
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
        let mut ancestors = Vec::new();
        let mut current_id = id;

        // CQ-B08: walk at most MAX_ANCESTOR_DEPTH steps; if we exhaust the limit
        // without reaching a root (parent_id = None), the hierarchy is either
        // pathologically deep or contains a cycle — surface an error.
        let mut steps = 0usize;
        loop {
            if steps >= MAX_ANCESTOR_DEPTH {
                return Err(DbError::Migration(
                    "resource hierarchy exceeds maximum depth — possible cycle".into(),
                )
                .into());
            }
            steps += 1;

            let current_str = current_id.to_string();

            let mut result = self
                .db
                .query(
                    "SELECT * FROM type::record('resource', $id) \
                     WHERE tenant_id = $tenant_id",
                )
                .bind(("id", current_str))
                .bind(("tenant_id", tenant_id_str.clone()))
                .await
                .map_err(DbError::from)?;

            let rows: Vec<ResourceRow> = result.take(0).map_err(DbError::from)?;
            let row = match rows.into_iter().next() {
                Some(r) => r,
                None => break,
            };

            let parent_id_str = row.parent_id.clone();
            let resource = row_to_resource(row, current_id)?;

            // Don't include the starting resource itself; only ancestors.
            if current_id != id {
                ancestors.push(resource);
            }

            match parent_id_str {
                Some(pid) => {
                    current_id = Uuid::parse_str(&pid)
                        .map_err(|e| DbError::Migration(format!("invalid parent UUID: {e}")))?;
                }
                None => break,
            }
        }

        Ok(ancestors)
    }
}

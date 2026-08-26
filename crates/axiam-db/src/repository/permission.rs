//! SurrealDB implementation of [`PermissionRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::permission::{
    CreatePermission, Permission, PermissionEffect, PermissionGrant, UpdatePermission,
};
use axiam_core::repository::{PaginatedResult, Pagination, PermissionRepository};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use surrealdb::Connection;
use surrealdb_types::{RecordId, SurrealValue};
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_write_error, paginate, search_bind, search_filter, take_first_or_not_found,
};

#[derive(Debug, SurrealValue)]
struct PermissionRow {
    tenant_id: String,
    action: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct PermissionRowWithId {
    record_id: String,
    tenant_id: String,
    action: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl PermissionRowWithId {
    fn try_into_permission(self) -> Result<Permission, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        Ok(Permission {
            id,
            tenant_id,
            action: self.action,
            description: self.description,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Debug, SurrealValue)]
struct PermissionGrantRow {
    record_id: String,
    tenant_id: String,
    action: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    scope_ids: Option<Vec<String>>,
    /// B1: `NONE` on every pre-deny-override edge, which reads back as
    /// `Allow` — that is the whole migration.
    effect: Option<String>,
}

/// Row for the batched grant lookup — carries the owning role id so callers can
/// group the flattened result set back per role.
#[derive(Debug, SurrealValue)]
struct RolePermissionGrantRow {
    role_id: String,
    record_id: String,
    tenant_id: String,
    action: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    scope_ids: Option<Vec<String>>,
    effect: Option<String>,
}

impl RolePermissionGrantRow {
    /// `Ok(None)` when the row's `effect` is unrecognised — see
    /// [`PermissionGrantRow::try_into_grant`] (SEC-092).
    fn try_into_role_grant(self) -> Result<Option<(Uuid, PermissionGrant)>, DbError> {
        let role_id = Uuid::parse_str(&self.role_id)
            .map_err(|e| DbError::Migration(format!("invalid role UUID: {e}")))?;
        let grant = PermissionGrantRow {
            record_id: self.record_id,
            tenant_id: self.tenant_id,
            action: self.action,
            description: self.description,
            created_at: self.created_at,
            updated_at: self.updated_at,
            scope_ids: self.scope_ids,
            effect: self.effect,
        }
        .try_into_grant()?;
        Ok(grant.map(|g| (role_id, g)))
    }
}

impl PermissionGrantRow {
    /// `Ok(None)` means "this grant edge is malformed and contributes nothing"
    /// — not an error, and deliberately not an allow. See the `effect` match
    /// below (SEC-092).
    fn try_into_grant(self) -> Result<Option<PermissionGrant>, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        let scope_ids = self
            .scope_ids
            .unwrap_or_default()
            .into_iter()
            .map(|s| {
                Uuid::parse_str(&s)
                    .map_err(|e| DbError::Migration(format!("invalid scope UUID: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // B1: an ABSENT `effect` reads back as Allow; an UNRECOGNISED one
        // drops the grant entirely (`Ok(None)`).
        //
        // Absent is the backward-compatibility case and is simply correct:
        // every edge written before deny-override existed means "allow".
        //
        // Unrecognised is the security-relevant one, and it has three possible
        // answers, not two:
        //
        // 1. **Fail the read.** Takes the whole authorization path down for the
        //    tenant over a single malformed row. Rejected.
        // 2. **Default to Allow** — what this did until SEC-092. A grant edge
        //    nobody can interpret became a *permissive* one. `from_wire` trims
        //    and lowercases, so casing and whitespace are not how this happens;
        //    the realistic paths are a truncated or partially-written value, a
        //    row edited outside the API, and — the one worth planning for — a
        //    **rolling upgrade in which a newer node writes a third effect** a
        //    node still on this version does not know. Under the old default,
        //    every one of those grants read back as allow on the old node,
        //    which is deny-override defeated by a version skew.
        // 3. **Default to Deny.** Tempting, and wrong for a different reason:
        //    `PermissionEffect::Deny` is not "ignore this grant", it is an
        //    active override that masks the action for *everyone* holding the
        //    role. One malformed row would revoke access tenant-wide.
        //
        // Dropping the grant is the only answer that fails closed without
        // being weaponisable: the row contributes neither an allow nor a deny,
        // so the decision falls through to the other grants and ultimately to
        // default-deny. It is logged at `error` — the write path validates
        // `effect` (`PermissionEffect::from_wire`) and the v25 schema ASSERT
        // rejects anything else, so reaching this branch means either a
        // datastore modified outside both, or exactly the version skew above.
        let effect = match self.effect.as_deref() {
            None => PermissionEffect::Allow,
            Some(raw) => match PermissionEffect::from_wire(raw) {
                Some(effect) => effect,
                None => {
                    tracing::error!(
                        effect = %raw,
                        permission_id = %id,
                        "grant edge carries an unrecognised effect; DROPPING the \
                         grant (SEC-092). It contributes neither an allow nor a \
                         deny — treating it as 'allow' would let a malformed \
                         value defeat deny-override"
                    );
                    return Ok(None);
                }
            },
        };

        Ok(Some(PermissionGrant {
            permission: Permission {
                id,
                tenant_id,
                action: self.action,
                description: self.description,
                created_at: self.created_at,
                updated_at: self.updated_at,
            },
            scope_ids,
            effect,
        }))
    }
}

/// SurrealDB implementation of the Permission repository.
#[derive(Clone)]
pub struct SurrealPermissionRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealPermissionRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }

    /// The single `RELATE` behind every grant entry point (B1).
    ///
    /// `effect` is written as a plain string on the SAME `grants` edge the
    /// allow path already used. That is what keeps the authorization hot path
    /// at one batched query: denies arrive in the fetch that was already
    /// happening, so there is no deny-specific round trip and no per-tenant
    /// "has denies" flag that could go stale.
    ///
    /// It is also what keeps the `EXPLAIN` guard holding. `effect` appears
    /// only in the SELECT *projection*, never in a predicate, so it cannot
    /// make the query opaque to the planner — the I7(a) failure mode, where
    /// wrapping an indexed field in a function call turned an `IndexScan` into
    /// a full `TableScan` over every tenant's grants.
    async fn relate_grant(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
        scope_ids: Vec<Uuid>,
        effect: PermissionEffect,
    ) -> AxiamResult<()> {
        let role_id_str = role_id.to_string();
        let perm_id_str = permission_id.to_string();

        // SEC-058/SECFIX-02: mirror grant_to_role's tenant guard on BOTH branches —
        // this method is the REST-reachable path (POST /api/v1/roles/{id}/permissions).
        let result = if scope_ids.is_empty() {
            // Wildcard — same as grant_to_role
            let query = format!(
                "LET $ro = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
                 LET $pe = (SELECT id FROM permission:`{perm_id_str}` WHERE tenant_id = $tid);\
                 IF array::len($ro) = 0 OR array::len($pe) = 0 {{\
                     THROW 'cross-tenant edge denied';\
                 }};\
                 RELATE role:`{role_id_str}` -> grants -> \
                 permission:`{perm_id_str}` SET scope_ids = NONE, effect = $effect;"
            );
            self.db
                .current()
                .query(query)
                .bind(("tid", tenant_id.to_string()))
                .bind(("effect", effect.as_str().to_string()))
                .await
                .map_err(DbError::from)?
        } else {
            let scope_strs: Vec<String> = scope_ids.iter().map(|id| id.to_string()).collect();
            // Also verify every scope_id belongs to the caller's tenant before RELATE.
            let query = format!(
                "LET $ro = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
                 LET $pe = (SELECT id FROM permission:`{perm_id_str}` WHERE tenant_id = $tid);\
                 LET $sc = (SELECT id FROM scope WHERE tenant_id = $tid AND meta::id(id) IN $scope_ids);\
                 IF array::len($ro) = 0 OR array::len($pe) = 0 \
                    OR array::len($sc) != array::len($scope_ids) {{\
                     THROW 'cross-tenant edge denied';\
                 }};\
                 RELATE role:`{role_id_str}` -> grants -> \
                 permission:`{perm_id_str}` SET scope_ids = $scope_ids, effect = $effect;"
            );
            self.db
                .current()
                .query(query)
                .bind(("tid", tenant_id.to_string()))
                .bind(("scope_ids", scope_strs))
                .bind(("effect", effect.as_str().to_string()))
                .await
                .map_err(DbError::from)?
        };

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant edge denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant permission grant denied".into(),
                    action: None,
                    resource_id: None,
                });
            }
            // This is the REST-reachable path
            // (POST /api/v1/roles/{id}/permissions) — mirror grant_to_role's
            // classify_write_error so a duplicate grant surfaces as 409, not 500.
            return Err(classify_write_error(msg, "permission_grant").into());
        }

        Ok(())
    }
}

impl<C: Connection> PermissionRepository for SurrealPermissionRepository<C> {
    async fn create(&self, input: CreatePermission) -> AxiamResult<Permission> {
        let id = new_id();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('permission', $id) SET \
                 tenant_id = $tenant_id, \
                 action = $action, description = $description",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("action", input.action))
            .bind(("description", input.description))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e.to_string(), "permission"))?;

        let rows: Vec<PermissionRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "permission", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Permission {
            id,
            tenant_id,
            action: row.action,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Permission> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('permission', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PermissionRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "permission", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Permission {
            id,
            tenant_id,
            action: row.action,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdatePermission,
    ) -> AxiamResult<Permission> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.action.is_some() {
            sets.push("action = $action");
        }
        if input.description.is_some() {
            sets.push("description = $description");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('permission', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            sets.join(", ")
        );

        let db = self.db.current();
        let mut builder = db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(action) = input.action {
            builder = builder.bind(("action", action));
        }
        if let Some(description) = input.description {
            builder = builder.bind(("description", description));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| classify_write_error(e.to_string(), "permission"))?;

        let rows: Vec<PermissionRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "permission", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;

        Ok(Permission {
            id,
            tenant_id,
            action: row.action,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let id_str = id.to_string();

        // Delete associated grants edges first, then the permission record —
        // all inside one transaction so a concurrent reader never observes a
        // partially-deleted permission. The grants edge carries no flat
        // tenant_id column, so tenant scoping is expressed as a node-tenant
        // guard on the edge's `out` endpoint (out.tenant_id) — mirroring
        // role.delete. Without this guard a caller supplying a foreign-tenant
        // permission id could strip another tenant's grants edges. `.check()`
        // surfaces per-statement failures instead of swallowing them as Ok.
        // SEC-104 — see `helpers::delete_existence_guard`.
        let guard = crate::helpers::delete_existence_guard("permission");
        let query = format!(
            "BEGIN TRANSACTION; \
             {guard} \
             DELETE grants WHERE out = permission:`{id_str}` AND out.tenant_id = $tenant_id; \
             DELETE type::record('permission', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );

        let mut result = self
            .db
            .current()
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        crate::helpers::map_delete_errors(result.take_errors(), "permission", &id_str)?;

        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Permission>> {
        let tenant_id_str = tenant_id.to_string();

        // Free-text filter, applied to BOTH queries below so the
        // total counts matches rather than rows — a pager whose page
        // count belongs to a different result set than the page it
        // shows is worse than no pager. Empty when unsearched, so an
        // unfiltered list runs exactly the query it always ran.
        let search = search_filter(&pagination, &["action", "description"]);
        let search_term = search_bind(&pagination);

        let mut count_result = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM permission \
                 WHERE tenant_id = $tenant_id{search} GROUP ALL"
            ))
            .bind(("tenant_id", tenant_id_str.clone()))
            .bind(("search", search_term.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;

        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT meta::id(id) AS record_id, * FROM permission \
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

        let rows: Vec<PermissionRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_permission())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(paginate(items, count_rows, &pagination))
    }

    async fn grant_to_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> AxiamResult<()> {
        let role_id_str = role_id.to_string();
        let perm_id_str = permission_id.to_string();

        // CQ-B07: verify both endpoints belong to the same tenant before RELATE.
        let query = format!(
            "LET $ro = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             LET $pe = (SELECT id FROM permission:`{perm_id_str}` WHERE tenant_id = $tid);\
             IF array::len($ro) = 0 OR array::len($pe) = 0 {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             RELATE role:`{role_id_str}` -> grants -> \
             permission:`{perm_id_str}` SET scope_ids = NONE;"
        );

        let result = self
            .db
            .current()
            .query(query)
            .bind(("tid", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant edge denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant permission grant denied".into(),
                    action: None,
                    resource_id: None,
                });
            }
            return Err(classify_write_error(msg, "permission_grant").into());
        }

        Ok(())
    }

    async fn revoke_from_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> AxiamResult<()> {
        let role_id_str = role_id.to_string();
        let perm_id_str = permission_id.to_string();

        // CQ-B07: verify both endpoints belong to the same tenant before DELETE.
        let query = format!(
            "LET $ro = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             LET $pe = (SELECT id FROM permission:`{perm_id_str}` WHERE tenant_id = $tid);\
             IF array::len($ro) = 0 OR array::len($pe) = 0 {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             DELETE grants WHERE \
             in = role:`{role_id_str}` AND \
             out = permission:`{perm_id_str}`"
        );

        let result = self
            .db
            .current()
            .query(query)
            .bind(("tid", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant edge denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant permission revocation denied".into(),
                    action: None,
                    resource_id: None,
                });
            }
            return Err(DbError::Migration(msg).into());
        }

        Ok(())
    }

    async fn get_role_permissions(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Vec<Permission>> {
        let tenant_id_str = tenant_id.to_string();
        let role_id_str = role_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM permission \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE out FROM grants \
                     WHERE in = type::record('role', $role_id)\
                 )",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("role_id", role_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PermissionRowWithId> = result.take(0).map_err(DbError::from)?;

        let permissions = rows
            .into_iter()
            .map(|row| row.try_into_permission())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(permissions)
    }

    async fn grant_to_role_with_effect(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
        scope_ids: Vec<Uuid>,
        effect: PermissionEffect,
    ) -> AxiamResult<()> {
        self.relate_grant(tenant_id, role_id, permission_id, scope_ids, effect)
            .await
    }

    async fn grant_to_role_with_scopes(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
        scope_ids: Vec<Uuid>,
    ) -> AxiamResult<()> {
        // Pre-B1 entry point: an unqualified grant means allow, which is what
        // it has always meant.
        self.relate_grant(
            tenant_id,
            role_id,
            permission_id,
            scope_ids,
            PermissionEffect::Allow,
        )
        .await
    }

    async fn get_role_permission_grants(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> AxiamResult<Vec<PermissionGrant>> {
        let tenant_id_str = tenant_id.to_string();
        let role_id_str = role_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT \
                     meta::id(out.id) AS record_id, \
                     out.tenant_id AS tenant_id, \
                     out.action AS action, \
                     out.description AS description, \
                     out.created_at AS created_at, \
                     out.updated_at AS updated_at, \
                     scope_ids, \
                     effect \
                 FROM grants \
                 WHERE in = type::record('role', $role_id) \
                 AND out.tenant_id = $tenant_id",
            )
            .bind(("role_id", role_id_str))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PermissionGrantRow> = result.take(0).map_err(DbError::from)?;

        let grants = rows
            .into_iter()
            .map(|row| row.try_into_grant())
            .collect::<Result<Vec<_>, DbError>>()?
            .into_iter()
            .flatten()
            .collect();

        Ok(grants)
    }

    async fn get_role_permission_grants_for_roles(
        &self,
        tenant_id: Uuid,
        role_ids: &[Uuid],
    ) -> AxiamResult<HashMap<Uuid, Vec<PermissionGrant>>> {
        if role_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let tenant_id_str = tenant_id.to_string();

        // I7(a) — the predicate MUST compare the raw `in` field against record
        // ids, never `meta::id(in)`.
        //
        // Wrapping the indexed field in a function call makes the predicate
        // opaque to the planner: SurrealDB reports
        // `TableScan { pre_decode_filter: "no (unsupported predicate)" }` and
        // walks **every** `grants` edge in the database — i.e. every
        // role→permission grant of every tenant — on every authorization check.
        // Comparing `in` directly lets the `(in, out)` composite index
        // `idx_grants_unique` (schema v19) serve it as an `IndexScan`.
        // `crates/axiam-db/tests/authz_query_plan_test.rs` pins both plans.
        let role_records: Vec<RecordId> = role_ids
            .iter()
            .map(|id| RecordId::new("role", id.to_string()))
            .collect();

        // Batched mirror of get_role_permission_grants: one query for every
        // applicable role. `meta::id(in)` in the *projection* is fine (it is not
        // a filter) and yields the owning role's UUID so the flattened rows can
        // be regrouped per role. Tenant scoping is enforced on the permission
        // endpoint (out.tenant_id), identical to the single-role query.
        let mut result = self
            .db
            .current()
            .query(
                "SELECT \
                     meta::id(in) AS role_id, \
                     meta::id(out.id) AS record_id, \
                     out.tenant_id AS tenant_id, \
                     out.action AS action, \
                     out.description AS description, \
                     out.created_at AS created_at, \
                     out.updated_at AS updated_at, \
                     scope_ids, \
                     effect \
                 FROM grants \
                 WHERE in IN $role_records \
                 AND out.tenant_id = $tenant_id",
            )
            .bind(("role_records", role_records))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RolePermissionGrantRow> = result.take(0).map_err(DbError::from)?;

        let mut grouped: HashMap<Uuid, Vec<PermissionGrant>> = HashMap::new();
        for row in rows {
            // A dropped grant (SEC-092) contributes no entry at all, so a role
            // whose ONLY grant is malformed is absent from the map rather than
            // present-and-empty. The engine's `grants_by_role.get(role_id)`
            // miss and an empty Vec are already equivalent, so both spellings
            // reach the same decision.
            let Some((role_id, grant)) = row.try_into_role_grant()? else {
                continue;
            };
            grouped.entry(role_id).or_default().push(grant);
        }

        Ok(grouped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn row(effect: Option<&str>) -> PermissionGrantRow {
        PermissionGrantRow {
            record_id: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            action: "read".into(),
            description: "read".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope_ids: None,
            effect: effect.map(str::to_string),
        }
    }

    /// The backward-compatibility case: every grant edge written before B1 has
    /// no `effect` at all, and every one of them means allow.
    #[test]
    fn an_absent_effect_reads_back_as_allow() {
        let grant = row(None).try_into_grant().unwrap().expect("kept");
        assert_eq!(grant.effect, PermissionEffect::Allow);
    }

    #[test]
    fn the_two_valid_effects_round_trip() {
        assert_eq!(
            row(Some("allow")).try_into_grant().unwrap().unwrap().effect,
            PermissionEffect::Allow
        );
        assert_eq!(
            row(Some("deny")).try_into_grant().unwrap().unwrap().effect,
            PermissionEffect::Deny
        );
    }

    /// Casing and surrounding whitespace are *not* malformed — `from_wire`
    /// trims and lowercases. Pinned here so the SEC-092 drop below is not
    /// mistaken for strictness it does not have.
    #[test]
    fn casing_and_whitespace_still_parse() {
        for raw in ["DENY", "Deny", " deny ", "ALLOW"] {
            assert!(
                row(Some(raw)).try_into_grant().unwrap().is_some(),
                "effect {raw:?} is well-formed and must not be dropped"
            );
        }
    }

    /// **SEC-092.** An unrecognised effect drops the grant. It must be neither
    /// an allow (which would let an uninterpretable value read back as
    /// permission) nor a deny (which would let one malformed row mask the
    /// action for every holder of the role), and it must not be an error
    /// (which would take the whole authorization path down for the tenant).
    ///
    /// `"restrict"` stands in for the case worth planning for: a **third
    /// effect written by a newer node** during a rolling upgrade. Before
    /// SEC-092 every such grant read back as **allow** on the old node.
    #[test]
    fn an_unrecognised_effect_drops_the_grant() {
        for raw in ["restrict", "audit", "den", "", "true"] {
            let outcome = row(Some(raw)).try_into_grant().unwrap();
            assert!(
                outcome.is_none(),
                "effect {raw:?} must drop the grant, not resolve to an effect"
            );
        }
    }

    /// The batched shape drops the same rows, and drops them *without* losing
    /// the role id of the rows that survive — a bug here would silently empty a
    /// role that has perfectly good grants alongside a malformed one.
    #[test]
    fn the_batched_row_drops_malformed_grants_and_keeps_the_rest() {
        let role_id = Uuid::new_v4();
        let batched = |effect: Option<&str>| RolePermissionGrantRow {
            role_id: role_id.to_string(),
            record_id: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            action: "read".into(),
            description: "read".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            scope_ids: None,
            effect: effect.map(str::to_string),
        };

        assert!(
            batched(Some("nonsense"))
                .try_into_role_grant()
                .unwrap()
                .is_none()
        );

        let (kept_role, kept) = batched(Some("deny"))
            .try_into_role_grant()
            .unwrap()
            .expect("kept");
        assert_eq!(kept_role, role_id);
        assert_eq!(kept.effect, PermissionEffect::Deny);
    }
}

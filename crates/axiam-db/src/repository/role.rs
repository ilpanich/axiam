//! SurrealDB implementation of [`RoleRepository`].

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::role::{CreateRole, Role, RoleAssignment, UpdateRole};
use axiam_core::repository::{PaginatedResult, Pagination, RoleRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::helpers::{CountRow, classify_write_error, parse_uuid};

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
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
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
        })
    }
}

/// SurrealDB implementation of the Role repository.
#[derive(Clone)]
pub struct SurrealRoleRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealRoleRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }

    /// Look up a single role by name within a tenant (CQ-B42: replaces list()+scan pattern).
    pub async fn get_by_name(&self, tenant_id: Uuid, name: &str) -> AxiamResult<Option<Role>> {
        let tenant_str = tenant_id.to_string();
        let mut result = self
            .db
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
}

impl<C: Connection> RoleRepository for SurrealRoleRepository<C> {
    async fn create(&self, input: CreateRole) -> AxiamResult<Role> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let result = self
            .db
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
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.description.is_some() {
            sets.push("description = $description");
        }
        if input.is_global.is_some() {
            sets.push("is_global = $is_global");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('role', $id) SET {} \
             WHERE tenant_id = $tenant_id",
            sets.join(", ")
        );

        let mut builder = self
            .db
            .query(&query)
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(description) = input.description {
            builder = builder.bind(("description", description));
        }
        if let Some(is_global) = input.is_global {
            builder = builder.bind(("is_global", is_global));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

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

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
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
        // reader never observes a partially-deleted role.
        //
        // Result slots: BEGIN=0, DELETE has_role=1, DELETE grants=2,
        // DELETE role=3, COMMIT=4. delete() returns Ok(()) — no row data
        // to extract, .check() alone proves the transaction committed.
        let query = format!(
            "BEGIN TRANSACTION; \
             DELETE has_role WHERE out = role:`{id_str}` AND out.tenant_id = $tenant_id; \
             DELETE grants WHERE in = role:`{id_str}` AND in.tenant_id = $tenant_id; \
             DELETE type::record('role', $id) WHERE tenant_id = $tenant_id; \
             COMMIT TRANSACTION"
        );

        self.db
            .query(query)
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id_str))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(())
    }

    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Role>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM role \
                 WHERE tenant_id = $tenant_id GROUP ALL",
            )
            .bind(("tenant_id", tenant_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
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
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let user_id_str = user_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = resource_id.map(|r| r.to_string());

        // CQ-B07: verify both endpoints belong to the same tenant before RELATE.
        let query = format!(
            "LET $u = (SELECT id FROM user:`{user_id_str}` WHERE tenant_id = $tid);\
             LET $r = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             IF array::len($u) = 0 OR array::len($r) = 0 {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             RELATE user:`{user_id_str}` -> has_role -> role:`{role_id_str}` \
             SET resource_id = $resource_id;"
        );

        let result = self
            .db
            .query(query)
            .bind(("tid", tenant_id.to_string()))
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant edge denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant role assignment denied".into(),
                });
            }
            // QUAL-03/D-09: a duplicate has_role edge violates the
            // idx_has_role_unique UNIQUE(in,out) index — classify_write_error
            // routes that (and only that) to 409, not this generic Migration
            // fallback.
            return Err(classify_write_error(msg, "role_assignment").into());
        }

        Ok(())
    }

    async fn unassign_from_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let user_id_str = user_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = resource_id.map(|r| r.to_string());

        // CQ-B07: verify both endpoints belong to the same tenant before DELETE.
        let delete_clause = if resource_id_str.is_some() {
            format!(
                "DELETE has_role WHERE \
                 in = user:`{user_id_str}` AND \
                 out = role:`{role_id_str}` AND \
                 resource_id = $resource_id"
            )
        } else {
            format!(
                "DELETE has_role WHERE \
                 in = user:`{user_id_str}` AND \
                 out = role:`{role_id_str}` AND \
                 resource_id = NONE"
            )
        };

        let query = format!(
            "LET $u = (SELECT id FROM user:`{user_id_str}` WHERE tenant_id = $tid);\
             LET $r = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             IF array::len($u) = 0 OR array::len($r) = 0 {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             {delete_clause}"
        );

        let result = self
            .db
            .query(query)
            .bind(("tid", tenant_id.to_string()))
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant edge denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant role unassignment denied".into(),
                });
            }
            return Err(DbError::Migration(msg).into());
        }

        Ok(())
    }

    async fn get_user_roles(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Role>> {
        let tenant_id_str = tenant_id.to_string();
        let user_id_str = user_id.to_string();

        // Two queries: direct roles + roles inherited through group membership.
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE out FROM has_role \
                     WHERE in = type::record('user', $user_id)\
                 ); \
                 SELECT meta::id(id) AS record_id, * FROM role \
                 WHERE tenant_id = $tenant_id \
                 AND id IN (\
                     SELECT VALUE out FROM has_role \
                     WHERE in IN (\
                         SELECT VALUE out FROM member_of \
                         WHERE in = type::record('user', $user_id)\
                     )\
                 );",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("user_id", user_id_str))
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

    async fn get_user_role_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<RoleAssignment>> {
        let tenant_id_str = tenant_id.to_string();
        let user_id_str = user_id.to_string();

        // Query has_role edges (direct + via groups) and join with role data.
        // Each result row contains role fields + the resource_id from the edge.
        let mut result = self
            .db
            .query(
                "SELECT meta::id(out.id) AS record_id, \
                        out.tenant_id AS tenant_id, \
                        out.name AS name, \
                        out.description AS description, \
                        out.is_global AS is_global, \
                        out.created_at AS created_at, \
                        out.updated_at AS updated_at, \
                        resource_id \
                 FROM has_role \
                 WHERE in = type::record('user', $user_id) \
                 AND out.tenant_id = $tenant_id; \
                 SELECT meta::id(out.id) AS record_id, \
                        out.tenant_id AS tenant_id, \
                        out.name AS name, \
                        out.description AS description, \
                        out.is_global AS is_global, \
                        out.created_at AS created_at, \
                        out.updated_at AS updated_at, \
                        resource_id \
                 FROM has_role \
                 WHERE in IN (\
                     SELECT VALUE out FROM member_of \
                     WHERE in = type::record('user', $user_id)\
                 ) \
                 AND out.tenant_id = $tenant_id;",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("user_id", user_id_str))
            .await
            .map_err(DbError::from)?;

        let direct: Vec<RoleAssignmentRow> = result.take(0).map_err(DbError::from)?;
        let inherited: Vec<RoleAssignmentRow> = result.take(1).map_err(DbError::from)?;

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
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let group_id_str = group_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = resource_id.map(|r| r.to_string());

        // CQ-B07: verify both endpoints belong to the same tenant before RELATE.
        let query = format!(
            "LET $g = (SELECT id FROM group:`{group_id_str}` WHERE tenant_id = $tid);\
             LET $r = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             IF array::len($g) = 0 OR array::len($r) = 0 {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             RELATE group:`{group_id_str}` -> has_role -> role:`{role_id_str}` \
             SET resource_id = $resource_id;"
        );

        let result = self
            .db
            .query(query)
            .bind(("tid", tenant_id.to_string()))
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant edge denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant group role assignment denied".into(),
                });
            }
            // QUAL-03/D-09: a duplicate has_role edge violates the
            // idx_has_role_unique UNIQUE(in,out) index — classify_write_error
            // routes that (and only that) to 409, not this generic Migration
            // fallback.
            return Err(classify_write_error(msg, "role_assignment").into());
        }

        Ok(())
    }

    async fn unassign_from_group(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let group_id_str = group_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = resource_id.map(|r| r.to_string());

        // CQ-B07: verify both endpoints belong to the same tenant before DELETE.
        let delete_clause = if resource_id_str.is_some() {
            format!(
                "DELETE has_role WHERE \
                 in = group:`{group_id_str}` AND \
                 out = role:`{role_id_str}` AND \
                 resource_id = $resource_id"
            )
        } else {
            format!(
                "DELETE has_role WHERE \
                 in = group:`{group_id_str}` AND \
                 out = role:`{role_id_str}` AND \
                 resource_id = NONE"
            )
        };

        let query = format!(
            "LET $g = (SELECT id FROM group:`{group_id_str}` WHERE tenant_id = $tid);\
             LET $r = (SELECT id FROM role:`{role_id_str}` WHERE tenant_id = $tid);\
             IF array::len($g) = 0 OR array::len($r) = 0 {{\
                 THROW 'cross-tenant edge denied';\
             }};\
             {delete_clause}"
        );

        let result = self
            .db
            .query(query)
            .bind(("tid", tenant_id.to_string()))
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

        if let Err(e) = result.check() {
            let msg = e.to_string();
            if msg.contains("cross-tenant edge denied") {
                return Err(AxiamError::AuthorizationDenied {
                    reason: "cross-tenant group role unassignment denied".into(),
                });
            }
            return Err(DbError::Migration(msg).into());
        }

        Ok(())
    }

    async fn get_group_roles(&self, tenant_id: Uuid, group_id: Uuid) -> AxiamResult<Vec<Role>> {
        let tenant_id_str = tenant_id.to_string();
        let group_id_str = group_id.to_string();

        let mut result = self
            .db
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
}

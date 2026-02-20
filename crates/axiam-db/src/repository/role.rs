//! SurrealDB implementation of [`RoleRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::role::{CreateRole, Role, UpdateRole};
use axiam_core::repository::{PaginatedResult, Pagination, RoleRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

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
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
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

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
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

        // Delete associated edges first, then the role record.
        let query = format!(
            "DELETE has_role WHERE out = role:`{id_str}`; \
             DELETE grants WHERE in = role:`{id_str}`; \
             DELETE type::record('role', $id) WHERE tenant_id = $tenant_id;"
        );

        self.db
            .query(query)
            .bind(("id", id_str))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

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
        _tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let user_id_str = user_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = resource_id.map(|r| r.to_string());

        let query = format!(
            "RELATE user:`{user_id_str}` -> has_role -> role:`{role_id_str}` \
             SET resource_id = $resource_id;"
        );

        self.db
            .query(query)
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn unassign_from_user(
        &self,
        _tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let resource_id_str = resource_id.map(|r| r.to_string());

        // Match on resource_id: None means global, Some means scoped.
        let query = if resource_id_str.is_some() {
            "DELETE has_role WHERE \
             in = type::record('user', $user_id) AND \
             out = type::record('role', $role_id) AND \
             resource_id = $resource_id"
        } else {
            "DELETE has_role WHERE \
             in = type::record('user', $user_id) AND \
             out = type::record('role', $role_id) AND \
             resource_id = NONE"
        };

        self.db
            .query(query)
            .bind(("user_id", user_id.to_string()))
            .bind(("role_id", role_id.to_string()))
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

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

    async fn assign_to_group(
        &self,
        _tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let group_id_str = group_id.to_string();
        let role_id_str = role_id.to_string();
        let resource_id_str = resource_id.map(|r| r.to_string());

        let query = format!(
            "RELATE group:`{group_id_str}` -> has_role -> role:`{role_id_str}` \
             SET resource_id = $resource_id;"
        );

        self.db
            .query(query)
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn unassign_from_group(
        &self,
        _tenant_id: Uuid,
        group_id: Uuid,
        role_id: Uuid,
        resource_id: Option<Uuid>,
    ) -> AxiamResult<()> {
        let resource_id_str = resource_id.map(|r| r.to_string());

        let query = if resource_id_str.is_some() {
            "DELETE has_role WHERE \
             in = type::record('group', $group_id) AND \
             out = type::record('role', $role_id) AND \
             resource_id = $resource_id"
        } else {
            "DELETE has_role WHERE \
             in = type::record('group', $group_id) AND \
             out = type::record('role', $role_id) AND \
             resource_id = NONE"
        };

        self.db
            .query(query)
            .bind(("group_id", group_id.to_string()))
            .bind(("role_id", role_id.to_string()))
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

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
}

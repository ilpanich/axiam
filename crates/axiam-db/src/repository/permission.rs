//! SurrealDB implementation of [`PermissionRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::permission::{CreatePermission, Permission, UpdatePermission};
use axiam_core::repository::{PaginatedResult, Pagination, PermissionRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

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
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the Permission repository.
#[derive(Clone)]
pub struct SurrealPermissionRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealPermissionRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> PermissionRepository for SurrealPermissionRepository<C> {
    async fn create(&self, input: CreatePermission) -> AxiamResult<Permission> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();

        let result = self
            .db
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
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<PermissionRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "permission".into(),
            id: id_str,
        })?;

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
            .query(
                "SELECT * FROM type::record('permission', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PermissionRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "permission".into(),
            id: id_str,
        })?;

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

        let mut builder = self
            .db
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
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<PermissionRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "permission".into(),
            id: id_str,
        })?;

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

        // Delete associated grants edges first, then the permission record.
        let query = format!(
            "DELETE grants WHERE out = permission:`{id_str}`; \
             DELETE type::record('permission', $id) WHERE tenant_id = $tenant_id;"
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
    ) -> AxiamResult<PaginatedResult<Permission>> {
        let tenant_id_str = tenant_id.to_string();

        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM permission \
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
                "SELECT meta::id(id) AS record_id, * FROM permission \
                 WHERE tenant_id = $tenant_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PermissionRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_permission())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }

    async fn grant_to_role(
        &self,
        _tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> AxiamResult<()> {
        let role_id_str = role_id.to_string();
        let perm_id_str = permission_id.to_string();

        let query = format!("RELATE role:`{role_id_str}` -> grants -> permission:`{perm_id_str}`;");

        self.db.query(query).await.map_err(DbError::from)?;

        Ok(())
    }

    async fn revoke_from_role(
        &self,
        _tenant_id: Uuid,
        role_id: Uuid,
        permission_id: Uuid,
    ) -> AxiamResult<()> {
        self.db
            .query(
                "DELETE grants WHERE \
                 in = type::record('role', $role_id) AND \
                 out = type::record('permission', $perm_id)",
            )
            .bind(("role_id", role_id.to_string()))
            .bind(("perm_id", permission_id.to_string()))
            .await
            .map_err(DbError::from)?;

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
}

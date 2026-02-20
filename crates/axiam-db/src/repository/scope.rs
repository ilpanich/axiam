//! SurrealDB implementation of [`ScopeRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::scope::{CreateScope, Scope, UpdateScope};
use axiam_core::repository::ScopeRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

#[derive(Debug, SurrealValue)]
struct ScopeRow {
    tenant_id: String,
    resource_id: String,
    name: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct ScopeRowWithId {
    record_id: String,
    tenant_id: String,
    resource_id: String,
    name: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl ScopeRowWithId {
    fn try_into_scope(self) -> Result<Scope, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let resource_id = Uuid::parse_str(&self.resource_id)
            .map_err(|e| DbError::Migration(format!("invalid resource UUID: {e}")))?;
        Ok(Scope {
            id,
            tenant_id,
            resource_id,
            name: self.name,
            description: self.description,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// SurrealDB implementation of the Scope repository.
#[derive(Clone)]
pub struct SurrealScopeRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealScopeRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> ScopeRepository for SurrealScopeRepository<C> {
    async fn create(&self, input: CreateScope) -> AxiamResult<Scope> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let tenant_id_str = input.tenant_id.to_string();
        let resource_id_str = input.resource_id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('scope', $id) SET \
                 tenant_id = $tenant_id, \
                 resource_id = $resource_id, \
                 name = $name, description = $description",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id_str))
            .bind(("resource_id", resource_id_str))
            .bind(("name", input.name))
            .bind(("description", input.description))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ScopeRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "scope".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let resource_id = Uuid::parse_str(&row.resource_id)
            .map_err(|e| DbError::Migration(format!("invalid resource UUID: {e}")))?;

        Ok(Scope {
            id,
            tenant_id,
            resource_id,
            name: row.name,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Scope> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT * FROM type::record('scope', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ScopeRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "scope".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let resource_id = Uuid::parse_str(&row.resource_id)
            .map_err(|e| DbError::Migration(format!("invalid resource UUID: {e}")))?;

        Ok(Scope {
            id,
            tenant_id,
            resource_id,
            name: row.name,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn update(&self, tenant_id: Uuid, id: Uuid, input: UpdateScope) -> AxiamResult<Scope> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.description.is_some() {
            sets.push("description = $description");
        }
        sets.push("updated_at = time::now()");

        let query = format!(
            "UPDATE type::record('scope', $id) SET {} \
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

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ScopeRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "scope".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let resource_id = Uuid::parse_str(&row.resource_id)
            .map_err(|e| DbError::Migration(format!("invalid resource UUID: {e}")))?;

        Ok(Scope {
            id,
            tenant_id,
            resource_id,
            name: row.name,
            description: row.description,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "DELETE type::record('scope', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn list_by_resource(
        &self,
        tenant_id: Uuid,
        resource_id: Uuid,
    ) -> AxiamResult<Vec<Scope>> {
        let tenant_id_str = tenant_id.to_string();
        let resource_id_str = resource_id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM scope \
                 WHERE tenant_id = $tenant_id AND resource_id = $resource_id \
                 ORDER BY created_at ASC",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("resource_id", resource_id_str))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<ScopeRowWithId> = result.take(0).map_err(DbError::from)?;

        rows.into_iter()
            .map(|row| row.try_into_scope())
            .collect::<Result<Vec<_>, DbError>>()
            .map_err(Into::into)
    }
}

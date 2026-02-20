//! SurrealDB implementation of [`TenantRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::tenant::{CreateTenant, Tenant, UpdateTenant};
use axiam_core::repository::{PaginatedResult, Pagination, TenantRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

/// DB-side row struct for queries where the UUID is already known.
#[derive(Debug, SurrealValue)]
struct TenantRow {
    organization_id: String,
    name: String,
    slug: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TenantRow {
    fn into_tenant(self, id: Uuid) -> Result<Tenant, DbError> {
        let org_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(Tenant {
            id,
            organization_id: org_id,
            name: self.name,
            slug: self.slug,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// DB-side row struct that includes the record ID via `meta::id(id)`.
#[derive(Debug, SurrealValue)]
struct TenantRowWithId {
    record_id: String,
    organization_id: String,
    name: String,
    slug: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TenantRowWithId {
    fn try_into_tenant(self) -> Result<Tenant, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let org_id = Uuid::parse_str(&self.organization_id)
            .map_err(|e| DbError::Migration(format!("invalid org UUID: {e}")))?;
        Ok(Tenant {
            id,
            organization_id: org_id,
            name: self.name,
            slug: self.slug,
            metadata: self.metadata,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Row struct for count queries.
#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the Tenant repository.
#[derive(Clone)]
pub struct SurrealTenantRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealTenantRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> TenantRepository for SurrealTenantRepository<C> {
    async fn create(&self, input: CreateTenant) -> AxiamResult<Tenant> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();
        let org_id_str = input.organization_id.to_string();
        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        // Create tenant record and relate to organization in one query.
        // RELATE requires literal record-id syntax, so we embed UUIDs
        // directly in the RELATE portion (they are safe — UUID format).
        let query = format!(
            "CREATE type::record('tenant', $id) SET \
             organization_id = $org_id, \
             name = $name, slug = $slug, \
             metadata = $metadata; \
             RELATE organization:`{org_id_str}` \
             -> has_tenant -> tenant:`{id_str}`;"
        );

        let result = self
            .db
            .query(query)
            .bind(("id", id_str.clone()))
            .bind(("org_id", org_id_str))
            .bind(("name", input.name))
            .bind(("slug", input.slug))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        // Statement 0 is the CREATE, statement 1 is the RELATE.
        let rows: Vec<TenantRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "tenant".into(),
            id: id_str,
        })?;

        Ok(row.into_tenant(id)?)
    }

    async fn get_by_id(&self, id: Uuid) -> AxiamResult<Tenant> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .query("SELECT * FROM type::record('tenant', $id)")
            .bind(("id", id_str.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "tenant".into(),
            id: id_str,
        })?;

        Ok(row.into_tenant(id)?)
    }

    async fn get_by_slug(&self, organization_id: Uuid, slug: &str) -> AxiamResult<Tenant> {
        let org_id_str = organization_id.to_string();
        let slug_owned = slug.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM tenant \
                 WHERE organization_id = $org_id AND slug = $slug",
            )
            .bind(("org_id", org_id_str))
            .bind(("slug", slug_owned))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "tenant".into(),
            id: format!("org={organization_id},slug={slug}"),
        })?;

        Ok(row.try_into_tenant()?)
    }

    async fn update(&self, id: Uuid, input: UpdateTenant) -> AxiamResult<Tenant> {
        let id_str = id.to_string();

        let mut sets = Vec::new();
        if input.name.is_some() {
            sets.push("name = $name");
        }
        if input.slug.is_some() {
            sets.push("slug = $slug");
        }
        if input.metadata.is_some() {
            sets.push("metadata = $metadata");
        }
        sets.push("updated_at = time::now()");

        let query = format!("UPDATE type::record('tenant', $id) SET {}", sets.join(", "));

        let mut builder = self.db.query(&query).bind(("id", id_str.clone()));

        if let Some(name) = input.name {
            builder = builder.bind(("name", name));
        }
        if let Some(slug) = input.slug {
            builder = builder.bind(("slug", slug));
        }
        if let Some(metadata) = input.metadata {
            builder = builder.bind(("metadata", metadata));
        }

        let result = builder.await.map_err(DbError::from)?;
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TenantRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "tenant".into(),
            id: id_str,
        })?;

        Ok(row.into_tenant(id)?)
    }

    async fn delete(&self, id: Uuid) -> AxiamResult<()> {
        self.db
            .query("DELETE type::record('tenant', $id)")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn list_by_organization(
        &self,
        organization_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<Tenant>> {
        let org_id_str = organization_id.to_string();

        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM tenant \
                 WHERE organization_id = $org_id GROUP ALL",
            )
            .bind(("org_id", org_id_str.clone()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM tenant \
                 WHERE organization_id = $org_id \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("org_id", org_id_str))
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TenantRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_tenant())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }
}

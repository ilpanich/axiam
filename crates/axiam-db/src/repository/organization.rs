//! SurrealDB implementation of [`OrganizationRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::organization::{CreateOrganization, Organization, UpdateOrganization};
use axiam_core::repository::{OrganizationRepository, PaginatedResult, Pagination};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

/// DB-side row struct for queries where the UUID is already known.
#[derive(Debug, SurrealValue)]
struct OrganizationRow {
    name: String,
    slug: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

/// DB-side row struct that includes the record ID via `meta::id(id)`.
#[derive(Debug, SurrealValue)]
struct OrganizationRowWithId {
    record_id: String,
    name: String,
    slug: String,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl OrganizationRowWithId {
    fn try_into_organization(self) -> Result<Organization, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        Ok(Organization {
            id,
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

/// SurrealDB implementation of the Organization repository.
#[derive(Clone)]
pub struct SurrealOrganizationRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealOrganizationRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> OrganizationRepository for SurrealOrganizationRepository<C> {
    async fn create(&self, input: CreateOrganization) -> AxiamResult<Organization> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let metadata = input
            .metadata
            .unwrap_or(serde_json::Value::Object(Default::default()));

        let result = self
            .db
            .query(
                "CREATE type::record('organization', $id) SET \
                 name = $name, slug = $slug, metadata = $metadata",
            )
            .bind(("id", id_str.clone()))
            .bind(("name", input.name))
            .bind(("slug", input.slug))
            .bind(("metadata", metadata))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<OrganizationRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "organization".into(),
            id: id_str,
        })?;

        Ok(Organization {
            id,
            name: row.name,
            slug: row.slug,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_id(&self, id: Uuid) -> AxiamResult<Organization> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .query("SELECT * FROM type::record('organization', $id)")
            .bind(("id", id_str.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OrganizationRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "organization".into(),
            id: id_str,
        })?;

        Ok(Organization {
            id,
            name: row.name,
            slug: row.slug,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn get_by_slug(&self, slug: &str) -> AxiamResult<Organization> {
        let slug_owned = slug.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM organization WHERE slug = $slug",
            )
            .bind(("slug", slug_owned))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OrganizationRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "organization".into(),
            id: format!("slug={slug}"),
        })?;

        Ok(row.try_into_organization()?)
    }

    async fn update(&self, id: Uuid, input: UpdateOrganization) -> AxiamResult<Organization> {
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

        let query = format!(
            "UPDATE type::record('organization', $id) SET {}",
            sets.join(", ")
        );

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

        let rows: Vec<OrganizationRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "organization".into(),
            id: id_str,
        })?;

        Ok(Organization {
            id,
            name: row.name,
            slug: row.slug,
            metadata: row.metadata,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }

    async fn delete(&self, id: Uuid) -> AxiamResult<()> {
        self.db
            .query("DELETE type::record('organization', $id)")
            .bind(("id", id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn list(&self, pagination: Pagination) -> AxiamResult<PaginatedResult<Organization>> {
        let mut count_result = self
            .db
            .query("SELECT count() AS total FROM organization GROUP ALL")
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM organization \
                 ORDER BY created_at ASC \
                 LIMIT $limit START $offset",
            )
            .bind(("limit", pagination.limit))
            .bind(("offset", pagination.offset))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<OrganizationRowWithId> = result.take(0).map_err(DbError::from)?;

        let items = rows
            .into_iter()
            .map(|row| row.try_into_organization())
            .collect::<Result<Vec<_>, DbError>>()?;

        Ok(PaginatedResult {
            items,
            total,
            offset: pagination.offset,
            limit: pagination.limit,
        })
    }
}

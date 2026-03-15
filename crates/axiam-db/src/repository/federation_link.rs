//! SurrealDB implementation of [`FederationLinkRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::federation::{CreateFederationLink, FederationLink};
use axiam_core::repository::FederationLinkRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct FederationLinkRow {
    tenant_id: String,
    user_id: String,
    federation_config_id: String,
    external_subject: String,
    external_email: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct FederationLinkRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    federation_config_id: String,
    external_subject: String,
    external_email: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Row -> Domain conversions
// ---------------------------------------------------------------------------

fn parse_uuid(s: &str) -> Result<Uuid, DbError> {
    Uuid::parse_str(s).map_err(|e| DbError::Migration(e.to_string()))
}

impl FederationLinkRow {
    fn try_into_entry(self, id: Uuid) -> Result<FederationLink, DbError> {
        Ok(FederationLink {
            id,
            tenant_id: parse_uuid(&self.tenant_id)?,
            user_id: parse_uuid(&self.user_id)?,
            federation_config_id: parse_uuid(&self.federation_config_id)?,
            external_subject: self.external_subject,
            external_email: self.external_email,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

impl FederationLinkRowWithId {
    fn try_into_entry(self) -> Result<FederationLink, DbError> {
        let id = parse_uuid(&self.record_id)?;
        Ok(FederationLink {
            id,
            tenant_id: parse_uuid(&self.tenant_id)?,
            user_id: parse_uuid(&self.user_id)?,
            federation_config_id: parse_uuid(&self.federation_config_id)?,
            external_subject: self.external_subject,
            external_email: self.external_email,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealFederationLinkRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealFederationLinkRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealFederationLinkRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> FederationLinkRepository for SurrealFederationLinkRepository<C> {
    async fn create(&self, input: CreateFederationLink) -> AxiamResult<FederationLink> {
        let id = Uuid::new_v4();

        let result = self
            .db
            .query(
                "CREATE type::record('federation_link', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 federation_config_id = $federation_config_id, \
                 external_subject = $external_subject, \
                 external_email = $external_email, \
                 created_at = time::now(), \
                 updated_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind((
                "federation_config_id",
                input.federation_config_id.to_string(),
            ))
            .bind(("external_subject", input.external_subject))
            .bind(("external_email", input.external_email))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationLinkRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "federation_link".into(),
            id: id.to_string(),
        })?;
        row.try_into_entry(id).map_err(Into::into)
    }

    async fn get_by_external_subject(
        &self,
        tenant_id: Uuid,
        federation_config_id: Uuid,
        external_subject: &str,
    ) -> AxiamResult<FederationLink> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM federation_link \
                 WHERE tenant_id = $tenant_id \
                 AND federation_config_id = $federation_config_id \
                 AND external_subject = $external_subject",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("federation_config_id", federation_config_id.to_string()))
            .bind(("external_subject", external_subject.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationLinkRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "federation_link".into(),
            id: format!(
                "subject={external_subject} \
                         config={federation_config_id}"
            ),
        })?;
        row.try_into_entry().map_err(Into::into)
    }

    async fn get_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<FederationLink>> {
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM federation_link \
                 WHERE tenant_id = $tenant_id \
                 AND user_id = $user_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationLinkRowWithId> = result.take(0).map_err(DbError::from)?;

        rows.into_iter()
            .map(|r| r.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .query(
                "DELETE type::record('federation_link', $id) \
                 WHERE tenant_id = $tenant_id RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<FederationLinkRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "federation_link".into(),
                id: id.to_string(),
            }
            .into());
        }
        Ok(())
    }
}

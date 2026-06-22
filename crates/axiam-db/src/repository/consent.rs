//! SurrealDB implementation of [`ConsentRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::gdpr::{Consent, CreateConsent};
use axiam_core::repository::ConsentRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct ConsentRow {
    tenant_id: String,
    user_id: String,
    consent_type: String,
    version: String,
    accepted_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

#[derive(Debug, SurrealValue)]
struct ConsentRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    consent_type: String,
    version: String,
    accepted_at: DateTime<Utc>,
    ip_address: Option<String>,
    user_agent: Option<String>,
}

impl ConsentRowWithId {
    fn try_into_domain(self) -> Result<Consent, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(Consent {
            id,
            tenant_id,
            user_id,
            consent_type: self.consent_type,
            version: self.version,
            accepted_at: self.accepted_at,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealConsentRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealConsentRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealConsentRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> ConsentRepository for SurrealConsentRepository<C> {
    async fn create(&self, input: CreateConsent) -> AxiamResult<Consent> {
        let id = Uuid::new_v4();
        let result = self
            .db
            .query(
                "CREATE type::record('consent', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 consent_type = $consent_type, \
                 version = $version, \
                 accepted_at = time::now(), \
                 ip_address = $ip_address, \
                 user_agent = $user_agent",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("consent_type", input.consent_type))
            .bind(("version", input.version))
            .bind(("ip_address", input.ip_address))
            .bind(("user_agent", input.user_agent))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<ConsentRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "consent".into(),
            id: id.to_string(),
        })?;

        // Build domain object from row + known id.
        Ok(Consent {
            id,
            tenant_id: input.tenant_id,
            user_id: input.user_id,
            consent_type: row.consent_type,
            version: row.version,
            accepted_at: row.accepted_at,
            ip_address: row.ip_address,
            user_agent: row.user_agent,
        })
    }

    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Consent>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM consent \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 ORDER BY accepted_at ASC",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<ConsentRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn consent_round_trip() {
        let db = setup_db().await;
        let repo = SurrealConsentRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let consent = repo
            .create(CreateConsent {
                tenant_id,
                user_id,
                consent_type: "terms_of_service".into(),
                version: "2026-01-01".into(),
                ip_address: Some("127.0.0.1".into()),
                user_agent: None,
            })
            .await
            .unwrap();

        assert_eq!(consent.consent_type, "terms_of_service");
        assert_eq!(consent.tenant_id, tenant_id);

        let list = repo.list_by_user(tenant_id, user_id).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].version, "2026-01-01");
    }
}

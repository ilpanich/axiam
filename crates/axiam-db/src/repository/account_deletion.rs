//! SurrealDB implementation of [`AccountDeletionRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::gdpr::{AccountDeletion, AccountDeletionStatus, CreateAccountDeletion};
use axiam_core::repository::AccountDeletionRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct AccountDeletionRow {
    tenant_id: String,
    user_id: String,
    cancel_token_hash: String,
    scheduled_purge_at: DateTime<Utc>,
    status: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct AccountDeletionRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    cancel_token_hash: String,
    scheduled_purge_at: DateTime<Utc>,
    status: String,
    created_at: DateTime<Utc>,
}

fn parse_status(s: &str) -> Result<AccountDeletionStatus, DbError> {
    match s {
        "pending" => Ok(AccountDeletionStatus::Pending),
        "cancelled" => Ok(AccountDeletionStatus::Cancelled),
        "completed" => Ok(AccountDeletionStatus::Completed),
        other => Err(DbError::Migration(format!(
            "unknown account_deletion status: {other}"
        ))),
    }
}

impl AccountDeletionRowWithId {
    fn try_into_domain(self) -> Result<AccountDeletion, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(AccountDeletion {
            id,
            tenant_id,
            user_id,
            cancel_token_hash: self.cancel_token_hash,
            scheduled_purge_at: self.scheduled_purge_at,
            status: parse_status(&self.status)?,
            created_at: self.created_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

pub struct SurrealAccountDeletionRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealAccountDeletionRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealAccountDeletionRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }

    /// Find a pending deletion request by user_id within a tenant.
    ///
    /// Used by the purge sweep to mark the deletion row as completed once
    /// the purge pipeline finishes.
    pub async fn find_pending_by_user_id(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Option<AccountDeletion>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM account_deletion \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id AND status = 'pending'",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AccountDeletionRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .transpose()
    }

    /// Look up a pending deletion by token hash without requiring tenant_id.
    ///
    /// Used by the public cancel endpoint where the caller is not authenticated
    /// and the tenant_id is not in the request context (D-09).  The token hash
    /// uniqueness enforced by the UNIQUE index makes cross-tenant collision
    /// practically impossible.
    pub async fn find_by_token_hash_global(
        &self,
        cancel_token_hash: &str,
    ) -> AxiamResult<Option<AccountDeletion>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM account_deletion \
                 WHERE cancel_token_hash = $hash",
            )
            .bind(("hash", cancel_token_hash.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AccountDeletionRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .transpose()
    }
}

impl<C: Connection> AccountDeletionRepository for SurrealAccountDeletionRepository<C> {
    async fn create(&self, input: CreateAccountDeletion) -> AxiamResult<AccountDeletion> {
        let id = Uuid::new_v4();
        let result = self
            .db
            .query(
                "CREATE type::record('account_deletion', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 cancel_token_hash = $cancel_token_hash, \
                 scheduled_purge_at = $scheduled_purge_at, \
                 status = 'pending', \
                 created_at = time::now()",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("cancel_token_hash", input.cancel_token_hash))
            .bind(("scheduled_purge_at", input.scheduled_purge_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<AccountDeletionRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "account_deletion".into(),
            id: id.to_string(),
        })?;

        Ok(AccountDeletion {
            id,
            tenant_id: input.tenant_id,
            user_id: input.user_id,
            cancel_token_hash: row.cancel_token_hash,
            scheduled_purge_at: row.scheduled_purge_at,
            status: parse_status(&row.status)?,
            created_at: row.created_at,
        })
    }

    async fn find_by_token_hash(
        &self,
        tenant_id: Uuid,
        cancel_token_hash: &str,
    ) -> AxiamResult<Option<AccountDeletion>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM account_deletion \
                 WHERE tenant_id = $tenant_id AND cancel_token_hash = $hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", cancel_token_hash.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AccountDeletionRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(|r| r.try_into_domain().map_err(Into::into))
            .transpose()
    }

    async fn mark_cancelled(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "UPDATE type::record('account_deletion', $id) SET \
                 status = 'cancelled' \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn mark_completed(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "UPDATE type::record('account_deletion', $id) SET \
                 status = 'completed' \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn account_deletion_round_trip() {
        let db = setup_db().await;
        let repo = SurrealAccountDeletionRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let purge_at = Utc::now() + Duration::days(30);

        let req = repo
            .create(CreateAccountDeletion {
                tenant_id,
                user_id,
                cancel_token_hash: "sha256-of-token".into(),
                scheduled_purge_at: purge_at,
            })
            .await
            .unwrap();

        assert_eq!(req.status, AccountDeletionStatus::Pending);
        // Stores hash, not raw token
        assert_eq!(req.cancel_token_hash, "sha256-of-token");

        let found = repo
            .find_by_token_hash(tenant_id, "sha256-of-token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, req.id);

        repo.mark_cancelled(tenant_id, req.id).await.unwrap();
        let found2 = repo
            .find_by_token_hash(tenant_id, "sha256-of-token")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found2.status, AccountDeletionStatus::Cancelled);
    }
}

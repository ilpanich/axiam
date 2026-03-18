//! SurrealDB implementation of [`PasswordHistoryRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::password_history::{CreatePasswordHistoryEntry, PasswordHistoryEntry};
use axiam_core::repository::PasswordHistoryRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// -----------------------------------------------------------------------
// Row structs
// -----------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct PasswordHistoryRow {
    tenant_id: String,
    user_id: String,
    password_hash: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct PasswordHistoryRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    password_hash: String,
    created_at: DateTime<Utc>,
}

impl PasswordHistoryRowWithId {
    fn into_entry(self) -> Result<PasswordHistoryEntry, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;

        Ok(PasswordHistoryEntry {
            id,
            tenant_id,
            user_id,
            password_hash: self.password_hash,
            created_at: self.created_at,
        })
    }
}

// -----------------------------------------------------------------------
// Repository
// -----------------------------------------------------------------------

#[derive(Clone)]
pub struct SurrealPasswordHistoryRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealPasswordHistoryRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> PasswordHistoryRepository for SurrealPasswordHistoryRepository<C> {
    async fn create(&self, input: CreatePasswordHistoryEntry) -> AxiamResult<PasswordHistoryEntry> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('password_history', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 password_hash = $password_hash",
            )
            .bind(("id", id_str))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("password_hash", input.password_hash.clone()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<PasswordHistoryRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "password_history".into(),
            id: id.to_string(),
        })?;

        Ok(PasswordHistoryEntry {
            id,
            tenant_id: input.tenant_id,
            user_id: input.user_id,
            password_hash: row.password_hash,
            created_at: row.created_at,
        })
    }

    async fn get_recent(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        count: u32,
    ) -> AxiamResult<Vec<PasswordHistoryEntry>> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM password_history \
                 WHERE tenant_id = $tenant_id \
                 AND user_id = $user_id \
                 ORDER BY created_at DESC \
                 LIMIT $limit",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("limit", count))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<PasswordHistoryRowWithId> = result.take(0).map_err(DbError::from)?;

        rows.into_iter()
            .map(|r| r.into_entry().map_err(Into::into))
            .collect()
    }

    async fn prune(&self, tenant_id: Uuid, user_id: Uuid, keep_count: u32) -> AxiamResult<u64> {
        let tid = tenant_id.to_string();
        let uid = user_id.to_string();

        // When keep_count is 0, delete all entries for this user.
        if keep_count == 0 {
            let mut result = self
                .db
                .query(
                    "DELETE password_history \
                     WHERE tenant_id = $tenant_id \
                     AND user_id = $user_id \
                     RETURN BEFORE",
                )
                .bind(("tenant_id", tid))
                .bind(("user_id", uid))
                .await
                .map_err(DbError::from)?;

            let deleted: Vec<PasswordHistoryRow> =
                result.take(0).map_err(DbError::from)?;
            return Ok(deleted.len() as u64);
        }

        // Get the IDs to keep (most recent N).
        #[derive(Debug, SurrealValue)]
        struct IdRow {
            record_id: String,
        }

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id \
                 FROM password_history \
                 WHERE tenant_id = $tenant_id \
                 AND user_id = $user_id \
                 ORDER BY created_at DESC \
                 LIMIT $limit",
            )
            .bind(("tenant_id", tid.clone()))
            .bind(("user_id", uid.clone()))
            .bind(("limit", keep_count))
            .await
            .map_err(DbError::from)?;

        let keep_rows: Vec<IdRow> = result.take(0).map_err(DbError::from)?;

        if keep_rows.is_empty() {
            return Ok(0);
        }

        // Build a list of record IDs to keep as backtick-quoted refs.
        let keep_ids: Vec<String> = keep_rows
            .iter()
            .map(|r| format!("password_history:`{}`", r.record_id))
            .collect();
        let keep_list = keep_ids.join(", ");

        // Delete all entries for this user that are NOT in the keep set.
        let delete_query = format!(
            "DELETE password_history \
             WHERE tenant_id = $tenant_id \
             AND user_id = $user_id \
             AND id NOT IN [{}] \
             RETURN BEFORE",
            keep_list,
        );

        let mut result = self
            .db
            .query(&delete_query)
            .bind(("tenant_id", tid))
            .bind(("user_id", uid))
            .await
            .map_err(DbError::from)?;

        let deleted: Vec<PasswordHistoryRow> =
            result.take(0).map_err(DbError::from)?;
        Ok(deleted.len() as u64)
    }
}

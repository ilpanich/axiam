//! SurrealDB implementation of [`PasswordResetTokenRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::password_reset::{CreatePasswordResetToken, PasswordResetToken};
use axiam_core::repository::PasswordResetTokenRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, retry_hot_row, take_first_or_not_found};
use crate::repository::mail_cap;

#[derive(Debug, SurrealValue)]
struct TokenRow {
    tenant_id: String,
    user_id: String,
    token_hash: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct TokenRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    token_hash: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl TokenRow {
    fn into_token(self, id: Uuid) -> Result<PasswordResetToken, DbError> {
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(PasswordResetToken {
            id,
            tenant_id,
            user_id,
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            consumed_at: self.consumed_at,
            created_at: self.created_at,
        })
    }
}

impl TokenRowWithId {
    fn try_into_token(self) -> Result<PasswordResetToken, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(PasswordResetToken {
            id,
            tenant_id,
            user_id,
            token_hash: self.token_hash,
            expires_at: self.expires_at,
            consumed_at: self.consumed_at,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the password reset token repository.
pub struct SurrealPasswordResetTokenRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealPasswordResetTokenRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealPasswordResetTokenRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> PasswordResetTokenRepository for SurrealPasswordResetTokenRepository<C> {
    async fn create(&self, input: CreatePasswordResetToken) -> AxiamResult<PasswordResetToken> {
        let id = new_id();
        let id_str = id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('password_reset_token', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 token_hash = $token_hash, \
                 expires_at = $expires_at, \
                 consumed_at = NONE",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("token_hash", input.token_hash))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "password_reset_token", &id_str)?;

        Ok(row.into_token(id)?)
    }

    async fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<PasswordResetToken> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM password_reset_token \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND consumed_at IS NONE \
                   AND expires_at > time::now()",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("token_hash", token_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "password_reset_token",
            &format!("token_hash={token_hash}"),
        )?;

        Ok(row.try_into_token()?)
    }

    async fn consume(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<PasswordResetToken> {
        let result = self
            .db
            .current()
            .query(
                "UPDATE password_reset_token SET \
                 consumed_at = time::now() \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND consumed_at IS NONE \
                   AND expires_at > time::now(); \
                 SELECT meta::id(id) AS record_id, * \
                 FROM password_reset_token \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND consumed_at IS NOT NONE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("token_hash", token_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        // Statement 0 is the UPDATE — if no rows were affected, the
        // token was already consumed, invalidated, or expired.
        let updated: Vec<TokenRow> = result.take(0).map_err(DbError::from)?;
        if updated.is_empty() {
            return Err(DbError::NotFound {
                entity: "password_reset_token".into(),
                id: format!("token_hash={token_hash}"),
            }
            .into());
        }

        // Statement 1 is the SELECT with full record_id.
        let rows: Vec<TokenRowWithId> = result.take(1).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "password_reset_token",
            &format!("token_hash={token_hash}"),
        )?;

        Ok(row.try_into_token()?)
    }

    async fn count_today(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        let today_start = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("midnight is always valid")
            .and_utc();

        let result = self
            .db
            .current()
            .query(
                "SELECT count() AS total \
                 FROM password_reset_token \
                 WHERE tenant_id = $tenant_id \
                   AND user_id = $user_id \
                   AND created_at >= $today_start \
                 GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("today_start", today_start))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn delete_expired(&self) -> AxiamResult<u64> {
        // A token minted since UTC midnight is kept, dead or alive, until the
        // day is over: the daily cap counts the account's tokens minted today
        // (`count_today`, and the capped mint's own count in `mail_cap`), so
        // deleting a consumed or expired one lowered the count and handed the
        // account its cap again within the same day. What is kept is a hash
        // that no longer redeems anything, for at most a day — and the account's
        // own erasure still deletes it.
        let result = self
            .db
            .current()
            .query(
                "DELETE FROM password_reset_token \
                 WHERE (expires_at < time::now() OR consumed_at IS NOT NONE) \
                    AND created_at < $day_start \
                 RETURN BEFORE",
            )
            .bind(("day_start", crate::repository::mail_cap::day_start()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }

    async fn delete_unconsumed_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        // Mark unconsumed tokens as consumed (invalidated) rather than
        // deleting them so that count_today() still sees them for
        // rate-limit enforcement.
        let result = self
            .db
            .current()
            .query(
                "UPDATE password_reset_token \
                 SET consumed_at = time::now() \
                 WHERE tenant_id = $tenant_id \
                   AND user_id = $user_id \
                   AND consumed_at IS NONE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        let rows: Vec<TokenRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }

    /// Item 7 of the 1.1.0 atomicity audit — the cap, the invalidation of the
    /// earlier links and the new token in one transaction that claims the
    /// user row (`mail_cap`). Of N requests sent together at most the cap's
    /// remainder mint, and each one's invalidation sees the tokens the
    /// earlier winners minted, so exactly one link is live afterwards.
    async fn replace_within_daily_cap(
        &self,
        input: CreatePasswordResetToken,
        daily_cap: u64,
    ) -> AxiamResult<Option<PasswordResetToken>> {
        let id = new_id();
        let id_str = id.to_string();
        let user_id_str = input.user_id.to_string();
        let query = format!(
            "BEGIN TRANSACTION; {claim}\
             UPDATE password_reset_token SET consumed_at = time::now() \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 AND consumed_at IS NONE; \
             CREATE type::record('password_reset_token', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 token_hash = $token_hash, \
                 expires_at = $expires_at, \
                 consumed_at = NONE; \
             COMMIT TRANSACTION",
            claim = mail_cap::claim("password_reset_token"),
        );
        // Result slots: BEGIN, the claim's, the invalidation, the CREATE.
        let create_slot = 1 + mail_cap::CLAIM_SLOTS + 1;
        let daily_cap = i64::try_from(daily_cap).unwrap_or(i64::MAX);
        let day_start = mail_cap::day_start();

        let rows = retry_hot_row(|| async {
            let mut result = self
                .db
                .current()
                .query(query.as_str())
                .bind(("id", id_str.clone()))
                .bind(("tenant_id", input.tenant_id.to_string()))
                .bind(("user_id", user_id_str.clone()))
                .bind(("token_hash", input.token_hash.clone()))
                .bind(("expires_at", input.expires_at))
                .bind(("day_start", day_start))
                .bind(("daily_cap", daily_cap))
                .await
                .map_err(DbError::from)?;
            if mail_cap::outcome(result.take_errors(), "password_reset_token", &user_id_str)? {
                return Ok(None);
            }
            let rows: Vec<TokenRow> = result.take(create_slot).map_err(DbError::from)?;
            Ok(Some(rows))
        })
        .await?;
        let Some(rows) = rows else {
            return Ok(None);
        };
        let row = take_first_or_not_found(rows, "password_reset_token", &id_str)?;
        Ok(Some(row.into_token(id)?))
    }
}

//! SurrealDB implementation of [`EmailVerificationTokenRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::email_verification::{
    CreateEmailVerificationToken, EmailVerificationToken,
};
use axiam_core::repository::EmailVerificationTokenRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

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

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

impl TokenRow {
    fn into_token(self, id: Uuid) -> Result<EmailVerificationToken, DbError> {
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(EmailVerificationToken {
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
    fn try_into_token(self) -> Result<EmailVerificationToken, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(EmailVerificationToken {
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

/// SurrealDB implementation of the email verification token repository.
pub struct SurrealEmailVerificationTokenRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> Clone for SurrealEmailVerificationTokenRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealEmailVerificationTokenRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> EmailVerificationTokenRepository
    for SurrealEmailVerificationTokenRepository<C>
{
    async fn create(
        &self,
        input: CreateEmailVerificationToken,
    ) -> AxiamResult<EmailVerificationToken> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('email_verification_token', $id) SET \
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
        let row =
            rows.into_iter().next().ok_or_else(|| DbError::NotFound {
                entity: "email_verification_token".into(),
                id: id_str,
            })?;

        Ok(row.into_token(id)?)
    }

    async fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<EmailVerificationToken> {
        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM email_verification_token \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND consumed_at IS NONE \
                   AND expires_at > time::now()",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("token_hash", token_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TokenRowWithId> =
            result.take(0).map_err(DbError::from)?;
        let row =
            rows.into_iter().next().ok_or_else(|| DbError::NotFound {
                entity: "email_verification_token".into(),
                id: format!("token_hash={token_hash}"),
            })?;

        Ok(row.try_into_token()?)
    }

    async fn consume(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<EmailVerificationToken> {
        // Use a single UPDATE + SELECT meta::id pattern to atomically
        // consume and return the full record with its ID.
        let mut result = self
            .db
            .query(
                "UPDATE email_verification_token SET \
                 consumed_at = time::now() \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND consumed_at IS NONE \
                   AND expires_at > time::now(); \
                 SELECT meta::id(id) AS record_id, * \
                 FROM email_verification_token \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND consumed_at IS NOT NONE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("token_hash", token_hash.to_string()))
            .await
            .map_err(DbError::from)?;

        // Statement 0 is the UPDATE; statement 1 is the SELECT.
        let rows: Vec<TokenRowWithId> =
            result.take(1).map_err(DbError::from)?;
        let row =
            rows.into_iter().next().ok_or_else(|| DbError::NotFound {
                entity: "email_verification_token".into(),
                id: format!("token_hash={token_hash}"),
            })?;

        Ok(row.try_into_token()?)
    }

    async fn count_today(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<u64> {
        let today_start = Utc::now()
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("midnight is always valid")
            .and_utc();

        let mut result = self
            .db
            .query(
                "SELECT count() AS total \
                 FROM email_verification_token \
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

        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn delete_expired(&self) -> AxiamResult<u64> {
        let mut result = self
            .db
            .query(
                "DELETE FROM email_verification_token \
                 WHERE expires_at < time::now() \
                    OR consumed_at IS NOT NONE \
                 RETURN BEFORE",
            )
            .await
            .map_err(DbError::from)?;

        let rows: Vec<TokenRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }
}

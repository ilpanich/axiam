//! SurrealDB implementation of [`RefreshTokenRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_client::{CreateRefreshToken, RefreshToken};
use axiam_core::repository::RefreshTokenRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;

/// Parse an optional stored session id.
///
/// Absent and empty both mean "no session": SurrealDB writes `NONE` as absent,
/// and a row migrated from the pre-v28 shape can carry `""`. Treating that as a
/// parse failure would make an old refresh token unreadable rather than merely
/// session-less.
fn parse_opt_session(raw: Option<&str>) -> Result<Option<Uuid>, DbError> {
    match raw {
        None | Some("") => Ok(None),
        Some(v) => Uuid::parse_str(v)
            .map(Some)
            .map_err(|e| DbError::Migration(format!("invalid session UUID: {e}"))),
    }
}
use crate::helpers::{CountRow, take_first_or_not_found};

#[derive(Debug, SurrealValue)]
struct RefreshTokenRow {
    tenant_id: String,
    token_hash: String,
    client_id: String,
    user_id: Option<String>,
    scopes: Vec<String>,
    #[surreal(default)]
    session_id: Option<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct RefreshTokenRowWithId {
    record_id: String,
    tenant_id: String,
    token_hash: String,
    client_id: String,
    user_id: Option<String>,
    scopes: Vec<String>,
    #[surreal(default)]
    session_id: Option<String>,
    expires_at: DateTime<Utc>,
    revoked: bool,
    created_at: DateTime<Utc>,
}

impl RefreshTokenRowWithId {
    fn try_into_refresh_token(self) -> Result<RefreshToken, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = self
            .user_id
            .map(|uid| {
                Uuid::parse_str(&uid)
                    .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))
            })
            .transpose()?;

        Ok(RefreshToken {
            id,
            tenant_id,
            token_hash: self.token_hash,
            client_id: self.client_id,
            user_id,
            scopes: self.scopes,
            session_id: parse_opt_session(self.session_id.as_deref())?,
            expires_at: self.expires_at,
            revoked: self.revoked,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the RefreshToken repository.
pub struct SurrealRefreshTokenRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone impl (not derive): avoids the spurious `C: Clone` bound that
// blocks cloning under generic `C: Connection` callers. Matches SurrealUserRepository.
impl<C: Connection> Clone for SurrealRefreshTokenRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealRefreshTokenRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> RefreshTokenRepository for SurrealRefreshTokenRepository<C> {
    async fn create(&self, input: CreateRefreshToken) -> AxiamResult<RefreshToken> {
        let id = new_id();
        let id_str = id.to_string();

        let user_id_str = input.user_id.map(|u| u.to_string());

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('oauth2_refresh_token', $id) SET \
                 tenant_id = $tenant_id, \
                 token_hash = $token_hash, \
                 client_id = $client_id, \
                 user_id = $user_id, \
                 scopes = $scopes, \
                 session_id = $session_id, \
                 expires_at = $expires_at, \
                 revoked = false",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("token_hash", input.token_hash.clone()))
            .bind(("client_id", input.client_id.clone()))
            .bind(("user_id", user_id_str))
            .bind(("scopes", input.scopes))
            .bind(("session_id", input.session_id.map(|id| id.to_string())))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "oauth2_refresh_token", &id_str)?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = row
            .user_id
            .map(|uid| {
                Uuid::parse_str(&uid)
                    .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))
            })
            .transpose()?;

        Ok(RefreshToken {
            id,
            tenant_id,
            token_hash: row.token_hash,
            client_id: row.client_id,
            user_id,
            scopes: row.scopes,
            session_id: parse_opt_session(row.session_id.as_deref())?,
            expires_at: row.expires_at,
            revoked: row.revoked,
            created_at: row.created_at,
        })
    }

    async fn get_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<RefreshToken> {
        let token_hash_owned = token_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT *, meta::id(id) AS record_id \
                 FROM oauth2_refresh_token \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND revoked = false \
                   AND expires_at > time::now() \
                 LIMIT 1",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("token_hash", token_hash_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(
            rows,
            "oauth2_refresh_token",
            &format!("token_hash={token_hash_owned}"),
        )?;

        row.try_into_refresh_token().map_err(Into::into)
    }

    async fn revoke(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<()> {
        let token_hash_owned = token_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        // Only revoke tokens that are not already revoked — this
        // provides atomic single-use semantics for refresh token
        // rotation.  If no rows are updated (token already revoked or
        // not found) we return NotFound so callers can detect
        // concurrent use.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET revoked = true \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash \
                   AND revoked = false \
                 RETURN AFTER",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("token_hash", token_hash_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        if rows.is_empty() {
            return Err(DbError::NotFound {
                entity: "oauth2_refresh_token".into(),
                id: format!("token_hash={token_hash_owned}"),
            }
            .into());
        }

        Ok(())
    }

    async fn revoke_all_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        // Revoke all non-revoked tokens for the user atomically. Skip already-revoked
        // tokens so the returned count reflects only newly-revoked tokens.
        // RETURN AFTER gives us the updated rows for counting.
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET revoked = true \
                 WHERE tenant_id = $tenant_id \
                   AND user_id = $user_id \
                   AND revoked = false \
                 RETURN AFTER",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<RefreshTokenRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }

    async fn revoke_all_for_client(&self, tenant_id: Uuid, client_id: &str) -> AxiamResult<()> {
        let client_id_owned = client_id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_refresh_token SET revoked = true \
                 WHERE tenant_id = $tenant_id \
                   AND client_id = $client_id",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("client_id", client_id_owned))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(())
    }

    async fn delete_expired(&self) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM oauth2_refresh_token \
                 WHERE expires_at < time::now() OR revoked = true \
                 GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        let count = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .current()
            .query(
                "DELETE FROM oauth2_refresh_token \
                 WHERE expires_at < time::now() OR revoked = true",
            )
            .await
            .map_err(DbError::from)?;

        Ok(count)
    }
}

//! SurrealDB implementation of [`RefreshTokenRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::oauth2_client::{CreateRefreshToken, RefreshToken};
use axiam_core::repository::RefreshTokenRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

#[derive(Debug, SurrealValue)]
struct RefreshTokenRow {
    tenant_id: String,
    token_hash: String,
    client_id: String,
    user_id: Option<String>,
    scopes: Vec<String>,
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
    expires_at: DateTime<Utc>,
    revoked: bool,
    created_at: DateTime<Utc>,
}

impl RefreshTokenRowWithId {
    fn try_into_refresh_token(self) -> Result<RefreshToken, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| {
                DbError::Migration(format!("invalid tenant UUID: {e}"))
            })?;
        let user_id = self
            .user_id
            .map(|uid| {
                Uuid::parse_str(&uid).map_err(|e| {
                    DbError::Migration(format!("invalid user UUID: {e}"))
                })
            })
            .transpose()?;

        Ok(RefreshToken {
            id,
            tenant_id,
            token_hash: self.token_hash,
            client_id: self.client_id,
            user_id,
            scopes: self.scopes,
            expires_at: self.expires_at,
            revoked: self.revoked,
            created_at: self.created_at,
        })
    }
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the RefreshToken repository.
#[derive(Clone)]
pub struct SurrealRefreshTokenRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealRefreshTokenRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> RefreshTokenRepository
    for SurrealRefreshTokenRepository<C>
{
    async fn create(
        &self,
        input: CreateRefreshToken,
    ) -> AxiamResult<RefreshToken> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let user_id_str = input.user_id.map(|u| u.to_string());

        let result = self
            .db
            .query(
                "CREATE type::record('oauth2_refresh_token', $id) SET \
                 tenant_id = $tenant_id, \
                 token_hash = $token_hash, \
                 client_id = $client_id, \
                 user_id = $user_id, \
                 scopes = $scopes, \
                 expires_at = $expires_at, \
                 revoked = false",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("token_hash", input.token_hash.clone()))
            .bind(("client_id", input.client_id.clone()))
            .bind(("user_id", user_id_str))
            .bind(("scopes", input.scopes))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<RefreshTokenRow> =
            result.take(0).map_err(DbError::from)?;
        let row =
            rows.into_iter().next().ok_or_else(|| DbError::NotFound {
                entity: "oauth2_refresh_token".into(),
                id: id_str,
            })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| {
                DbError::Migration(format!("invalid tenant UUID: {e}"))
            })?;
        let user_id = row
            .user_id
            .map(|uid| {
                Uuid::parse_str(&uid).map_err(|e| {
                    DbError::Migration(format!("invalid user UUID: {e}"))
                })
            })
            .transpose()?;

        Ok(RefreshToken {
            id,
            tenant_id,
            token_hash: row.token_hash,
            client_id: row.client_id,
            user_id,
            scopes: row.scopes,
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

        let rows: Vec<RefreshTokenRowWithId> =
            result.take(0).map_err(DbError::from)?;
        let row =
            rows.into_iter().next().ok_or_else(|| DbError::NotFound {
                entity: "oauth2_refresh_token".into(),
                id: format!("token_hash={token_hash_owned}"),
            })?;

        row.try_into_refresh_token().map_err(Into::into)
    }

    async fn revoke(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
    ) -> AxiamResult<()> {
        let token_hash_owned = token_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = self
            .db
            .query(
                "UPDATE oauth2_refresh_token SET revoked = true \
                 WHERE tenant_id = $tenant_id \
                   AND token_hash = $token_hash",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("token_hash", token_hash_owned))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(())
    }

    async fn revoke_all_for_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
    ) -> AxiamResult<()> {
        let client_id_owned = client_id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = self
            .db
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
            .query(
                "SELECT count() AS total FROM oauth2_refresh_token \
                 WHERE expires_at < time::now() OR revoked = true \
                 GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> =
            result.take(0).map_err(DbError::from)?;
        let count = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .query(
                "DELETE FROM oauth2_refresh_token \
                 WHERE expires_at < time::now() OR revoked = true",
            )
            .await
            .map_err(DbError::from)?;

        Ok(count)
    }
}

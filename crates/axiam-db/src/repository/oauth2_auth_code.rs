//! SurrealDB implementation of [`AuthorizationCodeRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::oauth2_client::{AuthorizationCode, CreateAuthorizationCode};
use axiam_core::repository::AuthorizationCodeRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

#[derive(Debug, SurrealValue)]
struct AuthCodeRow {
    tenant_id: String,
    client_id: String,
    user_id: String,
    code_hash: String,
    redirect_uri: String,
    scopes: Vec<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    expires_at: DateTime<Utc>,
    used: bool,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct AuthCodeRowWithId {
    record_id: String,
    tenant_id: String,
    client_id: String,
    user_id: String,
    code_hash: String,
    redirect_uri: String,
    scopes: Vec<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    expires_at: DateTime<Utc>,
    used: bool,
    created_at: DateTime<Utc>,
}

impl AuthCodeRowWithId {
    fn try_into_auth_code(self) -> Result<AuthorizationCode, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(AuthorizationCode {
            id,
            tenant_id,
            client_id: self.client_id,
            user_id,
            code_hash: self.code_hash,
            redirect_uri: self.redirect_uri,
            scopes: self.scopes,
            code_challenge: self.code_challenge,
            code_challenge_method: self.code_challenge_method,
            nonce: self.nonce,
            expires_at: self.expires_at,
            used: self.used,
            created_at: self.created_at,
        })
    }
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the AuthorizationCode repository.
#[derive(Clone)]
pub struct SurrealAuthorizationCodeRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealAuthorizationCodeRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> AuthorizationCodeRepository for SurrealAuthorizationCodeRepository<C> {
    async fn create(&self, input: CreateAuthorizationCode) -> AxiamResult<AuthorizationCode> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('oauth2_auth_code', $id) SET \
                 tenant_id = $tenant_id, \
                 client_id = $client_id, \
                 user_id = $user_id, \
                 code_hash = $code_hash, \
                 redirect_uri = $redirect_uri, \
                 scopes = $scopes, \
                 code_challenge = $code_challenge, \
                 code_challenge_method = $code_challenge_method, \
                 nonce = $nonce, \
                 expires_at = $expires_at, \
                 used = false",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("client_id", input.client_id))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("code_hash", input.code_hash))
            .bind(("redirect_uri", input.redirect_uri))
            .bind(("scopes", input.scopes))
            .bind(("code_challenge", input.code_challenge))
            .bind(("code_challenge_method", input.code_challenge_method))
            .bind(("nonce", input.nonce))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AuthCodeRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "oauth2_auth_code".into(),
            id: id_str,
        })?;

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&row.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;

        Ok(AuthorizationCode {
            id,
            tenant_id,
            client_id: row.client_id,
            user_id,
            code_hash: row.code_hash,
            redirect_uri: row.redirect_uri,
            scopes: row.scopes,
            code_challenge: row.code_challenge,
            code_challenge_method: row.code_challenge_method,
            nonce: row.nonce,
            expires_at: row.expires_at,
            used: row.used,
            created_at: row.created_at,
        })
    }

    async fn get_by_hash(
        &self,
        tenant_id: Uuid,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> AxiamResult<AuthorizationCode> {
        let code_hash_owned = code_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * \
                 FROM oauth2_auth_code \
                 WHERE tenant_id = $tenant_id \
                   AND code_hash = $code_hash \
                   AND client_id = $client_id \
                   AND redirect_uri = $redirect_uri \
                   AND used = false \
                   AND expires_at > time::now()",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("code_hash", code_hash_owned.clone()))
            .bind(("client_id", client_id.to_string()))
            .bind(("redirect_uri", redirect_uri.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AuthCodeRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "oauth2_auth_code".into(),
            id: format!("code_hash={code_hash_owned}"),
        })?;

        row.try_into_auth_code().map_err(Into::into)
    }

    async fn consume(
        &self,
        tenant_id: Uuid,
        code_hash: &str,
        client_id: &str,
        redirect_uri: &str,
    ) -> AxiamResult<AuthorizationCode> {
        let code_hash_owned = code_hash.to_string();
        let tenant_id_str = tenant_id.to_string();

        // Single atomic UPDATE with WHERE guards: only one concurrent
        // caller can match `used = false`, eliminating the race
        // condition of a separate SELECT + UPDATE. client_id and
        // redirect_uri are verified atomically to prevent
        // code-burning attacks.
        let result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM \
                 (UPDATE oauth2_auth_code SET used = true \
                  WHERE tenant_id = $tenant_id \
                    AND code_hash = $code_hash \
                    AND client_id = $client_id \
                    AND redirect_uri = $redirect_uri \
                    AND used = false \
                    AND expires_at > time::now())",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("code_hash", code_hash_owned.clone()))
            .bind(("client_id", client_id.to_string()))
            .bind(("redirect_uri", redirect_uri.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AuthCodeRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "oauth2_auth_code".into(),
            id: format!("code_hash={code_hash_owned}"),
        })?;

        row.try_into_auth_code().map_err(Into::into)
    }

    async fn delete_expired(&self) -> AxiamResult<u64> {
        let mut result = self
            .db
            .query(
                "SELECT count() AS total FROM oauth2_auth_code \
                 WHERE expires_at < time::now() OR used = true GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        let count = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .query(
                "DELETE FROM oauth2_auth_code \
                 WHERE expires_at < time::now() OR used = true",
            )
            .await
            .map_err(DbError::from)?;

        Ok(count)
    }
}

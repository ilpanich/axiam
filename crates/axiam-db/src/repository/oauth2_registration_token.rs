//! SurrealDB implementation of [`OAuth2RegistrationTokenRepository`] (T21.4).

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_registration_token::{
    CreateOAuth2RegistrationToken, OAuth2RegistrationToken,
};
use axiam_core::repository::OAuth2RegistrationTokenRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::take_first_or_not_found;

#[derive(Debug, SurrealValue)]
struct TokenRowWithId {
    record_id: String,
    tenant_id: String,
    name: String,
    token_hash: String,
    created_by: String,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    used_by_client_id: Option<String>,
    created_at: DateTime<Utc>,
}

impl TokenRowWithId {
    fn try_into_token(self) -> Result<OAuth2RegistrationToken, DbError> {
        let parse = |raw: &str, what: &str| {
            Uuid::parse_str(raw)
                .map_err(|e| DbError::Migration(format!("invalid {what} UUID: {e}")))
        };
        Ok(OAuth2RegistrationToken {
            id: parse(&self.record_id, "oauth2_registration_token")?,
            tenant_id: parse(&self.tenant_id, "tenant")?,
            name: self.name,
            token_hash: self.token_hash,
            created_by: parse(&self.created_by, "created_by")?,
            expires_at: self.expires_at,
            used_at: self.used_at,
            used_by_client_id: self.used_by_client_id,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the RFC 7591 initial-access-token repository.
pub struct SurrealOAuth2RegistrationTokenRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealOAuth2RegistrationTokenRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealOAuth2RegistrationTokenRepository<C> {
    /// Bind a repository to a connection handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> OAuth2RegistrationTokenRepository
    for SurrealOAuth2RegistrationTokenRepository<C>
{
    async fn create(
        &self,
        input: CreateOAuth2RegistrationToken,
    ) -> AxiamResult<OAuth2RegistrationToken> {
        let id = new_id();
        let id_str = id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('oauth2_registration_token', $id) SET \
                 tenant_id = $tenant_id, \
                 name = $name, \
                 token_hash = $token_hash, \
                 created_by = $created_by, \
                 expires_at = $expires_at, \
                 used_at = NONE, \
                 used_by_client_id = NONE, \
                 created_at = time::now(); \
                 SELECT meta::id(id) AS record_id, * FROM \
                 type::record('oauth2_registration_token', $id);",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("name", input.name))
            .bind(("token_hash", input.token_hash))
            .bind(("created_by", input.created_by.to_string()))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRowWithId> = result.take(1).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "oauth2_registration_token", &id_str)?;
        Ok(row.try_into_token()?)
    }

    /// The single-use guarantee, as one statement.
    ///
    /// `used_at IS NONE` in the `WHERE` clause is the compare-and-swap: two
    /// registrations presenting the same handle at the same moment both run
    /// this `UPDATE`, exactly one matches a row, and the other receives an
    /// empty result and is refused. Doing it as a read followed by a write —
    /// which is what "check the token, then mark it" means — would let both
    /// pass the check before either performed the write, on an endpoint that
    /// is by design reachable without a credential.
    ///
    /// `tenant_id` and `expires_at` are conditions rather than post-checks for
    /// the same reason: a handle minted for one tenant must not register a
    /// client in another even for the instant between two statements, and a
    /// token that expires mid-request must not be spendable by whichever half
    /// of the race read it first.
    ///
    /// The `UPDATE` returns the rows it wrote, so a non-empty result *is* the
    /// proof that this call is the one that spent the token.
    async fn consume_by_token_hash(
        &self,
        tenant_id: Uuid,
        token_hash: &str,
        now: DateTime<Utc>,
    ) -> AxiamResult<Option<OAuth2RegistrationToken>> {
        let result = self
            .db
            .current()
            .query(
                "UPDATE oauth2_registration_token SET used_at = $now \
                 WHERE token_hash = $token_hash \
                   AND tenant_id = $tenant_id \
                   AND used_at IS NONE \
                   AND expires_at > $now \
                 RETURN meta::id(id) AS record_id, *",
            )
            .bind(("token_hash", token_hash.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("now", now))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRowWithId> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.try_into_token()?)),
            None => Ok(None),
        }
    }

    async fn list_for_tenant(&self, tenant_id: Uuid) -> AxiamResult<Vec<OAuth2RegistrationToken>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM oauth2_registration_token \
                 WHERE tenant_id = $tenant_id ORDER BY created_at DESC",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_token().map_err(Into::into))
            .collect()
    }

    async fn prune_expired(&self, before: DateTime<Utc>) -> AxiamResult<u64> {
        let result = self
            .db
            .current()
            .query(
                "DELETE oauth2_registration_token WHERE expires_at < $before \
                 RETURN BEFORE",
            )
            .bind(("before", before))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRowWithId> = result.take(0).map_err(DbError::from)?;
        Ok(rows.len() as u64)
    }
}

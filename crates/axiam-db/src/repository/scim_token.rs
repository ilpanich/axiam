//! SurrealDB implementation of [`ScimTokenRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::scim_token::{CreateScimToken, ScimToken};
use axiam_core::repository::ScimTokenRepository;
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
    user_id: String,
    name: String,
    token_hash: String,
    created_by: String,
    expires_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl TokenRowWithId {
    fn try_into_token(self) -> Result<ScimToken, DbError> {
        let parse = |raw: &str, what: &str| {
            Uuid::parse_str(raw)
                .map_err(|e| DbError::Migration(format!("invalid {what} UUID: {e}")))
        };
        Ok(ScimToken {
            id: parse(&self.record_id, "scim_token")?,
            tenant_id: parse(&self.tenant_id, "tenant")?,
            user_id: parse(&self.user_id, "user")?,
            name: self.name,
            token_hash: self.token_hash,
            created_by: parse(&self.created_by, "created_by")?,
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the SCIM provisioning-token repository.
pub struct SurrealScimTokenRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> Clone for SurrealScimTokenRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealScimTokenRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> ScimTokenRepository for SurrealScimTokenRepository<C> {
    async fn create(&self, input: CreateScimToken) -> AxiamResult<ScimToken> {
        let id = new_id();
        let id_str = id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('scim_token', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 name = $name, \
                 token_hash = $token_hash, \
                 created_by = $created_by, \
                 expires_at = $expires_at, \
                 last_used_at = NONE, \
                 revoked_at = NONE, \
                 created_at = time::now(); \
                 SELECT meta::id(id) AS record_id, * FROM type::record('scim_token', $id);",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
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
        let row = take_first_or_not_found(rows, "scim_token", &id_str)?;
        Ok(row.try_into_token()?)
    }

    /// Deliberately unfiltered on `revoked_at`/`expires_at` — see the trait
    /// docs. The caller distinguishes "no such handle" from "a handle whose
    /// authority was withdrawn", which the audit trail needs and a filtering
    /// query would collapse.
    async fn get_by_token_hash(&self, token_hash: &str) -> AxiamResult<Option<ScimToken>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM scim_token \
                 WHERE token_hash = $token_hash",
            )
            .bind(("token_hash", token_hash.to_string()))
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

    async fn list_for_tenant(&self, tenant_id: Uuid) -> AxiamResult<Vec<ScimToken>> {
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM scim_token \
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

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<ScimToken> {
        let id_str = id.to_string();
        let result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM scim_token \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<TokenRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "scim_token", &id_str)?;
        Ok(row.try_into_token()?)
    }

    /// `revoked_at IS NONE` in the WHERE clause is what makes this idempotent
    /// in the way the trait promises: a second revoke matches no row and
    /// therefore leaves the original timestamp alone.
    async fn revoke(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPDATE scim_token SET revoked_at = time::now() \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id \
                   AND revoked_at IS NONE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    async fn touch_last_used(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPDATE scim_token SET last_used_at = time::now() \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }

    /// Hard delete rather than revoke: the user this token authenticated as no
    /// longer exists, so there is no principal left for the row to describe and
    /// nothing an operator could learn from keeping it.
    async fn delete_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.db
            .current()
            .query("DELETE scim_token WHERE tenant_id = $tenant_id AND user_id = $user_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(())
    }
}

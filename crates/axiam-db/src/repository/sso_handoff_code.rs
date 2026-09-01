//! SurrealDB implementation of [`SsoHandoffCodeRepository`].
//!
//! Single-use, 60-second codes that convert a cross-site SSO return (SAML, and
//! Apple's `response_mode=form_post`) into a same-site session issuance without
//! weakening `SameSite=Strict` on the session cookies. See
//! [`axiam_core::repository::SsoHandoffCode`] and
//! `claude_dev/federation-sso-login-design.md` §5.2.
//!
//! Only the SHA-256 hash of a code is ever written here. That is the difference
//! between this table and `federation_login_state`, which stores its `state`
//! raw: a `state` is a correlation value, while a handoff code is a bearer
//! credential for a session, and a database read must not yield one.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::repository::{SsoHandoffCode, SsoHandoffCodeRepository};
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, classify_conflict_write_error};

#[derive(Debug, SurrealValue)]
struct SsoHandoffCodeRow {
    code_hash: String,
    tenant_id: String,
    user_id: String,
    redirect_uri: String,
    expires_at: DateTime<Utc>,
}

/// SurrealDB implementation of the SSO handoff-code repository.
#[derive(Clone)]
pub struct SurrealSsoHandoffCodeRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealSsoHandoffCodeRepository<C> {
    /// Construct a repository over a database handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> SsoHandoffCodeRepository for SurrealSsoHandoffCodeRepository<C> {
    async fn insert(&self, row: &SsoHandoffCode) -> AxiamResult<()> {
        let row_id = new_id().to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('sso_handoff_code', $id) SET \
                 code_hash = $code_hash, \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 redirect_uri = $redirect_uri, \
                 expires_at = $expires_at",
            )
            .bind(("id", row_id))
            .bind(("code_hash", row.code_hash.clone()))
            .bind(("tenant_id", row.tenant_id.to_string()))
            .bind(("user_id", row.user_id.to_string()))
            .bind(("redirect_uri", row.redirect_uri.clone()))
            .bind(("expires_at", row.expires_at))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            // A UNIQUE violation is a hash collision on 256 bits of entropy,
            // i.e. never in practice — but it is classified rather than
            // swallowed, because the alternative reading is "somebody replayed
            // a code", and that must not look like a success.
            .map_err(|e| classify_conflict_write_error(e, "sso_handoff_code.code_hash"))
            .map(|_| ())
    }

    async fn consume_by_hash(&self, code_hash: &str) -> AxiamResult<Option<SsoHandoffCode>> {
        let hash_owned = code_hash.to_string();

        // SELECT + DELETE in one transaction, exactly as `consume_by_state`
        // does. The row is deleted whenever it is found — expired or not — so a
        // second redemption of the same code cannot succeed even if the first
        // one was rejected for expiry.
        let mut result = self
            .db
            .current()
            .query(
                "BEGIN TRANSACTION; \
                 LET $row = (SELECT code_hash, tenant_id, user_id, redirect_uri, expires_at \
                             FROM sso_handoff_code \
                             WHERE code_hash = $code_hash LIMIT 1); \
                 DELETE sso_handoff_code WHERE code_hash = $code_hash; \
                 RETURN $row; \
                 COMMIT TRANSACTION",
            )
            .bind(("code_hash", hash_owned))
            .await
            .map_err(DbError::from)?;

        // BEGIN=0, LET=1, DELETE=2, RETURN=3.
        let rows: Vec<SsoHandoffCodeRow> = result
            .take(3)
            .map_err(|e| AxiamError::Database(e.to_string()))?;

        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        let tenant_id = Uuid::parse_str(&row.tenant_id)
            .map_err(|_| AxiamError::Database("invalid tenant_id in handoff row".into()))?;
        let user_id = Uuid::parse_str(&row.user_id)
            .map_err(|_| AxiamError::Database("invalid user_id in handoff row".into()))?;

        // Expiry is checked after the delete, and both outcomes are reported to
        // the caller as the same `None`: "expired" and "never existed" must be
        // indistinguishable, for the same reason they are on the state row.
        if row.expires_at <= Utc::now() {
            return Ok(None);
        }

        Ok(Some(SsoHandoffCode {
            code_hash: row.code_hash,
            tenant_id,
            user_id,
            redirect_uri: row.redirect_uri,
            expires_at: row.expires_at,
        }))
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        let mut count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM sso_handoff_code \
                 WHERE expires_at < time::now() GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .current()
            .query("DELETE sso_handoff_code WHERE expires_at < time::now()")
            .await
            .map_err(DbError::from)?;

        Ok(total)
    }
}

//! SurrealDB implementation of [`FederationLoginStateRepository`].
//!
//! Provides atomic insert + consume semantics for the first-time SSO state
//! table (D-24). Each row is single-use: `consume_by_state` deletes the row
//! and returns its data in one transaction. Expired rows are rejected by the
//! caller check and can be swept by `cleanup_expired`.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::repository::{FederationLoginState, FederationLoginStateRepository};
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct FederationLoginStateRow {
    state: String,
    nonce: String,
    tenant_id: String,
    federation_config_id: String,
    redirect_uri: String,
    expires_at: DateTime<Utc>,
    /// SAML AuthnRequest ID for InResponseTo verification (SEC-005/REQ-14 AC-5).
    /// Empty string for OIDC flows where no request ID is tracked.
    request_id: Option<String>,
}

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the federation login state repository.
#[derive(Clone)]
pub struct SurrealFederationLoginStateRepository<C: Connection> {
    db: Surreal<C>,
}

impl<C: Connection> SurrealFederationLoginStateRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> FederationLoginStateRepository for SurrealFederationLoginStateRepository<C> {
    async fn insert(&self, row: &FederationLoginState) -> AxiamResult<()> {
        let row_id = Uuid::new_v4().to_string();

        let result = self
            .db
            .query(
                "CREATE type::record('federation_login_state', $id) SET \
                 state = $state, \
                 nonce = $nonce, \
                 tenant_id = $tenant_id, \
                 federation_config_id = $config_id, \
                 redirect_uri = $redirect_uri, \
                 expires_at = $expires_at, \
                 request_id = $request_id",
            )
            .bind(("id", row_id))
            .bind(("state", row.state.clone()))
            .bind(("nonce", row.nonce.clone()))
            .bind(("tenant_id", row.tenant_id.to_string()))
            .bind(("config_id", row.federation_config_id.to_string()))
            .bind(("redirect_uri", row.redirect_uri.clone()))
            .bind(("expires_at", row.expires_at))
            .bind(("request_id", row.request_id.clone()))
            .await
            .map_err(DbError::from)?;

        result
            .check()
            .map_err(|e| {
                let msg = e.to_string();
                // UNIQUE index violation on `state` — duplicate state value.
                if msg.contains("already contains")
                    || msg.contains("already exists")
                    || msg.contains("unique")
                {
                    AxiamError::AlreadyExists {
                        entity: "federation_login_state.state".into(),
                    }
                } else {
                    AxiamError::Database(msg)
                }
            })
            .map(|_| ())
    }

    async fn consume_by_state(&self, state: &str) -> AxiamResult<Option<FederationLoginState>> {
        let state_owned = state.to_string();

        // Atomic SELECT + DELETE in a transaction. We fetch the row first,
        // delete it, then return the fetched data. If no row exists, both
        // SELECT and DELETE are no-ops and we return None.
        let mut result = self
            .db
            .query(
                "BEGIN TRANSACTION; \
                 LET $row = (SELECT state, nonce, tenant_id, federation_config_id, \
                               redirect_uri, expires_at, request_id \
                             FROM federation_login_state \
                             WHERE state = $state LIMIT 1); \
                 DELETE federation_login_state WHERE state = $state; \
                 RETURN $row; \
                 COMMIT TRANSACTION",
            )
            .bind(("state", state_owned))
            .await
            .map_err(DbError::from)?;

        // The RETURN $row result is at index 3 (BEGIN=0, LET=1, DELETE=2, RETURN=3).
        let rows: Vec<FederationLoginStateRow> = result
            .take(3)
            .map_err(|e| AxiamError::Database(e.to_string()))?;

        match rows.into_iter().next() {
            None => Ok(None),
            Some(row) => {
                let tenant_id = Uuid::parse_str(&row.tenant_id)
                    .map_err(|_| AxiamError::Database("invalid tenant_id in state row".into()))?;
                let federation_config_id = Uuid::parse_str(&row.federation_config_id)
                    .map_err(|_| AxiamError::Database("invalid config_id in state row".into()))?;

                let state_obj = FederationLoginState {
                    state: row.state,
                    nonce: row.nonce,
                    tenant_id,
                    federation_config_id,
                    redirect_uri: row.redirect_uri,
                    expires_at: row.expires_at,
                    request_id: row.request_id.unwrap_or_default(),
                };

                // Check expiry in Rust — row was deleted; returning None here
                // means the caller gets "state not found or expired" → 401.
                if state_obj.expires_at <= Utc::now() {
                    return Ok(None);
                }

                Ok(Some(state_obj))
            }
        }
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        // Count expired rows first, then delete.
        let mut count_result = self
            .db
            .query(
                "SELECT count() AS total FROM federation_login_state \
                 WHERE expires_at < time::now() GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .query("DELETE federation_login_state WHERE expires_at < time::now()")
            .await
            .map_err(DbError::from)?;

        Ok(total)
    }
}

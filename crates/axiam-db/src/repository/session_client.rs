//! SurrealDB implementation of [`SessionClientRepository`] (B5).
//!
//! Records which OAuth2 clients participated in an AXIAM session, so that
//! back-channel logout can notify exactly those clients and no others.
//!
//! # Why this is a table rather than a column on `session`
//!
//! One AXIAM session serves many relying parties — that is what SSO *is*. A
//! single `client_id` on the session would record only whichever RP happened
//! to authorize last, and the logout fan-out would silently skip every other
//! RP the user was signed into: the exact failure back-channel logout exists
//! to prevent.

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_client::{CreateSessionClient, SessionClient};
use axiam_core::repository::SessionClientRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::CountRow;

const SELECT_FIELDS: &str =
    "meta::id(id) AS record_id, tenant_id, session_id, client_id, user_id, created_at";

#[derive(Debug, SurrealValue)]
struct SessionClientRow {
    record_id: String,
    tenant_id: String,
    session_id: String,
    client_id: String,
    user_id: String,
    created_at: DateTime<Utc>,
}

impl SessionClientRow {
    fn try_into_model(self) -> Result<SessionClient, DbError> {
        let parse = |raw: &str, what: &str| {
            Uuid::parse_str(raw).map_err(|e| DbError::Migration(format!("invalid {what}: {e}")))
        };
        Ok(SessionClient {
            id: parse(&self.record_id, "session_client UUID")?,
            tenant_id: parse(&self.tenant_id, "tenant UUID")?,
            session_id: parse(&self.session_id, "session UUID")?,
            client_id: self.client_id,
            user_id: parse(&self.user_id, "user UUID")?,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the session/client participation repository.
#[derive(Clone)]
pub struct SurrealSessionClientRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealSessionClientRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> SessionClientRepository for SurrealSessionClientRepository<C> {
    async fn record(&self, input: CreateSessionClient) -> AxiamResult<SessionClient> {
        let id = new_id();
        let mut result = self
            .db
            .current()
            .query(format!(
                "LET $created = (CREATE type::record('session_client', $id) SET \
                     tenant_id = $tenant_id, \
                     session_id = $session_id, \
                     client_id = $client_id, \
                     user_id = $user_id); \
                 SELECT {SELECT_FIELDS} FROM $created"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("session_id", input.session_id.to_string()))
            .bind(("client_id", input.client_id))
            .bind(("user_id", input.user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SessionClientRow> = result.take(1).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .ok_or_else(|| DbError::Migration("session_client insert returned no row".into()))?
            .try_into_model()
            .map_err(Into::into)
    }

    async fn list_for_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> AxiamResult<Vec<SessionClient>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM session_client \
                 WHERE tenant_id = $tenant_id AND session_id = $session_id \
                 ORDER BY created_at ASC"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("session_id", session_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SessionClientRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(SessionClientRow::try_into_model)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    async fn delete_for_session(&self, tenant_id: Uuid, session_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM (DELETE session_client \
                 WHERE tenant_id = $tenant_id AND session_id = $session_id \
                 RETURN BEFORE) GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("session_id", session_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }
}

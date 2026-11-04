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
//!
//! # The lineage (#844)
//!
//! A record keeps the `session_id` it was written under, because that is the
//! `sid` the client's ID token carried and the one its logout token must
//! carry. It also records the session's **lineage**, resolved from the live
//! session row in the same statement, because a console refresh replaces that
//! row: a logout of the replacement finds the record by lineage, and a record
//! written before schema v115 is found by its `session_id`, which is the key of
//! the lineage it belonged to.

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

const SELECT_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, session_id, client_id, \
     user_id, created_at, lineage_id";

#[derive(Debug, SurrealValue)]
struct SessionClientRow {
    record_id: String,
    tenant_id: String,
    session_id: String,
    client_id: String,
    user_id: String,
    created_at: DateTime<Utc>,
    /// #844 — absent on every record written before schema v115; read as
    /// `session_id` (see the module docs).
    #[surreal(default)]
    lineage_id: Option<String>,
}

impl SessionClientRow {
    fn try_into_model(self) -> Result<SessionClient, DbError> {
        let parse = |raw: &str, what: &str| {
            Uuid::parse_str(raw).map_err(|e| DbError::Migration(format!("invalid {what}: {e}")))
        };
        let session_id = parse(&self.session_id, "session UUID")?;
        let lineage_id = match self.lineage_id.as_deref() {
            None | Some("") => session_id,
            Some(raw) => parse(raw, "session lineage UUID")?,
        };
        Ok(SessionClient {
            id: parse(&self.record_id, "session_client UUID")?,
            tenant_id: parse(&self.tenant_id, "tenant UUID")?,
            session_id,
            lineage_id,
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
                // #844: the live session's lineage (its own id for a row
                // written before v115), or the session id when the row is
                // already gone — the pre-#844 scope, never a wider one.
                "LET $lineage = array::first((SELECT VALUE lineage_id ?? meta::id(id) \
                     FROM type::record('session', $session_id) \
                     WHERE tenant_id = $tenant_id)) ?? $session_id; \
                 LET $created = (CREATE type::record('session_client', $id) SET \
                     tenant_id = $tenant_id, \
                     session_id = $session_id, \
                     client_id = $client_id, \
                     user_id = $user_id, \
                     lineage_id = $lineage); \
                 SELECT {SELECT_FIELDS} FROM $created"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("session_id", input.session_id.to_string()))
            .bind(("client_id", input.client_id))
            .bind(("user_id", input.user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        // Statement index 2: the projected SELECT (0 and 1 are the `LET`s).
        let rows: Vec<SessionClientRow> = result.take(2).map_err(DbError::from)?;
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

    async fn list_for_lineage(
        &self,
        tenant_id: Uuid,
        lineage_id: Uuid,
    ) -> AxiamResult<Vec<SessionClient>> {
        // Two indexed reads, one round trip: the records that captured the
        // lineage, and those written before v115 under the session that keys
        // it. A record can satisfy both (the lineage's first session, written
        // after v115); it is returned once.
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM session_client \
                 WHERE tenant_id = $tenant_id AND lineage_id = $lineage_id; \
                 SELECT {SELECT_FIELDS} FROM session_client \
                 WHERE tenant_id = $tenant_id AND session_id = $lineage_id \
                   AND lineage_id = NONE"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("lineage_id", lineage_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let mut rows: Vec<SessionClientRow> = result.take(0).map_err(DbError::from)?;
        let legacy: Vec<SessionClientRow> = result.take(1).map_err(DbError::from)?;
        rows.extend(legacy);
        let mut out = rows
            .into_iter()
            .map(SessionClientRow::try_into_model)
            .collect::<Result<Vec<_>, _>>()?;
        out.sort_by_key(|r| r.created_at);
        Ok(out)
    }

    async fn delete_for_lineage(&self, tenant_id: Uuid, lineage_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM (DELETE session_client \
                 WHERE tenant_id = $tenant_id AND lineage_id = $lineage_id \
                 RETURN BEFORE) GROUP ALL; \
                 SELECT count() AS total FROM (DELETE session_client \
                 WHERE tenant_id = $tenant_id AND session_id = $lineage_id \
                 RETURN BEFORE) GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("lineage_id", lineage_id.to_string()))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let by_lineage: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        let by_session: Vec<CountRow> = result.take(1).map_err(DbError::from)?;
        Ok(by_lineage.first().map(|r| r.total).unwrap_or(0)
            + by_session.first().map(|r| r.total).unwrap_or(0))
    }
}

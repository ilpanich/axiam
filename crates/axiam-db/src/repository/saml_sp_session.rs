//! SurrealDB implementation of [`SamlSpSessionRepository`] (G-2, T23.2.4, schema
//! v76): the participant record of D-37.
//!
//! One row per (tenant, AXIAM session, service provider). See
//! [`axiam_core::models::saml_slo`] for what a row is and is not.
//!
//! # `record` is a create-or-refresh, decided by the datastore
//!
//! Two unique indexes define the table: `(tenant_id, session_id, sp_id)` and
//! `(tenant_id, sp_id, session_index)`. `record` tries a `CREATE`; a unique
//! violation (the one answer both indexes give, classified through the helper
//! every replay guard shares) means the session already has a row for this SP,
//! and the row is **refreshed** — the `NameID` and its format take the values now
//! being asserted — and read back with its **original** `SessionIndex`. So two
//! concurrent sign-ons to one SP in one session agree on one index, and a
//! second sign-on never accumulates a second row (T-384).
//!
//! # The sweeper
//!
//! [`SamlSpSessionRepository::cleanup_expired`] removes a row once its session
//! has expired, or once its session row is gone — unless a logout ended the
//! session within the last run lifetime (`ended_at`), because the chain that
//! logout started still needs the rows it is about to tell.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::saml_slo::{NewSamlSpSession, SAML_LOGOUT_RUN_TTL_SECS, SamlSpSession};
use axiam_core::repository::SamlSpSessionRepository;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, classify_replay_write_error, is_transaction_conflict};

const SELECT_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, session_id, user_id, sp_id, \
     sp_entity_id, name_id, name_id_format, session_index, created_at, expires_at";

/// The most rows `list_for_sp_name_id` returns: far above what one person holds
/// at one SP, and a bound on what a request that names no `SessionIndex` can
/// make the endpoint do.
const MAX_ROWS_PER_NAME_ID: u32 = 100;

#[derive(Debug, SurrealValue)]
struct ParticipantRow {
    record_id: String,
    tenant_id: String,
    session_id: String,
    user_id: String,
    sp_id: String,
    sp_entity_id: String,
    name_id: String,
    name_id_format: String,
    session_index: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl ParticipantRow {
    fn try_into_model(self) -> Result<SamlSpSession, DbError> {
        let parse = |raw: &str, what: &str| {
            Uuid::parse_str(raw)
                .map_err(|_| DbError::Migration(format!("invalid {what} in saml_sp_session")))
        };
        Ok(SamlSpSession {
            id: parse(&self.record_id, "id")?,
            tenant_id: parse(&self.tenant_id, "tenant_id")?,
            session_id: parse(&self.session_id, "session_id")?,
            user_id: parse(&self.user_id, "user_id")?,
            sp_id: parse(&self.sp_id, "sp_id")?,
            sp_entity_id: self.sp_entity_id,
            name_id: self.name_id,
            name_id_format: self.name_id_format,
            session_index: self.session_index,
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

fn models(rows: Vec<ParticipantRow>) -> AxiamResult<Vec<SamlSpSession>> {
    rows.into_iter()
        .map(ParticipantRow::try_into_model)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn id_strings(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(Uuid::to_string).collect()
}

/// SurrealDB implementation of the SAML participant repository.
pub struct SurrealSamlSpSessionRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone: no spurious `C: Clone` bound (the `saml_replay` pattern).
impl<C: Connection> Clone for SurrealSamlSpSessionRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealSamlSpSessionRepository<C> {
    /// Construct a repository over a database handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    /// The row a session holds for an SP, if any.
    async fn find(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
        sp_id: Uuid,
    ) -> AxiamResult<Option<SamlSpSession>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM saml_sp_session \
                 WHERE tenant_id = $tenant_id AND session_id = $session_id \
                 AND sp_id = $sp_id LIMIT 1"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("session_id", session_id.to_string()))
            .bind(("sp_id", sp_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<ParticipantRow> = result.take(0).map_err(DbError::from)?;
        Ok(models(rows)?.into_iter().next())
    }
}

impl<C: Connection> SamlSpSessionRepository for SurrealSamlSpSessionRepository<C> {
    async fn record(&self, input: NewSamlSpSession) -> AxiamResult<SamlSpSession> {
        let row_id = new_id().to_string();
        let created = self
            .db
            .current()
            .query(
                "CREATE type::record('saml_sp_session', $id) SET \
                 tenant_id = $tenant_id, \
                 session_id = $session_id, \
                 user_id = $user_id, \
                 sp_id = $sp_id, \
                 sp_entity_id = $sp_entity_id, \
                 name_id = $name_id, \
                 name_id_format = $name_id_format, \
                 session_index = $session_index, \
                 created_at = $created_at, \
                 expires_at = $expires_at, \
                 ended_at = NONE",
            )
            .bind(("id", row_id))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("session_id", input.session_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("sp_id", input.sp_id.to_string()))
            .bind(("sp_entity_id", input.sp_entity_id.clone()))
            .bind(("name_id", input.name_id.clone()))
            .bind(("name_id_format", input.name_id_format.clone()))
            .bind(("session_index", input.session_index.clone()))
            .bind(("created_at", Utc::now()))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        // A unique violation — or a write conflict, which is what two sign-ons
        // racing to create the same row can be told instead — means the session
        // already has (or is about to have) a row for this SP.
        let exists = match created.check() {
            Ok(_) => false,
            Err(e) if is_transaction_conflict(&e) => true,
            Err(e) => match classify_replay_write_error(e) {
                AxiamError::ReplayDetected => true,
                other => return Err(other),
            },
        };
        if exists {
            // Refresh what is now being asserted; the original index stays.
            let refreshed = self
                .db
                .current()
                .query(
                    "UPDATE saml_sp_session SET \
                     name_id = $name_id, name_id_format = $name_id_format, \
                     sp_entity_id = $sp_entity_id \
                     WHERE tenant_id = $tenant_id AND session_id = $session_id \
                     AND sp_id = $sp_id",
                )
                .bind(("tenant_id", input.tenant_id.to_string()))
                .bind(("session_id", input.session_id.to_string()))
                .bind(("sp_id", input.sp_id.to_string()))
                .bind(("sp_entity_id", input.sp_entity_id.clone()))
                .bind(("name_id", input.name_id.clone()))
                .bind(("name_id_format", input.name_id_format.clone()))
                .await
                .map_err(DbError::from)?;
            match refreshed.check() {
                Ok(_) => {}
                // The racing writer wrote the same facts; the read-back below
                // decides whether the row is there.
                Err(e) if is_transaction_conflict(&e) => {}
                Err(e) => return Err(AxiamError::Database(e.to_string())),
            }
        }

        // Read back, whichever branch: the row whose index the assertion carries.
        // Absent only if the violation was the *index* index (a 256-bit
        // collision) — an error, never a silently different index.
        self.find(input.tenant_id, input.session_id, input.sp_id)
            .await?
            .ok_or_else(|| {
                DbError::Migration("the participant row could not be recorded".into()).into()
            })
    }

    async fn get_by_index(
        &self,
        tenant_id: Uuid,
        sp_id: Uuid,
        session_index: &str,
    ) -> AxiamResult<Option<SamlSpSession>> {
        if session_index.is_empty() {
            return Ok(None);
        }
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM saml_sp_session \
                 WHERE tenant_id = $tenant_id AND sp_id = $sp_id \
                 AND session_index = $session_index LIMIT 1"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("sp_id", sp_id.to_string()))
            .bind(("session_index", session_index.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<ParticipantRow> = result.take(0).map_err(DbError::from)?;
        Ok(models(rows)?.into_iter().next())
    }

    async fn list_for_sp_name_id(
        &self,
        tenant_id: Uuid,
        sp_id: Uuid,
        name_id: &str,
    ) -> AxiamResult<Vec<SamlSpSession>> {
        if name_id.is_empty() {
            return Ok(Vec::new());
        }
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM saml_sp_session \
                 WHERE tenant_id = $tenant_id AND sp_id = $sp_id AND name_id = $name_id \
                 ORDER BY created_at ASC LIMIT {MAX_ROWS_PER_NAME_ID}"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("sp_id", sp_id.to_string()))
            .bind(("name_id", name_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<ParticipantRow> = result.take(0).map_err(DbError::from)?;
        models(rows)
    }

    async fn list_for_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> AxiamResult<Vec<SamlSpSession>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM saml_sp_session \
                 WHERE tenant_id = $tenant_id AND session_id = $session_id \
                 ORDER BY created_at ASC"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("session_id", session_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<ParticipantRow> = result.take(0).map_err(DbError::from)?;
        models(rows)
    }

    async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Option<SamlSpSession>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM saml_sp_session \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id LIMIT 1"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<ParticipantRow> = result.take(0).map_err(DbError::from)?;
        Ok(models(rows)?.into_iter().next())
    }

    async fn mark_ended(&self, tenant_id: Uuid, session_ids: &[Uuid]) -> AxiamResult<u64> {
        if session_ids.is_empty() {
            return Ok(0);
        }
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM (UPDATE saml_sp_session \
                 SET ended_at = time::now() \
                 WHERE tenant_id = $tenant_id AND session_id IN $session_ids) GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("session_ids", id_strings(session_ids)))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn delete_for_sessions(&self, tenant_id: Uuid, session_ids: &[Uuid]) -> AxiamResult<u64> {
        if session_ids.is_empty() {
            return Ok(0);
        }
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM (DELETE saml_sp_session \
                 WHERE tenant_id = $tenant_id AND session_id IN $session_ids \
                 RETURN BEFORE) GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("session_ids", id_strings(session_ids)))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn delete_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM (DELETE saml_sp_session \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                 RETURN BEFORE) GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        Ok(rows.first().map(|r| r.total).unwrap_or(0))
    }

    async fn cleanup_expired(&self) -> AxiamResult<u64> {
        // The grace a logout that ended the session gets: one run lifetime, so a
        // chain that revoked first and is still telling the other SPs finds its
        // rows. After that the chain has ended or expired.
        let ended_before = Utc::now() - Duration::seconds(SAML_LOGOUT_RUN_TTL_SECS);
        // A record link (`type::record(..).tenant_id`) reads the session row
        // itself and is NONE when it is not there: "the session row is gone".
        const GONE: &str = "(expires_at < time::now() \
             OR (type::record('session', session_id).tenant_id IS NONE \
                 AND (ended_at IS NONE OR ended_at < $ended_before)))";
        let mut counted = self
            .db
            .current()
            .query(format!(
                "SELECT count() AS total FROM saml_sp_session WHERE {GONE} GROUP ALL"
            ))
            .bind(("ended_before", ended_before))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CountRow> = counted.take(0).map_err(DbError::from)?;
        let total = rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .current()
            .query(format!("DELETE saml_sp_session WHERE {GONE}"))
            .bind(("ended_before", ended_before))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;
        Ok(total)
    }
}

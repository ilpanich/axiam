//! SurrealDB implementation of [`SamlLogoutRunRepository`] (G-2, T23.2.4, schema
//! v76): the logout chain of D-39 and the replay guard of D-38.
//!
//! See [`axiam_core::models::saml_slo`] for what a run is.
//!
//! # The replay guard
//!
//! `(tenant_id, replay_key)` is UNIQUE, with `replay_key` `{sp_id}:{request id}`
//! for an SP-initiated run and `idp:{row id}` for an IdP-initiated one (which
//! answers no request and so replays nothing). A second `LogoutRequest` with an
//! `ID` the SP already used is a unique violation, which is the replay answer
//! ([`AxiamError::ReplayDetected`], through the classifier every replay guard
//! shares). The row is kept — finished — until it expires, so the guard spans
//! its whole ten-minute life, longer than an `IssueInstant` is accepted in.
//!
//! # Consuming a response — the X6 two-layer arbiter
//!
//! The same shape as `saml_authn_request`: a guarded `UPDATE … WHERE
//! current_request_hash = $hash` inside an explicit transaction, so the deployed
//! engine aborts the loser of a race; then, in a **separate** query after the
//! commit, a read-back of the per-attempt nonce, so a racer whose write landed
//! but was overwritten learns it lost. The guard also names the answering SP: a
//! response from any other SP matches no row and consumes nothing.
//!
//! # No raw request `ID`
//!
//! The run holds the SHA-256 of the outbound request's `ID` (T-383). A database
//! read yields nothing a browser can present.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::saml_slo::{
    NewSamlLogoutRun, SAML_LOGOUT_RUN_TTL_SECS, SamlLogoutInitiator, SamlLogoutPlan,
    SamlLogoutProgress, SamlLogoutRun,
};
use axiam_core::repository::SamlLogoutRunRepository;
use chrono::{DateTime, Duration, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{
    CountRow, classify_replay_write_error, cleanup_expired_rows, is_transaction_conflict,
};

const SELECT_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, user_id, initiator_sp_id, \
     initiator_request_id, initiator_relay_state, queue, session_ids, current_sp_id, \
     partial, sessions_ended, sps_told, created_at, expires_at";

#[derive(Debug, SurrealValue)]
struct RunRow {
    record_id: String,
    tenant_id: String,
    user_id: Option<String>,
    initiator_sp_id: Option<String>,
    initiator_request_id: Option<String>,
    initiator_relay_state: Option<String>,
    queue: Vec<String>,
    session_ids: Vec<String>,
    current_sp_id: Option<String>,
    partial: bool,
    sessions_ended: i64,
    sps_told: i64,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl RunRow {
    fn try_into_model(self) -> Result<SamlLogoutRun, DbError> {
        let parse = |raw: &str, what: &str| {
            Uuid::parse_str(raw)
                .map_err(|_| DbError::Migration(format!("invalid {what} in saml_logout_run")))
        };
        let optional = |raw: &Option<String>, what: &str| -> Result<Option<Uuid>, DbError> {
            raw.as_deref().map(|r| parse(r, what)).transpose()
        };
        let many = |raw: &[String], what: &str| -> Result<Vec<Uuid>, DbError> {
            raw.iter().map(|r| parse(r, what)).collect()
        };
        Ok(SamlLogoutRun {
            id: parse(&self.record_id, "id")?,
            tenant_id: parse(&self.tenant_id, "tenant_id")?,
            user_id: optional(&self.user_id, "user_id")?,
            initiator_sp_id: optional(&self.initiator_sp_id, "initiator_sp_id")?,
            initiator_request_id: self.initiator_request_id,
            initiator_relay_state: self.initiator_relay_state,
            queue: many(&self.queue, "queue")?,
            session_ids: many(&self.session_ids, "session_ids")?,
            current_sp_id: optional(&self.current_sp_id, "current_sp_id")?,
            partial: self.partial,
            sessions_ended: u32::try_from(self.sessions_ended).unwrap_or(u32::MAX),
            sps_told: u32::try_from(self.sps_told).unwrap_or(u32::MAX),
            created_at: self.created_at,
            expires_at: self.expires_at,
        })
    }
}

fn id_strings(ids: &[Uuid]) -> Vec<String> {
    ids.iter().map(Uuid::to_string).collect()
}

/// SurrealDB implementation of the SAML logout-run repository.
pub struct SurrealSamlLogoutRunRepository<C: Connection> {
    db: DbHandle<C>,
}

// Manual Clone: no spurious `C: Clone` bound (the `saml_replay` pattern).
impl<C: Connection> Clone for SurrealSamlLogoutRunRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealSamlLogoutRunRepository<C> {
    /// Construct a repository over a database handle.
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }

    async fn fetch(&self, tenant_id: Uuid, run_id: Uuid) -> AxiamResult<Option<SamlLogoutRun>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM saml_logout_run \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id LIMIT 1"
            ))
            .bind(("id", run_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<RunRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(RunRow::try_into_model)
            .transpose()
            .map_err(Into::into)
    }
}

impl<C: Connection> SamlLogoutRunRepository for SurrealSamlLogoutRunRepository<C> {
    async fn claim(&self, input: NewSamlLogoutRun) -> AxiamResult<SamlLogoutRun> {
        let row_id = new_id();
        let (initiator_sp_id, replay_key) = match (input.initiator, &input.initiator_request_id) {
            (SamlLogoutInitiator::ServiceProvider(sp_id), Some(request_id)) => {
                (Some(sp_id), format!("{sp_id}:{request_id}"))
            }
            (SamlLogoutInitiator::ServiceProvider(_), None) => {
                return Err(AxiamError::Validation {
                    message: "an SP-initiated logout run needs the request id".into(),
                });
            }
            (SamlLogoutInitiator::Idp, _) => (None, format!("idp:{row_id}")),
        };
        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(SAML_LOGOUT_RUN_TTL_SECS);
        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('saml_logout_run', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = NONE, \
                 initiator_sp_id = $initiator_sp_id, \
                 initiator_request_id = $initiator_request_id, \
                 initiator_relay_state = $initiator_relay_state, \
                 replay_key = $replay_key, \
                 queue = [], \
                 session_ids = [], \
                 current_sp_id = NONE, \
                 current_request_hash = NONE, \
                 consumption_id = NONE, \
                 status = 'active', \
                 partial = false, \
                 sessions_ended = 0, \
                 sps_told = 0, \
                 created_at = $created_at, \
                 expires_at = $expires_at",
            )
            .bind(("id", row_id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("initiator_sp_id", initiator_sp_id.map(|id| id.to_string())))
            .bind(("initiator_request_id", input.initiator_request_id.clone()))
            .bind(("initiator_relay_state", input.initiator_relay_state.clone()))
            .bind(("replay_key", replay_key))
            .bind(("created_at", created_at))
            .bind(("expires_at", expires_at))
            .await
            .map_err(DbError::from)?;

        // The UNIQUE violation IS the answer: this request id was already used
        // with this SP.
        result.check().map_err(classify_replay_write_error)?;

        Ok(SamlLogoutRun {
            id: row_id,
            tenant_id: input.tenant_id,
            user_id: None,
            initiator_sp_id,
            initiator_request_id: input.initiator_request_id,
            initiator_relay_state: input.initiator_relay_state,
            queue: Vec::new(),
            session_ids: Vec::new(),
            current_sp_id: None,
            partial: false,
            sessions_ended: 0,
            sps_told: 0,
            created_at,
            expires_at,
        })
    }

    async fn plan(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        plan: SamlLogoutPlan,
    ) -> AxiamResult<SamlLogoutRun> {
        let ended = i64::try_from(plan.session_ids.len()).unwrap_or(i64::MAX);
        self.db
            .current()
            .query(
                "UPDATE type::record('saml_logout_run', $id) SET \
                 user_id = $user_id, queue = $queue, session_ids = $session_ids, \
                 partial = $partial, sessions_ended = $ended \
                 WHERE tenant_id = $tenant_id AND status = 'active'",
            )
            .bind(("id", run_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", plan.user_id.to_string()))
            .bind(("queue", id_strings(&plan.queue)))
            .bind(("session_ids", id_strings(&plan.session_ids)))
            .bind(("partial", plan.partial))
            .bind(("ended", ended))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| AxiamError::Database(e.to_string()))?;
        self.fetch(tenant_id, run_id)
            .await?
            .ok_or_else(|| AxiamError::NotFound {
                entity: "saml_logout_run".into(),
                id: run_id.to_string(),
            })
    }

    async fn progress(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        progress: SamlLogoutProgress,
    ) -> AxiamResult<()> {
        let (current_sp, current_hash) = match progress.outbound {
            Some((sp_id, hash)) => (Some(sp_id.to_string()), Some(hash)),
            None => (None, None),
        };
        self.db
            .current()
            .query(
                "UPDATE type::record('saml_logout_run', $id) SET \
                 queue = $queue, current_sp_id = $current_sp_id, \
                 current_request_hash = $current_hash, partial = $partial, \
                 sps_told = $told \
                 WHERE tenant_id = $tenant_id AND status = 'active'",
            )
            .bind(("id", run_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("queue", id_strings(&progress.queue)))
            .bind(("current_sp_id", current_sp))
            .bind(("current_hash", current_hash))
            .bind(("partial", progress.partial))
            .bind(("told", i64::from(progress.sps_told)))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| AxiamError::Database(e.to_string()))?;
        Ok(())
    }

    async fn consume_response(
        &self,
        tenant_id: Uuid,
        request_hash: &str,
        sp_id: Uuid,
    ) -> AxiamResult<Option<SamlLogoutRun>> {
        if request_hash.len() != 64 {
            return Ok(None);
        }
        // Layer 1: the guarded transition inside an explicit transaction.
        let nonce = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; \
                 LET $before = (UPDATE saml_logout_run \
                     SET current_request_hash = NONE, consumption_id = $nonce \
                     WHERE tenant_id = $tenant_id AND current_request_hash = $hash \
                     AND current_sp_id = $sp_id \
                     AND status = 'active' AND expires_at > time::now() \
                     RETURN BEFORE); \
                 SELECT {SELECT_FIELDS} FROM $before; \
                 COMMIT TRANSACTION"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", request_hash.to_string()))
            .bind(("sp_id", sp_id.to_string()))
            .bind(("nonce", nonce.clone()))
            .await;
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        // BEGIN=0, LET=1, SELECT=2, COMMIT=3.
        let rows: Vec<RunRow> = match result.take::<Vec<RunRow>>(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let record_id = row.record_id.clone();

        // Layer 2: outside, and after, the transaction above.
        let stored = self
            .db
            .current()
            .query(
                "SELECT VALUE consumption_id FROM saml_logout_run \
                 WHERE tenant_id = $tenant_id AND meta::id(id) = $id LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("id", record_id))
            .await;
        let mut stored = match stored {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let stored: Vec<Option<String>> = match stored.take::<Vec<Option<String>>>(0) {
            Ok(v) => v,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if stored.into_iter().flatten().next().as_deref() != Some(nonce.as_str()) {
            return Ok(None);
        }

        Ok(Some(row.try_into_model()?))
    }

    async fn get(&self, tenant_id: Uuid, run_id: Uuid) -> AxiamResult<Option<SamlLogoutRun>> {
        self.fetch(tenant_id, run_id).await
    }

    async fn finish(
        &self,
        tenant_id: Uuid,
        run_id: Uuid,
        partial: bool,
        sps_told: u32,
    ) -> AxiamResult<()> {
        self.db
            .current()
            .query(
                "UPDATE type::record('saml_logout_run', $id) SET \
                 status = 'finished', queue = [], current_sp_id = NONE, \
                 current_request_hash = NONE, partial = $partial, sps_told = $told \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", run_id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("partial", partial))
            .bind(("told", i64::from(sps_told)))
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| AxiamError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM (DELETE saml_logout_run \
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
        cleanup_expired_rows(&self.db, "saml_logout_run").await
    }
}

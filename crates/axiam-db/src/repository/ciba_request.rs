//! SurrealDB implementation of [`CibaRequestRepository`] (G-7, schema v80).
//!
//! # Two writers, so every transition carries its precondition
//!
//! A CIBA request is written by two parties who never coordinate: the user,
//! deciding on the identity pages, and the client, asking the token endpoint
//! whether the user has decided. Every write below is therefore one statement
//! whose `WHERE` clause holds the state it was prepared from (T-406's lesson):
//!
//! | write | conditional on |
//! |---|---|
//! | approve / deny | `status = 'pending'`, `version` the page read, the request's user, unexpired |
//! | mark expired | `status IN ['pending','approved']`, `version`, past `expires_at` |
//! | record a poll | the `last_polled_at` the token endpoint read (compare-and-set) |
//! | redeem | `status = 'approved'`, the client that started it, unexpired — the X6 arbiter |
//!
//! Polls deliberately do **not** bump `version`: a client polling every five
//! seconds would otherwise make every approval page's read stale before the
//! user could click.
//!
//! # Single use — the X6 two-layer arbiter
//!
//! [`CibaRequestRepository::redeem`] is `device_grant.redeem` with one more
//! guard (the client): a guarded `UPDATE … RETURN BEFORE` inside an explicit
//! transaction, so two concurrent redemptions conflict on one key and the
//! engine aborts the loser, and then a per-attempt nonce read back **after**
//! the commit in a query of its own, so a conflict the engine missed is still
//! caught unless the two commits interleave around the read-back. See
//! `device_grant.rs` for the measurements and why the read-back must stay
//! outside the transaction.
//!
//! # Ping-mode credentials are sealed
//!
//! A ping-mode request must keep its `auth_req_id` recoverable (the
//! notification body is that identifier) and the client's
//! `client_notification_token` (the bearer the notification presents). Both go
//! into one AES-256-GCM blob under `pki_encryption_key`, nonce in its own
//! column; no read of the table projects either column except
//! [`CibaRequestRepository::ping_credentials`]. With no key configured a
//! ping-mode request is refused with `ServiceUnavailable` rather than stored in
//! clear.

use axiam_auth::crypto::{decrypt_separate, encrypt_separate};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::id::new_id;
use axiam_core::models::ciba::{
    CibaApprovalEvidence, CibaDeliveryMode, CibaPingCredentials, CibaRequest, CibaRequestStatus,
    CreateCibaRequest,
};
use axiam_core::models::session::Amr;
use axiam_core::repository::CibaRequestRepository;
use axiam_core::secrets::{PKI_ENCRYPTION_KEY, env_var_name};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::is_transaction_conflict;

/// Every column a read projects. The sealed ping columns are not among them.
const SELECT_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, client_id, \
     auth_req_id_hash, user_id, scopes, binding_message, acr_values, resource, \
     delivery_mode, status, version, interval_secs, last_polled_at, expires_at, \
     approval_session_id, auth_time, acr, amr, decided_at, created_at";

#[derive(Debug, SurrealValue)]
struct CibaRequestRow {
    record_id: String,
    tenant_id: String,
    client_id: String,
    auth_req_id_hash: String,
    user_id: Option<String>,
    scopes: Vec<String>,
    binding_message: Option<String>,
    acr_values: Vec<String>,
    resource: Option<String>,
    delivery_mode: String,
    status: String,
    version: i64,
    interval_secs: i64,
    last_polled_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    approval_session_id: Option<String>,
    auth_time: Option<DateTime<Utc>>,
    acr: Option<String>,
    amr: Vec<String>,
    decided_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

fn parse_uuid(raw: &str, what: &str) -> Result<Uuid, DbError> {
    Uuid::parse_str(raw).map_err(|e| DbError::Migration(format!("invalid {what} UUID: {e}")))
}

impl CibaRequestRow {
    fn try_into_request(self) -> Result<CibaRequest, DbError> {
        let status = CibaRequestStatus::from_wire(&self.status).ok_or_else(|| {
            DbError::Migration(format!(
                "unrecognised CIBA request status {:?}",
                self.status
            ))
        })?;
        let delivery_mode = CibaDeliveryMode::from_wire(&self.delivery_mode).ok_or_else(|| {
            DbError::Migration(format!(
                "unrecognised CIBA delivery mode {:?}",
                self.delivery_mode
            ))
        })?;
        let user_id = match self.user_id.as_deref() {
            None | Some("") => None,
            Some(raw) => Some(parse_uuid(raw, "user")?),
        };
        // The evidence is all or nothing: a row with a session but no time is
        // not evidence of anything, and is read as none.
        let approval = match (
            self.approval_session_id.as_deref(),
            self.auth_time,
            self.acr,
        ) {
            (Some(session), Some(auth_time), Some(acr)) => Some(CibaApprovalEvidence {
                session_id: parse_uuid(session, "session")?,
                auth_time,
                acr,
                amr: Amr::decode_list(&self.amr),
            }),
            _ => None,
        };
        Ok(CibaRequest {
            id: parse_uuid(&self.record_id, "CIBA request")?,
            tenant_id: parse_uuid(&self.tenant_id, "tenant")?,
            client_id: self.client_id,
            auth_req_id_hash: self.auth_req_id_hash,
            user_id,
            scopes: self.scopes,
            binding_message: self.binding_message,
            acr_values: self.acr_values,
            resource: self.resource,
            delivery_mode,
            status,
            version: self.version.max(0) as u64,
            interval_secs: self.interval_secs.max(1) as u64,
            last_polled_at: self.last_polled_at,
            expires_at: self.expires_at,
            approval,
            decided_at: self.decided_at,
            created_at: self.created_at,
        })
    }
}

/// The sealed blob's plaintext.
#[derive(Serialize, Deserialize)]
struct PingPlaintext {
    auth_req_id: String,
    client_notification_token: String,
}

#[derive(SurrealValue)]
struct IdRow {
    #[allow(dead_code)]
    record_id: String,
}

/// SurrealDB implementation of the CIBA request repository.
pub struct SurrealCibaRequestRepository<C: Connection> {
    db: DbHandle<C>,
    /// `pki_encryption_key`, or `None` when it is not configured: then a
    /// ping-mode request is refused and everything else works.
    key: Option<[u8; 32]>,
}

impl<C: Connection> Clone for SurrealCibaRequestRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            key: self.key,
        }
    }
}

/// Redacting `Debug`: the key is the one thing here worth protecting.
impl<C: Connection> std::fmt::Debug for SurrealCibaRequestRepository<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SurrealCibaRequestRepository")
            .field("key_configured", &self.key.is_some())
            .finish_non_exhaustive()
    }
}

impl<C: Connection> SurrealCibaRequestRepository<C> {
    /// Build the repository. `key` is the 256-bit `pki_encryption_key`.
    pub fn new(db: impl Into<DbHandle<C>>, key: Option<[u8; 32]>) -> Self {
        Self { db: db.into(), key }
    }

    /// Whether ping-mode requests can be stored.
    #[must_use]
    pub fn has_encryption_key(&self) -> bool {
        self.key.is_some()
    }

    fn missing_key() -> AxiamError {
        AxiamError::ServiceUnavailable(format!(
            "a ping-mode CIBA request cannot be stored: {PKI_ENCRYPTION_KEY} ({}) is not \
             configured",
            env_var_name(PKI_ENCRYPTION_KEY)
        ))
    }

    async fn fetch_one(
        &self,
        query: String,
        binds: Vec<(&'static str, String)>,
    ) -> AxiamResult<Option<CibaRequest>> {
        let db = self.db.current();
        let mut builder = db.query(query);
        for bind in binds {
            builder = builder.bind(bind);
        }
        let mut result = builder.await.map_err(DbError::from)?;
        let rows: Vec<CibaRequestRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .map(CibaRequestRow::try_into_request)
            .transpose()
            .map_err(Into::into)
    }
}

/// Whether a guarded `UPDATE … RETURN meta::id(id) AS record_id` matched.
///
/// A conflicting concurrent write is "the precondition failed", not a fault.
fn matched(result: Result<surrealdb::IndexedResults, surrealdb::Error>) -> AxiamResult<bool> {
    let mut result = match result {
        Ok(r) => r,
        Err(e) if is_transaction_conflict(&e) => return Ok(false),
        Err(e) => return Err(DbError::from(e).into()),
    };
    let rows: Vec<IdRow> = match result.take(0) {
        Ok(rows) => rows,
        Err(e) if is_transaction_conflict(&e) => return Ok(false),
        Err(e) => return Err(DbError::from(e).into()),
    };
    Ok(!rows.is_empty())
}

impl<C: Connection> CibaRequestRepository for SurrealCibaRequestRepository<C> {
    async fn create(&self, input: CreateCibaRequest) -> AxiamResult<CibaRequest> {
        let id = new_id();
        let (ping_nonce, ping_ciphertext) = match &input.ping {
            None => (None, None),
            Some(creds) => {
                let key = self.key.as_ref().ok_or_else(Self::missing_key)?;
                let plaintext = Zeroizing::new(
                    serde_json::to_vec(&PingPlaintext {
                        auth_req_id: creds.auth_req_id.clone(),
                        client_notification_token: creds.client_notification_token.clone(),
                    })
                    .map_err(|_| {
                        AxiamError::Crypto("the ping credentials could not be encoded".into())
                    })?,
                );
                let (nonce, ciphertext) = encrypt_separate(key, &plaintext).map_err(|_| {
                    AxiamError::Crypto("the ping credentials could not be encrypted".into())
                })?;
                (Some(nonce), Some(ciphertext))
            }
        };

        let mut result = self
            .db
            .current()
            .query(format!(
                "CREATE type::record('ciba_request', $id) SET \
                 tenant_id = $tenant_id, \
                 client_id = $client_id, \
                 auth_req_id_hash = $hash, \
                 user_id = $user_id, \
                 scopes = $scopes, \
                 binding_message = $binding_message, \
                 acr_values = $acr_values, \
                 resource = $resource, \
                 delivery_mode = $delivery_mode, \
                 ping_ciphertext = $ping_ciphertext, \
                 ping_nonce = $ping_nonce, \
                 status = 'pending', \
                 version = 0, \
                 interval_secs = $interval_secs, \
                 last_polled_at = NONE, \
                 expires_at = $expires_at, \
                 approval_session_id = NONE, \
                 auth_time = NONE, \
                 acr = NONE, \
                 amr = [], \
                 decided_at = NONE, \
                 redemption_id = NONE, \
                 created_at = time::now() \
                 RETURN {SELECT_FIELDS}"
            ))
            .bind(("id", id.to_string()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("client_id", input.client_id))
            .bind(("hash", input.auth_req_id_hash))
            .bind(("user_id", input.user_id.map(|u| u.to_string())))
            .bind(("scopes", input.scopes))
            .bind(("binding_message", input.binding_message))
            .bind(("acr_values", input.acr_values))
            .bind(("resource", input.resource))
            .bind(("delivery_mode", input.delivery_mode.as_str().to_owned()))
            .bind(("ping_ciphertext", ping_ciphertext))
            .bind(("ping_nonce", ping_nonce))
            .bind(("interval_secs", input.interval_secs as i64))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<CibaRequestRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .next()
            .ok_or_else(|| DbError::Migration("CIBA request not returned after create".into()))?
            .try_into_request()
            .map_err(Into::into)
    }

    async fn get_by_hash(
        &self,
        tenant_id: Uuid,
        auth_req_id_hash: &str,
    ) -> AxiamResult<Option<CibaRequest>> {
        self.fetch_one(
            format!(
                "SELECT {SELECT_FIELDS} FROM ciba_request \
                 WHERE tenant_id = $tenant_id AND auth_req_id_hash = $hash"
            ),
            vec![
                ("tenant_id", tenant_id.to_string()),
                ("hash", auth_req_id_hash.to_owned()),
            ],
        )
        .await
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Option<CibaRequest>> {
        self.fetch_one(
            format!(
                "SELECT {SELECT_FIELDS} FROM ciba_request \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id"
            ),
            vec![("id", id.to_string()), ("tenant_id", tenant_id.to_string())],
        )
        .await
    }

    async fn list_pending_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        limit: u32,
    ) -> AxiamResult<Vec<CibaRequest>> {
        let mut result = self
            .db
            .current()
            .query(format!(
                "SELECT {SELECT_FIELDS} FROM ciba_request \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id \
                     AND status = 'pending' AND expires_at > time::now() \
                 ORDER BY expires_at ASC LIMIT $limit"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("limit", i64::from(limit)))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<CibaRequestRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(CibaRequestRow::try_into_request)
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    async fn approve(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_version: u64,
        user_id: Uuid,
        evidence: CibaApprovalEvidence,
    ) -> AxiamResult<bool> {
        matched(
            self.db
                .current()
                .query(
                    "UPDATE type::record('ciba_request', $id) SET \
                         status = 'approved', version = version + 1, \
                         approval_session_id = $session_id, auth_time = $auth_time, \
                         acr = $acr, amr = $amr, decided_at = time::now() \
                     WHERE tenant_id = $tenant_id AND status = 'pending' \
                         AND version = $version AND user_id = $user_id \
                         AND expires_at > time::now() \
                     RETURN meta::id(id) AS record_id",
                )
                .bind(("id", id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("version", expected_version as i64))
                .bind(("user_id", user_id.to_string()))
                .bind(("session_id", evidence.session_id.to_string()))
                .bind(("auth_time", evidence.auth_time))
                .bind(("acr", evidence.acr))
                .bind(("amr", Amr::encode_list(&evidence.amr)))
                .await,
        )
    }

    async fn deny(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_version: u64,
        user_id: Uuid,
    ) -> AxiamResult<bool> {
        matched(
            self.db
                .current()
                .query(
                    "UPDATE type::record('ciba_request', $id) SET \
                         status = 'denied', version = version + 1, decided_at = time::now() \
                     WHERE tenant_id = $tenant_id AND status = 'pending' \
                         AND version = $version AND user_id = $user_id \
                         AND expires_at > time::now() \
                     RETURN meta::id(id) AS record_id",
                )
                .bind(("id", id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("version", expected_version as i64))
                .bind(("user_id", user_id.to_string()))
                .await,
        )
    }

    async fn mark_expired(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected_version: u64,
    ) -> AxiamResult<bool> {
        matched(
            self.db
                .current()
                .query(
                    "UPDATE type::record('ciba_request', $id) SET \
                         status = 'expired', version = version + 1 \
                     WHERE tenant_id = $tenant_id AND status IN ['pending', 'approved'] \
                         AND version = $version AND expires_at <= time::now() \
                     RETURN meta::id(id) AS record_id",
                )
                .bind(("id", id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("version", expected_version as i64))
                .await,
        )
    }

    async fn record_poll(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        seen_last_polled_at: Option<DateTime<Utc>>,
        polled_at: DateTime<Utc>,
        interval_secs: u64,
    ) -> AxiamResult<bool> {
        // Compare-and-set on the value the caller read. `last_polled_at = NONE`
        // is its own spelling because NONE does not compare equal to a bound
        // value in SurrealQL.
        let guard = if seen_last_polled_at.is_some() {
            "last_polled_at = $seen"
        } else {
            "last_polled_at = NONE"
        };
        matched(
            self.db
                .current()
                .query(format!(
                    "UPDATE type::record('ciba_request', $id) SET \
                         last_polled_at = $polled_at, interval_secs = $interval \
                     WHERE tenant_id = $tenant_id AND {guard} \
                     RETURN meta::id(id) AS record_id"
                ))
                .bind(("id", id.to_string()))
                .bind(("tenant_id", tenant_id.to_string()))
                .bind(("polled_at", polled_at))
                .bind(("interval", interval_secs as i64))
                .bind(("seen", seen_last_polled_at))
                .await,
        )
    }

    async fn redeem(
        &self,
        tenant_id: Uuid,
        auth_req_id_hash: &str,
        client_id: &str,
    ) -> AxiamResult<Option<CibaRequest>> {
        // Layer 1: the guarded UPDATE inside an explicit transaction.
        let nonce = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; \
                 LET $before = (UPDATE ciba_request \
                     SET status = 'redeemed', version = version + 1, redemption_id = $nonce \
                     WHERE tenant_id = $tenant_id AND auth_req_id_hash = $hash \
                     AND client_id = $client_id \
                     AND status = 'approved' AND expires_at > time::now() \
                     RETURN BEFORE); \
                 SELECT {SELECT_FIELDS} FROM $before; \
                 COMMIT TRANSACTION"
            ))
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", auth_req_id_hash.to_owned()))
            .bind(("client_id", client_id.to_owned()))
            .bind(("nonce", nonce.clone()))
            .await;
        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        // BEGIN=0, LET=1, SELECT=2, COMMIT=3.
        let rows: Vec<CibaRequestRow> = match result.take::<Vec<CibaRequestRow>>(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Ok(None),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if rows.is_empty() {
            return Ok(None);
        }

        // Layer 2: outside, and after, the transaction above.
        let stored = self
            .db
            .current()
            .query(
                "SELECT VALUE redemption_id FROM ciba_request \
                 WHERE tenant_id = $tenant_id AND auth_req_id_hash = $hash LIMIT 1",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("hash", auth_req_id_hash.to_owned()))
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
            // Another redemption's write landed after ours: it holds the
            // request, and this one must not also mint a token set.
            return Ok(None);
        }

        rows.into_iter()
            .next()
            .map(CibaRequestRow::try_into_request)
            .transpose()
            .map_err(Into::into)
    }

    async fn ping_credentials(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AxiamResult<Option<CibaPingCredentials>> {
        #[derive(SurrealValue)]
        struct SealedRow {
            ping_ciphertext: Option<String>,
            ping_nonce: Option<String>,
        }
        let mut result = self
            .db
            .current()
            .query(
                "SELECT ping_ciphertext, ping_nonce FROM ciba_request \
                 WHERE meta::id(id) = $id AND tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let rows: Vec<SealedRow> = result.take(0).map_err(DbError::from)?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let (Some(ciphertext), Some(nonce)) = (row.ping_ciphertext, row.ping_nonce) else {
            return Ok(None);
        };
        let key = self.key.as_ref().ok_or_else(Self::missing_key)?;
        let plaintext =
            Zeroizing::new(decrypt_separate(key, &nonce, &ciphertext).map_err(|_| {
                AxiamError::Crypto(
                    "the CIBA ping credentials could not be decrypted: the stored value does \
                     not match the configured pki_encryption_key"
                        .into(),
                )
            })?);
        let decoded: PingPlaintext = serde_json::from_slice(&plaintext)
            .map_err(|_| AxiamError::Crypto("the CIBA ping credentials are malformed".into()))?;
        Ok(Some(CibaPingCredentials {
            auth_req_id: decoded.auth_req_id,
            client_notification_token: decoded.client_notification_token,
        }))
    }

    async fn sweep_expired(
        &self,
        now: DateTime<Utc>,
        retention: chrono::Duration,
    ) -> AxiamResult<u64> {
        // First mark, then delete: a request that expired a moment ago stays
        // long enough (`retention`) for a client still polling to be told
        // `expired_token` rather than `invalid_grant`.
        let cutoff = now - retention;
        let mut result = self
            .db
            .current()
            .query(
                "UPDATE ciba_request SET status = 'expired', version = version + 1 \
                     WHERE status IN ['pending', 'approved'] AND expires_at <= $now \
                     RETURN NONE; \
                 LET $removed = (DELETE ciba_request WHERE expires_at <= $cutoff RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id FROM $removed",
            )
            .bind(("now", now))
            .bind(("cutoff", cutoff))
            .await
            .map_err(DbError::from)?;
        // UPDATE=0, LET=1, SELECT=2.
        let removed: Vec<IdRow> = result.take(2).map_err(DbError::from)?;
        Ok(removed.len() as u64)
    }
}

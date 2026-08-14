//! SurrealDB implementation of [`AuthorizationCodeRepository`].
//!
//! # Why `consume` layers a transaction under a nonce
//!
//! An authorization code is single-use: redeeming it mints one token pair, and
//! a code redeemed twice is two token pairs from one authorization. The
//! precondition — unused, unexpired, right tenant, right client, right
//! `redirect_uri` — lives in the `WHERE` clause of the redeeming `UPDATE`,
//! which is what makes a later, non-concurrent replay match nothing.
//!
//! Single-use is a **guarantee, conditional on an attested persistent storage
//! engine**, carried by the same two layers as `permission_ticket.consume`,
//! `device_grant.redeem` and `pushed_auth_request.consume` (#302, T-164):
//!
//!   1. The guarded `UPDATE` runs inside an explicit `BEGIN`/`COMMIT`, so two
//!      concurrent redemptions conflict on one key and the deployed engine
//!      aborts the loser. This path had that layer implicitly before — its
//!      redemption was a single statement, which runs in the engine's own
//!      transaction — and writing it out changes nothing about the
//!      arbitration. It is written out anyway so all four consumes read the
//!      same and none of them depends on a reader knowing that a lone
//!      statement is atomic.
//!   2. A per-attempt nonce is read back **after** the commit, in a query of
//!      its own; only the caller whose `redemption_id` survived reports a
//!      redemption. This is what this path did not have before v37. It asks
//!      the engine for nothing, so it catches a conflict the engine silently
//!      missed — and conflict detection is not a documented SurrealDB
//!      guarantee, so a version bump could take layer 1 away without notice.
//!
//! The read-back **must** stay outside the transaction. Inside one, snapshot
//! isolation shows every racer its own write and every racer believes it won,
//! turning an occasional double redemption into a certain one — see
//! `SCHEMA_V31`, and `SCHEMA_V37` for why this path joined them.
//!
//! Losing either race answers exactly as an unknown code does: `NotFound`. A
//! caller that could distinguish "someone else just redeemed this" from "no
//! such code" could probe for live codes, and the token endpoint answers
//! `invalid_grant` for both regardless.

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::oauth2_client::{AuthorizationCode, CreateAuthorizationCode};
use axiam_core::repository::AuthorizationCodeRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

use crate::handle::DbHandle;
use crate::helpers::{CountRow, is_transaction_conflict, take_first_or_not_found};

/// Projected explicitly rather than `SELECT *` because the redeeming statement
/// now also writes `redemption_id`, which [`AuthCodeRowWithId`] does not carry
/// — naming the columns keeps the row type and the query in step instead of
/// relying on how the deserializer treats an unexpected key.
const CONSUME_FIELDS: &str = "meta::id(id) AS record_id, tenant_id, client_id, user_id, \
     code_hash, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, \
     session_id, expires_at, used, created_at";

/// Parse an optional stored UUID.
///
/// Empty string and absent both mean "no session": SurrealDB writes `NONE` as
/// absent, but a row migrated in from an earlier shape can carry `""`, and
/// treating that as a parse failure would make an old authorization code
/// unreadable rather than merely session-less.
fn parse_opt_uuid(raw: Option<&str>) -> Result<Option<Uuid>, DbError> {
    match raw {
        None | Some("") => Ok(None),
        Some(v) => Uuid::parse_str(v)
            .map(Some)
            .map_err(|e| DbError::Migration(format!("invalid session UUID: {e}"))),
    }
}

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
    #[surreal(default)]
    session_id: Option<String>,
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
    #[surreal(default)]
    session_id: Option<String>,
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
            session_id: parse_opt_uuid(self.session_id.as_deref())?,
            expires_at: self.expires_at,
            used: self.used,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the AuthorizationCode repository.
#[derive(Clone)]
pub struct SurrealAuthorizationCodeRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealAuthorizationCodeRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self { db }
    }
}

impl<C: Connection> AuthorizationCodeRepository for SurrealAuthorizationCodeRepository<C> {
    async fn create(&self, input: CreateAuthorizationCode) -> AxiamResult<AuthorizationCode> {
        let id = new_id();
        let id_str = id.to_string();

        let result = self
            .db
            .current()
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
                 session_id = $session_id, \
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
            .bind(("session_id", input.session_id.map(|id| id.to_string())))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<AuthCodeRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "oauth2_auth_code", &id_str)?;

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
            session_id: parse_opt_uuid(row.session_id.as_deref())?,
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
            .current()
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
        let row = take_first_or_not_found(
            rows,
            "oauth2_auth_code",
            &format!("code_hash={code_hash_owned}"),
        )?;

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

        // Two layers, in two queries (#302 / T-164 — see the module header).
        //
        // Layer 1, here: the guarded `UPDATE` inside an explicit transaction.
        // `used = false` is what makes a later, non-concurrent replay match
        // nothing; `client_id` and `redirect_uri` are matched inside the
        // statement rather than checked on the returned row, so a redemption
        // attempt with the wrong pair changes nothing and cannot burn a code
        // its holder is entitled to.
        //
        // Layer 2, in the SEPARATE query below: the per-attempt nonce read
        // back after this transaction has committed. It must not be folded in
        // here — under snapshot isolation every racer would see its own write
        // and believe it won (`SCHEMA_V31`, `SCHEMA_V37`).
        let redemption = new_id().to_string();
        let result = self
            .db
            .current()
            .query(format!(
                "BEGIN TRANSACTION; \
                 LET $claimed = (UPDATE oauth2_auth_code \
                     SET used = true, redemption_id = $redemption \
                  WHERE tenant_id = $tenant_id \
                    AND code_hash = $code_hash \
                    AND client_id = $client_id \
                    AND redirect_uri = $redirect_uri \
                    AND used = false \
                    AND expires_at > time::now()); \
                 SELECT {CONSUME_FIELDS} FROM $claimed; \
                 COMMIT TRANSACTION"
            ))
            .bind(("tenant_id", tenant_id_str.clone()))
            .bind(("code_hash", code_hash_owned.clone()))
            .bind(("client_id", client_id.to_string()))
            .bind(("redirect_uri", redirect_uri.to_string()))
            .bind(("redemption", redemption.clone()))
            .await;

        // A loser's abort is "someone else redeemed first", which is this
        // method's `NotFound` answer rather than a server fault; propagating
        // it would turn a correctly-refused replay into a 500.
        let not_found = || {
            DbError::NotFound {
                entity: "oauth2_auth_code".to_string(),
                id: format!("code_hash={code_hash_owned}"),
            }
            .into()
        };

        let mut result = match result {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Err(not_found()),
            Err(e) => return Err(DbError::from(e).into()),
        };

        // BEGIN=0, LET=1, SELECT=2, COMMIT=3.
        let rows: Vec<AuthCodeRowWithId> = match result.take::<Vec<AuthCodeRowWithId>>(2) {
            Ok(rows) => rows,
            Err(e) if is_transaction_conflict(&e) => return Err(not_found()),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let row = take_first_or_not_found(
            rows,
            "oauth2_auth_code",
            &format!("code_hash={code_hash_owned}"),
        )?;

        // Layer 2: outside, and after, the transaction above.
        let stored = self
            .db
            .current()
            .query(
                "SELECT VALUE redemption_id FROM oauth2_auth_code \
                 WHERE tenant_id = $tenant_id AND code_hash = $code_hash LIMIT 1",
            )
            .bind(("tenant_id", tenant_id_str))
            .bind(("code_hash", code_hash_owned.clone()))
            .await;
        let mut stored = match stored {
            Ok(r) => r,
            Err(e) if is_transaction_conflict(&e) => return Err(not_found()),
            Err(e) => return Err(DbError::from(e).into()),
        };
        let stored: Vec<Option<String>> = match stored.take::<Vec<Option<String>>>(0) {
            Ok(v) => v,
            Err(e) if is_transaction_conflict(&e) => return Err(not_found()),
            Err(e) => return Err(DbError::from(e).into()),
        };
        if stored.into_iter().flatten().next().as_deref() != Some(redemption.as_str()) {
            // Our write landed but another redemption's landed after it. That
            // caller holds the code; this one must not also mint a token pair.
            // The code is spent either way, so `used` staying true is correct.
            return Err(not_found());
        }

        row.try_into_auth_code().map_err(Into::into)
    }

    async fn delete_expired(&self) -> AxiamResult<u64> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM oauth2_auth_code \
                 WHERE expires_at < time::now() OR used = true GROUP ALL",
            )
            .await
            .map_err(DbError::from)?;

        let count_rows: Vec<CountRow> = result.take(0).map_err(DbError::from)?;
        let count = count_rows.first().map(|r| r.total).unwrap_or(0);

        self.db
            .current()
            .query(
                "DELETE FROM oauth2_auth_code \
                 WHERE expires_at < time::now() OR used = true",
            )
            .await
            .map_err(DbError::from)?;

        Ok(count)
    }
}

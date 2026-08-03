//! SurrealDB implementation of [`SessionRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::id::new_id;
use axiam_core::models::session::{CreateSession, Session};
use axiam_core::repository::SessionRepository;
use chrono::{DateTime, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use std::sync::Arc;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::{CountRow, take_first_or_not_found};
use crate::session_validation_cache::SessionValidationCache;

#[derive(Debug, SurrealValue)]
struct SessionRow {
    tenant_id: String,
    user_id: String,
    token_hash: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, SurrealValue)]
struct SessionRowWithId {
    record_id: String,
    tenant_id: String,
    user_id: String,
    token_hash: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    expires_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

fn row_to_session(row: SessionRow, id: Uuid) -> Result<Session, DbError> {
    let tenant_id = Uuid::parse_str(&row.tenant_id)
        .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
    let user_id = Uuid::parse_str(&row.user_id)
        .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
    Ok(Session {
        id,
        tenant_id,
        user_id,
        token_hash: row.token_hash,
        ip_address: row.ip_address,
        user_agent: row.user_agent,
        expires_at: row.expires_at,
        created_at: row.created_at,
    })
}

impl SessionRowWithId {
    fn try_into_session(self) -> Result<Session, DbError> {
        let id = Uuid::parse_str(&self.record_id)
            .map_err(|e| DbError::Migration(format!("invalid UUID: {e}")))?;
        let tenant_id = Uuid::parse_str(&self.tenant_id)
            .map_err(|e| DbError::Migration(format!("invalid tenant UUID: {e}")))?;
        let user_id = Uuid::parse_str(&self.user_id)
            .map_err(|e| DbError::Migration(format!("invalid user UUID: {e}")))?;
        Ok(Session {
            id,
            tenant_id,
            user_id,
            token_hash: self.token_hash,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            expires_at: self.expires_at,
            created_at: self.created_at,
        })
    }
}

/// SurrealDB implementation of the Session repository.
pub struct SurrealSessionRepository<C: Connection> {
    db: DbHandle<C>,
    /// I6: optional short-TTL validity cache. `None` (the default) makes every
    /// method below byte-identical to the pre-I6 behaviour.
    validation_cache: Option<Arc<SessionValidationCache>>,
}

// Manual Clone impl (not derive): `#[derive(Clone)]` would add a `C: Clone`
// bound that generic `C: Connection` callers (e.g. REST handlers) cannot
// satisfy, silently cloning a `&Self` instead. Matches SurrealUserRepository.
impl<C: Connection> Clone for SurrealSessionRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            // Clones share the same cache: `axiam-server` clones this repository
            // into several services, and they must agree on what has been
            // revoked.
            validation_cache: self.validation_cache.clone(),
        }
    }
}

impl<C: Connection> SurrealSessionRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        let db = db.into();
        Self {
            db,
            validation_cache: None,
        }
    }

    /// Attach a [`SessionValidationCache`] (I6).
    ///
    /// Only [`Self::is_session_active_checked`] reads the cache; every delete path in
    /// this file writes to it. Attaching a cache therefore cannot desynchronise
    /// it from the rows this repository owns — see the invalidation contract in
    /// [`crate::session_validation_cache`].
    pub fn with_validation_cache(mut self, cache: Arc<SessionValidationCache>) -> Self {
        self.validation_cache = Some(cache);
        self
    }

    /// The attached validity cache, if any.
    pub fn validation_cache(&self) -> Option<&Arc<SessionValidationCache>> {
        self.validation_cache.as_ref()
    }

    /// Is the session behind an access token's `jti` still usable? (D-15 /
    /// REQ-7.)
    ///
    /// Named `_checked` rather than `is_session_active` so it can never be
    /// confused with `axiam_api_rest::SessionValidator::is_session_active`,
    /// which delegates here — an accidental name collision there would recurse
    /// forever.
    ///
    /// This is the per-request session-revocation check every authenticated
    /// REST request performs. Without a cache attached it is exactly
    /// `get_by_id(..).is_ok() && expires_at > now` — one SurrealDB read per
    /// request. With one attached, a repeat check inside the TTL is answered in
    /// process.
    ///
    /// Negative answers are never cached (see the module docs), so a revoked or
    /// unknown session always costs a read and can never be resurrected.
    pub async fn is_session_active_checked(&self, tenant_id: Uuid, session_id: Uuid) -> bool {
        if let Some(cache) = &self.validation_cache
            && cache.get(tenant_id, session_id) == Some(true)
        {
            return true;
        }

        match self.get_by_id(tenant_id, session_id).await {
            Ok(session) if session.expires_at > Utc::now() => {
                if let Some(cache) = &self.validation_cache {
                    cache.insert_valid(tenant_id, session_id, session.user_id, session.expires_at);
                }
                true
            }
            _ => false,
        }
    }
}

impl<C: Connection> SessionRepository for SurrealSessionRepository<C> {
    async fn create(&self, input: CreateSession) -> AxiamResult<Session> {
        let id = new_id();
        let id_str = id.to_string();

        let result = self
            .db
            .current()
            .query(
                "CREATE type::record('session', $id) SET \
                 tenant_id = $tenant_id, \
                 user_id = $user_id, \
                 token_hash = $token_hash, \
                 ip_address = $ip_address, \
                 user_agent = $user_agent, \
                 expires_at = $expires_at",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", input.tenant_id.to_string()))
            .bind(("user_id", input.user_id.to_string()))
            .bind(("token_hash", input.token_hash))
            .bind(("ip_address", input.ip_address))
            .bind(("user_agent", input.user_agent))
            .bind(("expires_at", input.expires_at))
            .await
            .map_err(DbError::from)?;

        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let rows: Vec<SessionRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "session", &id_str)?;

        row_to_session(row, id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Session> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT * FROM type::record('session', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SessionRow> = result.take(0).map_err(DbError::from)?;
        let row = take_first_or_not_found(rows, "session", &id_str)?;

        row_to_session(row, id).map_err(Into::into)
    }

    async fn get_by_token_hash(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<Session> {
        let token_hash_owned = token_hash.to_string();

        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM session \
                 WHERE tenant_id = $tenant_id AND token_hash = $token_hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("token_hash", token_hash_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SessionRowWithId> = result.take(0).map_err(DbError::from)?;
        let row =
            take_first_or_not_found(rows, "session", &format!("token_hash={token_hash_owned}"))?;

        row.try_into_session().map_err(Into::into)
    }

    async fn invalidate(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query(
                "DELETE type::record('session', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        // I6: drop the validity entry in the same call that removes the row, so
        // a logout can never be outlived by a cached "still valid" answer on
        // this replica.
        //
        // ORDERING (residual 2, security re-verification 2026-08-03): this MUST
        // stay above the `.check()` below. Invalidation is infallible and
        // idempotent, and dropping a cache entry for a row that turned out NOT
        // to be deleted only costs one avoidable re-read — whereas the reverse
        // order would let a newly-fallible step strand a *positive* cache entry
        // for a session the DELETE did remove.
        if let Some(cache) = &self.validation_cache {
            cache.invalidate(tenant_id, id);
        }

        // OBS-3 (security re-verification 2026-08-03): a `DELETE` that fails at
        // the *statement* level still returns `Ok` from the `.await` — only
        // `.check()` surfaces it. Without this, logout / password-reset session
        // revocation / MFA reset were told "revoked" when nothing was deleted.
        // No `take()` here, so no deserialization is involved: this can only
        // fail when the statement itself did.
        result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(())
    }

    async fn consume(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<bool> {
        // NEW-3: `RETURN BEFORE` yields the pre-delete row; a non-empty result
        // means THIS statement removed the session. SurrealDB serializes two
        // concurrent DELETEs on the same record, so exactly one caller sees a
        // non-empty BEFORE image — the single-use gate for refresh rotation.
        let result = self
            .db
            .current()
            .query(
                "DELETE type::record('session', $id) \
                 WHERE tenant_id = $tenant_id RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        // I6: invalidate unconditionally — whether or not this caller won the
        // single-use race, the row is gone once any caller consumed it.
        //
        // This MUST come before `take(0)` (security re-verification
        // 2026-08-03, residual 2). The DELETE has already committed by the
        // time the `.await` returns `Ok`; if the BEFORE image then failed to
        // deserialize, an early `?` would leave a *positive* cache entry live
        // for up to the TTL — i.e. a deleted session would keep validating.
        // Invalidation is infallible and idempotent, so running it first is
        // free.
        if let Some(cache) = &self.validation_cache {
            cache.invalidate(tenant_id, id);
        }

        // OBS-3: `.check()` before `take(0)` so a statement-level failure is
        // reported as such rather than as a "no rows" (`won == false`) answer.
        // `take(0)` alone would already surface it for this single-statement
        // query; the explicit check keeps all five delete paths uniform.
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let deleted: Vec<SessionRow> = result.take(0).map_err(DbError::from)?;
        Ok(!deleted.is_empty())
    }

    async fn invalidate_user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        let result = self
            .db
            .current()
            .query("DELETE session WHERE tenant_id = $tenant_id AND user_id = $user_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        // I6: every session of this user just disappeared.
        //
        // ORDERING: above `.check()` for the same reason as `invalidate` —
        // see the note there (residual 2).
        if let Some(cache) = &self.validation_cache {
            cache.invalidate_user(tenant_id, user_id, None);
        }

        // OBS-3: propagate a statement-level DELETE failure instead of
        // reporting a revocation that may not have happened.
        result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(())
    }

    async fn invalidate_user_sessions_except(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> AxiamResult<u64> {
        // DELETE all sessions for this user in this tenant EXCEPT the
        // current one (identified by its record ID). RETURN BEFORE gives us
        // the deleted rows so we can count them.
        let result = self
            .db
            .current()
            .query(
                "DELETE session \
                 WHERE tenant_id = $tenant_id \
                   AND user_id = $user_id \
                   AND id != type::record('session', $current_session_id) \
                 RETURN BEFORE",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .bind(("current_session_id", current_session_id.to_string()))
            .await
            .map_err(DbError::from)?;

        // I6: same set, minus the session the caller deliberately kept.
        //
        // Ordered before `take(0)` for the same reason as `consume` — the
        // DELETE is already committed once the `.await` returns, so a
        // deserialize failure of the BEFORE image must not be able to strand a
        // positive cache entry for a session that no longer exists
        // (residual 2).
        if let Some(cache) = &self.validation_cache {
            cache.invalidate_user(tenant_id, user_id, Some(current_session_id));
        }

        // OBS-3: uniform with the other four delete paths — a statement-level
        // failure must never be reported as "0 sessions deleted".
        let mut result = result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        let deleted: Vec<SessionRow> = result.take(0).map_err(DbError::from)?;
        Ok(deleted.len() as u64)
    }

    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Session>> {
        let mut result = self
            .db
            .current()
            .query(
                "SELECT meta::id(id) AS record_id, * FROM session \
                 WHERE tenant_id = $tenant_id AND user_id = $user_id",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SessionRowWithId> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_session().map_err(Into::into))
            .collect()
    }

    async fn cleanup_expired(&self, tenant_id: Uuid) -> AxiamResult<u64> {
        // Count expired sessions first, then delete.
        let mut count_result = self
            .db
            .current()
            .query(
                "SELECT count() AS total FROM session \
                 WHERE tenant_id = $tenant_id AND expires_at < time::now() \
                 GROUP ALL",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;
        let count_rows: Vec<CountRow> = count_result.take(0).map_err(DbError::from)?;
        let total = count_rows.first().map(|r| r.total).unwrap_or(0);

        let result = self
            .db
            .current()
            .query("DELETE session WHERE tenant_id = $tenant_id AND expires_at < time::now()")
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        // I6: this deletes by predicate, not by id, so the cache cannot know
        // which entries went. Dropping the whole tenant is the conservative
        // choice; entries for expired sessions could not have been served
        // anyway (`get` re-checks `expires_at`), so this only costs a few
        // avoidable re-reads on a periodic janitor run.
        //
        // ORDERING: above `.check()`, per residual 2.
        if let Some(cache) = &self.validation_cache {
            cache.invalidate_tenant(tenant_id);
        }

        // OBS-3: the janitor must not log "N sessions reaped" when the DELETE
        // statement failed. `total` is a pre-delete count, so returning it
        // after a failed DELETE would be doubly misleading.
        result
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::session::CreateSession;
    use chrono::Duration;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        crate::schema::run_migrations(&db).await.unwrap();
        db
    }

    #[tokio::test]
    async fn list_by_user_returns_only_target_users_sessions() {
        let db = setup_db().await;
        let repo = SurrealSessionRepository::new(db);
        let tenant_id = Uuid::new_v4();
        let other_tenant_id = Uuid::new_v4();
        let target_user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();

        let expires = Utc::now() + Duration::hours(1);

        // 2 sessions for the target user in the target tenant.
        for i in 0..2 {
            repo.create(CreateSession {
                tenant_id,
                user_id: target_user_id,
                token_hash: format!("target-token-hash-{i}"),
                ip_address: Some("127.0.0.1".into()),
                user_agent: Some("test-agent".into()),
                expires_at: expires,
            })
            .await
            .unwrap();
        }

        // 1 session for a different user in the same tenant.
        repo.create(CreateSession {
            tenant_id,
            user_id: other_user_id,
            token_hash: "other-user-token-hash".into(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("test-agent".into()),
            expires_at: expires,
        })
        .await
        .unwrap();

        // 1 session for the target user but in a DIFFERENT tenant — must be
        // excluded (tenant isolation).
        repo.create(CreateSession {
            tenant_id: other_tenant_id,
            user_id: target_user_id,
            token_hash: "cross-tenant-token-hash".into(),
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("test-agent".into()),
            expires_at: expires,
        })
        .await
        .unwrap();

        let sessions = repo.list_by_user(tenant_id, target_user_id).await.unwrap();
        assert_eq!(
            sessions.len(),
            2,
            "expected exactly the target user's 2 sessions"
        );
        for session in &sessions {
            assert_eq!(session.tenant_id, tenant_id);
            assert_eq!(session.user_id, target_user_id);
        }
    }

    // ------------------------------------------------------------------
    // OBS-3 — statement-level DELETE failures must propagate
    // (security-analysis-2026-08-02 §11.3)
    // ------------------------------------------------------------------

    /// Forces every `DELETE session` in this database to fail at the
    /// **statement** level, which is the exact failure mode OBS-3 is about:
    /// the `.await` still returns `Ok(Response)`, and only `.check()` (or a
    /// `take()`) surfaces the error.
    ///
    /// §10.7/residual 2 recorded that "the repository takes a concrete
    /// `Surreal<C>` rather than a mockable trait, so there is no seam". That
    /// is true of the *connection*, but SurrealDB provides one inside the
    /// database: a `DEFINE EVENT … THEN THROW` on the DELETE event makes the
    /// server itself fail the statement. No mock, no fake — the real embedded
    /// engine returns the real error shape.
    async fn poison_session_deletes(db: &Surreal<surrealdb::engine::local::Db>) {
        db.query(
            "DEFINE EVENT session_delete_poison ON TABLE session \
             WHEN $event = 'DELETE' THEN { THROW 'poisoned delete' }",
        )
        .await
        .expect("define poison event")
        .check()
        .expect("poison event definition must itself succeed");
    }

    async fn seed_session(
        repo: &SurrealSessionRepository<surrealdb::engine::local::Db>,
        tenant_id: Uuid,
        user_id: Uuid,
        suffix: &str,
    ) -> Session {
        repo.create(CreateSession {
            tenant_id,
            user_id,
            token_hash: format!("hash-{suffix}"),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap()
    }

    /// OBS-3: all five session-deleting methods must return `Err` when the
    /// DELETE statement fails, instead of reporting a revocation that never
    /// happened. Before the fix, `invalidate`, `invalidate_user_sessions` and
    /// `cleanup_expired` returned `Ok` here.
    #[tokio::test]
    async fn every_delete_path_propagates_a_statement_level_failure() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        // `invalidate`
        let db = setup_db().await;
        let repo = SurrealSessionRepository::new(db.clone());
        let s = seed_session(&repo, tenant_id, user_id, "a").await;
        poison_session_deletes(&db).await;
        assert!(
            repo.invalidate(tenant_id, s.id).await.is_err(),
            "invalidate must not report success when the DELETE statement failed"
        );

        // `consume`
        let db = setup_db().await;
        let repo = SurrealSessionRepository::new(db.clone());
        let s = seed_session(&repo, tenant_id, user_id, "b").await;
        poison_session_deletes(&db).await;
        assert!(
            repo.consume(tenant_id, s.id).await.is_err(),
            "consume must not report `false` (lost the race) for a failed statement"
        );

        // `invalidate_user_sessions`
        let db = setup_db().await;
        let repo = SurrealSessionRepository::new(db.clone());
        seed_session(&repo, tenant_id, user_id, "c").await;
        poison_session_deletes(&db).await;
        assert!(
            repo.invalidate_user_sessions(tenant_id, user_id)
                .await
                .is_err(),
            "invalidate_user_sessions must not report success when the DELETE failed"
        );

        // `invalidate_user_sessions_except`
        let db = setup_db().await;
        let repo = SurrealSessionRepository::new(db.clone());
        let keep = seed_session(&repo, tenant_id, user_id, "d").await;
        seed_session(&repo, tenant_id, user_id, "e").await;
        poison_session_deletes(&db).await;
        assert!(
            repo.invalidate_user_sessions_except(tenant_id, user_id, keep.id)
                .await
                .is_err(),
            "invalidate_user_sessions_except must not report `0 deleted` for a failed statement"
        );

        // `cleanup_expired`
        let db = setup_db().await;
        let repo = SurrealSessionRepository::new(db.clone());
        repo.create(CreateSession {
            tenant_id,
            user_id,
            token_hash: "hash-expired".into(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() - Duration::hours(1),
        })
        .await
        .unwrap();
        poison_session_deletes(&db).await;
        assert!(
            repo.cleanup_expired(tenant_id).await.is_err(),
            "cleanup_expired must not return a pre-delete count when the DELETE failed"
        );
    }

    /// Residual 2 (cache-invalidation ordering) must survive OBS-3 making
    /// these paths fallible: the cache entry is dropped **before** the newly
    /// added `.check()`, so an erroring DELETE can never leave a positive
    /// "still valid" entry behind.
    ///
    /// This is the regression test §10.7 could not write — the poison event
    /// above supplies the failing step that did not previously exist.
    #[tokio::test]
    async fn cache_is_invalidated_before_the_fallible_step_on_every_path() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        /// Builds a repo whose cache holds a live positive entry for each of
        /// `n` fresh sessions, optionally adds `expired` already-expired rows
        /// (which `cleanup_expired` needs in order to delete anything at all,
        /// and which are never cached because the cache is positive-only),
        /// then poisons DELETE.
        async fn armed(
            tenant_id: Uuid,
            user_id: Uuid,
            n: usize,
            expired: usize,
        ) -> (
            SurrealSessionRepository<surrealdb::engine::local::Db>,
            Arc<SessionValidationCache>,
            Vec<Session>,
        ) {
            let db = setup_db().await;
            let cache = Arc::new(SessionValidationCache::new(std::time::Duration::from_secs(
                300,
            )));
            let repo =
                SurrealSessionRepository::new(db.clone()).with_validation_cache(cache.clone());
            let mut sessions = Vec::new();
            for i in 0..n {
                let s = seed_session(&repo, tenant_id, user_id, &format!("{i}")).await;
                assert!(
                    repo.is_session_active_checked(tenant_id, s.id).await,
                    "session must warm the cache before the delete path runs"
                );
                sessions.push(s);
            }
            for i in 0..expired {
                repo.create(CreateSession {
                    tenant_id,
                    user_id,
                    token_hash: format!("hash-expired-{i}"),
                    ip_address: None,
                    user_agent: None,
                    expires_at: Utc::now() - Duration::hours(1),
                })
                .await
                .unwrap();
            }
            assert_eq!(cache.len(), n, "cache must be warm");
            poison_session_deletes(&db).await;
            (repo, cache, sessions)
        }

        // `invalidate`
        let (repo, cache, sessions) = armed(tenant_id, user_id, 1, 0).await;
        assert!(repo.invalidate(tenant_id, sessions[0].id).await.is_err());
        assert_eq!(
            cache.len(),
            0,
            "invalidate: cache entry must be dropped even though the DELETE failed"
        );

        // `consume`
        let (repo, cache, sessions) = armed(tenant_id, user_id, 1, 0).await;
        assert!(repo.consume(tenant_id, sessions[0].id).await.is_err());
        assert_eq!(cache.len(), 0, "consume: cache entry must be dropped");

        // `invalidate_user_sessions`
        let (repo, cache, _) = armed(tenant_id, user_id, 2, 0).await;
        assert!(
            repo.invalidate_user_sessions(tenant_id, user_id)
                .await
                .is_err()
        );
        assert_eq!(
            cache.len(),
            0,
            "invalidate_user_sessions: all of the user's entries must be dropped"
        );

        // `invalidate_user_sessions_except` — the kept session stays cached by
        // design; every other entry must go.
        let (repo, cache, sessions) = armed(tenant_id, user_id, 2, 0).await;
        assert!(
            repo.invalidate_user_sessions_except(tenant_id, user_id, sessions[0].id)
                .await
                .is_err()
        );
        assert_eq!(
            cache.len(),
            1,
            "invalidate_user_sessions_except: only the deliberately kept session may remain"
        );

        // `cleanup_expired`
        let (repo, cache, _) = armed(tenant_id, user_id, 2, 1).await;
        assert!(repo.cleanup_expired(tenant_id).await.is_err());
        assert_eq!(
            cache.len(),
            0,
            "cleanup_expired: the tenant's entries must be dropped"
        );
    }

    /// The happy path is unchanged by OBS-3: every delete path still returns
    /// `Ok`, still removes the rows, and still clears the cache. Guards
    /// against a `.check()` that rejects an ordinary successful DELETE.
    #[tokio::test]
    async fn delete_paths_still_succeed_and_clear_the_cache() {
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let db = setup_db().await;
        let cache = Arc::new(SessionValidationCache::new(std::time::Duration::from_secs(
            300,
        )));
        let repo = SurrealSessionRepository::new(db).with_validation_cache(cache.clone());

        let a = seed_session(&repo, tenant_id, user_id, "1").await;
        let b = seed_session(&repo, tenant_id, user_id, "2").await;
        let c = seed_session(&repo, tenant_id, user_id, "3").await;
        for s in [&a, &b, &c] {
            assert!(repo.is_session_active_checked(tenant_id, s.id).await);
        }
        assert_eq!(cache.len(), 3);

        repo.invalidate(tenant_id, a.id).await.unwrap();
        assert!(repo.get_by_id(tenant_id, a.id).await.is_err());
        assert_eq!(cache.len(), 2);

        assert!(repo.consume(tenant_id, b.id).await.unwrap());
        assert!(
            !repo.consume(tenant_id, b.id).await.unwrap(),
            "second consume of the same session must lose the single-use race"
        );
        assert_eq!(cache.len(), 1);

        assert_eq!(
            repo.invalidate_user_sessions_except(tenant_id, user_id, c.id)
                .await
                .unwrap(),
            0,
            "c is the only session left and it is the one being kept"
        );
        repo.invalidate_user_sessions(tenant_id, user_id)
            .await
            .unwrap();
        assert!(repo.get_by_id(tenant_id, c.id).await.is_err());
        assert_eq!(cache.len(), 0);

        // `cleanup_expired` over an empty/all-fresh table still succeeds.
        assert_eq!(repo.cleanup_expired(tenant_id).await.unwrap(), 0);
    }
}

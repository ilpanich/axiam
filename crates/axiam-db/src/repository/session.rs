//! SurrealDB implementation of [`SessionRepository`].

use axiam_core::error::AxiamResult;
use axiam_core::models::session::{CreateSession, Session};
use axiam_core::repository::SessionRepository;
use chrono::{DateTime, Utc};
use surrealdb::{Connection, Surreal};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;

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

#[derive(Debug, SurrealValue)]
struct CountRow {
    total: u64,
}

/// SurrealDB implementation of the Session repository.
pub struct SurrealSessionRepository<C: Connection> {
    db: Surreal<C>,
}

// Manual Clone impl (not derive): `#[derive(Clone)]` would add a `C: Clone`
// bound that generic `C: Connection` callers (e.g. REST handlers) cannot
// satisfy, silently cloning a `&Self` instead. Matches SurrealUserRepository.
impl<C: Connection> Clone for SurrealSessionRepository<C> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
        }
    }
}

impl<C: Connection> SurrealSessionRepository<C> {
    pub fn new(db: Surreal<C>) -> Self {
        Self { db }
    }
}

impl<C: Connection> SessionRepository for SurrealSessionRepository<C> {
    async fn create(&self, input: CreateSession) -> AxiamResult<Session> {
        let id = Uuid::new_v4();
        let id_str = id.to_string();

        let result = self
            .db
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
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "session".into(),
            id: id_str,
        })?;

        row_to_session(row, id).map_err(Into::into)
    }

    async fn get_by_id(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<Session> {
        let id_str = id.to_string();

        let mut result = self
            .db
            .query(
                "SELECT * FROM type::record('session', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id_str.clone()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SessionRow> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "session".into(),
            id: id_str,
        })?;

        row_to_session(row, id).map_err(Into::into)
    }

    async fn get_by_token_hash(&self, tenant_id: Uuid, token_hash: &str) -> AxiamResult<Session> {
        let token_hash_owned = token_hash.to_string();

        let mut result = self
            .db
            .query(
                "SELECT meta::id(id) AS record_id, * FROM session \
                 WHERE tenant_id = $tenant_id AND token_hash = $token_hash",
            )
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("token_hash", token_hash_owned.clone()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<SessionRowWithId> = result.take(0).map_err(DbError::from)?;
        let row = rows.into_iter().next().ok_or_else(|| DbError::NotFound {
            entity: "session".into(),
            id: format!("token_hash={token_hash_owned}"),
        })?;

        row.try_into_session().map_err(Into::into)
    }

    async fn invalidate(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.db
            .query(
                "DELETE type::record('session', $id) \
                 WHERE tenant_id = $tenant_id",
            )
            .bind(("id", id.to_string()))
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }

    async fn invalidate_user_sessions(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        self.db
            .query("DELETE session WHERE tenant_id = $tenant_id AND user_id = $user_id")
            .bind(("tenant_id", tenant_id.to_string()))
            .bind(("user_id", user_id.to_string()))
            .await
            .map_err(DbError::from)?;

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
        let mut result = self
            .db
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

        let deleted: Vec<SessionRow> = result.take(0).map_err(DbError::from)?;
        Ok(deleted.len() as u64)
    }

    async fn list_by_user(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<Vec<Session>> {
        let mut result = self
            .db
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

        self.db
            .query("DELETE session WHERE tenant_id = $tenant_id AND expires_at < time::now()")
            .bind(("tenant_id", tenant_id.to_string()))
            .await
            .map_err(DbError::from)?;

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
        assert_eq!(sessions.len(), 2, "expected exactly the target user's 2 sessions");
        for session in &sessions {
            assert_eq!(session.tenant_id, tenant_id);
            assert_eq!(session.user_id, target_user_id);
        }
    }
}

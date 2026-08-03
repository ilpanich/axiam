//! I6 — integration tests for the session-validation cache wired into
//! [`SurrealSessionRepository`].
//!
//! The property under test is not "it is fast" but "it cannot be wrong":
//!
//! * with no cache attached the behaviour is exactly the pre-I6 read,
//! * with a cache attached a repeat check inside the TTL is served without
//!   touching the database (proved by deleting the row *behind the
//!   repository's back* and observing the cached answer),
//! * every session-deleting method on the repository drops the entry, so a
//!   revocation performed through the API is never outlived by the cache,
//! * entries are tenant-scoped.

use std::sync::Arc;
use std::time::Duration;

use axiam_core::models::session::CreateSession;
use axiam_core::repository::SessionRepository;
use axiam_db::SessionValidationCache;
use axiam_db::repository::SurrealSessionRepository;
use chrono::Utc;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn cached(
    db: Surreal<Db>,
    ttl_secs: u64,
) -> (SurrealSessionRepository<Db>, Arc<SessionValidationCache>) {
    let cache = Arc::new(SessionValidationCache::new(Duration::from_secs(ttl_secs)));
    let repo = SurrealSessionRepository::new(db).with_validation_cache(Arc::clone(&cache));
    (repo, cache)
}

async fn make_session(repo: &SurrealSessionRepository<Db>, tenant_id: Uuid, user_id: Uuid) -> Uuid {
    repo.create(CreateSession {
        tenant_id,
        user_id,
        token_hash: format!("hash-{}", Uuid::new_v4()),
        ip_address: None,
        user_agent: None,
        expires_at: Utc::now() + chrono::Duration::hours(1),
    })
    .await
    .unwrap()
    .id
}

/// Delete a session row directly, bypassing the repository — the only way to
/// observe whether an answer came from the cache or the database.
async fn delete_row_behind_the_repositorys_back(db: &Surreal<Db>, tenant_id: Uuid, id: Uuid) {
    db.query("DELETE type::record('session', $id) WHERE tenant_id = $tenant_id")
        .bind(("id", id.to_string()))
        .bind(("tenant_id", tenant_id.to_string()))
        .await
        .unwrap();
}

#[tokio::test]
async fn without_a_cache_every_check_reads_the_database() {
    let db = setup().await;
    let repo = SurrealSessionRepository::new(db.clone());
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let session_id = make_session(&repo, tenant_id, user_id).await;

    assert!(repo.is_session_active_checked(tenant_id, session_id).await);

    delete_row_behind_the_repositorys_back(&db, tenant_id, session_id).await;
    assert!(
        !repo.is_session_active_checked(tenant_id, session_id).await,
        "with no cache attached the check must see the deleted row immediately"
    );
    assert!(repo.validation_cache().is_none());
}

#[tokio::test]
async fn a_warm_entry_is_served_without_a_database_read() {
    let db = setup().await;
    let (repo, cache) = cached(db.clone(), 60);
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let session_id = make_session(&repo, tenant_id, user_id).await;

    assert!(repo.is_session_active_checked(tenant_id, session_id).await);
    assert_eq!(cache.len(), 1, "the first check must populate the cache");

    // Row vanishes without the repository knowing. A cached answer is the only
    // way the next check can still say "active".
    delete_row_behind_the_repositorys_back(&db, tenant_id, session_id).await;
    assert!(
        repo.is_session_active_checked(tenant_id, session_id).await,
        "the second check must be answered from the cache, not the database"
    );
}

#[tokio::test]
async fn a_miss_is_never_cached() {
    let db = setup().await;
    let (repo, cache) = cached(db, 60);
    let (tenant_id, session_id) = (Uuid::new_v4(), Uuid::new_v4());

    assert!(!repo.is_session_active_checked(tenant_id, session_id).await);
    assert!(
        cache.is_empty(),
        "a negative answer must never be stored — a session created a moment \
         later must be usable at once"
    );
}

#[tokio::test]
async fn invalidate_through_the_repository_drops_the_cached_entry() {
    let db = setup().await;
    let (repo, _cache) = cached(db, 60);
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let session_id = make_session(&repo, tenant_id, user_id).await;

    assert!(repo.is_session_active_checked(tenant_id, session_id).await);
    repo.invalidate(tenant_id, session_id).await.unwrap();
    assert!(
        !repo.is_session_active_checked(tenant_id, session_id).await,
        "logout must take effect immediately on this replica"
    );
}

#[tokio::test]
async fn consume_drops_the_cached_entry() {
    let db = setup().await;
    let (repo, _cache) = cached(db, 60);
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let session_id = make_session(&repo, tenant_id, user_id).await;

    assert!(repo.is_session_active_checked(tenant_id, session_id).await);
    assert!(repo.consume(tenant_id, session_id).await.unwrap());
    assert!(!repo.is_session_active_checked(tenant_id, session_id).await);
}

#[tokio::test]
async fn invalidate_user_sessions_drops_every_cached_entry_for_that_user() {
    let db = setup().await;
    let (repo, _cache) = cached(db, 60);
    let tenant_id = Uuid::new_v4();
    let (alice, bob) = (Uuid::new_v4(), Uuid::new_v4());
    let a1 = make_session(&repo, tenant_id, alice).await;
    let a2 = make_session(&repo, tenant_id, alice).await;
    let b1 = make_session(&repo, tenant_id, bob).await;
    for s in [a1, a2, b1] {
        assert!(repo.is_session_active_checked(tenant_id, s).await);
    }

    repo.invalidate_user_sessions(tenant_id, alice)
        .await
        .unwrap();

    assert!(!repo.is_session_active_checked(tenant_id, a1).await);
    assert!(!repo.is_session_active_checked(tenant_id, a2).await);
    assert!(
        repo.is_session_active_checked(tenant_id, b1).await,
        "another user's sessions must survive"
    );
}

#[tokio::test]
async fn invalidate_user_sessions_except_keeps_the_current_session_cached() {
    let db = setup().await;
    let (repo, _cache) = cached(db, 60);
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let keep = make_session(&repo, tenant_id, user_id).await;
    let drop = make_session(&repo, tenant_id, user_id).await;
    assert!(repo.is_session_active_checked(tenant_id, keep).await);
    assert!(repo.is_session_active_checked(tenant_id, drop).await);

    let deleted = repo
        .invalidate_user_sessions_except(tenant_id, user_id, keep)
        .await
        .unwrap();
    assert_eq!(deleted, 1);

    assert!(repo.is_session_active_checked(tenant_id, keep).await);
    assert!(!repo.is_session_active_checked(tenant_id, drop).await);
}

/// Tenant isolation: a warm entry for `(tenant_a, session)` must never answer a
/// check for `(tenant_b, session)`. The rows themselves are tenant-scoped, and
/// the cache key must not weaken that.
#[tokio::test]
async fn cached_entries_do_not_leak_across_tenants() {
    let db = setup().await;
    let (repo, _cache) = cached(db, 60);
    let (tenant_a, tenant_b) = (Uuid::new_v4(), Uuid::new_v4());
    let user_id = Uuid::new_v4();
    let session_id = make_session(&repo, tenant_a, user_id).await;

    assert!(repo.is_session_active_checked(tenant_a, session_id).await);
    assert!(
        !repo.is_session_active_checked(tenant_b, session_id).await,
        "a foreign tenant must never see this session as active"
    );
}

/// The TTL is a backstop, not the primary mechanism — but it must actually fire.
#[tokio::test]
async fn the_ttl_expires_a_warm_entry() {
    let db = setup().await;
    let cache = Arc::new(SessionValidationCache::new(Duration::from_millis(50)));
    let repo = SurrealSessionRepository::new(db.clone()).with_validation_cache(Arc::clone(&cache));
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let session_id = make_session(&repo, tenant_id, user_id).await;

    assert!(repo.is_session_active_checked(tenant_id, session_id).await);
    delete_row_behind_the_repositorys_back(&db, tenant_id, session_id).await;
    assert!(repo.is_session_active_checked(tenant_id, session_id).await);

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        !repo.is_session_active_checked(tenant_id, session_id).await,
        "past the TTL the check must fall back to the database"
    );
}

/// A session whose row says it expired must not be served from cache even
/// inside the TTL — expiry is enforced exactly, staleness only applies to
/// revocation.
#[tokio::test]
async fn an_expired_session_is_not_cached() {
    let db = setup().await;
    let (repo, cache) = cached(db, 3600);
    let (tenant_id, user_id) = (Uuid::new_v4(), Uuid::new_v4());
    let session_id = repo
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: "expired".into(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() - chrono::Duration::seconds(1),
        })
        .await
        .unwrap()
        .id;

    assert!(!repo.is_session_active_checked(tenant_id, session_id).await);
    assert!(cache.is_empty());
}

//! The minimal profile's singleton lease (T23.8.1, G-8, D-59), against a real
//! in-memory SurrealDB with the v83 migration applied.
//!
//! The protocol takes `now` and the TTL as arguments, so every case here is
//! deterministic and uses the production-shaped values scaled down: a 30 s TTL
//! is `ttl` below, and "time passing" is a later `now`.

use axiam_db::{LeaseClaim, SurrealMinimalProfileLeaseRepository};
use chrono::{DateTime, Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

async fn setup() -> (SurrealMinimalProfileLeaseRepository<Db>, Surreal<Db>) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    (SurrealMinimalProfileLeaseRepository::new(db.clone()), db)
}

fn t0() -> DateTime<Utc> {
    "2026-10-05T12:00:00Z".parse().unwrap()
}

fn ttl() -> Duration {
    Duration::seconds(30)
}

#[tokio::test]
async fn the_first_claim_creates_the_lease() {
    let (repo, _db) = setup().await;
    assert!(repo.current().await.unwrap().is_none());

    assert_eq!(
        repo.claim("instance-a", t0(), ttl()).await.unwrap(),
        LeaseClaim::Acquired
    );
    let row = repo.current().await.unwrap().expect("the row exists");
    assert_eq!(row.holder, "instance-a");
    assert_eq!(row.acquired_at, t0());
    assert_eq!(row.expires_at, t0() + ttl());
}

#[tokio::test]
async fn a_claim_is_refused_while_another_instances_lease_is_live() {
    let (repo, _db) = setup().await;
    repo.claim("instance-a", t0(), ttl()).await.unwrap();

    let at = t0() + Duration::seconds(10);
    assert_eq!(
        repo.claim("instance-b", at, ttl()).await.unwrap(),
        LeaseClaim::Held {
            holder: "instance-a".into(),
            expires_at: t0() + ttl(),
        }
    );
    // The refusal changed nothing.
    assert_eq!(repo.current().await.unwrap().unwrap().holder, "instance-a");
}

#[tokio::test]
async fn a_claim_takes_the_lease_over_once_it_has_expired() {
    let (repo, _db) = setup().await;
    repo.claim("instance-a", t0(), ttl()).await.unwrap();

    // Exactly at the expiry instant and after: free.
    let at = t0() + ttl();
    assert_eq!(
        repo.claim("instance-b", at, ttl()).await.unwrap(),
        LeaseClaim::Acquired
    );
    let row = repo.current().await.unwrap().unwrap();
    assert_eq!(row.holder, "instance-b");
    assert_eq!(row.acquired_at, at);
    assert_eq!(row.expires_at, at + ttl());
}

#[tokio::test]
async fn the_holder_renews_and_a_renewal_extends_the_expiry() {
    let (repo, _db) = setup().await;
    repo.claim("instance-a", t0(), ttl()).await.unwrap();

    let at = t0() + Duration::seconds(10);
    assert!(repo.renew("instance-a", at, ttl()).await.unwrap());
    let row = repo.current().await.unwrap().unwrap();
    assert_eq!(row.holder, "instance-a");
    assert_eq!(row.acquired_at, t0(), "a renewal is not a new acquisition");
    assert_eq!(row.renewed_at, at);
    assert_eq!(row.expires_at, at + ttl());

    // A claim by another instance at the ORIGINAL expiry still finds it live.
    assert!(matches!(
        repo.claim("instance-b", t0() + ttl(), ttl()).await.unwrap(),
        LeaseClaim::Held { .. }
    ));
}

#[tokio::test]
async fn a_renewal_finds_the_lease_taken_when_another_instance_took_it_over() {
    let (repo, _db) = setup().await;
    repo.claim("instance-a", t0(), ttl()).await.unwrap();
    // instance-a stalls past its TTL; instance-b takes over.
    let later = t0() + ttl() + Duration::seconds(1);
    assert_eq!(
        repo.claim("instance-b", later, ttl()).await.unwrap(),
        LeaseClaim::Acquired
    );

    assert!(
        !repo.renew("instance-a", later, ttl()).await.unwrap(),
        "the old holder learns it lost the lease"
    );
    assert_eq!(repo.current().await.unwrap().unwrap().holder, "instance-b");
}

#[tokio::test]
async fn a_renewal_without_a_lease_reports_lost() {
    let (repo, _db) = setup().await;
    assert!(!repo.renew("instance-a", t0(), ttl()).await.unwrap());
}

#[tokio::test]
async fn reclaiming_your_own_lease_is_acquired() {
    // A restarted process keeps no memory of its previous lease; a fresh
    // instance id never matches, but the same holder id (a retried claim) does.
    let (repo, _db) = setup().await;
    repo.claim("instance-a", t0(), ttl()).await.unwrap();
    assert_eq!(
        repo.claim("instance-a", t0() + Duration::seconds(1), ttl())
            .await
            .unwrap(),
        LeaseClaim::Acquired
    );
}

#[tokio::test]
async fn a_release_frees_the_lease_for_a_successor_at_once() {
    let (repo, _db) = setup().await;
    repo.claim("instance-a", t0(), ttl()).await.unwrap();

    // Another instance's release is a no-op.
    repo.release("instance-b").await.unwrap();
    assert_eq!(repo.current().await.unwrap().unwrap().holder, "instance-a");

    repo.release("instance-a").await.unwrap();
    assert!(repo.current().await.unwrap().is_none());
    assert_eq!(
        repo.claim("instance-b", t0() + Duration::seconds(1), ttl())
            .await
            .unwrap(),
        LeaseClaim::Acquired,
        "no waiting out the TTL after an orderly stop"
    );
    // Idempotent.
    repo.release("instance-a").await.unwrap();
}

/// Concurrent claimants: exactly one wins, every other is told who holds it.
#[tokio::test]
async fn concurrent_claims_have_exactly_one_winner() {
    let (repo, _db) = setup().await;
    let mut tasks = Vec::new();
    for i in 0..8 {
        let repo = repo.clone();
        tasks.push(tokio::spawn(async move {
            repo.claim(&format!("instance-{i}"), t0(), ttl()).await
        }));
    }
    let mut winners = Vec::new();
    for (i, task) in tasks.into_iter().enumerate() {
        match task
            .await
            .unwrap()
            .expect("a claim never errors under contention")
        {
            LeaseClaim::Acquired => winners.push(i),
            LeaseClaim::Held { holder, .. } => {
                assert!(holder.starts_with("instance-"));
            }
        }
    }
    assert_eq!(winners.len(), 1, "exactly one winner, got {winners:?}");
    let row = repo.current().await.unwrap().unwrap();
    assert_eq!(row.holder, format!("instance-{}", winners[0]));
}

#[tokio::test]
async fn concurrent_takeovers_of_an_expired_lease_have_exactly_one_winner() {
    let (repo, _db) = setup().await;
    repo.claim("instance-old", t0(), ttl()).await.unwrap();
    let later = t0() + ttl() + Duration::seconds(5);

    let mut tasks = Vec::new();
    for i in 0..8 {
        let repo = repo.clone();
        tasks.push(tokio::spawn(async move {
            repo.claim(&format!("instance-{i}"), later, ttl()).await
        }));
    }
    let mut winners = 0;
    for task in tasks {
        if task.await.unwrap().unwrap() == LeaseClaim::Acquired {
            winners += 1;
        }
    }
    assert_eq!(winners, 1);
}

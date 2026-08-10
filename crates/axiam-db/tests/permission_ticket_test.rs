//! X2 — UMA 2.0 permission-ticket redemption against the real datastore.
//!
//! Single-use is the security surface here. A ticket that could be redeemed
//! twice would mint two RPTs from one authorization decision, and the
//! precondition lives in a `WHERE` clause rather than in the service, so it is
//! tested against SurrealDB rather than a mock that would agree with whatever
//! the code does.
//!
//! The client binding is tested for the *opposite* property to the others: a
//! wrong-client attempt must change nothing, so the rightful holder can still
//! redeem. Checking the binding after the update would have burned the ticket
//! and turned a leaked handle into a denial of service.

use axiam_core::models::uma::{CreatePermissionTicket, RequestedPermission};
use axiam_core::repository::PermissionTicketRepository;
use axiam_db::repository::SurrealPermissionTicketRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn repo() -> SurrealPermissionTicketRepository<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    SurrealPermissionTicketRepository::new(db)
}

fn ticket(
    tenant_id: Uuid,
    hash: &str,
    client_id: &str,
    ttl_secs: i64,
    resource_id: Uuid,
) -> CreatePermissionTicket {
    CreatePermissionTicket {
        tenant_id,
        ticket_hash: hash.into(),
        client_id: client_id.into(),
        permissions: vec![RequestedPermission {
            resource_id,
            resource_scopes: vec!["view".into(), "edit".into()],
        }],
        expires_at: Utc::now() + Duration::seconds(ttl_secs),
    }
}

#[tokio::test]
async fn a_new_ticket_round_trips_its_permissions() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let resource = Uuid::new_v4();

    let created = repo
        .create(ticket(tenant, "hash-1", "rs-1", 60, resource))
        .await
        .unwrap();

    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.client_id, "rs-1");
    assert!(!created.consumed);
    assert_eq!(created.permissions.len(), 1);
    assert_eq!(created.permissions[0].resource_id, resource);
    assert_eq!(
        created.permissions[0].resource_scopes,
        vec!["view".to_string(), "edit".to_string()]
    );
}

#[tokio::test]
async fn consume_returns_the_ticket_and_marks_it_used() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-2", "rs-1", 60, Uuid::new_v4()))
        .await
        .unwrap();

    let consumed = repo.consume(tenant, "hash-2", "rs-1").await.unwrap();
    assert!(consumed.is_some(), "first redemption must succeed");
    // The returned row is the BEFORE image, so it still reads as unconsumed —
    // the caller needs what the ticket said, not the tombstone.
    assert!(!consumed.unwrap().consumed);

    let after = repo.find_by_hash(tenant, "hash-2").await.unwrap().unwrap();
    assert!(after.consumed, "the stored row must now be marked consumed");
}

/// UMA 2.0 §3.3 single-use: the second redemption gets nothing.
#[tokio::test]
async fn a_ticket_cannot_be_redeemed_twice() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-3", "rs-1", 60, Uuid::new_v4()))
        .await
        .unwrap();

    assert!(
        repo.consume(tenant, "hash-3", "rs-1")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.consume(tenant, "hash-3", "rs-1")
            .await
            .unwrap()
            .is_none(),
        "a replayed ticket must not mint a second RPT"
    );
}

#[tokio::test]
async fn an_expired_ticket_cannot_be_redeemed() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-4", "rs-1", -1, Uuid::new_v4()))
        .await
        .unwrap();

    assert!(
        repo.consume(tenant, "hash-4", "rs-1")
            .await
            .unwrap()
            .is_none(),
        "expiry is part of the consuming statement, not a later check"
    );
}

/// The load-bearing case: a ticket presented by the wrong client must be
/// refused *without* being consumed, so the client it was minted for can still
/// use it. This is why `client_id` is in the WHERE clause.
#[tokio::test]
async fn a_wrong_client_redemption_refuses_without_burning_the_ticket() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-5", "rs-1", 60, Uuid::new_v4()))
        .await
        .unwrap();

    assert!(
        repo.consume(tenant, "hash-5", "rs-2")
            .await
            .unwrap()
            .is_none(),
        "a ticket is bound to the client it was minted for"
    );

    let still_there = repo.find_by_hash(tenant, "hash-5").await.unwrap().unwrap();
    assert!(
        !still_there.consumed,
        "a wrong-client attempt must not consume the ticket — otherwise a \
         leaked handle becomes a denial of service against its owner"
    );

    assert!(
        repo.consume(tenant, "hash-5", "rs-1")
            .await
            .unwrap()
            .is_some(),
        "the rightful client must still be able to redeem"
    );
}

/// Tenant isolation: the same handle in another tenant is not this tenant's.
#[tokio::test]
async fn consume_is_scoped_to_the_tenant() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-6", "rs-1", 60, Uuid::new_v4()))
        .await
        .unwrap();

    assert!(
        repo.consume(other, "hash-6", "rs-1")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.consume(tenant, "hash-6", "rs-1")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn find_by_hash_does_not_consume() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-7", "rs-1", 60, Uuid::new_v4()))
        .await
        .unwrap();

    assert!(repo.find_by_hash(tenant, "hash-7").await.unwrap().is_some());
    assert!(
        repo.consume(tenant, "hash-7", "rs-1")
            .await
            .unwrap()
            .is_some(),
        "the diagnostic read must leave the ticket redeemable"
    );
}

#[tokio::test]
async fn find_by_hash_returns_none_for_an_unknown_handle() {
    let repo = repo().await;
    assert!(
        repo.find_by_hash(Uuid::new_v4(), "no-such-hash")
            .await
            .unwrap()
            .is_none()
    );
}

/// Concurrent redemptions of one ticket: exactly one may win. This is the race
/// the single-statement `consume` exists to lose safely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_redemptions_yield_exactly_one_winner() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-8", "rs-1", 60, Uuid::new_v4()))
        .await
        .unwrap();

    // Real threads, not interleaved polling on one: the property under test is
    // that the datastore serialises the racers, and a single-threaded runtime
    // could pass by never overlapping them.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let repo = repo.clone();
        set.spawn(async move { repo.consume(tenant, "hash-8", "rs-1").await.unwrap() });
    }

    let mut winners = 0;
    while let Some(result) = set.join_next().await {
        if result.unwrap().is_some() {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one concurrent redemption may succeed");
}

#[tokio::test]
async fn cleanup_removes_only_expired_tickets() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    repo.create(ticket(tenant, "hash-live", "rs-1", 600, Uuid::new_v4()))
        .await
        .unwrap();
    repo.create(ticket(tenant, "hash-dead", "rs-1", -60, Uuid::new_v4()))
        .await
        .unwrap();

    let removed = repo.cleanup_expired(tenant).await.unwrap();
    assert_eq!(removed, 1);
    assert!(
        repo.find_by_hash(tenant, "hash-live")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.find_by_hash(tenant, "hash-dead")
            .await
            .unwrap()
            .is_none()
    );
}

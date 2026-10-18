//! Item 11 of the 1.1.0 atomicity audit: a deletion cancel and the purge
//! sweep never both win.
//!
//! The cancel endpoint read the request ("pending, inside the window") and then
//! wrote `cancelled` and re-enabled the account in two unconditional
//! statements; the sweep selected due accounts and erased them with
//! unconditional writes. A cancel arriving at the deadline could land after the
//! sweep had selected the account: the subject was told "cancelled" while the
//! sweep went on to strip and erase the account. The sweep now claims the
//! request before its first destructive step (`purge_claimed_at`, schema v107)
//! and a cancel is one transaction that refuses a claimed request.
//!
//! The race runs on `surrealkv` (`tests/common`), the engine production runs.
//! The sweep's `now` is past the deadline while the datastore's clock is not —
//! the instant at the deadline, or a sweep on a replica whose clock runs ahead
//! — so both sides are legal on their reads. Each round both read, wait at a
//! barrier, then write at once. Exactly one may win.

mod common;

use std::sync::Arc;

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AccountDeletionRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    CancelOutcome, SurrealAccountDeletionRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use uuid::Uuid;

/// Rounds per run; the test was also run 20 times in a row.
const ROUNDS: usize = 8;

/// A tenant with one account whose deletion is pending, purge an hour away by
/// the datastore's clock. Returns `(tenant, user, request)`.
async fn pending_deletion(db: &Surreal<Db>, n: usize) -> (Uuid, Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {n}"),
            slug: format!("org-{n}"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {n}"),
            slug: format!("tenant-{n}"),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant,
            username: format!("leaving-{n}"),
            email: format!("leaving-{n}@example.com"),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let request = SurrealAccountDeletionRepository::new(db.clone())
        .create_with_pending_flag(
            tenant,
            user,
            Utc::now() + Duration::hours(1),
            format!("h-{n}"),
        )
        .await
        .unwrap()
        .id;
    (tenant, user, request)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancel_and_the_purge_claim_sent_together_never_both_win() {
    let db = common::serialising_db().await;
    // The sweep's `now`: past the deadline.
    let sweep_now = Utc::now() + Duration::hours(2);
    let (mut cancels_won, mut claims_won) = (0, 0);
    for round in 0..ROUNDS {
        let (tenant, user, request) = pending_deletion(&db, round).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        let cancel = {
            let (barrier, repo) = (
                barrier.clone(),
                SurrealAccountDeletionRepository::new(db.handle()),
            );
            tokio::spawn(async move {
                // The handler's lookup: pending, inside the window.
                let found = repo.find_by_token_hash(tenant, &format!("h-{round}")).await;
                assert!(found.unwrap().is_some(), "round {round}: the read");
                barrier.wait().await;
                repo.cancel_pending(tenant, request).await.unwrap()
            })
        };
        let claim = {
            let (barrier, repo, users) = (
                barrier.clone(),
                SurrealAccountDeletionRepository::new(db.handle()),
                SurrealUserRepository::new(db.handle()),
            );
            tokio::spawn(async move {
                // The sweep's selection: the account is due at its `now`.
                let due = users.find_due_for_purge(sweep_now).await.unwrap();
                assert!(due.iter().any(|u| u.id == user), "round {round}: the read");
                barrier.wait().await;
                // The claim is the shorter transaction; staggering its start
                // by a few hundred microseconds lets either side commit first
                // across the rounds, so both outcomes are exercised.
                let stagger = u64::try_from(round % 4).unwrap() * 400;
                tokio::time::sleep(std::time::Duration::from_micros(stagger)).await;
                repo.claim_for_purge(tenant, user, sweep_now).await.unwrap()
            })
        };
        let cancelled = cancel.await.unwrap();
        let claimed = claim.await.unwrap();

        let account = SurrealUserRepository::new(db.handle())
            .get_by_id(tenant, user)
            .await
            .unwrap();
        match (cancelled, claimed) {
            (CancelOutcome::Cancelled, false) => {
                assert!(!account.deletion_pending, "round {round}: active again");
                cancels_won += 1;
            }
            (CancelOutcome::Erasing, true) => {
                assert!(account.deletion_pending, "round {round}: still due");
                claims_won += 1;
            }
            other => panic!("round {round}: both or neither won: {other:?}"),
        }
    }
    eprintln!("cancels won {cancels_won}, claims won {claims_won}");
}

/// Sequentially: each order, and each other state a cancel can meet.
#[tokio::test]
async fn a_cancel_answers_the_request_state_it_meets() {
    let db = common::serialising_db().await;
    let repo = SurrealAccountDeletionRepository::new(db.handle());
    let users = SurrealUserRepository::new(db.handle());
    let late = Utc::now() + Duration::hours(2);

    // Claimed first: the cancel is refused and changes nothing.
    let (tenant, user, request) = pending_deletion(&db, 0).await;
    assert!(repo.claim_for_purge(tenant, user, late).await.unwrap());
    assert!(
        repo.claim_for_purge(tenant, user, late).await.unwrap(),
        "a claim is idempotent"
    );
    assert_eq!(
        repo.cancel_pending(tenant, request).await.unwrap(),
        CancelOutcome::Erasing
    );
    assert!(
        users
            .get_by_id(tenant, user)
            .await
            .unwrap()
            .deletion_pending
    );
    assert!(
        repo.mark_cancelled(tenant, request).await.is_err(),
        "the trait's cancel is conditional too"
    );

    // Cancelled first: the claim finds nothing due; a second cancel is told so.
    let (tenant, user, request) = pending_deletion(&db, 1).await;
    assert_eq!(
        repo.cancel_pending(tenant, request).await.unwrap(),
        CancelOutcome::Cancelled
    );
    assert!(!repo.claim_for_purge(tenant, user, late).await.unwrap());
    assert_eq!(
        repo.cancel_pending(tenant, request).await.unwrap(),
        CancelOutcome::AlreadyCancelled
    );
    // A completion never rewrites a cancelled request.
    repo.mark_completed(tenant, request).await.unwrap();
    let row = repo
        .find_by_token_hash(tenant, "h-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        row.status,
        axiam_core::models::gdpr::AccountDeletionStatus::Cancelled
    );

    // Completed: the erasure happened; the cancel says so.
    let (tenant, _, request) = pending_deletion(&db, 2).await;
    repo.mark_completed(tenant, request).await.unwrap();
    assert_eq!(
        repo.cancel_pending(tenant, request).await.unwrap(),
        CancelOutcome::Erasing
    );

    // Past the window by the datastore's clock.
    let (tenant, user, request) = pending_deletion(&db, 3).await;
    db.query(
        "UPDATE account_deletion SET scheduled_purge_at = time::now() - 1s WHERE user_id = $u",
    )
    .bind(("u", user.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    assert_eq!(
        repo.cancel_pending(tenant, request).await.unwrap(),
        CancelOutcome::Expired
    );

    // Another tenant's request is not found.
    assert!(repo.cancel_pending(Uuid::new_v4(), request).await.is_err());

    // An account not yet due at the sweep's `now` is not claimed.
    let (tenant, user, _) = pending_deletion(&db, 4).await;
    assert!(
        !repo
            .claim_for_purge(tenant, user, Utc::now())
            .await
            .unwrap(),
        "not due yet at the sweep's now"
    );
}

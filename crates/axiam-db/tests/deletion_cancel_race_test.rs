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
    CancelOutcome, PurgeClaimOutcome, SurrealAccountDeletionRepository,
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use uuid::Uuid;

/// Rounds per run; the test was also run 20 times in a row.
const ROUNDS: usize = 8;

/// The erasure claim's lease (#738), the cleanup task's one hour.
fn lease() -> Duration {
    Duration::hours(1)
}

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
                repo.claim_for_purge(tenant, user, sweep_now, lease())
                    .await
                    .unwrap()
            })
        };
        let cancelled = cancel.await.unwrap();
        let claimed = claim.await.unwrap();

        let account = SurrealUserRepository::new(db.handle())
            .get_by_id(tenant, user)
            .await
            .unwrap();
        match (cancelled, claimed) {
            (CancelOutcome::Cancelled, PurgeClaimOutcome::NotDue) => {
                assert!(!account.deletion_pending, "round {round}: active again");
                cancels_won += 1;
            }
            (CancelOutcome::Erasing, PurgeClaimOutcome::Claimed) => {
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
    assert_eq!(
        repo.claim_for_purge(tenant, user, late, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Claimed
    );
    assert_eq!(
        repo.claim_for_purge(tenant, user, late, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Held,
        "a claim is exclusive (#738)"
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
    assert_eq!(
        repo.claim_for_purge(tenant, user, late, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::NotDue
    );
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
    assert_eq!(
        repo.claim_for_purge(tenant, user, Utc::now(), lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::NotDue,
        "not due yet at the sweep's now"
    );
}

/// The request's `purge_claimed_at`, as stored.
async fn request_claim(db: &Surreal<Db>, user: Uuid) -> Option<chrono::DateTime<Utc>> {
    let mut result = db
        .query("SELECT VALUE purge_claimed_at FROM account_deletion WHERE user_id = $u")
        .bind(("u", user.to_string()))
        .await
        .unwrap();
    let stamps: Vec<Option<chrono::DateTime<Utc>>> = result.take(0).unwrap();
    stamps.into_iter().next().flatten()
}

/// The user row's `erasure_audit_pending`, as stored.
async fn user_stamp(db: &Surreal<Db>, user: Uuid) -> Option<chrono::DateTime<Utc>> {
    let mut result = db
        .query("SELECT VALUE erasure_audit_pending FROM type::record('user', $u)")
        .bind(("u", user.to_string()))
        .await
        .unwrap();
    let stamps: Vec<Option<chrono::DateTime<Utc>>> = result.take(0).unwrap();
    stamps.into_iter().next().flatten()
}

/// #738: the erasure claim is exclusive for its lease. A second claimant is
/// told `Held`; a released claim is taken at once and stays uncancellable; a
/// claim older than the lease is taken over, and the stalled claimant's late
/// release then changes nothing.
#[tokio::test]
async fn an_erasure_claim_is_exclusive_until_released_or_its_lease_runs_out() {
    let db = common::serialising_db().await;
    let repo = SurrealAccountDeletionRepository::new(db.handle());
    let (tenant, user, request) = pending_deletion(&db, 10).await;
    let first = Utc::now() + Duration::hours(2);

    assert_eq!(
        repo.claim_for_purge(tenant, user, first, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Claimed
    );
    assert_eq!(request_claim(&db, user).await, Some(first));
    assert_eq!(
        user_stamp(&db, user).await,
        None,
        "a request holds the claim; the user row is not stamped"
    );
    // Another claimant inside the lease is refused, and the claim keeps its
    // stamp.
    let second = first + Duration::minutes(59);
    assert_eq!(
        repo.claim_for_purge(tenant, user, second, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Held
    );
    assert_eq!(request_claim(&db, user).await, Some(first));

    // Released: the next claimant takes it at once, and a cancel is still
    // refused in between.
    repo.release_purge_claim(tenant, user, first).await.unwrap();
    assert_eq!(
        request_claim(&db, user).await,
        Some(chrono::DateTime::<Utc>::UNIX_EPOCH)
    );
    assert_eq!(
        repo.cancel_pending(tenant, request).await.unwrap(),
        CancelOutcome::Erasing,
        "a released claim does not reopen the cancel"
    );
    assert_eq!(
        repo.claim_for_purge(tenant, user, second, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Claimed
    );
    assert_eq!(request_claim(&db, user).await, Some(second));

    // The holder stalls: past the lease, another claimant takes it over.
    let third = second + lease() + Duration::seconds(1);
    assert_eq!(
        repo.claim_for_purge(tenant, user, third, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Claimed
    );
    assert_eq!(request_claim(&db, user).await, Some(third));
    // The stalled claimant's release names its own stamp and changes nothing.
    repo.release_purge_claim(tenant, user, second)
        .await
        .unwrap();
    assert_eq!(request_claim(&db, user).await, Some(third));
}

/// #738: an account deletion-pending with no request row is claimed by a stamp
/// on the user row, under the same rule; the release clears it; and once the
/// anonymization has run — the point of no return, after which the field is
/// the erasure's record marker — a release leaves the row alone.
#[tokio::test]
async fn an_erasure_without_a_request_is_claimed_on_the_user_row() {
    let db = common::serialising_db().await;
    let repo = SurrealAccountDeletionRepository::new(db.handle());
    let users = SurrealUserRepository::new(db.handle());
    let (tenant, user, request) = pending_deletion(&db, 11).await;
    // No request: the account stays deletion-pending, the row goes.
    db.query("DELETE type::record('account_deletion', $id)")
        .bind(("id", request.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let first = Utc::now() + Duration::hours(2);

    assert_eq!(
        repo.claim_for_purge(tenant, user, first, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Claimed
    );
    assert_eq!(user_stamp(&db, user).await, Some(first));
    assert_eq!(
        repo.claim_for_purge(tenant, user, first + Duration::minutes(1), lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Held
    );
    // The stamp on a row not yet erased is never an owed record.
    assert!(
        repo.claim_owed_erasure_records(first + Duration::days(1), lease())
            .await
            .unwrap()
            .is_empty()
    );
    repo.release_purge_claim(tenant, user, first).await.unwrap();
    assert_eq!(user_stamp(&db, user).await, None);

    // Past the lease, a stalled claim is taken over.
    let second = first + Duration::minutes(5);
    assert_eq!(
        repo.claim_for_purge(tenant, user, second, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Claimed
    );
    let third = second + lease() + Duration::seconds(1);
    assert_eq!(
        repo.claim_for_purge(tenant, user, third, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::Claimed
    );
    assert_eq!(user_stamp(&db, user).await, Some(third));

    // The anonymization writes its record marker over the claim; a release
    // after it — even one that names the marker's own value — is refused,
    // because the account is no longer deletion-pending.
    users
        .anonymize_user(tenant, user, "hashed", "DELETED_USER_claim0000001")
        .await
        .unwrap();
    let marker = user_stamp(&db, user)
        .await
        .expect("the record marker is set");
    repo.release_purge_claim(tenant, user, marker)
        .await
        .unwrap();
    assert_eq!(user_stamp(&db, user).await, Some(marker));
    assert_eq!(
        repo.claim_for_purge(tenant, user, third + lease() * 2, lease())
            .await
            .unwrap(),
        PurgeClaimOutcome::NotDue,
        "an erased account is not claimed again"
    );
}

/// #784: the erasure's anonymization writes only a deletion-pending account. A
/// unit stalled past its claim's lease that reaches it after its successor
/// erased the account matches nothing: `false`, and the row — its pseudonym,
/// its record marker, its `updated_at` — is left as the successor wrote it.
#[tokio::test]
async fn the_marked_anonymization_of_an_erased_account_writes_nothing() {
    let db = common::serialising_db().await;
    let (tenant, user, _) = pending_deletion(&db, 0).await;
    let users = SurrealUserRepository::new(db.handle());
    let first = Utc::now();
    assert!(
        users
            .anonymize_user_marked(tenant, user, "hashed_a", "DELETED_USER_first000001", first)
            .await
            .unwrap(),
        "the successor anonymizes the pending account"
    );
    let erased = users.get_by_id(tenant, user).await.unwrap();
    assert_eq!(user_stamp(&db, user).await, Some(first));

    assert!(
        !users
            .anonymize_user_marked(
                tenant,
                user,
                "hashed_b",
                "DELETED_USER_stalled00001",
                first + Duration::minutes(1),
            )
            .await
            .unwrap(),
        "the stalled unit's anonymization matches nothing"
    );
    let after = users.get_by_id(tenant, user).await.unwrap();
    assert_eq!(after.username, "DELETED_USER_first000001");
    assert_eq!(after.email, "hashed_a");
    assert_eq!(after.updated_at, erased.updated_at);
    assert_eq!(
        user_stamp(&db, user).await,
        Some(first),
        "no marker set again"
    );
}

/// #784: a unit stalled past its claim's lease and its successor that reach the
/// anonymization of one pending account together anonymize it once: one call
/// answers `true`, the other `false`, and the record marker is the winner's.
/// On `surrealkv` (`tests/common`): the assertion is "exactly one wins".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_anonymizations_of_one_pending_account_sent_together_have_one_winner() {
    let db = common::serialising_db().await;
    for round in 0..ROUNDS {
        let (tenant, user, _) = pending_deletion(&db, 100 + round).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let base = Utc::now();
        let racers: Vec<_> = (0..2)
            .map(|i| {
                let (barrier, users) = (barrier.clone(), SurrealUserRepository::new(db.handle()));
                let stamp = base + Duration::seconds(i);
                tokio::spawn(async move {
                    barrier.wait().await;
                    let won = users
                        .anonymize_user_marked(
                            tenant,
                            user,
                            &format!("hashed_{round}_{i}"),
                            &format!("DELETED_USER_r{round:03}u{i}"),
                            stamp,
                        )
                        .await
                        .unwrap();
                    (won, stamp)
                })
            })
            .collect();
        let mut winners = Vec::new();
        for racer in racers {
            let (won, stamp) = racer.await.unwrap();
            if won {
                winners.push(stamp);
            }
        }
        assert_eq!(winners.len(), 1, "round {round}: exactly one anonymizes");
        assert_eq!(
            user_stamp(&db, user).await,
            Some(winners[0]),
            "round {round}: the marker is the winner's"
        );
    }
}

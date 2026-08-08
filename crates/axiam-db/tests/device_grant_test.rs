//! B2 — device-grant state machine against the real datastore.
//!
//! The transitions are the security surface here: a grant that could be
//! redeemed twice would mint two token sets from one approval, and a grant
//! that could be re-decided would let a second person's answer overwrite the
//! first's. Both are expressed as single statements with the precondition in
//! the WHERE clause, so both are tested against SurrealDB rather than against
//! a mock that would happily agree with whatever the code does.

use axiam_core::models::oauth2_client::{CreateDeviceGrant, DeviceGrantStatus};
use axiam_core::repository::DeviceGrantRepository;
use axiam_db::repository::SurrealDeviceGrantRepository;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn repo() -> SurrealDeviceGrantRepository<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    SurrealDeviceGrantRepository::new(db)
}

fn grant(tenant_id: Uuid, user_code: &str, hash: &str, ttl_secs: i64) -> CreateDeviceGrant {
    CreateDeviceGrant {
        tenant_id,
        client_id: "tv-app".into(),
        device_code_hash: hash.into(),
        user_code: user_code.into(),
        scopes: vec!["openid".into(), "profile".into()],
        expires_at: Utc::now() + Duration::seconds(ttl_secs),
        interval_secs: 5,
    }
}

#[tokio::test]
async fn a_new_grant_is_pending_and_findable_by_both_codes() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();

    let created = repo
        .create(grant(tenant, "BCDFGHJK", "hash-1", 600))
        .await
        .unwrap();
    assert_eq!(created.status, DeviceGrantStatus::Pending);
    assert_eq!(created.user_id, None, "nobody has approved it yet");
    assert_eq!(created.scopes, vec!["openid", "profile"]);

    assert!(
        repo.get_by_user_code(tenant, "BCDFGHJK")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        repo.get_by_device_code_hash(tenant, "hash-1")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn grants_are_tenant_scoped() {
    let repo = repo().await;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();

    repo.create(grant(a, "BCDFGHJK", "hash-a", 600))
        .await
        .unwrap();

    assert!(
        repo.get_by_user_code(b, "BCDFGHJK")
            .await
            .unwrap()
            .is_none(),
        "another tenant must not see this grant — the user-code space is small \
         enough that a cross-tenant hit is a realistic collision, not a theoretical one"
    );
    assert!(
        repo.get_by_device_code_hash(b, "hash-a")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn approval_records_the_subject_and_can_then_be_redeemed_once() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-1", 600))
        .await
        .unwrap();

    assert!(repo.decide(tenant, "BCDFGHJK", true, user).await.unwrap());

    let after = repo
        .get_by_user_code(tenant, "BCDFGHJK")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.status, DeviceGrantStatus::Approved);
    assert_eq!(after.user_id, Some(user));

    let redeemed = repo.redeem(tenant, "hash-1").await.unwrap();
    assert!(redeemed.is_some(), "an approved grant redeems");
    assert_eq!(redeemed.unwrap().user_id, Some(user));

    // THE property: one approval, one token set.
    assert!(
        repo.redeem(tenant, "hash-1").await.unwrap().is_none(),
        "a second redeem must find nothing — the device polls in a loop by \
         construction, so a read-then-write here would mint two token sets \
         from one approval"
    );
}

#[tokio::test]
async fn a_pending_grant_cannot_be_redeemed() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-1", 600))
        .await
        .unwrap();

    assert!(
        repo.redeem(tenant, "hash-1").await.unwrap().is_none(),
        "redeeming without approval would be the whole flow bypassed"
    );
}

#[tokio::test]
async fn a_denied_grant_cannot_be_redeemed_or_re_decided() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-1", 600))
        .await
        .unwrap();

    assert!(repo.decide(tenant, "BCDFGHJK", false, user).await.unwrap());
    assert_eq!(
        repo.get_by_user_code(tenant, "BCDFGHJK")
            .await
            .unwrap()
            .unwrap()
            .status,
        DeviceGrantStatus::Denied
    );

    assert!(repo.redeem(tenant, "hash-1").await.unwrap().is_none());
    assert!(
        !repo
            .decide(tenant, "BCDFGHJK", true, Uuid::new_v4())
            .await
            .unwrap(),
        "a second decision must lose — otherwise whoever clicks last wins, and \
         a refusal could be quietly overturned"
    );
}

#[tokio::test]
async fn an_approved_grant_cannot_be_re_decided() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    let first = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-1", 600))
        .await
        .unwrap();

    assert!(repo.decide(tenant, "BCDFGHJK", true, first).await.unwrap());
    assert!(
        !repo
            .decide(tenant, "BCDFGHJK", false, Uuid::new_v4())
            .await
            .unwrap()
    );

    let after = repo
        .get_by_user_code(tenant, "BCDFGHJK")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.status, DeviceGrantStatus::Approved);
    assert_eq!(
        after.user_id,
        Some(first),
        "the first decider stays recorded"
    );
}

#[tokio::test]
async fn an_expired_grant_can_neither_be_decided_nor_redeemed() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-1", -1))
        .await
        .unwrap();

    assert!(
        !repo
            .decide(tenant, "BCDFGHJK", true, Uuid::new_v4())
            .await
            .unwrap(),
        "approving an expired code must fail in the statement, not just in the \
         service — expiry is a datastore precondition here"
    );
    assert!(repo.redeem(tenant, "hash-1").await.unwrap().is_none());
}

#[tokio::test]
async fn polling_faster_than_the_interval_raises_it() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-1", 600))
        .await
        .unwrap();

    // First poll: nothing to compare against, so it is not "too fast".
    let (interval, too_fast) = repo.record_poll(tenant, "hash-1").await.unwrap();
    assert_eq!(interval, 5);
    assert!(!too_fast, "the first poll cannot be too fast");

    // Immediately again: well inside the 5 s interval.
    let (interval, too_fast) = repo.record_poll(tenant, "hash-1").await.unwrap();
    assert!(too_fast, "a poll inside the interval must be flagged");
    assert!(interval > 5, "…and must raise the interval (slow_down)");

    // Repeatedly — the interval must climb but stay bounded, or "slow down"
    // would eventually mean "never succeed".
    for _ in 0..40 {
        repo.record_poll(tenant, "hash-1").await.unwrap();
    }
    let (interval, _) = repo.record_poll(tenant, "hash-1").await.unwrap();
    assert!(
        interval <= 60,
        "the interval must stay under the cap; got {interval}"
    );
}

#[tokio::test]
async fn polling_an_unknown_code_is_not_an_error() {
    let repo = repo().await;
    // The caller rejects the unknown code; `record_poll` must not blow up on
    // it, or an unknown device code would surface as a 500 rather than an
    // invalid_grant.
    let (interval, too_fast) = repo.record_poll(Uuid::new_v4(), "nope").await.unwrap();
    assert_eq!(interval, 0);
    assert!(!too_fast);
}

#[tokio::test]
async fn cleanup_removes_expired_grants_and_leaves_live_ones() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-dead", -10))
        .await
        .unwrap();
    repo.create(grant(tenant, "LMNPQRST", "hash-live", 600))
        .await
        .unwrap();

    assert_eq!(repo.cleanup_expired(tenant).await.unwrap(), 1);
    assert!(
        repo.get_by_user_code(tenant, "BCDFGHJK")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.get_by_user_code(tenant, "LMNPQRST")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn user_codes_are_unique_within_a_tenant() {
    let repo = repo().await;
    let tenant = Uuid::new_v4();
    repo.create(grant(tenant, "BCDFGHJK", "hash-1", 600))
        .await
        .unwrap();

    // A duplicate user code would mean one user's approval landing on another
    // user's device — the worst failure this feature can have, so it is a
    // datastore invariant rather than a retry loop's good intentions.
    assert!(
        repo.create(grant(tenant, "BCDFGHJK", "hash-2", 600))
            .await
            .is_err(),
        "the unique index must reject a duplicate user code"
    );
}

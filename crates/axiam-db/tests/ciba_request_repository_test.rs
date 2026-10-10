//! The CIBA pending-request store against the real datastore (T23.7.1, G-7,
//! schema v80).
//!
//! What lives in the datastore rather than in plain Rust: every transition's
//! precondition (version, user, status, expiry, client), the poll
//! compare-and-set, the X6 single-use redemption under real concurrency, the
//! sealed ping credentials, the expiry sweep, and erasure and tenant deletion.
//!
//! No credential literal appears here: the sealing key and every token are
//! generated at run time.

mod common;

use std::sync::OnceLock;

use axiam_core::error::AxiamError;
use axiam_core::models::ciba::{
    CibaApprovalEvidence, CibaDeliveryMode, CibaPingCredentials, CibaRequestStatus,
    CreateCibaRequest,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::Amr;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    CibaRequestRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealCibaRequestRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

/// A sealing key generated once per test binary, never written down.
fn sealing() -> [u8; 32] {
    static SEALING: OnceLock<[u8; 32]> = OnceLock::new();
    *SEALING.get_or_init(|| {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        out
    })
}

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn repo(db: &Surreal<Db>) -> SurrealCibaRequestRepository<Db> {
    SurrealCibaRequestRepository::new(db.clone(), Some(sealing()))
}

/// A digest-shaped value (64 hex characters), unique per call.
fn digest() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn input(tenant_id: Uuid, user_id: Option<Uuid>, hash: &str, ttl_secs: i64) -> CreateCibaRequest {
    CreateCibaRequest {
        tenant_id,
        client_id: "oa_ciba_client".into(),
        auth_req_id_hash: hash.into(),
        user_id,
        scopes: vec!["openid".into(), "profile".into()],
        binding_message: Some("W4SCT".into()),
        acr_values: vec!["urn:axiam:acr:mfa".into()],
        resource: None,
        delivery_mode: CibaDeliveryMode::Poll,
        ping: None,
        interval_secs: 5,
        expires_at: Utc::now() + Duration::seconds(ttl_secs),
    }
}

fn evidence() -> CibaApprovalEvidence {
    CibaApprovalEvidence {
        session_id: Uuid::new_v4(),
        auth_time: Utc::now(),
        acr: "urn:axiam:acr:mfa".into(),
        amr: vec![Amr::Pwd, Amr::Otp, Amr::Mfa],
    }
}

#[tokio::test]
async fn a_request_round_trips_every_column() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let hash = digest();

    let created = repo
        .create(input(tenant, Some(user), &hash, 300))
        .await
        .unwrap();
    assert_eq!(created.status, CibaRequestStatus::Pending);
    assert_eq!(created.version, 0);
    assert_eq!(created.user_id, Some(user));
    assert_eq!(created.scopes, ["openid", "profile"]);
    assert_eq!(created.binding_message.as_deref(), Some("W4SCT"));
    assert_eq!(created.acr_values, ["urn:axiam:acr:mfa"]);
    assert_eq!(created.delivery_mode, CibaDeliveryMode::Poll);
    assert!(created.approval.is_none());

    let by_hash = repo.get_by_hash(tenant, &hash).await.unwrap().unwrap();
    assert_eq!(by_hash, created);
    let by_id = repo.get_by_id(tenant, created.id).await.unwrap().unwrap();
    assert_eq!(by_id, created);

    // Tenant isolation on both reads.
    let other = Uuid::new_v4();
    assert!(repo.get_by_hash(other, &hash).await.unwrap().is_none());
    assert!(repo.get_by_id(other, created.id).await.unwrap().is_none());
}

#[tokio::test]
async fn the_hash_is_unique() {
    let db = setup().await;
    let repo = repo(&db);
    let hash = digest();
    repo.create(input(Uuid::new_v4(), None, &hash, 300))
        .await
        .unwrap();
    assert!(
        repo.create(input(Uuid::new_v4(), None, &hash, 300))
            .await
            .is_err(),
        "a second request may not answer to the same auth_req_id"
    );
}

/// Approval is conditional on the version read, the request's own user, the
/// pending status and the expiry — and records the evidence once.
#[tokio::test]
async fn approval_is_conditional_on_version_user_status_and_expiry() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let req = repo
        .create(input(tenant, Some(user), &digest(), 300))
        .await
        .unwrap();

    // Another user cannot approve it.
    assert!(
        !repo
            .approve(tenant, req.id, 0, Uuid::new_v4(), evidence())
            .await
            .unwrap()
    );
    // A stale version cannot.
    assert!(
        !repo
            .approve(tenant, req.id, 7, user, evidence())
            .await
            .unwrap()
    );
    // Another tenant cannot.
    assert!(
        !repo
            .approve(Uuid::new_v4(), req.id, 0, user, evidence())
            .await
            .unwrap()
    );

    let ev = evidence();
    assert!(
        repo.approve(tenant, req.id, 0, user, ev.clone())
            .await
            .unwrap()
    );
    let stored = repo.get_by_id(tenant, req.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CibaRequestStatus::Approved);
    assert_eq!(stored.version, 1);
    let approval = stored.approval.expect("evidence recorded");
    assert_eq!(approval.session_id, ev.session_id);
    assert_eq!(approval.acr, ev.acr);
    assert_eq!(approval.amr, ev.amr);
    assert_eq!(approval.auth_time.timestamp(), ev.auth_time.timestamp());
    assert!(stored.decided_at.is_some());

    // Decided once: neither a second approval nor a denial lands.
    assert!(
        !repo
            .approve(tenant, req.id, 1, user, evidence())
            .await
            .unwrap()
    );
    assert!(!repo.deny(tenant, req.id, 1, user).await.unwrap());

    // An expired request cannot be approved.
    let expired = repo
        .create(input(tenant, Some(user), &digest(), -1))
        .await
        .unwrap();
    assert!(
        !repo
            .approve(tenant, expired.id, 0, user, evidence())
            .await
            .unwrap()
    );
    // A request whose hint named nobody has no user to approve it.
    let decoy = repo
        .create(input(tenant, None, &digest(), 300))
        .await
        .unwrap();
    assert!(
        !repo
            .approve(tenant, decoy.id, 0, user, evidence())
            .await
            .unwrap()
    );
    assert!(!repo.deny(tenant, decoy.id, 0, user).await.unwrap());
}

/// The pending list (#566) holds the user's own, unexpired, undecided requests
/// of one tenant, soonest expiry first, and honours the limit.
#[tokio::test]
async fn the_pending_list_is_one_users_open_requests_soonest_first() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();

    let later = repo
        .create(input(tenant, Some(user), &digest(), 500))
        .await
        .unwrap();
    let sooner = repo
        .create(input(tenant, Some(user), &digest(), 100))
        .await
        .unwrap();
    let decided = repo
        .create(input(tenant, Some(user), &digest(), 300))
        .await
        .unwrap();
    assert!(repo.deny(tenant, decided.id, 0, user).await.unwrap());
    repo.create(input(tenant, Some(user), &digest(), -1))
        .await
        .unwrap();
    repo.create(input(tenant, Some(Uuid::new_v4()), &digest(), 300))
        .await
        .unwrap();
    repo.create(input(tenant, None, &digest(), 300))
        .await
        .unwrap();
    repo.create(input(Uuid::new_v4(), Some(user), &digest(), 300))
        .await
        .unwrap();

    let listed = repo.list_pending_for_user(tenant, user, 50).await.unwrap();
    let ids: Vec<Uuid> = listed.iter().map(|r| r.id).collect();
    assert_eq!(ids, [sooner.id, later.id]);
    let limited = repo.list_pending_for_user(tenant, user, 1).await.unwrap();
    assert_eq!(limited.len(), 1);
    assert_eq!(limited[0].id, sooner.id);
    assert!(
        repo.list_pending_for_user(tenant, Uuid::new_v4(), 50)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn denial_is_conditional_and_final() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let req = repo
        .create(input(tenant, Some(user), &digest(), 300))
        .await
        .unwrap();
    assert!(!repo.deny(tenant, req.id, 0, Uuid::new_v4()).await.unwrap());
    assert!(repo.deny(tenant, req.id, 0, user).await.unwrap());
    let stored = repo.get_by_id(tenant, req.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CibaRequestStatus::Denied);
    assert!(stored.approval.is_none());
    assert!(
        !repo
            .approve(tenant, req.id, 1, user, evidence())
            .await
            .unwrap()
    );
}

/// The poll write is a compare-and-set on what the token endpoint read, and it
/// does not move `version` (an approval page's read stays valid while the
/// client polls).
#[tokio::test]
async fn polls_compare_and_set_without_moving_the_version() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let req = repo
        .create(input(tenant, Some(user), &digest(), 300))
        .await
        .unwrap();

    let first = Utc::now();
    assert!(
        repo.record_poll(tenant, req.id, None, first, 5)
            .await
            .unwrap()
    );
    // The same read again lost the race: someone wrote in between.
    assert!(
        !repo
            .record_poll(tenant, req.id, None, first, 5)
            .await
            .unwrap()
    );
    let stored = repo.get_by_id(tenant, req.id).await.unwrap().unwrap();
    assert_eq!(stored.version, 0, "a poll is not a transition");
    let seen = stored.last_polled_at;
    assert!(seen.is_some());

    let second = first + Duration::seconds(6);
    assert!(
        repo.record_poll(tenant, req.id, seen, second, 10)
            .await
            .unwrap()
    );
    let stored = repo.get_by_id(tenant, req.id).await.unwrap().unwrap();
    assert_eq!(stored.interval_secs, 10);
    // The approval page's read is still current.
    assert!(
        repo.approve(tenant, req.id, 0, user, evidence())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn redemption_needs_approval_the_starting_client_and_happens_once() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let hash = digest();
    let req = repo
        .create(input(tenant, Some(user), &hash, 300))
        .await
        .unwrap();

    // Pending: nothing to redeem.
    assert!(
        repo.redeem(tenant, &hash, "oa_ciba_client")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.approve(tenant, req.id, 0, user, evidence())
            .await
            .unwrap()
    );
    // Another client, or another tenant: nothing.
    assert!(
        repo.redeem(tenant, &hash, "oa_other")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.redeem(Uuid::new_v4(), &hash, "oa_ciba_client")
            .await
            .unwrap()
            .is_none()
    );

    let redeemed = repo
        .redeem(tenant, &hash, "oa_ciba_client")
        .await
        .unwrap()
        .expect("the approved request redeems");
    assert_eq!(redeemed.user_id, Some(user));
    assert!(redeemed.approval.is_some());
    assert!(
        repo.redeem(tenant, &hash, "oa_ciba_client")
            .await
            .unwrap()
            .is_none()
    );
    let stored = repo.get_by_hash(tenant, &hash).await.unwrap().unwrap();
    assert_eq!(stored.status, CibaRequestStatus::Redeemed);
}

/// The X6 arbiter under real concurrency, on the persistent engine production
/// runs (see `permission_ticket_test` for how to triage a red run).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_redemptions_yield_exactly_one_winner() {
    const ROUNDS: usize = 50;
    const RACERS: usize = 8;

    let db = common::serialising_db().await;
    let repo = SurrealCibaRequestRepository::new(db.handle(), None);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();

    for round in 0..ROUNDS {
        let hash = digest();
        let req = repo
            .create(input(tenant, Some(user), &hash, 300))
            .await
            .unwrap();
        assert!(
            repo.approve(tenant, req.id, 0, user, evidence())
                .await
                .unwrap()
        );

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let hash = hash.clone();
            set.spawn(async move {
                barrier.wait().await;
                repo.redeem(tenant, &hash, "oa_ciba_client").await.unwrap()
            });
        }
        let mut winners = 0;
        while let Some(result) = set.join_next().await {
            if result.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "exactly one redemption may win (round {round})");
    }
}

#[tokio::test]
async fn expiry_is_marked_conditionally_and_the_sweep_marks_then_deletes() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let live = repo
        .create(input(tenant, Some(user), &digest(), 300))
        .await
        .unwrap();
    let lapsed = repo
        .create(input(tenant, Some(user), &digest(), -1))
        .await
        .unwrap();

    // Not yet expired: refused. Expired, with a stale version: refused.
    assert!(!repo.mark_expired(tenant, live.id, 0).await.unwrap());
    assert!(!repo.mark_expired(tenant, lapsed.id, 3).await.unwrap());
    assert!(repo.mark_expired(tenant, lapsed.id, 0).await.unwrap());
    let stored = repo.get_by_id(tenant, lapsed.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CibaRequestStatus::Expired);

    let other = repo
        .create(input(tenant, Some(user), &digest(), -1))
        .await
        .unwrap();
    // Within the retention: marked, kept.
    let removed = repo
        .sweep_expired(Utc::now(), Duration::minutes(10))
        .await
        .unwrap();
    assert_eq!(removed, 0);
    let stored = repo.get_by_id(tenant, other.id).await.unwrap().unwrap();
    assert_eq!(stored.status, CibaRequestStatus::Expired);
    // Past the retention: deleted, and the live one survives.
    let removed = repo
        .sweep_expired(Utc::now() + Duration::minutes(11), Duration::minutes(10))
        .await
        .unwrap();
    assert_eq!(removed, 2);
    assert!(repo.get_by_id(tenant, other.id).await.unwrap().is_none());
    assert!(repo.get_by_id(tenant, live.id).await.unwrap().is_some());
}

#[tokio::test]
async fn ping_credentials_are_sealed_and_need_the_key() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let creds = CibaPingCredentials {
        auth_req_id: Uuid::new_v4().simple().to_string(),
        client_notification_token: Uuid::new_v4().simple().to_string(),
    };
    let mut ping = input(tenant, Some(Uuid::new_v4()), &digest(), 300);
    ping.delivery_mode = CibaDeliveryMode::Ping;
    ping.ping = Some(creds.clone());

    // No key: refused rather than stored in clear.
    let keyless = SurrealCibaRequestRepository::new(db.clone(), None);
    assert!(matches!(
        keyless.create(ping.clone()).await,
        Err(AxiamError::ServiceUnavailable(_))
    ));

    let repo = repo(&db);
    let stored = repo.create(ping).await.unwrap();
    assert_eq!(stored.delivery_mode, CibaDeliveryMode::Ping);
    let opened = repo
        .ping_credentials(tenant, stored.id)
        .await
        .unwrap()
        .expect("a ping request holds credentials");
    assert!(
        opened == creds,
        "the sealed credentials open to what was stored"
    );

    // At rest, neither value appears.
    let mut raw = db
        .query("SELECT ping_ciphertext, ping_nonce FROM ciba_request")
        .await
        .unwrap();
    let rows: Vec<serde_json::Value> = raw.take(0).unwrap();
    let rendered = serde_json::to_string(&rows).unwrap();
    assert!(!rendered.contains(&creds.auth_req_id));
    assert!(!rendered.contains(&creds.client_notification_token));

    // A poll request holds none.
    let poll = repo
        .create(input(tenant, None, &digest(), 300))
        .await
        .unwrap();
    assert!(
        repo.ping_credentials(tenant, poll.id)
            .await
            .unwrap()
            .is_none()
    );
}

async fn tenant_with_user(db: &Surreal<Db>) -> (Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "CIBA Org".into(),
            slug: format!("ciba-org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "CIBA Tenant".into(),
            slug: format!("ciba-tenant-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "ciba-user".into(),
            email: "ciba-user@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    (tenant.id, user.id)
}

#[tokio::test]
async fn erasure_and_tenant_deletion_remove_the_requests() {
    let db = setup().await;
    let repo = repo(&db);
    let (tenant, user) = tenant_with_user(&db).await;
    let req = repo
        .create(input(tenant, Some(user), &digest(), 300))
        .await
        .unwrap();
    SurrealUserRepository::new(db.clone())
        .delete(tenant, user)
        .await
        .unwrap();
    assert!(
        repo.get_by_id(tenant, req.id).await.unwrap().is_none(),
        "erasing the user removes the requests that name them"
    );

    let (tenant, user) = tenant_with_user(&db).await;
    let req = repo
        .create(input(tenant, Some(user), &digest(), 300))
        .await
        .unwrap();
    SurrealTenantRepository::new(db.clone())
        .delete(tenant)
        .await
        .unwrap();
    assert!(repo.get_by_id(tenant, req.id).await.unwrap().is_none());
}

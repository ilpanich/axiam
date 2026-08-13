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

mod common;

async fn repo() -> SurrealPermissionTicketRepository<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    SurrealPermissionTicketRepository::new(db)
}

/// The single-use tests need the engine production runs, not `Mem` — see
/// `tests/common/mod.rs` for the measurements. Everything else in this file
/// asserts what a query does rather than how it serialises, and stays on `Mem`.
async fn serialising_repo() -> (
    SurrealPermissionTicketRepository<surrealdb::engine::local::Db>,
    common::SerialisingDb,
) {
    let db = common::serialising_db().await;
    (SurrealPermissionTicketRepository::new(db.handle()), db)
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
/// the guarded `consume` exists to lose safely.
///
/// # Why this runs many rounds, and on surrealkv
///
/// Until 2026-08 this test fired 8 racers **once**, against `Mem`. Both halves
/// of that were wrong for what it claims to prove.
///
/// A single round cannot distinguish "serialises" from "usually serialises":
/// the defect it is looking for shows up in roughly 1–2% of contended rounds,
/// so one round passes ~98 times in 100. That is exactly the shape #302
/// describes — "intermittent on the `cargo-llvm-cov` job, passes routinely
/// otherwise" — and an intermittently-passing test is not a regression guard,
/// it is a coin toss that gets re-run until it agrees.
///
/// And `Mem` is not the engine AXIAM deploys. On the synthetic path in
/// `tools/surreal-race-probe`, `Mem` admits two winners where `surrealkv` and
/// `rocksdb` admit none, so a green run there was a statement about an engine
/// this project does not ship.
///
/// # What ROUNDS does and does not buy
///
/// Be careful about what this test proves, because the honest answer is less
/// than it looks. Running THIS path — the real `consume`, not the probe's
/// synthetic one — against `Mem` for 2000 rounds × 8 racers produced **zero**
/// violations in 16 000 attempts, on an idle machine without coverage
/// instrumentation. The probe's simpler query on the same engine produced 6 in
/// 9600. So the two are not measuring the same thing, and no round count
/// derived from the probe's rate transfers here.
///
/// #302 is explicit that its own 1-in-640 needed `cargo-llvm-cov` **plus** a
/// saturated machine to surface. This test has neither, so its silence is weak
/// evidence and must not be read as proof that the path is sound.
///
/// 200 rounds is therefore a *regression guard*, not a proof: it costs a few
/// seconds, it catches anything that breaks badly rather than rarely, and it is
/// strictly better than the single unsynchronised round this test used to run —
/// which could not even distinguish "serialises" from "never overlapped".
/// For questions about an engine, run the probe; that is what it is for.
///
/// # Triaging a red run here (revised by X6, #302 closed)
///
/// #302 used to carry a note telling triagers that an intermittent failure of
/// this test was a known residual rather than a regression from whatever PR was
/// in front of them, to be re-run once and moved past. **That note no longer
/// applies and must not be used.** The residual it described was a property of
/// the nonce-only mechanism, and `consume` now runs a transaction *and* the
/// nonce: the engine aborts the losers and the nonce read-back catches anything
/// it missed.
///
/// So on `surrealkv` — which is what this test opens — a failure here is a real
/// regression. Do not re-run it and move on, and do not weaken the test.
/// Diagnose in this order:
///
///   1. Did someone fold the nonce read-back back inside the transaction?
///      Under snapshot isolation every racer then sees its own write and
///      believes it won, so the failure will be near-total rather than rare.
///   2. Did the `BEGIN`/`COMMIT` come off, or `WHERE consumed = false`?
///   3. Did SurrealDB move? Run `tools/surreal-race-probe surrealkv tx 5000 8`
///      and compare against `RESULTS.md`. That is the case the CI gate exists
///      to catch before it reaches here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_redemptions_yield_exactly_one_winner() {
    const ROUNDS: usize = 200;
    const RACERS: usize = 8;

    let (repo, _db) = serialising_repo().await;
    let tenant = Uuid::new_v4();

    for round in 0..ROUNDS {
        let hash = format!("hash-8-{round}");
        repo.create(ticket(tenant, &hash, "rs-1", 60, Uuid::new_v4()))
            .await
            .unwrap();

        // Real threads, not interleaved polling on one: the property under test
        // is that the datastore serialises the racers, and a single-threaded
        // runtime could pass by never overlapping them. The barrier is what
        // makes them actually overlap — without it the first racer routinely
        // finishes before the last one starts, and the window never opens.
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            let hash = hash.clone();
            set.spawn(async move {
                barrier.wait().await;
                repo.consume(tenant, &hash, "rs-1").await.unwrap()
            });
        }

        let mut winners = 0;
        while let Some(result) = set.join_next().await {
            if result.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "exactly one concurrent redemption may succeed (round {round})"
        );
    }
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

// ---------------------------------------------------------------------------
// Single-use serialisation across every credential that claims it
// ---------------------------------------------------------------------------
//
// Deliberately an inner module of this file rather than a test file of its own.
// Each integration-test file is a separate linked binary, `axiam-db` already
// has ~39 of them, and the CI runner ran out of disk linking this crate's
// tests — `ld` died with SIGBUS at 48 MB free. Two suites that share a theme
// can share a binary.

mod single_use_serialisation {
    // Single-use consumes must serialise under concurrency (SEC — X2 follow-up).
    //
    // # What these tests exist to prevent
    //
    // Several credentials in AXIAM are single-use: an authorization code, a
    // device code, a PAR `request_uri`, a UMA permission ticket. Each is enforced
    // by an `UPDATE ... WHERE <precondition> ... RETURN BEFORE` whose doc comment
    // says exactly one concurrent caller can win.
    //
    // That guard is necessary but **not sufficient**. A multi-statement query
    // (`LET $x = (UPDATE ...); SELECT ... FROM $x`) is not atomic in SurrealDB —
    // each statement runs in its own transaction — so without an explicit
    // `BEGIN`/`COMMIT` the racers are not serialised at all. Measured before the
    // fix: the device grant let **4 of 8** concurrent redemptions win (one user
    // approval minting four token sets) and PAR let **2 of 8** win.
    //
    // The single-threaded tests that already cover these paths all passed against
    // the broken code, because they never overlap two callers. These do, on real
    // threads — a current-thread runtime could pass by never overlapping them.
    //
    // # Engine, 2026-08
    //
    // These opened `Mem` until the #302 investigation measured what `Mem`
    // actually guarantees, which is less than production's `surrealkv`: it
    // admits two winners to a guarded single-use UPDATE in ~1% of contended
    // rounds, where `surrealkv` and `rocksdb` admit none. Details and numbers
    // in `tests/common/mod.rs`. They now use the engine we deploy, so a green
    // run here is a statement about the shipped system.
    //
    // They remain single-round: unlike the permission ticket above, these four
    // paths have never been observed failing, and one barrier-synchronised
    // round each is the cheap regression guard. The permission-ticket test is
    // the instrument — it runs 200 rounds because it is the path whose defect
    // was actually measured.

    use axiam_core::models::oauth2_client::{
        CreateAuthorizationCode, CreateDeviceGrant, CreatePushedAuthRequest, CreateRefreshToken,
        PushedAuthParams,
    };
    use axiam_core::repository::{
        AuthorizationCodeRepository, DeviceGrantRepository, PushedAuthRequestRepository,
        RefreshTokenRepository,
    };
    use axiam_db::repository::{
        SurrealAuthorizationCodeRepository, SurrealDeviceGrantRepository,
        SurrealPushedAuthRequestRepository, SurrealRefreshTokenRepository,
    };
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use super::common;

    const RACERS: usize = 8;

    async fn db() -> common::SerialisingDb {
        common::serialising_db().await
    }

    /// One approval must mint exactly one token set, however hard the device polls.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn device_grant_redeem_serialises() {
        // `_db` is bound rather than dropped: it owns the TempDir backing the
        // surrealkv datastore, and dropping it would delete the files underneath.
        let _db = db().await;
        let repo = SurrealDeviceGrantRepository::new(_db.handle());
        let tenant = Uuid::new_v4();

        let grant = repo
            .create(CreateDeviceGrant {
                tenant_id: tenant,
                client_id: "tv-app".into(),
                device_code_hash: "dc-hash".into(),
                user_code: "BCDFGHJK".into(),
                scopes: vec!["openid".into()],
                expires_at: Utc::now() + Duration::seconds(600),
                interval_secs: 5,
            })
            .await
            .unwrap();
        repo.decide(tenant, &grant.user_code, true, Uuid::new_v4())
            .await
            .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            set.spawn(async move {
                barrier.wait().await;
                repo.redeem(tenant, "dc-hash").await.unwrap()
            });
        }

        let mut winners = 0;
        while let Some(r) = set.join_next().await {
            if r.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "one approval must redeem exactly once (RFC 8628 §3.5)"
        );
    }

    /// RFC 9126 §2.2: a `request_uri` is one-time-use, because a replayable one is
    /// a replayable authorization request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pushed_auth_request_consume_serialises() {
        // `_db` is bound rather than dropped: it owns the TempDir backing the
        // surrealkv datastore, and dropping it would delete the files underneath.
        let _db = db().await;
        let repo = SurrealPushedAuthRequestRepository::new(_db.handle());
        let tenant = Uuid::new_v4();

        repo.create(CreatePushedAuthRequest {
            tenant_id: tenant,
            client_id: "web-app".into(),
            request_uri_hash: "par-hash".into(),
            params: PushedAuthParams::default(),
            expires_at: Utc::now() + Duration::seconds(60),
        })
        .await
        .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            set.spawn(async move {
                barrier.wait().await;
                repo.consume(tenant, "par-hash").await.unwrap()
            });
        }

        let mut winners = 0;
        while let Some(r) = set.join_next().await {
            if r.unwrap().is_some() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "a pushed request must be spendable exactly once"
        );
    }

    /// The authorization code path was already safe — its consume is a single
    /// statement, which SurrealDB does execute atomically. Pinned so a later
    /// refactor to the `LET ...; SELECT ...` shape cannot silently reintroduce the
    /// bug the other two had.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn authorization_code_consume_serialises() {
        // `_db` is bound rather than dropped: it owns the TempDir backing the
        // surrealkv datastore, and dropping it would delete the files underneath.
        let _db = db().await;
        let repo = SurrealAuthorizationCodeRepository::new(_db.handle());
        let tenant = Uuid::new_v4();

        repo.create(CreateAuthorizationCode {
            tenant_id: tenant,
            code_hash: "code-hash".into(),
            client_id: "web-app".into(),
            user_id: Uuid::new_v4(),
            redirect_uri: "https://app.example/cb".into(),
            scopes: vec!["openid".into()],
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
            session_id: None,
            expires_at: Utc::now() + Duration::seconds(60),
        })
        .await
        .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            set.spawn(async move {
                barrier.wait().await;
                repo.consume(tenant, "code-hash", "web-app", "https://app.example/cb")
                    .await
            });
        }

        // This repository signals a lost race as `Err`, not `Ok(None)` — the
        // assertion is on how many callers got a code, not on the error shape.
        let mut winners = 0;
        while let Some(r) = set.join_next().await {
            if r.unwrap().is_ok() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "an authorization code must be exchangeable exactly once"
        );
    }

    /// Refresh-token rotation was also already safe, by a different route: its
    /// `revoke` is a single statement, and the service's rotation compensates on a
    /// lost race — the loser's `revoke` returns `NotFound`, so it revokes the token
    /// it just minted and answers `invalid_grant` instead of handing over a second
    /// live token set.
    ///
    /// That makes `revoke` the serialisation point for rotation, so it is pinned
    /// here: exactly one of N concurrent revocations of one token may succeed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refresh_token_revoke_serialises() {
        // `_db` is bound rather than dropped: it owns the TempDir backing the
        // surrealkv datastore, and dropping it would delete the files underneath.
        let _db = db().await;
        let repo = SurrealRefreshTokenRepository::new(_db.handle());
        let tenant = Uuid::new_v4();

        repo.create(CreateRefreshToken {
            tenant_id: tenant,
            token_hash: "rt-hash".into(),
            client_id: "web-app".into(),
            user_id: Some(Uuid::new_v4()),
            scopes: vec!["openid".into()],
            session_id: None,
            expires_at: Utc::now() + Duration::seconds(3600),
        })
        .await
        .unwrap();

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(RACERS));
        let mut set = tokio::task::JoinSet::new();
        for _ in 0..RACERS {
            let repo = repo.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            set.spawn(async move {
                barrier.wait().await;
                repo.revoke(tenant, "rt-hash").await
            });
        }

        let mut winners = 0;
        while let Some(r) = set.join_next().await {
            if r.unwrap().is_ok() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "exactly one rotation may consume a refresh token — the others must \
             see NotFound and refuse rather than mint a second token set"
        );
    }
}

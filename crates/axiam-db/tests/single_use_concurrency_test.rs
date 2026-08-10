//! Single-use consumes must serialise under concurrency (SEC — X2 follow-up).
//!
//! # What these tests exist to prevent
//!
//! Several credentials in AXIAM are single-use: an authorization code, a
//! device code, a PAR `request_uri`, a UMA permission ticket. Each is enforced
//! by an `UPDATE ... WHERE <precondition> ... RETURN BEFORE` whose doc comment
//! says exactly one concurrent caller can win.
//!
//! That guard is necessary but **not sufficient**. A multi-statement query
//! (`LET $x = (UPDATE ...); SELECT ... FROM $x`) is not atomic in SurrealDB —
//! each statement runs in its own transaction — so without an explicit
//! `BEGIN`/`COMMIT` the racers are not serialised at all. Measured before the
//! fix: the device grant let **4 of 8** concurrent redemptions win (one user
//! approval minting four token sets) and PAR let **2 of 8** win.
//!
//! The single-threaded tests that already cover these paths all passed against
//! the broken code, because they never overlap two callers. These do, on real
//! threads — a current-thread runtime could pass by never overlapping them.

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
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const RACERS: usize = 8;

async fn db() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// One approval must mint exactly one token set, however hard the device polls.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn device_grant_redeem_serialises() {
    let repo = SurrealDeviceGrantRepository::new(db().await);
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

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let repo = repo.clone();
        set.spawn(async move { repo.redeem(tenant, "dc-hash").await.unwrap() });
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
    let repo = SurrealPushedAuthRequestRepository::new(db().await);
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

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let repo = repo.clone();
        set.spawn(async move { repo.consume(tenant, "par-hash").await.unwrap() });
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
    let repo = SurrealAuthorizationCodeRepository::new(db().await);
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

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let repo = repo.clone();
        set.spawn(async move {
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
    let repo = SurrealRefreshTokenRepository::new(db().await);
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

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..RACERS {
        let repo = repo.clone();
        set.spawn(async move { repo.revoke(tenant, "rt-hash").await });
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

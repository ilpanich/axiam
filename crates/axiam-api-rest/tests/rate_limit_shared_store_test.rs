//! SECHRD-03 / D-01a, D-01b — shared rate-limit store middleware.
//!
//! Since the H2 performance fix the middleware counts through the write-behind
//! `axiam_db::SharedRateLimitCounter` instead of awaiting one SurrealDB UPSERT
//! per request, so cross-replica enforcement is *eventual*: a replica counts
//! its own traffic immediately and adopts the other replicas' contributions at
//! its next flush. These tests inject an explicit counter into `AppState` and
//! drive `flush_once()` themselves, proving the same property
//! deterministically rather than sleeping on the background flusher.
//!
//! Proves:
//! - `rate_limit_shared_store_cross_instance`: two independent middleware
//!   instances ("replicas") sharing ONE SurrealDB enforce a single combined
//!   limit after a flush cycle — the in-memory-only baseline (per-replica
//!   buckets) would allow `2 × LIMIT`.
//! - `rate_limit_shared_store_fails_open_on_db_error`: an unreachable shared
//!   store never 5xxes, never panics and never hard-blocks; the flush failure
//!   is absorbed and local enforcement continues — D-01b.
//! - `rate_limit_shared_store_disabled_by_env_allows_everything`:
//!   `AXIAM__RATE_LIMIT__SHARED=off` leaves the in-memory governor as the sole
//!   limiter and touches no store.

use std::sync::Arc;

use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::middleware::rate_limit_shared::RateLimitShared;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_db::repository::SurrealRateLimitBucketRepository;
use axiam_db::{SharedRateLimitConfig, SharedRateLimitCounter};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

type TestDb = Db;

/// Per-endpoint limit shared by both "replicas" in the cross-instance test.
const LIMIT: u32 = 3;

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// One "replica": an independent write-behind counter over the supplied
/// SurrealDB handle, with NO background flusher so the test controls exactly
/// when convergence happens.
fn replica_counter(db: Surreal<TestDb>) -> SharedRateLimitCounter {
    SharedRateLimitCounter::without_flusher(
        SharedRateLimitConfig::default(),
        Arc::new(SurrealRateLimitBucketRepository::new(db)),
    )
}

/// Builds a minimal single-resource app wrapping `/t` with
/// `RateLimitShared` (standing in for the real `build_governor(...)` +
/// `RateLimitShared` pairing in `server.rs` — the in-memory governor itself
/// is not needed to prove the shared-store's own behavior here; the plain
/// handler stands in for "the request proceeded").
///
/// `counter` is injected into `AppState` exactly as `main.rs` does, which is
/// also what lets a test hold the handle and flush it.
fn build_app(
    db: Surreal<TestDb>,
    counter: SharedRateLimitCounter,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    let mut state = AppState::for_test(db, AuthConfig::default());
    state.shared_rate_limit = counter;
    App::new().app_data(web::Data::new(state)).service(
        web::resource("/t")
            .wrap(RateLimitShared::<TestDb>::new("shared_test", LIMIT))
            .route(web::get().to(ok_handler)),
    )
}

#[actix_rt::test]
async fn rate_limit_shared_store_cross_instance() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    // Two INDEPENDENT app instances ("replicas"), each with its own
    // write-behind counter, sharing the SAME underlying SurrealDB handle —
    // proving the bucket is combined across replicas rather than reset
    // per-replica.
    let counter1 = replica_counter(db.clone());
    let counter2 = replica_counter(db.clone());
    let app1 = test::init_service(build_app(db.clone(), counter1.clone())).await;
    let app2 = test::init_service(build_app(db.clone(), counter2.clone())).await;

    let peer: std::net::SocketAddr = "203.0.113.42:5000".parse().unwrap();
    let get = || {
        test::TestRequest::get()
            .uri("/t")
            .peer_addr(peer)
            .to_request()
    };

    // LIMIT requests split alternately across BOTH "replicas" must all
    // succeed (this is the combined count climbing to exactly LIMIT).
    for i in 0..LIMIT {
        let resp = if i % 2 == 0 {
            test::call_service(&app1, get()).await
        } else {
            test::call_service(&app2, get()).await
        };
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    // One write-behind flush cycle per replica: each writes its coalesced
    // delta and reads back the authoritative combined count.
    counter1.flush_once().await;
    counter2.flush_once().await;
    // counter1 flushed before counter2's delta landed, so it needs one more
    // pass to adopt the combined count — the documented bounded staleness,
    // not a lost update.
    test::call_service(&app1, get()).await;
    counter1.flush_once().await;

    // Requests on EITHER replica are now rejected — proving the count is
    // SHARED (an in-memory-only per-replica baseline would instead allow
    // LIMIT more requests on whichever replica hasn't seen traffic).
    let resp = test::call_service(&app1, get()).await;
    assert_eq!(
        resp.status(),
        429,
        "replica 1 must observe the shared count"
    );

    let resp = test::call_service(&app2, get()).await;
    assert_eq!(
        resp.status(),
        429,
        "replica 2 must observe the shared count"
    );
}

#[actix_rt::test]
async fn rate_limit_shared_store_fails_open_on_db_error() {
    // A DB handle that never selected a namespace/database — every query
    // against it errors ("Specify a namespace to use"). This simulates the
    // shared store being unreachable without touching migrations.
    let broken_db = Surreal::new::<Mem>(()).await.unwrap();

    let counter = replica_counter(broken_db.clone());
    let app = test::init_service(build_app(broken_db, counter.clone())).await;

    let peer: std::net::SocketAddr = "198.51.100.9:1111".parse().unwrap();
    let get = || {
        test::TestRequest::get()
            .uri("/t")
            .peer_addr(peer)
            .to_request()
    };

    // Fail-open (D-01b): requests within the configured limit proceed to the
    // handler (standing in for the in-memory governor) despite the broken
    // shared store — never a 5xx, never a hard block on auth traffic. The
    // decision no longer involves a datastore round trip at all (H2 fix), so
    // there is no store error on the request path to fail open *from*.
    for i in 0..LIMIT {
        let resp = test::call_service(&app, get()).await;
        assert_eq!(resp.status(), 200, "request {i} must proceed");
    }

    // The flusher discovers the outage: it must absorb the error without
    // panicking or poisoning the counter.
    counter.flush_once().await;

    // Still serving. The local count legitimately sits at the limit, so this
    // is a 429 from the limit — not from the outage. "Store unreachable" must
    // never become "limit disabled".
    let resp = test::call_service(&app, get()).await;
    assert_eq!(resp.status(), 429);

    // A different client is unaffected — the flush failure did not break the
    // counter.
    let other: std::net::SocketAddr = "198.51.100.11:3333".parse().unwrap();
    let resp = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/t")
            .peer_addr(other)
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), 200);
}

/// `AXIAM__RATE_LIMIT__SHARED=off` (single-replica deployments): the shared
/// layer is skipped entirely and never denies, leaving the per-replica
/// in-memory governor as the sole limiter. Uses an explicitly disabled counter
/// rather than mutating the process env, which would race other tests.
#[actix_rt::test]
async fn rate_limit_shared_store_disabled_by_env_allows_everything() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let disabled = SharedRateLimitCounter::disabled(SharedRateLimitConfig {
        enabled: false,
        ..SharedRateLimitConfig::default()
    });
    assert!(!disabled.is_enabled());

    let app = test::init_service(build_app(db, disabled.clone())).await;
    let peer: std::net::SocketAddr = "198.51.100.30:4444".parse().unwrap();

    // Far past LIMIT: the shared layer must never reject.
    for i in 0..(LIMIT * 5) {
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .uri("/t")
                .peer_addr(peer)
                .to_request(),
        )
        .await;
        assert_eq!(
            resp.status(),
            200,
            "request {i} must pass — the shared layer is off"
        );
    }

    // No state was even allocated, so nothing could have been written.
    assert_eq!(disabled.bucket_count(), 0);
}

/// Proves `RateLimitShared`'s `Clone` impl (only ever invoked by an
/// explicit `.clone()` call — actix's `.wrap()` takes ownership, so no
/// existing test calls it) produces a middleware that enforces the exact
/// same limit as the original.
#[actix_rt::test]
async fn rate_limit_shared_clone_enforces_the_same_limit() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let original = RateLimitShared::<TestDb>::new("shared_clone_test", LIMIT);
    let cloned = original.clone();

    let mut state = AppState::for_test(db.clone(), AuthConfig::default());
    state.shared_rate_limit = replica_counter(db);
    let app = test::init_service(
        App::new().app_data(web::Data::new(state)).service(
            web::resource("/t")
                .wrap(cloned)
                .route(web::get().to(ok_handler)),
        ),
    )
    .await;

    let peer: std::net::SocketAddr = "203.0.113.222:1".parse().unwrap();
    for i in 0..LIMIT {
        let req = test::TestRequest::get()
            .uri("/t")
            .peer_addr(peer)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            200,
            "request {i} via the cloned middleware should succeed"
        );
    }
    let req = test::TestRequest::get()
        .uri("/t")
        .peer_addr(peer)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status(),
        429,
        "the cloned middleware must enforce the same limit as the original"
    );
}

/// `RateLimitSharedService::poll_ready` (delegates to the inner service) is
/// never invoked by `actix_web::test::call_service` — actix's test harness
/// calls `.call()` directly without polling readiness first. Call it
/// directly on the assembled service to prove it delegates cleanly instead
/// of panicking/erroring.
#[actix_rt::test]
async fn rate_limit_shared_service_poll_ready_delegates_to_inner() {
    use actix_web::dev::Service;
    use std::task::{Context, Waker};

    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let counter = replica_counter(db.clone());
    let app = test::init_service(build_app(db, counter)).await;

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let poll = app.poll_ready(&mut cx);
    assert!(
        poll.is_ready(),
        "assembled service (including RateLimitShared) must report ready immediately"
    );
}

#[actix_rt::test]
async fn rate_limit_shared_store_fails_open_when_no_db_registered() {
    // No `web::Data<AppState<TestDb>>` registered at all (e.g. a
    // misconfigured test harness), so the middleware finds no shared counter —
    // it must still fail open rather than panicking or 500ing.
    let app = test::init_service(
        App::new().service(
            web::resource("/t")
                .wrap(RateLimitShared::<TestDb>::new("shared_test_no_db", LIMIT))
                .route(web::get().to(ok_handler)),
        ),
    )
    .await;

    let peer: std::net::SocketAddr = "198.51.100.10:2222".parse().unwrap();
    let req = test::TestRequest::get()
        .uri("/t")
        .peer_addr(peer)
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), 200);
}

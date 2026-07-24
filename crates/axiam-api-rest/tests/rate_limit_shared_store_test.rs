//! SECHRD-03 / D-01a, D-01b — shared SurrealDB rate-limit store middleware.
//!
//! Proves:
//! - `rate_limit_shared_store_cross_instance`: two independent middleware
//!   instances ("replicas") sharing ONE SurrealDB enforce a single combined
//!   limit — the in-memory-only baseline (per-replica buckets) would NOT
//!   reject at this point.
//! - `rate_limit_shared_store_fails_open_on_db_error`: when the shared
//!   store errors, the request proceeds (no 5xx, no hard block) — D-01b.

use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::middleware::rate_limit_shared::RateLimitShared;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

type TestDb = Db;

/// Per-endpoint limit shared by both "replicas" in the cross-instance test.
const LIMIT: u32 = 3;

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// Builds a minimal single-resource app wrapping `/t` with
/// `RateLimitShared` (standing in for the real `build_governor(...)` +
/// `RateLimitShared` pairing in `server.rs` — the in-memory governor itself
/// is not needed to prove the shared-store's own behavior here; the plain
/// handler stands in for "the request proceeded").
fn build_app(
    db: Surreal<TestDb>,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .app_data(web::Data::new(AppState::for_test(
            db,
            AuthConfig::default(),
        )))
        .service(
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

    // Two INDEPENDENT app instances ("replicas") sharing the SAME
    // underlying SurrealDB handle — proving the bucket is combined across
    // replicas rather than reset per-replica.
    let app1 = test::init_service(build_app(db.clone())).await;
    let app2 = test::init_service(build_app(db.clone())).await;

    let peer: std::net::SocketAddr = "203.0.113.42:5000".parse().unwrap();

    // LIMIT requests split alternately across BOTH "replicas" must all
    // succeed (this is the shared count climbing to exactly LIMIT).
    for i in 0..LIMIT {
        let req = test::TestRequest::get()
            .uri("/t")
            .peer_addr(peer)
            .to_request();
        let resp = if i % 2 == 0 {
            test::call_service(&app1, req).await
        } else {
            test::call_service(&app2, req).await
        };
        assert_eq!(resp.status(), 200, "request {i} should succeed");
    }

    // The NEXT request on EITHER replica must be rejected — proving the
    // count is SHARED (an in-memory-only per-replica baseline would instead
    // allow LIMIT more requests on whichever replica hasn't seen traffic).
    let req = test::TestRequest::get()
        .uri("/t")
        .peer_addr(peer)
        .to_request();
    let resp = test::call_service(&app1, req).await;
    assert_eq!(
        resp.status(),
        429,
        "replica 1 must observe the shared count"
    );

    let req = test::TestRequest::get()
        .uri("/t")
        .peer_addr(peer)
        .to_request();
    let resp = test::call_service(&app2, req).await;
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

    let app = test::init_service(build_app(broken_db)).await;

    let peer: std::net::SocketAddr = "198.51.100.9:1111".parse().unwrap();
    let req = test::TestRequest::get()
        .uri("/t")
        .peer_addr(peer)
        .to_request();
    let resp = test::call_service(&app, req).await;

    // Fail-open (D-01b): the request proceeds to the handler (standing in
    // for the in-memory governor) despite the broken shared store — never a
    // 5xx, never a hard block on auth traffic.
    assert_eq!(resp.status(), 200);
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

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(AppState::for_test(
                db,
                AuthConfig::default(),
            )))
            .service(
                web::resource("/t")
                    .wrap(cloned)
                    .route(web::get().to(ok_handler)),
            ),
    )
    .await;

    let peer: std::net::SocketAddr = "203.0.113.222:1".parse().unwrap();
    for i in 0..LIMIT {
        let req = test::TestRequest::get().uri("/t").peer_addr(peer).to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200, "request {i} via the cloned middleware should succeed");
    }
    let req = test::TestRequest::get().uri("/t").peer_addr(peer).to_request();
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

    let app = test::init_service(build_app(db)).await;

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
    // No `web::Data<Surreal<TestDb>>` registered at all (e.g. a
    // misconfigured test harness) — the middleware must still fail open
    // rather than panicking or 500ing.
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

//! SECHRD-03 / D-01a, D-01b, D-01c, D-01d — shared SurrealDB rate-limit store
//! for the gRPC path, bringing it to parity with the REST shared-store
//! pre-check (plan 24-04).
//!
//! Since the H2 performance fix the layer is backed by the write-behind
//! `axiam_db::SharedRateLimitCounter`, so cross-replica enforcement is
//! *eventual*: a replica counts its own traffic immediately and adopts the
//! other replicas' contributions at its next flush. These tests therefore
//! drive `flush_once()` explicitly (via
//! `GrpcSharedRateLimitLayer::with_counter` plus
//! `SharedRateLimitCounter::without_flusher`) instead of sleeping on the
//! background flusher, proving the same property deterministically.
//!
//! Proves:
//! - `rate_limit_shared_store_cross_instance`: two independent
//!   `GrpcSharedRateLimitLayer` instances ("replicas") sharing ONE SurrealDB
//!   enforce a single combined limit after a flush cycle — an in-memory-only
//!   baseline (per-replica buckets) would allow `2 × LIMIT`.
//! - `rate_limit_shared_store_peer_parity_rotating_xff`: a rotating
//!   (attacker-controlled) single-hop `X-Forwarded-For` header does NOT mint
//!   a fresh bucket when `trusted_hops >= hops.len()` — the shared bucket
//!   key is derived from the verified peer address instead (D-01d parity
//!   with the fixed REST `XForwardedForKeyExtractor`).
//! - `rate_limit_shared_store_fails_open_on_db_error`: when the shared store
//!   is unreachable, traffic keeps flowing (no hard block, no panic, no 5xx)
//!   and the layer keeps enforcing from local counts — D-01b.
//!
//! Run with: cargo test -p axiam-api-grpc --test rate_limit_shared_store_test

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use axiam_api_grpc::middleware::rate_limit::GrpcSharedRateLimitLayer;
use axiam_db::repository::SurrealRateLimitBucketRepository;
use axiam_db::{SharedRateLimitConfig, SharedRateLimitCounter};
use http::{HeaderValue, Request, Response};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};

type TestDb = Db;

/// Per-endpoint limit shared across "replicas" in the cross-instance test.
const LIMIT: u32 = 3;

/// Trivial always-ok inner tower service standing in for the real
/// `AuthorizationServiceServer`/`GovernorLayer` stack — this test proves the
/// shared-store LAYER's own behavior, not any particular gRPC service.
fn ok_service() -> impl Service<
    Request<tonic::body::Body>,
    Response = Response<tonic::body::Body>,
    Error = Infallible,
    Future: Send,
> + Clone
+ Send {
    tower::service_fn(|_req: Request<tonic::body::Body>| async move {
        Ok::<_, Infallible>(Response::new(tonic::body::Body::empty()))
    })
}

fn request_with_peer(peer: SocketAddr) -> Request<tonic::body::Body> {
    let mut req = Request::new(tonic::body::Body::empty());
    req.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(peer),
    });
    req
}

fn request_with_peer_and_xff(peer: SocketAddr, xff: &str) -> Request<tonic::body::Body> {
    let mut req = request_with_peer(peer);
    req.headers_mut()
        .insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
    req
}

/// Drives a request through a tower `Service`, awaiting readiness first
/// (both services under test here are always-ready, but this respects the
/// tower contract rather than calling `.call()` blind).
async fn call<S>(svc: &mut S, req: Request<tonic::body::Body>) -> Response<tonic::body::Body>
where
    S: Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>>,
    S::Error: std::fmt::Debug,
{
    std::future::poll_fn(|cx| svc.poll_ready(cx)).await.unwrap();
    svc.call(req).await.unwrap()
}

/// `true` when the response is the layer's own `RESOURCE_EXHAUSTED`
/// rejection. A `tonic::Status` extension is inserted ONLY by
/// `too_many_requests_response()` (via `Status::into_http`) — the trivial
/// `ok_service()` inner response never carries one, so this cleanly
/// distinguishes "allowed" from "rejected" without needing a shared counter.
fn is_rejected(resp: &Response<tonic::body::Body>) -> bool {
    resp.extensions()
        .get::<tonic::Status>()
        .map(|s| s.code() == tonic::Code::ResourceExhausted)
        .unwrap_or(false)
}

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
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

#[tokio::test]
async fn rate_limit_shared_store_cross_instance() {
    let db = setup_db().await;

    // Two INDEPENDENT layered services ("replicas"), each with its OWN
    // write-behind counter, sharing the SAME underlying SurrealDB handle —
    // proving the bucket is combined across replicas rather than reset
    // per-replica.
    let counter1 = replica_counter(db.clone());
    let counter2 = replica_counter(db);
    let mut svc1 = GrpcSharedRateLimitLayer::with_counter(
        counter1.clone(),
        "grpc_authz_cross_instance",
        LIMIT,
        0,
    )
    .layer(ok_service());
    let mut svc2 = GrpcSharedRateLimitLayer::with_counter(
        counter2.clone(),
        "grpc_authz_cross_instance",
        LIMIT,
        0,
    )
    .layer(ok_service());

    let peer: SocketAddr = "203.0.113.42:5000".parse().unwrap();

    // LIMIT requests split alternately across BOTH "replicas" must all
    // succeed (the combined count climbing to exactly LIMIT).
    for i in 0..LIMIT {
        let resp = if i % 2 == 0 {
            call(&mut svc1, request_with_peer(peer)).await
        } else {
            call(&mut svc2, request_with_peer(peer)).await
        };
        assert!(!is_rejected(&resp), "request {i} should succeed");
    }

    // One write-behind flush cycle per replica: each writes its coalesced
    // delta and reads back the authoritative combined count.
    counter1.flush_once().await;
    counter2.flush_once().await;
    // counter1 flushed before counter2's delta landed, so give it one more
    // pass to adopt the combined count (this is the documented bounded
    // staleness, not a lost update).
    call(&mut svc1, request_with_peer(peer)).await;
    counter1.flush_once().await;

    // Both replicas now observe the COMBINED count and reject — an
    // in-memory-only per-replica baseline would instead allow LIMIT more
    // requests on whichever replica hasn't seen traffic (2 × LIMIT total).
    let resp1 = call(&mut svc1, request_with_peer(peer)).await;
    assert!(
        is_rejected(&resp1),
        "replica 1 must observe the shared count"
    );

    let resp2 = call(&mut svc2, request_with_peer(peer)).await;
    assert!(
        is_rejected(&resp2),
        "replica 2 must observe the shared count"
    );
}

/// The shared count really is ONE row shared by both replicas (not two
/// independent per-replica counts), and the flusher coalesces: 6 requests
/// across two replicas produce ONE row holding 6.
#[tokio::test]
async fn rate_limit_shared_store_coalesces_into_one_shared_row() {
    let db = setup_db().await;

    let counter1 = replica_counter(db.clone());
    let counter2 = replica_counter(db.clone());
    let endpoint = "grpc_authz_coalesce";
    let mut svc1 = GrpcSharedRateLimitLayer::with_counter(counter1.clone(), endpoint, 100, 0)
        .layer(ok_service());
    let mut svc2 = GrpcSharedRateLimitLayer::with_counter(counter2.clone(), endpoint, 100, 0)
        .layer(ok_service());

    let peer: SocketAddr = "203.0.113.77:5000".parse().unwrap();
    for _ in 0..3 {
        assert!(!is_rejected(
            &call(&mut svc1, request_with_peer(peer)).await
        ));
        assert!(!is_rejected(
            &call(&mut svc2, request_with_peer(peer)).await
        ));
    }

    counter1.flush_once().await;
    counter2.flush_once().await;

    // A delta-0 write reads the authoritative count back without changing it.
    let repo = SurrealRateLimitBucketRepository::new(db);
    let key = format!("{endpoint}:203.0.113.77");
    let window = chrono::Utc::now();
    let window =
        chrono::DateTime::from_timestamp(window.timestamp() - window.timestamp().rem_euclid(60), 0)
            .unwrap();
    assert_eq!(
        repo.increment_by(&key, window, 0).await.unwrap(),
        6,
        "6 requests across 2 replicas must land in ONE shared row as 6"
    );
}

#[tokio::test]
async fn rate_limit_shared_store_peer_parity_rotating_xff() {
    let db = setup_db().await;

    // trusted_hops=1 with a single-hop XFF header: trusted_hops(1) >=
    // hops.len()(1), so the header is untrusted and the key is derived from
    // the verified peer address instead (SECHRD-03/D-01d).
    let mut svc =
        GrpcSharedRateLimitLayer::new(db, "grpc_authz_peer_parity", LIMIT, 1).layer(ok_service());

    let peer: SocketAddr = "198.51.100.7:9000".parse().unwrap();

    // LIMIT requests, each with a DIFFERENT (attacker-rotated) spoofed XFF
    // value but the SAME real peer, must all count against ONE shared
    // bucket — an XFF-trusting extractor would instead mint a fresh bucket
    // per rotation and never reject.
    for i in 0..LIMIT {
        let xff = format!("10.0.0.{i}");
        let resp = call(&mut svc, request_with_peer_and_xff(peer, &xff)).await;
        assert!(!is_rejected(&resp), "request {i} should succeed");
    }

    let resp = call(&mut svc, request_with_peer_and_xff(peer, "10.0.0.99")).await;
    assert!(
        is_rejected(&resp),
        "rotating XFF must not yield a fresh bucket — the peer-keyed shared count must reject"
    );
}

#[tokio::test]
async fn rate_limit_shared_store_fails_open_on_db_error() {
    // A DB handle that never selected a namespace/database — every query
    // against it errors ("Specify a namespace to use"). This simulates the
    // shared store being unreachable without touching migrations.
    let broken_db = Surreal::new::<Mem>(()).await.unwrap();

    let counter = replica_counter(broken_db);
    let mut svc =
        GrpcSharedRateLimitLayer::with_counter(counter.clone(), "grpc_authz_fail_open", LIMIT, 0)
            .layer(ok_service());

    let peer: SocketAddr = "198.51.100.9:1111".parse().unwrap();

    // With the store unreachable, traffic within the configured limit still
    // flows: the decision no longer depends on a datastore round trip at all
    // (H2 fix), so there is no store error on the request path to fail open
    // *from*.
    for i in 0..LIMIT {
        let resp = call(&mut svc, request_with_peer(peer)).await;
        assert!(
            !is_rejected(&resp),
            "request {i} must proceed despite the unreachable shared store"
        );
    }

    // The flusher discovers the outage. It must not panic, must not poison
    // the counter, and must keep the layer serving: D-01b fail-open now means
    // "cross-replica convergence pauses, local enforcement continues".
    counter.flush_once().await;

    // Still serving — a further request is evaluated against the local count
    // (which is legitimately at the limit), never a 5xx and never a panic.
    let resp = call(&mut svc, request_with_peer(peer)).await;
    assert!(
        is_rejected(&resp),
        "the local count still enforces the configured limit while the store is down — \
         a store outage must not become 'the limit is disabled'"
    );

    // And a DIFFERENT key is unaffected: the outage did not break the counter.
    let other: SocketAddr = "198.51.100.10:2222".parse().unwrap();
    let resp = call(&mut svc, request_with_peer(other)).await;
    assert!(
        !is_rejected(&resp),
        "a fresh bucket must still be admitted after a flush failure"
    );
}

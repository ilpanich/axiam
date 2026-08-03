//! I1/I2 — the gRPC rate-limit **units** and **scope**, driven through the
//! full layered stack (shared cross-replica pre-check → in-memory governor →
//! service), exactly as `server.rs::start_grpc_server` wires it.
//!
//! Proves:
//! - `sustained_overload_admits_configured_rate_times_sixty_per_minute`: under
//!   sustained overload the stack admits ≈ `configured_per_sec × 60` requests
//!   per minute (±10%). Before the I1 fix the shared pre-check enforced the
//!   per-**second** number against its 60-second window, so the stack admitted
//!   `configured_per_sec` per MINUTE — 1/60th of that — and this test fails
//!   loudly against the old wiring.
//! - `identity_reads_are_not_throttled_by_the_authz_ceiling`: an identity-read
//!   method keeps flowing after the authz bucket is exhausted (I2).
//! - `reflection_and_health_survive_a_saturated_server`: the infrastructure
//!   family has its own generous bucket, so probes keep answering while every
//!   other family is saturated.
//! - `reflection_and_health_are_bounded`: …and that bucket is finite, so the
//!   family is not an unmetered surface selected by prefix-matching the
//!   attacker-controlled `:path` (security re-verification, residual 4).
//!
//! Run with: cargo test -p axiam-api-grpc --test rate_limit_units_test

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axiam_api_grpc::middleware::rate_limit::{
    ADMIN_PER_SEC_DEFAULT, GrpcRateLimits, GrpcSharedRateLimitLayer, INFRA_PER_SEC,
    build_grpc_method_scoped_governor_layer,
};
use axiam_db::repository::SurrealRateLimitBucketRepository;
use axiam_db::{SharedRateLimitConfig, SharedRateLimitCounter};
use http::{Request, Response};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};

const AUTHZ_PATH: &str = "/axiam.v1.AuthorizationService/CheckAccess";
const IDENTITY_PATH: &str = "/axiam.v1.UserInfoService/GetUserInfo";
const ADMIN_PATH: &str = "/axiam.v1.UserService/ValidateCredentials";
const HEALTH_PATH: &str = "/grpc.health.v1.Health/Check";
const REFLECTION_PATH: &str = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo";

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

fn request(path: &str, peer: SocketAddr) -> Request<tonic::body::Body> {
    let mut req = Request::builder()
        .uri(path)
        .body(tonic::body::Body::empty())
        .expect("valid request");
    req.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(peer),
    });
    req
}

async fn call<S>(svc: &mut S, req: Request<tonic::body::Body>) -> bool
where
    S: Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>>,
    S::Error: std::fmt::Debug,
{
    std::future::poll_fn(|cx| svc.poll_ready(cx)).await.unwrap();
    let resp = svc.call(req).await.unwrap();
    // Either layer's rejection carries a `tonic::Status` extension (the
    // shared layer via `Status::into_http`, the governor via
    // `From<GovernorError> for Response<tonic::body::Body>`); the trivial
    // inner service never does.
    !resp
        .extensions()
        .get::<tonic::Status>()
        .map(|s| s.code() == tonic::Code::ResourceExhausted)
        .unwrap_or(false)
}

async fn counter() -> SharedRateLimitCounter {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    // No background flusher: this replica enforces from its own local counts,
    // which is exactly the single-replica production behaviour between two
    // flushes and keeps the test deterministic.
    SharedRateLimitCounter::without_flusher(
        SharedRateLimitConfig::default(),
        Arc::new(SurrealRateLimitBucketRepository::new(db)),
    )
}

/// The production stack: shared pre-check OUTERMOST, then the per-family
/// in-memory governor, then the service — the same order `server.rs` uses.
async fn stack(
    limits: GrpcRateLimits,
) -> impl Service<Request<tonic::body::Body>, Response = Response<tonic::body::Body>, Error = Infallible>
+ Clone {
    let shared = GrpcSharedRateLimitLayer::with_counter_method_scoped(counter().await, limits, 0);
    shared.layer(build_grpc_method_scoped_governor_layer(limits).layer(ok_service()))
}

/// **I1 acceptance.** Sustained overload through the full layered stack must
/// admit approximately `configured_per_sec` requests per second — i.e.
/// `configured_per_sec × 60` per minute — not `configured_per_sec` per minute.
///
/// Method: drain the governor's initial burst (a one-off allowance that is
/// not sustained throughput), then offer ~3x the configured rate for a fixed
/// measurement interval and extrapolate the admitted count to a minute. The
/// offered total stays far below the shared layer's 60-second budget
/// (`per_sec × 60`), so the *governor* is the binding layer — which is the
/// point: before the fix the shared layer clamped first, at 1/60th.
#[tokio::test]
async fn sustained_overload_admits_configured_rate_times_sixty_per_minute() {
    const PER_SEC: u32 = 200;
    const MEASURE: Duration = Duration::from_secs(4);
    const TICK: Duration = Duration::from_millis(5);
    /// 3 requests every 5 ms = 600/s offered against a 200/s ceiling.
    const PER_TICK: usize = 3;

    let limits = GrpcRateLimits::from_authz_per_sec(PER_SEC);
    let mut svc = stack(limits).await;
    let peer: SocketAddr = "203.0.113.10:5000".parse().unwrap();

    // Drain the governor's initial burst so it is not counted as sustained
    // throughput. (Under the pre-I1 wiring this loop already exhausts the
    // shared budget of 200-per-60s, and the measurement below then admits ~0.)
    let mut drained = 0usize;
    while call(&mut svc, request(AUTHZ_PATH, peer)).await {
        drained += 1;
        assert!(
            drained < 10_000,
            "the burst never drained — the stack is not limiting at all"
        );
    }

    let started = Instant::now();
    let mut admitted = 0u64;
    let mut offered = 0u64;
    while started.elapsed() < MEASURE {
        for _ in 0..PER_TICK {
            offered += 1;
            if call(&mut svc, request(AUTHZ_PATH, peer)).await {
                admitted += 1;
            }
        }
        tokio::time::sleep(TICK).await;
    }
    let elapsed = started.elapsed().as_secs_f64();

    // The shared layer counts every OFFERED request (denied ones included),
    // so this test is only measuring the governor if the offered total stayed
    // inside the shared window budget. Assert that explicitly rather than
    // assuming it.
    let window_budget = u64::from(PER_SEC) * 60;
    assert!(
        offered < window_budget,
        "test drove {offered} requests, at or above the shared 60 s budget of \
         {window_budget} — the measurement would be clamped by the shared layer"
    );

    let admitted_per_minute = admitted as f64 * 60.0 / elapsed;
    let expected_per_minute = f64::from(PER_SEC) * 60.0;
    let low = expected_per_minute * 0.9;
    let high = expected_per_minute * 1.1;
    assert!(
        admitted_per_minute >= low && admitted_per_minute <= high,
        "expected ≈{expected_per_minute} admitted per minute (configured {PER_SEC}/s × 60, \
         allowed {low}..={high}), got {admitted_per_minute:.0} from {admitted} admissions \
         over {elapsed:.2}s. A value near {PER_SEC} means the shared layer is enforcing the \
         per-SECOND number against its 60-second window again (the I1 ×60 units bug)."
    );
}

/// **I2 acceptance.** Exhausting the authz bucket must not throttle an
/// identity read: the families have separate buckets in both layers.
#[tokio::test]
async fn identity_reads_are_not_throttled_by_the_authz_ceiling() {
    let limits = GrpcRateLimits::from_authz_per_sec(5);
    let mut svc = stack(limits).await;
    let peer: SocketAddr = "203.0.113.11:5000".parse().unwrap();

    // Saturate authz until it rejects.
    let mut authz_admitted = 0usize;
    while call(&mut svc, request(AUTHZ_PATH, peer)).await {
        authz_admitted += 1;
        assert!(authz_admitted < 10_000, "authz never throttled");
    }
    assert!(authz_admitted > 0, "authz should admit its burst first");

    // The identity family has its own bucket and its own (5x) ceiling, so it
    // is still serving. Before I2 this request shared the authz bucket and
    // would be rejected here.
    assert!(
        call(&mut svc, request(IDENTITY_PATH, peer)).await,
        "an identity read must not be throttled by the exhausted authz bucket (I2)"
    );

    // ...and the authz family is still throttled (we did not simply disable
    // limiting).
    assert!(
        !call(&mut svc, request(AUTHZ_PATH, peer)).await,
        "the authz bucket must still be exhausted"
    );
}

/// **SEC-079 acceptance, through the full stack.** The Argon2id-bound admin
/// family stays at its absolute CPU-guard ceiling even when the authz ceiling
/// is raised to a service-mesh number — the decoupling is what stops a mesh
/// posture from also widening online password guessing.
#[tokio::test]
async fn admin_family_is_capped_independently_of_the_authz_ceiling() {
    // A `mesh`-shaped authz ceiling: 5 000/s.
    let limits = GrpcRateLimits::from_authz_per_sec(5_000);
    assert_eq!(limits.admin_per_sec, ADMIN_PER_SEC_DEFAULT);

    let mut svc = stack(limits).await;
    let peer: SocketAddr = "203.0.113.14:5000".parse().unwrap();

    let mut admin_admitted = 0usize;
    while call(&mut svc, request(ADMIN_PATH, peer)).await {
        admin_admitted += 1;
        assert!(
            admin_admitted <= ADMIN_PER_SEC_DEFAULT as usize * 4,
            "the admin family admitted {admin_admitted} back-to-back credential checks \
             against a {ADMIN_PER_SEC_DEFAULT}/s ceiling — it is tracking the authz \
             ceiling again (SEC-079)"
        );
    }
    assert!(
        admin_admitted >= ADMIN_PER_SEC_DEFAULT as usize,
        "the admin bucket must still allow a full {ADMIN_PER_SEC_DEFAULT}-token burst, \
         got {admin_admitted}"
    );

    // …while the authz family, sized for the mesh, is still wide open.
    for i in 0..500 {
        assert!(
            call(&mut svc, request(AUTHZ_PATH, peer)).await,
            "authz request {i} must not be throttled by the admin ceiling"
        );
    }
}

/// **Residual 4, half one.** Reflection and health have their own generous
/// bucket, so an incident that saturates every other family still leaves the
/// probes answering — a throttled liveness probe turns an overload into an
/// outage.
///
/// The probe volume asserted here (30 per path, ~60 total) is far above any
/// real probe cadence and far below [`INFRA_PER_SEC`]'s one-second burst.
#[tokio::test]
async fn reflection_and_health_survive_a_saturated_server() {
    let limits = GrpcRateLimits::from_authz_per_sec(1);
    let mut svc = stack(limits).await;
    let peer: SocketAddr = "203.0.113.12:5000".parse().unwrap();

    // Saturate every *other* family.
    while call(&mut svc, request(AUTHZ_PATH, peer)).await {}
    assert!(!call(&mut svc, request(AUTHZ_PATH, peer)).await);
    while call(&mut svc, request(IDENTITY_PATH, peer)).await {}
    while call(&mut svc, request(ADMIN_PATH, peer)).await {}

    for path in [HEALTH_PATH, REFLECTION_PATH] {
        for i in 0..30 {
            assert!(
                call(&mut svc, request(path, peer)).await,
                "{path} request {i} must still be served while every other family is \
                 saturated — a throttled liveness probe turns an overload into an outage"
            );
        }
    }
}

/// **Residual 4, half two.** The infrastructure family is nonetheless
/// *bounded*: it used to bypass both limiter layers entirely on a prefix match
/// against the attacker-controlled `:path`. Sustained flooding must eventually
/// be rejected.
#[tokio::test]
async fn reflection_and_health_are_bounded() {
    let limits = GrpcRateLimits::from_authz_per_sec(100);
    let mut svc = stack(limits).await;
    let peer: SocketAddr = "203.0.113.13:5000".parse().unwrap();

    let mut admitted = 0usize;
    let mut rejected = false;
    // A generous but finite bucket: `INFRA_PER_SEC` tokens of burst plus
    // whatever replenishes during the loop. Well under 10x the ceiling is
    // enough to prove the bucket exists at all.
    for _ in 0..(INFRA_PER_SEC as usize * 10) {
        if call(&mut svc, request(HEALTH_PATH, peer)).await {
            admitted += 1;
        } else {
            rejected = true;
            break;
        }
    }

    assert!(
        rejected,
        "the infrastructure family admitted {admitted} consecutive requests without \
         ever rejecting — it is still an unbounded pass-through (residual 4)"
    );
    assert!(
        admitted >= INFRA_PER_SEC as usize,
        "the infrastructure bucket must be generous: expected at least a full \
         {INFRA_PER_SEC}-token burst, got {admitted}"
    );
}

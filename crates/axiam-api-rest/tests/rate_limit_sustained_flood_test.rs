//! R5.2 (A1 §5) — sustained-flood integration test for the REST rate
//! limiter's two-layer stack: the in-memory `Governor` (per-replica,
//! sub-second granularity) wrapped by the DB-backed `RateLimitShared`
//! write-behind counter (cross-replica, minute granularity) — the exact
//! pairing every plain (non-client-aware) resource in `server.rs` uses, e.g.
//! `/oauth2/device_authorization` and `/oauth2/revoke`.
//!
//! A1's own diagnosis (`claude_dev/improvement-after-run5-benchmark.md` §A1)
//! found the two layers could disagree under flood: the write-behind
//! pre-check admits its whole per-minute allowance in the first instants of
//! its window, while the in-memory governor only leaks `burst + rate * t` of
//! that front-loaded spike — so a SHORT flood can look fine while a
//! SUSTAINED one under-admits relative to the configured ceiling. Every
//! other rate-limit test in this crate runs for milliseconds and proves a
//! single window boundary; none of them run long enough, at a high enough
//! multiple of the configured rate, for that shape to show up. This is the
//! test that does — "A1's still-owed sustained-flood integration test"
//! `claude_dev/remediation-plan-2026-08-15.md` R5.2 names explicitly.
//!
//! Real wall-clock time, not simulated: `SharedRateLimitCounter::from_env`
//! (via `AppState::for_test`, same as `rate_limit_shared_store_test.rs`)
//! spins a REAL background flusher on its own interval, and the governor's
//! leak rate is driven by the OS clock — a mocked clock would prove nothing
//! about whether the two layers' independent timers actually agree once real
//! time, not test-controlled `flush_once()` calls, drives both.
//!
//! Ignored by default (>= 60s wall-clock, `RATE_LIMIT_SUSTAINED_FLOOD_SECS`
//! below): follows the same convention as this crate's other
//! network/wall-clock-bound integration test,
//! `tests/webhook_consumer_test.rs`'s `#[ignore = "requires a live RabbitMQ
//! broker — run via ... -- --ignored"]`.
//!
//! Run it:
//!   cargo test -p axiam-api-rest --test rate_limit_sustained_flood_test -- --ignored --nocapture
//! List it without running the (long) body:
//!   cargo test -p axiam-api-rest --test rate_limit_sustained_flood_test -- --list

use std::time::{Duration, Instant};

use actix_governor::Governor;
use actix_governor::GovernorConfigBuilder;
use actix_governor::governor::middleware::NoOpMiddleware;
use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::extractors::rate_limit::XForwardedForKeyExtractor;
use axiam_api_rest::middleware::rate_limit_shared::RateLimitShared;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

type TestDb = Db;

/// Per-minute limit the flood must stay within `TOLERANCE` of, on the
/// admitted side. Small and round so `LIMIT_PER_MIN * (secs / 60.0)` is easy
/// to sanity-check by eye; not tied to any shipped default on purpose — this
/// test proves the two-layer MECHANISM holds its bar, independent of which
/// numbers `RateLimitConfig::default()` ships this week.
const LIMIT_PER_MIN: u32 = 60;

/// I1's own acceptance bar ("admitted-per-minute ≈ configured × 60, ±10%"),
/// reused here rather than re-invented — see
/// `benchmarks/runner/rl_prod_check.py`'s `TOLERANCE`, which this assertion
/// is written to agree with.
const TOLERANCE: f64 = 0.10;

/// How long to sustain the flood. Comfortably over the 60s R5.2 acceptance
/// bar so at least one full governor leak cycle AND at least one shared-store
/// flush interval land inside the measured window, not just at its edges.
const FLOOD_SECS: u64 = 65;

/// The flood must clear this multiple of the configured per-minute rate
/// (measured in requests actually sent, not just offered) — A1's own
/// diagnosis reproduced the starvation shape at ">= 10x"; failing this
/// assertion means the test's in-process load generator was the bottleneck,
/// not the limiter, and the run proved nothing.
const MIN_FLOOD_MULTIPLE: f64 = 10.0;

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().finish()
}

/// Mirrors `server.rs`'s private `build_governor()` byte-for-byte (that
/// function is not `pub`, so integration tests cannot call it directly) —
/// same builder calls, same `requests_per_minute`/`burst_size` pairing, same
/// key extractor. `trusted_hops` is hardcoded to 0 rather than read from
/// `AXIAM__RATE_LIMIT__TRUSTED_HOPS`: this test's peer address is not behind
/// a proxy, so the env-driven hop count is not part of what it verifies.
fn build_governor_for_test(
    requests_per_min: u32,
) -> Governor<XForwardedForKeyExtractor, NoOpMiddleware> {
    let config = GovernorConfigBuilder::default()
        .requests_per_minute(requests_per_min as u64)
        .burst_size(requests_per_min)
        .key_extractor(XForwardedForKeyExtractor::with_trusted_hops(0))
        .finish()
        .expect("valid governor config");
    Governor::new(&config)
}

/// One resource, wrapped by BOTH layers in production's wrap order — governor
/// added first (inner), `RateLimitShared` added second (outer) — matching
/// every plain (non-client-aware) resource in `server.rs`
/// (`/oauth2/device_authorization`, `/oauth2/revoke`, `/api/v1/device/verify`
/// all use exactly this pairing and order).
///
/// `AppState::for_test` already wires a REAL, env-configured
/// `SharedRateLimitCounter` (background flusher included) over the supplied
/// DB — see its own doc comment in `src/state.rs` — so unlike
/// `rate_limit_shared_store_test.rs`'s deterministic tests (which inject a
/// `without_flusher` counter and drive `flush_once()` by hand), this test
/// does not touch `state.shared_rate_limit` at all.
#[allow(clippy::type_complexity)]
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
    let state = AppState::<TestDb>::for_test(db, AuthConfig::default());
    App::new().app_data(web::Data::new(state)).service(
        web::resource("/t")
            .wrap(build_governor_for_test(LIMIT_PER_MIN))
            .wrap(RateLimitShared::<TestDb>::new(
                "sustained_flood_test",
                LIMIT_PER_MIN,
            ))
            .route(web::get().to(ok_handler)),
    )
}

/// A1 §5 / R5.2: sustained (>= 60s), high-multiple flood against the two-layer
/// stack, asserting the admitted rate lands within `TOLERANCE` of
/// `LIMIT_PER_MIN` — the same bar `rl_prod_check.py` enforces against a real
/// k6 run, proved here deterministically and without any container.
///
/// A single-task tight loop (no spawned concurrency) is deliberate and
/// sufficient: each in-process `call_service` completes in well under a
/// millisecond, so a straight `while` loop clears `MIN_FLOOD_MULTIPLE` (10x)
/// by a wide margin on its own, and staying single-task keeps this test free
/// of `Send`-bound futures across `actix_web::test`'s app service (which is
/// not `Send`) while still yielding at every `.await`, so the counter's
/// background flusher gets scheduled time exactly as it would under real
/// concurrent load.
#[actix_rt::test]
#[ignore = "sustained ~65s flood — run via `cargo test -p axiam-api-rest --test rate_limit_sustained_flood_test -- --ignored`"]
async fn rate_limit_sustained_flood_admitted_rate_within_bar() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let app = test::init_service(build_app(db)).await;
    let peer: std::net::SocketAddr = "203.0.113.99:6000".parse().unwrap();

    let mut admitted: u64 = 0;
    let mut throttled: u64 = 0;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(FLOOD_SECS);

    while Instant::now() < deadline {
        let req = test::TestRequest::get()
            .uri("/t")
            .peer_addr(peer)
            .to_request();
        let resp = test::call_service(&app, req).await;
        match resp.status().as_u16() {
            200 => admitted += 1,
            429 => throttled += 1,
            other => panic!(
                "unexpected status {other} mid-flood — this endpoint only ever \
                 answers 200 (admitted) or 429 (throttled)"
            ),
        }
    }

    let elapsed_secs = start.elapsed().as_secs_f64();
    let total_sent = admitted + throttled;
    let sent_rate_per_min = (total_sent as f64) / elapsed_secs * 60.0;

    // Sanity-check the load generator BEFORE trusting the limiter assertion
    // below — a flood that never cleared the multiple would make a passing
    // admitted-rate meaningless (the governor never had a reason to reject
    // anything).
    assert!(
        sent_rate_per_min >= (LIMIT_PER_MIN as f64) * MIN_FLOOD_MULTIPLE,
        "flood only sustained {sent_rate_per_min:.0} req/min against a \
         {LIMIT_PER_MIN}/min limit (< {MIN_FLOOD_MULTIPLE}x) — the test's own \
         load generator was the bottleneck, not the limiter; this run proves \
         nothing and must not be trusted as a pass"
    );

    let expected_admitted = (LIMIT_PER_MIN as f64) * (elapsed_secs / 60.0);
    let low = expected_admitted * (1.0 - TOLERANCE);
    let high = expected_admitted * (1.0 + TOLERANCE);
    let admitted_f = admitted as f64;

    assert!(
        admitted_f >= low && admitted_f <= high,
        "admitted {admitted} requests over {elapsed_secs:.1}s (throttled {throttled}) is \
         outside ±{:.0}% of the configured bar — expected {expected_admitted:.1} \
         (window [{low:.1}, {high:.1}]). This is exactly A1's starvation shape: the \
         DB-backed pre-check front-loads its whole window allowance while the \
         in-memory governor only leaks burst + rate*t of it, so a sustained flood \
         under-admits relative to the configured ceiling.",
        TOLERANCE * 100.0
    );
}

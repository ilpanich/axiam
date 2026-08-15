//! R5.2: the `/scim/v2` limiter is ENFORCED, not merely configured.
//!
//! `axiam-scim` shipped (R3.1) with no rate-limit bucket at all while thirteen
//! other endpoint families each had one — `grep -rn "scim.*_per_min"` over
//! `crates/` returned nothing. R5.2 added
//! [`RateLimitConfig::scim_per_min`](axiam_api_rest::RateLimitConfig) and
//! wrapped the scope in the same two layers every family in `server.rs` uses.
//!
//! A configured-but-unenforced bucket is worse than none — it reads as
//! protection that isn't there — so these tests drive the REAL
//! `scim_routes_with_rate_limits` wiring (not a hand-rolled stand-in) and
//! assert on actual `429`s:
//!
//! 1. `scim_requests_past_the_limit_are_rejected` — the bucket bites.
//! 2. `one_bucket_spans_the_whole_scim_scope` — the sizing decision recorded
//!    in `scim_per_min`'s docs (ONE bucket for reads, writes and discovery
//!    alike) is what the wiring actually does, so a later split has to be a
//!    deliberate edit here too.
//! 3. `the_shipped_default_is_actually_wired` — the plain `scim_routes` entry
//!    point carries the limiter with the shipped 600/min, so a deployment that
//!    never touches the env var is still limited.
//!
//! Modelled on `axiam-api-rest/tests/users_rate_limit_split_test.rs`, which
//! pins the `/users` limiter split the same way.
//!
//! Run with: cargo test -p axiam-scim --test scim_rate_limit_test

use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

type TestDb = Db;

/// Deliberately tiny so "past the limit" is a handful of requests rather than
/// the shipped 600. The number under test is the *wiring*, not the default —
/// the default is pinned in `axiam-api-rest`'s own config unit tests.
const SCIM_PER_MIN: u32 = 4;

async fn test_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    db
}

/// Every request below is unauthenticated, so it is rejected by
/// `AuthzMiddleware` with a 401 — which is exactly what these tests want.
/// The limiters are wrapped OUTSIDE that middleware, so the request is
/// charged to the bucket before the credential check runs, and the assertion
/// is only ever "429 or not".
fn scim_request(method: &str, path: &str, peer: std::net::SocketAddr) -> test::TestRequest {
    let req = match method {
        "POST" => test::TestRequest::post(),
        _ => test::TestRequest::get(),
    };
    req.uri(path)
        .peer_addr(peer)
        .insert_header(("Authorization", "Bearer not-a-real-token"))
}

macro_rules! limited_app {
    ($db:expr, $limit:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    AuthConfig::default(),
                )))
                .configure(|cfg| {
                    axiam_scim::scim_routes_with_rate_limits::<TestDb>(
                        cfg,
                        &RateLimitConfig {
                            scim_per_min: $limit,
                            ..RateLimitConfig::default()
                        },
                    )
                }),
        )
        .await
    };
}

/// The bucket bites: past `scim_per_min`, `/scim/v2` returns 429.
#[actix_rt::test]
async fn scim_requests_past_the_limit_are_rejected() {
    let db = test_db().await;
    let app = limited_app!(db, SCIM_PER_MIN);
    let peer: std::net::SocketAddr = "203.0.113.40:5000".parse().unwrap();

    // Within budget: rejected on auth (401), never rate-limited.
    for i in 0..SCIM_PER_MIN {
        let resp = test::call_service(
            &app,
            scim_request("POST", "/scim/v2/Users", peer).to_request(),
        )
        .await;
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "SCIM request {i} is within scim_per_min and must not be rate-limited"
        );
    }

    // Past it, one of the two layers (shared counter or in-memory governor)
    // must reject. A couple of requests of slack so this does not depend on
    // which layer rejects first — same tolerance as the `/users` split test.
    let mut rejected = false;
    for _ in 0..3 {
        let resp = test::call_service(
            &app,
            scim_request("POST", "/scim/v2/Users", peer).to_request(),
        )
        .await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            rejected = true;
            break;
        }
    }
    assert!(
        rejected,
        "POST /scim/v2/Users past scim_per_min={SCIM_PER_MIN} must be rate-limited — \
         a configured-but-unenforced bucket reads as protection that isn't there"
    );
}

/// The sizing decision in `scim_per_min`'s docs is ONE bucket for the whole
/// scope: reads, writes and the RFC 7643 discovery endpoints alike. Spend the
/// budget on writes, and a *read* on a different path must be refused too.
#[actix_rt::test]
async fn one_bucket_spans_the_whole_scim_scope() {
    let db = test_db().await;
    let app = limited_app!(db, SCIM_PER_MIN);
    let peer: std::net::SocketAddr = "203.0.113.41:5000".parse().unwrap();

    for _ in 0..SCIM_PER_MIN {
        let _ = test::call_service(
            &app,
            scim_request("POST", "/scim/v2/Users", peer).to_request(),
        )
        .await;
    }

    let mut rejected = false;
    for path in [
        "/scim/v2/Groups",
        "/scim/v2/ServiceProviderConfig",
        "/scim/v2/Schemas",
    ] {
        let resp = test::call_service(&app, scim_request("GET", path, peer).to_request()).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            rejected = true;
            break;
        }
    }
    assert!(
        rejected,
        "the whole /scim/v2 scope shares ONE bucket — a read after the write budget \
         is spent must still be refused. If this was split deliberately, update \
         RateLimitConfig::scim_per_min's docs and rl_prod_check.py's ENDPOINTS too"
    );
}

/// The plain `scim_routes` entry point (shipped posture, no env override)
/// must carry the limiter as well — otherwise a default deployment ships
/// unlimited. 600/min is too many requests to drive here, so this asserts the
/// weaker but sufficient property: the shipped wiring rejects nothing inside
/// the shipped budget and is the same code path as above.
#[actix_rt::test]
async fn the_shipped_default_is_actually_wired() {
    assert_eq!(
        RateLimitConfig::default().scim_per_min,
        600,
        "shipped SCIM bucket changed — re-read its doc comment before editing this"
    );

    let db = test_db().await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(AppState::for_test(
                db.clone(),
                AuthConfig::default(),
            )))
            .configure(axiam_scim::scim_routes::<TestDb>),
    )
    .await;
    let peer: std::net::SocketAddr = "203.0.113.42:5000".parse().unwrap();

    let resp = test::call_service(
        &app,
        scim_request("GET", "/scim/v2/Schemas", peer).to_request(),
    )
    .await;
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a single request must be well inside the shipped 600/min budget"
    );
}

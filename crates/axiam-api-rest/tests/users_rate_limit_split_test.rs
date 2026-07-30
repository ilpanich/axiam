//! Regression test for the `/users` rate-limiter split
//! (`claude_dev/postseed-transient-investigation.md` §2.1 / §7 ask 1).
//!
//! `server.rs` used to register ONE resource for both `/users` routes:
//!
//! ```ignore
//! web::resource("/users")
//!     .wrap(build_governor(rate_limit_cfg.register_per_min))
//!     .wrap(RateLimitShared::<C>::new("users_create", rate_limit_cfg.register_per_min))
//!     .route(web::post().to(handlers::users::create::<C>))
//!     .route(web::get().to(handlers::users::list::<C>))
//! ```
//!
//! An actix resource-level `.wrap()` applies to EVERY method on the
//! resource, so `GET /api/v1/users` — an admin *list* — inherited the user
//! *registration* limiter and was charged to the `users_create` bucket. With
//! the production posture's `register_per_min = 5`, listing users started
//! returning 429 after five reads per minute per IP. It also put the shared
//! rate-limit store's round trip on the list path (measured 60-65 ms vs
//! 11-12 ms for the structurally identical `GET /roles` / `GET /resources`).
//!
//! These tests pin the fixed wiring — a method-guarded POST resource
//! carrying both limiters, followed by a plain `/users` resource carrying the
//! GET — by driving the REAL `register_api_v1_routes` wiring:
//!
//! 1. `post_users_past_the_limit_is_rejected` — the POST keeps its limiter.
//! 2. `get_users_is_not_charged_to_the_users_create_bucket` — far more GETs
//!    than `register_per_min` all keep working, and they do not consume the
//!    create bucket (a subsequent POST burst still gets its full budget).
//! 3. `both_users_routes_still_reach_their_own_handler` — actix's guard
//!    fall-through actually works: POST and GET each reach the right handler.
//!
//! Run with: cargo test -p axiam-api-rest --test users_rate_limit_split_test

use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use axiam_api_rest::config::rate_limit::RateLimitConfig;
use axiam_api_rest::server::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

type TestDb = Db;

/// Deliberately tiny so "past the limit" is reached in a handful of requests.
/// Mirrors the shape of the production posture (`register_per_min = 5`), where
/// the bug was reachable by any admin UI.
const REGISTER_PER_MIN: u32 = 3;

/// The `/users` GET burst size — comfortably above `REGISTER_PER_MIN` so that
/// any residual coupling to the `users_create` bucket shows up as a 429.
const GET_BURST: u32 = 25;

async fn test_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// Builds the app with the REAL `/api/v1` wiring (not a hand-rolled stand-in),
/// so this test fails if `server.rs` ever regresses to a single `/users`
/// resource.
macro_rules! build_real_app {
    ($db:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    AuthConfig::default(),
                )))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(
                        cfg,
                        &RateLimitConfig {
                            register_per_min: REGISTER_PER_MIN,
                            ..RateLimitConfig::default()
                        },
                    )
                }),
        )
        .await
    };
}

/// `/api/v1` is wrapped in `AuthzMiddleware` (credential *presence* check)
/// and `CsrfMiddleware` (cookie/header equality on unsafe methods). Both run
/// OUTSIDE the resource-level rate limiters, so a request must carry a bearer
/// header and a matching CSRF pair to reach the limiter at all. Neither is
/// verified here — the handlers still reject with 401/403, which is exactly
/// what these tests want: they assert on "429 or not", never on success.
fn post_users(peer: std::net::SocketAddr) -> test::TestRequest {
    test::TestRequest::post()
        .uri("/api/v1/users")
        .peer_addr(peer)
        .insert_header(("Authorization", "Bearer test-token"))
        .insert_header(("X-CSRF-Token", "csrf-token"))
        .cookie(actix_web::cookie::Cookie::build("axiam_csrf", "csrf-token").finish())
        .set_json(serde_json::json!({
            "username": "someone",
            "email": "someone@example.com",
            // Obviously-fake in-process test fixture, same convention as
            // `user_test.rs` — this body never leaves the test server, and
            // this suite asserts routing/limiter behaviour, not credentials.
            "password": "securepass123",
        }))
}

fn get_users(peer: std::net::SocketAddr) -> test::TestRequest {
    test::TestRequest::get()
        .uri("/api/v1/users")
        .peer_addr(peer)
        .insert_header(("Authorization", "Bearer test-token"))
}

/// The POST keeps BOTH limiters: past `register_per_min` it must 429.
#[actix_web::test]
async fn post_users_past_the_limit_is_rejected() {
    let db = test_db().await;
    let app = build_real_app!(db);
    let peer: std::net::SocketAddr = "203.0.113.10:5000".parse().unwrap();

    // The first `REGISTER_PER_MIN` POSTs are within budget: they reach the
    // handler and are rejected on auth (401/403), NOT rate-limited.
    for i in 0..REGISTER_PER_MIN {
        let resp = test::call_service(&app, post_users(peer).to_request()).await;
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "POST {i} is within register_per_min and must not be rate-limited"
        );
    }

    // Past the limit, one of the two limiters (shared store or governor) must
    // reject. Allow a couple of extra requests of slack so this does not
    // depend on which layer rejects first.
    let mut rejected = false;
    for _ in 0..3 {
        let resp = test::call_service(&app, post_users(peer).to_request()).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            rejected = true;
            break;
        }
    }
    assert!(
        rejected,
        "POST /api/v1/users past register_per_min={REGISTER_PER_MIN} must be rate-limited — \
         the registration limiter must stay on the create route"
    );
}

/// The regression itself: many GETs must all keep working, and they must not
/// consume the `users_create` bucket.
#[actix_web::test]
async fn get_users_is_not_charged_to_the_users_create_bucket() {
    let db = test_db().await;
    let app = build_real_app!(db);
    let peer: std::net::SocketAddr = "203.0.113.11:5000".parse().unwrap();

    // GET_BURST (25) >> register_per_min (3): before the fix the 4th GET
    // onwards returned 429.
    for i in 0..GET_BURST {
        let resp = test::call_service(&app, get_users(peer).to_request()).await;
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "GET /api/v1/users #{i} must never be rate-limited by the registration limiter"
        );
    }

    // And the create bucket was untouched by those GETs: a POST burst from
    // the SAME IP still gets its full `register_per_min` budget.
    for i in 0..REGISTER_PER_MIN {
        let resp = test::call_service(&app, post_users(peer).to_request()).await;
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "POST {i} must still have its full budget — {GET_BURST} GETs must not have \
             consumed the users_create bucket"
        );
    }
}

/// Guard fall-through sanity: with `/users` registered twice (a
/// `guard(Post())` resource first, then a plain one), actix must still route
/// each method to its own handler rather than 404/405-ing one of them.
#[actix_web::test]
async fn both_users_routes_still_reach_their_own_handler() {
    let db = test_db().await;
    let app = build_real_app!(db);
    let peer: std::net::SocketAddr = "203.0.113.12:5000".parse().unwrap();

    // GET reaches the list handler: it is rejected on auth, never NOT_FOUND
    // (which is what a broken guard fall-through would produce) and never
    // METHOD_NOT_ALLOWED.
    let resp = test::call_service(&app, get_users(peer).to_request()).await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "GET /users must route"
    );
    assert_ne!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET /users must route to the list handler, not fall on the POST-guarded resource"
    );

    // POST reaches the create handler (via the guarded resource).
    let resp = test::call_service(&app, post_users(peer).to_request()).await;
    assert_ne!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "POST /users must route"
    );
    assert_ne!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "POST /users must route to the create handler"
    );

    // A method neither resource serves still 405s (unchanged behavior).
    let resp = test::call_service(
        &app,
        test::TestRequest::patch()
            .uri("/api/v1/users")
            .peer_addr(peer)
            .insert_header(("Authorization", "Bearer test-token"))
            .insert_header(("X-CSRF-Token", "csrf-token"))
            .cookie(actix_web::cookie::Cookie::build("axiam_csrf", "csrf-token").finish())
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "an unserved method on /users must still 405"
    );
}

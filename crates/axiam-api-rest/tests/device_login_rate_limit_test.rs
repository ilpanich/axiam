//! `POST /api/v1/auth/device` is rate-limited (S-2, suggested finding DF-028).
//!
//! The route was registered bare:
//!
//! ```ignore
//! .route("/device", web::post().to(handlers::auth::device_auth::<C>))
//! ```
//!
//! No governor, no shared store — while `/auth/login` two hundred lines above
//! it, the three OPAQUE routes, the six WebAuthn ceremony routes and the
//! federation sign-in routes all carry both layers. It is also in
//! `PUBLIC_PATHS` and CSRF-exempt, as it must be: a device has no session and
//! no cookie. So the one auth endpoint that makes the server complete a TLS
//! handshake with a client certificate — the most expensive thing an
//! unauthenticated caller can ask of it — was the one endpoint an
//! unauthenticated caller could ask for without limit.
//!
//! These tests drive the REAL `register_api_v1_routes` wiring, so they fail if
//! `server.rs` ever regresses to a bare route.
//!
//! Run with: cargo test -p axiam-api-rest --test device_login_rate_limit_test

use actix_web::http::StatusCode;
use actix_web::{App, test, web};
use axiam_api_rest::config::rate_limit::{RateLimitConfig, RateLimitProfile};
use axiam_api_rest::server::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

type TestDb = Db;

/// Deliberately tiny, so "past the limit" costs a handful of requests rather
/// than the shipped sixty. The shipped default is asserted separately, from
/// the config, in `the_shipped_default_is_sixty_per_minute`.
const DEVICE_LOGIN_PER_MIN: u32 = 3;

/// Comfortably above `DEVICE_LOGIN_PER_MIN` — any residual coupling of the
/// login bucket to the device route shows up as a 429 well before this.
const LOGIN_BURST: u32 = 12;

async fn test_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

macro_rules! build_real_app {
    ($db:expr, $cfg:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    AuthConfig::default(),
                )))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &$cfg)),
        )
        .await
    };
}

/// No certificate and no `X-Client-Certificate` header, so the handler refuses
/// with a 401 long before it does any work. That is deliberate: these tests
/// assert "429 or not", never success, and a request that never reaches a
/// handler still passes through the limiter — which is the whole point.
fn device_login(peer: std::net::SocketAddr) -> test::TestRequest {
    test::TestRequest::post()
        .uri("/api/v1/auth/device")
        .peer_addr(peer)
}

fn password_login(peer: std::net::SocketAddr) -> test::TestRequest {
    test::TestRequest::post()
        .uri("/api/v1/auth/login")
        .peer_addr(peer)
        .insert_header(("X-CSRF-Token", "csrf-token"))
        .cookie(actix_web::cookie::Cookie::build("axiam_csrf", "csrf-token").finish())
        .set_json(serde_json::json!({
            "username": "nobody",
            "password": "wrong-on-purpose",
        }))
}

fn tiny_limit() -> RateLimitConfig {
    RateLimitConfig {
        device_login_per_min: DEVICE_LOGIN_PER_MIN,
        ..RateLimitConfig::default()
    }
}

#[actix_web::test]
async fn device_login_is_rate_limited_per_ip() {
    let db = test_db().await;
    let app = build_real_app!(db, tiny_limit());
    let peer: std::net::SocketAddr = "203.0.113.20:5000".parse().unwrap();

    for i in 0..DEVICE_LOGIN_PER_MIN {
        let resp = test::call_service(&app, device_login(peer).to_request()).await;
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "device login {i} is within device_login_per_min and must not be rate-limited"
        );
    }

    // Past the limit one of the two layers must reject. Which one rejects
    // first is not the property under test, so a little slack.
    let mut rejected = None;
    for _ in 0..3 {
        let resp = test::call_service(&app, device_login(peer).to_request()).await;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            rejected = Some(resp);
            break;
        }
    }
    let resp = rejected.expect(
        "POST /api/v1/auth/device past device_login_per_min must be rate-limited — the \
         route was bare before S-2 and must never become bare again",
    );
    assert!(
        resp.headers().contains_key("retry-after"),
        "the 429 must say when to come back: a device fleet that cannot read \
         Retry-After backs off by guessing"
    );
}

/// Each IP gets its own bucket, so one noisy device cannot lock a fleet out.
#[actix_web::test]
async fn one_exhausted_address_does_not_refuse_another() {
    let db = test_db().await;
    let app = build_real_app!(db, tiny_limit());
    let noisy: std::net::SocketAddr = "203.0.113.21:5000".parse().unwrap();
    let quiet: std::net::SocketAddr = "203.0.113.22:5000".parse().unwrap();

    for _ in 0..(DEVICE_LOGIN_PER_MIN + 3) {
        let _ = test::call_service(&app, device_login(noisy).to_request()).await;
    }

    let resp = test::call_service(&app, device_login(quiet).to_request()).await;
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the device-login bucket is per IP; another address must have its own"
    );
}

/// **I4 twin.** The device knob is its own bucket: exhausting it must not
/// touch `/auth/login`, and `login_per_min` must not have moved.
#[actix_web::test]
async fn login_per_min_is_unchanged_by_the_device_knob() {
    assert_eq!(
        RateLimitConfig::default().login_per_min,
        10,
        "S-2 adds a knob; it moves no existing default. `login_per_min` is a \
         human endpoint and G7 rules that none of them moves."
    );

    let db = test_db().await;
    // The device limit is tiny and the login limit is generous, so any
    // crossing of the two buckets shows up immediately.
    let cfg = RateLimitConfig {
        device_login_per_min: DEVICE_LOGIN_PER_MIN,
        login_per_min: LOGIN_BURST * 2,
        ..RateLimitConfig::default()
    };
    let app = build_real_app!(db, cfg);
    let peer: std::net::SocketAddr = "203.0.113.23:5000".parse().unwrap();

    // Exhaust the device bucket from this address...
    for _ in 0..(DEVICE_LOGIN_PER_MIN + 3) {
        let _ = test::call_service(&app, device_login(peer).to_request()).await;
    }

    // ...and the password login from the same address is untouched.
    for i in 0..LOGIN_BURST {
        let resp = test::call_service(&app, password_login(peer).to_request()).await;
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "login {i} must not be charged to the device-login bucket"
        );
    }
}

/// **I1.** At the shipped default a device on the shipped token lifetime never
/// sees a 429: one handshake per 15 minutes against sixty per minute.
#[actix_web::test]
async fn the_shipped_default_is_sixty_per_minute() {
    let d = RateLimitConfig::default();
    assert_eq!(d.device_login_per_min, 60);

    let lifetime_secs = AuthConfig::default().access_token_lifetime_secs;
    assert!(
        lifetime_secs >= 60,
        "the sizing argument assumes a device re-authenticates at most once a \
         minute; at a sub-minute token lifetime it needs redoing"
    );
    // Devices that fit inside the allowance when each re-authenticates once
    // per token lifetime. At the shipped 900 s that is 900 devices on one
    // address — the NAT case the machine family exists to let a preset widen.
    let fleet_on_one_address = u64::from(d.device_login_per_min) * lifetime_secs / 60;
    assert!(
        fleet_on_one_address >= 900,
        "sixty per minute must hold a real fleet behind one NAT, got \
         {fleet_on_one_address}"
    );
}

/// The knob is in the machine family, so a posture preset scales it — with the
/// same 5x and 50x the rest of that family takes.
#[actix_web::test]
async fn device_login_limit_scales_with_the_machine_preset() {
    let shipped = RateLimitConfig::default();

    for (profile, expected) in [
        (RateLimitProfile::Gateway, 300),
        (RateLimitProfile::Mesh, 3_000),
    ] {
        let mut cfg = RateLimitConfig {
            profile,
            ..RateLimitConfig::default()
        };
        let posture = cfg.apply_profile(|_| false);
        assert!(posture.preset_applied, "{profile:?}");
        assert_eq!(
            cfg.device_login_per_min, expected,
            "{profile:?} must preset the device-login limit"
        );
        // ...and it is preset with the same multiplier as `token_per_min`, so
        // the family scales coherently rather than by taste.
        assert_eq!(
            cfg.token_per_min / shipped.token_per_min,
            cfg.device_login_per_min / shipped.device_login_per_min,
            "{profile:?}: the device-login multiplier must match token's"
        );
        // A human endpoint is still untouched — a preset cannot express one.
        assert_eq!(cfg.login_per_min, shipped.login_per_min);
    }
}

/// An operator who pinned the variable beats the preset, like every other knob
/// in the family.
#[actix_web::test]
async fn an_explicit_device_login_value_beats_the_preset() {
    use axiam_api_rest::config::rate_limit::ENV_DEVICE_LOGIN_PER_MIN;

    let mut cfg = RateLimitConfig {
        profile: RateLimitProfile::Mesh,
        device_login_per_min: 5,
        ..RateLimitConfig::default()
    };
    let posture = cfg.apply_profile(|name| name == ENV_DEVICE_LOGIN_PER_MIN);

    assert_eq!(cfg.device_login_per_min, 5, "the pinned value must survive");
    assert!(
        posture
            .operator_overrides
            .contains(&ENV_DEVICE_LOGIN_PER_MIN),
        "the startup log must name it as an override, got {:?}",
        posture.operator_overrides
    );
    assert_eq!(
        cfg.token_per_min, 6_000,
        "pinning one knob must not stop the preset applying to the rest"
    );
}

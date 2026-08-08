//! D8 — rate-limiter key configurability (`AXIAM__RATE_LIMIT__KEY`).
//!
//! End-to-end proof (real `RateLimitShared` middleware + a Mem SurrealDB,
//! mirroring `rate_limit_shared_store_test.rs`'s pattern) that:
//! - `client_id` mode gives independent buckets per `client_id` under ONE
//!   shared IP — the NAT'd-fleet collision this task fixes.
//! - `client_id` mode still gives the SAME bucket to the SAME client_id
//!   connecting from different IPs.
//! - `ip_client_id` mode distinguishes both dimensions.
//! - `ip` mode (the default) is byte-for-byte unchanged: two different
//!   client_ids behind one IP still share ONE bucket, exactly like before
//!   this field existed.
//! - The body is transparently restored: the downstream `web::Form<..>`
//!   handler still sees the full, correct form body after the middleware
//!   peeked it for `client_id`.
//! - A `RateLimitShared::new(...)`-wired resource (standing in for
//!   `/auth/login`) NEVER keys on `client_id`, regardless of what's in the
//!   body — proving login-stays-per-IP is structural, not merely
//!   configuration-default.

use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::config::rate_limit::RateLimitKeyMode;
use axiam_api_rest::middleware::rate_limit_shared::RateLimitShared;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use serde::Deserialize;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};

type TestDb = Db;

/// Per-bucket limit shared by every scenario below.
const LIMIT: u32 = 2;

#[derive(Debug, Deserialize)]
struct FormLikeTokenRequest {
    client_id: String,
}

/// Echoes the parsed `client_id` back — proves the middleware's body
/// peek-and-restore left the payload intact for the real `web::Form<..>`
/// extractor downstream (the same extraction style `handlers::oauth2::token`
/// / `revoke` / `introspect` use).
async fn echo_client_id(form: web::Form<FormLikeTokenRequest>) -> HttpResponse {
    HttpResponse::Ok().body(form.client_id.clone())
}

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().finish()
}

fn form_body(client_id: &str) -> String {
    format!("grant_type=client_credentials&client_id={client_id}&client_secret=s")
}

fn post_form(uri: &str, peer: std::net::SocketAddr, client_id: &str) -> actix_http::Request {
    use actix_web::http::header::{CONTENT_TYPE, HeaderValue};
    test::TestRequest::post()
        .uri(uri)
        .peer_addr(peer)
        .insert_header((
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        ))
        .set_payload(form_body(client_id))
        .to_request()
}

/// Builds a single-resource app with a client-identity-aware
/// `RateLimitShared` in the given key mode, wired exactly like
/// `/oauth2/token` in `server.rs`.
fn build_client_aware_app(
    db: Surreal<TestDb>,
    key_mode: RateLimitKeyMode,
    endpoint: &'static str,
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
                .wrap(RateLimitShared::<TestDb>::new_client_identity_aware(
                    endpoint, LIMIT, key_mode,
                ))
                .route(web::post().to(echo_client_id)),
        )
}

/// Builds a single-resource app with the PLAIN (non-client-identity-aware)
/// `RateLimitShared` — exactly how `/auth/login` is wired in `server.rs`.
/// Uses the plain `ok_handler` (not `web::Form<..>`) since login's real
/// request body is JSON, not form-encoded — the point of this test is that
/// the rate limiter never even looks at it.
fn build_login_like_app(
    db: Surreal<TestDb>,
    endpoint: &'static str,
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
                .wrap(RateLimitShared::<TestDb>::new(endpoint, LIMIT))
                .route(web::post().to(ok_handler)),
        )
}

/// Drive a bucket until it rejects, evaluating to how many requests were
/// admitted.
///
/// # Why every test below uses this instead of `for _ in 0..LIMIT { assert 200 }`
///
/// Since run-5 J1 the shared counter seeds a **newly seen** key with its
/// pro-rata share of the window it arrives in (plus an explicit burst
/// allowance), so a key first seen at second 50 gets roughly a sixth of the
/// budget rather than all of it. That is the property that makes admission
/// independent of *when* a flood starts — and it makes "the first N requests
/// all succeed" a wall-clock-dependent assertion.
///
/// None of these tests is actually about the count. Every one of them is about
/// **bucket separation**: which requests share a budget and which do not. So
/// they drive a bucket to exhaustion and then assert that a *different* bucket
/// is (or is not) affected, which is the real invariant and is arrival-time
/// independent.
///
/// A macro rather than a function because `test::call_service`'s bounds are
/// impractical to name generically over an `App`'s opaque service type.
macro_rules! drive_until_rejected {
    ($app:expr, $peer:expr, $client:expr) => {{
        let mut admitted = 0usize;
        let mut rejected = false;
        // Generous ceiling: enough to exhaust any bucket in these tests even
        // when the window has just rolled over, low enough to fail fast if the
        // limiter never rejects at all — which is the bug worth catching here.
        for _ in 0..(LIMIT * 20) {
            let resp = test::call_service(&$app, post_form("/t", $peer, $client)).await;
            if resp.status() == 429 {
                rejected = true;
                break;
            }
            admitted += 1;
        }
        assert!(
            rejected,
            "bucket never rejected after {} requests — the limiter is not enforcing",
            LIMIT * 20
        );
        admitted
    }};
}

async fn fresh_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

#[actix_rt::test]
async fn client_id_mode_gives_independent_buckets_per_client_under_one_ip() {
    let db = fresh_db().await;
    let app = test::init_service(build_client_aware_app(
        db,
        RateLimitKeyMode::ClientId,
        "client_id_mode_test",
    ))
    .await;

    let peer: std::net::SocketAddr = "203.0.113.50:1".parse().unwrap();

    // Exhaust client "alice"'s bucket.
    let admitted = drive_until_rejected!(app, peer, "alice");
    assert!(admitted >= 1, "alice must be admitted at least once");

    // Client "bob", SAME source IP, is COMPLETELY unaffected — this is the
    // NAT'd-fleet collision fix: before D8 (or in `ip` mode) this request
    // would already be 429 because it shares alice's IP-only bucket.
    let resp = test::call_service(&app, post_form("/t", peer, "bob")).await;
    assert_eq!(
        resp.status(),
        200,
        "bob must be unaffected by alice's exhausted bucket — that is the whole \
         point of client_id keying"
    );
    let body = test::read_body(resp).await;
    assert_eq!(
        body, "bob",
        "handler must still see the correct client_id after body restore"
    );
}

#[actix_rt::test]
async fn client_id_mode_shares_one_bucket_for_same_client_across_ips() {
    let db = fresh_db().await;
    let app = test::init_service(build_client_aware_app(
        db,
        RateLimitKeyMode::ClientId,
        "client_id_mode_cross_ip_test",
    ))
    .await;

    let peer_a: std::net::SocketAddr = "203.0.113.60:1".parse().unwrap();
    let peer_b: std::net::SocketAddr = "203.0.113.61:1".parse().unwrap();

    // Exhaust the SAME client_id from one IP...
    drive_until_rejected!(app, peer_a, "carol");

    // ...and it must already be exhausted from a DIFFERENT IP, because
    // client_id mode ignores IP entirely.
    let resp = test::call_service(&app, post_form("/t", peer_b, "carol")).await;
    assert_eq!(
        resp.status(),
        429,
        "same client_id from another IP must hit the SAME per-client bucket"
    );
}

#[actix_rt::test]
async fn ip_client_id_mode_distinguishes_both_dimensions() {
    let db = fresh_db().await;
    let app = test::init_service(build_client_aware_app(
        db,
        RateLimitKeyMode::IpClientId,
        "ip_client_id_mode_test",
    ))
    .await;

    let peer_a: std::net::SocketAddr = "203.0.113.70:1".parse().unwrap();
    let peer_b: std::net::SocketAddr = "203.0.113.71:1".parse().unwrap();

    // Exhaust (peer_a, "dave").
    drive_until_rejected!(app, peer_a, "dave");

    // Same client_id "dave" from a DIFFERENT IP: independent bucket.
    let resp = test::call_service(&app, post_form("/t", peer_b, "dave")).await;
    assert_eq!(
        resp.status(),
        200,
        "(peer_b, dave) must be independent of (peer_a, dave) in ip_client_id mode"
    );

    // Different client_id "erin" from the SAME peer_a: also independent.
    let resp = test::call_service(&app, post_form("/t", peer_a, "erin")).await;
    assert_eq!(
        resp.status(),
        200,
        "(peer_a, erin) must be independent of (peer_a, dave) in ip_client_id mode"
    );
}

#[actix_rt::test]
async fn ip_mode_is_unchanged_two_client_ids_share_one_ip_bucket() {
    // D8 acceptance: default behavior (`ip`) is identical to today — two
    // DIFFERENT client_ids behind the SAME IP must still collide into ONE
    // bucket, exactly like the pre-D8 code path.
    let db = fresh_db().await;
    let app = test::init_service(build_client_aware_app(
        db,
        RateLimitKeyMode::Ip,
        "ip_mode_unchanged_test",
    ))
    .await;

    let peer: std::net::SocketAddr = "203.0.113.80:1".parse().unwrap();

    // Exhaust the per-IP bucket using one client_id...
    drive_until_rejected!(app, peer, "frank");

    // ...and yet ANOTHER client_id from the same IP must already be 429:
    // `ip` mode never distinguishes clients.
    let resp = test::call_service(&app, post_form("/t", peer, "henry")).await;
    assert_eq!(
        resp.status(),
        429,
        "ip mode must ignore client_id entirely and share one per-IP bucket"
    );
}

#[actix_rt::test]
async fn login_like_endpoint_stays_per_ip_and_never_reads_client_id_from_body() {
    // Simulates `/auth/login`'s wiring: `RateLimitShared::new(...)` (NOT
    // `new_client_identity_aware`). Even though the request bodies below
    // carry distinct "client_id"-shaped form fields, the login-style
    // resource must treat them as one shared per-IP bucket — proving the
    // login-stays-per-IP guarantee holds regardless of body content, not
    // just because the global key mode defaults to `ip`.
    let db = fresh_db().await;
    let app = test::init_service(build_login_like_app(db, "login_like_test")).await;

    let peer: std::net::SocketAddr = "203.0.113.90:1".parse().unwrap();

    drive_until_rejected!(app, peer, "alice");

    // A DIFFERENT client_id-shaped body field from the same IP must already be
    // 429: a login-style resource never reads the body for keying.
    let resp = test::call_service(&app, post_form("/t", peer, "someone-else")).await;
    assert_eq!(
        resp.status(),
        429,
        "login-like endpoint must be rate-limited per-IP, ignoring any client_id-shaped body field"
    );
}

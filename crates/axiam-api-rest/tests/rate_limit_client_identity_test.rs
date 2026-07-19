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
) -> impl actix_web::dev::ServiceFactory<
    actix_web::dev::ServiceRequest,
    Config = (),
    Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
    Error = actix_web::Error,
    InitError = (),
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
) -> impl actix_web::dev::ServiceFactory<
    actix_web::dev::ServiceRequest,
    Config = (),
    Response = actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
    Error = actix_web::Error,
    InitError = (),
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

    // Exhaust client "alice"'s bucket (LIMIT requests all succeed).
    for i in 0..LIMIT {
        let resp = test::call_service(&app, post_form("/t", peer, "alice")).await;
        assert_eq!(resp.status(), 200, "alice request {i} should succeed");
    }
    let resp = test::call_service(&app, post_form("/t", peer, "alice")).await;
    assert_eq!(resp.status(), 429, "alice must now be rate-limited");

    // Client "bob", SAME source IP, is COMPLETELY unaffected — this is the
    // NAT'd-fleet collision fix: before D8 (or in `ip` mode) this request
    // would already be 429 because it shares alice's IP-only bucket.
    for i in 0..LIMIT {
        let resp = test::call_service(&app, post_form("/t", peer, "bob")).await;
        assert_eq!(
            resp.status(),
            200,
            "bob request {i} must succeed independently of alice's exhausted bucket"
        );
        let body = test::read_body(resp).await;
        assert_eq!(
            body, "bob",
            "handler must still see the correct client_id after body restore"
        );
    }
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

    // Split the SAME client_id's LIMIT requests across two different IPs —
    // the bucket must still be shared (client_id mode ignores IP entirely).
    for i in 0..LIMIT {
        let peer = if i % 2 == 0 { peer_a } else { peer_b };
        let resp = test::call_service(&app, post_form("/t", peer, "carol")).await;
        assert_eq!(resp.status(), 200);
    }
    let resp = test::call_service(&app, post_form("/t", peer_a, "carol")).await;
    assert_eq!(
        resp.status(),
        429,
        "same client_id from a third IP must still hit the shared per-client bucket"
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
    for _ in 0..LIMIT {
        let resp = test::call_service(&app, post_form("/t", peer_a, "dave")).await;
        assert_eq!(resp.status(), 200);
    }
    let resp = test::call_service(&app, post_form("/t", peer_a, "dave")).await;
    assert_eq!(resp.status(), 429, "(peer_a, dave) must be exhausted");

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

    for i in 0..LIMIT {
        let client_id = if i % 2 == 0 { "frank" } else { "grace" };
        let resp = test::call_service(&app, post_form("/t", peer, client_id)).await;
        assert_eq!(resp.status(), 200);
    }
    // Third request, yet ANOTHER client_id, same IP: must already be 429 —
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

    for i in 0..LIMIT {
        let client_id = if i % 2 == 0 { "alice" } else { "bob" };
        let resp = test::call_service(&app, post_form("/t", peer, client_id)).await;
        assert_eq!(resp.status(), 200, "login-like request {i} should succeed");
    }
    let resp = test::call_service(&app, post_form("/t", peer, "someone-else")).await;
    assert_eq!(
        resp.status(),
        429,
        "login-like endpoint must be rate-limited per-IP, ignoring any client_id-shaped body field"
    );
}

//! T-39 / T-143 — the revocation feed as an HTTP surface.
//!
//! Two properties, and the second is the one that makes the feature safe to
//! ship: with `AXIAM__AUTH__REVOCATION_FEED_ENABLED` unset the route **does
//! not exist**. Not "exists and answers 404 or an empty list" — a route that
//! exists is one an operator finds in a log, a proxy is configured for and a
//! scanner reports on, and an off-by-default feature that leaves traces is not
//! off.

use actix_web::{App, test, web};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{
    RateLimitConfig, RouteOptions, register_api_v1_routes, register_api_v1_routes_with,
};
use axiam_auth::config::AuthConfig;
use surrealdb::Surreal;
use surrealdb::engine::local::Db as TestDb;
use surrealdb::engine::local::Mem;

async fn db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn test_auth_config() -> AuthConfig {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.test.example".into(),
        ..AuthConfig::default()
    }
}

const PATH: &str = "/oauth2/revocations";

#[actix_rt::test]
async fn the_feed_is_served_when_the_deployment_asked_for_it() {
    let db = db().await;
    let state = AppState::for_test(db.clone(), test_auth_config());
    let app = test::init_service(App::new().app_data(web::Data::new(state)).configure(|cfg| {
        register_api_v1_routes_with::<TestDb>(
            cfg,
            &RateLimitConfig::default(),
            RouteOptions {
                revocation_feed_enabled: true,
                ..RouteOptions::default()
            },
        )
    }))
    .await;

    let resp = test::call_service(&app, test::TestRequest::get().uri(PATH).to_request()).await;
    assert_eq!(resp.status(), 200);
    // The caching headers are the whole cost model: a conformant poller spends
    // one conditional request per interval, not one full transfer.
    assert!(resp.headers().contains_key("ETag"));
    assert!(resp.headers().contains_key("Cache-Control"));

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["alg"], "SHA-256");
    assert_eq!(body["ttl"], 900);
    assert!(
        body["revoked"].as_array().expect("an array").is_empty(),
        "nothing has been revoked in this fixture"
    );
    // The member set is what an SDK decodes. A fourth member would be a
    // disclosure decision, so it has to be argued rather than added.
    let mut members: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(members, vec!["alg", "issued_at", "revoked", "ttl"]);
}

/// **I4 twin.** The default route table has no such path, so a deployment that
/// did not opt in is byte-identical to one built before the feed existed.
#[actix_rt::test]
async fn the_feed_does_not_exist_unless_the_deployment_asked_for_it() {
    let db = db().await;
    let state = AppState::for_test(db.clone(), test_auth_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;

    let resp = test::call_service(&app, test::TestRequest::get().uri(PATH).to_request()).await;
    assert_eq!(
        resp.status(),
        404,
        "a deployment that did not opt in must not serve this path"
    );
}

/// A conditional request is answered `304`, which is what makes polling cheap.
/// Asserted through the real headers rather than against the handler, because
/// an `ETag` that does not survive the response builder is an `ETag` nobody
/// gets.
#[actix_rt::test]
async fn a_conditional_poll_is_answered_not_modified() {
    let db = db().await;
    let state = AppState::for_test(db.clone(), test_auth_config());
    let app = test::init_service(App::new().app_data(web::Data::new(state)).configure(|cfg| {
        register_api_v1_routes_with::<TestDb>(
            cfg,
            &RateLimitConfig::default(),
            RouteOptions {
                revocation_feed_enabled: true,
                ..RouteOptions::default()
            },
        )
    }))
    .await;

    let first = test::call_service(&app, test::TestRequest::get().uri(PATH).to_request()).await;
    let etag = first
        .headers()
        .get("ETag")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let second = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(PATH)
            .insert_header(("If-None-Match", etag.clone()))
            .to_request(),
    )
    .await;
    assert_eq!(second.status(), 304);
    assert_eq!(
        second.headers().get("ETag").unwrap().to_str().unwrap(),
        etag
    );
}

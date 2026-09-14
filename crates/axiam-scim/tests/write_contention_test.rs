//! T-262 / R-4: a contended SCIM write answers `503` + `Retry-After: 1`.
//!
//! `3ccef6a30` introduced [`AxiamError::WriteContention`] and wired it into
//! `axiam-api-rest` and `axiam-api-grpc`, but not into this crate's own
//! `From<AxiamError> for ScimError`. It therefore fell through to the
//! catch-all and a SCIM caller that lost an optimistic-concurrency race was
//! told the server had broken.
//!
//! `src/error.rs`'s unit tests already pin the rendering. These drive it
//! through a REAL Actix service instead, because the three things the
//! contract is written in terms of — the status line, the `Retry-After`
//! header, and the body a client parses — are properties of the response
//! Actix puts on the wire, and a `ResponseError` impl can render a header
//! that the pipeline then drops (an error body rebuilt by a middleware, a
//! `map_into_boxed_body` that loses it). This is the same observation
//! `benchmarks/scenarios/scim_provisioning.js` makes with k6, at a scale
//! that fits in CI.
//!
//! Run with: cargo test -p axiam-scim --test write_contention_test

use actix_web::http::StatusCode;
use actix_web::http::header::RETRY_AFTER;
use actix_web::{App, HttpResponse, test, web};
use axiam_core::error::AxiamError;
use axiam_scim::error::{SCIM_ERROR_SCHEMA, ScimError};

/// Stands in for any SCIM write whose repository call exhausted
/// `retry_on_write_conflict`'s four attempts. What is under test is the
/// `?`-propagation path every SCIM handler uses, not the repository — which
/// is why this returns the error directly rather than racing a real one: a
/// probabilistic race would make the test flaky in exactly the direction that
/// hides the defect.
async fn contended_write() -> Result<HttpResponse, ScimError> {
    Err(AxiamError::WriteContention.into())
}

macro_rules! contended_app {
    () => {
        test::init_service(
            App::new().route("/scim/v2/Users/{id}", web::patch().to(contended_write)),
        )
        .await
    };
}

/// The defect itself: the status a provisioning IdP (Okta, Entra) reads as
/// "repeat this", not the `500` it reads as a failed sync and recovers from by
/// re-sending the whole record.
#[actix_rt::test]
async fn a_contended_scim_write_answers_503_not_500() {
    let app = contended_app!();
    let req = test::TestRequest::patch()
        .uri("/scim/v2/Users/u-1")
        .to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_ne!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

/// The half that makes the status useful, and the half a match arm alone
/// would not have delivered: the header survives onto the wire. CONTRACT
/// §16.1 has every SDK honour it as a floor.
#[actix_rt::test]
async fn the_503_reaches_the_wire_carrying_retry_after() {
    let app = contended_app!();
    let req = test::TestRequest::patch()
        .uri("/scim/v2/Users/u-1")
        .to_request();
    let resp = test::call_service(&app, req).await;

    let retry_after = resp
        .headers()
        .get(RETRY_AFTER)
        .expect("a 503 that does not say when to come back is no better than the 500 was");
    assert_eq!(retry_after.to_str().unwrap(), "1");
}

/// The blanket 5xx redaction (SEC-011/CQ-B33) must not reach this one body.
/// Redacting it would leave a client holding a `Retry-After` and a sentence
/// saying the server is broken — the two halves contradicting each other.
#[actix_rt::test]
async fn the_body_tells_the_client_to_retry_rather_than_that_the_server_broke() {
    let app = contended_app!();
    let req = test::TestRequest::patch()
        .uri("/scim/v2/Users/u-1")
        .to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // RFC 7644 §3.12: a SCIM client parses this shape, not AXIAM's ordinary
    // REST envelope.
    assert_eq!(body["schemas"][0], SCIM_ERROR_SCHEMA);
    assert_eq!(body["status"], "503");
    assert_ne!(body["detail"], "An internal error occurred");
    assert_eq!(body["detail"], AxiamError::WriteContention.to_string());

    // The variant carries no payload, so the engine's own words stay in the
    // log where `DbError::Conflict` keeps them.
    let rendered = body.to_string();
    for leak in ["Transaction", "write conflict", "surreal", "SurrealDB"] {
        assert!(
            !rendered.contains(leak),
            "{leak:?} must not appear in the response body: {rendered}"
        );
    }
}

/// **Control.** The carve-out above is one variant wide. An ordinary 5xx
/// still redacts, still carries no `Retry-After`, and still never echoes the
/// datastore string that produced it.
#[actix_rt::test]
async fn an_ordinary_5xx_still_redacts_and_advertises_no_retry() {
    async fn database_error() -> Result<HttpResponse, ScimError> {
        Err(AxiamError::Database("host=db-1 user=axiam".into()).into())
    }

    let app = test::init_service(App::new().route("/boom", web::get().to(database_error))).await;
    let req = test::TestRequest::get().uri("/boom").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        resp.headers().get(RETRY_AFTER).is_none(),
        "a 500 must not advertise a retry"
    );

    let req = test::TestRequest::get().uri("/boom").to_request();
    let body: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(body["detail"], "An internal error occurred");
    assert!(!body.to_string().contains("host=db-1"));
}

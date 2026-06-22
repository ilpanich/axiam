//! REQ-14 AC-5 — Generic 5xx error body tests (SEC-011/SEC-039/CQ-B33).
//!
//! Tests the body serialisation by calling error_response() and inspecting
//! the JSON body.  Small static bodies are available synchronously via
//! `actix_web::body::to_bytes` which internally polls a `Bytes` body.

use actix_rt::System;
use actix_web::{ResponseError, body::to_bytes};
use axiam_api_rest::error::AxiamApiError;
use axiam_core::error::AxiamError;

fn extract_body(err: AxiamError) -> String {
    let api_err = AxiamApiError::from(err);
    let resp = api_err.error_response();
    // body::to_bytes is an async fn; we use actix_rt::System::new().block_on
    System::new().block_on(async {
        let bytes = to_bytes(resp.into_body()).await.expect("body bytes");
        String::from_utf8(bytes.to_vec()).expect("utf8 body")
    })
}

/// 5xx variants must return a generic body that does not leak internal detail.
#[test]
fn internal_error_body_generic() {
    let super_secret = "DB password is hunter2 and key is AABBCC";
    let body = extract_body(AxiamError::Database(super_secret.to_string()));
    assert!(
        !body.contains(super_secret),
        "Internal detail must not appear in response body: {body}"
    );
    assert!(
        body.contains("internal_error") || body.contains("An internal error occurred"),
        "Generic message expected in body: {body}"
    );
}

/// Crypto errors must not leak key material.
#[test]
fn crypto_error_body_generic() {
    let body = extract_body(AxiamError::Crypto(
        "AES-GCM nonce mismatch; key=DEADBEEF".to_string(),
    ));
    assert!(
        !body.contains("DEADBEEF"),
        "Crypto key material must not leak: {body}"
    );
}

/// Client-error variants (NotFound) must echo the message (not scrub it).
#[test]
fn not_found_body_echoes_message() {
    let body = extract_body(AxiamError::NotFound {
        entity: "user".to_string(),
        id: "abc-123".to_string(),
    });
    assert!(
        body.contains("user") || body.contains("not_found"),
        "NotFound body should reference entity: {body}"
    );
}

/// ValidationError echoes its message.
#[test]
fn validation_error_body_echoes() {
    let body = extract_body(AxiamError::Validation {
        message: "email is required".to_string(),
    });
    assert!(
        body.contains("email"),
        "Validation body should echo message: {body}"
    );
}

/// Internal errors return HTTP 500.
#[test]
fn internal_error_returns_500() {
    let err = AxiamError::Internal("something went wrong internally".to_string());
    let api_err = AxiamApiError::from(err);
    assert_eq!(
        api_err.status_code(),
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
    );
}

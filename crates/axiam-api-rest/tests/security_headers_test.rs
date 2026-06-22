//! Integration tests for SecurityHeadersMiddleware — verify that all OWASP-required
//! security headers are injected into every API response.

use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::middleware::security_headers::SecurityHeadersMiddleware;

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().body("hello")
}

#[actix_web::test]
async fn security_header_x_content_type_options_nosniff() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeadersMiddleware)
            .route("/test", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    let value = resp
        .headers()
        .get("x-content-type-options")
        .expect("x-content-type-options header missing");
    assert_eq!(value, "nosniff");
}

#[actix_web::test]
async fn security_header_x_frame_options_deny() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeadersMiddleware)
            .route("/test", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    let value = resp
        .headers()
        .get("x-frame-options")
        .expect("x-frame-options header missing");
    assert_eq!(value, "DENY");
}

#[actix_web::test]
async fn security_header_referrer_policy_strict_origin() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeadersMiddleware)
            .route("/test", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    let value = resp
        .headers()
        .get("referrer-policy")
        .expect("referrer-policy header missing");
    assert_eq!(value, "strict-origin-when-cross-origin");
}

#[actix_web::test]
async fn all_three_security_headers_present_simultaneously() {
    let app = test::init_service(
        App::new()
            .wrap(SecurityHeadersMiddleware)
            .route("/test", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/test").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(
        resp.headers().contains_key("x-content-type-options"),
        "x-content-type-options missing"
    );
    assert!(
        resp.headers().contains_key("x-frame-options"),
        "x-frame-options missing"
    );
    assert!(
        resp.headers().contains_key("referrer-policy"),
        "referrer-policy missing"
    );
    assert_eq!(resp.status().as_u16(), 200);
}

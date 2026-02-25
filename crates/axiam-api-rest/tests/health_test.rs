//! Integration tests for health and readiness endpoints.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::health::HealthChecker;
use axiam_api_rest::server::health_routes;

struct MockHealthy;

impl HealthChecker for MockHealthy {
    fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

struct MockUnhealthy;

impl HealthChecker for MockUnhealthy {
    fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Err("db down".into()) })
    }
}

#[actix_rt::test]
async fn health_returns_200_ok() {
    let checker: Arc<dyn HealthChecker> = Arc::new(MockHealthy);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(checker))
            .configure(health_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/health").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
}

#[actix_rt::test]
async fn ready_returns_200_when_db_healthy() {
    let checker: Arc<dyn HealthChecker> = Arc::new(MockHealthy);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(checker))
            .configure(health_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/ready").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["database"], "connected");
}

#[actix_rt::test]
async fn ready_returns_503_when_db_unhealthy() {
    let checker: Arc<dyn HealthChecker> = Arc::new(MockUnhealthy);
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(checker))
            .configure(health_routes),
    )
    .await;

    let req = test::TestRequest::get().uri("/ready").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 503);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "unavailable");
    assert_eq!(body["database"], "disconnected");
}

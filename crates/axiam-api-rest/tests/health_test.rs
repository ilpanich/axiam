//! Integration tests for health and readiness endpoints.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::health::HealthChecker;
use axiam_api_rest::server::health_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

type TestDb = surrealdb::engine::local::Db;

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

/// Build an `AppState<TestDb>` (QUAL-01) with `health_checker` overridden to
/// the given test double — `/ready` now extracts `web::Data<AppState<C>>`
/// instead of a standalone `web::Data<Arc<dyn HealthChecker>>`.
async fn state_with_checker(checker: Arc<dyn HealthChecker>) -> AppState<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let mut state = AppState::for_test(db, AuthConfig::default());
    state.health_checker = checker;
    state
}

#[actix_rt::test]
async fn health_returns_200_ok() {
    let state = state_with_checker(Arc::new(MockHealthy)).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(health_routes::<TestDb>),
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
    let state = state_with_checker(Arc::new(MockHealthy)).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(health_routes::<TestDb>),
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
    let state = state_with_checker(Arc::new(MockUnhealthy)).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(health_routes::<TestDb>),
    )
    .await;

    let req = test::TestRequest::get().uri("/ready").to_request();
    let resp = test::call_service(&app, req).await;

    assert_eq!(resp.status().as_u16(), 503);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "unavailable");
    assert_eq!(body["database"], "disconnected");
}

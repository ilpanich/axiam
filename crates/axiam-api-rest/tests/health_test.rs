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

// ---------------------------------------------------------------------------
// T-129 — scheduled-job liveness
// ---------------------------------------------------------------------------

use axiam_api_rest::health::{JobHealthReporter, JobStatus};

/// Reports a fixed set of jobs, so the endpoint's aggregation can be tested
/// without running a real sweep loop.
struct FixedJobs(Vec<JobStatus>);

impl JobHealthReporter for FixedJobs {
    fn snapshot(&self) -> Vec<JobStatus> {
        self.0.clone()
    }
}

fn job(name: &str, stalled: bool) -> JobStatus {
    JobStatus {
        name: name.into(),
        last_success_at: Some("2026-08-21T12:00:00+00:00".into()),
        last_failure_at: None,
        last_error: None,
        consecutive_failures: 0,
        stalled,
    }
}

async fn state_with_jobs(jobs: Vec<JobStatus>) -> AppState<TestDb> {
    let mut state = state_with_checker(Arc::new(MockHealthy)).await;
    state.job_health = Arc::new(FixedJobs(jobs));
    state
}

async fn get_jobs(state: AppState<TestDb>) -> (u16, serde_json::Value) {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(health_routes::<TestDb>),
    )
    .await;
    let req = test::TestRequest::get().uri("/health/jobs").to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    (status, test::read_body_json(resp).await)
}

#[actix_rt::test]
async fn jobs_reports_ok_when_every_sweep_is_running() {
    let (status, body) = get_jobs(
        state_with_jobs(vec![
            job("gdpr_purge", false),
            job("audit_retention", false),
        ])
        .await,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["jobs"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn jobs_reports_degraded_when_any_sweep_is_stalled() {
    let (status, body) = get_jobs(
        state_with_jobs(vec![job("gdpr_purge", true), job("audit_retention", false)]).await,
    )
    .await;
    // 200, not 503, and deliberately so: this is not a readiness gate. A stuck
    // cleanup sweep must not pull a serving pod out of the load balancer and
    // shift its traffic onto replicas running the identical stuck code.
    assert_eq!(status, 200);
    assert_eq!(body["status"], "degraded");
}

#[actix_rt::test]
async fn jobs_reports_ok_with_an_empty_list_when_nothing_is_registered() {
    // The `NoJobs` default. An empty list must not read as "degraded", or a
    // deployment that never wires a reporter alerts forever and gets muted.
    let (status, body) = get_jobs(state_with_jobs(vec![]).await).await;
    assert_eq!(status, 200);
    assert_eq!(body["status"], "ok");
    assert!(body["jobs"].as_array().unwrap().is_empty());
}

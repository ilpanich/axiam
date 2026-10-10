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

use axiam_api_rest::health::{JobHealthReporter, JobStatus, RequestAuditHealth};

/// Reports a fixed set of jobs, so the endpoint's aggregation can be tested
/// without running a real sweep loop.
struct FixedJobs(Vec<JobStatus>, Option<RequestAuditHealth>);

impl JobHealthReporter for FixedJobs {
    fn snapshot(&self) -> Vec<JobStatus> {
        self.0.clone()
    }

    fn request_audit(&self) -> Option<RequestAuditHealth> {
        self.1.clone()
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
    state.job_health = Arc::new(FixedJobs(jobs, None));
    state
}

async fn get_jobs(state: AppState<TestDb>) -> (u16, serde_json::Value) {
    get_jobs_from(state).await
}

async fn get_jobs_from(state: AppState<TestDb>) -> (u16, serde_json::Value) {
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

// ---------------------------------------------------------------------------
// T-108 — request-audit loss on /health/jobs
// ---------------------------------------------------------------------------

fn request_audit(recent_loss: bool) -> RequestAuditHealth {
    RequestAuditHealth {
        dropped: 7,
        failed: 3,
        dead_lettered: 9,
        not_recoverable: 1,
        dead_letter_configured: true,
        dead_letter_full: false,
        last_loss_at: Some("2026-10-09T12:00:00+00:00".into()),
        recent_loss,
    }
}

async fn get_jobs_with_audit(audit: Option<RequestAuditHealth>) -> serde_json::Value {
    let mut state = state_with_checker(Arc::new(MockHealthy)).await;
    state.job_health = Arc::new(FixedJobs(vec![job("gdpr_purge", false)], audit));
    let (status, body) = get_jobs_from(state).await;
    assert_eq!(status, 200, "never a readiness gate");
    body
}

#[actix_rt::test]
async fn jobs_reports_the_request_audit_counters() {
    let body = get_jobs_with_audit(Some(request_audit(false))).await;
    let a = &body["request_audit"];
    assert_eq!(a["dropped"], 7);
    assert_eq!(a["failed"], 3);
    assert_eq!(a["dead_lettered"], 9);
    assert_eq!(a["not_recoverable"], 1);
    assert_eq!(a["dead_letter_configured"], true);
    assert_eq!(a["dead_letter_full"], false);
    assert_eq!(a["recent_loss"], false);
    assert_eq!(body["status"], "ok", "a past loss alone is not degraded");
}

#[actix_rt::test]
async fn jobs_reports_degraded_while_request_audit_rows_are_being_lost() {
    let body = get_jobs_with_audit(Some(request_audit(true))).await;
    assert_eq!(body["status"], "degraded");
}

/// R1W2-02: a dead-letter file at its budget refuses every further request
/// row, so it is reported, and is `degraded` with no recent loss: the next
/// loss would not be recoverable.
#[actix_rt::test]
async fn jobs_reports_a_full_dead_letter_file_as_degraded() {
    let body = get_jobs_with_audit(Some(RequestAuditHealth {
        dead_letter_full: true,
        ..request_audit(false)
    }))
    .await;
    assert_eq!(body["request_audit"]["dead_letter_full"], true);
    assert_eq!(body["status"], "degraded");
}

#[actix_rt::test]
async fn jobs_omits_request_audit_when_the_process_does_not_count_it() {
    let body = get_jobs_with_audit(None).await;
    assert!(body.get("request_audit").is_none());
    assert_eq!(body["status"], "ok");
}

// ---------------------------------------------------------------------------
// G-8 / D-59 — `/health` states the deployment profile
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn health_reports_the_full_profile_with_no_unavailable_list() {
    let state = state_with_checker(Arc::new(MockHealthy)).await;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(health_routes::<TestDb>),
    )
    .await;

    let resp = test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["profile"], "full");
    assert!(
        body.get("unavailable").is_none(),
        "the full profile gives nothing up, so the field is absent: {body}"
    );
}

#[actix_rt::test]
async fn health_reports_the_minimal_profile_and_what_it_does_not_provide() {
    let mut state = state_with_checker(Arc::new(MockHealthy)).await;
    state.deployment_profile = axiam_core::models::deployment::DeploymentProfile::Minimal;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(health_routes::<TestDb>),
    )
    .await;

    let resp = test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
    assert_eq!(resp.status().as_u16(), 200, "liveness is unaffected");
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["profile"], "minimal");
    assert_eq!(
        body["unavailable"],
        serde_json::json!([
            "reactors",
            "amqp_authz",
            "amqp_audit_ingestion",
            "decision_cache_broadcast"
        ])
    );
}

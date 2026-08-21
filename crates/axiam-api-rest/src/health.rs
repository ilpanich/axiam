//! Health and readiness endpoints.

use std::future::Future;
use std::pin::Pin;

use actix_web::{HttpResponse, web};
use serde::Serialize;
use surrealdb::Connection;

use crate::state::AppState;

/// Trait for checking backend health (DB, etc.).
///
/// Object-safe — stored as `web::Data<Arc<dyn HealthChecker>>`.
pub trait HealthChecker: Send + Sync {
    fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>>;
}

impl HealthChecker for axiam_db::DbManager {
    fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async {
            self.health_check()
                .await
                .map_err(|e| format!("db health check failed: {e}"))
        })
    }
}

impl HealthChecker for axiam_db::DbPool {
    fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async {
            // Probes every pooled handle so readiness reflects the whole pool
            // (an auth-expired or poisoned handle anywhere trips the gate).
            self.health_check()
                .await
                .map_err(|e| format!("db health check failed: {e}"))
        })
    }
}

/// Always-healthy test double (mirrors the `AllowAllAuthzChecker` test
/// fixture precedent already established in this crate). Used by
/// `AppState::for_test` so test harnesses that don't specifically exercise
/// `/ready` degraded-health behavior get a working default.
pub struct AlwaysHealthy;

impl HealthChecker for AlwaysHealthy {
    fn check(&self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Scheduled-job liveness (T-129)
// ---------------------------------------------------------------------------

/// The last-known outcome of one background sweep.
///
/// T-129: a scheduled job that stops running is invisible. GDPR erasure and
/// certificate expiry are exactly the jobs whose *absence* is the incident —
/// nothing errors, nothing 500s, deletions simply stop happening and the first
/// symptom is a regulator's question months later. Failures were already
/// logged, but a log line nobody greps for is not a control.
#[derive(Serialize, utoipa::ToSchema, Clone, Debug)]
pub struct JobStatus {
    /// Stable identifier for the sweep, e.g. `gdpr_purge`.
    pub name: String,
    /// RFC 3339 timestamp of the last run that completed without error.
    pub last_success_at: Option<String>,
    /// RFC 3339 timestamp of the last run that returned an error.
    pub last_failure_at: Option<String>,
    /// The last error text, for the operator who is now looking at this page
    /// wondering what went wrong.
    pub last_error: Option<String>,
    /// Consecutive failures since the last success. Reset to 0 on success.
    pub consecutive_failures: u32,
    /// Whether the job has missed enough expected runs to be considered stuck.
    ///
    /// The single field to build an alert on. Computed server-side rather than
    /// left to the caller because the sweep interval is configuration the
    /// caller does not have, and "how long is too long" is not a judgement a
    /// dashboard should be re-deriving from timestamps.
    pub stalled: bool,
}

/// Source of [`JobStatus`] snapshots.
///
/// A trait for the same reason [`HealthChecker`] is one: the jobs live in
/// `axiam-server`, which sits above this crate in the layering, so the
/// dependency has to point inward.
pub trait JobHealthReporter: Send + Sync {
    /// Current status of every registered job.
    fn snapshot(&self) -> Vec<JobStatus>;
}

/// Reports no jobs. The default in [`AppState::for_test`], and what a
/// deployment gets if nothing registers a real reporter.
///
/// [`AppState::for_test`]: crate::state::AppState::for_test
pub struct NoJobs;

impl JobHealthReporter for NoJobs {
    fn snapshot(&self) -> Vec<JobStatus> {
        Vec::new()
    }
}

/// Response body for `GET /health/jobs`.
#[derive(Serialize, utoipa::ToSchema)]
pub struct JobsHealthResponse {
    /// `ok` when no job is stalled, `degraded` when at least one is.
    pub status: &'static str,
    pub jobs: Vec<JobStatus>,
}

/// `GET /health/jobs` — scheduled-job liveness (T-129).
///
/// Always 200, including when a job is stalled, and that is deliberate. This
/// is not a readiness gate: a stuck cleanup sweep is an operational problem,
/// not a reason to pull a healthy server out of the load balancer and send its
/// traffic to replicas running the same stuck code. Alert on
/// `status == "degraded"`, or on a specific job's `stalled`.
#[utoipa::path(
    get,
    path = "/health/jobs",
    tag = "health",
    responses(
        (status = 200, description = "Scheduled-job status", body = JobsHealthResponse),
    )
)]
pub async fn jobs<C: Connection + Clone>(state: web::Data<AppState<C>>) -> HttpResponse {
    let jobs = state.job_health.snapshot();
    let status = if jobs.iter().any(|j| j.stalled) {
        "degraded"
    } else {
        "ok"
    };
    HttpResponse::Ok().json(JobsHealthResponse { status, jobs })
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub database: &'static str,
}

/// `GET /health` — liveness probe. Always returns 200.
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is alive", body = HealthResponse),
    )
)]
pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse { status: "ok" })
}

/// `GET /ready` — readiness probe. Checks DB connectivity.
#[utoipa::path(
    get,
    path = "/ready",
    tag = "health",
    responses(
        (status = 200, description = "Service is ready", body = ReadyResponse),
        (status = 503, description = "Service is not ready", body = ReadyResponse),
    )
)]
pub async fn ready<C: Connection + Clone>(state: web::Data<AppState<C>>) -> HttpResponse {
    match state.health_checker.check().await {
        Ok(()) => HttpResponse::Ok().json(ReadyResponse {
            status: "ok",
            database: "connected",
        }),
        Err(_) => HttpResponse::ServiceUnavailable().json(ReadyResponse {
            status: "unavailable",
            database: "disconnected",
        }),
    }
}

// ---------------------------------------------------------------------------
// Tests
//
// `impl HealthChecker for axiam_db::DbManager` and `impl HealthChecker for
// axiam_db::DbPool` (above) are NOT covered here: `DbManager`'s only public
// constructors (`connect`/`connect_with_ttl`) dial a real SurrealDB server,
// and `DbPool`'s `from_handles` (the one constructor that accepts the
// in-memory `Mem` engine) is a private `axiam-db`-internal fn, not
// reachable from this crate. Exercising those two impls would need either a
// live SurrealDB server or a new public test-only constructor in
// `axiam-db` — both out of scope for this test-only pass. `ready<C>`'s own
// Ok/Err branches are already covered end-to-end in `tests/health_test.rs`
// via `MockHealthy`/`MockUnhealthy`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Direct test of the `AlwaysHealthy` test-double `HealthChecker` impl
    /// (used as `AppState::for_test`'s default `health_checker`, but every
    /// existing `/ready` test overrides it with `MockHealthy`/`MockUnhealthy`
    /// to control the branch under test — so `AlwaysHealthy::check()` itself
    /// was never directly invoked).
    #[tokio::test]
    async fn always_healthy_check_returns_ok() {
        let checker = AlwaysHealthy;
        assert!(checker.check().await.is_ok());
    }
}

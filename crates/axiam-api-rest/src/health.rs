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

impl<C: Connection> HealthChecker for axiam_db::DbPool<C> {
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

    /// Request-audit loss counters (T-108), when this process counts them.
    fn request_audit(&self) -> Option<RequestAuditHealth> {
        None
    }
}

/// Request-audit rows that were not recorded, since this process started (T-108).
///
/// The audit middleware appends each request's row on a background worker. A row
/// is lost when the worker's queue is full at the end of the request (`dropped`)
/// or when the datastore refuses the append (`failed`). Both counters only go up
/// and reset when the process restarts; alert on their rate, or on `recent_loss`.
#[derive(Serialize, utoipa::ToSchema, Clone, Debug, PartialEq, Eq)]
pub struct RequestAuditHealth {
    /// Rows refused because the queue was full.
    pub dropped: u64,
    /// Rows the worker took and could not append to the datastore.
    pub failed: u64,
    /// Lost rows written to the dead-letter file, from which they can be replayed.
    pub dead_lettered: u64,
    /// Lost rows kept nowhere: no dead-letter file is configured, or it could not
    /// take them.
    pub not_recoverable: u64,
    /// Whether `AXIAM__GDPR_AUDIT_DLQ_FILE` names a dead-letter file.
    pub dead_letter_configured: bool,
    /// Whether the dead-letter file has reached the request rows' share of its
    /// budget (`AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES`): further request rows are
    /// refused by it and counted in `not_recoverable` until it is replayed and
    /// moved. Turns the endpoint's `status` to `degraded`.
    pub dead_letter_full: bool,
    /// RFC 3339 timestamp of the most recent lost row.
    pub last_loss_at: Option<String>,
    /// Whether a row was lost in the last 15 minutes. Turns the endpoint's
    /// `status` to `degraded`, and clears itself once rows are being recorded again.
    pub recent_loss: bool,
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
    /// `ok` when no job is stalled, no request-audit row was lost recently and
    /// the dead-letter file is not full; `degraded` otherwise.
    pub status: &'static str,
    pub jobs: Vec<JobStatus>,
    /// Request-audit loss counters (T-108). Absent when the process does not
    /// count them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_audit: Option<RequestAuditHealth>,
}

/// `GET /health/jobs` — scheduled-job liveness (T-129).
///
/// Always 200, including when a job is stalled, and that is deliberate. This
/// is not a readiness gate: a stuck cleanup sweep is an operational problem,
/// not a reason to pull a healthy server out of the load balancer and send its
/// traffic to replicas running the same stuck code. Alert on
/// `status == "degraded"`, or on a specific job's `stalled`. `request_audit`
/// counts the request-audit rows this process lost (T-108); a loss in the last
/// 15 minutes is `degraded` too, and so is a full dead-letter file.
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
    let request_audit = state.job_health.request_audit();
    let status = if jobs.iter().any(|j| j.stalled)
        || request_audit
            .as_ref()
            .is_some_and(|a| a.recent_loss || a.dead_letter_full)
    {
        "degraded"
    } else {
        "ok"
    };
    HttpResponse::Ok().json(JobsHealthResponse {
        status,
        jobs,
        request_audit,
    })
}

/// Response body for `GET /health`.
///
/// `profile` and `unavailable` are additive (G-8, D-59): a client that reads
/// only `status` is unaffected.
#[derive(Serialize, utoipa::ToSchema)]
pub struct HealthResponse {
    pub status: &'static str,
    /// The messaging profile this process runs: `full` (RabbitMQ is used) or
    /// `minimal` (`AXIAM__AMQP__ENABLED=false`, no broker).
    #[schema(example = "full")]
    pub profile: &'static str,
    /// Present only in the `minimal` profile: the capabilities it does not
    /// provide — `reactors`, `amqp_authz`, `amqp_audit_ingestion` and
    /// `decision_cache_broadcast`. Absent in `full`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<Vec<&'static str>>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct ReadyResponse {
    pub status: &'static str,
    pub database: &'static str,
}

/// `GET /health` — liveness probe. Always returns 200.
///
/// Also states the deployment profile (`full` | `minimal`) and, in `minimal`,
/// what that profile does not provide. The state is optional so the route
/// stays a liveness probe that answers even when mounted without it (`full`).
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is alive", body = HealthResponse),
    )
)]
pub async fn health<C: Connection + Clone>(state: Option<web::Data<AppState<C>>>) -> HttpResponse {
    let profile = state.map(|s| s.deployment_profile).unwrap_or_default();
    HttpResponse::Ok().json(HealthResponse {
        status: "ok",
        profile: profile.as_str(),
        unavailable: profile.is_minimal().then(|| profile.unavailable().to_vec()),
    })
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

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

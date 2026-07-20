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

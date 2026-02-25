//! Health and readiness endpoints.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::{HttpResponse, web};
use serde::Serialize;

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

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct ReadyResponse {
    status: &'static str,
    database: &'static str,
}

/// `GET /health` — liveness probe. Always returns 200.
pub async fn health() -> HttpResponse {
    HttpResponse::Ok().json(HealthResponse { status: "ok" })
}

/// `GET /ready` — readiness probe. Checks DB connectivity.
pub async fn ready(checker: web::Data<Arc<dyn HealthChecker>>) -> HttpResponse {
    match checker.check().await {
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

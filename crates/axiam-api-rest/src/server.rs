//! Actix-Web application factory — composable route and middleware builders.

use actix_cors::Cors;
use actix_web::http::header;
use actix_web::web;

/// Register health and readiness routes.
pub fn health_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(crate::health::health))
        .route("/ready", web::get().to(crate::health::ready));
}

/// Register the API v1 scope (placeholder for future endpoints).
pub fn api_v1_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/v1"));
}

/// Build CORS middleware from configuration.
///
/// An empty `allowed_origins` slice enables permissive mode (suitable for
/// development). A populated slice restricts to those origins.
pub fn build_cors(allowed_origins: &[String]) -> Cors {
    if allowed_origins.is_empty() {
        Cors::permissive()
    } else {
        let mut cors = Cors::default()
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
            ])
            .max_age(3600);
        for origin in allowed_origins {
            cors = cors.allowed_origin(origin);
        }
        cors
    }
}

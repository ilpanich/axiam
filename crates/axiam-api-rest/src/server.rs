//! Actix-Web application factory — composable route and middleware builders.

use actix_cors::Cors;
use actix_web::http::header;
use actix_web::web;
use axiam_db::WsClient;

use crate::handlers;

/// Register health and readiness routes.
pub fn health_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(crate::health::health))
        .route("/ready", web::get().to(crate::health::ready));
}

/// Register the API v1 scope with all domain endpoints (production WsClient).
pub fn api_v1_routes(cfg: &mut web::ServiceConfig) {
    register_api_v1_routes::<WsClient>(cfg);
}

/// Register the API v1 scope, generic over the SurrealDB connection type.
///
/// This allows tests to use an in-memory DB while production uses WebSocket.
pub fn register_api_v1_routes<C: surrealdb::Connection>(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/login", web::post().to(handlers::auth::login::<C>))
            .route("/logout", web::post().to(handlers::auth::logout::<C>))
            .route("/refresh", web::post().to(handlers::auth::refresh::<C>))
            .route(
                "/mfa/enroll",
                web::post().to(handlers::auth::enroll_mfa::<C>),
            )
            .route(
                "/mfa/confirm",
                web::post().to(handlers::auth::confirm_mfa::<C>),
            )
            .route(
                "/mfa/verify",
                web::post().to(handlers::auth::verify_mfa::<C>),
            ),
    );
    cfg.service(
        web::scope("/api/v1")
            .service(
                web::resource("/organizations")
                    .route(web::post().to(handlers::organizations::create::<C>))
                    .route(web::get().to(handlers::organizations::list::<C>)),
            )
            .service(
                web::resource("/organizations/{org_id}")
                    .route(web::get().to(handlers::organizations::get::<C>))
                    .route(web::put().to(handlers::organizations::update::<C>))
                    .route(web::delete().to(handlers::organizations::delete::<C>)),
            )
            .service(
                web::resource("/organizations/{org_id}/tenants")
                    .route(web::post().to(handlers::tenants::create::<C>))
                    .route(web::get().to(handlers::tenants::list::<C>)),
            )
            .service(
                web::resource("/organizations/{org_id}/tenants/{tenant_id}")
                    .route(web::get().to(handlers::tenants::get::<C>))
                    .route(web::put().to(handlers::tenants::update::<C>))
                    .route(web::delete().to(handlers::tenants::delete::<C>)),
            )
            .service(
                web::resource("/users")
                    .route(web::post().to(handlers::users::create::<C>))
                    .route(web::get().to(handlers::users::list::<C>)),
            )
            .service(
                web::resource("/users/{user_id}")
                    .route(web::get().to(handlers::users::get::<C>))
                    .route(web::put().to(handlers::users::update::<C>))
                    .route(web::delete().to(handlers::users::delete::<C>)),
            ),
    );
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

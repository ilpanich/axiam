//! Actix-Web application factory — composable route and middleware builders.

use actix_cors::Cors;
use actix_web::http::header;
use actix_web::web;
use axiam_db::WsClient;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::handlers;
use crate::openapi::ApiDoc;

/// Register health and readiness routes.
pub fn health_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(crate::health::health))
        .route("/ready", web::get().to(crate::health::ready));
}

/// Register Swagger UI and OpenAPI JSON spec routes.
pub fn openapi_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        SwaggerUi::new("/api/docs/{_:.*}").url("/api/docs/openapi.json", ApiDoc::openapi()),
    );
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
            )
            .service(
                web::resource("/groups")
                    .route(web::post().to(handlers::groups::create::<C>))
                    .route(web::get().to(handlers::groups::list::<C>)),
            )
            .service(
                web::resource("/groups/{group_id}")
                    .route(web::get().to(handlers::groups::get::<C>))
                    .route(web::put().to(handlers::groups::update::<C>))
                    .route(web::delete().to(handlers::groups::delete::<C>)),
            )
            .service(
                web::resource("/groups/{group_id}/members")
                    .route(web::post().to(handlers::groups::add_member::<C>))
                    .route(web::get().to(handlers::groups::list_members::<C>)),
            )
            .service(
                web::resource("/groups/{group_id}/members/{user_id}")
                    .route(web::delete().to(handlers::groups::remove_member::<C>)),
            )
            // --- Roles ---
            .service(
                web::resource("/roles")
                    .route(web::post().to(handlers::roles::create::<C>))
                    .route(web::get().to(handlers::roles::list::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}")
                    .route(web::get().to(handlers::roles::get::<C>))
                    .route(web::put().to(handlers::roles::update::<C>))
                    .route(web::delete().to(handlers::roles::delete::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/users")
                    .route(web::post().to(handlers::roles::assign_to_user::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/users/{user_id}")
                    .route(web::delete().to(handlers::roles::unassign_from_user::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/groups")
                    .route(web::post().to(handlers::roles::assign_to_group::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/groups/{group_id}")
                    .route(web::delete().to(handlers::roles::unassign_from_group::<C>)),
            )
            // --- Permissions ---
            .service(
                web::resource("/permissions")
                    .route(web::post().to(handlers::permissions::create::<C>))
                    .route(web::get().to(handlers::permissions::list::<C>)),
            )
            .service(
                web::resource("/permissions/{permission_id}")
                    .route(web::get().to(handlers::permissions::get::<C>))
                    .route(web::put().to(handlers::permissions::update::<C>))
                    .route(web::delete().to(handlers::permissions::delete::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/permissions")
                    .route(web::post().to(handlers::permissions::grant_to_role::<C>))
                    .route(web::get().to(handlers::permissions::list_role_permissions::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/permissions/{permission_id}")
                    .route(
                        web::delete().to(handlers::permissions::revoke_from_role::<C>),
                    ),
            )
            // --- Resources ---
            .service(
                web::resource("/resources")
                    .route(web::post().to(handlers::resources::create::<C>))
                    .route(web::get().to(handlers::resources::list::<C>)),
            )
            .service(
                web::resource("/resources/{resource_id}")
                    .route(web::get().to(handlers::resources::get::<C>))
                    .route(web::put().to(handlers::resources::update::<C>))
                    .route(web::delete().to(handlers::resources::delete::<C>)),
            )
            .service(
                web::resource("/resources/{resource_id}/children")
                    .route(web::get().to(handlers::resources::list_children::<C>)),
            )
            .service(
                web::resource("/resources/{resource_id}/ancestors")
                    .route(web::get().to(handlers::resources::list_ancestors::<C>)),
            )
            // --- Scopes (nested under resources) ---
            .service(
                web::resource("/resources/{resource_id}/scopes")
                    .route(web::post().to(handlers::scopes::create::<C>))
                    .route(web::get().to(handlers::scopes::list::<C>)),
            )
            .service(
                web::resource("/resources/{resource_id}/scopes/{scope_id}")
                    .route(web::get().to(handlers::scopes::get::<C>))
                    .route(web::put().to(handlers::scopes::update::<C>))
                    .route(web::delete().to(handlers::scopes::delete::<C>)),
            )
            // --- Service Accounts ---
            .service(
                web::resource("/service-accounts")
                    .route(web::post().to(handlers::service_accounts::create::<C>))
                    .route(web::get().to(handlers::service_accounts::list::<C>)),
            )
            .service(
                web::resource("/service-accounts/{sa_id}")
                    .route(web::get().to(handlers::service_accounts::get::<C>))
                    .route(web::put().to(handlers::service_accounts::update::<C>))
                    .route(web::delete().to(handlers::service_accounts::delete::<C>)),
            )
            .service(
                web::resource("/service-accounts/{sa_id}/rotate-secret")
                    .route(web::post().to(handlers::service_accounts::rotate_secret::<C>)),
            ),
    );
}

/// Build CORS middleware from configuration.
///
/// An empty `allowed_origins` slice yields a restrictive default policy
/// (denying cross-origin requests). A populated slice restricts CORS to the
/// specified origins.
pub fn build_cors(allowed_origins: &[String]) -> Cors {
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

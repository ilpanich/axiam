//! `/scim/v2/*` route wiring.

use actix_web::{HttpResponse, ResponseError, web};
use surrealdb::Connection;

use axiam_api_rest::middleware::authz::AuthzMiddleware;

use crate::error::ScimError;
use crate::{groups, schema, users};

/// Register every `/scim/v2/*` route on the given `ServiceConfig`.
///
/// Wrapped in the same [`AuthzMiddleware`] every other authenticated AXIAM
/// REST scope uses (`server.rs`'s `/api/v1/*` scopes) — SCIM clients always
/// carry `Authorization: Bearer <token>` (never the browser session cookie),
/// so it behaves here exactly as it does on any bearer-only route: 401 on a
/// wholly missing credential, then defer the actual `scim:provision` check
/// to [`crate::auth::require_scim_provision`] inside each handler.
pub fn scim_routes<C: Connection + Clone>(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/scim/v2")
            .wrap(AuthzMiddleware)
            // Service-discovery endpoints (RFC 7643 §5-7). Same auth
            // requirement as every other SCIM route — nothing here is
            // registered as an `AuthzMiddleware` public path, since even
            // these mostly-static bodies still describe an AXIAM-tenant-
            // specific deployment surface.
            .route(
                "/ServiceProviderConfig",
                web::get().to(schema::service_provider_config),
            )
            .route("/ResourceTypes", web::get().to(schema::resource_types))
            .route("/ResourceTypes/{name}", web::get().to(schema::resource_type))
            .route("/Schemas", web::get().to(schema::schemas))
            .route("/Schemas/{id}", web::get().to(schema::schema_by_id))
            // B4: bulk operations are explicitly out of scope — return the
            // correct SCIM error (501) rather than a generic 404.
            .route("/Bulk", web::post().to(bulk_not_supported))
            .service(
                web::resource("/Users")
                    .route(web::get().to(users::list::<C>))
                    .route(web::post().to(users::create::<C>)),
            )
            .service(
                web::resource("/Users/{id}")
                    .route(web::get().to(users::get::<C>))
                    .route(web::put().to(users::replace::<C>))
                    .route(web::patch().to(users::patch::<C>))
                    .route(web::delete().to(users::delete::<C>)),
            )
            .service(
                web::resource("/Groups")
                    .route(web::get().to(groups::list::<C>))
                    .route(web::post().to(groups::create::<C>)),
            )
            .service(
                web::resource("/Groups/{id}")
                    .route(web::get().to(groups::get::<C>))
                    .route(web::put().to(groups::replace::<C>))
                    .route(web::patch().to(groups::patch::<C>))
                    .route(web::delete().to(groups::delete::<C>)),
            ),
    );
}

async fn bulk_not_supported() -> HttpResponse {
    ScimError::not_implemented("Bulk operations are not supported (B4: explicitly out of scope)")
        .error_response()
}

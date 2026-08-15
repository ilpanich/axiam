//! `/scim/v2/*` route wiring.

use actix_web::{HttpResponse, ResponseError, web};
use surrealdb::Connection;

use axiam_api_rest::config::RateLimitConfig;
use axiam_api_rest::middleware::authz::AuthzMiddleware;
use axiam_api_rest::middleware::rate_limit_shared::RateLimitShared;
use axiam_api_rest::server::build_governor;

use crate::error::ScimError;
use crate::{groups, schema, users};

/// Bucket name for the shared (cross-replica) rate-limit counter. Must be
/// unique across every rate-limited resource in the deployment — see
/// [`RateLimitShared`]'s docs.
const SCIM_BUCKET: &str = "scim";

/// Register every `/scim/v2/*` route with the shipped rate-limit posture.
///
/// Equivalent to [`scim_routes_with_rate_limits`] with
/// [`RateLimitConfig::default`], mirroring `axiam_api_rest::api_v1_routes`
/// versus `register_api_v1_routes`. The composition root
/// (`axiam-server::main`) uses the configured form; tests that do not care
/// about the limiter use this one.
pub fn scim_routes<C: Connection + Clone>(cfg: &mut web::ServiceConfig) {
    scim_routes_with_rate_limits::<C>(cfg, &RateLimitConfig::default());
}

/// Register every `/scim/v2/*` route on the given `ServiceConfig`.
///
/// Wrapped in the same [`AuthzMiddleware`] every other authenticated AXIAM
/// REST scope uses (`server.rs`'s `/api/v1/*` scopes) — SCIM clients always
/// carry `Authorization: Bearer <token>` (never the browser session cookie),
/// so it behaves here exactly as it does on any bearer-only route: 401 on a
/// wholly missing credential, then defer the actual `scim:provision` check
/// to [`crate::auth::require_scim_provision`] inside each handler.
///
/// # Rate limiting (R5.2)
///
/// Wrapped in the SAME two layers every rate-limited family in `server.rs`
/// uses, in the same order — [`RateLimitShared`] (cross-replica, fail-open)
/// as the OUTER wrap, [`build_governor`] (per-replica, in-memory GCRA) just
/// inside it. Because `.wrap()` applies last-registered-outermost, the calls
/// below read bottom-up: `RateLimitShared` first, then the governor, then
/// `AuthzMiddleware`.
///
/// The limiters sit OUTSIDE `AuthzMiddleware` deliberately: an unauthenticated
/// `/scim/v2` flood should be shed before it reaches the credential check,
/// which is also why the discovery endpoints are covered by the same bucket
/// rather than left unmetered.
///
/// One bucket spans the whole scope — see
/// [`RateLimitConfig::scim_per_min`] for why (and for where the 600/min
/// default comes from).
pub fn scim_routes_with_rate_limits<C: Connection + Clone>(
    cfg: &mut web::ServiceConfig,
    rate_limit_cfg: &RateLimitConfig,
) {
    let scim_per_min = rate_limit_cfg.scim_per_min;
    cfg.service(
        web::scope("/scim/v2")
            .wrap(AuthzMiddleware)
            .wrap(build_governor(scim_per_min))
            .wrap(RateLimitShared::<C>::new(SCIM_BUCKET, scim_per_min))
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

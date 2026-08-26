//! Actix-Web application factory — composable route and middleware builders.

use actix_cors::Cors;
use actix_governor::Governor;
use actix_governor::GovernorConfigBuilder;
use actix_governor::governor::middleware::NoOpMiddleware;
use actix_web::http::header;
use actix_web::web;
use axiam_db::DbClient;
use utoipa_swagger_ui::SwaggerUi;

use crate::config::RateLimitConfig;
use crate::config::rate_limit::RateLimitKeyMode;
use crate::extractors::rate_limit::{ClientAwareKeyExtractor, XForwardedForKeyExtractor};
use crate::handlers;
use crate::middleware::authz::AuthzMiddleware;
use crate::middleware::csrf::CsrfMiddleware;
use crate::middleware::rate_limit_shared::RateLimitShared;
use crate::openapi::api_doc;

/// Build a per-endpoint Governor middleware instance from a requests-per-minute
/// limit.
///
/// Each call creates an independent in-memory store — never share configs
/// between endpoints with different limits (that would merge their counters).
///
/// **Public for cross-crate route modules only** (R5.2): `axiam-scim` mounts
/// `/scim/v2` from its own crate but must be limited by the SAME two layers
/// as every family wired here — this per-replica governor plus
/// [`crate::middleware::rate_limit_shared::RateLimitShared`] as the outer
/// wrap. Exporting the constructor is what lets it reuse the wiring instead
/// of inventing a parallel one. It stays IP-keyed; use
/// `build_client_aware_governor` only for the three OAuth2 endpoints that
/// carry a form-encoded `client_id`.
pub fn build_governor(
    requests_per_min: u32,
) -> Governor<XForwardedForKeyExtractor, NoOpMiddleware> {
    // SEC-048: trusted_hops=0 default; override via AXIAM__RATE_LIMIT__TRUSTED_HOPS
    // when running behind a single ingress/nginx layer (set to 1).
    let trusted_hops: usize = std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let config = GovernorConfigBuilder::default()
        .requests_per_minute(requests_per_min as u64)
        .burst_size(requests_per_min)
        .key_extractor(XForwardedForKeyExtractor::with_trusted_hops(trusted_hops))
        .finish()
        .expect("valid governor config");
    Governor::new(&config)
}

/// D8: build a per-endpoint Governor middleware instance for the three
/// endpoints where an OAuth2 client identity (`client_id`) is available —
/// `/oauth2/token`, `/oauth2/revoke`, `/oauth2/introspect` ONLY.
///
/// `key_mode` (`AXIAM__RATE_LIMIT__KEY`, from [`RateLimitConfig::key`])
/// controls whether the bucket key is IP alone (default, unchanged
/// behavior), the OAuth2 `client_id` alone, or the `(ip, client_id)` pair —
/// see [`crate::config::rate_limit::RateLimitKeyMode`] for the full
/// NAT'd-fleet rationale. The `client_id` itself is read from request
/// extensions populated by `middleware::rate_limit_shared::RateLimitShared`
/// (wired as the OUTER `.wrap()` on the same resource, so it always runs
/// first — see that middleware's docs).
///
/// **Never call this for `/auth/login`** (or any other endpoint without a
/// client identity) — use [`build_governor`] there instead, unconditionally.
fn build_client_aware_governor(
    requests_per_min: u32,
    key_mode: RateLimitKeyMode,
) -> Governor<ClientAwareKeyExtractor, NoOpMiddleware> {
    let trusted_hops: usize = std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let config = GovernorConfigBuilder::default()
        .requests_per_minute(requests_per_min as u64)
        .burst_size(requests_per_min)
        .key_extractor(ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::with_trusted_hops(trusted_hops),
            key_mode,
        ))
        .finish()
        .expect("valid governor config");
    Governor::new(&config)
}

/// Register health and readiness routes.
///
/// Generic over `C` (QUAL-01) since `/ready` now extracts
/// `web::Data<AppState<C>>` for its `HealthChecker`.
pub fn health_routes<C: surrealdb::Connection + Clone>(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(crate::health::health))
        .route("/ready", web::get().to(crate::health::ready::<C>))
        // T-129. Unauthenticated like the other two probes: it reports
        // whether background sweeps are running and when they last
        // succeeded, which is operational metadata about this server, not
        // tenant data — the same category as `/ready` disclosing that the
        // database is reachable.
        .route("/health/jobs", web::get().to(crate::health::jobs::<C>));
}

/// Register Swagger UI and OpenAPI JSON spec routes.
pub fn openapi_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(SwaggerUi::new("/api/docs/{_:.*}").url("/api/docs/openapi.json", api_doc()));
}

/// Register the API v1 scope with all domain endpoints (production DbClient).
pub fn api_v1_routes(cfg: &mut web::ServiceConfig) {
    register_api_v1_routes::<DbClient>(cfg, &RateLimitConfig::default());
}

/// Register the API v1 scope, generic over the SurrealDB connection type.
///
/// This allows tests to use an in-memory DB while production uses WebSocket.
/// The `rate_limit_cfg` parameter controls per-endpoint rate limits.
pub fn register_api_v1_routes<C: surrealdb::Connection + Clone>(
    cfg: &mut web::ServiceConfig,
    rate_limit_cfg: &RateLimitConfig,
) {
    let auth_scope = web::scope("/api/v1/auth")
            .wrap(AuthzMiddleware)
            .wrap(CsrfMiddleware)
            .app_data(web::JsonConfig::default().limit(65_536))
            .service(
                // D8: `/auth/login` ALWAYS keys per-IP, regardless of
                // `AXIAM__RATE_LIMIT__KEY`. Login authenticates a *user* via
                // username/password — there is no OAuth2 `client_id` (or any
                // other client identity) anywhere in this request to key
                // on, so `build_governor`/`RateLimitShared::new` (the
                // IP-only constructors) are used unconditionally here, never
                // the client-identity-aware variants. See
                // `crate::config::rate_limit::RateLimitKeyMode` docs.
                web::resource("/login")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new("login", rate_limit_cfg.login_per_min))
                    .route(web::post().to(handlers::auth::login::<C>)),
            )
            // OPAQUE shares `/login`'s per-IP budget policy for the same
            // reason: both are unauthenticated, both take a user identifier,
            // and neither carries a client identity to key on. Every one of
            // the three is rate-limited, not just the finish — each performs
            // elliptic-curve work per call, so leaving any of them open would
            // hand an attacker a cheap way to burn server CPU. `register/start`
            // in particular is unauthenticated by necessity (it is used while
            // creating a user who does not exist yet), which makes it the one
            // most worth a budget.
            .service(
                web::resource("/opaque/register/start")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "opaque_register_start",
                        rate_limit_cfg.login_per_min,
                    ))
                    .route(web::post().to(handlers::opaque::opaque_register_start::<C>)),
            )
            .service(
                web::resource("/opaque/login/start")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "opaque_login_start",
                        rate_limit_cfg.login_per_min,
                    ))
                    .route(web::post().to(handlers::opaque::opaque_login_start::<C>)),
            )
            .service(
                web::resource("/opaque/login/finish")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "opaque_login_finish",
                        rate_limit_cfg.login_per_min,
                    ))
                    .route(web::post().to(handlers::opaque::opaque_login_finish::<C>)),
            )
            .route("/logout", web::post().to(handlers::auth::logout::<C>))
            .route("/refresh", web::post().to(handlers::auth::refresh::<C>))
            .route("/me", web::get().to(handlers::auth::me::<C>))
            // SEC-020: MFA endpoints rate-limited to prevent brute-force/enumeration.
            .service(
                web::resource("/mfa/enroll")
                    .wrap(build_governor(rate_limit_cfg.mfa_per_min))
                    .wrap(RateLimitShared::<C>::new("mfa_enroll", rate_limit_cfg.mfa_per_min))
                    .route(web::post().to(handlers::auth::enroll_mfa::<C>)),
            )
            .service(
                web::resource("/mfa/confirm")
                    .wrap(build_governor(rate_limit_cfg.mfa_per_min))
                    .wrap(RateLimitShared::<C>::new("mfa_confirm", rate_limit_cfg.mfa_per_min))
                    .route(web::post().to(handlers::auth::confirm_mfa::<C>)),
            )
            .service(
                web::resource("/mfa/verify")
                    .wrap(build_governor(rate_limit_cfg.mfa_per_min))
                    .wrap(RateLimitShared::<C>::new("mfa_verify", rate_limit_cfg.mfa_per_min))
                    .route(web::post().to(handlers::auth::verify_mfa::<C>)),
            )
            .service(
                web::resource("/mfa/setup/enroll")
                    .wrap(build_governor(rate_limit_cfg.mfa_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "mfa_setup_enroll",
                        rate_limit_cfg.mfa_per_min,
                    ))
                    .route(web::post().to(handlers::auth::setup_enroll_mfa::<C>)),
            )
            .service(
                web::resource("/mfa/setup/confirm")
                    .wrap(build_governor(rate_limit_cfg.mfa_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "mfa_setup_confirm",
                        rate_limit_cfg.mfa_per_min,
                    ))
                    .route(web::post().to(handlers::auth::setup_confirm_mfa::<C>)),
            )
            .route("/device", web::post().to(handlers::auth::device_auth::<C>))
            // All six WebAuthn ceremony routes take their limit from
            // `webauthn_per_min`, the way the five MFA routes above take theirs
            // from `mfa_per_min`. Each route still gets its OWN bucket —
            // `RateLimitShared` keys `"{endpoint}:{ip}"` — so the value is the
            // allowance each route carries, not one pool they divide. That is
            // why it equals `login_per_min` rather than doubling it: a ceremony
            // spends one from `start` and one from `finish`.
            //
            // They carried NO limiter at all until this change — neither
            // `build_governor` nor `RateLimitShared` — while the MFA routes
            // directly above and the OPAQUE routes directly below each carried
            // one, which is what made it an omission rather than a decision.
            //
            // D8 applies here for the same reason it applies to `/auth/login`:
            // a ceremony authenticates a USER and carries no OAuth2 client
            // identity to key on, so the IP-only constructors are used
            // unconditionally, never the client-identity-aware variants.
            .service(
                web::resource("/webauthn/register/start")
                    .wrap(build_governor(rate_limit_cfg.webauthn_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "webauthn_register_start",
                        rate_limit_cfg.webauthn_per_min,
                    ))
                    .route(web::post().to(handlers::webauthn::start_registration::<C>)),
            )
            .service(
                web::resource("/webauthn/register/finish")
                    .wrap(build_governor(rate_limit_cfg.webauthn_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "webauthn_register_finish",
                        rate_limit_cfg.webauthn_per_min,
                    ))
                    .route(web::post().to(handlers::webauthn::finish_registration::<C>)),
            )
            .service(
                web::resource("/webauthn/authenticate/start")
                    .wrap(build_governor(rate_limit_cfg.webauthn_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "webauthn_authenticate_start",
                        rate_limit_cfg.webauthn_per_min,
                    ))
                    .route(web::post().to(handlers::webauthn::start_authentication::<C>)),
            )
            .service(
                web::resource("/webauthn/authenticate/finish")
                    .wrap(build_governor(rate_limit_cfg.webauthn_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "webauthn_authenticate_finish",
                        rate_limit_cfg.webauthn_per_min,
                    ))
                    .route(web::post().to(handlers::webauthn::finish_authentication::<C>)),
            )
            // Usernameless (discoverable-credential) sign-in. Separate from the
            // pair above because the ceremonies differ in what identifies the
            // user: those continue a login that already named one, these
            // discover it from the assertion.
            //
            // These two are UNAUTHENTICATED — no session, no username — which
            // makes them the pair whose missing limiter mattered most, and the
            // reason this bucket could not wait for a capacity measurement.
            .service(
                web::resource("/webauthn/authenticate/discoverable/start")
                    .wrap(build_governor(rate_limit_cfg.webauthn_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "webauthn_discoverable_start",
                        rate_limit_cfg.webauthn_per_min,
                    ))
                    .route(
                        web::post().to(handlers::webauthn::start_discoverable_authentication::<C>),
                    ),
            )
            .service(
                web::resource("/webauthn/authenticate/discoverable/finish")
                    .wrap(build_governor(rate_limit_cfg.webauthn_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "webauthn_discoverable_finish",
                        rate_limit_cfg.webauthn_per_min,
                    ))
                    .route(
                        web::post().to(handlers::webauthn::finish_discoverable_authentication::<C>),
                    ),
            )
            .route(
                "/verify-email",
                web::post().to(handlers::email_verification::verify_email::<C>),
            )
            .route(
                "/resend-verification",
                web::post().to(handlers::email_verification::resend_verification::<C>),
            )
            .service(
                web::resource("/reset")
                    .wrap(build_governor(rate_limit_cfg.password_reset_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "password_reset",
                        rate_limit_cfg.password_reset_per_min,
                    ))
                    .route(web::post().to(handlers::password_reset::request_reset::<C>)),
            )
            .route(
                "/reset/confirm",
                web::post().to(handlers::password_reset::confirm_reset::<C>),
            )
            // Token-gated lookup that lets an unauthenticated reset page compute
            // an OPAQUE record. Shares `/reset`'s budget: it is unauthenticated
            // and takes a token, so it must not be a cheaper probe than the
            // endpoint it supports.
            .service(
                web::resource("/reset/context")
                    .wrap(build_governor(rate_limit_cfg.password_reset_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "password_reset_context",
                        rate_limit_cfg.password_reset_per_min,
                    ))
                    .route(web::get().to(handlers::password_reset::reset_context::<C>)),
            )
            // --- GDPR delete-cancel (public — emailed single-use token, D-09) ---
            // Listed in PUBLIC_PATHS so AuthzMiddleware lets it through without a JWT.
            .service(
                web::resource("/account/delete/cancel")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "account_delete_cancel",
                        rate_limit_cfg.login_per_min,
                    ))
                    .route(
                        web::get()
                            .to(handlers::gdpr::cancel_account_delete::<C>),
                    ),
            )
            .service(
                web::resource("/password/change")
                    .wrap(build_governor(rate_limit_cfg.password_reset_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "password_change",
                        rate_limit_cfg.password_reset_per_min,
                    ))
                    .route(web::post().to(handlers::auth::change_password::<C>)),
            )
            // --- First-time SSO — public (Phase 4 D-22) ---
            // These routes are listed in PUBLIC_PATHS (permissions.rs) so the
            // AuthzMiddleware lets them through without a JWT.
            .service(
                web::resource("/federation/oidc/start")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "federation_oidc_start",
                        rate_limit_cfg.login_per_min,
                    ))
                    .route(
                        web::post()
                            .to(handlers::federation::oidc_start_public::<C>),
                    ),
            )
            .service(
                web::resource("/federation/oidc/callback")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "federation_oidc_callback",
                        rate_limit_cfg.login_per_min,
                    ))
                    .route(
                        web::post()
                            .to(handlers::federation::oidc_callback_public::<C>),
                    ),
            );
    // First-time SSO SAML public routes — only when the `saml` feature is on.
    #[cfg(feature = "saml")]
    let auth_scope = auth_scope
        .service(
            web::resource("/federation/saml/login")
                .wrap(build_governor(rate_limit_cfg.login_per_min))
                .wrap(RateLimitShared::<C>::new(
                    "federation_saml_login",
                    rate_limit_cfg.login_per_min,
                ))
                .route(web::post().to(handlers::federation::saml_login_public::<C>)),
        )
        .service(
            web::resource("/federation/saml/acs")
                .wrap(build_governor(rate_limit_cfg.login_per_min))
                .wrap(RateLimitShared::<C>::new(
                    "federation_saml_acs",
                    rate_limit_cfg.login_per_min,
                ))
                .route(web::post().to(handlers::federation::saml_acs_public::<C>)),
        );
    cfg.service(auth_scope);
    // OIDC Discovery (must be outside /oauth2 scope per spec)
    cfg.route(
        "/.well-known/openid-configuration",
        web::get().to(handlers::oauth2::discovery),
    );
    // X2 / UMA 2.0 §2. Outside the `/oauth2` scope for the same reason as OIDC
    // discovery: the spec fixes the path at the host root.
    cfg.route(
        "/.well-known/uma2-configuration",
        web::get().to(handlers::uma::uma2_configuration),
    );
    // X2 — the UMA Protection API. Its own scope rather than a route under
    // `/oauth2`, because UMA 2.0 §3.2 fixes the path and because these
    // endpoints are PAT-protected bearer routes, not client-credential form
    // posts like the token endpoint family.
    cfg.service(
        web::scope("/uma2")
            .wrap(AuthzMiddleware)
            .service(
                web::resource("/perm")
                    .wrap(build_governor(rate_limit_cfg.uma_perm_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "uma_perm",
                        rate_limit_cfg.uma_perm_per_min,
                    ))
                    .route(web::post().to(handlers::uma::permission_request::<C>)),
            )
            // FedAuthz §2.2. Shares the `uma_perm` bucket sizing but gets its
            // own counter name: registration is administrative traffic (a
            // resource server registers at deploy time, not per request), so
            // letting it consume the permission endpoint's allowance would let
            // a registration loop starve live authorization.
            .service(
                web::resource("/rreg/resource_set")
                    .wrap(build_governor(rate_limit_cfg.uma_perm_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "uma_rreg",
                        rate_limit_cfg.uma_perm_per_min,
                    ))
                    .route(web::post().to(handlers::uma::register_resource_set::<C>))
                    .route(web::get().to(handlers::uma::list_resource_sets::<C>)),
            )
            .service(
                web::resource("/rreg/resource_set/{id}")
                    .wrap(build_governor(rate_limit_cfg.uma_perm_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "uma_rreg",
                        rate_limit_cfg.uma_perm_per_min,
                    ))
                    .route(web::get().to(handlers::uma::read_resource_set::<C>))
                    .route(web::put().to(handlers::uma::update_resource_set::<C>))
                    .route(web::delete().to(handlers::uma::delete_resource_set::<C>)),
            ),
    );
    cfg.service(
        web::scope("/oauth2")
            .wrap(AuthzMiddleware)
            .route(
                "/authorize",
                web::get().to(handlers::oauth2::authorize::<C>),
            )
            // D8: `/token`, `/revoke`, `/introspect` are the ONLY three
            // endpoints with a form-encoded OAuth2 `client_id`
            // (`client_secret_post`, RFC 6749 §2.3.1) — the client-aware
            // governor/`RateLimitShared` constructors honor
            // `rate_limit_cfg.key` (`AXIAM__RATE_LIMIT__KEY`) here so a
            // NAT'd fleet of distinct OAuth2 clients no longer collides into
            // one shared per-IP bucket. `key` defaults to `ip`, which is
            // byte-for-byte the pre-D8 behavior.
            .service(
                web::resource("/token")
                    .wrap(build_client_aware_governor(
                        rate_limit_cfg.token_per_min,
                        rate_limit_cfg.key,
                    ))
                    .wrap(RateLimitShared::<C>::new_client_identity_aware(
                        "oauth2_token",
                        rate_limit_cfg.token_per_min,
                        rate_limit_cfg.key,
                    ))
                    .route(web::post().to(handlers::oauth2::token::<C>)),
            )
            // SEC-020: revoke and introspect rate-limited to prevent DoS via token flooding
            // and token probing attacks.
            .service(
                web::resource("/revoke")
                    .wrap(build_client_aware_governor(
                        rate_limit_cfg.revoke_per_min,
                        rate_limit_cfg.key,
                    ))
                    .wrap(RateLimitShared::<C>::new_client_identity_aware(
                        "oauth2_revoke",
                        rate_limit_cfg.revoke_per_min,
                        rate_limit_cfg.key,
                    ))
                    .route(web::post().to(handlers::oauth2::revoke::<C>)),
            )
            .service(
                web::resource("/introspect")
                    .wrap(build_client_aware_governor(
                        rate_limit_cfg.introspect_per_min,
                        rate_limit_cfg.key,
                    ))
                    .wrap(RateLimitShared::<C>::new_client_identity_aware(
                        "oauth2_introspect",
                        rate_limit_cfg.introspect_per_min,
                        rate_limit_cfg.key,
                    ))
                    .route(web::post().to(handlers::oauth2::introspect::<C>)),
            )
            // B2 / RFC 8628 §3.1. Its own bucket rather than the token
            // endpoint's: this one is unauthenticated AND every accepted
            // request allocates state (a pending grant plus a user code drawn
            // from a deliberately small, human-typable space). Sharing the
            // token bucket would let ordinary token traffic pay for — or mask
            // — an attempt to exhaust that space. Per-IP, never client-keyed:
            // RFC 8628 clients are public, so `client_id` is caller-supplied
            // and worthless as a bucket key here.
            .service(
                web::resource("/device_authorization")
                    .wrap(build_governor(rate_limit_cfg.device_authorization_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "oauth2_device_authorization",
                        rate_limit_cfg.device_authorization_per_min,
                    ))
                    .route(web::post().to(handlers::oauth2::device_authorization::<C>)),
            )
            // B5 / RFC 9126. Its own bucket, and unlike
            // `/device_authorization` this one is client-keyed: PAR always
            // carries client credentials, so there is a real identity to key
            // on, and the per-client check happens inside the handler after
            // authentication so an unauthenticated caller cannot burn a real
            // client's allowance. The governor here is the per-IP floor that
            // keeps unauthenticated flooding off the authentication path.
            .service(
                web::resource("/par")
                    .wrap(build_governor(rate_limit_cfg.par_per_min))
                    .route(
                        web::post().to(handlers::oauth2::pushed_authorization_request::<C>),
                    ),
            )
            // B5 / RP-Initiated Logout 1.0. GET and POST both, because §2
            // permits either and browsers reach it by navigation. Its own
            // bucket, per-IP: like `/device_authorization` it is
            // unauthenticated and it TERMINATES state, which is a different
            // abuse profile from the token endpoint's.
            .service(
                web::resource("/end_session")
                    .wrap(build_governor(rate_limit_cfg.end_session_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "oauth2_end_session",
                        rate_limit_cfg.end_session_per_min,
                    ))
                    .route(web::get().to(handlers::oauth2::end_session::<C>))
                    .route(web::post().to(handlers::oauth2::end_session::<C>)),
            )
            .route("/jwks", web::get().to(handlers::oauth2::jwks::<C>))
            .route("/userinfo", web::get().to(handlers::oauth2::userinfo::<C>)),
    );
    let api_scope = web::scope("/api/v1")
            .wrap(AuthzMiddleware)
            .wrap(CsrfMiddleware) // SEC-046: CSRF protection on all /api/v1 CRUD routes
            .app_data(web::JsonConfig::default().limit(65_536)) // CQ-B21: body size limit
            // B2 — the human half of RFC 8628, deliberately inside /api/v1
            // rather than under /oauth2. Two properties come from that
            // placement and both are load-bearing:
            //
            //   * AuthzMiddleware: approving a device grant records the
            //     approver as the subject the eventual token is minted for,
            //     so the caller must be an authenticated human.
            //   * CsrfMiddleware: a user code is short and typed, so another
            //     origin can plausibly know one. Double-submit is what stops
            //     an attacker's page silently POSTing an approval on a
            //     victim's session — the device-code phishing shape RFC 8628
            //     §5.4 warns about, from the other direction.
            //
            // Their shared bucket is the user-code brute-force bound; see
            // `RateLimitConfig::device_verify_per_min`, whose `validate()`
            // asserts the OWASP arithmetic rather than trusting the comment.
            .service(
                web::resource("/device/verify")
                    .wrap(build_governor(rate_limit_cfg.device_verify_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "device_verify",
                        rate_limit_cfg.device_verify_per_min,
                    ))
                    .route(web::get().to(handlers::device::verify::<C>)),
            )
            .service(
                web::resource("/device/decide")
                    .wrap(build_governor(rate_limit_cfg.device_verify_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "device_decide",
                        rate_limit_cfg.device_verify_per_min,
                    ))
                    .route(web::post().to(handlers::device::decide::<C>)),
            )
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
            // --- Organization Settings ---
            .service(
                web::resource("/organizations/{org_id}/settings")
                    .route(web::get().to(
                        handlers::settings::get_org_settings::<C>,
                    ))
                    .route(web::put().to(
                        handlers::settings::set_org_settings::<C>,
                    )),
            )
            // --- Organization Email Config (FUNC-03 / D-13) ---
            .service(
                web::resource("/organizations/{org_id}/email-config")
                    .route(web::get().to(
                        handlers::email_config::get_org_email_config::<C>,
                    ))
                    .route(web::put().to(
                        handlers::email_config::set_org_email_config::<C>,
                    ))
                    .route(web::delete().to(
                        handlers::email_config::delete_org_email_config::<C>,
                    )),
            )
            .service(
                web::resource("/organizations/{org_id}/email-config/test")
                    .route(web::post().to(
                        handlers::email_config::test_org_email_config::<C>,
                    )),
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
            // --- CA Certificates (nested under organizations) ---
            .service(
                web::resource("/organizations/{org_id}/ca-certificates")
                    .route(web::post().to(handlers::ca_certificates::generate::<C>))
                    .route(web::get().to(handlers::ca_certificates::list::<C>)),
            )
            .service(
                web::resource("/organizations/{org_id}/ca-certificates/import")
                    .route(web::post().to(handlers::ca_certificates::import::<C>)),
            )
            .service(
                web::resource("/organizations/{org_id}/ca-certificates/{id}")
                    .route(web::get().to(handlers::ca_certificates::get::<C>)),
            )
            .service(
                web::resource("/organizations/{org_id}/ca-certificates/{id}/revoke")
                    .route(web::post().to(handlers::ca_certificates::revoke::<C>)),
            )
            .service(
                web::resource(
                    "/organizations/{org_id}/ca-certificates/{id}/mtls-trust-anchor",
                )
                .route(
                    web::put().to(handlers::ca_certificates::set_mtls_trust_anchor::<C>),
                ),
            )
            .service(
                web::resource(
                    "/organizations/{org_id}/ca-certificates/{id}/migrate-custody",
                )
                .route(web::post().to(handlers::ca_certificates::migrate_custody::<C>)),
            )
            .service(
                // Registered before the two-segment tenant routes would shadow
                // it: actix matches in registration order, and
                // `/tenants/{tenant_id}` with a trailing literal is a different
                // resource from `/tenants/{tenant_id}` alone, so order is what
                // keeps `signing-cas` from being read as a tenant id.
                web::resource("/organizations/{org_id}/tenants/{tenant_id}/signing-cas")
                    .route(web::post().to(handlers::ca_certificates::generate_intermediate::<C>))
                    .route(web::get().to(handlers::ca_certificates::list_intermediates::<C>)),
            )
            .service(
                web::resource(
                    "/organizations/{org_id}/tenants/{tenant_id}/signing-cas/sign-csr",
                )
                .route(web::post().to(handlers::ca_certificates::sign_intermediate_csr::<C>)),
            )
            // --- Users ---
            //
            // `/users` is deliberately registered as TWO resources, method-
            // guarded, instead of one resource with both routes.
            //
            // An actix `Resource`-level `.wrap()` applies to EVERY method on
            // that resource, so the single-resource form charged `GET /users`
            // (an admin *list*) to the `users_create` registration bucket at
            // `register_per_min` — 5/min per IP in the production posture, so
            // an admin UI listing users started getting 429s after five reads
            // a minute. It also put the shared-store rate-limit pre-check on
            // the list path, which measured 60-65 ms vs 11-12 ms for its
            // structurally identical siblings `GET /roles` / `GET /resources`
            // (see `claude_dev/postseed-transient-investigation.md` §2.1, §7
            // ask 1).
            //
            // Actix tries registered services in order and falls through to
            // the next one when a resource's guards reject, so the guarded
            // POST resource MUST come first; the unguarded `/users` below it
            // then serves the GET (and returns the usual 405 for any other
            // method). Regression test:
            // `tests/users_rate_limit_split_test.rs`.
            .service(
                web::resource("/users")
                    .guard(actix_web::guard::Post())
                    .wrap(build_governor(rate_limit_cfg.register_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "users_create",
                        rate_limit_cfg.register_per_min,
                    ))
                    .route(web::post().to(handlers::users::create::<C>)),
            )
            .service(
                // Unlimited, matching the posture of its sibling list
                // endpoints `/roles` and `/resources`.
                web::resource("/users").route(web::get().to(handlers::users::list::<C>)),
            )
            .service(
                // Registered BEFORE `/users/{user_id}`: actix matches routes in
                // registration order, and `me` would otherwise be captured as a
                // user id and fail to parse as a UUID.
                //
                // Rate-limited on the same governor as the public resend, since
                // it mints the same token and enqueues the same mail — being
                // authenticated is not a reason to be allowed to send more of
                // them.
                web::resource("/users/me/resend-verification")
                    .wrap(build_governor(rate_limit_cfg.register_per_min))
                    .route(
                        web::post()
                            .to(handlers::email_verification::resend_own_verification::<C>),
                    ),
            )
            .service(
                web::resource("/users/{user_id}")
                    .route(web::get().to(handlers::users::get::<C>))
                    .route(web::put().to(handlers::users::update::<C>))
                    .route(web::delete().to(handlers::users::delete::<C>)),
            )
            .service(
                web::resource("/users/{user_id}/unlock")
                    .route(web::post().to(handlers::users::unlock::<C>)),
            )
            .service(
                web::resource("/users/{user_id}/reset-mfa")
                    .route(web::post().to(handlers::auth::reset_mfa::<C>)),
            )
            .service(
                web::resource("/users/{user_id}/mfa-methods")
                    .route(web::get().to(
                        handlers::mfa_methods::list_mfa_methods::<C>,
                    )),
            )
            .service(
                web::resource("/users/{user_id}/mfa-methods/{method_id}")
                    .route(web::delete().to(
                        handlers::mfa_methods::delete_mfa_method::<C>,
                    )),
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
            // The group's and the user's side of the role-assignment edge. They
            // live in `handlers::roles` with the rest of that edge's endpoints,
            // and are the read surface that carries `resource_id` — without
            // which a scoped assignment is indistinguishable from a global one.
            .service(
                web::resource("/groups/{group_id}/roles")
                    .route(web::get().to(handlers::roles::list_group_roles::<C>)),
            )
            .service(
                web::resource("/users/{user_id}/roles")
                    .route(web::get().to(handlers::roles::list_user_roles::<C>)),
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
                    .route(web::get().to(handlers::roles::list_users::<C>))
                    .route(web::post().to(handlers::roles::assign_to_user::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/users/{user_id}")
                    .route(web::delete().to(handlers::roles::unassign_from_user::<C>)),
            )
            .service(
                web::resource("/roles/{role_id}/groups")
                    .route(web::get().to(handlers::roles::list_groups::<C>))
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
            // --- Certificates (tenant scope) ---
            .service(
                web::resource("/certificates")
                    .route(web::post().to(handlers::certificates::generate::<C>))
                    .route(web::get().to(handlers::certificates::list::<C>)),
            )
            .service(
                web::resource("/certificates/{id}")
                    .route(web::get().to(handlers::certificates::get::<C>)),
            )
            .service(
                web::resource("/certificates/{id}/revoke")
                    .route(web::post().to(handlers::certificates::revoke::<C>)),
            )
            // --- Audit Logs ---
            .service(
                web::resource("/audit-logs")
                    .route(web::get().to(handlers::audit::list::<C>)),
            )
            .service(
                web::resource("/audit-logs/system")
                    .route(web::get().to(handlers::audit::list_system::<C>)),
            )
            // --- SCIM provisioning tokens ---
            .service(
                web::resource("/scim-tokens")
                    .route(web::post().to(handlers::scim_tokens::create::<C>))
                    .route(web::get().to(handlers::scim_tokens::list::<C>)),
            )
            .service(
                web::resource("/scim-tokens/{id}")
                    .route(web::delete().to(handlers::scim_tokens::revoke::<C>)),
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
            )
            .service(
                web::resource("/service-accounts/{sa_id}/bind-certificate")
                    .route(web::post().to(handlers::certificates::bind::<C>)),
            )
            // --- PGP Keys ---
            .service(
                web::resource("/pgp-keys/sign-audit-batch")
                    .route(web::post().to(handlers::pgp_keys::sign_audit_batch::<C>)),
            )
            .service(
                web::resource("/pgp-keys")
                    .route(web::post().to(handlers::pgp_keys::generate::<C>))
                    .route(web::get().to(handlers::pgp_keys::list::<C>)),
            )
            .service(
                web::resource("/pgp-keys/{id}")
                    .route(web::get().to(handlers::pgp_keys::get::<C>)),
            )
            .service(
                web::resource("/pgp-keys/{id}/revoke")
                    .route(web::post().to(handlers::pgp_keys::revoke::<C>)),
            )
            .service(
                web::resource("/pgp-keys/{id}/encrypt")
                    .route(web::post().to(handlers::pgp_keys::encrypt::<C>)),
            )
            // --- Notification Rules ---
            .service(
                web::resource("/notification-rules")
                    .route(
                        web::post().to(
                            handlers::notification_rules::create::<C>,
                        ),
                    )
                    .route(
                        web::get().to(
                            handlers::notification_rules::list::<C>,
                        ),
                    ),
            )
            .service(
                web::resource("/notification-rules/{id}")
                    .route(
                        web::get().to(
                            handlers::notification_rules::get::<C>,
                        ),
                    )
                    .route(
                        web::put().to(
                            handlers::notification_rules::update::<C>,
                        ),
                    )
                    .route(
                        web::delete().to(
                            handlers::notification_rules::delete::<C>,
                        ),
                    ),
            )
            // --- Reactors (X1) ---
            //
            // `/reactors/events` is registered BEFORE `/reactors/{id}`:
            // actix matches in registration order, and `{id}` would otherwise
            // swallow `events` and fail as an invalid UUID.
            .service(
                web::resource("/reactors/events")
                    .route(web::get().to(handlers::reactors::list_events::<C>)),
            )
            .service(
                web::resource("/reactors")
                    .route(web::post().to(handlers::reactors::create::<C>))
                    .route(web::get().to(handlers::reactors::list::<C>)),
            )
            .service(
                web::resource("/reactors/{id}")
                    .route(web::get().to(handlers::reactors::get::<C>))
                    .route(web::put().to(handlers::reactors::update::<C>))
                    .route(web::delete().to(handlers::reactors::delete::<C>)),
            )
            // --- Webhooks ---
            .service(
                web::resource("/webhooks")
                    .route(web::post().to(handlers::webhooks::create::<C>))
                    .route(web::get().to(handlers::webhooks::list::<C>)),
            )
            .service(
                web::resource("/webhooks/{id}")
                    .route(web::get().to(handlers::webhooks::get::<C>))
                    .route(web::put().to(handlers::webhooks::update::<C>))
                    .route(
                        web::delete().to(handlers::webhooks::delete::<C>),
                    ),
            )
            // --- OAuth2 Clients ---
            .service(
                web::resource("/oauth2-clients")
                    .route(web::post().to(handlers::oauth2_clients::create::<C>))
                    .route(web::get().to(handlers::oauth2_clients::list::<C>)),
            )
            .service(
                web::resource("/oauth2-clients/{id}")
                    .route(web::get().to(handlers::oauth2_clients::get::<C>))
                    .route(web::put().to(handlers::oauth2_clients::update::<C>))
                    .route(
                        web::delete().to(handlers::oauth2_clients::delete::<C>),
                    ),
            )
            // --- Federation Configs ---
            .service(
                web::resource("/federation-configs")
                    .route(web::post().to(handlers::federation::create::<C>))
                    .route(web::get().to(handlers::federation::list::<C>)),
            )
            .service(
                web::resource("/federation-configs/{id}")
                    .route(web::get().to(handlers::federation::get::<C>))
                    .route(web::put().to(handlers::federation::update::<C>))
                    .route(
                        web::delete().to(handlers::federation::delete::<C>),
                    ),
            )
            // --- Federation OIDC Flow ---
            .service(
                web::resource("/federation/oidc/authorize")
                    .route(
                        web::post().to(handlers::federation::oidc_authorize::<C>),
                    ),
            )
            .service(
                web::resource("/federation/oidc/callback")
                    .route(
                        web::post().to(handlers::federation::oidc_callback::<C>),
                    ),
            )
            // --- Federation SAML Flow: registered at the end, feature-gated ---
            // --- Tenant Settings (from JWT context) ---
            .service(
                web::resource("/settings")
                    .route(web::get().to(
                        handlers::settings::get_tenant_settings::<C>,
                    ))
                    .route(web::put().to(
                        handlers::settings::set_tenant_settings::<C>,
                    )),
            )
            // --- Tenant Email Config (explicit {tenant_id} path segment, D-13) ---
            .service(
                web::resource("/tenants/{tenant_id}/email-config")
                    .route(web::get().to(
                        handlers::email_config::get_tenant_email_config::<C>,
                    ))
                    .route(web::put().to(
                        handlers::email_config::set_tenant_email_config::<C>,
                    ))
                    .route(web::delete().to(
                        handlers::email_config::delete_tenant_email_config::<C>,
                    )),
            )
            .service(
                web::resource("/tenants/{tenant_id}/email-config/test")
                    .route(web::post().to(
                        handlers::email_config::test_tenant_email_config::<C>,
                    )),
            )
            // --- Tenant security overrides (explicit {tenant_id} path segment,
            // same convention as the email-config trio above) ---
            .service(
                web::resource("/tenants/{tenant_id}/settings")
                    .route(web::get().to(
                        handlers::settings::get_tenant_override::<C>,
                    ))
                    .route(web::put().to(
                        handlers::settings::set_tenant_override::<C>,
                    ))
                    .route(web::delete().to(
                        handlers::settings::delete_tenant_override::<C>,
                    )),
            )
            // --- Tenant WebAuthn Attestation Policy (X3 wave 3, explicit
            // {tenant_id} path segment, same convention as email-config above) ---
            .service(
                web::resource("/tenants/{tenant_id}/webauthn/attestation-policy")
                    .route(web::get().to(
                        handlers::webauthn_policy::get_policy::<C>,
                    ))
                    .route(web::put().to(
                        handlers::webauthn_policy::set_policy::<C>,
                    )),
            )
            .service(
                web::resource("/tenants/{tenant_id}/webauthn/compliance-report")
                    .route(web::get().to(
                        handlers::webauthn_policy::compliance_report::<C>,
                    )),
            )
            // --- FIDO MDS3 (X3 wave 3) — server-global, no {tenant_id} ---
            .service(
                web::resource("/mds/status")
                    .route(web::get().to(handlers::mds::status::<C>)),
            )
            .service(
                web::resource("/mds/refresh")
                    .route(web::post().to(handlers::mds::refresh::<C>)),
            )
            // --- Federation Links ---
            .service(
                web::resource("/federation-links/user/{user_id}")
                    .route(
                        web::get().to(handlers::federation::list_user_links::<C>),
                    ),
            )
            .service(
                web::resource("/federation-links/{id}")
                    .route(
                        web::delete().to(handlers::federation::delete_link::<C>),
                    ),
            )
            // --- Admin Bootstrap (public — no auth required) ---
            .service(
                web::resource("/admin/bootstrap")
                    .route(web::post().to(handlers::bootstrap::bootstrap::<C>)),
            )
            // --- GDPR Art. 15 Export ---
            .service(
                web::resource("/account/export")
                    .wrap(build_governor(rate_limit_cfg.register_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "account_export",
                        rate_limit_cfg.register_per_min,
                    ))
                    .route(
                        web::post()
                            .to(handlers::gdpr::request_account_export::<C>),
                    ),
            )
            .service(
                web::resource("/account/export/{token}")
                    .route(
                        web::get()
                            .to(handlers::gdpr::download_account_export::<C>),
                    ),
            )
            // --- GDPR Art. 17 Delete ---
            .service(
                web::resource("/account/delete")
                    .wrap(build_governor(rate_limit_cfg.register_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "account_delete",
                        rate_limit_cfg.register_per_min,
                    ))
                    .route(
                        web::post()
                            .to(handlers::gdpr::request_account_delete::<C>),
                    ),
            )
            // --- Authz check (FND-04) — dedicated higher rate-limit tier (D-07) ---
            // AuthzMiddleware and CsrfMiddleware are inherited from the /api/v1 scope.
            .service(
                web::resource("/authz/check")
                    .wrap(build_governor(rate_limit_cfg.authz_check_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "authz_check",
                        rate_limit_cfg.authz_check_per_min,
                    ))
                    .route(web::post().to(handlers::authz_check::check_access::<C>)),
            )
            .service(
                web::resource("/authz/check/batch")
                    .wrap(build_governor(rate_limit_cfg.authz_check_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "authz_check_batch",
                        rate_limit_cfg.authz_check_per_min,
                    ))
                    .route(web::post().to(handlers::authz_check::batch_check_access::<C>)),
            );
    // Authenticated SAML SP routes — only when the `saml` feature is on.
    #[cfg(feature = "saml")]
    let api_scope = api_scope
        .service(
            web::resource("/federation/saml/authn-request")
                .route(web::post().to(handlers::federation::saml_authn_request::<C>)),
        )
        .service(
            web::resource("/federation/saml/acs")
                .route(web::post().to(handlers::federation::saml_acs::<C>)),
        )
        .service(
            web::resource("/federation/saml/metadata")
                .route(web::get().to(handlers::federation::saml_metadata::<C>)),
        );
    cfg.service(api_scope);
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
        .allowed_header("X-CSRF-Token")
        .max_age(3600);

    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    cors
}

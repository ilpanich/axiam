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
use crate::extractors::rate_limit::XForwardedForKeyExtractor;
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
fn build_governor(requests_per_min: u32) -> Governor<XForwardedForKeyExtractor, NoOpMiddleware> {
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

/// Register health and readiness routes.
///
/// Generic over `C` (QUAL-01) since `/ready` now extracts
/// `web::Data<AppState<C>>` for its `HealthChecker`.
pub fn health_routes<C: surrealdb::Connection + Clone>(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(crate::health::health))
        .route("/ready", web::get().to(crate::health::ready::<C>));
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
                web::resource("/login")
                    .wrap(build_governor(rate_limit_cfg.login_per_min))
                    .wrap(RateLimitShared::<C>::new("login", rate_limit_cfg.login_per_min))
                    .route(web::post().to(handlers::auth::login::<C>)),
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
            .route(
                "/webauthn/register/start",
                web::post().to(handlers::webauthn::start_registration::<C>),
            )
            .route(
                "/webauthn/register/finish",
                web::post().to(handlers::webauthn::finish_registration::<C>),
            )
            .route(
                "/webauthn/authenticate/start",
                web::post().to(handlers::webauthn::start_authentication::<C>),
            )
            .route(
                "/webauthn/authenticate/finish",
                web::post().to(handlers::webauthn::finish_authentication::<C>),
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
    cfg.service(
        web::scope("/oauth2")
            .wrap(AuthzMiddleware)
            .route(
                "/authorize",
                web::get().to(handlers::oauth2::authorize::<C>),
            )
            .service(
                web::resource("/token")
                    .wrap(build_governor(rate_limit_cfg.token_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "oauth2_token",
                        rate_limit_cfg.token_per_min,
                    ))
                    .route(web::post().to(handlers::oauth2::token::<C>)),
            )
            // SEC-020: revoke and introspect rate-limited to prevent DoS via token flooding
            // and token probing attacks.
            .service(
                web::resource("/revoke")
                    .wrap(build_governor(rate_limit_cfg.revoke_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "oauth2_revoke",
                        rate_limit_cfg.revoke_per_min,
                    ))
                    .route(web::post().to(handlers::oauth2::revoke::<C>)),
            )
            .service(
                web::resource("/introspect")
                    .wrap(build_governor(rate_limit_cfg.introspect_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "oauth2_introspect",
                        rate_limit_cfg.introspect_per_min,
                    ))
                    .route(web::post().to(handlers::oauth2::introspect::<C>)),
            )
            .route("/jwks", web::get().to(handlers::oauth2::jwks))
            .route("/userinfo", web::get().to(handlers::oauth2::userinfo::<C>)),
    );
    let api_scope = web::scope("/api/v1")
            .wrap(AuthzMiddleware)
            .wrap(CsrfMiddleware) // SEC-046: CSRF protection on all /api/v1 CRUD routes
            .app_data(web::JsonConfig::default().limit(65_536)) // CQ-B21: body size limit
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
                web::resource("/organizations/{org_id}/ca-certificates/{id}")
                    .route(web::get().to(handlers::ca_certificates::get::<C>)),
            )
            .service(
                web::resource("/organizations/{org_id}/ca-certificates/{id}/revoke")
                    .route(web::post().to(handlers::ca_certificates::revoke::<C>)),
            )
            .service(
                web::resource("/users")
                    .wrap(build_governor(rate_limit_cfg.register_per_min))
                    .wrap(RateLimitShared::<C>::new(
                        "users_create",
                        rate_limit_cfg.register_per_min,
                    ))
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

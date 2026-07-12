//! `AppState<C>` — the single composition root for every REST handler
//! dependency (QUAL-01).
//!
//! Before this module, `axiam-server/src/main.rs` registered ~49 individual
//! `.app_data(web::Data::new(...))` calls and every handler extracted its own
//! subset of `web::Data<Repo<C>>` / `web::Data<Service<...>>` params. Now
//! `main.rs` builds ONE `AppState<C>` and registers it once; handlers extract
//! `web::Data<AppState<C>>` and access dependencies as fields
//! (`state.user_repo`, `state.auth_service`, ...).
//!
//! ## Three dependencies stay registered outside `AppState<C>` (documented deviation)
//!
//! `AuthConfig`, `Arc<dyn SessionValidator>`, and `Arc<dyn AuthzChecker>` are
//! deliberately KEPT as their own standalone `web::Data<T>` registrations in
//! `main.rs`, in addition to being available as `AppState<C>` fields
//! (`state.auth_config`, `state.session_validator`) for handler-level
//! consistency where it is convenient. This is not an oversight:
//!
//! - `impl actix_web::FromRequest for AuthenticatedUser`
//!   (`extractors/auth.rs`) is a fixed, non-generic impl. It cannot know the
//!   concrete `C` used by `AppState<C>` at the call site, so it cannot do
//!   `req.app_data::<web::Data<AppState<C>>>()` — there is no `C` in scope.
//!   It must keep looking up the connection-agnostic `web::Data<AuthConfig>`
//!   and `web::Data<Arc<dyn SessionValidator>>` types directly.
//! - `axiam-audit::middleware::AuditMiddleware` (a different crate, wrapping
//!   the *entire* `App` in `main.rs`, with no dependency on
//!   `axiam-api-rest::AppState`) independently does
//!   `req.app_data::<web::Data<AuthConfig>>()`. It has no way to resolve a
//!   generic `AppState<C>` either.
//! - 118 handler call sites across the crate use the `AuthzData` type alias
//!   (`web::Data<Arc<dyn AuthzChecker>>`) directly via
//!   `authz.get_ref().as_ref()` — none of that call-site shape changes in
//!   this plan (only the 283 `web::Data<T>` sites named in 29-03-PLAN.md's
//!   scope note are migrated), so `Arc<dyn AuthzChecker>` must remain
//!   registered under its own type too.
//!
//! `SurrealPasswordResetTokenRepository<C>` and
//! `SurrealEmailVerificationTokenRepository<C>` were NEVER registered in
//! `main.rs` at all (a pre-existing bug — see 29-03-SUMMARY.md) despite being
//! required by `password_reset.rs`/`email_verification.rs`; since both
//! services are now hoisted singletons, these two repos are constructed
//! once in `main.rs` purely to build `password_reset_service` /
//! `email_verification_service` and do not need their own `AppState` field.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_auth::config::AuthConfig;
use axiam_auth::{
    AuthService, EmailVerificationService, MfaMethodService, PasswordResetService, WebauthnService,
};
use axiam_authz::AuthzConfig;
use axiam_db::{
    SurrealAccountDeletionRepository, SurrealAssertionReplayRepository, SurrealAuditLogRepository,
    SurrealAuthorizationCodeRepository, SurrealCertificateRepository, SurrealConsentRepository,
    SurrealEmailConfigRepository, SurrealErasureProofRepository, SurrealExportJobRepository,
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealFederationLoginStateRepository, SurrealGroupRepository,
    SurrealNotificationRuleRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository, SurrealPermissionRepository,
    SurrealRefreshTokenRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealServiceAccountRepository, SurrealSessionRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebhookRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
#[cfg(feature = "saml")]
use axiam_federation::saml::SamlFederationService;
use axiam_oauth2::authorize::AuthorizeService;
use axiam_oauth2::token::TokenService;
use axiam_pki::{CaService, CertService, DeviceAuthService, PgpService};
use surrealdb::{Connection, Surreal};
use tokio::sync::Semaphore;

use crate::extractors::auth::SessionValidator;
use crate::health::HealthChecker;
use crate::webhook::WebhookDeliveryService;

// ---------------------------------------------------------------------------
// DynMailPublisher — object-safe seam over axiam_core::repository::MailPublisher
// ---------------------------------------------------------------------------
//
// `MailPublisher::publish` returns `impl Future` (RPITIT), which is not
// dyn-safe on its own. `AppState<C>` needs ONE concrete, non-generic field
// type that works for both the real AMQP-backed `MailOutboundPublisher`
// (production — requires a live `lapin::Channel`) and test harnesses (no
// broker available). This mirrors the exact boxed-future seam
// `extractors::auth::SessionValidator` already uses for the identical
// reason. Mechanical call sites are unaffected: `state.mail_outbound_publisher
// .publish(msg).await` reads identically to the old `mail_publisher.publish(msg).await`.

/// Object-safe wrapper trait over [`axiam_core::repository::MailPublisher`].
pub trait DynMailPublisher: Send + Sync {
    fn publish<'a>(
        &'a self,
        msg: axiam_core::models::mail::OutboundMailMessage,
    ) -> Pin<Box<dyn Future<Output = axiam_core::error::AxiamResult<()>> + Send + 'a>>;
}

impl<T> DynMailPublisher for T
where
    T: axiam_core::repository::MailPublisher + Send + Sync,
{
    fn publish<'a>(
        &'a self,
        msg: axiam_core::models::mail::OutboundMailMessage,
    ) -> Pin<Box<dyn Future<Output = axiam_core::error::AxiamResult<()>> + Send + 'a>> {
        Box::pin(axiam_core::repository::MailPublisher::publish(self, msg))
    }
}

/// Always-succeeds no-op mail publisher for test harnesses that don't
/// exercise a mail-sending route (the common case — see 29-03-SUMMARY.md).
/// Mirrors the `AllowAllAuthzChecker` test-fixture precedent already
/// established in this crate (`crate::authz::AllowAllAuthzChecker`).
pub struct NoopMailPublisher;

impl DynMailPublisher for NoopMailPublisher {
    fn publish<'a>(
        &'a self,
        _msg: axiam_core::models::mail::OutboundMailMessage,
    ) -> Pin<Box<dyn Future<Output = axiam_core::error::AxiamResult<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

// ---------------------------------------------------------------------------
// Concrete service type aliases (mirror the ones already declared per-handler
// file, e.g. handlers/auth.rs::AuthSvc<C>, handlers/oauth2.rs::ConcreteTokenService<C>)
// ---------------------------------------------------------------------------

pub type AuthServiceT<C> = AuthService<
    SurrealUserRepository<C>,
    SurrealSessionRepository<C>,
    SurrealFederationLinkRepository<C>,
    SurrealRefreshTokenRepository<C>,
>;

pub type WebauthnServiceT<C> = WebauthnService<axiam_db::SurrealWebauthnCredentialRepository<C>>;

pub type MfaMethodServiceT<C> =
    MfaMethodService<SurrealUserRepository<C>, axiam_db::SurrealWebauthnCredentialRepository<C>>;

pub type CaServiceT<C> = CaService<axiam_db::SurrealCaCertificateRepository<C>>;

pub type CertServiceT<C> =
    CertService<axiam_db::SurrealCaCertificateRepository<C>, SurrealCertificateRepository<C>>;

pub type PgpServiceT<C> = PgpService<axiam_db::SurrealPgpKeyRepository<C>>;

pub type DeviceAuthServiceT<C> =
    DeviceAuthService<SurrealCertificateRepository<C>, axiam_db::SurrealCaCertificateRepository<C>>;

pub type WebhookDeliveryServiceT<C> = WebhookDeliveryService<SurrealWebhookRepository<C>>;

pub type AuthorizeServiceT<C> =
    AuthorizeService<SurrealOAuth2ClientRepository<C>, SurrealAuthorizationCodeRepository<C>>;

pub type TokenServiceT<C> = TokenService<
    SurrealOAuth2ClientRepository<C>,
    SurrealAuthorizationCodeRepository<C>,
    SurrealTenantRepository<C>,
    SurrealRefreshTokenRepository<C>,
    SurrealUserRepository<C>,
>;

pub type PasswordResetServiceT<C> = PasswordResetService<
    SurrealUserRepository<C>,
    axiam_db::SurrealPasswordResetTokenRepository<C>,
    SurrealFederationLinkRepository<C>,
    SurrealPasswordHistoryRepository<C>,
    SurrealSessionRepository<C>,
    SurrealRefreshTokenRepository<C>,
>;

pub type EmailVerificationServiceT<C> = EmailVerificationService<
    SurrealUserRepository<C>,
    axiam_db::SurrealEmailVerificationTokenRepository<C>,
    SurrealFederationLinkRepository<C>,
>;

pub type OidcFederationServiceT<C> = OidcFederationService<
    SurrealFederationConfigRepository<C>,
    SurrealFederationLinkRepository<C>,
    SurrealUserRepository<C>,
>;

#[cfg(feature = "saml")]
pub type SamlFederationServiceT<C> = SamlFederationService<
    SurrealFederationConfigRepository<C>,
    SurrealFederationLinkRepository<C>,
    SurrealUserRepository<C>,
    SurrealAssertionReplayRepository<C>,
>;

// ---------------------------------------------------------------------------
// AppState<C>
// ---------------------------------------------------------------------------

/// Single composition root for every REST handler dependency (QUAL-01).
///
/// Generic bound mirrors `server.rs::register_api_v1_routes<C>` exactly, so
/// the same `AppState<C>` instantiation backs both production
/// (`AppState<axiam_db::DbClient>`) and every test harness
/// (`AppState<surrealdb::engine::local::Db>`).
///
/// All fields are `pub` — this struct is an internal DI container, not a
/// public API surface with invariants to protect; tests need to override
/// individual fields (e.g. swap `authz_checker`... see note above: that one
/// stays outside `AppState`, but e.g. a test overriding `health_checker`)
/// after calling [`AppState::for_test`].
#[derive(Clone)]
pub struct AppState<C: Connection + Clone> {
    pub authz_config: AuthzConfig,
    pub auth_config: AuthConfig,
    pub db: Surreal<C>,
    pub health_checker: Arc<dyn HealthChecker>,
    pub audit_repo: SurrealAuditLogRepository<C>,
    pub org_repo: SurrealOrganizationRepository<C>,
    pub tenant_repo: SurrealTenantRepository<C>,
    pub user_repo: SurrealUserRepository<C>,
    pub group_repo: SurrealGroupRepository<C>,
    pub role_repo: SurrealRoleRepository<C>,
    pub permission_repo: SurrealPermissionRepository<C>,
    pub resource_repo: SurrealResourceRepository<C>,
    pub scope_repo: SurrealScopeRepository<C>,
    pub service_account_repo: SurrealServiceAccountRepository<C>,
    pub auth_service: AuthServiceT<C>,
    pub webauthn_service: WebauthnServiceT<C>,
    pub mfa_method_service: MfaMethodServiceT<C>,
    pub mail_outbound_publisher: Arc<dyn DynMailPublisher>,
    pub session_repo: SurrealSessionRepository<C>,
    pub session_validator: Arc<dyn SessionValidator>,
    pub refresh_token_repo: SurrealRefreshTokenRepository<C>,
    pub password_history_repo: SurrealPasswordHistoryRepository<C>,
    pub consent_repo: SurrealConsentRepository<C>,
    pub account_deletion_repo: SurrealAccountDeletionRepository<C>,
    pub export_job_repo: SurrealExportJobRepository<C>,
    pub erasure_proof_repo: SurrealErasureProofRepository<C>,
    /// D-17: AES-256-GCM key for email-provider secrets. Absent (`None`)
    /// means email-config admin endpoints and mail delivery stay disabled
    /// (fail-closed) — mirrors the pre-existing behavior exactly.
    pub email_encryption_key: Option<[u8; 32]>,
    pub ca_service: CaServiceT<C>,
    pub cert_service: CertServiceT<C>,
    pub cert_repo: SurrealCertificateRepository<C>,
    pub device_auth_service: DeviceAuthServiceT<C>,
    pub pgp_service: PgpServiceT<C>,
    pub webhook_repo: SurrealWebhookRepository<C>,
    pub webhook_delivery: WebhookDeliveryServiceT<C>,
    /// AMQP publisher used by [`AppState::emit_webhook`] to dispatch domain
    /// events onto the durable webhook queue (CQ-B22). `None` in tests and when
    /// AMQP is unavailable — `emit_webhook` becomes a no-op rather than failing
    /// the originating request (webhook delivery is a best-effort side effect).
    pub webhook_publisher: Option<Arc<axiam_amqp::WebhookPublisher>>,
    pub notification_rule_repo: SurrealNotificationRuleRepository<C>,
    pub oauth2_client_repo: SurrealOAuth2ClientRepository<C>,
    pub authorize_service: AuthorizeServiceT<C>,
    pub token_service: TokenServiceT<C>,
    pub settings_repo: SurrealSettingsRepository<C>,
    pub federation_config_repo: SurrealFederationConfigRepository<C>,
    pub federation_link_repo: SurrealFederationLinkRepository<C>,
    pub assertion_replay_repo: SurrealAssertionReplayRepository<C>,
    pub federation_login_state_repo: SurrealFederationLoginStateRepository<C>,
    pub http_client: reqwest::Client,
    pub jwks_cache: Arc<JwksCache>,
    pub crypto_semaphore: Arc<Semaphore>,
    /// D-02: `None` when `AXIAM__EMAIL_ENCRYPTION_KEY` is unset — the six
    /// email-config routes fail closed rather than silently using a
    /// constant/zero key.
    pub email_config_repo: Option<SurrealEmailConfigRepository<C>>,

    // -- QUAL-07: hoisted per-request service constructions (13 call sites) --
    pub password_reset_service: PasswordResetServiceT<C>,
    pub email_verification_service: EmailVerificationServiceT<C>,
    /// `None` when `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` is unset — the
    /// OIDC federation encryption key is baked into `OidcFederationService`
    /// at construction, so absence is resolved once at startup rather than
    /// per-request (identical fail-closed error at the 4 call sites).
    pub oidc_federation_service: Option<OidcFederationServiceT<C>>,
    /// Constructed unconditionally (SamlFederationService::new needs no
    /// encryption key) — but the FIELD itself stays `#[cfg(feature = "saml")]`
    /// gated. Why: `axiam_federation::saml` only exists when
    /// axiam-federation's OWN `saml` Cargo feature is on, and
    /// axiam-api-rest's `saml` feature intentionally forwards to it so
    /// `cargo build -p axiam-server --no-default-features` can still build
    /// without the `samael`/`libxml2` dependency chain (documented escape
    /// hatch for hosts with an incompatible system libxml2 — see
    /// `axiam-server/src/main.rs`'s `--dump-openapi` doc comment and
    /// `axiam-api-rest/Cargo.toml`). Un-gating this field would force
    /// `axiam-federation/saml` on unconditionally and break that hatch.
    #[cfg(feature = "saml")]
    pub saml_federation_service: SamlFederationServiceT<C>,
}

impl<C: Connection + Clone> AppState<C> {
    /// Dispatch a domain event to any webhooks subscribed to `event_type` in
    /// `tenant_id` (CQ-B22). Best-effort: if no AMQP publisher is wired
    /// (`webhook_publisher` is `None`, e.g. tests or AMQP disabled) this is a
    /// no-op, and publish failures inside `emit` are logged, never propagated —
    /// a webhook side effect must not fail the originating API request.
    pub async fn emit_webhook(
        &self,
        tenant_id: uuid::Uuid,
        event_type: &str,
        payload: serde_json::Value,
    ) {
        if let Some(publisher) = &self.webhook_publisher {
            self.webhook_delivery
                .emit(publisher, tenant_id, event_type.to_string(), payload)
                .await;
        }
    }

    /// Build a fully-populated `AppState<C>` for test harnesses from just a
    /// `db` handle and an `AuthConfig` — every field gets a working,
    /// connection-backed default (repos constructed via `::new(db.clone())`,
    /// services via their real constructors with a fresh crypto semaphore and
    /// no PKI/webhook/email encryption key configured).
    ///
    /// Fields all being `pub` means any test needing to exercise a
    /// non-default value (a real PKI encryption key, a mock
    /// `health_checker`, a `RecordingMailPublisher`, ...) can do so with a
    /// plain field-mutation after calling this:
    /// ```ignore
    /// let mut state = AppState::for_test(db.clone(), auth_config.clone());
    /// state.email_encryption_key = Some(TEST_KEY);
    /// ```
    pub fn for_test(db: Surreal<C>, auth_config: AuthConfig) -> Self {
        let crypto_semaphore = Arc::new(Semaphore::new(4));
        let pki_config = axiam_pki::PkiConfig {
            encryption_key: None,
        };

        let user_repo = SurrealUserRepository::new(db.clone());
        let session_repo = SurrealSessionRepository::new(db.clone());
        let federation_link_repo = SurrealFederationLinkRepository::new(db.clone());
        let refresh_token_repo = SurrealRefreshTokenRepository::new(db.clone());
        let webauthn_cred_repo = axiam_db::SurrealWebauthnCredentialRepository::new(db.clone());
        let cert_repo = SurrealCertificateRepository::new(db.clone());
        let ca_cert_repo = axiam_db::SurrealCaCertificateRepository::new(db.clone());
        let pgp_repo = axiam_db::SurrealPgpKeyRepository::new(db.clone());
        let webhook_repo = SurrealWebhookRepository::new(db.clone());
        let oauth2_client_repo = SurrealOAuth2ClientRepository::new(db.clone());
        let auth_code_repo = SurrealAuthorizationCodeRepository::new(db.clone());
        let tenant_repo = SurrealTenantRepository::new(db.clone());
        let password_history_repo = SurrealPasswordHistoryRepository::new(db.clone());
        let password_reset_token_repo =
            axiam_db::SurrealPasswordResetTokenRepository::new(db.clone());
        let email_verification_token_repo =
            axiam_db::SurrealEmailVerificationTokenRepository::new(db.clone());
        let federation_config_repo = SurrealFederationConfigRepository::new(db.clone());
        let assertion_replay_repo = SurrealAssertionReplayRepository::new(db.clone());

        let auth_service = AuthService::new(
            user_repo.clone(),
            session_repo.clone(),
            federation_link_repo.clone(),
            refresh_token_repo.clone(),
            auth_config.clone(),
            Arc::clone(&crypto_semaphore),
        );
        let webauthn_service =
            WebauthnService::new(webauthn_cred_repo.clone(), auth_config.clone())
                .expect("test WebauthnService construction");
        let mfa_method_service =
            MfaMethodService::new(user_repo.clone(), webauthn_cred_repo.clone());
        let ca_service = CaService::new(
            ca_cert_repo.clone(),
            pki_config.clone(),
            Arc::clone(&crypto_semaphore),
        );
        let cert_service = CertService::new(
            ca_cert_repo.clone(),
            cert_repo.clone(),
            pki_config.clone(),
            Arc::clone(&crypto_semaphore),
        );
        let pgp_service = PgpService::new(
            pgp_repo.clone(),
            pki_config.clone(),
            Arc::clone(&crypto_semaphore),
        );
        let device_auth_service = DeviceAuthService::new(cert_repo.clone(), ca_cert_repo.clone());
        let webhook_delivery = WebhookDeliveryService::new(webhook_repo.clone(), None);
        let authorize_service =
            AuthorizeService::new(oauth2_client_repo.clone(), auth_code_repo.clone(), 600);
        let token_service = TokenService::new(
            oauth2_client_repo.clone(),
            auth_code_repo.clone(),
            tenant_repo.clone(),
            refresh_token_repo.clone(),
            user_repo.clone(),
            auth_config.clone(),
            2_592_000,
        );
        let password_reset_service = PasswordResetService::new(
            user_repo.clone(),
            password_reset_token_repo,
            federation_link_repo.clone(),
            password_history_repo.clone(),
            session_repo.clone(),
            refresh_token_repo.clone(),
            Arc::clone(&crypto_semaphore),
        );
        let email_verification_service = EmailVerificationService::new(
            user_repo.clone(),
            email_verification_token_repo,
            federation_link_repo.clone(),
        );

        Self {
            authz_config: AuthzConfig::default(),
            auth_config,
            db: db.clone(),
            health_checker: Arc::new(crate::health::AlwaysHealthy),
            audit_repo: SurrealAuditLogRepository::new(db.clone()),
            org_repo: SurrealOrganizationRepository::new(db.clone()),
            tenant_repo,
            user_repo: user_repo.clone(),
            group_repo: SurrealGroupRepository::new(db.clone()),
            role_repo: SurrealRoleRepository::new(db.clone()),
            permission_repo: SurrealPermissionRepository::new(db.clone()),
            resource_repo: SurrealResourceRepository::new(db.clone()),
            scope_repo: SurrealScopeRepository::new(db.clone()),
            service_account_repo: SurrealServiceAccountRepository::new(db.clone()),
            auth_service,
            webauthn_service,
            mfa_method_service,
            mail_outbound_publisher: Arc::new(NoopMailPublisher),
            session_repo,
            session_validator: Arc::new(SurrealSessionRepository::new(db.clone())),
            refresh_token_repo,
            password_history_repo,
            consent_repo: axiam_db::SurrealConsentRepository::new(db.clone()),
            account_deletion_repo: SurrealAccountDeletionRepository::new(db.clone()),
            export_job_repo: SurrealExportJobRepository::new(db.clone()),
            erasure_proof_repo: SurrealErasureProofRepository::new(db.clone()),
            email_encryption_key: None,
            ca_service,
            cert_service,
            cert_repo,
            device_auth_service,
            pgp_service,
            webhook_repo,
            webhook_delivery,
            webhook_publisher: None,
            notification_rule_repo: SurrealNotificationRuleRepository::new(db.clone()),
            oauth2_client_repo,
            authorize_service,
            token_service,
            settings_repo: SurrealSettingsRepository::new(db.clone()),
            federation_config_repo: federation_config_repo.clone(),
            federation_link_repo: federation_link_repo.clone(),
            assertion_replay_repo: assertion_replay_repo.clone(),
            federation_login_state_repo: SurrealFederationLoginStateRepository::new(db.clone()),
            http_client: reqwest::Client::new(),
            jwks_cache: Arc::new(JwksCache::new()),
            crypto_semaphore,
            email_config_repo: None,
            password_reset_service,
            email_verification_service,
            oidc_federation_service: None,
            #[cfg(feature = "saml")]
            saml_federation_service: SamlFederationService::new(
                federation_config_repo,
                federation_link_repo,
                user_repo,
                assertion_replay_repo,
                reqwest::Client::new(),
            ),
        }
    }
}

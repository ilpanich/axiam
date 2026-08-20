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

pub mod bundles;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_auth::config::AuthConfig;
use axiam_auth::{
    AttestationCaCache, AuthService, EmailVerificationService, MfaMethodService,
    PasswordResetService, SrpServer, WebauthnService,
};
use axiam_authz::AuthzConfig;
use axiam_db::DbHandle;
use axiam_db::attestation_metadata_source::MdsAttestationMetadataSource;
use axiam_db::repository::SurrealPermissionTicketRepository;
use axiam_db::{
    SharedRateLimitCounter, SurrealAccountDeletionRepository, SurrealAssertionReplayRepository,
    SurrealAuditLogRepository, SurrealAuthorizationCodeRepository, SurrealCertificateRepository,
    SurrealConsentRepository, SurrealDeviceGrantRepository, SurrealEmailConfigRepository,
    SurrealErasureProofRepository, SurrealExportJobRepository, SurrealFederationConfigRepository,
    SurrealFederationLinkRepository, SurrealFederationLoginStateRepository, SurrealGroupRepository,
    SurrealMdsRepository, SurrealNotificationRuleRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository, SurrealPermissionRepository,
    SurrealProofReplayRepository, SurrealPushedAuthRequestRepository,
    SurrealRateLimitBucketRepository, SurrealReactorRepository, SurrealRefreshTokenRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScimTokenRepository,
    SurrealScopeRepository, SurrealServiceAccountRepository, SurrealSessionClientRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealSrpCredentialRepository,
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnAttestationPolicyRepository,
    SurrealWebauthnCredentialRepository, SurrealWebhookRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
#[cfg(feature = "saml")]
use axiam_federation::saml::SamlFederationService;
use axiam_oauth2::authorize::AuthorizeService;
use axiam_oauth2::device_service::DeviceAuthorizationService;
use axiam_oauth2::jwks_cache::{
    JwksCache as Oauth2JwksCache, JwksCacheConfig as Oauth2JwksCacheConfig,
};
use axiam_oauth2::par::ParService;
use axiam_oauth2::token::TokenService;
use axiam_oauth2::token_exchange::TokenExchangeService;
use axiam_pki::{CaService, CertService, DeviceAuthService, PgpService, PkiConfig};
use surrealdb::Connection;
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
    SurrealServiceAccountRepository<C>,
>;

/// B2 — the device-authorization grant's own service. Separate from
/// [`TokenServiceT`] on purpose: the device flow needs one repository nothing
/// else needs, and threading it through a service that already carries six
/// would change every construction site in the codebase to serve one grant.
/// The REST layer keeps the seam at a single `match` arm on `grant_type`.
pub type DeviceAuthorizationServiceT<C> = DeviceAuthorizationService<
    SurrealDeviceGrantRepository<C>,
    SurrealOAuth2ClientRepository<C>,
    SurrealTenantRepository<C>,
    SurrealRefreshTokenRepository<C>,
    SurrealUserRepository<C>,
>;

/// B3 — RFC 8693 token exchange. Needs only the tenant repository: the
/// exchanging client is authenticated by `TokenService::authenticate_client`
/// and handed in, so there is exactly one secret-verification path in the
/// codebase rather than two to keep correct.
pub type TokenExchangeServiceT<C> = TokenExchangeService<SurrealTenantRepository<C>>;

/// B5 — RFC 9126 pushed authorization requests. Two repositories: the client
/// registry (to validate `redirect_uri` at push time, while the client is
/// authenticated) and the pushed-request store.
pub type ParServiceT<C> =
    ParService<SurrealOAuth2ClientRepository<C>, SurrealPushedAuthRequestRepository<C>>;

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
///
/// # Shape (F3)
///
/// Twenty-nine fields that most of the crate reads — the tenant and user
/// repositories, the auth config, the session machinery — plus **seven
/// cohesive sub-states** for the forty-six that a single handler module each
/// reads. Before that split this struct had seventy-five fields and every
/// handler saw all of them.
///
/// The sub-states are a *field-grouping* change and nothing more: every type
/// is what it was and monomorphisation is what it was, so the authorization
/// hot path is untouched. See [`bundles`] for why boxing them behind trait
/// objects would have been the wrong fix.
#[derive(Clone)]
pub struct AppState<C: Connection + Clone> {
    pub authz_config: AuthzConfig,
    pub auth_config: AuthConfig,
    /// LIVE reference to the pooled SurrealDB connection (NOT a boot-time
    /// clone): handlers that query directly — `/api/v1/admin/bootstrap`, the
    /// tenant seeder — must follow a reconnect-loop handle swap just as the
    /// repositories do, or they permanently 401 after an eviction.
    pub db: DbHandle<C>,
    pub health_checker: Arc<dyn HealthChecker>,
    pub audit_repo: SurrealAuditLogRepository<C>,
    pub org_repo: SurrealOrganizationRepository<C>,
    pub tenant_repo: SurrealTenantRepository<C>,
    /// A2/J2: `tenant_id -> organization_id`, so the refresh rotation path
    /// stops paying a datastore round trip per request for one immutable
    /// field. See [`crate::tenant_org_cache`] for why caching this — and only
    /// this — is safe.
    pub tenant_org_cache: Arc<crate::tenant_org_cache::TenantOrgCache>,
    pub user_repo: SurrealUserRepository<C>,
    pub group_repo: SurrealGroupRepository<C>,
    pub role_repo: SurrealRoleRepository<C>,
    pub permission_repo: SurrealPermissionRepository<C>,
    pub resource_repo: SurrealResourceRepository<C>,
    pub scope_repo: SurrealScopeRepository<C>,
    /// SCIM provisioning tokens (`claude_dev/scim-provisioning-token-design.md`).
    /// Read on every `/scim/v2/*` request that presents a provisioning handle
    /// rather than a JWT, and written by the `/api/v1/scim-tokens` admin
    /// endpoints.
    pub scim_token_repo: SurrealScimTokenRepository<C>,
    pub service_account_repo: SurrealServiceAccountRepository<C>,
    pub auth_service: AuthServiceT<C>,
    pub mfa_method_service: MfaMethodServiceT<C>,
    pub session_repo: SurrealSessionRepository<C>,
    pub session_validator: Arc<dyn SessionValidator>,
    pub refresh_token_repo: SurrealRefreshTokenRepository<C>,
    pub password_history_repo: SurrealPasswordHistoryRepository<C>,
    pub oauth2_client_repo: SurrealOAuth2ClientRepository<C>,
    pub settings_repo: SurrealSettingsRepository<C>,
    /// Stored SRP verifiers. Read by `/auth/srp/challenge` and written by
    /// every path that legitimately holds a plaintext password.
    pub srp_credential_repo: SurrealSrpCredentialRepository<C>,
    /// The SRP-6a engine, present only when `AXIAM__AUTH__SRP_SESSION_KEY` is
    /// configured. `None` makes the SRP endpoints answer `503` regardless of
    /// policy — see [`axiam_auth::AuthConfig::srp_session_key`] for why that is
    /// preferable to falling back to password login.
    pub srp_server: Option<SrpServer>,
    pub http_client: reqwest::Client,
    /// Federation JWKS cache: caches REMOTE identity providers' JWKS
    /// documents fetched during OIDC federation login. NOT related to
    /// `oauth2_jwks_cache` below -- see `axiam_oauth2::jwks_cache` module
    /// docs for the distinction.
    pub jwks_cache: Arc<JwksCache>,
    pub crypto_semaphore: Arc<Semaphore>,
    /// Process-wide write-behind shared rate-limit counter used by
    /// [`crate::middleware::rate_limit_shared::RateLimitShared`]
    /// (SECHRD-03 / D-01a; H2 performance fix).
    ///
    /// **MUST be one instance per process**, cloned (not rebuilt) into every
    /// actix worker: the counter accumulates each replica's unflushed
    /// increments in process memory, so N per-worker instances would fragment
    /// the local count and weaken the effective limit by up to N×. Living in
    /// `AppState` — registered exactly once as `web::Data<AppState<C>>` in
    /// `main.rs` — is what guarantees that; the `Clone` here is the cheap
    /// `Arc` clone, not a new counter.
    ///
    /// Absence of the whole `AppState` (a misconfigured harness) makes the
    /// middleware fail open, exactly as a missing DB handle did before.
    pub shared_rate_limit: SharedRateLimitCounter,
    /// B3: the token endpoint serves every grant behind one route, so a
    /// per-grant limit cannot be route middleware — the grant is not knowable
    /// until the body has been read. The exchange arm reads its ceiling from
    /// here instead.
    pub rate_limit_cfg: crate::config::rate_limit::RateLimitConfig,

    // ---------------------------------------------------------------
    // Cohesive sub-states (F3) — see `state/bundles.rs`
    // ---------------------------------------------------------------
    /// Certificate authority, X.509 issuance, PGP and device certificate auth.
    ///
    /// See [`bundles::PkiState`].
    pub pki: bundles::PkiState<C>,
    /// WebAuthn ceremonies, attestation policy and FIDO MDS metadata.
    ///
    /// See [`bundles::WebauthnState`].
    pub webauthn: bundles::WebauthnState<C>,
    /// Consent records, account deletion, data export and erasure proofs.
    ///
    /// See [`bundles::GdprState`].
    pub gdpr: bundles::GdprState<C>,
    /// Outbound mail, provider configuration and the two token-mail services.
    ///
    /// See [`bundles::MailState`].
    pub mail: bundles::MailState<C>,
    /// Reactors, webhooks and notification rules — everything AXIAM emits outward.
    ///
    /// See [`bundles::EventsState`].
    pub events: bundles::EventsState<C>,
    /// The OAuth2 authorization server and OIDC provider.
    ///
    /// See [`bundles::OAuth2State`].
    pub oauth2: bundles::OAuth2State<C>,
    /// Inbound SAML and OIDC federation.
    ///
    /// See [`bundles::FederationState`].
    pub federation: bundles::FederationState<C>,
}

impl<C: Connection + Clone> AppState<C> {
    /// Switch on X4's external token-exchange path.
    ///
    /// A method on the assembled state rather than a constructor parameter,
    /// because the collaborator it needs — the OIDC federation service — is
    /// itself conditional on `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` and is
    /// installed after this state is built.
    ///
    /// **No federation service ⇒ no external path**, and that is the correct
    /// coupling rather than an accident of ordering: without the encryption
    /// key there is no way to read a provider's configuration, so there is
    /// nothing to trust an external issuer *with*. Returns whether it was
    /// enabled, so a caller can log the posture instead of guessing at it.
    #[must_use = "the return value says whether the external path is actually live"]
    pub fn enable_external_token_exchange(&mut self) -> bool {
        let Some(federation) = self.federation.oidc_federation_service.clone() else {
            return false;
        };
        let (resolver, authority) = crate::token_exchange::external_collaborators(
            federation,
            self.role_repo.clone(),
            self.permission_repo.clone(),
        );
        // `with_external_subjects` consumes and returns, so the field is
        // rebuilt rather than mutated in place — the service is a handful of
        // cheap handles, so this costs nothing and keeps the "both or
        // neither" pairing enforced by the type.
        self.oauth2.token_exchange_service = self
            .oauth2
            .token_exchange_service
            .clone()
            .with_external_subjects(resolver, authority);
        true
    }

    /// Assemble the X2 UMA service for one request.
    ///
    /// Built per call rather than stored, because it needs the
    /// [`crate::authz::AuthzChecker`] — which arrives as its own `web::Data`
    /// so that deployments can swap the checker without rebuilding this state.
    /// The three parts it composes are all cheap handles (two repository
    /// structs wrapping a cloned connection, and an `Arc`), so this is a
    /// handful of refcount bumps, not a connection or a query.
    pub fn uma_service(
        &self,
        authz: std::sync::Arc<dyn crate::authz::AuthzChecker>,
    ) -> axiam_oauth2::uma::UmaService<
        SurrealPermissionTicketRepository<C>,
        crate::uma::EngineEvaluator,
        crate::uma::ResourceScopeCatalog<SurrealScopeRepository<C>>,
    > {
        axiam_oauth2::uma::UmaService::new(
            self.oauth2.permission_ticket_repo.clone(),
            crate::uma::EngineEvaluator::new(authz),
            crate::uma::ResourceScopeCatalog::new(self.scope_repo.clone()),
            self.oauth2.rpt_max_lifetime_secs,
        )
    }

    /// X1 — tell the reactor gate that this tenant's registrations changed.
    ///
    /// A no-op when no gate is composed (AMQP off, or a test harness), which is
    /// the same shape [`Self::emit_webhook`] uses and for the same reason: a
    /// side effect of an administrative write must not fail the write, and a
    /// handler must not have to know whether the subsystem is configured.
    ///
    /// This is an **optimisation on top of the TTL, not a replacement for it**.
    /// It only reaches the replica that served the mutation; every other
    /// replica picks the change up when its own routing entry expires, which is
    /// the bound the acceptance test asserts.
    pub fn invalidate_reactor_routing(&self, tenant_id: uuid::Uuid) {
        if let Some(invalidate) = &self.events.reactor_routing_invalidator {
            invalidate(tenant_id);
        }
    }

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
        if let Some(publisher) = &self.events.webhook_publisher {
            self.events
                .webhook_delivery
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
    pub fn for_test(db: impl Into<DbHandle<C>>, auth_config: AuthConfig) -> Self {
        let db: DbHandle<C> = db.into();
        // `Option<[u8; 32]>` is `Copy`, so read it out before `auth_config` is
        // moved into the struct literal below.
        let srp_session_key = auth_config.srp_session_key;
        // B1: resolve the hash-gate permit count from config (0 = auto → min(cores, 4)).
        let crypto_semaphore =
            Arc::new(Semaphore::new(auth_config.resolved_max_concurrent_hashes()));
        let pki_config = axiam_pki::PkiConfig {
            encryption_key: None,
            ..Default::default()
        };

        let user_repo = SurrealUserRepository::new(db.clone());
        let session_repo = SurrealSessionRepository::new(db.clone());
        let federation_link_repo = SurrealFederationLinkRepository::new(db.clone());
        let refresh_token_repo = SurrealRefreshTokenRepository::new(db.clone());
        let webauthn_cred_repo = axiam_db::SurrealWebauthnCredentialRepository::new(db.clone());
        let webauthn_attestation_policy_repo =
            SurrealWebauthnAttestationPolicyRepository::new(db.clone());
        let mds_repo = SurrealMdsRepository::new(db.clone());
        let attestation_metadata_source = MdsAttestationMetadataSource::new(mds_repo.clone());
        let cert_repo = SurrealCertificateRepository::new(db.clone());
        let ca_cert_repo = axiam_db::SurrealCaCertificateRepository::new(db.clone());
        let pgp_repo = axiam_db::SurrealPgpKeyRepository::new(db.clone());
        let reactor_repo = SurrealReactorRepository::new(db.clone());
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
        let proof_replay_repo = SurrealProofReplayRepository::new(db.clone());

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
        let service_account_repo = SurrealServiceAccountRepository::new(db.clone());
        let webhook_delivery = WebhookDeliveryService::new(webhook_repo.clone(), None);
        let authorize_service =
            AuthorizeService::new(oauth2_client_repo.clone(), auth_code_repo.clone(), 600);
        let token_service = TokenService::new(
            oauth2_client_repo.clone(),
            service_account_repo.clone(),
            auth_code_repo.clone(),
            tenant_repo.clone(),
            refresh_token_repo.clone(),
            user_repo.clone(),
            auth_config.clone(),
            2_592_000,
        );
        // B2: the URI the user is told to visit. Derived from the OIDC issuer
        // rather than configured separately — a verification URI on a
        // different origin from the issuer is a phishing shape, and deriving
        // it means the two cannot drift.
        let device_grant_repo = SurrealDeviceGrantRepository::new(db.clone());
        let verification_uri = format!(
            "{}/device",
            auth_config.oauth2_issuer_url.trim_end_matches('/')
        );
        let session_client_repo = SurrealSessionClientRepository::new(db.clone());
        let par_service = ParService::new(
            oauth2_client_repo.clone(),
            SurrealPushedAuthRequestRepository::new(db.clone()),
        );
        let device_authorization_service = DeviceAuthorizationService::new(
            device_grant_repo.clone(),
            oauth2_client_repo.clone(),
            tenant_repo.clone(),
            refresh_token_repo.clone(),
            user_repo.clone(),
            auth_config.clone(),
            2_592_000,
            verification_uri,
        );
        // B3: the exchanged-token ceiling. The ordinary access-token lifetime
        // is the right default — an exchange is a narrowing, so it has no
        // business producing something longer-lived than a normal token — and
        // it is applied on top of "never outlives its subject", not instead
        // of it.
        let token_exchange_service = TokenExchangeService::new(
            tenant_repo.clone(),
            auth_config.clone(),
            auth_config.access_token_lifetime_secs as i64,
        );
        let password_reset_service = PasswordResetService::new(
            user_repo.clone(),
            password_reset_token_repo,
            federation_link_repo.clone(),
            password_history_repo.clone(),
            session_repo.clone(),
            refresh_token_repo.clone(),
            Arc::clone(&crypto_semaphore),
            auth_config.hash_acquire_timeout_secs,
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
            tenant_org_cache: Arc::new(Default::default()),
            user_repo: user_repo.clone(),
            group_repo: SurrealGroupRepository::new(db.clone()),
            role_repo: SurrealRoleRepository::new(db.clone()),
            permission_repo: SurrealPermissionRepository::new(db.clone()),
            resource_repo: SurrealResourceRepository::new(db.clone()),
            scope_repo: SurrealScopeRepository::new(db.clone()),
            scim_token_repo: SurrealScimTokenRepository::new(db.clone()),
            service_account_repo: service_account_repo.clone(),
            auth_service,
            mfa_method_service,
            session_repo,
            session_validator: Arc::new(SurrealSessionRepository::new(db.clone())),
            refresh_token_repo,
            password_history_repo,
            oauth2_client_repo,
            settings_repo: SurrealSettingsRepository::new(db.clone()),
            srp_credential_repo: SurrealSrpCredentialRepository::new(db.clone()),
            srp_server: srp_session_key.map(SrpServer::new),
            http_client: reqwest::Client::new(),
            jwks_cache: Arc::new(JwksCache::new()),
            crypto_semaphore,
            // Tests get a real, env-configured counter over the same
            // in-memory DB, so the shared-store layer behaves in tests
            // exactly as it does in production. A test that wants
            // deterministic convergence can replace this field with
            // `SharedRateLimitCounter::without_flusher(..)` and drive
            // `flush_once()` itself.
            rate_limit_cfg: crate::config::rate_limit::RateLimitConfig::default(),
            shared_rate_limit: SharedRateLimitCounter::from_env(Arc::new(
                SurrealRateLimitBucketRepository::new(db.clone()),
            )),
            pki: bundles::PkiState {
                ca_service,
                cert_service,
                cert_repo,
                pgp_service,
                device_auth_service,
            },
            webauthn: bundles::WebauthnState {
                webauthn_service,
                webauthn_credential_repo: webauthn_cred_repo.clone(),
                webauthn_attestation_policy_repo,
                mds_repo,
                attestation_metadata_source,
                attestation_ca_cache: Arc::new(AttestationCaCache::new()),
                pki_config,
            },
            gdpr: bundles::GdprState {
                consent_repo: axiam_db::SurrealConsentRepository::new(db.clone()),
                account_deletion_repo: SurrealAccountDeletionRepository::new(db.clone()),
                export_job_repo: SurrealExportJobRepository::new(db.clone()),
                erasure_proof_repo: SurrealErasureProofRepository::new(db.clone()),
            },
            mail: bundles::MailState {
                mail_outbound_publisher: Arc::new(NoopMailPublisher),
                email_config_repo: None,
                email_encryption_key: None,
                email_verification_service,
                password_reset_service,
            },
            events: bundles::EventsState {
                reactor_repo,
                // A test harness gets the no-op gate, which is also what a
                // production deployment without AMQP gets — so a handler test
                // exercises exactly the composition an un-hooked deployment runs.
                // A test that needs a live gate overrides this field (the same
                // pattern `email_encryption_key` documents above).
                reactor_gate: axiam_core::models::reactor::noop_reactor_gate(),
                reactor_routing_invalidator: None,
                webhook_repo,
                webhook_delivery,
                webhook_publisher: None,
                notification_rule_repo: SurrealNotificationRuleRepository::new(db.clone()),
            },
            oauth2: bundles::OAuth2State {
                authorize_service,
                token_service,
                device_authorization_service,
                token_exchange_service,
                par_service,
                permission_ticket_repo: SurrealPermissionTicketRepository::new(db.clone()),
                // X2: the protocol default is the ceiling until an operator lowers
                // it. Raising it past `DEFAULT_RPT_MAX_LIFETIME_SECS` buys nothing
                // — the effective lifetime is a minimum over all three bounds.
                rpt_max_lifetime_secs: axiam_core::models::uma::DEFAULT_RPT_MAX_LIFETIME_SECS,
                session_client_repo,
                device_grant_repo,
                proof_replay_repo,
                oauth2_jwks_cache: Arc::new(Oauth2JwksCache::new()),
                oauth2_jwks_cache_config: Oauth2JwksCacheConfig::default(),
            },
            federation: bundles::FederationState {
                federation_config_repo: federation_config_repo.clone(),
                federation_link_repo: federation_link_repo.clone(),
                federation_login_state_repo: SurrealFederationLoginStateRepository::new(db.clone()),
                assertion_replay_repo: assertion_replay_repo.clone(),
                oidc_federation_service: None,
                #[cfg(feature = "saml")]
                saml_federation_service: SamlFederationService::new(
                    federation_config_repo,
                    federation_link_repo,
                    user_repo,
                    assertion_replay_repo,
                    reqwest::Client::new(),
                ),
            },
        }
    }
}

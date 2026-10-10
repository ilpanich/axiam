//! The composition root: everything `main` does after the secrets are resolved
//! and the datastore is migrated.
//!
//! [`serve`] lives in the library, and is generic over the datastore
//! connection, so that a test can compose the whole server — repositories,
//! services, the dispatcher, the REST and gRPC listeners — over the embedded
//! in-memory engine and drive it over HTTP, with no broker and no datastore
//! server (G-8, T23.8.1). `main` calls it with the HTTP engine.
//!
//! What `serve` takes is what a running server has by then: the resolved
//! [`AppConfig`] (secrets included, which is why they are fields rather than
//! reads from a provider here) and a migrated pool. Process-wide installs that
//! must happen exactly once — the tracing subscriber, the rustls provider, the
//! client-secret hasher — stay with the caller.

use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer, web};
use axiam_amqp::{
    AmqpConfig, AmqpManager, MailOutboundPublisher, OutboundDeliverers, OutboundRetryConfig,
};
use axiam_api_grpc::{GrpcConfig, start_grpc_server};
use axiam_api_rest::middleware::request_span::RedactingRootSpanBuilder;
use axiam_api_rest::middleware::security_headers::SecurityHeadersMiddleware;
use axiam_api_rest::state::AppState;
use axiam_api_rest::state::bundles;
use axiam_api_rest::{
    HealthChecker, RateLimitConfig, RouteOptions, ServerConfig, build_cors, health_routes,
    openapi_routes, register_api_v1_routes_with,
};
use axiam_audit::{AuditMiddleware, DEAD_LETTER_FILE_ENV, DeadLetterWriter};
use axiam_auth::config::AuthConfig;
use axiam_auth::{
    AttestationCaCache, AuthService, EmailVerificationService, MfaMethodService,
    PasswordResetService, WebauthnService,
};
use axiam_core::models::deployment::DeploymentProfile;
use axiam_core::outbound::OutboundKind;
use axiam_core::repository::ServiceAccountRepository;
use axiam_db::attestation_metadata_source::MdsAttestationMetadataSource;
use axiam_db::{
    DbConfig, SurrealAccountDeletionRepository, SurrealAmqpNonceRepository,
    SurrealAssertionReplayRepository, SurrealAuditLogRepository,
    SurrealAuthorizationCodeRepository, SurrealCaCertificateRepository,
    SurrealCertificateRepository, SurrealDeviceGrantRepository, SurrealEmailConfigRepository,
    SurrealEmailTemplateRepository, SurrealEmailVerificationTokenRepository,
    SurrealErasureProofRepository, SurrealExportJobRepository, SurrealFederationConfigRepository,
    SurrealFederationLinkRepository, SurrealFederationLoginStateRepository, SurrealGroupRepository,
    SurrealMdsRepository, SurrealNotificationRuleRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository,
    SurrealPasswordResetTokenRepository, SurrealPermissionRepository, SurrealPgpKeyRepository,
    SurrealProofReplayRepository, SurrealPushedAuthRequestRepository, SurrealReactorRepository,
    SurrealRefreshTokenRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScimTokenRepository, SurrealScopeRepository, SurrealServiceAccountRepository,
    SurrealSessionClientRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealSsoHandoffCodeRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebauthnAttestationPolicyRepository, SurrealWebauthnCredentialRepository,
    SurrealWebhookRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
#[cfg(feature = "saml")]
use axiam_federation::saml::SamlFederationService;
use axiam_oauth2::authorize::AuthorizeService;
use axiam_oauth2::device_service::DeviceAuthorizationService;
use axiam_oauth2::jwks_cache::JwksCache as Oauth2JwksCache;
use axiam_oauth2::par::ParService;
use axiam_oauth2::token::TokenService;
use axiam_oauth2::token_exchange::TokenExchangeService;
use axiam_pki::{CaService, CertService, DeviceAuthService, PgpService, PkiConfig};
use secrecy::ExposeSecret;
use serde::Deserialize;
use surrealdb::Connection;
use tracing_actix_web::TracingLogger;

use crate::cleanup;
use crate::messaging::{MailTransportPublisher, OutboundTransport};
use crate::profile::{self, LeaseTiming, OnLeaseLost};

/// Returns the default cleanup interval in seconds (5 minutes).
fn default_cleanup_interval_secs() -> u64 {
    300
}

/// Default audit retention, in days (T-119). Two years.
///
/// Chosen to be longer than the retention most compliance regimes ask of an
/// access-control audit trail, because the failure modes are asymmetric:
/// keeping records too long is a storage cost and a GDPR data-minimisation
/// argument, while discarding them too early destroys the evidence an incident
/// investigation runs on, irreversibly and silently. A deployment with a
/// shorter lawful basis should shorten it deliberately rather than inherit a
/// default that decided for them.
fn default_audit_retention_days() -> u64 {
    730
}

/// Top-level configuration aggregating all sub-configs.
/// `AXIAM__AUDIT__*` — what reaches the append-only log (T-110).
///
/// Its own struct rather than a flat `audit_minimise` field because the
/// config layer maps `AXIAM__AUDIT__MINIMISE` onto `audit.minimise`, and
/// `AXIAM__AUDIT_RETENTION_DAYS` (single underscore, T-119) is deliberately
/// left where it is — renaming a shipped variable to tidy a namespace is a
/// breaking change for every deployment that sets it.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct AuditCollectionConfig {
    /// See [`AppConfig::audit`].
    pub minimise: bool,
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub db: DbConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub grpc: GrpcConfig,
    #[serde(default)]
    pub authz: axiam_authz::AuthzConfig,
    /// B3: `GET /oauth2/jwks` HTTP caching config (currently just the
    /// `Cache-Control` max-age). Configured via `AXIAM__OAUTH2__*` env vars,
    /// e.g. `AXIAM__OAUTH2__JWKS_CACHE_MAX_AGE_SECS`.
    #[serde(default)]
    pub oauth2: axiam_oauth2::jwks_cache::JwksCacheConfig,
    #[serde(default)]
    pub amqp: AmqpConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    /// How often (in seconds) the background cleanup task sweeps expired rows.
    /// Configurable via `AXIAM__SERVER__CLEANUP_INTERVAL_SECS`. Bounded to
    /// `60..=3600` at startup (T-04-35).
    #[serde(default = "default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
    /// How long audit entries are kept, in days (T-119).
    ///
    /// `AXIAM__AUDIT_RETENTION_DAYS`. `0` disables pruning entirely and
    /// restores the previous unbounded-growth behaviour — an explicit opt-out
    /// for deployments that archive out-of-band, not an accident you can fall
    /// into, since the default is [`default_audit_retention_days`].
    #[serde(default = "default_audit_retention_days")]
    pub audit_retention_days: u64,
    /// Whether this deployment minimises what it collects into the audit log
    /// (T-110).
    ///
    /// `AXIAM__AUDIT__MINIMISE`. `false` — today's behaviour — by default,
    /// because turning it on reduces forensic precision and that is a
    /// lawful-basis judgement a deployment must make deliberately rather than
    /// inherit. Deployment-wide and deliberately not per tenant: audit is an
    /// accountability control the deployment relies on *including against a
    /// tenant administrator*, and a tenant-level switch would let a tenant
    /// weaken the evidence used to investigate that tenant.
    ///
    /// Both states are logged at startup, exactly as retention is.
    #[serde(default)]
    pub audit: AuditCollectionConfig,
    /// AES-256-GCM key (32 bytes) for encrypting email provider secrets at rest
    /// (D-17). Loaded from `AXIAM__AUTH__EMAIL_ENCRYPTION_KEY` (hex-encoded, 64 chars).
    /// Skipped by serde — populated manually from env at startup.
    #[serde(skip)]
    pub email_encryption_key: Option<[u8; 32]>,
    /// AES-256-GCM key (32 bytes) for encrypting each tenant's directory (LDAP /
    /// Active Directory) bind secret at rest (G-3, D-15). Fetched from the
    /// secret provider as `directory_encryption_key`
    /// (`AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY` under the default provider).
    ///
    /// **Optional, and never a reason to refuse boot**: absent, the directory
    /// feature is unavailable — saving a directory configuration is refused
    /// with an error naming the key — and everything else is unaffected.
    /// Skipped by serde — populated from the secret provider at startup.
    #[serde(skip)]
    pub directory_encryption_key: Option<[u8; 32]>,
    /// The SAML IdP's pairwise-identifier key (32 bytes, D-22), from the secret
    /// provider as `saml_pairwise_key` (`AXIAM__AUTH__SAML_PAIRWISE_KEY` under
    /// the default provider).
    ///
    /// **Optional, never a reason to refuse boot, and must never rotate**:
    /// absent, a sign-on to a service provider whose `NameID` is the persistent
    /// pairwise identifier is answered `Responder` (an `emailAddress` SP still
    /// works); rotated or lost, every user becomes a new, unknown account at
    /// every such SP. Skipped by serde — populated from the secret provider.
    #[serde(skip)]
    pub saml_pairwise_key: Option<[u8; 32]>,
    /// HMAC-SHA256 pepper (32 bytes) for GDPR audit pseudonymization (D-02).
    /// Loaded from `AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER` (hex-encoded, 64 chars).
    /// Skipped by serde — populated manually from env at startup.
    #[serde(skip)]
    pub gdpr_pseudonym_pepper: Option<[u8; 32]>,
    /// AES-256-GCM key (32 bytes) shared by the PKI custodian, webhook secrets,
    /// SSF push credentials, SCIM targets and CIBA notification credentials
    /// (`pki_encryption_key` from the secret provider). Skipped by serde —
    /// populated from the secret provider at startup, so `serve` takes its
    /// secrets from the configuration it is handed rather than from a provider.
    #[serde(skip)]
    pub pki_encryption_key: Option<[u8; 32]>,
}

/// The one LDAP client every directory path shares (G-3), with the
/// deployment's connector guards (T23.3.7, D-19, D-32):
///
/// * the **address policy** — loopback, link-local (the metadata service),
///   unspecified, multicast and special-purpose addresses are always refused,
///   private ranges only inside `AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS`,
///   and this host's addresses on AXIAM's own REST and gRPC ports never — applied
///   to every directory connection, with the resolved address pinned;
/// * the **frame cap** on every LDAP message a directory sends
///   (`AXIAM__DIRECTORY__MAX_MESSAGE_BYTES`, default 2 MiB).
///
/// Both are deployment configuration a tenant administrator cannot change, and
/// both are logged here, once, at startup.
pub fn directory_client(config: &AppConfig) -> Arc<axiam_directory::DirectoryClient> {
    use axiam_directory::address::{ALLOWED_PRIVATE_NETWORKS_ENV, parse_allowed_networks};
    use axiam_directory::frame::{MAX_MESSAGE_BYTES_ENV, max_message_bytes_from};

    let raw_networks = std::env::var(ALLOWED_PRIVATE_NETWORKS_ENV).unwrap_or_default();
    let (networks, rejected) = parse_allowed_networks(&raw_networks);
    if !rejected.is_empty() {
        // A typo admits nothing (fail closed), but it must not pass silently.
        tracing::error!(
            setting = ALLOWED_PRIVATE_NETWORKS_ENV,
            rejected = %rejected.join(","),
            "directory allow-list entries that are not CIDR blocks or addresses were ignored"
        );
    }
    if networks.is_empty() {
        tracing::info!(
            "directory address guard: no private network admitted ({} unset) — a tenant's \
             directory must resolve to a globally routable address",
            ALLOWED_PRIVATE_NETWORKS_ENV
        );
    } else {
        tracing::warn!(
            networks = %networks.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
            "directory address guard: tenant directories may resolve into these private \
             networks ({}); loopback, link-local, metadata and AXIAM's own listeners stay \
             refused",
            ALLOWED_PRIVATE_NETWORKS_ENV
        );
    }
    let policy = axiam_directory::AddressPolicy::new()
        .with_allowed_private_networks(networks)
        .with_listener_ports([config.server.port, config.grpc.port]);

    let (max_message_bytes, adjusted) =
        max_message_bytes_from(std::env::var(MAX_MESSAGE_BYTES_ENV).ok().as_deref());
    if adjusted {
        tracing::warn!(
            setting = MAX_MESSAGE_BYTES_ENV,
            effective = max_message_bytes,
            "directory frame cap: the configured value was not usable or out of range; \
             using the effective value"
        );
    }
    tracing::info!(
        max_message_bytes,
        "directory frame guard: LDAP messages from a directory above this size end the connection"
    );

    Arc::new(
        axiam_directory::DirectoryClient::new(axiam_directory::ClientLimits::default())
            .with_address_policy(Arc::new(policy))
            .with_max_message_bytes(max_message_bytes),
    )
}

impl Default for AppConfig {
    /// The configuration of a server with nothing set: every section at its
    /// default, no secret. What `serde(default)` gives each field, so an
    /// embedding caller (a test) builds on it and fills in what it needs.
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            db: DbConfig::default(),
            auth: AuthConfig::default(),
            grpc: GrpcConfig::default(),
            authz: axiam_authz::AuthzConfig::default(),
            oauth2: axiam_oauth2::jwks_cache::JwksCacheConfig::default(),
            amqp: AmqpConfig::default(),
            rate_limit: RateLimitConfig::default(),
            cleanup_interval_secs: default_cleanup_interval_secs(),
            audit_retention_days: default_audit_retention_days(),
            audit: AuditCollectionConfig::default(),
            email_encryption_key: None,
            directory_encryption_key: None,
            saml_pairwise_key: None,
            gdpr_pseudonym_pepper: None,
            pki_encryption_key: None,
        }
    }
}

/// How [`serve`] is embedded, beyond the configuration. The default is what
/// `main` uses.
pub struct ServeOptions {
    /// A REST listener the caller already bound. `None` binds
    /// `server.host:server.port` (or serves TLS, when `server.tls` is enabled,
    /// which always binds its own).
    pub rest_listener: Option<std::net::TcpListener>,
    /// The timing of the minimal profile's singleton lease.
    pub lease_timing: LeaseTiming,
    /// The minimal profile's **backstop** for a lost lease. An instance whose
    /// lease another instance takes over stops in order — the REST listener
    /// stops accepting, the audit queue is drained, the cleanup task finishes —
    /// and [`serve`] returns an error, so `main` exits non-zero (T23.8.2,
    /// P23W5-A1). This runs only if that has not finished within
    /// [`LeaseTiming::lost_stop_deadline`]; production exits the process.
    pub lease_lost_backstop: OnLeaseLost,
    /// **Test seam, never set in production.** Lets the webhook and SSF push
    /// deliverers reach a loopback `http://` receiver (their own
    /// `admitting_private_networks_for_tests`), so a test can watch a delivery
    /// arrive. Everything else — the SSRF guard on every other fetch — is
    /// untouched.
    #[doc(hidden)]
    pub admit_private_networks_for_tests: bool,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            rest_listener: None,
            lease_timing: LeaseTiming::PRODUCTION,
            lease_lost_backstop: profile::exit_on_lease_lost(),
            admit_private_networks_for_tests: false,
        }
    }
}

/// Compose and run the server until the REST listener stops.
///
/// Everything `main` does after secrets are resolved and the datastore is
/// migrated: the minimal profile's boot guards (when `amqp.enabled` is false),
/// the broker connection (when it is true), every repository and service, the
/// dispatcher and its consumers, the gRPC listener, the cleanup scheduler and
/// the REST listener.
pub async fn serve<C>(
    mut config: AppConfig,
    pool: Arc<axiam_db::DbPool<C>>,
    health_checker: Arc<dyn HealthChecker>,
    mut opts: ServeOptions,
) -> std::io::Result<()>
where
    C: Connection + Clone + 'static,
{
    let audit_minimisation =
        axiam_core::audit_minimisation::AuditMinimisation::new(config.audit.minimise);
    // The messaging profile (G-8, D-59). `AXIAM__AMQP__ENABLED=false` composes
    // the minimal profile: no connection, no topology, and nothing below that
    // needs the broker is started — the four outbound kinds and transactional
    // mail run on in-process queues instead. Chosen once, here.
    let deployment_profile = if config.amqp.enabled {
        DeploymentProfile::Full
    } else {
        DeploymentProfile::Minimal
    };
    let instance_id = uuid::Uuid::new_v4();

    // The minimal profile's boot guards: broadcast off, no enabled reactor
    // registration, and the singleton lease that proves this is the only
    // instance. Each refusal names the profile and the fix.
    //
    // Losing the lease later raises `lease_lost`; the REST listener's run below
    // waits on it and stops in order (T23.8.2, P23W5-A1).
    let (lease_lost_tx, lease_lost) = tokio::sync::watch::channel(false);
    let lease_renewal = if deployment_profile.is_minimal() {
        let guards = profile::enforce_minimal_profile(
            config.authz.decision_cache_broadcast_enabled,
            &SurrealReactorRepository::new(pool.handle_for_repo()),
            axiam_db::SurrealMinimalProfileLeaseRepository::new(pool.handle_for_repo()),
            &instance_id.to_string(),
            opts.lease_timing,
            profile::signal_on_lease_lost(lease_lost_tx),
        )
        .await;
        match guards {
            Ok(handle) => Some(handle),
            Err(refusal) => {
                tracing::error!(%refusal, "the minimal profile refuses to start");
                return Err(std::io::Error::other(refusal.to_string()));
            }
        }
    } else {
        None
    };

    // Connect to RabbitMQ and declare queues.
    // Shared behind an Arc so background consumers can hold a handle and
    // recreate their channel on a transient broker blip (CQ-B53) instead of
    // taking the whole process down.
    let amqp: Option<Arc<AmqpManager>> = if config.amqp.enabled {
        let amqp = Arc::new(
            AmqpManager::connect_with_retry(&config.amqp)
                .await
                .expect("Failed to connect to RabbitMQ"),
        );
        amqp.declare_queues()
            .await
            .expect("Failed to declare AMQP queues");
        // CORR-03/D-06/D-07: primary/retry/DLQ webhook delivery topology (26-03).
        amqp.declare_webhook_topology()
            .await
            .expect("Failed to declare webhook AMQP topology");
        // G-5 / T23.5.3: the SSF push kind of the shared dispatcher (D-36) gets its
        // own sibling queues (`axiam.ssf_push`, `.retry`, `.dlq`); declaring them
        // changes nothing for the webhook queues above.
        amqp.declare_outbound_topology(OutboundKind::SsfPush)
            .await
            .expect("Failed to declare SSF push AMQP topology");
        // G-6 / T23.6.2: the outbound SCIM kind (D-57) — `axiam.scim_push`,
        // `.retry`, `.dlq` (the DLQ with the seven-day TTL: it holds user ids).
        amqp.declare_outbound_topology(OutboundKind::ScimPush)
            .await
            .expect("Failed to declare SCIM push AMQP topology");
        // G-7 / T23.7.2: the CIBA ping kind (D-65) — `axiam.ciba_ping`, `.retry`,
        // `.dlq` (the DLQ with the seven-day TTL: a record id names a person's
        // sign-in attempt).
        amqp.declare_outbound_topology(OutboundKind::CibaPing)
            .await
            .expect("Failed to declare CIBA ping AMQP topology");
        tracing::info!("RabbitMQ connected and queues declared");
        Some(amqp)
    } else {
        tracing::warn!(
            "AXIAM__AMQP__ENABLED=false — minimal profile: no broker connection. Webhooks, \
             SSF push, outbound SCIM, CIBA ping and transactional mail run on in-process \
             queues that are LOST ON RESTART; reactors, asynchronous authorization over AMQP, \
             external audit ingestion and cross-replica cache invalidation are unavailable. \
             This instance must be the only one."
        );
        None
    };
    // The transport of the four outbound kinds, chosen with the profile.
    let mut outbound = match &amqp {
        Some(amqp) => OutboundTransport::amqp(Arc::clone(amqp)),
        None => OutboundTransport::in_process(),
    };

    // LIVE pooled-connection reference — registered in `AppState` so handlers
    // that need direct access (e.g. /api/v1/admin/bootstrap) resolve the
    // CURRENT connection per query and therefore follow a reconnect-loop
    // handle swap, exactly as the repositories do.
    let db_handle = pool.handle_for_repo();
    let org_repo = SurrealOrganizationRepository::new(pool.handle_for_repo());
    let tenant_repo = SurrealTenantRepository::new(pool.handle_for_repo());
    // G-6 / T23.6.2 (D-57): the one provisioning event source. Every repository
    // that can write a provisioned field (users, groups and their memberships,
    // the GDPR deletion request's status write) reports to this handle after its
    // write committed. It is bound to the SCIM provisioner below, once the
    // dispatcher's publisher exists (it needs the broker); until then it is
    // inactive and the repositories issue the queries they always did.
    let provisioning_sink: Arc<
        axiam_core::models::ssf::Late<dyn axiam_core::provisioning::ProvisioningSink>,
    > = Arc::default();
    let user_repo = SurrealUserRepository::with_pepper(
        pool.handle_for_repo(),
        config
            .auth
            .pepper
            .as_ref()
            .map(|p| p.expose_secret().to_string())
            .unwrap_or_default(),
    )
    .with_provisioning_sink(provisioning_sink.clone());
    let group_repo = SurrealGroupRepository::new(pool.handle_for_repo())
        .with_provisioning_sink(provisioning_sink.clone());
    let role_repo = SurrealRoleRepository::new(pool.handle_for_repo());
    let permission_repo = SurrealPermissionRepository::new(pool.handle_for_repo());
    let resource_repo = SurrealResourceRepository::new(pool.handle_for_repo());
    let scope_repo = SurrealScopeRepository::new(pool.handle_for_repo());
    let scim_token_repo = SurrealScimTokenRepository::new(pool.handle_for_repo());
    let service_account_repo = SurrealServiceAccountRepository::new(pool.handle_for_repo());

    // §15.2 / §16.6 — legacy service-account secret hashes.
    //
    // `upgrade_client_secret_hash` only fires on a successful verification.
    // Service accounts can now authenticate (OAuth2 client-credentials accepts
    // an `sa_…` client id), so legacy rows migrate on first use just like
    // `oauth2_client` rows. What migration still cannot reach is a service
    // account that never authenticates — and its backlog is what decides
    // whether the legacy hash arm can be retired. Surfacing the count at
    // startup makes that answerable.
    match service_account_repo.count_legacy_secret_hashes(None).await {
        Ok(0) => {
            tracing::debug!("All service-account client secrets use the current hash scheme");
        }
        Ok(n) => {
            tracing::warn!(
                legacy_rows = n,
                "{n} service account(s) still store a legacy-SCHEME client-secret hash. Each migrates automatically the first time it authenticates (OAuth2 client-credentials); one that never authenticates will not, so rotate it (POST /api/v1/service-accounts/{{id}}/rotate-secret). Until this reaches 0, the legacy hash arm cannot be retired. NOTE: this counts the hash SCHEME only — a row already in the current scheme but keyed to a superseded AXIAM__AUTH__PEPPER is not counted here, because the stored format is identical; pepper-era rows migrate on the same first authentication."
            );
        }
        Err(e) => {
            // Diagnostic only — never a reason to refuse to start.
            tracing::debug!(error = %e, "Could not count legacy service-account secret hashes");
        }
    }

    // T-39/T-143: the revocation feed. Resolved once, and the same value both
    // mounts the route and turns on the write side — two switches for one
    // feature is how a deployment ends up publishing an empty feed forever, or
    // writing rows nothing serves.
    let revocation_feed_ttl = config
        .auth
        .revocation_feed_enabled
        .then(|| chrono::Duration::seconds(config.auth.access_token_lifetime_secs as i64));
    let route_options = RouteOptions {
        revocation_feed_enabled: config.auth.revocation_feed_enabled,
        tenant_issuer_paths: config.auth.tenant_issuer_paths,
    };
    // T21.6 — one line at boot, because an operator who set the flag needs to
    // see the issuer form their MCP servers must name, and one who did not
    // needs to see that `?tenant_id=` is still the only selector.
    if config.auth.tenant_issuer_paths {
        tracing::info!(
            root_issuer = %config.auth.root_issuer(),
            "per-tenant path issuers are ON (AXIAM__AUTH__TENANT_ISSUER_PATHS=true) — \
             the issuer of tenant T is {{root}}/t/{{T}}, discovery is served at all three \
             RFC 8414 §3 and OIDC Discovery §4 forms, and one JWKS signs every tenant"
        );
    }
    if let Some(ttl) = revocation_feed_ttl {
        tracing::info!(
            ttl_secs = ttl.num_seconds(),
            "session revocation feed is ON (AXIAM__AUTH__REVOCATION_FEED_ENABLED=true) — \
             GET /oauth2/revocations publishes hashed session ids for one access-token \
             lifetime; an SDK guard that polls it rejects a revoked session within one \
             poll interval rather than one token lifetime"
        );
    } else {
        tracing::info!(
            "session revocation feed is OFF (AXIAM__AUTH__REVOCATION_FEED_ENABLED) — \
             GET /oauth2/revocations is not served and no revocation row is written; a \
             revoked session's access token stays verifiable locally until it expires"
        );
    }

    // G-5 / T23.5.3 (D-52): the session repository reports every revocation to a
    // sink that is bound to the SSF emitter once the emitter exists (it needs the
    // outbox, which needs the broker); until then it is inactive and the
    // repository issues the queries it always did. The directory sync's
    // deactivation reports through the second.
    let ssf_session_sink: Arc<
        axiam_core::models::ssf::Late<dyn axiam_core::models::ssf::SessionRevocationSink>,
    > = Arc::default();
    let ssf_account_sink: Arc<
        axiam_core::models::ssf::Late<dyn axiam_core::models::ssf::SsfSystemAccountSink>,
    > = Arc::default();
    let session_repo = SurrealSessionRepository::new(pool.handle_for_repo())
        .with_revocation_sink(ssf_session_sink.clone());
    let session_repo = match revocation_feed_ttl {
        Some(ttl) => session_repo.with_revocation_feed(ttl),
        None => session_repo,
    };
    // Built here, beside the writer, and only when the feed is on: the sweep
    // that prunes the table and the path that fills it are two halves of one
    // decision and must not be able to disagree about whether it was taken.
    let revoked_session_repo = revocation_feed_ttl.map(|_| {
        Arc::new(axiam_db::SurrealRevokedSessionRepository::new(
            pool.handle_for_repo(),
        ))
    });
    // I6: optional short-TTL session-validation cache. Opt-in via
    // `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` (0 = off, the default);
    // every session-deleting path in the repository invalidates it, so on a
    // single replica revocation stays immediate and the TTL only bounds
    // cross-replica staleness — the same contract as the D7 decision cache.
    let session_repo = match config.auth.session_validation_cache_ttl_secs {
        0 => {
            tracing::info!(
                "session-validation cache disabled (every authenticated request \
                 re-reads its session row); enable with \
                 AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS"
            );
            session_repo
        }
        ttl_secs => {
            let cache = Arc::new(axiam_db::SessionValidationCache::new(
                std::time::Duration::from_secs(ttl_secs),
            ));
            tracing::warn!(
                ttl_secs,
                "session-validation cache ENABLED (I6) — a session revoked on \
                 another replica may remain acceptable here for up to ttl_secs"
            );
            session_repo.with_validation_cache(cache)
        }
    };
    // REQ-7 / D-15: per-request session-validity check so revoked sessions'
    // access tokens are rejected immediately (the AuthenticatedUser extractor
    // consults this on every authenticated request).
    let session_validator: std::sync::Arc<dyn axiam_api_rest::SessionValidator> =
        std::sync::Arc::new(session_repo.clone());
    // Organization scope: resolves the tenant named in `X-Axiam-Tenant` so the
    // `AuthenticatedUser` extractor can decide whether this caller may act on
    // it. Registered as its own app_data for the same reason
    // `session_validator` is — the extractor's `FromRequest` impl is
    // non-generic and cannot name `AppState<C>`.
    //
    // Without it the extractor fails closed and *every* `X-Axiam-Tenant`
    // request is refused, which would leave an organization-level super-admin
    // unable to act on any tenant — the exact gap organization scope exists to
    // close. See `claude_dev/organization-scope-design.md`.
    let tenant_scope_resolver: std::sync::Arc<dyn axiam_api_rest::TenantScopeResolver> =
        std::sync::Arc::new(SurrealTenantRepository::new(pool.handle_for_repo()));
    // How far an organization-level principal's roles reach across the tenants
    // of its organization, so a switch to a tenant outside that reach is
    // refused once, at the header, instead of as a 403 on every page that
    // follows. Registered the same way and for the same reason as the resolver
    // above — see `axiam_api_rest::PrincipalReachResolver`, which also explains
    // why its absence degrades to "unrestricted" rather than failing closed.
    let principal_reach_resolver: std::sync::Arc<dyn axiam_api_rest::PrincipalReachResolver> =
        std::sync::Arc::new(axiam_db::SurrealRoleRepository::new(pool.handle_for_repo()));
    // SCIM provisioning tokens: resolves the long-lived handle an IdP presents
    // on /scim/v2 into the tenant user it is bound to. Registered as its own
    // app_data (rather than reached through AppState) for the same reason
    // `session_validator` is — `ScimPrincipal`'s FromRequest impl is
    // non-generic and cannot name `AppState<C>`.
    // See `claude_dev/scim-provisioning-token-design.md`.
    let scim_token_resolver: std::sync::Arc<dyn axiam_api_rest::ScimTokenResolver> =
        std::sync::Arc::new(axiam_api_rest::SurrealScimTokenResolver::new(
            scim_token_repo.clone(),
            axiam_db::SurrealUserRepository::new(pool.handle_for_repo()),
        ));
    let audit_repo = SurrealAuditLogRepository::new(pool.handle_for_repo())
        .with_minimisation(audit_minimisation);
    let ca_cert_repo = SurrealCaCertificateRepository::new(pool.handle_for_repo());
    let federation_link_repo_for_auth =
        SurrealFederationLinkRepository::new(pool.handle_for_repo());
    // A separate refresh-token repo instance for AuthService (used by
    // revoke_all_sessions / revoke_all_sessions_except on password change and reset).
    let auth_refresh_token_repo = SurrealRefreshTokenRepository::new(pool.handle_for_repo());
    // Single shared bounding semaphore for all CPU-bound crypto operations (CQ-B02 / REQ-14 AC-2).
    // Limits concurrent Argon2 and PKI keygen/sign operations to prevent runtime-thread
    // starvation AND an unauthenticated memory-DoS (each Argon2id arena is ~19 MiB; B1).
    // Permit count is `AXIAM__AUTH__MAX_CONCURRENT_HASHES` (0 = auto → min(cores, 4)).
    // Constructed once, cloned (Arc) into each service.
    let crypto_hash_permits = config.auth.resolved_max_concurrent_hashes();
    tracing::info!(
        permits = crypto_hash_permits,
        acquire_timeout_secs = config.auth.hash_acquire_timeout_secs,
        "crypto hash gate configured (B1)"
    );
    let crypto_semaphore = Arc::new(tokio::sync::Semaphore::new(crypto_hash_permits));

    // SEC-022/SECHRD-08: Resolve the mandatory AMQP master signing key. In a
    // debug build this falls back to a documented dev-only default when
    // unset; in a release build (the production container image) an unset
    // key fails closed at startup — there is no unsigned code path (D-05c).
    // With the broker off (G-8, D-59) there is nothing to sign, so the key is
    // neither required nor resolved.
    //
    // Resolved here because THREE things need it and this is the earliest of
    // them: the X1 reactor gate below (which signs reactor events and verifies
    // reactor replies with the same §8 v2 scheme), §4.2's cross-replica
    // cache-invalidation publisher, and the AMQP consumers.
    let amqp_signing_key: Option<Vec<u8>> = if config.amqp.enabled {
        let key = config.amqp.resolve_signing_key().expect(
            "AMQP signing key must resolve (SECHRD-08 / D-05c) — see AXIAM__AMQP__SIGNING_KEY",
        );
        tracing::info!("AMQP signing key resolved (SEC-022/SECHRD-08)");
        Some(key)
    } else {
        None
    };

    // -------------------------------------------------------------------
    // X1 — the reactor gate (R2.2)
    // -------------------------------------------------------------------
    //
    // ONE gate, shared by all five hook sites: `login.post_auth` in
    // `AuthService`, `token.pre_issue` in `TokenService`, and
    // `user.pre_create` / `user.pre_update` / `grant.pre_assign` in the REST
    // handlers via `AppState`. One gate means one routing table, one
    // per-tenant concurrency bound and one audit sink — five gates would mean
    // five caps that each admit 64 in-flight interceptions per tenant.
    //
    // The routing table is TTL-cached, so a tenant with no registered reactor
    // costs one hash-map lookup per hooked operation and never touches the
    // database or the broker.
    let reactor_routing = Arc::new(axiam_amqp::ReactorRoutingTable::new(
        axiam_amqp::RepositoryReactorSource(SurrealReactorRepository::new(pool.handle_for_repo())),
        axiam_amqp::reactor::DEFAULT_ROUTING_TTL,
    ));
    let reactor_audit_sink = axiam_amqp::RepositoryAuditSink(
        SurrealAuditLogRepository::new(pool.handle_for_repo())
            .with_minimisation(audit_minimisation),
    );
    let reactor_gate: axiam_core::models::reactor::SharedReactorGate =
        match (&amqp, &amqp_signing_key) {
            (Some(amqp), Some(signing_key)) => Arc::new(axiam_amqp::DispatchingReactorGate::new(
                Arc::clone(&reactor_routing),
                // R2.4: the real lapin RPC transport (§22.1's scope note is
                // closed). `start` is infallible and supervises its own broker
                // session — a broker that is slow at boot or restarts later must
                // not stop the server from serving logins. While it has no
                // session every dispatch fails fast as a transport error and the
                // registration's `failure_policy` decides, which is the same
                // closed set §22.8 puts a timeout in.
                axiam_amqp::LapinReactorTransport::start(Arc::clone(amqp), signing_key.clone()),
                reactor_audit_sink,
                signing_key.clone(),
                axiam_amqp::ReactorGateConfig::default(),
            )),
            // The minimal profile (G-8, D-59): no broker, so the transport that
            // can never dispatch is composed (`can_dispatch() == false`, which
            // is what turns an enabling reactor write into a 409 / FAILED_PRECONDITION).
            // Boot already refused a datastore with an enabled registration, so
            // no tenant has a reactor for the gate to apply a failure policy to.
            // There is no signing key and nothing to sign.
            _ => Arc::new(axiam_amqp::DispatchingReactorGate::new(
                Arc::clone(&reactor_routing),
                axiam_amqp::UnavailableReactorTransport,
                reactor_audit_sink,
                Vec::new(),
                axiam_amqp::ReactorGateConfig::default(),
            )),
        };
    let reactor_routing_invalidator: Arc<dyn Fn(uuid::Uuid) + Send + Sync> = {
        let routing = Arc::clone(&reactor_routing);
        Arc::new(move |tenant_id| routing.invalidate_tenant(tenant_id))
    };
    if deployment_profile.is_minimal() {
        tracing::info!(
            "X1 reactors: unavailable in the minimal profile — the dispatch gate is wired \
             with the transport that cannot dispatch, and enabling a registration is \
             refused (409 / FAILED_PRECONDITION)"
        );
    } else {
        tracing::info!(
            "X1 reactors: the dispatch gate is wired into all five interceptor \
         events over the lapin AMQP transport. A tenant with NO registered \
         reactor is unaffected and never touches the broker. While the broker \
         is unreachable a REGISTERED reactor's failure_policy applies to every \
         dispatch — a fail_closed registration (the default for login.post_auth, \
         user.pre_create, user.pre_update and grant.pre_assign) will DENY those \
         operations, and every one of those denials is audited as \
         'reactor.dispatch_failed'."
        );
    }

    // G-3 (T23.3.2, T23.3.4): one directory authenticator, shared by the sign-in
    // path and the group mapper, so both read the same configuration and draw
    // on the same bounded connection pool.
    let directory_config_repo = axiam_db::SurrealDirectoryConfigRepository::new(
        pool.handle_for_repo(),
        config.directory_encryption_key,
    );
    let directory_authenticator = Arc::new(
        axiam_directory::RepositoryDirectoryAuthenticator::with_client(
            directory_config_repo.clone(),
            directory_client(&config),
        ),
    );
    // The mapper flushes the authorization decision cache for a user whose
    // memberships it changed, as the group-membership routes do. The cache does
    // not exist yet, so the hook is set below, once `rest_authz` is built.
    let directory_membership_slot = axiam_directory::MembershipChangeSlot::new();
    // One mapper and one audit sink, shared by the sign-in path and the sync job
    // (T23.3.5): the job applies the very same function, flushes the very same
    // decision cache, and writes to the very same append-only log.
    let directory_group_mapper = Arc::new(
        axiam_directory::RepositoryGroupMapper::new(
            Arc::clone(&directory_authenticator),
            // The mapping adds and removes directory-sourced memberships: it
            // reports them like every other writer (D-57).
            axiam_db::SurrealGroupRepository::new(pool.handle_for_repo())
                .with_provisioning_sink(provisioning_sink.clone()),
        )
        .with_change_slot(directory_membership_slot.clone()),
    );
    let directory_audit_sink = Arc::new(axiam_auth::service::RepositoryDirectoryAuditSink(
        SurrealAuditLogRepository::new(pool.handle_for_repo())
            .with_minimisation(audit_minimisation),
    ));
    // The sync job revokes through the same repository the sign-in path owns, so
    // the session validation cache and the revocation feed see what it revokes.
    let directory_sync_refresh_repo = auth_refresh_token_repo.clone();
    // Built here, with the handle the rest of this block uses: `pool` is moved
    // into the health checker further down.
    let directory_sync_state_repo =
        axiam_db::SurrealDirectorySyncStateRepository::new(pool.handle_for_repo());
    let auth_service = AuthService::new(
        user_repo.clone(),
        session_repo.clone(),
        federation_link_repo_for_auth,
        auth_refresh_token_repo,
        config.auth.clone(),
        Arc::clone(&crypto_semaphore),
    )
    .with_reactor_gate(Arc::clone(&reactor_gate))
    // G-3 (T23.3.2): directory accounts authenticate through the tenant's LDAP /
    // Active Directory server. Always attached: without
    // `directory_encryption_key` the repository cannot decrypt a bind secret,
    // so every directory sign-in fails closed as `Unavailable` (never a local
    // hash), and tenants without a directory are untouched.
    .with_directory_authenticator(Arc::clone(&directory_authenticator) as _)
    // G-3 (T23.3.4, D-30): the tenant's mapping table is applied on every
    // successful directory sign-in, before anything is issued; a mapping that
    // cannot be applied (the directory cannot be asked, the 1 000-group cap) is
    // a refused sign-in. A tenant with an empty table asks the directory nothing.
    .with_directory_group_mapper(Arc::clone(&directory_group_mapper) as _)
    // G-3 (T23.3.3): the rows for just-in-time provisioning, its refusals and
    // the linking of an account, on the same append-only repository (and the
    // same minimisation) as every other audit row.
    .with_directory_audit(Arc::clone(&directory_audit_sink) as _);
    // Password history repository — used by the password-change handler.
    let password_history_repo = SurrealPasswordHistoryRepository::new(pool.handle_for_repo());
    let consent_repo = axiam_db::SurrealConsentRepository::new(pool.handle_for_repo());
    // The deletion request sets the account `Inactive` in its own transaction,
    // so this repository reports it (D-57).
    let account_deletion_repo = SurrealAccountDeletionRepository::new(pool.handle_for_repo())
        .with_provisioning_sink(provisioning_sink.clone());
    let export_job_repo = SurrealExportJobRepository::new(pool.handle_for_repo());
    let erasure_proof_repo = SurrealErasureProofRepository::new(pool.handle_for_repo());

    let webauthn_cred_repo = SurrealWebauthnCredentialRepository::new(pool.handle_for_repo());
    let webauthn_service = WebauthnService::new(webauthn_cred_repo.clone(), config.auth.clone())
        .expect("Failed to build WebauthnService");
    let mfa_method_service = MfaMethodService::new(
        user_repo.clone(),
        webauthn_cred_repo.clone(),
        session_repo.clone(),
    );

    // X3 wave 3: attestation-policy resolution, MDS metadata, and the
    // process-wide CA-list cache the attested registration ceremony needs.
    let webauthn_attestation_policy_repo =
        SurrealWebauthnAttestationPolicyRepository::new(pool.handle_for_repo());
    let mds_repo = SurrealMdsRepository::new(pool.handle_for_repo());
    let attestation_metadata_source = MdsAttestationMetadataSource::new(mds_repo.clone());
    // Shared (Arc) so the REST handlers (policy update, MDS refresh) and the
    // background MDS refresh job below invalidate the SAME cache instance
    // (W2-D3) rather than each maintaining an unreachable private one.
    let attestation_ca_cache = Arc::new(AttestationCaCache::new());

    // PKI service — encryption key for CA private keys (SEC-012).
    // Absent key → None; operations that encrypt private key material will fail fast
    // with a clear error rather than silently using an all-zero key.
    //
    // X3 (D10): FIDO MDS3 ingestion config. `PkiConfig` doesn't derive
    // `Deserialize` (it holds `[u8; 32]`/`PathBuf`, same reason
    // `encryption_key` above is loaded manually rather than through
    // `AppConfig`), so these five `AXIAM__PKI__MDS_*` vars are parsed here by
    // hand. `mds_enabled` defaults to
    // `false` — "off means zero outbound calls" — so an unset env var
    // reproduces `PkiConfig::default()`'s documented behavior exactly.
    let pki_config = PkiConfig {
        encryption_key: config.pki_encryption_key,
        mds_enabled: std::env::var("AXIAM__PKI__MDS_ENABLED")
            .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false),
        mds_blob_url: std::env::var("AXIAM__PKI__MDS_BLOB_URL")
            .unwrap_or_else(|_| axiam_pki::config::DEFAULT_MDS_BLOB_URL.to_string()),
        mds_blob_path: std::env::var("AXIAM__PKI__MDS_BLOB_PATH")
            .ok()
            .map(std::path::PathBuf::from),
        mds_refresh_interval_secs: std::env::var("AXIAM__PKI__MDS_REFRESH_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(axiam_pki::config::DEFAULT_MDS_REFRESH_INTERVAL_SECS),
        mds_leaf_dns: std::env::var("AXIAM__PKI__MDS_LEAF_DNS")
            .unwrap_or_else(|_| axiam_pki::config::DEFAULT_MDS_LEAF_DNS.to_string()),
        // T-153. An unparseable value falls back to 0 (disabled) rather than
        // to some non-zero default: silently inventing a staleness bound the
        // operator did not ask for would start refusing registrations for a
        // reason nothing in their configuration mentions.
        mds_max_stale_days: std::env::var("AXIAM__PKI__MDS_MAX_STALE_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
    };
    // SEC-107: install the operator's SSRF host exception list, once, here in
    // the composition root so it is visible in one place and logged at
    // startup. Unset — the default and what every deployment gets unless
    // somebody decides otherwise — installs nothing and the address rule
    // admits no exceptions at all. See `axiam_pki::ssrf::set_allowed_hosts`
    // for why this is a host list rather than a boolean or a CIDR range.
    match std::env::var(axiam_pki::ssrf::ALLOWED_HOSTS_ENV) {
        Ok(raw) if !raw.trim().is_empty() => {
            let hosts = axiam_pki::ssrf::parse_allowed_hosts(&raw);
            let installed = axiam_pki::ssrf::set_allowed_hosts(hosts.clone());
            tracing::warn!(
                count = installed,
                hosts = %hosts.join(","),
                "SSRF host exceptions installed ({}): these hosts may resolve to \
                 private/loopback addresses. Every use is logged. Cloud metadata \
                 endpoints remain blocked for them, and redirect targets are still \
                 validated strictly.",
                axiam_pki::ssrf::ALLOWED_HOSTS_ENV
            );
        }
        _ => {
            tracing::info!(
                "SSRF guard: no host exceptions configured ({} unset) — every outbound \
                 fetch to an admin-supplied URL must resolve to a globally routable \
                 address",
                axiam_pki::ssrf::ALLOWED_HOSTS_ENV
            );
        }
    }

    tracing::info!(
        mds_enabled = pki_config.mds_enabled,
        mds_refresh_interval_secs = pki_config.mds_refresh_interval_secs,
        mds_blob_source = if pki_config.mds_blob_path.is_some() {
            "local_file"
        } else {
            "network"
        },
        "FIDO MDS3 ingestion config resolved (D10)"
    );
    // Who holds the CA signing keys. `database` unless an operator configured
    // Vault, which is what every existing deployment already had — and a
    // deliberate `vault` that is not actually reachable stops startup here,
    // rather than being quietly served from the database instead. A deployment
    // that configured neither issues no certificates and boots without either;
    // it learns what to set when it first tries to generate a CA.
    let ca_custodians = Arc::new(
        axiam_pki::custodians_from_env(pki_config.encryption_key)
            .map_err(|e| std::io::Error::other(format!("CA key custody: {e}")))?,
    );
    match ca_custodians.default_custody() {
        Some(custody) => tracing::info!(
            %custody,
            vault_inherited = ca_custodians.vault_inherited(),
            "CA signing key custody resolved"
        ),
        None => tracing::info!(
            "no CA signing key custodian configured; CA generation and import will be \
             refused until AXIAM__AUTH__PKI_ENCRYPTION_KEY or AXIAM__PKI__VAULT_ADDR is set"
        ),
    }
    // The arrangement nobody picks deliberately, and the one the 1.0.0-beta01
    // log showed: a reachable Vault, and every CA signing key sealed into a
    // `ca_certificate` row anyway. Reachable now only by naming `database`
    // explicitly, so it is a warning rather than a refusal — but it says what
    // is actually at stake, because the two differ by whether one database dump
    // hands over every CA in the deployment.
    if ca_custodians.database_custody_despite_vault() {
        tracing::warn!(
            "CA signing keys are being sealed into the database although Vault custody is \
             configured and reachable. A database dump plus one process's \
             AXIAM__AUTH__PKI_ENCRYPTION_KEY then yields every CA private key in this \
             deployment, and nothing records the read. Unset \
             AXIAM__PKI__CA_KEY_STORE (or set it to `vault`) to hold them in Vault \
             instead, then migrate the CAs you already have with \
             `POST /api/v1/organizations/{{org_id}}/ca-certificates/{{id}}/migrate-custody`."
        );
    }

    let cert_repo = SurrealCertificateRepository::new(pool.handle_for_repo());
    let ca_service = CaService::new(
        ca_cert_repo.clone(),
        pki_config.clone(),
        Arc::clone(&crypto_semaphore),
        Arc::clone(&ca_custodians),
    );
    let pgp_repo = SurrealPgpKeyRepository::new(pool.handle_for_repo());
    let pgp_service = PgpService::new(pgp_repo, pki_config.clone(), Arc::clone(&crypto_semaphore));
    let cert_service = CertService::new(
        ca_cert_repo,
        cert_repo.clone(),
        // X3: `pki_config` is needed again below (AppState field + the MDS
        // background job), so this is now a clone rather than the final move
        // it used to be.
        pki_config.clone(),
        Arc::clone(&crypto_semaphore),
        Arc::clone(&ca_custodians),
    );
    // SEC-024: DeviceAuthService now holds a CA repo for chain verification.
    // SurrealCaCertificateRepository is cloned; each clone shares the underlying Surreal<C>.
    let device_auth_service = DeviceAuthService::new(
        cert_repo.clone(),
        SurrealCaCertificateRepository::new(pool.handle_for_repo()),
    );
    let reactor_repo = SurrealReactorRepository::new(pool.handle_for_repo());
    let webhook_repo = SurrealWebhookRepository::new(pool.handle_for_repo());
    // SEC-031/SEC-059: Webhook secrets stored AES-256-GCM encrypted using the
    // same PKI encryption key. Absent key -> None (SEC-012 fail-closed
    // pattern, mirrors `pki_config.encryption_key` above): the server still
    // boots, but webhook registration and delivery are refused with an
    // explicit error + `warn!` until a real key is configured. NEVER an
    // all-zero/constant fallback key.
    let webhook_enc_key: Option<[u8; 32]> = config.pki_encryption_key;
    let webhook_delivery =
        axiam_api_rest::webhook::WebhookDeliveryService::new(webhook_repo.clone(), webhook_enc_key);
    let webhook_delivery = if opts.admit_private_networks_for_tests {
        webhook_delivery.admitting_private_networks_for_tests()
    } else {
        webhook_delivery
    };
    let settings_repo = SurrealSettingsRepository::new(pool.handle_for_repo());
    let opaque_credential_repo =
        axiam_db::SurrealOpaqueCredentialRepository::new(pool.handle_for_repo());
    let opaque_setup_repo =
        axiam_db::SurrealOpaqueServerSetupRepository::new(pool.handle_for_repo());
    // Notification-rule repository — required by the notification_rules handlers'
    // `web::Data<SurrealNotificationRuleRepository>` extractor. Without this
    // registration every /api/v1/notification-rules request 500s with
    // "App data is not configured".
    let notification_rule_repo = SurrealNotificationRuleRepository::new(pool.handle_for_repo());
    // Email-config repository (28-04, FUNC-03) — required by the
    // `handlers::email_config::*` handlers' `web::Data<SurrealEmailConfigRepository<C>>`
    // extractor. Only constructed when AXIAM__AUTH__EMAIL_ENCRYPTION_KEY is present (same
    // fail-closed, no-zero-key-fallback posture as the mail consumer above): when the
    // key is absent, `email_config_repo` stays `None` and is NOT registered as
    // app_data below, so the six email-config routes fail closed with actix's
    // "App data is not configured" 500 rather than silently encrypting with a
    // constant/zero key.
    let email_config_repo: Option<SurrealEmailConfigRepository<C>> = match config
        .email_encryption_key
    {
        Some(email_key) => Some(SurrealEmailConfigRepository::new(
            pool.handle_for_repo(),
            email_key,
        )),
        None => {
            tracing::warn!(
                "AXIAM__AUTH__EMAIL_ENCRYPTION_KEY missing — email-config admin endpoints disabled"
            );
            None
        }
    };
    let federation_config_repo = SurrealFederationConfigRepository::new(pool.handle_for_repo());
    let federation_link_repo = SurrealFederationLinkRepository::new(pool.handle_for_repo());
    let assertion_replay_repo = SurrealAssertionReplayRepository::new(pool.handle_for_repo());
    // X5.1 — the single-use `jti` store shared by RFC 7523 client assertions
    // and RFC 9449 DPoP proofs.
    let proof_replay_repo = SurrealProofReplayRepository::new(pool.handle_for_repo());
    // RFC 9449 §11.1: makes a DPoP proof single-use at the *resource*
    // endpoints, which the token endpoint has done since X5.1 and the
    // extractors could not — recording a `jti` is a write, and they verified
    // proofs synchronously. Registered as its own app_data for the same reason
    // `session_validator` is: the extractors are non-generic and cannot name
    // `AppState<C>`.
    //
    // Cloned from `proof_replay_repo` rather than built beside it, so that the
    // resource endpoints and the token endpoint share one store *by
    // construction*. A proof is single-use, not single-use per endpoint, and
    // two stores would let one proof be spent once at each.
    //
    // Without it the extractors fail closed for any request presenting a DPoP
    // proof — the correct direction, and the reason this sits on the next line
    // rather than somewhere it could be forgotten.
    let dpop_replay_guard: std::sync::Arc<dyn axiam_api_rest::DpopReplayGuard> =
        std::sync::Arc::new(proof_replay_repo.clone());
    // NEW-4: durable AMQP nonce store for replay protection, shared by the
    // authz + audit consumers and swept by the periodic cleanup task.
    let amqp_nonce_repo = SurrealAmqpNonceRepository::new(pool.handle_for_repo());
    let federation_login_state_repo =
        SurrealFederationLoginStateRepository::new(pool.handle_for_repo());
    let sso_handoff_code_repo = SurrealSsoHandoffCodeRepository::new(pool.handle_for_repo());
    // T23.2.3 — pending SAML AuthnRequests (schema v73). Built in every build:
    // the table exists whether or not SAML is compiled in, and the sweep below
    // keeps it bounded either way.
    let saml_pending_repo =
        axiam_db::SurrealPendingSamlRequestRepository::new(pool.handle_for_repo());
    // T23.2.4 — the single-logout stores (schema v76): which SPs hold which
    // session, and the logout chain. Built in every build for the same reason.
    let saml_participant_repo =
        axiam_db::SurrealSamlSpSessionRepository::new(pool.handle_for_repo());
    let saml_logout_run_repo =
        axiam_db::SurrealSamlLogoutRunRepository::new(pool.handle_for_repo());
    // Process-wide JWKS cache shared by all OIDC federation handlers (D-01/D-02/D-03).
    let jwks_cache = Arc::new(JwksCache::new());
    // B3: process-wide in-process cache for AXIAM's OWN `GET /oauth2/jwks`
    // response (distinct from the federation JWKS cache above -- see
    // `axiam_oauth2::jwks_cache` module docs).
    let oauth2_jwks_cache = Arc::new(Oauth2JwksCache::new());
    // Disable automatic redirects to prevent SSRF bypass (an HTTPS URL
    // could redirect to http:// or an internal host). Apply a global
    // timeout for consistent outbound HTTP behaviour.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client");
    let oauth2_client_repo = SurrealOAuth2ClientRepository::new(pool.handle_for_repo());
    // T21.4 — RFC 7591 initial access tokens. Read by the unauthenticated
    // registration endpoint and swept by the cleanup task.
    let oauth2_registration_token_repo =
        axiam_db::SurrealOAuth2RegistrationTokenRepository::new(pool.handle_for_repo());
    let auth_code_repo = SurrealAuthorizationCodeRepository::new(pool.handle_for_repo());
    let refresh_token_repo = SurrealRefreshTokenRepository::new(pool.handle_for_repo());
    // Separate instance for password-reset/change handlers that need direct
    // RefreshTokenRepository access via web::Data (TokenService owns the main one).
    let handler_refresh_token_repo = SurrealRefreshTokenRepository::new(pool.handle_for_repo());

    // OAuth2 authorization code grant services.
    let authorize_service = AuthorizeService::new(
        oauth2_client_repo.clone(),
        auth_code_repo.clone(),
        config.auth.auth_code_lifetime_secs,
    );
    let token_service = TokenService::new(
        oauth2_client_repo.clone(),
        // Service accounts authenticate via client-credentials too; the handler
        // dispatches on the `sa_` client-id prefix.
        service_account_repo.clone(),
        auth_code_repo,
        tenant_repo.clone(),
        refresh_token_repo,
        user_repo.clone(),
        // W4 — the session behind a refresh grant, so a re-issued ID token's
        // `auth_time` equals the original's (OIDC Core §12.2). Read only for a
        // client on the honour lane.
        session_repo.clone(),
        // T-254 — where a refresh token presented after rotation is recorded,
        // whether it was accepted under the FAPI grace or refused.
        audit_repo.clone(),
        config.auth.clone(),
        i64::try_from(config.auth.refresh_token_lifetime_secs)
            .expect("refresh_token_lifetime_secs exceeds i64::MAX"),
    )
    // X1 — the same gate `AuthService` holds, so `token.pre_issue` and
    // `login.post_auth` share one routing table and one per-tenant cap.
    .with_reactor_gate(Arc::clone(&reactor_gate))
    // X5.1 — `private_key_jwt` (RFC 7523 §2.2), one of FAPI 2.0's two
    // client-authentication families.
    //
    // Without this the crypto still exists and nothing can reach it:
    // `TokenService` answers a client registered for the method with
    // "no assertion verifier configured" and refuses — deliberately, rather
    // than falling back to another credential — so the effect of not wiring it
    // is that no client anywhere can authenticate this way. The whole
    // 56-module FAPI `private_key_jwt` conformance lane failed on that one
    // missing line.
    //
    // The JWKS cache is the FEDERATION one, shared with the OIDC IdP handlers
    // on purpose: a client's `jwks_uri` is a URL the server fetches on demand,
    // which is the same SEC-054 SSRF surface whichever feature asked for it,
    // and a second cache would be a second place for a guard to be missing.
    .with_assertion_verifier(Arc::new(
        axiam_oauth2::private_key_jwt::JwksAssertionVerifier::new(
            (*jwks_cache).clone(),
            http_client.clone(),
            proof_replay_repo.clone(),
            config.auth.oauth2_issuer_url.clone(),
            // The token endpoint, for clients following OIDC Core §9 rather
            // than RFC 7523. A FAPI 2.0 client is held to the issuer alone —
            // `JwksAssertionVerifier` decides that from the client's profile.
            vec![format!(
                "{}/oauth2/token",
                config.auth.oauth2_issuer_url.trim_end_matches('/')
            )],
        ),
    ));

    // B2 — device authorization grant (RFC 8628).
    //
    // `verification_uri` is derived from the OIDC issuer rather than
    // configured separately: a verification URI on a different origin from
    // the issuer is a phishing shape, and deriving it means the two cannot
    // drift. The device is told this URI and a user types it from memory, so
    // it is the one string in the flow that no client can validate.
    let device_grant_repo = SurrealDeviceGrantRepository::new(pool.handle_for_repo());
    let device_verification_uri = format!(
        "{}/device",
        config.auth.oauth2_issuer_url.trim_end_matches('/')
    );
    let device_authorization_service = DeviceAuthorizationService::new(
        device_grant_repo.clone(),
        oauth2_client_repo.clone(),
        tenant_repo.clone(),
        SurrealRefreshTokenRepository::new(pool.handle_for_repo()),
        user_repo.clone(),
        config.auth.clone(),
        i64::try_from(config.auth.refresh_token_lifetime_secs)
            .expect("refresh_token_lifetime_secs exceeds i64::MAX"),
        device_verification_uri,
    );

    // G-7 — CIBA. The pending-request store seals a ping-mode request's
    // notification credentials under `pki_encryption_key`, the key webhook
    // secrets use; without it a ping-mode request is refused and poll works.
    // The sweep below (`ciba_request` on `/health/jobs`) shares this store.
    let ciba_request_repo =
        axiam_db::SurrealCibaRequestRepository::new(pool.handle_for_repo(), webhook_enc_key);
    // The ping kind's publisher (T23.7.2, D-65): one channel for the decision
    // path's enqueue and for the consumer's TTL-delayed retries, below. A
    // queued message is the request's record id and tenant — never the
    // `auth_req_id` or the notification token.
    let ciba_ping_publisher = outbound.publisher(OutboundKind::CibaPing).await;
    let ciba_service = axiam_oauth2::ciba::CibaService::new(
        ciba_request_repo.clone(),
        user_repo.clone(),
        config.auth.jwt_public_key_pem.clone(),
    )
    // D-61 — signed authentication requests (CIBA Core §7.1.1, FAPI-CIBA).
    // The keys come through the same federation JWKS cache the
    // `private_key_jwt` verifier above uses (one SSRF guard, one cache entry
    // per client), and the `jti` goes into the same proof-replay table. Not
    // wiring it would refuse every signed request with `server_error` — never
    // accept one unverified.
    .with_signed_request_verifier(Arc::new(
        axiam_oauth2::ciba_signed_request::JwksSignedRequestVerifier::new(
            (*jwks_cache).clone(),
            http_client.clone(),
            proof_replay_repo.clone(),
        ),
    ))
    // D-65 — an approval or a refusal of a ping-mode request queues its
    // notification on the dispatcher (the consumer is spawned with the other
    // kinds' below).
    .with_ping_publisher(Arc::clone(&ciba_ping_publisher));

    // B3 — token exchange (RFC 8693).
    //
    // The ordinary access-token lifetime is the exchanged-token ceiling: an
    // exchange is a narrowing, so it has no business producing something
    // longer-lived than a normal token. It is applied on top of "never
    // outlives its subject", not instead of it.
    let token_exchange_service = TokenExchangeService::new(
        tenant_repo.clone(),
        config.auth.clone(),
        i64::try_from(config.auth.access_token_lifetime_secs)
            .expect("access_token_lifetime_secs exceeds i64::MAX"),
    );

    // B5 / RFC 9126. Composed here at the root, not lazily: an AppState field
    // that only the test builder populates is exactly the gap that left B2's
    // grant unreachable in a real deployment.
    let session_client_repo = SurrealSessionClientRepository::new(pool.handle_for_repo());
    // X2 — UMA 2.0 permission tickets. Built here with the other repositories
    // because `pool` is moved before the `AppState` literal is assembled.
    let permission_ticket_repo =
        axiam_db::repository::SurrealPermissionTicketRepository::new(pool.handle_for_repo());
    let par_service = ParService::new(
        oauth2_client_repo.clone(),
        SurrealPushedAuthRequestRepository::new(pool.handle_for_repo()),
    );

    // QUAL-07: hoist the 13 per-request service constructions
    // (password_reset.rs/email_verification.rs/federation.rs) into
    // once-at-startup singletons.
    //
    // These two repos were NEVER registered in main.rs before this plan (a
    // pre-existing bug — see 29-03-SUMMARY.md): `SurrealPasswordResetTokenRepository`
    // and `SurrealEmailVerificationTokenRepository` are constructed here
    // purely to build the two hoisted services below; no handler touches
    // them directly, so they are not their own AppState field.
    let password_reset_token_repo =
        SurrealPasswordResetTokenRepository::new(pool.handle_for_repo());
    let email_verification_token_repo =
        SurrealEmailVerificationTokenRepository::new(pool.handle_for_repo());

    let password_reset_service = PasswordResetService::new(
        user_repo.clone(),
        password_reset_token_repo,
        federation_link_repo.clone(),
        password_history_repo.clone(),
        session_repo.clone(),
        handler_refresh_token_repo.clone(),
        Arc::clone(&crypto_semaphore),
        config.auth.hash_acquire_timeout_secs,
    );
    let email_verification_service = EmailVerificationService::new(
        user_repo.clone(),
        email_verification_token_repo,
        federation_link_repo.clone(),
    );
    // OidcFederationService bakes in the federation encryption key at
    // construction (unlike SamlFederationService, which needs none) — so
    // absence of AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY is resolved ONCE
    // here (`None`) rather than per-request; the 4 OIDC handler call sites
    // return the identical fail-closed error as before.
    let oidc_federation_service = config.auth.federation_encryption_key.map(|enc_key| {
        OidcFederationService::new(
            federation_config_repo.clone(),
            federation_link_repo.clone(),
            user_repo.clone(),
            http_client.clone(),
            Arc::clone(&jwks_cache),
            enc_key,
        )
    });
    // SamlFederationService::new needs no encryption key — constructed
    // unconditionally regardless of the saml Cargo feature's own gating
    // (only the SAML REST handlers/routes stay #[cfg(feature = "saml")]).
    #[cfg(feature = "saml")]
    let saml_federation_service = SamlFederationService::new(
        federation_config_repo.clone(),
        federation_link_repo.clone(),
        user_repo.clone(),
        assertion_replay_repo.clone(),
        http_client.clone(),
    );
    // T23.2.3 (G-2) — the SAML IdP: the SP registry, the pending-request store,
    // the tenant signing-credential service (D-21: its keys are sealed through
    // the database custodian of the same custodian set the CAs use) and the
    // issuer, built on the deployment's root issuer and the pairwise key.
    let saml_idp_state = bundles::SamlIdpState {
        sp_repo: axiam_db::SurrealSamlServiceProviderRepository::new(pool.handle_for_repo()),
        pending_repo: saml_pending_repo.clone(),
        participant_repo: saml_participant_repo.clone(),
        logout_run_repo: saml_logout_run_repo.clone(),
        credential_service: axiam_pki::saml_signing::SamlIdpCredentialService::new(
            cert_service.clone(),
            Arc::clone(&ca_custodians),
            axiam_db::SurrealSamlIdpCredentialRepository::new(pool.handle_for_repo()),
        ),
        #[cfg(feature = "saml")]
        issuer: Arc::new(axiam_federation::saml_idp::SamlIdpIssuer::new(
            config.auth.root_issuer(),
            config
                .saml_pairwise_key
                .map(axiam_federation::saml_idp::PairwiseKey::new),
        )),
    };

    // G-5 / T23.5.2 — the SSF stream registry. Push credentials are sealed
    // under the key webhook secrets use (D-49); without it a stream with a push
    // header cannot be stored and everything else works.
    let ssf_stream_repo =
        axiam_db::SurrealSsfStreamRepository::new(pool.handle_for_repo(), webhook_enc_key);
    // T23.5.3 — the poll/hold buffer and the one emitter every change site calls
    // (D-52). The emitter does nothing until the outbox is bound (below, once the
    // broker's publisher exists); the two ports are bound to it now.
    let ssf_event_buffer_repo =
        axiam_db::SurrealSsfEventBufferRepository::new(pool.handle_for_repo());
    // D-53 (1): the step-up record the honour lane writes and the return leg
    // consumes; its ten-minute expiry is swept by the cleanup scheduler.
    let ssf_step_up_repo = axiam_db::SurrealSsfStepUpRepository::new(pool.handle_for_repo());
    // D-55: SSF requires per-tenant issuers in a deployment of more than one
    // tenant. One gate for the process: the emitter, the poll endpoint,
    // discovery and the push deliverer ask it; a change is audited per tenant
    // with SSF on.
    let ssf_gate = Arc::new(axiam_oauth2::ssf::SsfIssuerGate::new(
        config.auth.tenant_issuer_paths,
        Arc::new(tenant_repo.clone()),
    ));
    ssf_gate.bind_observer(Arc::new(
        axiam_api_rest::ssf_emitter::SharedIssuerAudit::new(
            org_repo.clone(),
            tenant_repo.clone(),
            settings_repo.clone(),
            audit_repo.clone(),
        ),
    ));
    let ssf_emitter = axiam_api_rest::ssf_emitter::SsfEmitter::new(
        ssf_stream_repo.clone(),
        tenant_repo.clone(),
        settings_repo.clone(),
        user_repo.clone(),
        config.auth.clone(),
        ssf_gate.clone(),
    );
    ssf_session_sink.bind(Arc::new(ssf_emitter.clone()));
    ssf_account_sink.bind(Arc::new(ssf_emitter.clone()));

    // G7: resolve the deployment rate-limit posture BEFORE validation and
    // before `config.rate_limit` / `config.grpc` are cloned into the App
    // factory and the gRPC task. `AXIAM__RATE_LIMIT__PROFILE` (default
    // `internet`) presets the machine-traffic family — key mode, token,
    // introspect, revoke, REST authz and the gRPC authz ceiling — as one
    // coherent unit; any `AXIAM__RATE_LIMIT__*` / `AXIAM__GRPC__*` env var the
    // operator set explicitly still wins. Human endpoints (login, register,
    // password reset, MFA) are never preset — see `RateLimitProfile`.
    let mut rate_limit_posture = config.rate_limit.apply_profile_from_env();
    if let Some(per_sec) = rate_limit_posture.grpc_authz_per_sec_preset
        && !config.grpc.apply_rate_limit_preset_from_env(per_sec)
    {
        rate_limit_posture
            .operator_overrides
            .push(axiam_api_grpc::config::ENV_GRPC_AUTHZ_PER_SEC);
    }

    config.rate_limit.validate();

    // G7: one non-secret line stating the posture this process is actually
    // enforcing, so an operator can see what they shipped (all values are
    // configuration, never credentials).
    tracing::info!(
        profile = config.rate_limit.profile.as_str(),
        preset_applied = rate_limit_posture.preset_applied,
        key_mode = config.rate_limit.key.as_str(),
        login_per_min = config.rate_limit.login_per_min,
        register_per_min = config.rate_limit.register_per_min,
        password_reset_per_min = config.rate_limit.password_reset_per_min,
        mfa_per_min = config.rate_limit.mfa_per_min,
        token_per_min = config.rate_limit.token_per_min,
        introspect_per_min = config.rate_limit.introspect_per_min,
        revoke_per_min = config.rate_limit.revoke_per_min,
        authz_check_per_min = config.rate_limit.authz_check_per_min,
        grpc_authz_per_sec = config.grpc.grpc_authz_per_sec,
        operator_overrides = %rate_limit_posture.overrides_display(),
        "Rate-limit posture active"
    );

    // R-4 (narrows T-212/T-233): the number AND the rule that derives it, in
    // one line, next to the posture it shapes.
    //
    // `trusted_hops` decides which entry of `X-Forwarded-For` becomes the
    // rate-limit key, on BOTH listeners — they read the same variable. One too
    // high and the header is discarded on every request, every client keys on
    // the proxy's address, and the whole deployment shares one bucket. That is
    // T-212's off-by-one, and it went unnoticed because nothing said so. The
    // extractors now warn and count when it happens
    // (`axiam_rate_limit_xff_discarded_total`); this line is the other half —
    // an operator reading boot logs sees the value in force and the rule
    // together, and can check one against their own topology before any traffic
    // arrives.
    let trusted_hops: usize = std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    tracing::info!(
        trusted_hops,
        rule = "trusted_hops = proxies - 1",
        implies_proxies = trusted_hops + 1,
        metric = "axiam_rate_limit_xff_discarded_total",
        "Rate-limit client-IP derivation: X-Forwarded-For is trusted for \
         {trusted_hops} appended hop(s), i.e. this server expects {} proxy/proxies \
         in front of it. Both listeners read the same value. If that count is \
         wrong the header is discarded and every client keys on the peer — \
         watch axiam_rate_limit_xff_discarded_total.",
        trusted_hops + 1
    );

    // §4 item 1 (security-analysis-2026-08-02): the bucket key for
    // `/oauth2/{token,introspect,revoke}` is derived from the raw form body
    // BEFORE the credential check, so under `AXIAM__RATE_LIMIT__KEY=client_id`
    // it is attacker-mintable. Silent for the shipped default (`ip`); `warn!`
    // for `client_id`; a softer `info!` note for the partially-mintable
    // `ip_client_id`. Same shape as the I3 advisory below and the
    // session-validation cache's startup `warn!` — announce the opt-in mode
    // that carries the caveat, say nothing when the safe default is active.
    config.rate_limit.warn_on_mintable_key();

    // T-244: a default tenant that does not parse is treated as unset, which
    // is the right behaviour — discovery is a public, unauthenticated document
    // and a fat-fingered UUID must not `500` for every relying party — and was
    // also completely silent, so a deployment that set it concluded the
    // setting does not work. Said once here, never on the request path (the
    // accessor is called per discovery request, and a warning there is a log
    // flood any anonymous caller can drive), and describing the value's shape
    // rather than the value: this variable is not proven to hold a tenant id,
    // so it is not proven to hold something safe to print.
    if let Some(problem) = config.auth.default_tenant_id_diagnostic() {
        tracing::warn!(
            variable = "AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID",
            value_shape = %problem,
            "the configured default tenant is not a UUID and is being ignored; \
             discovery will serve the document it serves when the variable is \
             unset, and no endpoint URL will carry a tenant"
        );
    }

    // I3: should the machine-traffic throttling advisory be armed on the
    // shared rate-limit counter built further down? Only when the shipped
    // `internet` defaults are what this process is actually enforcing —
    // i.e. no posture preset was applied AND no machine limit was pinned by
    // hand. An operator who chose `gateway`/`mesh`, or who set the numbers
    // themselves, has already made this sizing decision.
    let arm_machine_traffic_advisory = {
        use axiam_api_rest::config::rate_limit::{
            ENV_AUTHZ_CHECK_PER_MIN, ENV_INTROSPECT_PER_MIN, ENV_REVOKE_PER_MIN, ENV_TOKEN_PER_MIN,
        };
        config.rate_limit.profile == axiam_api_rest::config::rate_limit::RateLimitProfile::Internet
            && ![
                ENV_TOKEN_PER_MIN,
                ENV_INTROSPECT_PER_MIN,
                ENV_REVOKE_PER_MIN,
                ENV_AUTHZ_CHECK_PER_MIN,
            ]
            .iter()
            .any(|name| std::env::var_os(name).is_some())
    };

    let bind_addr = config.server.bind_address();
    let server_config = config.server.clone();
    // Direct-TLS is opt-in (default: terminate at the proxy layer). Cloned out
    // of `config.server` before `server_config` is moved into the App factory
    // closure below so the bind decision can still read it (F-04).
    let mut tls_config = config.server.tls.clone();

    // Build the mTLS client trust store from the organization CAs an operator
    // flagged in the admin UI (`mtls_trust_anchor`). Only their PUBLIC
    // certificates are exported; the signing keys stay with their custodian.
    // See `crate::mtls_anchors` for the whole argument, including why an
    // operator's own `client_auth` / `client_ca_path` is never overridden.
    //
    // Read here rather than at the bind below because rustls builds its
    // `RootCertStore` once, from this config — and because a flagged CA has to
    // reach `tls_config` before it is moved into the App factory.
    let anchor_result = {
        use axiam_core::repository::CaCertificateRepository as _;
        // A fresh handle: `ca_cert_repo` was moved into the CA service above,
        // and the repositories are cheap clones over one shared pool.
        SurrealCaCertificateRepository::new(pool.handle_for_repo())
            .list_mtls_trust_anchors()
            .await
    };
    match anchor_result {
        Ok(anchors) => {
            let plan = crate::mtls_anchors::plan(&tls_config, &anchors);
            match &plan {
                crate::mtls_anchors::AnchorPlan::NoAnchors => {}
                crate::mtls_anchors::AnchorPlan::NoBundlePath => {
                    tracing::warn!(
                        anchors = anchors.len(),
                        "CA certificates are flagged as mTLS trust anchors but there is \
                         nowhere to write the bundle — set \
                         AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH (or \
                         AXIAM__SERVER__TLS__CERT_PATH, beside which it defaults). \
                         Client-certificate authentication is NOT enabled."
                    );
                }
                crate::mtls_anchors::AnchorPlan::Write { anchor_count, .. } => {
                    match crate::mtls_anchors::apply(&mut tls_config, &plan) {
                        Ok(Some(path)) => tracing::info!(
                            anchors = anchor_count,
                            bundle = %path.display(),
                            client_auth = ?tls_config.client_auth,
                            "mTLS client trust store built from flagged organization CAs"
                        ),
                        Ok(None) => {}
                        // Warn rather than refuse to boot. The flag is set at
                        // runtime through the API, so failing startup here would
                        // let one admin request brick the next restart. The
                        // failure is permissive (client auth stays off), not a
                        // hole: `optional` rejects nobody it would otherwise
                        // have admitted.
                        Err(e) => tracing::error!(
                            error = %e,
                            "could not write the mTLS client-CA bundle — \
                             client-certificate authentication is NOT enabled"
                        ),
                    }
                }
            }
        }
        Err(e) => tracing::error!(
            error = %e,
            "could not read the mTLS trust anchors — \
             client-certificate authentication is left as configured"
        ),
    }

    // The seam that lets flagging a CA take effect without a restart.
    //
    // Built from the bundle path resolved against the *final* `tls_config`, so
    // a reload writes the same file the next boot reads and the two cannot
    // drift. Constructed even when nothing is flagged today: the whole point is
    // that the first CA an operator flags applies immediately, and a reloader
    // that only existed when anchors already existed would miss exactly that
    // case.
    let trust_anchor_reloader: Option<Arc<dyn axiam_api_rest::TrustAnchorReloader>> =
        Some(Arc::new(crate::mtls_anchors::TrustAnchorReload::new(
            SurrealCaCertificateRepository::new(pool.handle_for_repo()),
            crate::mtls_anchors::bundle_path(&tls_config),
        )));

    let rate_limit_cfg = config.rate_limit.clone();
    let auth_config = config.auth.clone();

    // PERF-01: initialize the process-wide HIBP circuit breaker from
    // AuthConfig (config-crate wired, not a manual env parse) before the
    // HTTP server starts serving.
    axiam_auth::hibp_breaker::init_global(
        auth_config.hibp_breaker_threshold,
        auth_config.hibp_breaker_cooldown_secs,
    );

    tracing::info!(bind = %bind_addr, "Starting REST API server");

    // D7: build the shared authorization decision cache. `None` unless
    // `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true` — when `None`, every engine
    // below is constructed exactly as before (no cache, zero behaviour
    // change). The SAME `Arc<DecisionCache>` is cloned into the REST, gRPC and
    // AMQP engines so an invalidation triggered from a REST mutation handler is
    // observed on every read path (all role/permission/resource mutations are
    // REST endpoints).
    let decision_cache = config.authz.build_decision_cache();
    if let Some(cache) = decision_cache.as_ref() {
        tracing::info!(
            // §17.1: the accessor, not the raw field. This was the workspace's
            // sole non-test raw read, and it logged the operator's *requested*
            // TTL while the cache ran on the clamped one — so an operator who
            // set 86400 saw "86400" here and reasonably concluded the clamp
            // had not applied. `configured_ttl_secs` is emitted only when the
            // two differ, which is exactly when the discrepancy needs
            // explaining.
            ttl_secs = config.authz.decision_cache_ttl_secs(),
            configured_ttl_secs = (config.authz.decision_cache_ttl_secs
                != config.authz.decision_cache_ttl_secs())
            .then_some(config.authz.decision_cache_ttl_secs),
            max_entries = config.authz.decision_cache_max_entries,
            // Multi-replica posture stated at the point of enablement, not
            // only in the docs. Without the §4.2 broadcast channel,
            // invalidation is process-local, so on any deployment with more
            // than one replica the worst-case revocation latency for the
            // deployment is the TTL. See the `decision_cache` module docs.
            revocation_scope = if config.authz.decision_cache_broadcast_enabled {
                "cross-replica: invalidations fan out over AMQP (§4.2)"
            } else {
                "process-local: other replicas stay stale up to ttl_secs"
            },
            "AuthZ decision cache ENABLED (D7)"
        );
        // Observability for the cache's own bounds (plan H5 item 4): without
        // this there is no way to tell a cache holding its full
        // `max_entries` from one that is silently evicting, nor to see the
        // FIFO queue length that used to grow without bound. Cheap: one
        // snapshot per interval, off the request path.
        let cache = Arc::clone(cache);
        let interval_secs = std::env::var("AXIAM__AUTHZ__DECISION_CACHE_STATS_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);
        if interval_secs > 0 {
            tokio::spawn(async move {
                let mut ticker =
                    tokio::time::interval(std::time::Duration::from_secs(interval_secs));
                ticker.tick().await; // the first tick fires immediately
                loop {
                    ticker.tick().await;
                    let s = cache.snapshot();
                    let total = s.hits + s.misses;
                    tracing::info!(
                        entries = s.entries,
                        tenants = s.tenants,
                        queue_slots = s.queue_slots,
                        hits = s.hits,
                        misses = s.misses,
                        hit_rate_pct = if total == 0 {
                            0.0
                        } else {
                            (s.hits as f64 / total as f64) * 100.0
                        },
                        // §4.2: `trusted=false` / a rising `bypassed` means this
                        // replica cannot hear cross-replica invalidations and is
                        // evaluating everything against the database.
                        trusted = s.trusted,
                        bypassed = s.bypassed,
                        "AuthZ decision cache stats (D7)"
                    );
                }
            });
        }
    }

    // `amqp_signing_key` (SEC-022/SECHRD-08) is resolved further up, next to
    // the X1 reactor gate — the gate signs reactor events with the same master
    // key, and it is constructed before `AuthService`. §4.2's cross-replica
    // cache-invalidation publisher, below, signs with that same value.
    //
    // NEW-4: freshness skew window shared by both consumers.
    let amqp_replay_skew = config.amqp.replay_skew();

    // §4.2: cross-replica decision-cache invalidation over the existing
    // RabbitMQ transport. Requires BOTH the decision cache and the broadcast
    // switch; with either off this is `None` and every `invalidate_*` stays
    // local-only and infallible, exactly as documented before §4.2.
    //
    // `replica_id` is fresh per process: it names this replica's own fanout
    // queue and is stamped into every broadcast so the publisher recognises
    // (and ignores) its own echo.
    let invalidation_broadcaster: Option<Arc<dyn axiam_authz::InvalidationBroadcaster>> = match (
        config.authz.cross_replica_invalidation_enabled(),
        decision_cache.as_ref(),
        amqp.as_ref(),
        amqp_signing_key.as_ref(),
    ) {
        // Without the broker the broadcast is refused at boot (minimal profile),
        // so this arm is only ever reached with AMQP on.
        (true, Some(cache), Some(amqp), Some(amqp_signing_key)) => {
            let replica_id = uuid::Uuid::new_v4();
            let broadcast_skew = config.authz.decision_cache_broadcast_skew();

            // §13.4 observation 2: the publisher takes the *manager*, not a
            // channel. It opens a publisher-confirm channel lazily and reopens
            // it after any channel-level exception. Previously this was one
            // channel created here and held for the process lifetime, so a
            // single exception made every access-narrowing mutation 503 until
            // the process restarted — the consumer side was supervised with
            // backoff, this side was not.
            //
            // Publisher confirms remain mandatory: without them the broker
            // answers `NotRequested` and a broadcast the broker never accepted
            // would be reported as success — the exact silent failure §4.2
            // exists to remove.
            let publisher = Arc::new(axiam_amqp::CacheInvalidationPublisher::new(
                Arc::clone(amqp) as Arc<dyn axiam_amqp::PublisherChannelFactory>,
                amqp_signing_key.clone(),
                replica_id,
            ));

            // §13.4 observation 1: trust otherwise follows consumer liveness
            // alone, which a `queue.unbind` defeats silently. This tracks
            // whether our own broadcasts still come back to us.
            let liveness = Arc::new(axiam_amqp::InvalidationLiveness::new());

            // Consumer supervisor. The consumer marks the cache TRUSTED once it
            // is subscribed and UNTRUSTED on every exit path, so a replica that
            // cannot hear invalidations falls back to full DB evaluation
            // (correct, slower) instead of serving allows it can no longer
            // invalidate. It must NOT take the process down: that would turn a
            // broker blip into an availability outage, which is precisely the
            // trade §4.2 refuses to make.
            let consumer_amqp = Arc::clone(amqp);
            let consumer_cache = Arc::clone(cache);
            let consumer_key = amqp_signing_key.clone();
            let consumer_liveness = Arc::clone(&liveness);
            tokio::spawn(async move {
                let mut backoff = Duration::from_secs(1);
                let max_backoff = Duration::from_secs(30);
                loop {
                    match consumer_amqp.create_channel().await {
                        Ok(channel) => {
                            backoff = Duration::from_secs(1);
                            if let Err(e) = axiam_amqp::run_cache_invalidation_consumer(
                                channel,
                                Arc::clone(&consumer_cache),
                                consumer_key.clone(),
                                replica_id,
                                broadcast_skew,
                                Some(Arc::clone(&consumer_liveness)),
                            )
                            .await
                            {
                                tracing::error!(
                                    error = %e,
                                    "AuthZ cache-invalidation consumer failed — the decision \
                                     cache is now UNTRUSTED on this replica; reconnecting"
                                );
                            } else {
                                tracing::error!(
                                    "AuthZ cache-invalidation consumer exited — the decision \
                                     cache is now UNTRUSTED on this replica; reconnecting"
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                "Failed to (re)create the AuthZ cache-invalidation channel — the \
                                 decision cache stays UNTRUSTED on this replica; retrying"
                            );
                        }
                    }
                    // Belt and braces: the consumer's own Drop guard already did
                    // this, but a failure to even open a channel never reached it.
                    consumer_cache.set_trusted(false);
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            });

            // §13.4 observation 1 — liveness watchdog. Publishes a
            // self-addressed heartbeat on an interval and revokes cache trust if
            // our own heartbeats stop coming back, which is what a `queue.unbind`
            // looks like from in here.
            //
            // It is a ONE-WAY revoker by construction: it calls
            // `set_trusted(false)` and never `set_trusted(true)`. Trust is
            // granted in exactly one place — the consumer, on a successful
            // subscribe — so this watchdog can never resurrect trust on a
            // replica whose consumer has died.
            if let Some(interval) = config.authz.decision_cache_broadcast_heartbeat() {
                let hb_publisher = Arc::clone(&publisher);
                let hb_liveness = Arc::clone(&liveness);
                let hb_cache = Arc::clone(cache);
                let period = interval
                    .to_std()
                    .expect("heartbeat interval is a small positive duration");
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(period).await;

                        // A publish failure is NOT itself a reason to distrust:
                        // the staleness check below is the single decision point,
                        // and a failed publish simply means no heartbeat was sent,
                        // which that check will notice on its own if it persists.
                        if let Err(e) = hb_publisher.publish_heartbeat(&hb_liveness).await {
                            tracing::warn!(
                                error = %e,
                                "AuthZ cache-invalidation heartbeat could not be published"
                            );
                        }

                        if hb_liveness.is_stale(chrono::Utc::now(), interval)
                            && hb_cache.set_trusted(false)
                        {
                            // `set_trusted` returns the PREVIOUS value, so this
                            // logs once on the transition rather than every tick.
                            tracing::error!(
                                replica_id = %replica_id,
                                interval_secs = interval.num_seconds(),
                                misses = axiam_amqp::HEARTBEAT_MISS_THRESHOLD,
                                "AuthZ cache-invalidation heartbeats stopped returning — this \
                                 replica's queue is subscribed but appears no longer bound to the \
                                 fanout exchange, so invalidations would be silently dropped. The \
                                 decision cache is now UNTRUSTED here (uncached evaluation: \
                                 correct, slower). Check the broker bindings for the exchange."
                            );
                        }
                    }
                });
            }
            // No `else`: `decision_cache_broadcast_heartbeat()` returns `Some`
            // whenever broadcast is on (§15.2). Heartbeats are not disableable —
            // they are the only thing that detects a replica whose queue has been
            // unbound, and an earlier revision let one environment variable turn
            // that off with nothing but a warning.

            tracing::info!(
                replica_id = %replica_id,
                exchange = axiam_amqp::exchanges::AUTHZ_CACHE_INVALIDATE,
                skew_secs = config.authz.decision_cache_broadcast_skew_secs,
                heartbeat_secs = config.authz.decision_cache_broadcast_heartbeat_secs,
                "Cross-replica AuthZ decision-cache invalidation ENABLED (§4.2, fanout) — a \
                 mutation whose broadcast the broker does not confirm now returns 503, and this \
                 replica will not serve from cache while its invalidation consumer is down"
            );
            Some(publisher as Arc<dyn axiam_authz::InvalidationBroadcaster>)
        }
        _ => None,
    };

    // Build REST-facing authorization checker (D-01, D-02).
    let rest_authz: Arc<dyn axiam_api_rest::authz::AuthzChecker> = {
        let engine = axiam_authz::AuthorizationEngine::new(
            role_repo.clone(),
            permission_repo.clone(),
            resource_repo.clone(),
            scope_repo.clone(),
            group_repo.clone(),
        )
        .with_batch_config(
            config.authz.batch_strategy,
            config.authz.batch_max_concurrency,
        );
        let engine = match decision_cache.as_ref() {
            Some(cache) => engine.with_decision_cache(cache.clone()),
            None => engine,
        };
        Arc::new(match invalidation_broadcaster.as_ref() {
            Some(b) => engine.with_invalidation_broadcaster(b.clone()),
            None => engine,
        })
    };

    // G-3 (T23.3.4): a membership the directory mapping changes at sign-in
    // flushes that one subject's cached decisions locally and on every replica
    // (the same call the group-membership routes make), so a role that arrived
    // through a group the directory has since removed does not outlive the
    // sign-in that noticed. A failed broadcast is logged: the local cache is
    // already flushed and the TTL bounds the other replicas.
    {
        let authz = Arc::clone(&rest_authz);
        directory_membership_slot.set(Arc::new(move |tenant_id, user_id| {
            let authz = Arc::clone(&authz);
            Box::pin(async move {
                if let Err(error) = authz.invalidate_subject(tenant_id, user_id).await {
                    tracing::error!(
                        target: "axiam::directory",
                        %tenant_id,
                        %user_id,
                        %error,
                        "the decision-cache flush after a directory group mapping change \
                         could not be broadcast to the other replicas"
                    );
                }
            })
        }));
    }

    // The asynchronous authorization consumer and the external audit-ingestion
    // consumer are AMQP-only (G-8, D-59): without the broker nothing arrives to
    // be consumed. AXIAM's own audit events never touch AMQP — the audit
    // middleware writes SurrealDB directly — so they are unaffected.
    if let (Some(amqp), Some(amqp_signing_key)) = (&amqp, &amqp_signing_key) {
        // Spawn AMQP authorization consumer on a background task.
        // Uses a publisher channel because the consumer also publishes responses.
        let amqp_channel = amqp
            .create_publisher_channel()
            .await
            .expect("Failed to create AMQP authz publisher channel");
        let amqp_engine = {
            let engine = axiam_authz::AuthorizationEngine::new(
                role_repo.clone(),
                permission_repo.clone(),
                resource_repo.clone(),
                scope_repo.clone(),
                group_repo.clone(),
            )
            .with_batch_config(
                config.authz.batch_strategy,
                config.authz.batch_max_concurrency,
            );
            let engine = match decision_cache.as_ref() {
                Some(cache) => engine.with_decision_cache(cache.clone()),
                None => engine,
            };
            match invalidation_broadcaster.as_ref() {
                Some(b) => engine.with_invalidation_broadcaster(b.clone()),
                None => engine,
            }
        };
        let amqp_signing_key_clone = amqp_signing_key.clone();
        let authz_nonce_repo = amqp_nonce_repo.clone();
        tokio::spawn(async move {
            axiam_amqp::authz_consumer::start_authz_consumer(
                amqp_channel,
                amqp_engine,
                amqp_signing_key_clone,
                authz_nonce_repo,
                amqp_replay_skew,
            )
            .await;
            tracing::error!("AMQP authz consumer exited — shutting down process");
            std::process::exit(1);
        });

        // Create notification publisher (available for services to emit events).
        // CQ-B29: publisher created but not yet wired into app_data — see comment at
        // app_data registration site. Prefixed with _ to suppress unused-variable warning.
        let notif_channel = amqp
            .create_publisher_channel()
            .await
            .expect("Failed to create AMQP notification channel");
        let _notification_publisher = axiam_amqp::NotificationPublisher::new(notif_channel);

        // Spawn AMQP audit event consumer on a background task.
        let audit_channel = amqp
            .create_channel()
            .await
            .expect("Failed to create AMQP audit consumer channel");
        let amqp_audit_repo = audit_repo.clone();
        let audit_nonce_repo = amqp_nonce_repo.clone();
        let audit_signing_key = amqp_signing_key.clone();
        tokio::spawn(async move {
            axiam_amqp::audit_consumer::start_audit_consumer(
                audit_channel,
                amqp_audit_repo,
                audit_signing_key,
                audit_nonce_repo,
                amqp_replay_skew,
            )
            .await;
            tracing::error!("AMQP audit consumer exited — shutting down process");
            std::process::exit(1);
        });
    }

    // Outbound mail (password-reset, email-verify, notification rules, GDPR
    // export notices, CIBA approval mail). With the broker: a publisher channel
    // on `axiam.mail.outbound`. Without it (G-8, D-59): a bounded in-process
    // channel whose worker is spawned with the mail consumer below — or, with no
    // email encryption key, no worker at all and a publisher that refuses and
    // says why.
    let (mail_outbound_publisher, mail_queue) = match &amqp {
        Some(amqp) => {
            let mail_pub_channel = amqp
                .create_publisher_channel()
                .await
                .expect("Failed to create AMQP mail outbound publisher channel");
            (
                MailTransportPublisher::Amqp(MailOutboundPublisher::new(mail_pub_channel)),
                None,
            )
        }
        None if config.email_encryption_key.is_some() => {
            let (publisher, queue) = axiam_amqp::in_process_mail_channel();
            (MailTransportPublisher::InProcess(publisher), Some(queue))
        }
        None => (
            MailTransportPublisher::InProcess(axiam_amqp::InProcessMailPublisher::disabled()),
            None,
        ),
    };

    // Webhook delivery publisher (CORR-03/D-06/D-07) — used by emit() to
    // enqueue onto the webhook kind (the durable axiam.webhook queue with the
    // broker, the in-process dispatcher without), and by the consumer below to
    // schedule retries.
    let webhook_publisher = outbound.publisher(OutboundKind::Webhook).await;

    // Spawn the webhook consumer on a background task (CORR-03/D-06).
    // The webhook kind of the shared outbound dispatcher (D-36): the webhook
    // deliverer (WebhookDeliveryService::deliver_once behind the core
    // OutboundDeliverer port) is registered with the consumer loop, which with
    // the broker schedules retries natively via the retry-queue TTL+DLX
    // (D-07/D-08, bounded exponential backoff read from AXIAM__WEBHOOK__* —
    // D-20) and, either way, writes per-attempt/terminal audit records (D-09).
    // Later kinds (SSF push, outbound SCIM, CIBA ping) register their own
    // deliverer here.
    {
        let mut outbound_deliverers = OutboundDeliverers::new();
        outbound_deliverers
            .register(Arc::new(webhook_delivery.clone()))
            .expect("Failed to register the webhook deliverer");
        outbound.spawn_consumer(
            OutboundKind::Webhook,
            outbound_deliverers,
            audit_repo.clone(),
            OutboundRetryConfig::from_env_for(OutboundKind::Webhook),
        );
        tracing::info!("Webhook consumer spawned");
    }

    // G-5 / T23.5.3 — the SSF push kind of the same dispatcher (D-36): one
    // publisher channel for enqueueing events and for the consumer's TTL-delayed
    // retries, the outbox every producer submits to (D-48), and a consumer
    // supervisor that is the webhook one's copy (the duplication is known and
    // carried to F4). Retry env vars are `AXIAM__SSF_PUSH__*`.
    let ssf_publisher = outbound.publisher(OutboundKind::SsfPush).await;
    let ssf_outbox: Arc<dyn axiam_core::models::ssf::SsfOutbox> =
        Arc::new(axiam_oauth2::ssf_delivery::SsfOutboxService::new(
            ssf_event_buffer_repo.clone(),
            Arc::clone(&ssf_publisher),
        ));
    ssf_emitter.bind_outbox(Arc::clone(&ssf_outbox));
    {
        let mut ssf_deliverers = OutboundDeliverers::new();
        let ssf_deliverer = axiam_oauth2::ssf_delivery::SsfPushDeliverer::new(
            ssf_stream_repo.clone(),
            ssf_event_buffer_repo.clone(),
            config.auth.clone(),
            ssf_gate.clone(),
        );
        let ssf_deliverer = if opts.admit_private_networks_for_tests {
            ssf_deliverer.admitting_private_networks_for_tests()
        } else {
            ssf_deliverer
        };
        ssf_deliverers
            .register(Arc::new(ssf_deliverer))
            .expect("Failed to register the SSF push deliverer");
        outbound.spawn_consumer(
            OutboundKind::SsfPush,
            ssf_deliverers,
            audit_repo.clone(),
            OutboundRetryConfig::from_env_for(OutboundKind::SsfPush),
        );
        tracing::info!("SSF push consumer spawned");
    }

    // Notification rules reach the audit stream through this sink: the HTTP audit
    // middleware's worker (further down) feeds it every request's row, and, since
    // T23.6.3 (D-58), the SCIM consumer below feeds it the dispatcher's own rows
    // — a dead letter is not an HTTP request, so without that second path a rule
    // for `scim_delivery_failed` would match nothing in a running server.
    //
    // A rule mails each recipient once per (rule, event, window) — the rule's
    // `window_minutes` — and counts the rest, the next mail saying how many
    // (#551, T-117). The window is claimed in the datastore, so every replica
    // sees the same one. The SCIM consumer's dead letters keep their own gate
    // (one per target per hour, D-73) and are not windowed again.
    let notification_sink: Arc<dyn axiam_audit::AuditEventSink> =
        Arc::new(axiam_audit::NotificationSink::new(
            notification_rule_repo.clone(),
            axiam_db::SurrealNotificationWindowRepository::new(pool.handle_for_repo()),
            mail_outbound_publisher.clone(),
        ));

    // G-6 / T23.6.2 (D-57) — outbound SCIM provisioning, the third kind of the
    // same dispatcher: one publisher channel (enqueue, and the consumer's
    // TTL-delayed retries), the provisioner every repository reports to, and the
    // deliverer behind the same `spawn_outbound_consumer` as the other kinds.
    // Retry env vars are `AXIAM__SCIM_PUSH__*`. Targets' credentials are sealed
    // under the key webhook secrets use; without it the deliverer cannot open
    // one and a target cannot be stored (the management API is T23.6.4).
    // The deliverer is also the reconciliation job's way out to the downstream
    // (T23.6.3, D-58): one instance, so that both share its credential path and
    // its access-token cache.
    // The management API starts an on-demand run through the same instance
    // (T23.6.4, `POST /api/v1/scim-targets/{id}/reconcile`).
    let (scim_reconciliation, scim_reconcile_trigger): (
        Arc<dyn axiam_scim::outbound::ScimReconciliation>,
        Arc<dyn axiam_api_rest::state::bundles::ScimReconcileTrigger>,
    ) = {
        let scim_publisher = outbound.publisher(OutboundKind::ScimPush).await;
        let scim_retry = OutboundRetryConfig::from_env_for(OutboundKind::ScimPush);
        let scim_target_repo =
            axiam_db::SurrealScimTargetRepository::new(db_handle.clone(), webhook_enc_key);
        let bound = provisioning_sink.bind(Arc::new(axiam_scim::outbound::ScimProvisioner::new(
            scim_target_repo.clone(),
            Arc::clone(&scim_publisher),
        )));
        debug_assert!(bound, "the provisioning sink is bound exactly once");
        // The attempt ceiling is told to the deliverer so that the dead letter
        // the consumer makes of a last failed attempt is counted on the target
        // once; the backoff, so that the per-target breaker's window follows
        // the schedule the operator set (#550, T-414).
        let scim_deliverer = Arc::new(
            axiam_scim::outbound::ScimPushDeliverer::new(
                scim_target_repo,
                axiam_db::SurrealScimTargetLinkRepository::new(db_handle.clone()),
                axiam_db::SurrealScimTargetStateRepository::new(db_handle.clone()),
                user_repo.clone(),
                group_repo.clone(),
                Arc::clone(&scim_publisher),
            )
            .with_max_attempts(scim_retry.max_attempts)
            .with_backoff(
                Duration::from_millis(scim_retry.backoff_base_ms),
                Duration::from_millis(scim_retry.backoff_ceiling_ms),
            ),
        );
        let mut scim_deliverers = OutboundDeliverers::new();
        scim_deliverers
            .register(scim_deliverer.clone())
            .expect("Failed to register the SCIM push deliverer");
        outbound.spawn_consumer(
            OutboundKind::ScimPush,
            scim_deliverers,
            // The dispatcher's `scim_push.delivery_failed` row is the record of a
            // dead letter and what a `scim_delivery_failed` notification rule
            // matches (D-58): written through the notifying wrapper, which lets
            // one per target per hour reach the rules (W5 F4 review, T-418,
            // D-73) — every row is still appended.
            crate::scim_notification::scim_dead_letter_audit(
                audit_repo.clone(),
                notification_sink.clone(),
                tenant_repo.clone(),
                axiam_db::SurrealScimTargetStateRepository::new(db_handle.clone()),
            ),
            scim_retry,
        );
        tracing::info!("SCIM push consumer spawned");
        (
            scim_deliverer.clone(),
            Arc::new(axiam_scim::outbound::ReconcileLauncher::new(scim_deliverer)),
        )
    };

    // G-7 / T23.7.2 (D-65) — the CIBA ping kind of the same dispatcher: the
    // deliverer re-reads the request and the client, opens the request's sealed
    // notification credentials and POSTs through `guarded_fetch_no_redirect`.
    // Retry env vars are `AXIAM__CIBA_PING__*`. No new loop: the same
    // `spawn_outbound_consumer` as every other kind.
    {
        let mut ciba_ping_deliverers = OutboundDeliverers::new();
        ciba_ping_deliverers
            .register(Arc::new(axiam_oauth2::ciba_ping::CibaPingDeliverer::new(
                ciba_request_repo.clone(),
                oauth2_client_repo.clone(),
            )))
            .expect("Failed to register the CIBA ping deliverer");
        outbound.spawn_consumer(
            OutboundKind::CibaPing,
            ciba_ping_deliverers,
            audit_repo.clone(),
            OutboundRetryConfig::from_env_for(OutboundKind::CibaPing),
        );
        tracing::info!("CIBA ping consumer spawned");
    }

    // Spawn the mail consumer on a background task (D-14): the AMQP consumer
    // with the broker, the in-process worker without it (G-8, D-59).
    // Only spawned when AXIAM__AUTH__EMAIL_ENCRYPTION_KEY is present; otherwise
    // mail delivery is disabled and a warning was logged at startup (T-5-key-absent).
    if let Some(email_key) = config.email_encryption_key {
        let mail_email_config_repo =
            SurrealEmailConfigRepository::new(db_handle.clone(), email_key);
        let mail_audit_repo = audit_repo.clone();
        let mail_user_repo = user_repo.clone();
        let mail_template_repo = SurrealEmailTemplateRepository::new(db_handle.clone());
        // The tenant and organization the mail is about, so `{{tenant_name}}`
        // and `{{org_name}}` resolve. Every built-in template uses them and no
        // publisher supplied them, so activation mail went out reading
        // "activate your {{tenant_name}} account".
        let mail_tenant_repo = SurrealTenantRepository::new(db_handle.clone());
        let mail_org_repo = SurrealOrganizationRepository::new(db_handle.clone());
        if let Some(amqp) = &amqp {
            let mail_channel = amqp
                .create_channel()
                .await
                .expect("Failed to create AMQP mail consumer channel");
            tokio::spawn(async move {
                axiam_amqp::start_mail_consumer(
                    mail_channel,
                    mail_email_config_repo,
                    mail_audit_repo,
                    mail_user_repo,
                    mail_template_repo,
                    mail_tenant_repo,
                    mail_org_repo,
                )
                .await;
                tracing::error!("AMQP mail consumer exited — shutting down process");
                std::process::exit(1);
            });
        } else if let Some(queue) = mail_queue {
            axiam_amqp::spawn_in_process_mail_worker_default(
                queue,
                mail_email_config_repo,
                mail_audit_repo,
                mail_user_repo,
                mail_template_repo,
                mail_tenant_repo,
                mail_org_repo,
            );
        }
        tracing::info!("Mail consumer spawned");
    } else {
        // Error, not warn, and it names the consequence rather than the cause.
        //
        // Without this consumer nothing ever *delivers* a message: every
        // password reset, activation mail and GDPR export notice is published to
        // the queue and read by nobody. The API cannot tell the caller — the
        // reset endpoint answers a uniform `{"sent": true}` for every outcome by
        // design (D-15), so an operator with no mail has a working-looking API,
        // a silent inbox, and one line of startup output between them.
        tracing::error!(
            "Mail consumer NOT spawned — AXIAM__AUTH__EMAIL_ENCRYPTION_KEY is missing. \
             NO transactional mail will be delivered: password-reset links, \
             email-verification links and GDPR export notices are queued and \
             never sent. Set the key and restart."
        );
    }

    // X3 (D10): weekly FIDO MDS3 background refresh job. `should_spawn_refresh_job`
    // is the single gate — `mds_enabled: false` (the shipped default) or
    // `mds_refresh_interval_secs == 0` both mean this branch is never taken,
    // so a default deployment makes ZERO outbound MDS calls (see
    // `crate::mds_job`'s unit tests for the pure decision function
    // this reads, since `main()` itself cannot be linked from `tests/`).
    if crate::mds_job::should_spawn_refresh_job(&pki_config) {
        let mds_repo_for_job = mds_repo.clone();
        let mds_blob_url = pki_config.mds_blob_url.clone();
        let mds_blob_path = pki_config.mds_blob_path.clone();
        let mds_leaf_dns = pki_config.mds_leaf_dns.clone();
        let mds_interval_secs = pki_config.mds_refresh_interval_secs;
        let mds_ca_cache_for_job = Arc::clone(&attestation_ca_cache);
        tokio::spawn(async move {
            // Jitter the FIRST fire only, so replicas that start at the same
            // moment don't all hit the MDS BLOB source in the same second
            // (D10). `Uuid::new_v4` is already a dependency of this binary
            // (used for `replica_id` above) — no new crate for randomness.
            let jitter =
                crate::mds_job::jitter_secs(mds_interval_secs, uuid::Uuid::new_v4().as_u128());
            tracing::info!(
                interval_secs = mds_interval_secs,
                jitter_secs = jitter,
                blob_source = if mds_blob_path.is_some() {
                    "local_file"
                } else {
                    "network"
                },
                "FIDO MDS3 background refresh job starting (D10)"
            );
            tokio::time::sleep(Duration::from_secs(jitter)).await;

            let mut ticker = tokio::time::interval(Duration::from_secs(mds_interval_secs));
            loop {
                ticker.tick().await;
                // D11: every outcome is logged — `mds.refreshed` on success
                // (axiam_db::mds_ingest::ingest_blob) and `mds.refresh_failed`
                // on a fetch/verify failure (axiam_pki::mds's
                // `log_fetch_failure`, invoked from `ingest_from_url`/
                // `ingest_from_file`) — both fire from inside these calls
                // regardless of caller, so the admin-triggered
                // `POST /api/v1/mds/refresh` endpoint and this background job
                // share exactly one audit-emitting code path.
                let outcome = if let Some(path) = &mds_blob_path {
                    axiam_db::mds_ingest::ingest_from_file(&mds_repo_for_job, path, &mds_leaf_dns)
                        .await
                } else {
                    axiam_db::mds_ingest::ingest_from_url(
                        &mds_repo_for_job,
                        &mds_blob_url,
                        &mds_leaf_dns,
                        false, // production: never allow private/loopback targets
                    )
                    .await
                };

                match outcome {
                    // W2-D3: the CA-list cache only needs rebuilding when the
                    // set of known attestation roots actually changed — a
                    // no-op refresh or a rejected rollback left it untouched.
                    Ok(
                        o @ (axiam_db::mds_ingest::MdsIngestOutcome::Initial { .. }
                        | axiam_db::mds_ingest::MdsIngestOutcome::Replaced { .. }),
                    ) => {
                        tracing::info!(
                            outcome = ?o,
                            "FIDO MDS3 background refresh completed with new entries"
                        );
                        mds_ca_cache_for_job.invalidate();
                    }
                    Ok(o) => {
                        tracing::info!(outcome = ?o, "FIDO MDS3 background refresh completed (no change)");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "FIDO MDS3 background refresh failed");
                    }
                }
            }
        });
        tracing::info!(
            interval_secs = pki_config.mds_refresh_interval_secs,
            "FIDO MDS3 background refresh job spawned (D10)"
        );
    } else {
        tracing::info!(
            mds_enabled = pki_config.mds_enabled,
            refresh_interval_secs = pki_config.mds_refresh_interval_secs,
            "FIDO MDS3 background refresh job NOT spawned (disabled, or refresh interval is 0) \
             — zero outbound MDS calls"
        );
    }

    // Build gRPC services and spawn server on a background task.
    let grpc_addr = config.grpc.bind_address();
    // One knob for both listeners: the reloader walks every registered leaf,
    // so a separate gRPC interval would be a number with nothing to control.
    let config_tls_reload_interval_secs = config.server.tls.reload_interval_secs;
    let grpc_engine = {
        let engine = axiam_authz::AuthorizationEngine::new(
            role_repo.clone(),
            permission_repo.clone(),
            resource_repo.clone(),
            scope_repo.clone(),
            group_repo.clone(),
        )
        .with_batch_config(
            config.authz.batch_strategy,
            config.authz.batch_max_concurrency,
        );
        let engine = match decision_cache.as_ref() {
            Some(cache) => engine.with_decision_cache(cache.clone()),
            None => engine,
        };
        match invalidation_broadcaster.as_ref() {
            Some(b) => engine.with_invalidation_broadcaster(b.clone()),
            None => engine,
        }
    };
    // X1 / R2.3 — `ReactorAdminServiceImpl`'s own `AuthorizationEngine`.
    // `AuthorizationEngine` does not implement `Clone`, so it cannot share
    // `grpc_engine`'s instance; built identically (same repositories, same
    // decision cache, same invalidation broadcaster) so the two stay
    // coherent — see `start_grpc_server`'s `reactor_engine` doc comment.
    let grpc_reactor_engine = {
        let engine = axiam_authz::AuthorizationEngine::new(
            role_repo.clone(),
            permission_repo.clone(),
            resource_repo.clone(),
            scope_repo.clone(),
            group_repo.clone(),
        )
        .with_batch_config(
            config.authz.batch_strategy,
            config.authz.batch_max_concurrency,
        );
        let engine = match decision_cache.as_ref() {
            Some(cache) => engine.with_decision_cache(cache.clone()),
            None => engine,
        };
        match invalidation_broadcaster.as_ref() {
            Some(b) => engine.with_invalidation_broadcaster(b.clone()),
            None => engine,
        }
    };
    let grpc_reactor_repo = reactor_repo.clone();
    // `pool` is moved into `health_checker` before this point (see the
    // comment near `session_client_repo` above), so this reuses the
    // `audit_repo` instance built earlier from `pool.handle_for_repo()`
    // rather than calling `pool` again.
    let grpc_reactor_audit_repo = audit_repo.clone();
    let grpc_reactor_routing_invalidator = Arc::clone(&reactor_routing_invalidator);
    // SEC-101: read off the SAME gate the REST layer holds, so the gRPC and
    // REST reactor-admin surfaces cannot disagree about whether a registration
    // is acceptable. Refusing on one and accepting on the other would leave
    // the outage one `grpcurl` away.
    let grpc_reactor_dispatch_available = {
        use axiam_core::models::reactor::ReactorGate;
        reactor_gate.can_dispatch()
    };
    let grpc_user_repo = user_repo.clone();
    let grpc_auth_config = config.auth.clone();
    let grpc_config = config.grpc.clone();
    // SECHRD-03 gap closure (24-07 follow-up): thread the same shared
    // Surreal<C> handle used by the REST repositories so the gRPC shared
    // rate-limit pre-check can enforce the multi-replica bucket store
    // (GrpcSharedRateLimitLayer), not just the per-replica in-memory
    // governor.
    //
    // `start_grpc_server` builds its OWN `SharedRateLimitCounter` from this
    // handle (see `shared_rate_limit_counter` below for the REST one). Two
    // counters in one process is correct, not a bug: their bucket keys never
    // overlap — the gRPC layer only ever writes `grpc_authz:<ip>`, while the
    // REST middleware writes `<rest_endpoint>:<key_part>` — so neither can
    // fragment the other's local count. Both read the same
    // `AXIAM__RATE_LIMIT__SHARED*` env knobs, so they behave identically.
    let grpc_db = db_handle.clone();
    let grpc_batch_max_concurrency = config.authz.batch_max_concurrency;
    // A4/J10: hand the gRPC listener the SAME session repository the REST path
    // uses — same instance, therefore same validation cache, therefore every
    // REST-side invalidation hook (logout, password change, MFA reset, refresh
    // rotation) already serves gRPC and event-path revocation is immediate in
    // strict mode too. A freshly constructed repository here would have its own
    // cache that nothing invalidates, which is precisely the stale allow this
    // mode exists to prevent.
    let grpc_strict_revocation: Option<
        std::sync::Arc<dyn axiam_api_grpc::middleware::strict_revocation::SessionRevocationCheck>,
    > = if grpc_config.strict_revocation {
        Some(std::sync::Arc::new(session_repo.clone()))
    } else {
        None
    };
    // B1 — the gRPC listener shares the ONE crypto semaphore built above (and
    // handed to `AppState` below), not a second instance: the permit count
    // bounds peak concurrent ~19 MiB Argon2id arenas process-wide, and
    // `UserService/ValidateCredentials` verifies passwords just like REST login.
    let grpc_crypto_semaphore = Arc::clone(&crypto_semaphore);
    // The tenant-effective lockout policy, resolved from the SAME settings and
    // tenant repositories the REST login handler reads. Both transports check
    // credentials, so both must meter failures against the administrator's
    // configured `max_failed_login_attempts` — a gRPC path still counting to the
    // deployment default would be a brute-force budget the admin UI does not
    // show and cannot lower.
    let grpc_lockout_policy: Arc<dyn axiam_auth::lockout::LockoutPolicySource> =
        Arc::new(axiam_auth::lockout::SettingsLockoutPolicy::new(
            settings_repo.clone(),
            tenant_repo.clone(),
            axiam_auth::lockout::policy_from_config(&config.auth),
        ));
    // R-1 / T-234 — the gRPC listener's TLS, built HERE rather than inside
    // `axiam-api-grpc`, because the reloadable certificate resolver lives in
    // this crate (layer 8) and that one is layer 6.
    //
    // Built before the REST listener's config (further down, at the bind) on
    // purpose-free grounds — order does not matter. `shared_resolver` returns
    // the SAME `ReloadableCertResolver` to whichever of the two asks second,
    // whenever both name the same cert and key, which is the documented
    // topology ("there is no second certificate and there must not be", Pi
    // runbook §14.4). One `SIGHUP`, both listeners renewed.
    //
    // Panics on a set-but-unreadable path: T-233 rests on "a typo is a failed
    // boot", because the alternative is a port an operator believes is TLS
    // quietly serving plaintext.
    let grpc_tls = match crate::tls::grpc_tls_from_env() {
        Some(config) => {
            // The seam that lets an ACME renewal take effect without a
            // restart. Called on BOTH listeners' paths since R-1 — either can
            // be the only one with TLS on — and idempotent, so the REST bind
            // calling it again below is a no-op.
            crate::tls::spawn_leaf_reloader(config_tls_reload_interval_secs);
            axiam_api_grpc::GrpcTls::Rustls(config)
        }
        None => axiam_api_grpc::GrpcTls::Plaintext,
    };

    tokio::spawn(async move {
        if let Err(e) = start_grpc_server(
            grpc_addr,
            grpc_engine,
            grpc_user_repo,
            grpc_auth_config,
            &grpc_config,
            grpc_db,
            grpc_batch_max_concurrency,
            grpc_strict_revocation,
            grpc_reactor_engine,
            grpc_reactor_repo,
            grpc_reactor_audit_repo,
            grpc_reactor_routing_invalidator,
            grpc_reactor_dispatch_available,
            grpc_crypto_semaphore,
            grpc_lockout_policy,
            grpc_tls,
            deployment_profile,
        )
        .await
        {
            tracing::error!(error = %e, "gRPC server failed — shutting down process");
            std::process::exit(1);
        }
    });

    // `notification_sink` (built above, before the outbound consumers) is how
    // notification rules reach the audit stream. Without it
    // `NotificationDispatcher` is constructed nowhere and every rule an
    // administrator configures is inert — stored, listed by the API, shown in the
    // admin UI, and consulted by nothing.
    //
    // A request-audit row that is dropped (queue full) or fails to append is
    // counted, reported on `/health/jobs` and, when `AXIAM__GDPR_AUDIT_DLQ_FILE`
    // names a file, written to it (T-108). The GDPR records (the export and
    // erasure requests, the erasure sweep's, a tenant deletion's) take the same
    // file, so this is the one boot-time warning for all of them (#552).
    let dead_letter = DeadLetterWriter::from_env();
    if !dead_letter.is_configured() {
        tracing::warn!(
            env_var = DEAD_LETTER_FILE_ENV,
            "no audit dead-letter file is configured — an audit row the datastore refuses \
             (request-audit rows that are dropped or fail to append, and the GDPR export, \
             erasure and tenant-deletion records) is counted and logged but cannot be \
             recovered; point it at a volume that outlives the container"
        );
    }
    let audit_middleware = AuditMiddleware::spawn_configured(
        audit_repo.clone(),
        Some(notification_sink),
        dead_letter,
        axiam_audit::middleware::CHANNEL_CAPACITY,
    );
    // A handle kept outside the App factory closure, which takes ownership of
    // the middleware. Cloning shares the shutdown flag — see
    // `AuditMiddleware::begin_shutdown` — so this is the same worker, reachable
    // after `http_server.run()` returns.
    let audit_shutdown = audit_middleware.clone();

    // Audit retention (T-119). Resolved here, and LOGGED either way: a policy
    // that silently deletes records is worse than one that deletes none, so
    // the window in force has to be visible in the startup log rather than
    // inferable only from the config file.
    let audit_retention = match config.audit_retention_days {
        0 => {
            tracing::warn!(
                "audit retention is DISABLED (AXIAM__AUDIT_RETENTION_DAYS=0) — audit_log will \
                 grow without bound; archive and prune out-of-band, or set a retention in days"
            );
            None
        }
        days => {
            tracing::info!(
                retention_days = days,
                "audit retention active — entries older than this are pruned by the cleanup sweep"
            );
            // i64 for chrono; the cast is safe for any value an operator could
            // plausibly mean, and saturating rather than wrapping means a
            // nonsense value becomes "effectively never" instead of a negative
            // duration that would prune everything ever written.
            Some(chrono::Duration::days(days.min(i64::MAX as u64) as i64))
        }
    };

    // T-129: one tracker, shared by the sweep loop (which writes) and
    // `AppState` (which reads for `GET /health/jobs`). Registering the jobs
    // up front matters: a sweep that has never run once must still appear,
    // because "absent from the list" and "never executed" are the same
    // silence this is meant to break.
    let job_health =
        crate::job_health::JobHealth::new(Duration::from_secs(config.cleanup_interval_secs))
            .with_request_audit(audit_middleware.loss());
    // The list is `job_health::SWEEP_JOBS`, which a test checks against what the
    // cleanup loop records.
    for job in crate::job_health::SWEEP_JOBS {
        job_health.register(job);
    }

    // Spawn the periodic cleanup task (D-09, D-24).
    // Shutdown channel: main sends `true` after HttpServer returns on SIGTERM.
    let (cleanup_shutdown_tx, cleanup_shutdown_rx) = tokio::sync::watch::channel(false);
    // Mail publisher for export-ready notifications from the cleanup task.
    let cleanup_mail_publisher: Arc<MailTransportPublisher> = Arc::new(match &amqp {
        Some(amqp) => {
            let cleanup_mail_pub_channel = amqp
                .create_publisher_channel()
                .await
                .expect("Failed to create AMQP cleanup mail channel");
            MailTransportPublisher::Amqp(MailOutboundPublisher::new(cleanup_mail_pub_channel))
        }
        // The same in-process channel the rest of the process publishes to.
        None => mail_outbound_publisher.clone(),
    });
    let cleanup_federation_link_repo =
        axiam_db::SurrealFederationLinkRepository::new(db_handle.clone());
    let cleanup = cleanup::CleanupTask::new(
        Arc::new(assertion_replay_repo.clone()),
        Arc::new(federation_login_state_repo.clone()),
        Arc::new(sso_handoff_code_repo.clone()),
        Arc::new(saml_pending_repo.clone()),
        Arc::new(saml_participant_repo.clone()),
        Arc::new(saml_logout_run_repo.clone()),
        Arc::new(amqp_nonce_repo.clone()),
        Arc::new(user_repo.clone()),
        Arc::new(auth_service.clone()),
        Arc::new(audit_repo.clone()),
        Arc::new(account_deletion_repo.clone()),
        Arc::new(erasure_proof_repo.clone()),
        Arc::new(cleanup_federation_link_repo),
        Arc::new(role_repo.clone()),
        Arc::new(group_repo.clone()),
        Arc::new(webauthn_cred_repo.clone()),
        Arc::new(password_history_repo.clone()),
        Arc::new(export_job_repo.clone()),
        Arc::new(consent_repo.clone()),
        Arc::new(tenant_repo.clone()),
        Arc::new(session_repo.clone()),
        cleanup_mail_publisher,
        config.gdpr_pseudonym_pepper,
        config.email_encryption_key,
        Duration::from_secs(config.cleanup_interval_secs),
        audit_retention,
        revoked_session_repo,
        // T21.4 — the dynamic-registration sweeps.
        Arc::new(oauth2_client_repo.clone()),
        Arc::new(oauth2_registration_token_repo.clone()),
        Arc::new(settings_repo.clone()),
        job_health.clone(),
        cleanup_shutdown_rx,
    )
    // G-3 (T23.3.5, D-31): the directory sync job runs on this scheduler, last in
    // each tick, one tenant at a time. There is no multi-replica guard (none of
    // the sweeps has one): every replica runs it, and every write is idempotent
    // or a compare-and-set.
    .with_directory_sync(Arc::new(axiam_directory::DirectorySync::new(
        directory_config_repo.clone(),
        Arc::clone(&directory_authenticator),
        user_repo.clone(),
        session_repo.clone(),
        directory_sync_refresh_repo,
        directory_sync_state_repo.clone(),
        Arc::clone(&directory_group_mapper) as _,
        Arc::clone(&directory_audit_sink) as _,
    )
    // G-5 (D-52): a directory deactivation is an SSF `account-disabled`.
    .with_ssf_sink(ssf_account_sink.clone())))
    // G-6 (T23.6.3, D-58): the nightly SCIM reconciliation, last in each tick.
    .with_scim_reconciliation(scim_reconciliation)
    // G-5 (T23.5.3): the buffer's seven-day sweep, and the `account-purged` of an
    // erasure.
    .with_ssf(
        Arc::new(ssf_event_buffer_repo.clone()),
        Arc::new(ssf_step_up_repo.clone()),
        ssf_account_sink.clone(),
    )
    // G-7 (T23.7.1): the CIBA pending-request expiry.
    .with_ciba(Arc::new(ciba_request_repo.clone()));
    let cleanup_handle = tokio::spawn(cleanup.run());

    // SECHRD-03 / D-01a (H2 performance fix): ONE write-behind shared
    // rate-limit counter for the whole process.
    //
    // It must be built here — outside the `HttpServer::new` worker closure —
    // and only ever CLONED into `AppState` (a cheap `Arc` clone). The counter
    // accumulates each replica's unflushed increments in process memory, so
    // one instance per worker would fragment the local count and weaken the
    // effective limit by up to the worker count. Its single background
    // flusher is spawned here too, on this runtime.
    //
    // Config (identical knobs for the gRPC listener, read the same way):
    // `AXIAM__RATE_LIMIT__SHARED` (on|off, default on) and
    // `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` (default 1000, clamped
    // 50..=60000). No configured *limit* is affected.
    let shared_rate_limit_counter = axiam_db::SharedRateLimitCounter::from_env(Arc::new(
        axiam_db::SurrealRateLimitBucketRepository::new(db_handle.clone()),
    ));

    // I3: arm the machine-traffic throttling advisory ONLY when the shipped
    // `internet` defaults are the active posture AND the operator has not
    // pinned any machine limit by hand. Anyone who deliberately selected
    // `gateway`/`mesh`, or set the numbers themselves, has already made this
    // sizing decision and does not need to be told about it. Riding on the
    // write-behind counter's existing flusher — no extra task, no extra
    // timer.
    if arm_machine_traffic_advisory {
        shared_rate_limit_counter.arm_machine_traffic_advisory();
    }

    // QUAL-01: single composition root — one AppState<C> built here and
    // registered once per worker below, replacing the ~49 individual
    // `.app_data(web::Data::new(...))` calls this closure used to make.
    let app_state = AppState {
        authz_config: config.authz.clone(),
        auth_config: auth_config.clone(),
        db: db_handle.clone(),
        health_checker: health_checker.clone(),
        // T-129: the same tracker the cleanup loop writes to.
        job_health: std::sync::Arc::new(job_health.clone()),
        deployment_profile,
        audit_repo: audit_repo.clone(),
        org_repo: org_repo.clone(),
        tenant_repo: tenant_repo.clone(),
        // A2/J2: refresh rotation reads the tenant only for `organization_id`,
        // an immutable field — cache it rather than pay a round trip per
        // refresh (see axiam_api_rest::tenant_org_cache).
        tenant_org_cache: Arc::new(Default::default()),
        // The authorize path reads a client once more only to learn
        // `managed_by`, which never changes for a `client_id` — cache it
        // (see axiam_api_rest::client_managed_by_cache).
        client_managed_by_cache: Arc::new(Default::default()),
        user_repo: user_repo.clone(),
        group_repo: group_repo.clone(),
        role_repo: role_repo.clone(),
        permission_repo: permission_repo.clone(),
        resource_repo: resource_repo.clone(),
        scope_repo: scope_repo.clone(),
        scim_token_repo: scim_token_repo.clone(),
        service_account_repo: service_account_repo.clone(),
        auth_service: auth_service.clone(),
        mfa_method_service: mfa_method_service.clone(),
        session_repo: session_repo.clone(),
        session_validator: session_validator.clone(),
        refresh_token_repo: handler_refresh_token_repo.clone(),
        password_history_repo: password_history_repo.clone(),
        oauth2_client_repo: oauth2_client_repo.clone(),
        oauth2_registration_token_repo: oauth2_registration_token_repo.clone(),
        // The device endpoints size their own governors from this (see
        // `server.rs`), so the handlers need the same numbers the middleware
        // was built from — not a second default that could disagree.
        rate_limit_cfg: config.rate_limit.clone(),
        settings_repo: settings_repo.clone(),
        opaque_credential_repo: opaque_credential_repo.clone(),
        opaque_setup_repo: opaque_setup_repo.clone(),
        // `None` unless *both* OPAQUE keys are set, which makes the OPAQUE
        // endpoints answer 503 rather than silently leaving clients on
        // password login — see `AuthConfig::opaque_session_key`.
        opaque_server: match (config.auth.opaque_session_key, config.auth.opaque_setup_key) {
            (Some(session_key), Some(setup_key)) => Some(axiam_auth::OpaqueServer::new(
                axiam_auth::OpaqueServerKeys {
                    session_key,
                    setup_key,
                },
            )),
            _ => None,
        },
        http_client: http_client.clone(),
        jwks_cache: jwks_cache.clone(),
        crypto_semaphore: Arc::clone(&crypto_semaphore),
        shared_rate_limit: shared_rate_limit_counter.clone(),
        pki: bundles::PkiState {
            ca_service: ca_service.clone(),
            cert_service: cert_service.clone(),
            cert_repo: cert_repo.clone(),
            ca_cert_repo: SurrealCaCertificateRepository::new(db_handle.clone()),
            pgp_service: pgp_service.clone(),
            device_auth_service: device_auth_service.clone(),
            trust_anchor_reloader: trust_anchor_reloader.clone(),
        },
        webauthn: bundles::WebauthnState {
            webauthn_service: webauthn_service.clone(),
            webauthn_credential_repo: webauthn_cred_repo.clone(),
            webauthn_attestation_policy_repo: webauthn_attestation_policy_repo.clone(),
            mds_repo: mds_repo.clone(),
            attestation_metadata_source: attestation_metadata_source.clone(),
            attestation_ca_cache: Arc::clone(&attestation_ca_cache),
            pki_config: pki_config.clone(),
        },
        gdpr: bundles::GdprState {
            consent_repo: consent_repo.clone(),
            account_deletion_repo: account_deletion_repo.clone(),
            export_job_repo: export_job_repo.clone(),
            erasure_proof_repo: erasure_proof_repo.clone(),
        },
        mail: bundles::MailState {
            mail_outbound_publisher: Arc::new(mail_outbound_publisher.clone())
                as Arc<dyn axiam_api_rest::state::DynMailPublisher>,
            email_config_repo: email_config_repo.clone(),
            email_encryption_key: config.email_encryption_key,
            email_verification_service: email_verification_service.clone(),
            password_reset_service: password_reset_service.clone(),
        },
        events: bundles::EventsState {
            reactor_repo: reactor_repo.clone(),
            // X1 — the REST-side hooks (`user.pre_create`, `user.pre_update`,
            // `grant.pre_assign`) call the same gate the two services hold.
            reactor_gate: Arc::clone(&reactor_gate),
            reactor_routing_invalidator: Some(Arc::clone(&reactor_routing_invalidator)),
            webhook_repo: webhook_repo.clone(),
            webhook_delivery: webhook_delivery.clone(),
            // CQ-B22: hand the delivery publisher to AppState so handlers can
            // dispatch domain events via `state.emit_webhook(...)`.
            webhook_publisher: Some(Arc::clone(&webhook_publisher)),
            notification_rule_repo: notification_rule_repo.clone(),
        },
        oauth2: bundles::OAuth2State {
            authorize_service: authorize_service.clone(),
            token_service: token_service.clone(),
            device_authorization_service: device_authorization_service.clone(),
            ciba_service: ciba_service.clone(),
            // G-7 (T23.7.2) — a stored request reaches its user as one mail on
            // the mail queue, linking to the approval page under the issuer's
            // origin; the caller throttles it to three a minute per user.
            ciba_notifier: Arc::new(axiam_oauth2::ciba_notifier::CibaMailNotifier::new(
                user_repo.clone(),
                tenant_repo.clone(),
                mail_outbound_publisher.clone(),
                &config.auth.oauth2_issuer_url,
            )),
            token_exchange_service: token_exchange_service.clone(),
            par_service: par_service.clone(),
            // X2 — UMA 2.0. The repository rather than an assembled service,
            // because the service also needs the `AuthzChecker`, which is
            // registered as its own `web::Data`; handlers compose the two with
            // `AppState::uma_service`.
            permission_ticket_repo: permission_ticket_repo.clone(),
            rpt_max_lifetime_secs: axiam_core::models::uma::DEFAULT_RPT_MAX_LIFETIME_SECS,
            session_client_repo: session_client_repo.clone(),
            device_grant_repo: device_grant_repo.clone(),
            proof_replay_repo: proof_replay_repo.clone(),
            oauth2_jwks_cache: oauth2_jwks_cache.clone(),
            oauth2_jwks_cache_config: config.oauth2.clone(),
            // T21.5 — built once here, cloned into every worker with the
            // rest of `AppState`; see `OAuth2State::cimd_cache`.
            cimd_cache: axiam_oauth2::cimd::ClientMetadataCache::new(),
        },
        federation: bundles::FederationState {
            federation_config_repo: federation_config_repo.clone(),
            federation_link_repo: federation_link_repo.clone(),
            federation_login_state_repo: federation_login_state_repo.clone(),
            sso_handoff_code_repo: sso_handoff_code_repo.clone(),
            assertion_replay_repo: assertion_replay_repo.clone(),
            oidc_federation_service: oidc_federation_service.clone(),
            #[cfg(feature = "saml")]
            saml_federation_service: saml_federation_service.clone(),
        },
        // G-3 (T23.3.8): the management routes share the sign-in path's
        // configuration repository (and so its encryption key) and its
        // connector — the address policy a write is checked against is the
        // policy every connection is checked against.
        directory: bundles::DirectoryState {
            config_repo: directory_config_repo.clone(),
            sync_state_repo: directory_sync_state_repo,
            client: Arc::clone(directory_authenticator.client()),
        },
        saml_idp: saml_idp_state,
        // G-5 / T23.5.2, T23.5.3 — the stream registry seals push credentials under
        // the key webhook secrets use (D-49); the outbox routes every produced
        // event to the dispatcher or the poll buffer (D-48).
        ssf: bundles::SsfState {
            stream_repo: ssf_stream_repo,
            buffer_repo: ssf_event_buffer_repo,
            step_up_repo: ssf_step_up_repo,
            outbox: Some(ssf_outbox),
            emitter: ssf_emitter,
            session_sink: ssf_session_sink,
            account_sink: ssf_account_sink,
            poll_waiters: Arc::default(),
            gate: ssf_gate,
        },
        // G-6 / T23.6.4 — the target registry's management routes seal the
        // credential under the same key the deliverer opens it with.
        scim_targets: bundles::ScimTargetsState {
            target_repo: axiam_db::SurrealScimTargetRepository::new(
                db_handle.clone(),
                webhook_enc_key,
            ),
            state_repo: axiam_db::SurrealScimTargetStateRepository::new(db_handle.clone()),
            reconcile: Some(scim_reconcile_trigger),
        },
    };

    // X4 — accept subject tokens from trusted external IdPs.
    //
    // Enabled here rather than at construction because it needs the OIDC
    // federation service, which is itself conditional on the federation
    // encryption key. Nothing changes for a deployment that has not switched
    // `token_exchange.enabled` on for any provider: the path exists, and every
    // issuer fails to resolve.
    let mut app_state = app_state;
    if app_state.enable_external_token_exchange() {
        tracing::info!(
            "X4: external-IdP token exchange is available (per-provider trust \
             still decides whether any issuer is accepted)"
        );
    } else {
        tracing::info!(
            "X4: external-IdP token exchange is OFF — no OIDC federation service \
             (AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY is unset)"
        );
    }
    let app_state = app_state;

    let http_server = HttpServer::new(move || {
        let rl = rate_limit_cfg.clone();
        App::new()
            .wrap(SecurityHeadersMiddleware)
            // F4 P23W3-03 (T-325): the default builder's field set, with query
            // values (a SAML handle, `RelayState`, `state`, a reset token) and
            // `{token}` path segments redacted from `http.target`.
            .wrap(TracingLogger::<RedactingRootSpanBuilder>::new())
            .wrap(audit_middleware.clone())
            .wrap(build_cors(&server_config.cors_allowed_origins))
            // web::Data::new wraps rest_authz (Arc<dyn AuthzChecker>) to produce
            // web::Data<Arc<dyn AuthzChecker>>, matching the AuthzData type alias used
            // by every RBAC-protected handler. web::Data::from would unwrap the Arc and
            // register it as web::Data<dyn AuthzChecker>, causing "Requested application
            // data is not configured correctly" 500s on every admin endpoint.
            //
            // QUAL-01: this is 1 of 3 dependencies that stay registered OUTSIDE
            // AppState<C> alongside the single AppState registration below — see
            // `axiam_api_rest::state` module docs for the full rationale (Rust
            // generics/dyn-safety: 118 handler call sites use `AuthzData` directly,
            // `AuthenticatedUser`'s non-generic `FromRequest` impl needs
            // `AuthConfig`/`SessionValidator` without knowing `C`, and
            // `axiam-audit::AuditMiddleware` — a different crate wrapping the whole
            // App — independently looks up `web::Data<AuthConfig>`).
            .app_data(web::Data::new(rest_authz.clone()))
            .app_data(web::Data::new(auth_config.clone()))
            .app_data(web::Data::new(session_validator.clone()))
            .app_data(web::Data::new(dpop_replay_guard.clone()))
            .app_data(web::Data::new(tenant_scope_resolver.clone()))
            .app_data(web::Data::new(principal_reach_resolver.clone()))
            .app_data(web::Data::new(scim_token_resolver.clone()))
            // QUAL-01: single composition root — every other REST handler
            // dependency (repos, services, the 4 hoisted QUAL-07 singletons)
            // lives on this one AppState<C> value (see above).
            .app_data(web::Data::new(app_state.clone()))
            .configure(health_routes::<C>)
            .configure(|cfg| {
                register_api_v1_routes_with::<C>(cfg, &rl, route_options)
            })
            // R3.1 (B4): SCIM 2.0 provisioning, mounted under /scim/v2.
            // R5.2: hand it the SAME resolved RateLimitConfig the /api/v1
            // wiring gets, so `AXIAM__RATE_LIMIT__SCIM_PER_MIN` (and the
            // posture log line) actually govern the provisioning surface.
            .configure(|cfg| {
                axiam_scim::scim_routes_with_rate_limits::<C>(cfg, &rl)
            })
            .configure(openapi_routes)
    })
    // D3 native mTLS: lift the rustls-VERIFIED client certificate off the TLS
    // connection into the per-connection extensions so cert-auth handlers read
    // the verified peer cert (via `HttpRequest::conn_data`) instead of a
    // spoofable proxy header. Only fires on the rustls bind with client-auth
    // enabled; on plaintext / server-auth-only connections there is no peer cert
    // and nothing is inserted (backward compatible).
    .on_connect(|conn, ext| {
        use actix_tls::accept::rustls_0_23::TlsStream;
        use actix_web::rt::net::TcpStream;
        if let Some(tls) = conn.downcast_ref::<TlsStream<TcpStream>>() {
            let (_io, session) = tls.get_ref();
            if let Some(certs) = session.peer_certificates()
                && let Some(leaf) = certs.first()
            {
                // Whether this certificate chained to a configured anchor
                // cannot be read off the handshake result — rustls's
                // `ClientCertVerified` carries no payload and the verifier is
                // given no connection handle to key a side channel on — so it
                // is re-derived here, where the peer chain is in hand. Free
                // under every client-auth policy except `optional_self_signed`;
                // see `crate::tls::peer_certificate_trust`.
                let trust = crate::tls::peer_certificate_trust(leaf, &certs[1..]);
                match axiam_api_rest::VerifiedClientCert::from_der(leaf.as_ref(), trust) {
                    Ok(vc) => {
                        ext.insert(vc);
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "failed to parse verified client certificate; \
                             cert-mapped identity will be unavailable for this connection"
                        );
                    }
                }
            }
        }
    });

    // G8/B2: optional HTTP/2 window tuning for the TLS bind. Unset keys are
    // never forwarded to actix, so the default build is bit-identical to
    // before. See `crate::tls::Http2Tuning`.
    let h2_tuning = crate::tls::Http2Tuning::load()?;
    let mut http_server = http_server;
    if let Some(size) = h2_tuning.initial_stream_window_size {
        http_server = http_server.h2_initial_window_size(size);
    }
    if let Some(size) = h2_tuning.initial_connection_window_size {
        http_server = http_server.h2_initial_connection_window_size(size);
    }

    // I5: set TCP_NODELAY explicitly on accepted connections. actix-web leaves
    // this unset by default, which means "do not touch the socket option" — so
    // Nagle's algorithm stayed enabled on the REST listener while the gRPC
    // listener (tonic, `tcp_nodelay: true` by default) has always had it off.
    // Nagle interacting with Linux's 40 ms delayed-ACK timer is the leading
    // explanation for the flat ~43 ms TLS client-credentials plateau observed
    // in benchmark run 4. `AXIAM__SERVER__TCP_NODELAY=false` restores the
    // previous behaviour so run 5 can A/B it.
    let tcp_nodelay = config.server.tcp_nodelay;
    http_server = http_server.tcp_nodelay(tcp_nodelay);
    tracing::info!(
        tcp_nodelay,
        "TCP_NODELAY configured on the REST listener (I5)"
    );

    // Bind plaintext (proxy-terminated TLS, the default) or, when
    // `server.tls.enabled`, bind with rustls restricted to TLS 1.3 (F-04 /
    // ASVS V9.1.2). `build_rustls_server_config` fails fast on any cert/key
    // misconfiguration, so a misconfigured TLS server never starts insecurely.
    let http_server = if tls_config.enabled {
        // Also fails fast on `http2=false`, which the actix rustls bind cannot
        // honour (it re-prepends h2 to ALPN) — see `crate::tls`.
        let rustls_config = crate::tls::build_rustls_server_config(&tls_config)?;
        // The seam that lets an ACME renewal take effect without a restart.
        // Spawned only on the TLS path: with no listener there is no leaf to
        // reload, and a SIGHUP handler that logs "nothing to reload" on a
        // plaintext deployment is noise an operator has to learn to ignore.
        crate::tls::spawn_leaf_reloader(tls_config.reload_interval_secs);
        tracing::info!(
            reload_interval_secs = tls_config.reload_interval_secs,
            bind = %bind_addr,
            alpn = "h2,http/1.1",
            resumption = "tls1.3-tickets",
            early_data = false,
            h2_stream_window = h2_tuning.effective_stream_window(),
            h2_connection_window = h2_tuning.effective_connection_window(),
            h2_tuning_default = h2_tuning.is_default(),
            "Direct TLS enabled — negotiating TLS 1.3 only"
        );
        http_server.bind_rustls_0_23(&bind_addr, rustls_config)?
    } else if let Some(listener) = opts.rest_listener.take() {
        // A listener the caller already bound (an embedded boot, a test).
        http_server.listen(listener)?
    } else {
        http_server.bind(&bind_addr)?
    };
    let http_server = http_server.run();

    // The minimal profile: a lost lease stops this instance through the same
    // orderly path as a SIGTERM — no new connections, in-flight requests
    // finished, then the teardown below — instead of ending the process
    // wherever it is, which lost every audit row still queued (T23.8.2,
    // P23W5-A1). The backstop runs only if that overruns its deadline.
    let lease_loss_stop = lease_renewal.as_ref().map(|_| {
        let handle = http_server.handle();
        profile::spawn_lease_loss_stop(
            lease_lost.clone(),
            move || {
                // `stop` sends its command eagerly; the returned future only
                // reports completion, which the teardown below observes.
                tokio::spawn(handle.stop(true));
            },
            opts.lease_timing.lost_stop_deadline,
            Arc::clone(&opts.lease_lost_backstop),
        )
    });

    http_server.await?;
    let lease_was_lost = *lease_lost.borrow();

    // An orderly stop gives the minimal profile's lease up, so a successor (a
    // rolling update's next instance) does not wait out the TTL. A lost lease
    // is not ours to release (and the release is conditional on the holder).
    if let Some(renewal) = lease_renewal {
        renewal.abort();
        if !lease_was_lost
            && let Err(e) = axiam_db::SurrealMinimalProfileLeaseRepository::new(db_handle.clone())
                .release(&instance_id.to_string())
                .await
        {
            tracing::warn!(error = %e, "could not release the minimal-profile lease");
        }
    }

    // Signal the cleanup task first, so it winds down while the audit queue
    // drains; it finishes the tick it is in, so an erasure and its
    // `gdpr.user_pseudonymized` row are not separated.
    let _ = cleanup_shutdown_tx.send(true);

    // Write what the audit middleware still holds before the runtime goes
    // (T23.8.2). `drain` also tells the worker the close is the orderly one,
    // so a clean stop does not log `Audit worker channel closed` at WARN — see
    // `AuditMiddleware::begin_shutdown` for why that matters. Bounded: a
    // datastore that never answers cannot hold the stop up.
    if !audit_shutdown.drain(AUDIT_DRAIN_DEADLINE).await {
        tracing::error!(
            deadline_secs = AUDIT_DRAIN_DEADLINE.as_secs_f64(),
            "audit entries still queued at shutdown could not be written in time — \
             they are lost (see the `Failed to write audit log entry` warnings above)"
        );
    }

    if let Err(e) = cleanup_handle.await {
        tracing::warn!(error = ?e, "cleanup task join error");
    }

    // The teardown is done: disarm the lost-lease backstop.
    if let Some(stop) = lease_loss_stop {
        stop.abort();
    }
    if lease_was_lost {
        return Err(std::io::Error::other(
            "the minimal-profile lease was taken by another instance; this instance stopped \
             in order and exits non-zero (AXIAM__AMQP__ENABLED=false is single-instance by \
             definition)",
        ));
    }

    Ok(())
}

/// How long the teardown waits for the audit middleware's queue to be written
/// (T23.8.2). The queue holds at most 4 096 entries; written one at a time
/// against a healthy datastore that is well under this.
const AUDIT_DRAIN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

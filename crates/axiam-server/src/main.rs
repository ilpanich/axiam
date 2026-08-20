//! AXIAM Server — Application entry point.

use axiam_server::cleanup;

// D9 (memory-retention experiment): opt-in jemalloc global allocator.
//
// Default build uses the platform allocator (glibc malloc in the release
// container image) — unchanged. Enabling the `jemalloc` cargo feature
// (`cargo build --release -p axiam-server --features jemalloc`) swaps the
// process-wide allocator to jemalloc, which is a candidate fix for the
// observed RSS-retention issue: server RSS never returns to baseline after a
// login burst (~93 -> ~646 MiB permanently, see
// claude_dev/memory-retention-experiment.md). B1 already bounds the
// concurrency *peak* via the Argon2 semaphore; this experiment targets the
// *retention* — glibc malloc is known to keep freed arenas mapped rather
// than returning pages to the OS, while jemalloc's decay-based purging
// actively `madvise`s freed dirty/muzzy pages back to the kernel.
//
// Decay tuning is deliberately NOT hardcoded here: jemalloc's dirty/muzzy
// page decay times are configured at process startup via the `MALLOC_CONF`
// (or tikv-jemallocator's `_RJEM_MALLOC_CONF`) environment variable, e.g.
//   MALLOC_CONF=dirty_decay_ms:1000,muzzy_decay_ms:0
// which returns freed pages to the OS within ~1s of a burst subsiding
// instead of jemalloc's default ~10s decay. See the experiment note for the
// full rationale and the A/B measurement procedure (pending laptop
// hardware — this feature is default-off so it ships safely un-measured).
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer, web};
use axiam_amqp::{AmqpConfig, AmqpManager, MailOutboundPublisher, WebhookPublisher};
use axiam_api_grpc::{GrpcConfig, start_grpc_server};
use axiam_api_rest::middleware::security_headers::SecurityHeadersMiddleware;
use axiam_api_rest::state::AppState;
use axiam_api_rest::state::bundles;
use axiam_api_rest::webhook_consumer::{WebhookRetryConfig, start_webhook_consumer};
use axiam_api_rest::{
    HealthChecker, RateLimitConfig, ServerConfig, build_cors, health_routes, openapi_routes,
    register_api_v1_routes,
};
use axiam_audit::AuditMiddleware;
use axiam_auth::config::AuthConfig;
use axiam_auth::{
    AttestationCaCache, AuthService, EmailVerificationService, MfaMethodService,
    PasswordResetService, WebauthnService,
};
use axiam_core::repository::{
    OrganizationRepository, Pagination, ServiceAccountRepository, TenantRepository,
};
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
    SurrealTenantRepository, SurrealUserRepository, SurrealWebauthnAttestationPolicyRepository,
    SurrealWebauthnCredentialRepository, SurrealWebhookRepository,
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
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

/// Returns the default cleanup interval in seconds (5 minutes).
fn default_cleanup_interval_secs() -> u64 {
    300
}

/// Load a 32-byte AES-256-GCM key (or pepper) from an environment variable.
///
/// The variable must contain a 64-character lowercase-hex string (256 bits).
/// - Returns `Some(key)` on success.
/// - Panics with a clear message if the variable is set but malformed or wrong length.
/// - Returns `None` (with a `warn` log) when the variable is absent.
fn load_key_from_env(name: &str) -> Option<[u8; 32]> {
    match std::env::var(name) {
        Ok(hex) => {
            let bytes = hex::decode(&hex).unwrap_or_else(|_| {
                panic!("{name} must be a 64-char hex string (32 bytes / 256 bits)")
            });
            let key: [u8; 32] = bytes
                .try_into()
                .unwrap_or_else(|_| panic!("{name} must be exactly 32 bytes (256 bits)"));
            Some(key)
        }
        Err(_) => {
            tracing::warn!("{name} not set");
            None
        }
    }
}

/// Top-level configuration aggregating all sub-configs.
#[derive(Debug, Deserialize)]
struct AppConfig {
    #[serde(default)]
    server: ServerConfig,
    #[serde(default)]
    db: DbConfig,
    #[serde(default)]
    auth: AuthConfig,
    #[serde(default)]
    grpc: GrpcConfig,
    #[serde(default)]
    authz: axiam_authz::AuthzConfig,
    /// B3: `GET /oauth2/jwks` HTTP caching config (currently just the
    /// `Cache-Control` max-age). Configured via `AXIAM__OAUTH2__*` env vars,
    /// e.g. `AXIAM__OAUTH2__JWKS_CACHE_MAX_AGE_SECS`.
    #[serde(default)]
    oauth2: axiam_oauth2::jwks_cache::JwksCacheConfig,
    #[serde(default)]
    amqp: AmqpConfig,
    #[serde(default)]
    rate_limit: RateLimitConfig,
    /// How often (in seconds) the background cleanup task sweeps expired rows.
    /// Configurable via `AXIAM__SERVER__CLEANUP_INTERVAL_SECS`. Bounded to
    /// `60..=3600` at startup (T-04-35).
    #[serde(default = "default_cleanup_interval_secs")]
    cleanup_interval_secs: u64,
    /// AES-256-GCM key (32 bytes) for encrypting email provider secrets at rest
    /// (D-17). Loaded from `AXIAM__EMAIL_ENCRYPTION_KEY` (hex-encoded, 64 chars).
    /// Skipped by serde — populated manually from env at startup.
    #[serde(skip)]
    email_encryption_key: Option<[u8; 32]>,
    /// HMAC-SHA256 pepper (32 bytes) for GDPR audit pseudonymization (D-02).
    /// Loaded from `AXIAM__GDPR_PSEUDONYM_PEPPER` (hex-encoded, 64 chars).
    /// Skipped by serde — populated manually from env at startup.
    #[serde(skip)]
    gdpr_pseudonym_pepper: Option<[u8; 32]>,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // D-09: healthcheck subcommand — self-probe /health, exit 0 on 2xx, exit 1 otherwise.
    // Runs before tracing init and before the async stack to keep the probe lightweight.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("healthcheck") {
            let url = std::env::var("AXIAM_HEALTHCHECK_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8090/health".to_owned());
            let ok = reqwest::blocking::get(&url)
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            std::process::exit(if ok { 0 } else { 1 });
        }
    }

    // FND-01: --dump-openapi flag — print the OpenAPI JSON spec to stdout and exit 0.
    // Runs before tracing init and before load_config() / SurrealDB / AMQP so it is
    // usable in CI without any running infrastructure.  Generate the committed
    // sdks/openapi.json with:
    //   cargo build -p axiam-server --no-default-features
    //   ./target/debug/axiam-server --dump-openapi > sdks/openapi.json
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("--dump-openapi") {
            let json = serde_json::to_string_pretty(&axiam_api_rest::openapi::api_doc())
                .expect("OpenAPI serialization failed");
            println!("{json}");
            std::process::exit(0);
        }
    }

    // `tracing-subscriber` with the `tracing-log` feature auto-installs a
    // LogTracer so third-party crates (actix-web, hyper, etc.) that log via
    // the `log` crate surface in structured tracing output.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("axiam=info".parse().unwrap()))
        .json()
        .init();

    tracing::info!("Starting AXIAM server...");
    // H4: log which global allocator is active so `jemalloc` can be verified
    // in a running container's logs (`docker logs` / `kubectl logs`) without
    // needing binary introspection. Release container images build with the
    // `jemalloc` feature on by default (see docker/Dockerfile.server); a
    // build without it (e.g. `--build-arg CARGO_FEATURES=`, or a plain
    // `cargo build --release -p axiam-server`) logs the platform default.
    #[cfg(feature = "jemalloc")]
    tracing::info!(allocator = "jemalloc", "Global allocator: jemalloc");
    #[cfg(not(feature = "jemalloc"))]
    tracing::info!(
        allocator = "system",
        "Global allocator: platform default (glibc malloc)"
    );

    // REQ-15 AC-1: install the process-level rustls CryptoProvider.
    // rustls 0.23 links BOTH `ring` and `aws-lc-rs` in this build (transitively —
    // e.g. via rustls-platform-verifier), so it cannot auto-select a default
    // provider and any code path that consults the process default panics with
    // "Could not automatically determine the process-level CryptoProvider".
    // The REST listener sidesteps this by passing `ring::default_provider()`
    // explicitly (see `tls::build_rustls_server_config`), but tonic's gRPC
    // `ServerTlsConfig` (crates/axiam-api-grpc/src/server.rs) builds its rustls
    // config from the process default — without this call every gRPC-over-TLS
    // handshake panics on the tokio worker and the connection is dropped (0 bytes
    // back), while REST TLS keeps working. Install `ring` (matching REST) once,
    // before any listener is built. Idempotent: `Err` means a provider was
    // already installed, which is fine.
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        tracing::debug!("rustls default CryptoProvider was already installed");
    }

    let mut config = load_config();

    // Load MFA encryption key from env (skipped by serde on AuthConfig).
    config.auth.mfa_encryption_key = load_key_from_env("AXIAM__AUTH__MFA_ENCRYPTION_KEY");
    if config.auth.mfa_encryption_key.is_some() {
        tracing::info!("MFA encryption key loaded");
    }

    // Load federation encryption key from env (skipped by serde on AuthConfig).
    config.auth.federation_encryption_key =
        load_key_from_env("AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY");
    if config.auth.federation_encryption_key.is_some() {
        tracing::info!("Federation encryption key loaded");
    }

    // Load the OPAQUE keys from env (skipped by serde on AuthConfig). Absent,
    // the OPAQUE endpoints answer 503 rather than quietly leaving clients on
    // password login — see `AuthConfig::opaque_session_key`.
    //
    // Two keys, not one, because rotating them costs wildly different things:
    // the session key seals 120 seconds of in-flight state, while losing the
    // setup key makes every registration record in every tenant unopenable.
    config.auth.opaque_session_key = load_key_from_env("AXIAM__AUTH__OPAQUE_SESSION_KEY");
    config.auth.opaque_setup_key = load_key_from_env("AXIAM__AUTH__OPAQUE_SETUP_KEY");
    match (
        config.auth.opaque_session_key.is_some(),
        config.auth.opaque_setup_key.is_some(),
    ) {
        (true, true) => tracing::info!("OPAQUE keys loaded"),
        (false, false) => {}
        // Half-configured is worth a warning rather than silence: the operator
        // set one of the two and almost certainly believes OPAQUE is on.
        (session, setup) => tracing::warn!(
            session_key = session,
            setup_key = setup,
            "OPAQUE is only half-configured; both AXIAM__AUTH__OPAQUE_SESSION_KEY \
             and AXIAM__AUTH__OPAQUE_SETUP_KEY are required, so the OPAQUE \
             endpoints will answer 503"
        ),
    }

    // Load email encryption key from env (D-17).
    config.email_encryption_key = load_key_from_env("AXIAM__EMAIL_ENCRYPTION_KEY");
    if config.email_encryption_key.is_some() {
        tracing::info!("Email encryption key loaded");
    }

    // Load GDPR pseudonym pepper from env (D-02).
    config.gdpr_pseudonym_pepper = load_key_from_env("AXIAM__GDPR_PSEUDONYM_PEPPER");
    if config.gdpr_pseudonym_pepper.is_some() {
        tracing::info!("GDPR pseudonym pepper loaded");
    }

    // CQ-B14: Parse Ed25519 JWT keys once at startup and cache them in the
    // AuthConfig so per-request token issuance/verification skips PEM parsing.
    config
        .auth
        .resolve_keys()
        .expect("Failed to parse JWT Ed25519 keys — check AXIAM__AUTH__JWT_*_KEY_PEM");
    tracing::info!("JWT Ed25519 keys parsed and cached (CQ-B14)");

    // Clamp cleanup interval to 60..=3600 seconds (T-04-35).
    config.cleanup_interval_secs = config.cleanup_interval_secs.clamp(60, 3600);

    // Load auth pepper from env (REQ-14 AC-1). Plain string — no hex decode.
    // The pepper is prepended to passwords before Argon2id hashing/verification.
    // SECURITY: do NOT log the pepper value. Wrapped in `SecretString`
    // (SECHRD-12) so the value can never be accidentally `Debug`-printed.
    if let Ok(value) = std::env::var("AXIAM__AUTH__PEPPER") {
        config.auth.pepper = Some(secrecy::SecretString::from(value));
        tracing::info!("Auth pepper loaded");
    } else {
        tracing::info!(
            "AXIAM__AUTH__PEPPER not set — password hashing will proceed without a pepper; \
             client-secret hashing is mandatory-keyed and will fail closed in a release build \
             (OBS-1)"
        );
    }

    // OBS-1: install the process-wide client-secret hasher. Client secrets are
    // stored as a keyed HMAC-SHA256 tag under the pepper — there is no unkeyed
    // fallback — so an unset pepper must be a *startup* failure in a release
    // build, not a first-request failure. Same posture as the mandatory AMQP
    // master signing key (SECHRD-08 / D-05c); a debug build resolves the
    // documented dev-only pepper with a warning.
    axiam_auth::client_secret::install_from_config(&config.auth)
        .expect("client-secret pepper must resolve (OBS-1) — see AXIAM__AUTH__PEPPER");
    tracing::info!("Client-secret hasher installed (OBS-1)");

    // Load allow_missing_aud_as_user override (bool, default true).
    // The serde default already sets it to true; this allows an operator to
    // explicitly disable the back-compat window via env var.
    if let Ok(val) = std::env::var("AXIAM__AUTH__ALLOW_MISSING_AUD_AS_USER") {
        match val.to_lowercase().as_str() {
            "false" | "0" | "no" => config.auth.allow_missing_aud_as_user = false,
            _ => config.auth.allow_missing_aud_as_user = true,
        }
    }

    // Connect to SurrealDB. `DbPool` holds N independent, individually-renewable
    // handles (default `pool_size = 1` ⇒ byte-for-byte today's single handle).
    // Held as `Arc` because it is both the source of every repository's bound
    // handle (`handle_for_repo`) and the process health checker.
    let pool = Arc::new(
        axiam_db::DbPool::connect(&config.db)
            .await
            .expect("Failed to connect to SurrealDB"),
    );

    // X6/#302: attest the storage engine before this process serves anything.
    // Single-use redemption of UMA permission tickets, RFC 8628 device grants
    // and RFC 9126 PAR request_uris is guaranteed only on a persistent engine;
    // on `memory` it is measurably not. SurrealDB 3.2.4 publishes no datastore
    // identity over the wire (the enumeration is in `engine_attestation`), so in
    // practice this logs the "cannot attest" WARN and enforcement rests on the
    // deployment layer — compose and the k8s StatefulSet pin `surrealkv:`, and
    // `docs/deployment/README.md` carries the MUST. The hard refusal below is
    // already wired for the day a SurrealDB release does expose the engine.
    if let Err(refused) = axiam_db::attest_storage_engine(
        &pool.handle_for_repo().current(),
        axiam_db::memory_engine_override_enabled(),
    )
    .await
    {
        panic!("{refused}");
    }

    // Run schema migrations
    axiam_db::run_migrations(&pool.handle_for_repo().current())
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database connected and migrations applied");

    // Boot: mint a one-time bootstrap setup token if this database has never
    // been bootstrapped (SECHRD-04 / D-03b). No-op on every subsequent boot.
    // Errors are logged, never fatal — an unminted token just means the
    // env-var gate (AXIAM_BOOTSTRAP_ADMIN_EMAIL) remains the only way in,
    // which is a safe (fail-closed) degraded state, not a startup blocker.
    match axiam_db::mint_bootstrap_setup_token_if_needed(&pool.handle_for_repo().current()).await {
        Ok(Some(token)) => {
            // D-03b: the ONE deliberate secret-log exception — logged exactly
            // once, at first boot only. Only the sha256 hash is ever
            // persisted to the database (see `mint_bootstrap_setup_token_if_needed`).
            tracing::info!(
                setup_token = %token,
                "AXIAM first-run bootstrap setup token minted. Use this token \
                 ONCE to complete first-admin bootstrap (POST \
                 /api/v1/admin/bootstrap, `setup_token` field) if \
                 AXIAM_BOOTSTRAP_ADMIN_EMAIL is not set. This token will not \
                 be shown again."
            );
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, "Failed to mint bootstrap setup token");
        }
    }

    // Boot backfill: encrypt any legacy plaintext federation client_secret rows (D-12).
    // Idempotent — rows that are already encrypted are skipped. Runs before HTTP bind
    // to avoid serving plaintext-secret rows after this deploy.
    {
        let boot_fed_repo =
            axiam_db::SurrealFederationConfigRepository::new(pool.handle_for_repo());
        let boot_audit_repo = axiam_db::SurrealAuditLogRepository::new(pool.handle_for_repo());
        if let Some(fed_key) = config.auth.federation_encryption_key {
            match axiam_federation::secrets::migrate_plaintext_federation_secrets(
                &boot_fed_repo,
                &boot_audit_repo,
                &fed_key,
            )
            .await
            {
                Ok(n) => tracing::info!(migrated = n, "federation secrets backfill complete"),
                Err(e) => tracing::warn!(error = %e, "federation secrets backfill failed"),
            }
        } else {
            tracing::warn!(
                "AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY missing — \
                 skipping federation secret backfill"
            );
        }
    }

    // Boot backfill: encrypt any legacy plaintext email provider secret rows (D-17).
    // Idempotent — rows where ciphertext IS NOT NULL are skipped. Runs before HTTP bind
    // to avoid serving plaintext-secret rows after this deploy.
    {
        if let Some(email_key) = config.email_encryption_key {
            let boot_email_repo =
                SurrealEmailConfigRepository::new(pool.handle_for_repo(), email_key);
            match boot_email_repo.backfill_plaintext_secrets().await {
                Ok(n) => tracing::info!(migrated = n, "email config secrets backfill complete"),
                Err(e) => tracing::warn!(error = %e, "email config secrets backfill failed"),
            }
        } else {
            tracing::warn!(
                "AXIAM__EMAIL_ENCRYPTION_KEY missing — \
                 skipping email config secrets backfill"
            );
        }
    }

    // Seed permissions for all existing tenants (D-07).
    // Uses UPSERT — safe to run on every startup.
    {
        let seed_org_repo = SurrealOrganizationRepository::new(pool.handle_for_repo());
        let seed_tenant_repo = SurrealTenantRepository::new(pool.handle_for_repo());
        let all_orgs = seed_org_repo
            .list(Pagination {
                offset: 0,
                limit: 10_000,
            })
            .await
            .expect("Failed to list organizations for permission seeding");
        let mut seeded_count = 0usize;
        for org in all_orgs.items {
            let tenants = seed_tenant_repo
                .list_by_organization(
                    org.id,
                    Pagination {
                        offset: 0,
                        limit: 10_000,
                    },
                )
                .await
                .expect("Failed to list tenants for permission seeding");
            for tenant in tenants.items {
                axiam_db::seed_permissions(
                    &pool.handle_for_repo().current(),
                    tenant.id,
                    axiam_api_rest::permissions::PERMISSION_REGISTRY,
                )
                .await
                .expect("Failed to seed permissions for tenant");
                // Back-fill default-role grants for any permissions added to the
                // registry since this tenant was bootstrapped (bootstrap, which
                // grants permissions to roles, self-disables after first admin).
                let backfilled = axiam_db::reconcile_default_role_grants(
                    &pool.handle_for_repo().current(),
                    tenant.id,
                )
                .await
                .expect("Failed to reconcile default role grants for tenant");
                if backfilled > 0 {
                    tracing::info!(
                        tenant = %tenant.id,
                        grants = backfilled,
                        "Back-filled {backfilled} missing default-role permission grants"
                    );
                }
                seeded_count += 1;
            }
        }
        tracing::info!(
            tenants = seeded_count,
            "Seeded permissions for {} tenants",
            seeded_count
        );
    }

    // Connect to RabbitMQ and declare queues.
    // Shared behind an Arc so background consumers can hold a handle and
    // recreate their channel on a transient broker blip (CQ-B53) instead of
    // taking the whole process down.
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
    tracing::info!("RabbitMQ connected and queues declared");

    // LIVE pooled-connection reference — registered in `AppState` so handlers
    // that need direct access (e.g. /api/v1/admin/bootstrap) resolve the
    // CURRENT connection per query and therefore follow a reconnect-loop
    // handle swap, exactly as the repositories do.
    let db_handle = pool.handle_for_repo();
    let org_repo = SurrealOrganizationRepository::new(pool.handle_for_repo());
    let tenant_repo = SurrealTenantRepository::new(pool.handle_for_repo());
    let user_repo = SurrealUserRepository::with_pepper(
        pool.handle_for_repo(),
        config
            .auth
            .pepper
            .as_ref()
            .map(|p| p.expose_secret().to_string())
            .unwrap_or_default(),
    );
    let group_repo = SurrealGroupRepository::new(pool.handle_for_repo());
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

    let session_repo = SurrealSessionRepository::new(pool.handle_for_repo());
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
    let audit_repo = SurrealAuditLogRepository::new(pool.handle_for_repo());
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
    //
    // Resolved here because THREE things need it and this is the earliest of
    // them: the X1 reactor gate below (which signs reactor events and verifies
    // reactor replies with the same §8 v2 scheme), §4.2's cross-replica
    // cache-invalidation publisher, and the AMQP consumers.
    let amqp_signing_key: Vec<u8> = config
        .amqp
        .resolve_signing_key()
        .expect("AMQP signing key must resolve (SECHRD-08 / D-05c) — see AXIAM__AMQP__SIGNING_KEY");
    tracing::info!("AMQP signing key resolved (SEC-022/SECHRD-08)");

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
    let reactor_gate: axiam_core::models::reactor::SharedReactorGate =
        Arc::new(axiam_amqp::DispatchingReactorGate::new(
            Arc::clone(&reactor_routing),
            // R2.4: the real lapin RPC transport (§22.1's scope note is
            // closed). `start` is infallible and supervises its own broker
            // session — a broker that is slow at boot or restarts later must
            // not stop the server from serving logins. While it has no
            // session every dispatch fails fast as a transport error and the
            // registration's `failure_policy` decides, which is the same
            // closed set §22.8 puts a timeout in.
            axiam_amqp::LapinReactorTransport::start(Arc::clone(&amqp), amqp_signing_key.clone()),
            axiam_amqp::RepositoryAuditSink(SurrealAuditLogRepository::new(pool.handle_for_repo())),
            amqp_signing_key.clone(),
            axiam_amqp::ReactorGateConfig::default(),
        ));
    let reactor_routing_invalidator: Arc<dyn Fn(uuid::Uuid) + Send + Sync> = {
        let routing = Arc::clone(&reactor_routing);
        Arc::new(move |tenant_id| routing.invalidate_tenant(tenant_id))
    };
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

    let auth_service = AuthService::new(
        user_repo.clone(),
        session_repo.clone(),
        federation_link_repo_for_auth,
        auth_refresh_token_repo,
        config.auth.clone(),
        Arc::clone(&crypto_semaphore),
    )
    .with_reactor_gate(Arc::clone(&reactor_gate));
    // Password history repository — used by the password-change handler.
    let password_history_repo = SurrealPasswordHistoryRepository::new(pool.handle_for_repo());
    let consent_repo = axiam_db::SurrealConsentRepository::new(pool.handle_for_repo());
    let account_deletion_repo = SurrealAccountDeletionRepository::new(pool.handle_for_repo());
    let export_job_repo = SurrealExportJobRepository::new(pool.handle_for_repo());
    let erasure_proof_repo = SurrealErasureProofRepository::new(pool.handle_for_repo());

    let webauthn_cred_repo = SurrealWebauthnCredentialRepository::new(pool.handle_for_repo());
    let webauthn_service = WebauthnService::new(webauthn_cred_repo.clone(), config.auth.clone())
        .expect("Failed to build WebauthnService");
    let mfa_method_service = MfaMethodService::new(user_repo.clone(), webauthn_cred_repo.clone());

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
    // hand, mirroring `load_key_from_env`'s style. `mds_enabled` defaults to
    // `false` — "off means zero outbound calls" — so an unset env var
    // reproduces `PkiConfig::default()`'s documented behavior exactly.
    let pki_config = PkiConfig {
        encryption_key: load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY"),
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
    let cert_repo = SurrealCertificateRepository::new(pool.handle_for_repo());
    let ca_service = CaService::new(
        ca_cert_repo.clone(),
        pki_config.clone(),
        Arc::clone(&crypto_semaphore),
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
    let webhook_enc_key: Option<[u8; 32]> = load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY");
    let webhook_delivery =
        axiam_api_rest::webhook::WebhookDeliveryService::new(webhook_repo.clone(), webhook_enc_key);
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
    // extractor. Only constructed when AXIAM__EMAIL_ENCRYPTION_KEY is present (same
    // fail-closed, no-zero-key-fallback posture as the mail consumer above): when the
    // key is absent, `email_config_repo` stays `None` and is NOT registered as
    // app_data below, so the six email-config routes fail closed with actix's
    // "App data is not configured" 500 rather than silently encrypting with a
    // constant/zero key.
    let email_config_repo: Option<SurrealEmailConfigRepository<axiam_db::DbClient>> =
        match config.email_encryption_key {
            Some(email_key) => Some(SurrealEmailConfigRepository::new(
                pool.handle_for_repo(),
                email_key,
            )),
            None => {
                tracing::warn!(
                    "AXIAM__EMAIL_ENCRYPTION_KEY missing — email-config admin endpoints disabled"
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
    // NEW-4: durable AMQP nonce store for replay protection, shared by the
    // authz + audit consumers and swept by the periodic cleanup task.
    let amqp_nonce_repo = SurrealAmqpNonceRepository::new(pool.handle_for_repo());
    let federation_login_state_repo =
        SurrealFederationLoginStateRepository::new(pool.handle_for_repo());
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
        config.auth.clone(),
        i64::try_from(config.auth.refresh_token_lifetime_secs)
            .expect("refresh_token_lifetime_secs exceeds i64::MAX"),
    )
    // X1 — the same gate `AuthService` holds, so `token.pre_issue` and
    // `login.post_auth` share one routing table and one per-tenant cap.
    .with_reactor_gate(Arc::clone(&reactor_gate));

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

    // §4 item 1 (security-analysis-2026-08-02): the bucket key for
    // `/oauth2/{token,introspect,revoke}` is derived from the raw form body
    // BEFORE the credential check, so under `AXIAM__RATE_LIMIT__KEY=client_id`
    // it is attacker-mintable. Silent for the shipped default (`ip`); `warn!`
    // for `client_id`; a softer `info!` note for the partially-mintable
    // `ip_client_id`. Same shape as the I3 advisory below and the
    // session-validation cache's startup `warn!` — announce the opt-in mode
    // that carries the caveat, say nothing when the safe default is active.
    config.rate_limit.warn_on_mintable_key();

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
    let tls_config = config.server.tls.clone();
    let rate_limit_cfg = config.rate_limit.clone();
    let auth_config = config.auth.clone();
    let health_checker: Arc<dyn HealthChecker> = pool;

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
    ) {
        (true, Some(cache)) => {
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
                Arc::clone(&amqp) as Arc<dyn axiam_amqp::PublisherChannelFactory>,
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
            let consumer_amqp = Arc::clone(&amqp);
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

    // Publisher channel for outbound mail (password-reset, email-verify, etc.)
    let mail_pub_channel = amqp
        .create_publisher_channel()
        .await
        .expect("Failed to create AMQP mail outbound publisher channel");
    let mail_outbound_publisher = MailOutboundPublisher::new(mail_pub_channel);

    // Spawn AMQP audit event consumer on a background task.
    let audit_channel = amqp
        .create_channel()
        .await
        .expect("Failed to create AMQP audit consumer channel");
    let amqp_audit_repo = audit_repo.clone();
    let audit_nonce_repo = amqp_nonce_repo.clone();
    tokio::spawn(async move {
        axiam_amqp::audit_consumer::start_audit_consumer(
            audit_channel,
            amqp_audit_repo,
            amqp_signing_key,
            audit_nonce_repo,
            amqp_replay_skew,
        )
        .await;
        tracing::error!("AMQP audit consumer exited — shutting down process");
        std::process::exit(1);
    });

    // Webhook delivery publisher (CORR-03/D-06/D-07) — used by emit() to
    // publish onto the durable axiam.webhook queue, and by the webhook
    // consumer below to publish TTL-delayed retries onto axiam.webhook.retry.
    let webhook_pub_channel = amqp
        .create_publisher_channel()
        .await
        .expect("Failed to create AMQP webhook publisher channel");
    let webhook_publisher = WebhookPublisher::new(webhook_pub_channel);

    // Spawn the webhook AMQP consumer on a background task (CORR-03/D-06).
    // Drives WebhookDeliveryService::deliver_once for each queued delivery,
    // schedules retries natively via the retry-queue TTL+DLX (D-07/D-08,
    // bounded exponential backoff read from AXIAM__WEBHOOK__* — D-20), and
    // writes per-attempt/terminal audit records (D-09).
    {
        let webhook_delivery_for_consumer = webhook_delivery.clone();
        let webhook_publisher_for_consumer = webhook_publisher.clone();
        let webhook_audit_repo = audit_repo.clone();
        let webhook_retry_cfg = WebhookRetryConfig::from_env();
        let webhook_amqp = Arc::clone(&amqp);
        // CQ-B53: a transient broker disconnect (consumer stream ends, or the
        // channel fails to open) must NOT kill the whole API server. Recreate
        // the consume channel on the shared connection and restart the consumer
        // with bounded exponential backoff instead of `process::exit(1)`.
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(30);
            loop {
                match webhook_amqp.create_channel().await {
                    Ok(webhook_channel) => {
                        backoff = Duration::from_secs(1);
                        start_webhook_consumer(
                            webhook_channel,
                            webhook_delivery_for_consumer.clone(),
                            webhook_publisher_for_consumer.clone(),
                            webhook_audit_repo.clone(),
                            webhook_retry_cfg,
                        )
                        .await;
                        tracing::warn!("Webhook AMQP consumer exited — reconnecting");
                    }
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Failed to (re)create webhook consumer channel — retrying"
                        );
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        });
        tracing::info!("Webhook consumer spawned");
    }

    // Spawn AMQP mail consumer on a background task (D-14).
    // Only spawned when AXIAM__EMAIL_ENCRYPTION_KEY is present; otherwise
    // mail delivery is disabled and a warning was logged at startup (T-5-key-absent).
    if let Some(email_key) = config.email_encryption_key {
        let mail_channel = amqp
            .create_channel()
            .await
            .expect("Failed to create AMQP mail consumer channel");
        let mail_email_config_repo =
            SurrealEmailConfigRepository::new(db_handle.clone(), email_key);
        let mail_audit_repo = audit_repo.clone();
        let mail_user_repo = user_repo.clone();
        let mail_template_repo = SurrealEmailTemplateRepository::new(db_handle.clone());
        tokio::spawn(async move {
            axiam_amqp::start_mail_consumer(
                mail_channel,
                mail_email_config_repo,
                mail_audit_repo,
                mail_user_repo,
                mail_template_repo,
            )
            .await;
            tracing::error!("AMQP mail consumer exited — shutting down process");
            std::process::exit(1);
        });
        tracing::info!("Mail consumer spawned");
    } else {
        tracing::warn!("Mail consumer NOT spawned — AXIAM__EMAIL_ENCRYPTION_KEY is missing");
    }

    // X3 (D10): weekly FIDO MDS3 background refresh job. `should_spawn_refresh_job`
    // is the single gate — `mds_enabled: false` (the shipped default) or
    // `mds_refresh_interval_secs == 0` both mean this branch is never taken,
    // so a default deployment makes ZERO outbound MDS calls (see
    // `axiam_server::mds_job`'s unit tests for the pure decision function
    // this reads, since `main()` itself cannot be linked from `tests/`).
    if axiam_server::mds_job::should_spawn_refresh_job(&pki_config) {
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
            let jitter = axiam_server::mds_job::jitter_secs(
                mds_interval_secs,
                uuid::Uuid::new_v4().as_u128(),
            );
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
        )
        .await
        {
            tracing::error!(error = %e, "gRPC server failed — shutting down process");
            std::process::exit(1);
        }
    });

    let audit_middleware = AuditMiddleware::spawn(audit_repo.clone());

    // Spawn the periodic cleanup task (D-09, D-24).
    // Shutdown channel: main sends `true` after HttpServer returns on SIGTERM.
    let (cleanup_shutdown_tx, cleanup_shutdown_rx) = tokio::sync::watch::channel(false);
    // Mail publisher for export-ready notifications from the cleanup task.
    let cleanup_mail_pub_channel = amqp
        .create_publisher_channel()
        .await
        .expect("Failed to create AMQP cleanup mail channel");
    let cleanup_mail_publisher: Arc<axiam_amqp::MailOutboundPublisher> = Arc::new(
        axiam_amqp::MailOutboundPublisher::new(cleanup_mail_pub_channel),
    );
    let cleanup_federation_link_repo =
        axiam_db::SurrealFederationLinkRepository::new(db_handle.clone());
    let cleanup = cleanup::CleanupTask::new(
        Arc::new(assertion_replay_repo.clone()),
        Arc::new(federation_login_state_repo.clone()),
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
        cleanup_shutdown_rx,
    );
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
        audit_repo: audit_repo.clone(),
        org_repo: org_repo.clone(),
        tenant_repo: tenant_repo.clone(),
        // A2/J2: refresh rotation reads the tenant only for `organization_id`,
        // an immutable field — cache it rather than pay a round trip per
        // refresh (see axiam_api_rest::tenant_org_cache).
        tenant_org_cache: Arc::new(Default::default()),
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
            pgp_service: pgp_service.clone(),
            device_auth_service: device_auth_service.clone(),
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
            webhook_publisher: Some(std::sync::Arc::new(webhook_publisher.clone())),
            notification_rule_repo: notification_rule_repo.clone(),
        },
        oauth2: bundles::OAuth2State {
            authorize_service: authorize_service.clone(),
            token_service: token_service.clone(),
            device_authorization_service: device_authorization_service.clone(),
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
        },
        federation: bundles::FederationState {
            federation_config_repo: federation_config_repo.clone(),
            federation_link_repo: federation_link_repo.clone(),
            federation_login_state_repo: federation_login_state_repo.clone(),
            assertion_replay_repo: assertion_replay_repo.clone(),
            oidc_federation_service: oidc_federation_service.clone(),
            #[cfg(feature = "saml")]
            saml_federation_service: saml_federation_service.clone(),
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
            .wrap(TracingLogger::default())
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
            .app_data(web::Data::new(scim_token_resolver.clone()))
            // QUAL-01: single composition root — every other REST handler
            // dependency (repos, services, the 4 hoisted QUAL-07 singletons)
            // lives on this one AppState<C> value (see above).
            .app_data(web::Data::new(app_state.clone()))
            .configure(health_routes::<axiam_db::DbClient>)
            .configure(|cfg| register_api_v1_routes::<axiam_db::DbClient>(cfg, &rl))
            // R3.1 (B4): SCIM 2.0 provisioning, mounted under /scim/v2.
            // R5.2: hand it the SAME resolved RateLimitConfig the /api/v1
            // wiring gets, so `AXIAM__RATE_LIMIT__SCIM_PER_MIN` (and the
            // posture log line) actually govern the provisioning surface.
            .configure(|cfg| {
                axiam_scim::scim_routes_with_rate_limits::<axiam_db::DbClient>(cfg, &rl)
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
                match axiam_api_rest::VerifiedClientCert::from_der(leaf.as_ref()) {
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
    // before. See `axiam_server::tls::Http2Tuning`.
    let h2_tuning = axiam_server::tls::Http2Tuning::load()?;
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
        // honour (it re-prepends h2 to ALPN) — see `axiam_server::tls`.
        let rustls_config = axiam_server::tls::build_rustls_server_config(&tls_config)?;
        tracing::info!(
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
    } else {
        http_server.bind(&bind_addr)?
    };
    http_server.run().await?;

    // Signal the cleanup task to shut down and wait for it to finish.
    let _ = cleanup_shutdown_tx.send(true);
    if let Err(e) = cleanup_handle.await {
        tracing::warn!(error = ?e, "cleanup task join error");
    }

    Ok(())
}

fn load_config() -> AppConfig {
    let builder = config::Config::builder()
        .add_source(config::File::with_name("config/default").required(false))
        .add_source(config::Environment::with_prefix("AXIAM").separator("__"));

    let config: AppConfig = builder
        .build()
        .and_then(|c| c.try_deserialize())
        .expect("Failed to load configuration — check config/default.toml or AXIAM__* env vars");

    // Validate critical fields to fail fast instead of booting an insecure/broken server.
    assert!(
        !config.auth.jwt_private_key_pem.is_empty(),
        "AXIAM__AUTH__JWT_PRIVATE_KEY_PEM must be set (Ed25519 PEM)"
    );
    assert!(
        !config.auth.jwt_public_key_pem.is_empty(),
        "AXIAM__AUTH__JWT_PUBLIC_KEY_PEM must be set (Ed25519 PEM)"
    );

    // Validate oauth2_issuer_url when explicitly configured.
    // jwt_issuer is intentionally unconstrained — it is used as the
    // JWT `iss` claim and may be a non-URL string.  OIDC discovery
    // compliance requires oauth2_issuer_url to be set.
    if !config.auth.oauth2_issuer_url.is_empty() {
        let issuer = &config.auth.oauth2_issuer_url;
        let url = url::Url::parse(issuer).unwrap_or_else(|e| {
            panic!(
                "AXIAM__AUTH__OAUTH2_ISSUER_URL is not a valid URL: \
                 {e} (got: {issuer})"
            )
        });
        let is_localhost = url
            .host_str()
            .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "::1");
        assert!(
            url.scheme() == "https" || (url.scheme() == "http" && is_localhost),
            "OIDC issuer must use https (http is only allowed for \
             localhost); got: {issuer}",
        );
        assert!(
            url.host().is_some(),
            "OIDC issuer URL must have a host: {issuer}",
        );
        // AXIAM limitation: path-based issuers are not currently
        // supported.  While OIDC allows path segments in issuers
        // (e.g. for reverse-proxy or multi-tenant deployments),
        // AXIAM serves discovery at a fixed `/.well-known/` route
        // and builds endpoint URLs as `{issuer}/oauth2/...`, which
        // would break with a non-root path.
        assert!(
            url.path() == "/" || url.path().is_empty(),
            "AXIAM does not support path-based issuer URLs \
             (path-based issuers require route changes not yet \
             implemented): {issuer}",
        );
        assert!(
            url.query().is_none(),
            "OIDC issuer URL must not contain a query string: \
             {issuer}",
        );
        assert!(
            url.fragment().is_none(),
            "OIDC issuer URL must not contain a fragment: {issuer}",
        );
    } else {
        tracing::warn!(
            "AXIAM__AUTH__OAUTH2_ISSUER_URL not set — OIDC discovery \
             will use jwt_issuer as a non-URL issuer identifier; \
             set oauth2_issuer_url for compliant discovery documents"
        );
    }

    config
}

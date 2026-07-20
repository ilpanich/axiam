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
use axiam_api_rest::webhook_consumer::{WebhookRetryConfig, start_webhook_consumer};
use axiam_api_rest::{
    HealthChecker, RateLimitConfig, ServerConfig, build_cors, health_routes, openapi_routes,
    register_api_v1_routes,
};
use axiam_audit::AuditMiddleware;
use axiam_auth::config::AuthConfig;
use axiam_auth::{
    AuthService, EmailVerificationService, MfaMethodService, PasswordResetService, WebauthnService,
};
use axiam_core::repository::{OrganizationRepository, Pagination, TenantRepository};
use axiam_db::{
    DbConfig, DbManager, SurrealAccountDeletionRepository, SurrealAmqpNonceRepository,
    SurrealAssertionReplayRepository, SurrealAuditLogRepository,
    SurrealAuthorizationCodeRepository, SurrealCaCertificateRepository,
    SurrealCertificateRepository, SurrealEmailConfigRepository, SurrealEmailTemplateRepository,
    SurrealEmailVerificationTokenRepository, SurrealErasureProofRepository,
    SurrealExportJobRepository, SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealFederationLoginStateRepository, SurrealGroupRepository,
    SurrealNotificationRuleRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository,
    SurrealPasswordResetTokenRepository, SurrealPermissionRepository, SurrealPgpKeyRepository,
    SurrealRefreshTokenRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealServiceAccountRepository, SurrealSessionRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebauthnCredentialRepository, SurrealWebhookRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
#[cfg(feature = "saml")]
use axiam_federation::saml::SamlFederationService;
use axiam_oauth2::authorize::AuthorizeService;
use axiam_oauth2::jwks_cache::JwksCache as Oauth2JwksCache;
use axiam_oauth2::token::TokenService;
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
            "AXIAM__AUTH__PEPPER not set — password hashing will proceed without a pepper"
        );
    }

    // Load allow_missing_aud_as_user override (bool, default true).
    // The serde default already sets it to true; this allows an operator to
    // explicitly disable the back-compat window via env var.
    if let Ok(val) = std::env::var("AXIAM__AUTH__ALLOW_MISSING_AUD_AS_USER") {
        match val.to_lowercase().as_str() {
            "false" | "0" | "no" => config.auth.allow_missing_aud_as_user = false,
            _ => config.auth.allow_missing_aud_as_user = true,
        }
    }

    // Connect to SurrealDB
    let db = DbManager::connect(&config.db)
        .await
        .expect("Failed to connect to SurrealDB");

    // Run schema migrations
    axiam_db::run_migrations(&db.client_cloned().await)
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database connected and migrations applied");

    // Boot: mint a one-time bootstrap setup token if this database has never
    // been bootstrapped (SECHRD-04 / D-03b). No-op on every subsequent boot.
    // Errors are logged, never fatal — an unminted token just means the
    // env-var gate (AXIAM_BOOTSTRAP_ADMIN_EMAIL) remains the only way in,
    // which is a safe (fail-closed) degraded state, not a startup blocker.
    match axiam_db::mint_bootstrap_setup_token_if_needed(&db.client_cloned().await).await {
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
            axiam_db::SurrealFederationConfigRepository::new(db.client_cloned().await);
        let boot_audit_repo = axiam_db::SurrealAuditLogRepository::new(db.client_cloned().await);
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
                SurrealEmailConfigRepository::new(db.client_cloned().await, email_key);
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
        let seed_org_repo = SurrealOrganizationRepository::new(db.client_cloned().await);
        let seed_tenant_repo = SurrealTenantRepository::new(db.client_cloned().await);
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
                    &db.client_cloned().await,
                    tenant.id,
                    axiam_api_rest::permissions::PERMISSION_REGISTRY,
                )
                .await
                .expect("Failed to seed permissions for tenant");
                // Back-fill default-role grants for any permissions added to the
                // registry since this tenant was bootstrapped (bootstrap, which
                // grants permissions to roles, self-disables after first admin).
                let backfilled =
                    axiam_db::reconcile_default_role_grants(&db.client_cloned().await, tenant.id)
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

    // Raw SurrealDB handle — registered as app_data so handlers that need direct
    // access (e.g. /api/v1/admin/bootstrap) can request `web::Data<Surreal<C>>`.
    let db_handle = db.client_cloned().await;
    let org_repo = SurrealOrganizationRepository::new(db.client_cloned().await);
    let tenant_repo = SurrealTenantRepository::new(db.client_cloned().await);
    let user_repo = SurrealUserRepository::with_pepper(
        db.client_cloned().await,
        config
            .auth
            .pepper
            .as_ref()
            .map(|p| p.expose_secret().to_string())
            .unwrap_or_default(),
    );
    let group_repo = SurrealGroupRepository::new(db.client_cloned().await);
    let role_repo = SurrealRoleRepository::new(db.client_cloned().await);
    let permission_repo = SurrealPermissionRepository::new(db.client_cloned().await);
    let resource_repo = SurrealResourceRepository::new(db.client_cloned().await);
    let scope_repo = SurrealScopeRepository::new(db.client_cloned().await);
    let service_account_repo = SurrealServiceAccountRepository::new(db.client_cloned().await);
    let session_repo = SurrealSessionRepository::new(db.client_cloned().await);
    // REQ-7 / D-15: per-request session-validity check so revoked sessions'
    // access tokens are rejected immediately (the AuthenticatedUser extractor
    // consults this on every authenticated request).
    let session_validator: std::sync::Arc<dyn axiam_api_rest::SessionValidator> =
        std::sync::Arc::new(session_repo.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.client_cloned().await);
    let ca_cert_repo = SurrealCaCertificateRepository::new(db.client_cloned().await);
    let federation_link_repo_for_auth =
        SurrealFederationLinkRepository::new(db.client_cloned().await);
    // A separate refresh-token repo instance for AuthService (used by
    // revoke_all_sessions / revoke_all_sessions_except on password change and reset).
    let auth_refresh_token_repo = SurrealRefreshTokenRepository::new(db.client_cloned().await);
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

    let auth_service = AuthService::new(
        user_repo.clone(),
        session_repo.clone(),
        federation_link_repo_for_auth,
        auth_refresh_token_repo,
        config.auth.clone(),
        Arc::clone(&crypto_semaphore),
    );
    // Password history repository — used by the password-change handler.
    let password_history_repo = SurrealPasswordHistoryRepository::new(db.client_cloned().await);
    let consent_repo = axiam_db::SurrealConsentRepository::new(db.client_cloned().await);
    let account_deletion_repo = SurrealAccountDeletionRepository::new(db.client_cloned().await);
    let export_job_repo = SurrealExportJobRepository::new(db.client_cloned().await);
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.client_cloned().await);

    let webauthn_cred_repo = SurrealWebauthnCredentialRepository::new(db.client_cloned().await);
    let webauthn_service = WebauthnService::new(webauthn_cred_repo.clone(), config.auth.clone())
        .expect("Failed to build WebauthnService");
    let mfa_method_service = MfaMethodService::new(user_repo.clone(), webauthn_cred_repo.clone());

    // PKI service — encryption key for CA private keys (SEC-012).
    // Absent key → None; operations that encrypt private key material will fail fast
    // with a clear error rather than silently using an all-zero key.
    let pki_config = PkiConfig {
        encryption_key: load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY"),
    };
    let cert_repo = SurrealCertificateRepository::new(db.client_cloned().await);
    let ca_service = CaService::new(
        ca_cert_repo.clone(),
        pki_config.clone(),
        Arc::clone(&crypto_semaphore),
    );
    let pgp_repo = SurrealPgpKeyRepository::new(db.client_cloned().await);
    let pgp_service = PgpService::new(pgp_repo, pki_config.clone(), Arc::clone(&crypto_semaphore));
    let cert_service = CertService::new(
        ca_cert_repo,
        cert_repo.clone(),
        pki_config,
        Arc::clone(&crypto_semaphore),
    );
    // SEC-024: DeviceAuthService now holds a CA repo for chain verification.
    // SurrealCaCertificateRepository is cloned; each clone shares the underlying Surreal<C>.
    let device_auth_service = DeviceAuthService::new(
        cert_repo.clone(),
        SurrealCaCertificateRepository::new(db.client_cloned().await),
    );
    let webhook_repo = SurrealWebhookRepository::new(db.client_cloned().await);
    // SEC-031/SEC-059: Webhook secrets stored AES-256-GCM encrypted using the
    // same PKI encryption key. Absent key -> None (SEC-012 fail-closed
    // pattern, mirrors `pki_config.encryption_key` above): the server still
    // boots, but webhook registration and delivery are refused with an
    // explicit error + `warn!` until a real key is configured. NEVER an
    // all-zero/constant fallback key.
    let webhook_enc_key: Option<[u8; 32]> = load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY");
    let webhook_delivery =
        axiam_api_rest::webhook::WebhookDeliveryService::new(webhook_repo.clone(), webhook_enc_key);
    let settings_repo = SurrealSettingsRepository::new(db.client_cloned().await);
    // Notification-rule repository — required by the notification_rules handlers'
    // `web::Data<SurrealNotificationRuleRepository>` extractor. Without this
    // registration every /api/v1/notification-rules request 500s with
    // "App data is not configured".
    let notification_rule_repo = SurrealNotificationRuleRepository::new(db.client_cloned().await);
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
                db.client_cloned().await,
                email_key,
            )),
            None => {
                tracing::warn!(
                    "AXIAM__EMAIL_ENCRYPTION_KEY missing — email-config admin endpoints disabled"
                );
                None
            }
        };
    let federation_config_repo = SurrealFederationConfigRepository::new(db.client_cloned().await);
    let federation_link_repo = SurrealFederationLinkRepository::new(db.client_cloned().await);
    let assertion_replay_repo = SurrealAssertionReplayRepository::new(db.client_cloned().await);
    // NEW-4: durable AMQP nonce store for replay protection, shared by the
    // authz + audit consumers and swept by the periodic cleanup task.
    let amqp_nonce_repo = SurrealAmqpNonceRepository::new(db.client_cloned().await);
    let federation_login_state_repo =
        SurrealFederationLoginStateRepository::new(db.client_cloned().await);
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
    let oauth2_client_repo = SurrealOAuth2ClientRepository::new(db.client_cloned().await);
    let auth_code_repo = SurrealAuthorizationCodeRepository::new(db.client_cloned().await);
    let refresh_token_repo = SurrealRefreshTokenRepository::new(db.client_cloned().await);
    // Separate instance for password-reset/change handlers that need direct
    // RefreshTokenRepository access via web::Data (TokenService owns the main one).
    let handler_refresh_token_repo = SurrealRefreshTokenRepository::new(db.client_cloned().await);

    // OAuth2 authorization code grant services.
    let authorize_service = AuthorizeService::new(
        oauth2_client_repo.clone(),
        auth_code_repo.clone(),
        config.auth.auth_code_lifetime_secs,
    );
    let token_service = TokenService::new(
        oauth2_client_repo.clone(),
        auth_code_repo,
        tenant_repo.clone(),
        refresh_token_repo,
        user_repo.clone(),
        config.auth.clone(),
        i64::try_from(config.auth.refresh_token_lifetime_secs)
            .expect("refresh_token_lifetime_secs exceeds i64::MAX"),
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
        SurrealPasswordResetTokenRepository::new(db.client_cloned().await);
    let email_verification_token_repo =
        SurrealEmailVerificationTokenRepository::new(db.client_cloned().await);

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

    config.rate_limit.validate();

    let bind_addr = config.server.bind_address();
    let server_config = config.server.clone();
    // Direct-TLS is opt-in (default: terminate at the proxy layer). Cloned out
    // of `config.server` before `server_config` is moved into the App factory
    // closure below so the bind decision can still read it (F-04).
    let tls_config = config.server.tls.clone();
    let rate_limit_cfg = config.rate_limit.clone();
    let auth_config = config.auth.clone();
    let health_checker: Arc<dyn HealthChecker> = Arc::new(db);

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
    if decision_cache.is_some() {
        tracing::info!(
            ttl_secs = config.authz.decision_cache_ttl_secs,
            max_entries = config.authz.decision_cache_max_entries,
            "AuthZ decision cache ENABLED (D7)"
        );
    }

    // Build REST-facing authorization checker (D-01, D-02).
    let rest_authz: Arc<dyn axiam_api_rest::authz::AuthzChecker> = {
        let engine = axiam_authz::AuthorizationEngine::new(
            role_repo.clone(),
            permission_repo.clone(),
            resource_repo.clone(),
            scope_repo.clone(),
            group_repo.clone(),
        );
        Arc::new(match decision_cache.as_ref() {
            Some(cache) => engine.with_decision_cache(cache.clone()),
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
        );
        match decision_cache.as_ref() {
            Some(cache) => engine.with_decision_cache(cache.clone()),
            None => engine,
        }
    };
    // SEC-022/SECHRD-08: Resolve the mandatory AMQP master signing key. In a
    // debug build this falls back to a documented dev-only default when
    // unset; in a release build (the production container image) an unset
    // key fails closed at startup — there is no unsigned code path (D-05c).
    let amqp_signing_key: Vec<u8> = config
        .amqp
        .resolve_signing_key()
        .expect("AMQP signing key must resolve (SECHRD-08 / D-05c) — see AXIAM__AMQP__SIGNING_KEY");
    tracing::info!("AMQP signing key resolved (SEC-022/SECHRD-08)");
    // NEW-4: freshness skew window shared by both consumers.
    let amqp_replay_skew = config.amqp.replay_skew();
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

    // Build gRPC services and spawn server on a background task.
    let grpc_addr = config.grpc.bind_address();
    let grpc_engine = {
        let engine = axiam_authz::AuthorizationEngine::new(
            role_repo.clone(),
            permission_repo.clone(),
            resource_repo.clone(),
            scope_repo.clone(),
            group_repo.clone(),
        );
        match decision_cache.as_ref() {
            Some(cache) => engine.with_decision_cache(cache.clone()),
            None => engine,
        }
    };
    let grpc_user_repo = user_repo.clone();
    let grpc_auth_config = config.auth.clone();
    let grpc_config = config.grpc.clone();
    // SECHRD-03 gap closure (24-07 follow-up): thread the same shared
    // Surreal<C> handle used by the REST repositories so the gRPC shared
    // rate-limit pre-check can enforce the multi-replica bucket store
    // (GrpcSharedRateLimitLayer), not just the per-replica in-memory
    // governor.
    let grpc_db = db_handle.clone();
    let grpc_batch_max_concurrency = config.authz.batch_max_concurrency;
    tokio::spawn(async move {
        if let Err(e) = start_grpc_server(
            grpc_addr,
            grpc_engine,
            grpc_user_repo,
            grpc_auth_config,
            &grpc_config,
            grpc_db,
            grpc_batch_max_concurrency,
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
        user_repo: user_repo.clone(),
        group_repo: group_repo.clone(),
        role_repo: role_repo.clone(),
        permission_repo: permission_repo.clone(),
        resource_repo: resource_repo.clone(),
        scope_repo: scope_repo.clone(),
        service_account_repo: service_account_repo.clone(),
        auth_service: auth_service.clone(),
        webauthn_service: webauthn_service.clone(),
        mfa_method_service: mfa_method_service.clone(),
        mail_outbound_publisher: Arc::new(mail_outbound_publisher.clone())
            as Arc<dyn axiam_api_rest::state::DynMailPublisher>,
        session_repo: session_repo.clone(),
        session_validator: session_validator.clone(),
        refresh_token_repo: handler_refresh_token_repo.clone(),
        password_history_repo: password_history_repo.clone(),
        consent_repo: consent_repo.clone(),
        account_deletion_repo: account_deletion_repo.clone(),
        export_job_repo: export_job_repo.clone(),
        erasure_proof_repo: erasure_proof_repo.clone(),
        email_encryption_key: config.email_encryption_key,
        ca_service: ca_service.clone(),
        cert_service: cert_service.clone(),
        cert_repo: cert_repo.clone(),
        device_auth_service: device_auth_service.clone(),
        pgp_service: pgp_service.clone(),
        webhook_repo: webhook_repo.clone(),
        webhook_delivery: webhook_delivery.clone(),
        // CQ-B22: hand the delivery publisher to AppState so handlers can
        // dispatch domain events via `state.emit_webhook(...)`.
        webhook_publisher: Some(std::sync::Arc::new(webhook_publisher.clone())),
        notification_rule_repo: notification_rule_repo.clone(),
        oauth2_client_repo: oauth2_client_repo.clone(),
        authorize_service: authorize_service.clone(),
        token_service: token_service.clone(),
        settings_repo: settings_repo.clone(),
        federation_config_repo: federation_config_repo.clone(),
        federation_link_repo: federation_link_repo.clone(),
        assertion_replay_repo: assertion_replay_repo.clone(),
        federation_login_state_repo: federation_login_state_repo.clone(),
        http_client: http_client.clone(),
        jwks_cache: jwks_cache.clone(),
        oauth2_jwks_cache: oauth2_jwks_cache.clone(),
        oauth2_jwks_cache_config: config.oauth2.clone(),
        crypto_semaphore: Arc::clone(&crypto_semaphore),
        email_config_repo: email_config_repo.clone(),
        password_reset_service: password_reset_service.clone(),
        email_verification_service: email_verification_service.clone(),
        oidc_federation_service: oidc_federation_service.clone(),
        #[cfg(feature = "saml")]
        saml_federation_service: saml_federation_service.clone(),
    };

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
            // QUAL-01: single composition root — every other REST handler
            // dependency (repos, services, the 4 hoisted QUAL-07 singletons)
            // lives on this one AppState<C> value (see above).
            .app_data(web::Data::new(app_state.clone()))
            .configure(health_routes::<axiam_db::DbClient>)
            .configure(|cfg| register_api_v1_routes::<axiam_db::DbClient>(cfg, &rl))
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

    // Bind plaintext (proxy-terminated TLS, the default) or, when
    // `server.tls.enabled`, bind with rustls restricted to TLS 1.3 (F-04 /
    // ASVS V9.1.2). `build_rustls_server_config` fails fast on any cert/key
    // misconfiguration, so a misconfigured TLS server never starts insecurely.
    let http_server = if tls_config.enabled {
        let rustls_config = axiam_server::tls::build_rustls_server_config(&tls_config)?;
        tracing::info!(
            bind = %bind_addr,
            http2_offered = tls_config.http2,
            resumption = "tls1.3-tickets",
            early_data = false,
            "Direct TLS enabled — negotiating TLS 1.3 only"
        );
        // B2 honesty: the http2=false knob narrows the rustls config's ALPN to
        // http/1.1, but actix-web's rustls HttpService re-adds h2 to ALPN, so
        // h2 still wins negotiation on this bind. Warn so an operator expecting
        // a true http/1.1-only listener is not misled.
        if !tls_config.http2 {
            tracing::warn!(
                "server.tls.http2=false requested: the rustls config advertises http/1.1 only, \
                 but the actix-web rustls HttpServer bind unconditionally re-adds h2 to ALPN, so \
                 h2 remains offered and preferred. For a genuine http/1.1-only TLS listener (e.g. \
                 the p2 h2-isolation benchmark cell) front the server with the tls13-h1 nginx edge. \
                 See docs/security-profiles.md."
            );
        }
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

//! AXIAM Server — Application entry point.

mod cleanup;

use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer, web};
use axiam_amqp::{AmqpConfig, AmqpManager, MailOutboundPublisher};
use axiam_api_grpc::{GrpcConfig, start_grpc_server};
use axiam_api_rest::middleware::security_headers::SecurityHeadersMiddleware;
use axiam_api_rest::{
    HealthChecker, RateLimitConfig, ServerConfig, build_cors, health_routes, openapi_routes,
    register_api_v1_routes,
};
use axiam_audit::AuditMiddleware;
use axiam_auth::config::AuthConfig;
use axiam_auth::{AuthService, MfaMethodService, WebauthnService};
use axiam_core::repository::{OrganizationRepository, Pagination, TenantRepository};
use axiam_db::{
    DbConfig, DbManager, SurrealAccountDeletionRepository, SurrealAssertionReplayRepository,
    SurrealAuditLogRepository, SurrealAuthorizationCodeRepository, SurrealCaCertificateRepository,
    SurrealCertificateRepository, SurrealEmailConfigRepository, SurrealErasureProofRepository,
    SurrealExportJobRepository, SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealFederationLoginStateRepository, SurrealGroupRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPasswordHistoryRepository, SurrealPermissionRepository,
    SurrealPgpKeyRepository, SurrealRefreshTokenRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealServiceAccountRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebauthnCredentialRepository, SurrealWebhookRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_oauth2::authorize::AuthorizeService;
use axiam_oauth2::token::TokenService;
use axiam_pki::{CaService, CertService, DeviceAuthService, PgpService, PkiConfig};
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

    // Clamp cleanup interval to 60..=3600 seconds (T-04-35).
    config.cleanup_interval_secs = config.cleanup_interval_secs.clamp(60, 3600);

    // Load auth pepper from env (REQ-14 AC-1). Plain string — no hex decode.
    // The pepper is prepended to passwords before Argon2id hashing/verification.
    // SECURITY: do NOT log the pepper value.
    if let Ok(value) = std::env::var("AXIAM__AUTH__PEPPER") {
        config.auth.pepper = Some(value);
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
    axiam_db::run_migrations(db.client())
        .await
        .expect("Failed to run database migrations");

    tracing::info!("Database connected and migrations applied");

    // Boot backfill: encrypt any legacy plaintext federation client_secret rows (D-12).
    // Idempotent — rows that are already encrypted are skipped. Runs before HTTP bind
    // to avoid serving plaintext-secret rows after this deploy.
    {
        let boot_fed_repo = axiam_db::SurrealFederationConfigRepository::new(db.client().clone());
        let boot_audit_repo = axiam_db::SurrealAuditLogRepository::new(db.client().clone());
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
            let boot_email_repo = SurrealEmailConfigRepository::new(db.client().clone(), email_key);
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
        let seed_org_repo = SurrealOrganizationRepository::new(db.client().clone());
        let seed_tenant_repo = SurrealTenantRepository::new(db.client().clone());
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
                    db.client(),
                    tenant.id,
                    axiam_api_rest::permissions::PERMISSION_REGISTRY,
                )
                .await
                .expect("Failed to seed permissions for tenant");
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
    let amqp = AmqpManager::connect_with_retry(&config.amqp)
        .await
        .expect("Failed to connect to RabbitMQ");
    amqp.declare_queues()
        .await
        .expect("Failed to declare AMQP queues");
    tracing::info!("RabbitMQ connected and queues declared");

    // Raw SurrealDB handle — registered as app_data so handlers that need direct
    // access (e.g. /api/v1/admin/bootstrap) can request `web::Data<Surreal<C>>`.
    let db_handle = db.client().clone();
    let org_repo = SurrealOrganizationRepository::new(db.client().clone());
    let tenant_repo = SurrealTenantRepository::new(db.client().clone());
    let user_repo = SurrealUserRepository::with_pepper(
        db.client().clone(),
        config.auth.pepper.clone().unwrap_or_default(),
    );
    let group_repo = SurrealGroupRepository::new(db.client().clone());
    let role_repo = SurrealRoleRepository::new(db.client().clone());
    let permission_repo = SurrealPermissionRepository::new(db.client().clone());
    let resource_repo = SurrealResourceRepository::new(db.client().clone());
    let scope_repo = SurrealScopeRepository::new(db.client().clone());
    let service_account_repo = SurrealServiceAccountRepository::new(db.client().clone());
    let session_repo = SurrealSessionRepository::new(db.client().clone());
    // REQ-7 / D-15: per-request session-validity check so revoked sessions'
    // access tokens are rejected immediately (the AuthenticatedUser extractor
    // consults this on every authenticated request).
    let session_validator: std::sync::Arc<dyn axiam_api_rest::SessionValidator> =
        std::sync::Arc::new(session_repo.clone());
    let audit_repo = SurrealAuditLogRepository::new(db.client().clone());
    let ca_cert_repo = SurrealCaCertificateRepository::new(db.client().clone());
    let federation_link_repo_for_auth = SurrealFederationLinkRepository::new(db.client().clone());
    // A separate refresh-token repo instance for AuthService (used by
    // revoke_all_sessions / revoke_all_sessions_except on password change and reset).
    let auth_refresh_token_repo = SurrealRefreshTokenRepository::new(db.client().clone());
    // Single shared bounding semaphore for all CPU-bound crypto operations (CQ-B02 / REQ-14 AC-2).
    // Limits concurrent Argon2 and PKI keygen/sign operations to 4 to prevent DoS via
    // runtime thread starvation. Constructed once, cloned (Arc) into each service.
    let crypto_semaphore = Arc::new(tokio::sync::Semaphore::new(4));

    let auth_service = AuthService::new(
        user_repo.clone(),
        session_repo.clone(),
        federation_link_repo_for_auth,
        auth_refresh_token_repo,
        config.auth.clone(),
        Arc::clone(&crypto_semaphore),
    );
    // Password history repository — used by the password-change handler.
    let password_history_repo = SurrealPasswordHistoryRepository::new(db.client().clone());
    let consent_repo = axiam_db::SurrealConsentRepository::new(db.client().clone());
    let account_deletion_repo = SurrealAccountDeletionRepository::new(db.client().clone());
    let export_job_repo = SurrealExportJobRepository::new(db.client().clone());
    let erasure_proof_repo = SurrealErasureProofRepository::new(db.client().clone());

    let webauthn_cred_repo = SurrealWebauthnCredentialRepository::new(db.client().clone());
    let webauthn_service = WebauthnService::new(webauthn_cred_repo.clone(), config.auth.clone())
        .expect("Failed to build WebauthnService");
    let mfa_method_service = MfaMethodService::new(user_repo.clone(), webauthn_cred_repo);

    // PKI service — encryption key for CA private keys (SEC-012).
    // Absent key → None; operations that encrypt private key material will fail fast
    // with a clear error rather than silently using an all-zero key.
    let pki_config = PkiConfig {
        encryption_key: load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY"),
    };
    let cert_repo = SurrealCertificateRepository::new(db.client().clone());
    let ca_service = CaService::new(
        ca_cert_repo.clone(),
        pki_config.clone(),
        Arc::clone(&crypto_semaphore),
    );
    let pgp_repo = SurrealPgpKeyRepository::new(db.client().clone());
    let pgp_service = PgpService::new(pgp_repo, pki_config.clone(), Arc::clone(&crypto_semaphore));
    let cert_service = CertService::new(
        ca_cert_repo,
        cert_repo.clone(),
        pki_config,
        Arc::clone(&crypto_semaphore),
    );
    // SEC-024: DeviceAuthService now holds a CA repo for chain verification.
    // SurrealCaCertificateRepository is cloned; each clone shares the underlying Surreal<C>.
    let device_auth_service =
        DeviceAuthService::new(cert_repo.clone(), SurrealCaCertificateRepository::new(db.client().clone()));
    let webhook_repo = SurrealWebhookRepository::new(db.client().clone());
    // SEC-031: Webhook secrets stored AES-256-GCM encrypted using the same PKI
    // encryption key. Falls back to an all-zero key if env var is absent so the
    // server still starts (will fail to decrypt secrets set under a real key).
    let webhook_enc_key: [u8; 32] =
        load_key_from_env("AXIAM__PKI__ENCRYPTION_KEY").unwrap_or([0u8; 32]);
    let webhook_delivery =
        axiam_api_rest::webhook::WebhookDeliveryService::new(webhook_repo.clone(), webhook_enc_key);
    let settings_repo = SurrealSettingsRepository::new(db.client().clone());
    let federation_config_repo = SurrealFederationConfigRepository::new(db.client().clone());
    let federation_link_repo = SurrealFederationLinkRepository::new(db.client().clone());
    let assertion_replay_repo = SurrealAssertionReplayRepository::new(db.client().clone());
    let federation_login_state_repo =
        SurrealFederationLoginStateRepository::new(db.client().clone());
    // Process-wide JWKS cache shared by all OIDC federation handlers (D-01/D-02/D-03).
    let jwks_cache = Arc::new(JwksCache::new());
    // Disable automatic redirects to prevent SSRF bypass (an HTTPS URL
    // could redirect to http:// or an internal host). Apply a global
    // timeout for consistent outbound HTTP behaviour.
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client");
    let oauth2_client_repo = SurrealOAuth2ClientRepository::new(db.client().clone());
    let auth_code_repo = SurrealAuthorizationCodeRepository::new(db.client().clone());
    let refresh_token_repo = SurrealRefreshTokenRepository::new(db.client().clone());
    // Separate instance for password-reset/change handlers that need direct
    // RefreshTokenRepository access via web::Data (TokenService owns the main one).
    let handler_refresh_token_repo = SurrealRefreshTokenRepository::new(db.client().clone());

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

    config.rate_limit.validate();

    let bind_addr = config.server.bind_address();
    let server_config = config.server.clone();
    let rate_limit_cfg = config.rate_limit.clone();
    let auth_config = config.auth.clone();
    let health_checker: Arc<dyn HealthChecker> = Arc::new(db);

    tracing::info!(bind = %bind_addr, "Starting REST API server");

    // Build REST-facing authorization checker (D-01, D-02).
    let rest_authz: Arc<dyn axiam_api_rest::authz::AuthzChecker> =
        Arc::new(axiam_authz::AuthorizationEngine::new(
            role_repo.clone(),
            permission_repo.clone(),
            resource_repo.clone(),
            scope_repo.clone(),
            group_repo.clone(),
        ));

    // Spawn AMQP authorization consumer on a background task.
    // Uses a publisher channel because the consumer also publishes responses.
    let amqp_channel = amqp
        .create_publisher_channel()
        .await
        .expect("Failed to create AMQP authz publisher channel");
    let amqp_engine = axiam_authz::AuthorizationEngine::new(
        role_repo.clone(),
        permission_repo.clone(),
        resource_repo.clone(),
        scope_repo.clone(),
        group_repo.clone(),
    );
    tokio::spawn(async move {
        axiam_amqp::authz_consumer::start_authz_consumer(amqp_channel, amqp_engine).await;
        tracing::error!("AMQP authz consumer exited — shutting down process");
        std::process::exit(1);
    });

    // Create notification publisher (available for services to emit events).
    let notif_channel = amqp
        .create_publisher_channel()
        .await
        .expect("Failed to create AMQP notification channel");
    let notification_publisher = axiam_amqp::NotificationPublisher::new(notif_channel);

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
    tokio::spawn(async move {
        axiam_amqp::audit_consumer::start_audit_consumer(audit_channel, amqp_audit_repo).await;
        tracing::error!("AMQP audit consumer exited — shutting down process");
        std::process::exit(1);
    });

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
        tokio::spawn(async move {
            axiam_amqp::start_mail_consumer(mail_channel, mail_email_config_repo, mail_audit_repo)
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
    let grpc_engine = axiam_authz::AuthorizationEngine::new(
        role_repo.clone(),
        permission_repo.clone(),
        resource_repo.clone(),
        scope_repo.clone(),
        group_repo.clone(),
    );
    let grpc_user_repo = user_repo.clone();
    let grpc_auth_config = config.auth.clone();
    let grpc_config = config.grpc.clone();
    tokio::spawn(async move {
        if let Err(e) = start_grpc_server(
            grpc_addr,
            grpc_engine,
            grpc_user_repo,
            grpc_auth_config,
            &grpc_config,
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
        Arc::new(user_repo.clone()),
        Arc::new(auth_service.clone()),
        Arc::new(audit_repo.clone()),
        Arc::new(account_deletion_repo.clone()),
        Arc::new(erasure_proof_repo.clone()),
        Arc::new(cleanup_federation_link_repo),
        Arc::new(export_job_repo.clone()),
        Arc::new(consent_repo.clone()),
        cleanup_mail_publisher,
        config.gdpr_pseudonym_pepper,
        config.email_encryption_key,
        Duration::from_secs(config.cleanup_interval_secs),
        cleanup_shutdown_rx,
    );
    let cleanup_handle = tokio::spawn(cleanup.run());

    HttpServer::new(move || {
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
            .app_data(web::Data::new(rest_authz.clone()))
            .app_data(web::Data::new(auth_config.clone()))
            .app_data(web::Data::new(db_handle.clone()))
            .app_data(web::Data::new(health_checker.clone()))
            .app_data(web::Data::new(audit_repo.clone()))
            .app_data(web::Data::new(org_repo.clone()))
            .app_data(web::Data::new(tenant_repo.clone()))
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(group_repo.clone()))
            .app_data(web::Data::new(role_repo.clone()))
            .app_data(web::Data::new(permission_repo.clone()))
            .app_data(web::Data::new(resource_repo.clone()))
            .app_data(web::Data::new(scope_repo.clone()))
            .app_data(web::Data::new(service_account_repo.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(webauthn_service.clone()))
            .app_data(web::Data::new(mfa_method_service.clone()))
            .app_data(web::Data::new(notification_publisher.clone()))
            .app_data(web::Data::new(mail_outbound_publisher.clone()))
            .app_data(web::Data::new(session_repo.clone()))
            .app_data(web::Data::new(session_validator.clone()))
            .app_data(web::Data::new(handler_refresh_token_repo.clone()))
            .app_data(web::Data::new(password_history_repo.clone()))
            .app_data(web::Data::new(consent_repo.clone()))
            .app_data(web::Data::new(account_deletion_repo.clone()))
            .app_data(web::Data::new(export_job_repo.clone()))
            .app_data(web::Data::new(erasure_proof_repo.clone()))
            .app_data(web::Data::new(config.email_encryption_key))
            .app_data(web::Data::new(ca_service.clone()))
            .app_data(web::Data::new(cert_service.clone()))
            .app_data(web::Data::new(cert_repo.clone()))
            .app_data(web::Data::new(device_auth_service.clone()))
            .app_data(web::Data::new(pgp_service.clone()))
            .app_data(web::Data::new(webhook_repo.clone()))
            .app_data(web::Data::new(webhook_delivery.clone()))
            .app_data(web::Data::new(oauth2_client_repo.clone()))
            .app_data(web::Data::new(authorize_service.clone()))
            .app_data(web::Data::new(token_service.clone()))
            .app_data(web::Data::new(settings_repo.clone()))
            .app_data(web::Data::new(federation_config_repo.clone()))
            .app_data(web::Data::new(federation_link_repo.clone()))
            .app_data(web::Data::new(assertion_replay_repo.clone()))
            .app_data(web::Data::new(federation_login_state_repo.clone()))
            .app_data(web::Data::new(http_client.clone()))
            .app_data(web::Data::new(jwks_cache.clone()))
            .configure(health_routes)
            .configure(|cfg| register_api_v1_routes::<axiam_db::WsClient>(cfg, &rl))
            .configure(openapi_routes)
    })
    .bind(&bind_addr)?
    .run()
    .await?;

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

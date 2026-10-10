//! AXIAM Server — Application entry point.

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

use axiam_api_rest::HealthChecker;
use axiam_core::repository::{OrganizationRepository, Pagination, TenantRepository};
use axiam_db::{
    SurrealEmailConfigRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use axiam_server::boot::{AppConfig, ServeOptions};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Subcommands. All of them run before tracing init and before the async
    // stack, so a probe stays lightweight, `--dump-openapi` needs no
    // infrastructure, and nothing a subcommand prints is interleaved with
    // startup logging. The parse itself is `axiam_server::cli`, which is
    // unit-tested; `main.rs` cannot be linked from `tests/`.
    match axiam_server::cli::parse(&std::env::args().collect::<Vec<_>>()) {
        axiam_server::cli::Command::Serve => {}

        // D-09: self-probe /health, exit 0 on 2xx, exit 1 otherwise. The
        // scheme follows the listener and the trust anchors follow the
        // certificate the server serves, so a direct-TLS deployment needs no
        // `AXIAM_HEALTHCHECK_URL` at all (DF-016) — and there is no switch that
        // skips verification.
        axiam_server::cli::Command::Healthcheck => {
            let probe = axiam_server::healthcheck::resolve(|name| std::env::var(name).ok());
            std::process::exit(i32::from(!axiam_server::healthcheck::run(&probe)));
        }

        // FND-01: print the OpenAPI JSON spec to stdout and exit 0. Generate
        // the committed sdks/openapi.json with:
        //   cargo build -p axiam-server --no-default-features
        //   ./target/debug/axiam-server --dump-openapi > sdks/openapi.json
        axiam_server::cli::Command::DumpOpenApi => {
            let json = serde_json::to_string_pretty(&axiam_api_rest::openapi::api_doc())
                .expect("OpenAPI serialization failed");
            println!("{json}");
            std::process::exit(0);
        }

        // DF-019: replace the bootstrap setup token. The gate lives in
        // `axiam_db::remint_bootstrap_setup_token` — no `user` row and no
        // consumed token, i.e. a deployment that has no administrator yet,
        // which is exactly the state an operator who lost the first-boot token
        // is stuck in. Before this, the documented recovery was to wipe the
        // volume.
        axiam_server::cli::Command::RemintSetupToken => {
            std::process::exit(remint_setup_token().await);
        }

        axiam_server::cli::Command::Usage(line) => {
            eprintln!("{line}");
            std::process::exit(2);
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

    // ---------------------------------------------------------------------
    // Secrets
    // ---------------------------------------------------------------------
    //
    // Every long-lived secret is resolved here, through one provider, rather
    // than by each subsystem reading its own environment variable. That is the
    // point of `axiam_core::secrets`: where secrets come from is a deployment
    // concern, and it should be changeable in one place instead of nine.
    //
    // A provider failure stops startup. Deliberate: a secret failing *open*
    // silently disables a control the operator believes is on, and "the server
    // did not start" is a far better signal than "logins began failing an hour
    // later".
    use axiam_auth::secrets::SecretProviderKind;
    use axiam_core::secrets as keys;

    let secret_provider = {
        let kind = SecretProviderKind::from_env()
            .unwrap_or_else(|e| panic!("secret provider configuration is invalid: {e}"));
        // A short-lived client: this runs once, before the shared one exists.
        let bootstrap_http = reqwest::Client::new();
        let provider = kind
            .build(&bootstrap_http, keys::ALL_KEYS, keys::ALL_SECRETS)
            .await
            .unwrap_or_else(|e| panic!("secret provider `{kind:?}` could not be initialised: {e}"));
        tracing::info!(provider = provider.describe(), "secret provider ready");
        provider
    };

    let read_key = |name: &str| {
        secret_provider
            .get_key(name)
            .unwrap_or_else(|e| panic!("reading {name} from the secret provider failed: {e}"))
    };
    let read_secret = |name: &str| {
        secret_provider
            .get_secret(name)
            .unwrap_or_else(|e| panic!("reading {name} from the secret provider failed: {e}"))
    };

    // DF-018/DF-022. Four variables were documented as the way to configure a
    // secret and are read by nothing; the deployment that set one has the
    // feature silently off. The names are corrected everywhere else in this
    // release, so this is for the operator who upgrades with the old spelling
    // still in the pod spec. It reads no value — `legacy_secret_env_warnings`
    // takes a predicate, not a lookup — and says nothing when the variable
    // AXIAM does read is also set.
    for warning in
        axiam_server::legacy_env::legacy_secret_env_warnings(|v| std::env::var_os(v).is_some())
    {
        tracing::warn!(
            legacy = warning.legacy,
            variable = %warning.resolved,
            "{} is set and is read by nothing. AXIAM reads this secret from {}; \
             until that variable is set, the feature it configures is off.",
            warning.legacy,
            warning.resolved,
        );
    }

    // Load MFA encryption key.
    config.auth.mfa_encryption_key = read_key(keys::MFA_ENCRYPTION_KEY);
    if config.auth.mfa_encryption_key.is_some() {
        tracing::info!("MFA encryption key loaded");
    }

    // Load federation encryption key.
    config.auth.federation_encryption_key = read_key(keys::FEDERATION_ENCRYPTION_KEY);
    if config.auth.federation_encryption_key.is_some() {
        tracing::info!("Federation encryption key loaded");
    }

    // The OPAQUE keys. Absent, the OPAQUE endpoints answer 503 rather than
    // quietly leaving clients on password login — see
    // `AuthConfig::opaque_session_key`.
    //
    // Two keys, not one, because rotating them costs wildly different things:
    // the session key seals 120 seconds of in-flight state, while losing the
    // setup key makes every registration record in every tenant unopenable.
    // That asymmetry is why the setup key is the one most worth putting in a
    // KMS — see `axiam_auth::secrets`.
    config.auth.opaque_session_key = read_key(keys::OPAQUE_SESSION_KEY);
    config.auth.opaque_setup_key = read_key(keys::OPAQUE_SETUP_KEY);
    match (
        config.auth.opaque_session_key.is_some(),
        config.auth.opaque_setup_key.is_some(),
    ) {
        (true, true) => tracing::info!(provider = secret_provider.describe(), "OPAQUE keys loaded"),
        (false, false) => {}
        // Half-configured is worth a warning rather than silence: the operator
        // set one of the two and almost certainly believes OPAQUE is on. Naming
        // the provider matters — the commonest cause is believing a key came
        // from somewhere it did not.
        (session, setup) => tracing::warn!(
            provider = secret_provider.describe(),
            session_key = session,
            setup_key = setup,
            "OPAQUE is only half-configured; both keys are required, so the \
             OPAQUE endpoints will answer 503"
        ),
    }

    // Load email encryption key (D-17).
    config.email_encryption_key = read_key(keys::EMAIL_ENCRYPTION_KEY);
    if config.email_encryption_key.is_some() {
        tracing::info!("Email encryption key loaded");
    }

    // The directory bind-secret key (G-3, D-15). Optional: a deployment that
    // does not federate an LDAP / Active Directory source has no reason to hold
    // one, so its absence is reported at INFO and never refuses boot. What it
    // costs is stated where the operator will read it, because the symptom
    // otherwise appears later and elsewhere — as a refused configuration save.
    config.directory_encryption_key = read_key(keys::DIRECTORY_ENCRYPTION_KEY);
    if config.directory_encryption_key.is_some() {
        tracing::info!(
            provider = secret_provider.describe(),
            "directory encryption key loaded"
        );
    } else {
        tracing::info!(
            provider = secret_provider.describe(),
            "directory encryption key not configured: the LDAP / Active Directory \
             identity source is unavailable (set {} to enable it)",
            keys::env_var_name(keys::DIRECTORY_ENCRYPTION_KEY),
        );
    }

    // The SAML IdP's pairwise-identifier key (G-2, D-22). Optional, like the
    // directory key: a deployment that issues no persistent SAML `NameID` has
    // no use for it, so its absence is INFO and never refuses boot. It must
    // never rotate (see the field's documentation), which is why the log names
    // the variable rather than suggesting one is generated.
    config.saml_pairwise_key = read_key(keys::SAML_PAIRWISE_KEY);
    if config.saml_pairwise_key.is_some() {
        tracing::info!(
            provider = secret_provider.describe(),
            "SAML pairwise-identifier key loaded"
        );
    } else {
        tracing::info!(
            provider = secret_provider.describe(),
            "SAML pairwise-identifier key not configured: SAML sign-on to a service \
             provider using persistent NameIDs is refused (set {} to enable it; it \
             must never change once set)",
            keys::env_var_name(keys::SAML_PAIRWISE_KEY),
        );
    }

    // The AMQP message-signing key (SEC-022/055, SECHRD-08). Mandatory: there
    // is no unsigned code path, and a release build refuses to start without
    // it. Routing it through the provider is what lets a deployment keep it in
    // a KMS alongside every other key rather than as the one secret still
    // living in a container spec.
    //
    // Hex-encoded here because `AmqpConfig::signing_key` is a hex string,
    // whereas the port models it as the 256-bit key it actually is. The
    // adaptation belongs at the composition root, not in the port.
    //
    // Backwards compatible: under the `env` provider this reads
    // `AXIAM__AUTH__AMQP_SIGNING_KEY`, which is a *different* variable from the
    // `AXIAM__AMQP__SIGNING_KEY` that `load_config` already honours. An
    // existing deployment setting the latter is untouched, because the provider
    // answers `None` and the loaded value stands. Setting both makes the
    // provider win, which is the same precedence the JWT keys use above.
    if let Some(key) = read_key(keys::AMQP_SIGNING_KEY) {
        config.amqp.signing_key = Some(hex::encode(key));
        tracing::info!(
            provider = secret_provider.describe(),
            "AMQP signing key loaded"
        );
    }

    // The key webhook secrets, SSF push credentials, SCIM targets, CIBA
    // notification credentials and the PKI custodian are sealed under
    // (`pki_encryption_key`). Resolved here with every other secret and handed
    // to the composition root as configuration.
    config.pki_encryption_key = read_key(keys::PKI_ENCRYPTION_KEY);

    // Load GDPR pseudonym pepper (D-02).
    config.gdpr_pseudonym_pepper = read_key(keys::GDPR_PSEUDONYM_PEPPER);
    if config.gdpr_pseudonym_pepper.is_some() {
        tracing::info!("GDPR pseudonym pepper loaded");
    }

    // The token signing key is the single most valuable secret AXIAM holds:
    // possessing it means being able to mint a token for any principal in any
    // tenant. If the provider carries it, it wins over whatever `load_config`
    // read — that is what lets a production deployment keep it out of the
    // container spec entirely.
    if let Some(pem) = read_secret(keys::JWT_PRIVATE_KEY_PEM) {
        config.auth.jwt_private_key_pem = (*pem).clone();
    }
    if let Some(pem) = read_secret(keys::JWT_PUBLIC_KEY_PEM) {
        config.auth.jwt_public_key_pem = (*pem).clone();
    }

    // ---------------------------------------------------------------------
    // Datastore and broker credentials (T-132's follow-up, R-5)
    // ---------------------------------------------------------------------
    //
    // The three credentials T-132 left behind. They were read by
    // `load_config` from `AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD` and
    // `AXIAM__AMQP__URL` before any provider existed, so a deployment that put
    // every key in Vault still had its datastore password in the pod spec —
    // which is the exact sentence T-132 was closed on.
    //
    // Now: the Vault token (or the `file` provider's mount) is the only
    // credential the container spec has to carry, and these three are fetched
    // in the same round trip as the other eleven secrets.
    //
    // The environment variables **stay, permanently** (decision B of the
    // 2026-09-12 plan). `env` is a supported provider kind, not a legacy path:
    // a single-node deployment, the dev compose file and the E2E stack all use
    // it deliberately, and deprecating the variables would deprecate the
    // provider that reads them.
    //
    // The WARN is scoped to the one case where the operator believes something
    // untrue — a *non-`env`* provider configured, and the value arriving from
    // the environment anyway. Under `env` there is nothing to warn about:
    // reading an environment variable is what that provider is for.
    {
        let provider_is_env = secret_provider.describe() == "env";
        let overlay = |name: &'static str, target: &mut String, what: &str| match read_secret(name)
        {
            Some(value) => {
                *target = (*value).clone();
                tracing::info!(
                    provider = secret_provider.describe(),
                    credential = what,
                    "datastore/broker credential loaded from the secret provider"
                );
            }
            None if provider_is_env || target.is_empty() => {}
            None => tracing::warn!(
                provider = secret_provider.describe(),
                variable = axiam_core::secrets::env_var_override(name).unwrap_or("(none)"),
                credential = what,
                "this credential was read from the environment; the configured secret \
                     provider has no entry for it. Environment variables appear in pod specs, \
                     crash dumps and orchestrator APIs — see docs/deployment/vault.md"
            ),
        };
        overlay(
            keys::DB_USERNAME,
            &mut config.db.username,
            "datastore username",
        );
        overlay(
            keys::DB_PASSWORD,
            &mut config.db.password,
            "datastore password",
        );
        overlay(keys::AMQP_URL, &mut config.amqp.url, "broker URL");
    }

    // R-5: the credential checks that `load_config` used to make, moved here so
    // they run once **every** source has been consulted. Doing it there meant a
    // `vault` deployment had to keep setting the very variables the provider
    // exists to replace.
    assert!(
        !config.auth.jwt_private_key_pem.is_empty(),
        "the token signing key is not configured: set AXIAM__AUTH__JWT_PRIVATE_KEY_PEM, \
         or provide `jwt_private_key_pem` through the configured secret provider"
    );
    assert!(
        !config.auth.jwt_public_key_pem.is_empty(),
        "the token verification key is not configured: set AXIAM__AUTH__JWT_PUBLIC_KEY_PEM, \
         or provide `jwt_public_key_pem` through the configured secret provider"
    );

    // CQ-B14: Parse Ed25519 JWT keys once at startup and cache them in the
    // AuthConfig so per-request token issuance/verification skips PEM parsing.
    config
        .auth
        .resolve_keys()
        .expect("Failed to parse JWT Ed25519 keys — check AXIAM__AUTH__JWT_*_KEY_PEM");
    tracing::info!("JWT Ed25519 keys parsed and cached (CQ-B14)");

    // Clamp cleanup interval to 60..=3600 seconds (T-04-35).
    config.cleanup_interval_secs = config.cleanup_interval_secs.clamp(60, 3600);

    // Load auth pepper (REQ-14 AC-1). Text, not a key: it is concatenated with
    // the password before Argon2id rather than used as one.
    // SECURITY: do NOT log the pepper value. Wrapped in `SecretString`
    // (SECHRD-12) so the value can never be accidentally `Debug`-printed.
    //
    // The pepper reaches `config.auth.pepper` from `AXIAM__AUTH__PEPPER` (the
    // configuration layer, the variable operators set) or from the provider
    // (`auth_pepper`; `AXIAM__AUTH__AUTH_PEPPER` under the env provider); the
    // log names what actually happened.
    use axiam_server::legacy_env::{PEPPER_CONFIG_VAR, PepperSource, pepper_unset_message};
    let provider_pepper = read_secret(keys::AUTH_PEPPER);
    let source = PepperSource::resolve(provider_pepper.is_some(), config.auth.pepper.is_some());
    if let Some(value) = provider_pepper {
        config.auth.pepper = Some(secrecy::SecretString::from((*value).clone()));
    }
    match source {
        PepperSource::SecretProvider => {
            tracing::info!(provider = secret_provider.describe(), "Auth pepper loaded");
        }
        PepperSource::Configuration => {
            tracing::info!(
                variable = PEPPER_CONFIG_VAR,
                "Auth pepper loaded from configuration"
            );
        }
        PepperSource::Unset => {
            tracing::info!("{}", pepper_unset_message());
        }
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
    // Audit collection minimisation (T-110). Logged either way, for the same
    // reason retention is logged either way further down: the posture in force
    // has to be readable from the startup log rather than inferable only from
    // a manifest. An operator investigating an incident needs to know, before
    // they start reading rows, whether the addresses in them are whole.
    let audit_minimisation =
        axiam_core::audit_minimisation::AuditMinimisation::new(config.audit.minimise);
    if audit_minimisation.is_enabled() {
        tracing::info!(
            "audit collection minimisation is ON (AXIAM__AUDIT__MINIMISE=true) — client \
             addresses are truncated to /24 or /48 and a user-agent is reduced to its family \
             before the append; structured accountability metadata is unaffected"
        );
    } else {
        tracing::info!(
            "audit collection minimisation is OFF (AXIAM__AUDIT__MINIMISE) — full client \
             addresses are recorded; set it when your lawful basis does not support holding \
             them for the retention window"
        );
    }

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
        let boot_audit_repo = axiam_db::SurrealAuditLogRepository::new(pool.handle_for_repo())
            .with_minimisation(audit_minimisation);
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
                "AXIAM__AUTH__EMAIL_ENCRYPTION_KEY missing — \
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
                search: None,
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
                        search: None,
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
                let reconciled = axiam_db::reconcile_default_role_grants(
                    &pool.handle_for_repo().current(),
                    tenant.id,
                )
                .await
                .expect("Failed to reconcile default role grants for tenant");
                if reconciled.granted > 0 {
                    tracing::info!(
                        tenant = %tenant.id,
                        grants = reconciled.granted,
                        "Back-filled {} missing default-role permission grants",
                        reconciled.granted
                    );
                }
                // Logged separately and at WARN: this REMOVES a capability a
                // role currently has. An operator whose tenant administrator
                // has been minting CA material since before B-04 was fixed
                // will start seeing 403s, and this line is where they find out
                // why (see `ReconcileOutcome`).
                if reconciled.revoked > 0 {
                    tracing::warn!(
                        tenant = %tenant.id,
                        revoked = reconciled.revoked,
                        "Revoked {} organization-level permission grant(s) from this tenant's \
                         default roles — organization-level actions (CA material, tenant and \
                         organization lifecycle) belong to the organization scope only",
                        reconciled.revoked
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

    // Everything from here on is the composition root, `axiam_server::boot::serve`
    // — in the library so that a test can compose the same server over an
    // embedded datastore (G-8, T23.8.1).
    let health_checker: Arc<dyn HealthChecker> = pool.clone();
    axiam_server::boot::serve(config, pool, health_checker, ServeOptions::default()).await
}

/// `axiam-server setup-token --remint` — the whole subcommand, as an exit code.
///
/// Runs before tracing is initialised, so everything it says it says on stdout
/// or stderr directly. **The token goes to stdout and nowhere else**: routing
/// it through `tracing` would put a live credential in the container log a
/// second time, which is the one thing first-boot minting already does once
/// and deliberately.
///
/// Migrations run first. They are idempotent and are what boot does anyway;
/// without them a datastore that has never served would have no
/// `bootstrap_setup_token` table to write to.
///
/// Exit codes: `0` minted, `2` refused, `1` could not tell (configuration,
/// datastore, migration). A refusal is not an error — see
/// [`axiam_db::SetupTokenRemint`].
async fn remint_setup_token() -> i32 {
    let config = load_config();

    let pool = match axiam_db::DbPool::connect(&config.db).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("could not connect to the datastore: {e}");
            return 1;
        }
    };
    let db = pool.handle_for_repo().current();

    if let Err(e) = axiam_db::run_migrations(&db).await {
        eprintln!("could not apply database migrations: {e}");
        return 1;
    }

    match axiam_db::remint_bootstrap_setup_token(&db).await {
        Ok(axiam_db::SetupTokenRemint::Minted(token)) => {
            println!("{token}");
            0
        }
        Ok(axiam_db::SetupTokenRemint::RefusedUserExists) => {
            eprintln!(
                "refused: this deployment already has at least one user. The setup token is \
                 re-mintable only before anyone has bootstrapped; an existing administrator \
                 creates further accounts through the authenticated API."
            );
            2
        }
        Ok(axiam_db::SetupTokenRemint::RefusedTokenConsumed) => {
            eprintln!(
                "refused: a bootstrap setup token has already been redeemed on this \
                 deployment. Whatever that bootstrap created is the way in."
            );
            2
        }
        Err(e) => {
            eprintln!("could not re-mint the setup token: {e}");
            1
        }
    }
}

fn load_config() -> AppConfig {
    let builder = config::Config::builder()
        .add_source(config::File::with_name("config/default").required(false))
        .add_source(config::Environment::with_prefix("AXIAM").separator("__"));

    let config: AppConfig = builder
        .build()
        .and_then(|c| c.try_deserialize())
        .expect("Failed to load configuration — check config/default.toml or AXIAM__* env vars");

    // The signing keys are NOT asserted here (T-132 follow-up, R-5). They are
    // asserted in `validate_credentials_after_secrets`, which runs after the
    // secret provider has been consulted — because on a `vault` or `file`
    // deployment they legitimately are not in the environment at all, and
    // asserting here forced every such deployment to keep the very variable
    // the provider exists to replace. The check did not move because it was
    // wrong; it moved because it ran at the one point where it could only see
    // one of the two sources.

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
        // The CONFIGURED issuer must still be a root URL. T21.6 did not lift
        // this assertion, it narrowed what it is about.
        //
        // Before T21.6 the reason was a limitation: discovery lived at a fixed
        // `/.well-known/` route and endpoints were built as `{issuer}/oauth2/…`,
        // so a configured path broke both. T21.6 built those routes — but it
        // built them for an issuer AXIAM *derives*, `{root}/t/{tenant_id}`, and
        // the derivation needs a root to derive from. A configured
        // `https://host/base` would make the tenant issuer
        // `https://host/base/t/{T}` while the routes stay at `/t/{T}/…`, so the
        // document would name endpoints the server does not serve.
        //
        // The tenant path is derived, never configured. That is the rule this
        // assertion now states.
        assert!(
            url.path() == "/" || url.path().is_empty(),
            "AXIAM issuer URLs must be a bare root URL; the per-tenant \
             issuer path (AXIAM__AUTH__TENANT_ISSUER_PATHS) is derived \
             from it as {{root}}/t/{{tenant_id}} and is never configured: \
             {issuer}",
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

    // T21.6 — the other half of "derived, never configured": there must be
    // something to derive from. `jwt_issuer` is a bare identifier rather than a
    // URL on most deployments, and `{axiam}/t/{T}` is not an issuer any client
    // can turn into a discovery URL, so the flag is refused rather than
    // silently producing one. A hard failure at boot, not a warning: a
    // deployment that came up serving unusable issuers would be discovered by
    // an MCP client, not by its operator.
    assert!(
        !(config.auth.tenant_issuer_paths && config.auth.oauth2_issuer_url.trim().is_empty()),
        "AXIAM__AUTH__TENANT_ISSUER_PATHS requires \
         AXIAM__AUTH__OAUTH2_ISSUER_URL to be set: the per-tenant issuer \
         is derived from it as {{root}}/t/{{tenant_id}}",
    );

    config
}

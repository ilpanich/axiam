//! Periodic cleanup task for expired federation rows, GDPR purges, and export jobs.
//!
//! SurrealDB v3 does not support native TTL on rows (RESEARCH §7), so this task
//! periodically sweeps various tables:
//! - `saml_assertion_replay` and `federation_login_state`: expired rows
//! - `user`: accounts past their scheduled purge date (D-05/D-06/D-08)
//! - `export_job`: queued jobs waiting to have their encrypted blob generated (D-12)
//!
//! The task shuts down cleanly when the caller sends `true` through the watch
//! channel (D-09, D-24).

use std::sync::Arc;
use std::time::Duration;

use axiam_amqp::MailOutboundPublisher;
use axiam_api_rest::handlers::gdpr::write_erasure_audit_with_dlq;
use axiam_auth::AuthService;
use axiam_auth::crypto::{encrypt_separate, gdpr_pseudonym};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::gdpr::CreateErasureProof;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::repository::{
    AccountDeletionRepository, AmqpNonceRepository, AssertionReplayRepository, AuditLogFilter,
    AuditLogRepository, ConsentRepository, ErasureProofRepository, ExportJobRepository,
    FederationLinkRepository, FederationLoginStateRepository, GroupRepository, MailPublisher,
    Pagination, PasswordHistoryRepository, RoleRepository, SessionRepository,
    SsoHandoffCodeRepository, TenantRepository, UserRepository, WebauthnCredentialRepository,
};
use axiam_db::{
    SurrealAccountDeletionRepository, SurrealAmqpNonceRepository, SurrealAssertionReplayRepository,
    SurrealAuditLogRepository, SurrealConsentRepository, SurrealErasureProofRepository,
    SurrealExportJobRepository, SurrealFederationLinkRepository,
    SurrealFederationLoginStateRepository, SurrealGroupRepository,
    SurrealPasswordHistoryRepository, SurrealRefreshTokenRepository, SurrealRoleRepository,
    SurrealSessionRepository, SurrealSsoHandoffCodeRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use chrono::Utc;
use surrealdb::Connection;
use tokio::sync::watch;
use uuid::Uuid;

/// Concrete `AuthService` type alias used by `CleanupTask` (same repos as main.rs).
type AuthSvc<C> = AuthService<
    SurrealUserRepository<C>,
    SurrealSessionRepository<C>,
    SurrealFederationLinkRepository<C>,
    SurrealRefreshTokenRepository<C>,
>;

// ---------------------------------------------------------------------------
// CleanupTask
// ---------------------------------------------------------------------------

/// Background task that sweeps expired rows and runs GDPR purge + export jobs.
pub struct CleanupTask<C: Connection> {
    // Existing federation cleanup repos.
    replay_repo: Arc<SurrealAssertionReplayRepository<C>>,
    state_repo: Arc<SurrealFederationLoginStateRepository<C>>,
    // SSO handoff codes. Sixty-second TTL and consumed on use, so in a healthy
    // deployment this sweeps almost nothing — but an abandoned login (the user
    // closed the tab at the IdP) leaves a row behind, and "almost nothing"
    // accumulates without a sweep.
    sso_handoff_code_repo: Arc<SurrealSsoHandoffCodeRepository<C>>,
    // NEW-4: AMQP nonce replay store sweep.
    amqp_nonce_repo: Arc<SurrealAmqpNonceRepository<C>>,
    // GDPR purge sweep (D-05/D-06/D-08).
    user_repo: Arc<SurrealUserRepository<C>>,
    auth_svc: Arc<AuthSvc<C>>,
    audit_repo: Arc<SurrealAuditLogRepository<C>>,
    account_deletion_repo: Arc<SurrealAccountDeletionRepository<C>>,
    erasure_proof_repo: Arc<SurrealErasureProofRepository<C>>,
    federation_link_repo: Arc<SurrealFederationLinkRepository<C>>,
    // Credential/authorization tables purged on erasure and surfaced in exports
    // (SEC-056, CQ-B38).
    role_repo: Arc<SurrealRoleRepository<C>>,
    group_repo: Arc<SurrealGroupRepository<C>>,
    webauthn_repo: Arc<SurrealWebauthnCredentialRepository<C>>,
    password_history_repo: Arc<SurrealPasswordHistoryRepository<C>>,
    // GDPR export sweep (D-12).
    export_job_repo: Arc<SurrealExportJobRepository<C>>,
    consent_repo: Arc<SurrealConsentRepository<C>>,
    // Real (metadata-only) session data for the export + org_id resolution
    // for the ExportReady mail producer (SECHRD-06/SECHRD-08, D-03c/D-05d).
    tenant_repo: Arc<SurrealTenantRepository<C>>,
    session_repo: Arc<SurrealSessionRepository<C>>,
    mail_publisher: Arc<MailOutboundPublisher>,
    // Keys (None = skip the respective sweep with a warning).
    gdpr_pepper: Option<[u8; 32]>,
    export_encryption_key: Option<[u8; 32]>,
    interval: Duration,
    /// Audit retention (T-119). `None` = never prune.
    audit_retention: Option<chrono::Duration>,
    /// T-39/T-143: the revocation feed's table, when the deployment runs one.
    ///
    /// `None` — the default — means the feed is off, no row is ever written,
    /// and this sweep is a no-op. A `Some` here is not optional in the way
    /// `audit_retention`'s is: the entries have their own `expires_at` and the
    /// read path filters on it, so a sweep that never ran would publish a
    /// truthful document over a table that grows forever. It is a size bound,
    /// not a correctness one.
    revoked_session_repo: Option<Arc<axiam_db::SurrealRevokedSessionRepository<C>>>,
    // T21.4 — the two repositories the dynamic-registration sweep reads, plus
    // the settings repository it resolves each row's tenant TTL from.
    oauth2_client_repo: Arc<axiam_db::SurrealOAuth2ClientRepository<C>>,
    oauth2_registration_token_repo: Arc<axiam_db::SurrealOAuth2RegistrationTokenRepository<C>>,
    settings_repo: Arc<axiam_db::SurrealSettingsRepository<C>>,
    /// T-129: records each sweep's outcome for `GET /health/jobs`.
    job_health: crate::job_health::JobHealth,
    shutdown: watch::Receiver<bool>,
}

// ---------------------------------------------------------------------------
// Dynamic client registration sweep (T21.4)
// ---------------------------------------------------------------------------

/// Whether a self-registered client is due to be swept (T21.4).
///
/// A free function, and public, for the reason [`run_erasure_pipeline`] is
/// one: the loop that calls it is awkward to construct in a test, and the
/// decision it makes — *delete somebody's client registration* — is the part
/// worth testing directly.
///
/// The clock it reads is `last_authorized_at` when the client has ever been
/// authorized and `created_at` when it has not. The second case is what the
/// TTL is really for: a registration made once by a tool nobody kept.
///
/// `ttl_days == 0` is never due. Zero means "never sweep", which an operator
/// who prunes out of band may legitimately want, and reading it as "sweep
/// everything immediately" would delete a tenant's whole client table on the
/// next tick.
pub fn dcr_client_is_due_for_sweep(
    client: &axiam_core::models::oauth2_client::OAuth2Client,
    ttl_days: u32,
    now: chrono::DateTime<Utc>,
) -> bool {
    if ttl_days == 0 {
        return false;
    }
    now - dcr_client_last_seen(client) > chrono::Duration::days(i64::from(ttl_days))
}

/// When a `dcr` row was last any use to anybody.
pub fn dcr_client_last_seen(
    client: &axiam_core::models::oauth2_client::OAuth2Client,
) -> chrono::DateTime<Utc> {
    client.last_authorized_at.unwrap_or(client.created_at)
}

/// When a `cimd` row was last any use to anybody — T21.8 / MCP-04.
///
/// `max(updated_at, last_authorized_at, created_at)`, and each of the three is
/// load-bearing.
///
/// **`updated_at` is the one that matters**, and it is already the stamp
/// #470 proposed adding a column for. `materialise_if_cimd` calls
/// `upsert_cimd_client` after *every* successful resolve, and a resolve
/// returns from the in-memory document cache on a hit — so the upsert runs
/// whether or not a fetch happened, on authorize, on token and on PAR. The
/// `UPDATE` arm sets `updated_at = time::now()`. A `cimd` row's `updated_at`
/// is therefore "last presented", with a resolution of one request, and no
/// migration is needed to read it.
///
/// `last_authorized_at` is read beside it because `touch_last_authorized`
/// guards on `managed_by != 'admin'` rather than `== 'dcr'`, so it is stamped
/// on `cimd` rows too. Taking the maximum of the three cannot pick a stamp
/// older than the row's real last use, whichever of them the write path
/// happened to move.
pub fn cimd_client_last_seen(
    client: &axiam_core::models::oauth2_client::OAuth2Client,
) -> chrono::DateTime<Utc> {
    client
        .updated_at
        .max(client.last_authorized_at.unwrap_or(client.created_at))
        .max(client.created_at)
}

/// Whether a `cimd` shadow row has gone unseen for longer than its tenant's
/// TTL (T21.8 / MCP-04).
///
/// Shares `dcr_unused_client_ttl_days` with the `dcr` sweep, on T21.5
/// amendment 4's precedent: `dcr_allowed_scopes` governs both mechanisms and
/// keeps its `dcr_` name because DCR defined it. A tenth CIMD field would cost
/// a spec change, an ordering decision, a range check and a rewrite of the
/// test that asserts the posture overrides all nine — for a number the
/// operator has already chosen once.
///
/// `0` is never due, for the same reason it is not in the `dcr` arm.
pub fn cimd_client_is_due_for_sweep(
    client: &axiam_core::models::oauth2_client::OAuth2Client,
    ttl_days: u32,
    now: chrono::DateTime<Utc>,
) -> bool {
    if ttl_days == 0 {
        return false;
    }
    now - cimd_client_last_seen(client) > chrono::Duration::days(i64::from(ttl_days))
}

/// The `dcr` arm of [`sweep_unused_external_clients`], kept as a named entry
/// point because T21.4's tests and the task method both call it that.
pub async fn sweep_unused_dcr_clients<CR, TR, SR>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
{
    sweep_unused_external_clients(
        client_repo,
        tenant_repo,
        settings_repo,
        axiam_core::models::oauth2_client::ManagedBy::Dcr,
        now,
    )
    .await
}

/// The `cimd` arm of [`sweep_unused_external_clients`] (T21.8 / MCP-04).
pub async fn sweep_unused_cimd_clients<CR, TR, SR>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
{
    sweep_unused_external_clients(
        client_repo,
        tenant_repo,
        settings_repo,
        axiam_core::models::oauth2_client::ManagedBy::Cimd,
        now,
    )
    .await
}

/// Delete externally registered clients that have gone unseen for longer than
/// their tenant's `dcr_unused_client_ttl_days` (T21.4, widened to `cimd` by
/// T21.8 / MCP-04).
///
/// One `managed_by` per call, so `/health/jobs` can distinguish the two
/// sweeps: they delete different things for different reasons and an operator
/// debugging one should not have to read the other's counter.
///
/// # What it will not touch
///
/// Never `admin`. An administrator's client is never swept, however long it
/// sits unused, because somebody decided it should exist and nothing here is
/// entitled to reverse that. The repository query filters on the value rather
/// than on "not admin", so a fourth provenance added later is opted **in** by
/// somebody writing it down.
///
/// # Why `cimd` is swept now, when T21.4 argued it should not be
///
/// T21.4's reasoning, which this function used to carry: a CIMD shadow row is
/// a cache of a document the client publishes, so deleting it would be
/// re-materialised on the next request and the TTL would mean nothing.
///
/// That is right about TTL semantics and says nothing about storage, which is
/// what MCP-04 is about: a cache that is never evicted is not a cache. An
/// inert row is still a row — listed on the OAuth2 clients page, counted in
/// every `list_all_by_managed_by` this function runs, and a permanent write a
/// stranger made at the cost of one unauthenticated request. And eviction on
/// last-seen is *consistent* with the old argument rather than against it: a
/// row deleted while its document is still published is re-materialised on the
/// next request, which is exactly what a cache should do. What it must not do
/// is delete a row that is still in use, which is what
/// [`cimd_client_last_seen`] is for — every resolve moves `updated_at`, so a
/// document presented once a day is never due under a 30-day TTL.
///
/// # Per-tenant TTL, resolved per row
///
/// The window is a tenant setting, so each row's tenant is resolved and its
/// effective settings read. Deployment-wide sweeps elsewhere in this file
/// (audit retention) deliberately do **not** work this way, and the difference
/// is who owns the decision: audit retention is a property of the datastore an
/// operator is responsible for, where this is a property of the tenant's
/// relationship with the clients it lets register.
///
/// The settings read is cached per tenant for the duration of one sweep —
/// `dcr_max_clients` bounds the rows per tenant, so a hundred clients in one
/// tenant is one read rather than a hundred.
///
/// A tenant whose settings cannot be read is skipped: the fail-closed
/// direction for a sweep that **deletes** is to delete nothing.
pub async fn sweep_unused_external_clients<CR, TR, SR>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    managed_by: axiam_core::models::oauth2_client::ManagedBy,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
{
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::repository::SettingsRepository;

    type DuePredicate =
        fn(&axiam_core::models::oauth2_client::OAuth2Client, u32, chrono::DateTime<Utc>) -> bool;
    let (job, is_due): (&str, DuePredicate) = match managed_by {
        ManagedBy::Dcr => ("dcr_unused_clients", dcr_client_is_due_for_sweep),
        ManagedBy::Cimd => ("cimd_unused_clients", cimd_client_is_due_for_sweep),
        // An administrator's client is never swept. Answered here rather than
        // by trusting every caller, because the argument for it is a security
        // one and belongs next to the query.
        ManagedBy::Admin => return Ok(0),
    };

    let clients = client_repo.list_all_by_managed_by(managed_by).await?;
    if clients.is_empty() {
        return Ok(0);
    }

    let mut ttl_by_tenant: std::collections::HashMap<Uuid, Option<u32>> =
        std::collections::HashMap::new();
    let mut removed = 0u64;

    for client in clients {
        let ttl_days = match ttl_by_tenant.get(&client.tenant_id) {
            Some(cached) => *cached,
            None => {
                let resolved = match tenant_repo.get_by_id(client.tenant_id).await {
                    Ok(tenant) => SettingsRepository::get_effective_settings(
                        settings_repo,
                        tenant.organization_id,
                        client.tenant_id,
                    )
                    .await
                    .ok()
                    .map(|s| s.oidc.dcr_unused_client_ttl_days),
                    Err(_) => None,
                };
                ttl_by_tenant.insert(client.tenant_id, resolved);
                resolved
            }
        };
        // `None` is an unreadable tenant or an unreadable settings row.
        let Some(ttl_days) = ttl_days else {
            continue;
        };
        if !is_due(&client, ttl_days, now) {
            continue;
        }

        if let Err(e) = client_repo.delete(client.tenant_id, client.id).await {
            // One failure must not stop the sweep: the next row may be a
            // different tenant entirely.
            tracing::warn!(
                job,
                error = %e,
                client_id = %client.client_id,
                "could not delete an unused externally registered client"
            );
            continue;
        }
        removed += 1;
        tracing::info!(
            job,
            tenant_id = %client.tenant_id,
            client_id = %client.client_id,
            ttl_days,
            "deleted an externally registered client that has gone unseen within its \
             tenant's TTL"
        );
    }

    Ok(removed)
}

// ---------------------------------------------------------------------------
// Erasure pipeline (test-seam extraction — RESEARCH.md Pattern 3, SECHRD-06)
// ---------------------------------------------------------------------------

/// Run the GDPR erasure pipeline for a single user: pseudonymize audit actor
/// references, anonymize the user row, then write the erasure proof
/// STRICTLY LAST.
///
/// Extracted as a free function generic over the three repo traits it needs
/// (rather than a `CleanupTask` method) so a unit test can inject a
/// synthetic failing `AuditLogRepository` double without depending on
/// `CleanupTask`'s concrete `Arc<SurrealXxxRepository<C>>` fields — `pub` so
/// `axiam-server`'s integration tests (which link this crate's library
/// target) can call it directly.
///
/// Ordering is a hard security invariant (D-03a, SECHRD-06 / T-25-13):
/// - `pseudonymize_actor` is now FATAL (`?`, no swallow-and-continue). A
///   failed audit-actor scrub must abort the erasure — no PII-bearing step
///   may ever be silently skipped (RESEARCH Pitfall 2).
/// - `anonymize_user` runs BEFORE the proof (not after). It is the ONLY
///   step that clears the user's `deletion_pending` flag that
///   `find_due_for_purge` selects on, so if it never runs (an earlier step
///   failed and aborted via `?`), the user remains re-selectable for a
///   retry (RESEARCH Assumption A3).
/// - `erasure_proof_repo.create` is the LITERAL LAST statement. It only
///   fires once every PII-bearing step above has succeeded — a proof must
///   never certify an erasure that did not fully happen (Pitfall 3). The DB
///   UNIQUE index on `(tenant_id, user_id)` (plan 25-04) makes a retried
///   erasure's duplicate proof insert an idempotent rejection (D-03b), not
///   a silent overwrite.
pub async fn run_erasure_pipeline<A, EP, U>(
    audit_repo: &A,
    erasure_proof_repo: &EP,
    user_repo: &U,
    tenant_id: Uuid,
    user_id: Uuid,
    pseudonym: &str,
    email_hash: &str,
) -> Result<(), AxiamError>
where
    A: AuditLogRepository,
    EP: ErasureProofRepository,
    U: UserRepository,
{
    // FATAL now (was: `if let Err(e) = ... { tracing::warn!(...) }`).
    audit_repo
        .pseudonymize_actor(tenant_id, user_id, pseudonym)
        .await?;

    // Clears `deletion_pending` — the re-selection anchor. Must run before
    // the proof so a failure here (unreachable in practice since this is
    // now the second of three fallible steps) still leaves the user due.
    user_repo
        .anonymize_user(tenant_id, user_id, email_hash, pseudonym)
        .await?;

    // Written STRICTLY LAST — only reached once every step above succeeded.
    erasure_proof_repo
        .create(CreateErasureProof {
            pseudonym: pseudonym.to_string(),
            tenant_id,
            user_id,
            erased_at: Utc::now(),
        })
        .await?;

    Ok(())
}

/// The Art. 15 `profile` section of one user's export.
///
/// A free function, and tested as one, because its **key set** is half of
/// T-261's gate: `axiam_core::personal_data::export_keys()` is the declared
/// answer to "what does a subject get to see", and
/// `the_profile_section_shows_exactly_the_declared_export_keys` requires this
/// literal to match it. A column classified as exported and missing here is a
/// column the subject is never shown — the defect that nearly stranded
/// `phone_number` and `address`, whose own entry warned that the path is an
/// explicit field list and that a column not named in it is never exported.
///
/// The literal is deliberately **not** derived from the inventory. Two of its
/// entries are not plain column reads: `id` is the record identifier rather
/// than a `DEFINE FIELD`, and `phone_number_verified` is a derived boolean
/// rather than the `phone_number_verified_at` timestamp — matching the claim
/// the subject would have seen released, since exporting the internal column
/// name would describe AXIAM's storage rather than the subject's data.
/// Deriving the section would have to special-case both, which is a worse
/// thing to maintain than a checked list.
///
/// EXCLUDED (D-10): `password_hash`, `mfa_secret`, any token_hash values.
fn profile_section(user: &axiam_core::models::user::User) -> serde_json::Value {
    serde_json::json!({
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "status": user.status,
        "mfa_enabled": user.mfa_enabled,
        "phone_number": user.phone_number,
        "phone_number_verified": user.phone_number_verified_at.is_some(),
        "address": user.address,
        "metadata": user.metadata,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    })
}

impl<C: Connection + Send + Sync + 'static> CleanupTask<C> {
    /// Construct a new `CleanupTask`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replay_repo: Arc<SurrealAssertionReplayRepository<C>>,
        state_repo: Arc<SurrealFederationLoginStateRepository<C>>,
        sso_handoff_code_repo: Arc<SurrealSsoHandoffCodeRepository<C>>,
        amqp_nonce_repo: Arc<SurrealAmqpNonceRepository<C>>,
        user_repo: Arc<SurrealUserRepository<C>>,
        auth_svc: Arc<AuthSvc<C>>,
        audit_repo: Arc<SurrealAuditLogRepository<C>>,
        account_deletion_repo: Arc<SurrealAccountDeletionRepository<C>>,
        erasure_proof_repo: Arc<SurrealErasureProofRepository<C>>,
        federation_link_repo: Arc<SurrealFederationLinkRepository<C>>,
        role_repo: Arc<SurrealRoleRepository<C>>,
        group_repo: Arc<SurrealGroupRepository<C>>,
        webauthn_repo: Arc<SurrealWebauthnCredentialRepository<C>>,
        password_history_repo: Arc<SurrealPasswordHistoryRepository<C>>,
        export_job_repo: Arc<SurrealExportJobRepository<C>>,
        consent_repo: Arc<SurrealConsentRepository<C>>,
        tenant_repo: Arc<SurrealTenantRepository<C>>,
        session_repo: Arc<SurrealSessionRepository<C>>,
        mail_publisher: Arc<MailOutboundPublisher>,
        gdpr_pepper: Option<[u8; 32]>,
        export_encryption_key: Option<[u8; 32]>,
        interval: Duration,
        // A required parameter rather than a builder setter, despite the
        // already-long list: `None` means "never prune", so a forgotten setter
        // would silently restore unbounded audit growth (T-119) and nothing
        // would ever complain. Being unable to construct the task without
        // stating a retention policy is the point.
        audit_retention: Option<chrono::Duration>,
        // T-39/T-143. `None` when the deployment does not run the feed.
        revoked_session_repo: Option<Arc<axiam_db::SurrealRevokedSessionRepository<C>>>,
        // T21.4 — the two repositories the dynamic-registration sweep reads,
        // plus the settings repository it resolves each row's tenant TTL from.
        oauth2_client_repo: Arc<axiam_db::SurrealOAuth2ClientRepository<C>>,
        oauth2_registration_token_repo: Arc<axiam_db::SurrealOAuth2RegistrationTokenRepository<C>>,
        settings_repo: Arc<axiam_db::SurrealSettingsRepository<C>>,
        // T-129: passed in rather than constructed here so `main` can hand
        // the same handle to `AppState`, which is what lets the HTTP layer
        // read what this loop writes.
        job_health: crate::job_health::JobHealth,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            replay_repo,
            state_repo,
            sso_handoff_code_repo,
            amqp_nonce_repo,
            user_repo,
            auth_svc,
            audit_repo,
            account_deletion_repo,
            erasure_proof_repo,
            federation_link_repo,
            role_repo,
            group_repo,
            webauthn_repo,
            password_history_repo,
            export_job_repo,
            consent_repo,
            tenant_repo,
            session_repo,
            mail_publisher,
            gdpr_pepper,
            export_encryption_key,
            interval,
            audit_retention,
            revoked_session_repo,
            oauth2_client_repo,
            oauth2_registration_token_repo,
            settings_repo,
            job_health,
            shutdown,
        }
    }

    /// Run the cleanup loop until a shutdown signal is received.
    ///
    /// Never returns `Err` — all sweep errors are logged at `warn` level and
    /// the loop continues (T-04-36).
    pub async fn run(mut self) -> Result<(), AxiamError> {
        let mut ticker = tokio::time::interval(self.interval);
        // Skip ticks that were missed while the sweep was running to prevent
        // catch-up storms after a pause (T-04-35).
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Existing federation cleanup sweeps.
                    Self::record(
                        &self.job_health,
                        "saml_assertion_replay",
                        self.replay_repo.cleanup_expired().await,
                        tracing::Level::DEBUG,
                    );

                    Self::record(
                        &self.job_health,
                        "federation_login_state",
                        self.state_repo.cleanup_expired().await,
                        tracing::Level::DEBUG,
                    );

                    Self::record(
                        &self.job_health,
                        "sso_handoff_code",
                        self.sso_handoff_code_repo.cleanup_expired().await,
                        tracing::Level::DEBUG,
                    );

                    // NEW-4: sweep expired AMQP replay-protection nonces.
                    Self::record(
                        &self.job_health,
                        "amqp_nonce_replay",
                        self.amqp_nonce_repo.cleanup_expired().await,
                        tracing::Level::DEBUG,
                    );

                    // GDPR purge sweep (D-01..D-06, D-08).
                    Self::record(
                        &self.job_health,
                        "gdpr_purge",
                        self.sweep_pending_purges().await,
                        tracing::Level::INFO,
                    );

                    // GDPR export sweep (D-10..D-12).
                    Self::record(
                        &self.job_health,
                        "gdpr_export",
                        self.sweep_pending_exports().await,
                        tracing::Level::INFO,
                    );

                    // Audit retention sweep (T-119).
                    // INFO because this is the one sweep that destroys records
                    // nothing else can reconstruct: that it ran, and how much it
                    // removed, belongs in the operational log by default.
                    Self::record(
                        &self.job_health,
                        "audit_retention",
                        self.sweep_audit_retention().await,
                        tracing::Level::INFO,
                    );

                    // T-39/T-143: drop revocation entries whose access tokens
                    // have all expired. DEBUG, not INFO: unlike the audit
                    // sweep this destroys nothing anyone could want back —
                    // an expired entry describes only tokens that have
                    // expired on their own `exp`.
                    Self::record(
                        &self.job_health,
                        "revocation_feed",
                        self.sweep_revocation_feed().await,
                        tracing::Level::DEBUG,
                    );

                    // T21.4 — delete self-registered clients nobody has used.
                    // INFO rather than DEBUG, and for the audit sweep's
                    // reason: this one destroys a registration an end user's
                    // client depends on, and an operator debugging "my MCP
                    // client suddenly has to register again" needs to find the
                    // sweep in the log.
                    Self::record(
                        &self.job_health,
                        "dcr_unused_clients",
                        self.sweep_unused_dcr_clients().await,
                        tracing::Level::INFO,
                    );

                    // T21.8 / MCP-04 — the same for CIMD shadow rows, on its
                    // own counter rather than folded into the one above: the
                    // two sweeps delete different things for different reasons
                    // and an operator debugging either should not have to read
                    // the other's number. INFO for the `dcr` sweep's reason —
                    // it destroys a registration a client depends on, even if
                    // that client re-materialises it on its next request.
                    Self::record(
                        &self.job_health,
                        "cimd_unused_clients",
                        self.sweep_unused_cimd_clients().await,
                        tracing::Level::INFO,
                    );

                    // T21.4 — drop expired initial access tokens, spent or
                    // not. DEBUG: an expired token authorises nothing, and
                    // the evidence a spent one carried is in the audit log,
                    // which is append-only.
                    Self::record(
                        &self.job_health,
                        "dcr_registration_tokens",
                        self.sweep_expired_registration_tokens().await,
                        tracing::Level::DEBUG,
                    );
                }
                changed = self.shutdown.changed() => {
                    if changed.is_ok() && *self.shutdown.borrow() {
                        tracing::info!("cleanup task received shutdown signal");
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Log one sweep's outcome and record it for `GET /health/jobs` (T-129).
    ///
    /// Every sweep in [`Self::run`] goes through here rather than logging for
    /// itself. That is the point: the previous shape repeated a six-line
    /// `match` per sweep, and a new sweep added by copying one of them would
    /// have logged correctly while reporting its liveness nowhere — which is
    /// the exact failure T-129 describes, reintroduced one sweep at a time.
    ///
    /// Errors are recorded and swallowed, never propagated: the loop must
    /// survive a failing sweep (T-04-36), and now the failure is visible on
    /// the health endpoint instead of only in the log.
    fn record(
        health: &crate::job_health::JobHealth,
        job: &'static str,
        outcome: Result<u64, AxiamError>,
        level: tracing::Level,
    ) {
        match outcome {
            Ok(n) => {
                if n > 0 {
                    // `tracing`'s macros need a literal level, so the two cases
                    // are spelled out rather than computed.
                    if level == tracing::Level::INFO {
                        tracing::info!(job, affected = n, "sweep completed");
                    } else {
                        tracing::debug!(job, affected = n, "sweep completed");
                    }
                }
                health.record(job, Ok(()));
            }
            Err(e) => {
                tracing::warn!(job, error = ?e, "sweep failed");
                health.record(job, Err(e.to_string()));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Audit retention sweep (T-119)
    // -----------------------------------------------------------------------

    /// Delete audit entries older than the configured retention window.
    ///
    /// A no-op returning `Ok(0)` when retention is `None` (`0` days), which is
    /// the explicit opt-out for deployments that archive out-of-band.
    ///
    /// The cutoff is recomputed from `Utc::now()` on every tick rather than
    /// held as a fixed instant, so a long-running process prunes a moving
    /// window rather than freezing the boundary at whenever it started.
    ///
    /// Runs deployment-wide, not per tenant: retention here is a property of
    /// the datastore an operator is responsible for, and a per-tenant override
    /// would let one tenant's settings decide how long another tenant's
    /// records survive on shared storage. Per-tenant retention is a real
    /// requirement, but it needs a settings surface (org baseline + tenant
    /// override + API + UI) rather than a field on this sweep.
    async fn sweep_audit_retention(&self) -> Result<u64, AxiamError> {
        let Some(retention) = self.audit_retention else {
            return Ok(0);
        };
        let cutoff = Utc::now() - retention;
        self.audit_repo.prune_older_than(cutoff).await
    }

    /// Drop revocation-feed entries that have expired (T-39/T-143).
    ///
    /// A no-op returning `Ok(0)` when the deployment does not run the feed —
    /// in which case there are no rows to drop, because nothing wrote any.
    async fn sweep_revocation_feed(&self) -> Result<u64, AxiamError> {
        let Some(repo) = &self.revoked_session_repo else {
            return Ok(0);
        };
        repo.prune_expired(Utc::now()).await
    }

    // -----------------------------------------------------------------------
    // Dynamic client registration sweeps (T21.4)
    // -----------------------------------------------------------------------

    /// Delete `managed_by: dcr` clients that have not been authorized within
    /// their tenant's `dcr_unused_client_ttl_days`.
    ///
    /// # What it will not touch
    ///
    /// Only `dcr`. Not `admin` — an administrator's client is never swept,
    /// however long it sits unused, because somebody decided it should exist
    /// and nothing here is entitled to reverse that. Not `cimd` either: a CIMD
    /// shadow row is a cache of a document the client publishes, so deleting
    /// it would be re-materialised on the next request and the TTL would mean
    /// nothing. The repository query filters on the value rather than on
    /// "not admin", so a fourth provenance added later is opted **in** by
    /// somebody writing it down.
    ///
    /// # Which clock it reads
    ///
    /// `last_authorized_at` when the client has ever been authorized,
    /// `created_at` when it has not. The second case is the one the TTL is
    /// really for: a registration made by a tool somebody tried once and never
    /// ran again.
    ///
    /// # Per-tenant TTL, resolved per row
    ///
    /// The window is a tenant setting, so each row's tenant is resolved and
    /// its effective settings read. Deployment-wide sweeps elsewhere in this
    /// file (audit retention) deliberately do **not** work this way, and the
    /// difference is who owns the decision: audit retention is a property of
    /// the datastore an operator is responsible for, where this is a property
    /// of the tenant's relationship with the clients it lets register.
    ///
    /// The settings read is cached per tenant for the duration of one sweep —
    /// `dcr_max_clients` bounds the rows per tenant, so a hundred clients in
    /// one tenant is one read rather than a hundred.
    ///
    /// A tenant whose TTL is `0` is skipped: `0` means "never sweep", which an
    /// operator who prunes out of band may legitimately want. A tenant whose
    /// settings cannot be read is skipped too — the fail-closed direction for
    /// a sweep that **deletes** is to delete nothing.
    async fn sweep_unused_dcr_clients(&self) -> Result<u64, AxiamError> {
        sweep_unused_dcr_clients(
            self.oauth2_client_repo.as_ref(),
            self.tenant_repo.as_ref(),
            self.settings_repo.as_ref(),
            Utc::now(),
        )
        .await
    }

    /// T21.8 / MCP-04 — the same sweep over `cimd` shadow rows, on its own
    /// health counter.
    async fn sweep_unused_cimd_clients(&self) -> Result<u64, AxiamError> {
        sweep_unused_cimd_clients(
            self.oauth2_client_repo.as_ref(),
            self.tenant_repo.as_ref(),
            self.settings_repo.as_ref(),
            Utc::now(),
        )
        .await
    }

    /// Drop initial access tokens that have expired, spent or not.
    async fn sweep_expired_registration_tokens(&self) -> Result<u64, AxiamError> {
        use axiam_core::repository::OAuth2RegistrationTokenRepository;

        self.oauth2_registration_token_repo
            .prune_expired(Utc::now())
            .await
    }

    // -----------------------------------------------------------------------
    // GDPR purge sweep (D-01..D-06, D-08)
    // -----------------------------------------------------------------------

    /// Sweep users past their scheduled purge date and run the full purge pipeline.
    ///
    /// For each user:
    /// (a) Revoke all sessions (auth artifact cascade via `AuthService`).
    /// (b) Hard-delete federation links.
    /// (b2) Hard-delete WebAuthn credentials and password history (SEC-056).
    /// (b3) Prune `member_of` and `has_role` graph edges (isolated tombstone).
    /// (c) Compute deterministic GDPR pseudonym via `gdpr_pseudonym`.
    /// (d)/(e)/(g) Run [`run_erasure_pipeline`]: pseudonymize all audit
    ///     entries for this user (now FATAL, D-01/D-03/D-04) -> anonymize the
    ///     user row in-place (D-05) -> insert a PII-free erasure-proof
    ///     record STRICTLY LAST (D-06, D-03a/D-03b — SECHRD-06).
    /// (f) Mark the account_deletion row as completed.
    /// (h) Emit `gdpr.user_pseudonymized` audit event (actor = System).
    ///
    /// Returns the count of users purged.
    async fn sweep_pending_purges(&self) -> Result<u64, AxiamError> {
        let pepper = match self.gdpr_pepper {
            Some(p) => p,
            None => {
                tracing::warn!("GDPR purge sweep skipped — AXIAM__GDPR_PSEUDONYM_PEPPER not set");
                return Ok(0);
            }
        };

        let now = Utc::now();
        let due = self.user_repo.find_due_for_purge(now).await?;
        let mut purged: u64 = 0;

        for user in due {
            if let Err(e) = self
                .purge_single_user(user.id, user.tenant_id, pepper)
                .await
            {
                tracing::warn!(
                    error = ?e,
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    "purge failed for user — skipping"
                );
            } else {
                purged += 1;
            }
        }

        Ok(purged)
    }

    /// Run the full purge pipeline for a single user.
    async fn purge_single_user(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        pepper: [u8; 32],
    ) -> Result<(), AxiamError> {
        // (a) Revoke all sessions and OAuth2 refresh tokens.
        self.auth_svc
            .revoke_all_sessions(tenant_id, user_id)
            .await?;

        // (b) Hard-delete federation identity links.
        match self
            .federation_link_repo
            .get_by_user_id(tenant_id, user_id)
            .await
        {
            Ok(links) => {
                for link in links {
                    if let Err(e) = self.federation_link_repo.delete(tenant_id, link.id).await {
                        tracing::warn!(
                            error = %e,
                            %tenant_id,
                            link_id = %link.id,
                            "cleanup: failed to delete expired federation link; will retry next cycle"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, user_id = %user_id, "failed to list federation links for purge");
            }
        }

        // (b2) Hard-delete stored credential material (SEC-056). Done with `?`
        // (fail-closed): erasure must not be certified while a user's passkeys or
        // password hashes remain. A transient failure aborts the purge and it is
        // retried next sweep — every step here is idempotent.
        let webauthn_creds = self.webauthn_repo.list_by_user(tenant_id, user_id).await?;
        for cred in webauthn_creds {
            self.webauthn_repo.delete(tenant_id, cred.id).await?;
        }
        // Prune the entire password-history chain (keep_count = 0 deletes all).
        self.password_history_repo
            .prune(tenant_id, user_id, 0)
            .await?;

        // (b3) Prune authorization-graph edges so the anonymized row is left as
        // an isolated tombstone — no dangling `member_of` / `has_role` relations
        // skewing group-member queries or leaving live authorization paths.
        // Remove group memberships first so the subsequent role pass only sees
        // the user's *direct* has_role edges (inherited ones vanish with the
        // membership). Fail-closed (`?`): the tombstone must not be created while
        // graph edges survive; every delete is idempotent and retried on failure.
        let groups = self.group_repo.get_user_groups(tenant_id, user_id).await?;
        for group in groups {
            self.group_repo
                .remove_member(tenant_id, user_id, group.id)
                .await?;
        }
        let assignments = self
            .role_repo
            .get_user_role_assignments(tenant_id, user_id)
            .await?;
        for a in assignments {
            self.role_repo
                .unassign_from_user(tenant_id, user_id, a.role.id, a.resource_id)
                .await?;
        }

        // (c) Compute deterministic pseudonym (keyed HMAC-SHA256, D-02).
        let pseudonym = gdpr_pseudonym(&pepper, tenant_id, user_id);

        // Derive email hash for anonymize_user from tenant+user IDs (original email
        // is no longer accessible at purge time — user already marked deletion_pending).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tenant_id.as_bytes());
        h.update(user_id.as_bytes());
        let email_hash = hex::encode(h.finalize());

        // (d)/(e)/(g) Run the erasure pipeline: pseudonymize audit actor refs
        // (now FATAL, was swallowed) -> anonymize the user row -> write the
        // erasure proof STRICTLY LAST (SECHRD-06 / D-03a, T-25-13). A failure
        // anywhere in this call propagates with `?` and aborts the purge:
        // `anonymize_user` (the only step that clears `deletion_pending`)
        // never ran, so the user stays due for a retry via
        // `find_due_for_purge`, and NO erasure proof is ever written for an
        // incomplete erasure.
        run_erasure_pipeline(
            self.audit_repo.as_ref(),
            self.erasure_proof_repo.as_ref(),
            self.user_repo.as_ref(),
            tenant_id,
            user_id,
            &pseudonym,
            &email_hash,
        )
        .await?;

        // (f) Mark the account_deletion row as completed (lookup by user_id).
        // Run AFTER the erasure pipeline succeeds — if the pipeline failed
        // above, this is never reached and the deletion row stays pending
        // for the next retry too.
        match self
            .account_deletion_repo
            .find_pending_by_user_id(tenant_id, user_id)
            .await
        {
            Ok(Some(deletion)) => {
                if let Err(e) = self
                    .account_deletion_repo
                    .mark_completed(tenant_id, deletion.id)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        %tenant_id,
                        deletion_id = %deletion.id,
                        "cleanup: failed to mark account_deletion completed"
                    );
                }
            }
            Ok(None) => {
                tracing::debug!(user_id = %user_id, "no pending account_deletion row found at purge time");
            }
            Err(e) => {
                tracing::warn!(error = ?e, user_id = %user_id, "failed to find account_deletion row");
            }
        }

        // (h) Emit gdpr.user_pseudonymized audit event. actor_id is the
        // erased subject's own (now-anonymized) row id — a real, resolvable
        // identifier rather than a fabricated nil UUID (Task 1 fix); the row
        // still exists (anonymize-in-place preserves referential integrity),
        // so this is a legitimate audit-trail reference, not PII leakage.
        // A DB-write failure here is dead-lettered to BOTH an append-only
        // file AND a structured audit event (SECHRD-12 / D-02, T-24-61) —
        // this legally-significant record must never be silently lost.
        write_erasure_audit_with_dlq(
            self.audit_repo.as_ref(),
            CreateAuditLogEntry {
                tenant_id,
                actor_id: user_id,
                actor_type: ActorType::System,
                action: "gdpr.user_pseudonymized".into(),
                resource_id: None,
                outcome: AuditOutcome::Success,
                ip_address: None,
                metadata: Some(serde_json::json!({
                    "pseudonym": pseudonym,
                })),
            },
        )
        .await;

        tracing::info!(
            pseudonym = %pseudonym,
            tenant_id = %tenant_id,
            "user purged and pseudonymized"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // GDPR export sweep (D-10..D-13)
    // -----------------------------------------------------------------------

    /// Sweep queued export jobs and generate the encrypted blobs.
    ///
    /// For each job:
    /// (a) Aggregate all Art. 15 sections from the DB (secrets excluded, D-10).
    /// (b) Serialize to a single sectioned JSON object (D-11).
    /// (c) Encrypt with `export_encryption_key` (AES-256-GCM, D-12).
    /// (d) Call `set_ready` with a SHA-256-hashed 24h single-use download token.
    /// (e) Enqueue `ExportReady` mail with the raw token (D-12).
    ///
    /// Returns the count of jobs processed.
    async fn sweep_pending_exports(&self) -> Result<u64, AxiamError> {
        let key = match self.export_encryption_key {
            Some(k) => k,
            None => {
                tracing::warn!("GDPR export sweep skipped — AXIAM__EMAIL_ENCRYPTION_KEY not set");
                return Ok(0);
            }
        };

        let queued = self.export_job_repo.find_queued().await?;
        let mut processed: u64 = 0;

        for job in queued {
            if let Err(e) = self
                .process_export_job(job.id, job.tenant_id, job.user_id, key)
                .await
            {
                tracing::warn!(
                    error = ?e,
                    job_id = %job.id,
                    "export job processing failed — marking Failed (CQ-B38)"
                );
                // Mark as Failed so the job does not stay stuck as Queued
                // (CQ-B38 / REQ-14 AC-5).
                if let Err(mark_err) = self.export_job_repo.mark_failed(job.id).await {
                    tracing::warn!(
                        error = ?mark_err,
                        job_id = %job.id,
                        "failed to mark export job as Failed"
                    );
                }
            } else {
                processed += 1;
            }
        }

        Ok(processed)
    }

    /// Process a single queued export job.
    async fn process_export_job(
        &self,
        job_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        key: [u8; 32],
    ) -> Result<(), AxiamError> {
        // (a)/(b) Aggregate Art. 15 inventory into one sectioned JSON.
        let export_json = self.aggregate_export_data(tenant_id, user_id).await?;
        let export_bytes = export_json.to_string().into_bytes();

        // (c) Encrypt the blob (D-12).
        let (nonce_b64, ct_b64) = encrypt_separate(&key, &export_bytes)
            .map_err(|e| AxiamError::Internal(format!("export encrypt failed: {e}")))?;

        // (d) Generate single-use 24h download token (D-13).
        //
        // Deliberately v4, not `new_id()`: this token is the sole bearer
        // credential for the export download, so it must stay maximally random.
        // See `axiam_core::id` — v7 is for identifiers, never for secrets.
        let raw_download_token = Uuid::new_v4().to_string();
        let token_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(raw_download_token.as_bytes());
            hex::encode(h.finalize())
        };
        let expires_at = Utc::now() + chrono::Duration::hours(24);

        self.export_job_repo
            .set_ready(
                job_id,
                token_hash,
                Some(ct_b64),
                None, // file_path: stored as DB blob
                Some(nonce_b64),
                expires_at,
            )
            .await?;

        // Resolve the real org_id from the tenant before enqueuing the mail
        // (SECHRD-08 / D-05d) — a Uuid::nil() org_id leaves the mail
        // consumer unable to resolve the sending organization, producing
        // undeliverable ExportReady mail.
        let org_id = match self.tenant_repo.get_by_id(tenant_id).await {
            Ok(tenant) => tenant.organization_id,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    %tenant_id,
                    "failed to resolve org_id for ExportReady mail — falling back to nil (mail may be undeliverable)"
                );
                Uuid::nil()
            }
        };

        // (e) Enqueue ExportReady email.
        let download_url = format!("/api/v1/account/export/{}", raw_download_token);
        let msg = OutboundMailMessage {
            mail_type: MailType::ExportReady,
            tenant_id,
            org_id,
            user_id,
            to_address: String::new(), // mail consumer resolves from user_id
            template_context: serde_json::json!({
                "action_url": download_url,
                "expiry_time": expires_at.to_rfc3339(),
            }),
            attempt_count: 0,
            enqueued_at: Utc::now(),
        };
        if let Err(e) = self.mail_publisher.publish(msg).await {
            tracing::warn!(error = %e, job_id = %job_id, "failed to enqueue ExportReady mail");
        }

        tracing::info!(job_id = %job_id, "export job completed");
        Ok(())
    }

    /// Aggregate Art. 15 personal-data inventory for a user.
    ///
    /// EXCLUDED (D-10): `password_hash`, `mfa_secret`, any token_hash values.
    async fn aggregate_export_data(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<serde_json::Value, AxiamError> {
        // Profile — no password_hash or mfa_secret.
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        let profile = profile_section(&user);

        // Consents — propagate errors (CQ-B38 / SEC-056): a section that fails to
        // query must fail the whole export job rather than emit a legally
        // incomplete Art. 15 inventory. `process_export_job` marks the job Failed.
        let consents = self.consent_repo.list_by_user(tenant_id, user_id).await?;
        let consents_json: Vec<_> = consents
            .iter()
            .map(|c| {
                serde_json::json!({
                    "consent_type": c.consent_type,
                    "version": c.version,
                    "accepted_at": c.accepted_at,
                    "ip_address": c.ip_address,
                })
            })
            .collect();

        // Audit entries where this user was the actor — paginated to collect ALL
        // entries regardless of volume (CQ-B38 / REQ-14 AC-5).
        const AUDIT_PAGE_SIZE: u64 = 1_000;
        let mut audit_items = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let page = self
                .audit_repo
                .list(
                    tenant_id,
                    AuditLogFilter {
                        actor_id: Some(user_id),
                        action: None,
                        outcome: None,
                        resource_id: None,
                        from: None,
                        to: None,
                    },
                    Pagination {
                        offset,
                        limit: AUDIT_PAGE_SIZE,
                        search: None,
                    },
                )
                .await?;
            let fetched = page.items.len() as u64;
            audit_items.extend(page.items);
            offset += fetched;
            if fetched < AUDIT_PAGE_SIZE {
                break;
            }
        }
        let audit_json: Vec<_> = audit_items
            .iter()
            .map(|e| {
                serde_json::json!({
                    "action": e.action,
                    "outcome": e.outcome,
                    "timestamp": e.timestamp,
                    "resource_id": e.resource_id,
                })
            })
            .collect();

        // Sessions — real, metadata-only rows (D-03c, SECHRD-06). Token/hash
        // material is live credential data and must NEVER appear in a GDPR
        // export, so `token_hash` is deliberately excluded from the
        // projection below. Propagate errors (CQ-B38 / SEC-056 convention):
        // a section that fails to query must fail the whole export job.
        let sessions = self.session_repo.list_by_user(tenant_id, user_id).await?;
        let sessions_json: Vec<_> = sessions
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.id,
                    "created_at": s.created_at,
                    "expires_at": s.expires_at,
                    "ip_address": s.ip_address,
                    "user_agent": s.user_agent,
                })
            })
            .collect();

        // Federation identities — propagate errors (CQ-B38 / SEC-056).
        let fed_links = self
            .federation_link_repo
            .get_by_user_id(tenant_id, user_id)
            .await?;
        let fed_json: Vec<_> = fed_links
            .iter()
            .map(|l| {
                serde_json::json!({
                    "federation_config_id": l.federation_config_id,
                    "external_subject": l.external_subject,
                    "created_at": l.created_at,
                })
            })
            .collect();

        // Role assignments (direct + inherited via groups), incl. resource scope.
        let assignments = self
            .role_repo
            .get_user_role_assignments(tenant_id, user_id)
            .await?;
        let assignments_json: Vec<_> = assignments
            .iter()
            .map(|a| {
                serde_json::json!({
                    "role_id": a.role.id,
                    "role_name": a.role.name,
                    "is_global": a.role.is_global,
                    "resource_id": a.resource_id,
                })
            })
            .collect();

        // Group memberships.
        let groups = self.group_repo.get_user_groups(tenant_id, user_id).await?;
        let groups_json: Vec<_> = groups
            .iter()
            .map(|g| {
                serde_json::json!({
                    "group_id": g.id,
                    "name": g.name,
                    "description": g.description,
                })
            })
            .collect();

        // WebAuthn credentials — metadata only; the encrypted `passkey_json`
        // secret material is intentionally EXCLUDED (D-10).
        let webauthn_creds = self.webauthn_repo.list_by_user(tenant_id, user_id).await?;
        let webauthn_json: Vec<_> = webauthn_creds
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "credential_id": c.credential_id,
                    "name": c.name,
                    "credential_type": c.credential_type,
                    "created_at": c.created_at,
                    "last_used_at": c.last_used_at,
                })
            })
            .collect();

        let export = serde_json::json!({
            "export_metadata": {
                "generated_at": Utc::now(),
                "tenant_id": tenant_id,
                "subject_id": user_id,
                "schema_version": "1.0",
            },
            "profile": profile,
            "consents": consents_json,
            "sessions": sessions_json, // metadata only; NO token_hash (D-03c)
            "mfa": { "enabled": user.mfa_enabled }, // NO mfa_secret
            "federation_identities": fed_json,
            "assignments": assignments_json,
            "group_memberships": groups_json,
            "audit_entries": audit_json,
            "webauthn_credentials": webauthn_json,
        });

        Ok(export)
    }
}

#[cfg(test)]
mod personal_data_export_tests {
    use std::collections::BTreeSet;

    use axiam_core::models::user::{User, UserStatus};
    use axiam_core::personal_data::{USER_COLUMNS, export_keys};
    use chrono::Utc;
    use uuid::Uuid;

    use super::profile_section;

    fn a_user() -> User {
        User {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            username: "subject".into(),
            email: "subject@example.test".into(),
            password_hash: "$argon2id$irrelevant".into(),
            status: UserStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            failed_login_attempts: 0,
            last_failed_login_at: None,
            locked_until: None,
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            email_verified_at: None,
            deletion_pending: false,
            scheduled_purge_at: None,
            totp_last_used_step: None,
            phone_number: None,
            phone_number_verified_at: None,
            address: None,
        }
    }

    /// The other half of T-261's gate. `axiam-db`'s
    /// `user_schema_matches_the_declared_inventory` proves every column is
    /// classified; this proves the export honours the classification.
    ///
    /// Both directions again: a column declared `export: Some(_)` and missing
    /// from the literal is a column the subject is never shown, and a key in
    /// the literal that no column declares is an export nobody classified.
    #[test]
    fn the_profile_section_shows_exactly_the_declared_export_keys() {
        let profile = profile_section(&a_user());
        let rendered: BTreeSet<&str> = profile
            .as_object()
            .expect("the profile section is an object")
            .keys()
            .map(String::as_str)
            .collect();
        let declared: BTreeSet<&str> = export_keys().into_iter().collect();

        let missing: Vec<_> = declared.difference(&rendered).collect();
        assert!(
            missing.is_empty(),
            "these are declared exported in \
             `axiam_core::personal_data::USER_COLUMNS` and are absent from the \
             Art. 15 `profile` section: {missing:?}. A column not named here is \
             a column the data subject is never shown."
        );

        let undeclared: Vec<_> = rendered.difference(&declared).collect();
        assert!(
            undeclared.is_empty(),
            "the `profile` section carries these keys and no column declares \
             them: {undeclared:?}. Either classify the column with an `export` \
             key or add the key to `EXPORT_KEYS_NOT_FROM_COLUMNS` with the \
             reason it is not a column."
        );
    }

    /// D-10, asserted rather than commented: the two credentials on the row
    /// are erased and never exported, and this is the test that fails if
    /// somebody "completes" the profile section by adding them.
    #[test]
    fn no_credential_column_is_exported() {
        for name in ["password_hash", "mfa_secret"] {
            let column = USER_COLUMNS
                .iter()
                .find(|c| c.name == name)
                .expect("credential columns are classified");
            assert!(
                column.export.is_none(),
                "{name} must never be exported (D-10)"
            );
            assert!(
                column.erasure.is_some(),
                "{name} must be erased by both paths"
            );
        }
        let profile = profile_section(&a_user());
        let object = profile.as_object().unwrap();
        assert!(!object.contains_key("password_hash"));
        assert!(!object.contains_key("mfa_secret"));
    }
}

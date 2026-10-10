//! Periodic cleanup task for expired federation rows, GDPR purges, and export jobs.
//!
//! SurrealDB v3 does not support native TTL on rows (RESEARCH §7), so this task
//! periodically sweeps various tables:
//! - `saml_assertion_replay` and `federation_login_state`: expired rows
//! - `user`: accounts past their scheduled purge date (D-05/D-06/D-08)
//! - `export_job`: queued jobs waiting to have their encrypted blob generated (D-12)
//! - every tenant-scoped table: the rows of a deleted (tombstoned) tenant, then
//!   its tenant row (#523, D-4)
//!
//! The task shuts down cleanly when the caller sends `true` through the watch
//! channel (D-09, D-24).

use std::sync::Arc;
use std::time::Duration;

use crate::messaging::MailTransportPublisher;
use axiam_api_rest::handlers::gdpr::{AuditWriteSink, write_erasure_audit_with_dlq};
use axiam_api_rest::ssf_emitter::{InitiatingEntity, with_cause};
use axiam_auth::AuthService;
use axiam_auth::crypto::{encrypt_separate, gdpr_pseudonym};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::gdpr::CreateErasureProof;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::settings::{DCR_UNAUTHORIZED_CLIENT_TTL_SECS, DynamicRegistrationMode};
use axiam_core::models::ssf::SsfSystemAccountSink;
use axiam_core::repository::{
    AccountDeletionRepository, AmqpNonceRepository, AssertionReplayRepository, AuditLogFilter,
    AuditLogRepository, ConsentRepository, ErasureProofRepository, ExportJobRepository,
    FederationLinkRepository, FederationLoginStateRepository, GroupRepository, MailPublisher,
    Pagination, PasswordHistoryRepository, PendingSamlRequestRepository, RoleRepository,
    SamlLogoutRunRepository, SamlSpSessionRepository, SessionRepository, SsfEventBufferRepository,
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
use axiam_oauth2::client_grants::ClientGrantStores;
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

/// The directory sync job over the production repositories (G-3, T23.3.5).
pub type DirectorySyncJob<C> = axiam_directory::DirectorySync<
    axiam_db::SurrealDirectoryConfigRepository<C>,
    SurrealUserRepository<C>,
    SurrealSessionRepository<C>,
    SurrealRefreshTokenRepository<C>,
    axiam_db::SurrealDirectorySyncStateRepository<C>,
>;

/// The grant stores the unused-client sweep revokes a client's grants from
/// before it removes the row (#517).
pub type SweptClientGrants<C> = ClientGrantStores<
    SurrealRefreshTokenRepository<C>,
    axiam_db::SurrealAuthorizationCodeRepository<C>,
    axiam_db::SurrealPushedAuthRequestRepository<C>,
>;

// ---------------------------------------------------------------------------
// CleanupTask
// ---------------------------------------------------------------------------

/// The certificate service the `vault_revocation` sweep forwards through
/// (T-470).
pub type VaultRevocationForwarder<C> = axiam_pki::CertService<
    axiam_db::SurrealCaCertificateRepository<C>,
    axiam_db::SurrealCertificateRepository<C>,
>;

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
    // T23.2.3: pending SAML AuthnRequests. Ten-minute rows, kept after use
    // until they expire (they are the request-id replay guard), so the sweep
    // is what bounds the table.
    saml_pending_repo: Arc<axiam_db::SurrealPendingSamlRequestRepository<C>>,
    // T23.2.4: the SAML single-logout stores (schema v76). The participant rows
    // are swept once their session has expired or is gone (a logout that just
    // ended it keeps them for one run lifetime), the logout runs once expired.
    saml_participant_repo: Arc<axiam_db::SurrealSamlSpSessionRepository<C>>,
    saml_logout_run_repo: Arc<axiam_db::SurrealSamlLogoutRunRepository<C>>,
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
    mail_publisher: Arc<MailTransportPublisher>,
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
    /// #517 — what a swept client was granted, revoked before its row goes.
    client_grants: Arc<SweptClientGrants<C>>,
    /// T-129: records each sweep's outcome for `GET /health/jobs`.
    job_health: crate::job_health::JobHealth,
    /// G-3 (T23.3.5): the directory sync job. `None` — the default — runs no
    /// sync; a test harness that exercises other sweeps leaves it out.
    directory_sync: Option<Arc<DirectorySyncJob<C>>>,
    /// G-5 (T23.5.3, D-48): the SSF poll/hold buffer, whose expired rows the
    /// `ssf_event_buffer` sweep removes. `None` runs no sweep.
    ssf_buffer_repo: Option<Arc<axiam_db::SurrealSsfEventBufferRepository<C>>>,
    /// G-5 (T23.5.3, D-53 (1)): the step-up records, whose ten-minute expiry the
    /// `ssf_step_up` sweep removes. `None` runs no sweep.
    ssf_step_up_repo: Option<Arc<axiam_db::SurrealSsfStepUpRepository<C>>>,
    /// G-5 (D-52): tells SSF receivers an account was purged (the account as it
    /// was before the erasure). `None` — the default — tells nobody.
    ssf_sink: Option<Arc<dyn SsfSystemAccountSink>>,
    /// G-6 (T23.6.3, D-58): the outbound SCIM reconciliation, which the
    /// `scim_reconcile` job runs once a day per enabled target (the claim in
    /// the datastore decides, so replicas do not double-run it). `None` — the
    /// default — runs no reconciliation.
    scim_reconciliation: Option<Arc<dyn axiam_scim::outbound::ScimReconciliation>>,
    /// G-7 (T23.7.1): the CIBA pending-request store, whose expired requests
    /// the `ciba_request` sweep marks `expired` and, after a retention, deletes.
    /// `None` runs no sweep.
    ciba_request_repo: Option<Arc<axiam_db::SurrealCibaRequestRepository<C>>>,
    /// T-470: forwards to Vault the revocations of `vault_pki` leaves it does
    /// not have yet, as the `vault_revocation` job. `None` runs no sweep.
    vault_revocations: Option<Arc<VaultRevocationForwarder<C>>>,
    /// #523: when the `tenant_purge` sweep last looked for orphaned tenant ids
    /// (rows whose tenant a pre-tombstone deletion removed). `None` until the
    /// first tick, which always looks; then once per
    /// [`ORPHAN_TENANT_SCAN_INTERVAL`].
    last_orphan_scan: Option<std::time::Instant>,
    shutdown: watch::Receiver<bool>,
}

// ---------------------------------------------------------------------------
// Tenant purge (#523, P23W2-04, D-4)
// ---------------------------------------------------------------------------

/// How often the `tenant_purge` sweep also looks for orphaned tenant ids.
///
/// The look reads every tenant-scoped table (one `GROUP BY` each), which is not
/// something to do every minute for a residue that only an upgrade can have: a
/// deletion made by this version tombstones, so it never leaves an orphan. Once
/// at process start, which is when an upgraded deployment first runs this
/// code, and once a day after that.
pub const ORPHAN_TENANT_SCAN_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// One pass of the `tenant_purge` job: purge every tombstoned tenant and, when
/// `scan_orphans`, every orphaned tenant id.
///
/// A free function, and public, for the reason [`run_erasure_pipeline`] is
/// one. Each tenant is purged by
/// [`SurrealTenantRepository::purge_tombstoned`] — every tenant-scoped table in
/// the order user erasure uses, its audit trail included (exported before the
/// deletion was allowed, T-118), then the tenant row — or, for an orphan, by
/// [`SurrealTenantRepository::purge_orphan`], which leaves the audit trail to
/// the retention sweep. Each completed purge is recorded in the **system** log
/// as `tenants.purged`, beside the `tenants.deleted` record the deletion wrote;
/// neither is ever purged.
///
/// * `Ok(n)` is the number of tenants (and orphaned ids) purged.
/// * One tenant's failure does not stop the others; any failure makes the sweep
///   fail, naming how many failed and never a tenant's data. The failed tenant
///   stays tombstoned and the next pass resumes it (every step is idempotent).
///
/// # Errors
///
/// [`AxiamError::Internal`] as above, or the datastore error that kept the
/// tombstoned tenants or the orphans from being listed (the tombstoned tenants
/// are still purged when only the orphans could not be).
pub async fn sweep_tenant_purge<C, S>(
    tenant_repo: &SurrealTenantRepository<C>,
    audit: &S,
    scan_orphans: bool,
) -> Result<u64, AxiamError>
where
    C: Connection,
    S: AuditWriteSink,
{
    let mut due: Vec<(Uuid, bool)> = tenant_repo
        .list_tombstoned()
        .await?
        .into_iter()
        .map(|id| (id, false))
        .collect();
    // A failed look for orphans does not hold back the tombstoned tenants: it
    // is reported after them, and the next pass looks again.
    let mut scan_error = None;
    if scan_orphans {
        match tenant_repo.orphaned_tenant_ids().await {
            Ok(ids) => due.extend(ids.into_iter().map(|id| (id, true))),
            Err(e) => scan_error = Some(e),
        }
    }

    let (mut purged, mut failed) = (0u64, 0u64);
    for (tenant_id, orphan) in due {
        let outcome = if orphan {
            tenant_repo.purge_orphan(tenant_id).await
        } else {
            tenant_repo.purge_tombstoned(tenant_id).await
        };
        if let Err(e) = outcome {
            failed += 1;
            tracing::warn!(
                error = %e,
                %tenant_id,
                orphan,
                "tenant purge incomplete; the tenant stays tombstoned and the next sweep resumes it"
            );
            continue;
        }
        purged += 1;
        write_erasure_audit_with_dlq(
            audit,
            CreateAuditLogEntry {
                tenant_id: Uuid::nil(),
                actor_id: Uuid::nil(),
                actor_type: ActorType::System,
                action: axiam_api_rest::handlers::tenants::TENANT_PURGED_ACTION.to_string(),
                resource_id: Some(tenant_id),
                outcome: AuditOutcome::Success,
                ip_address: None,
                metadata: Some(serde_json::json!({ "orphan": orphan })),
            },
        )
        .await;
        tracing::info!(%tenant_id, orphan, "deleted tenant's data purged");
    }

    if failed > 0 {
        return Err(AxiamError::Internal(format!(
            "tenant purge was incomplete for {failed} of {} tenant(s)",
            failed + purged
        )));
    }
    if let Some(e) = scan_error {
        return Err(e);
    }
    Ok(purged)
}

// ---------------------------------------------------------------------------
// Outbound SCIM reconciliation (G-6, T23.6.3, D-58)
// ---------------------------------------------------------------------------

/// One pass of the `scim_reconcile` job, as a sweep the scheduler can record.
///
/// A free function, and public, for the reason [`sweep_directories`] is one.
/// The scheduler ticks far more often than a target is due: at every tick this
/// walks the enabled targets and tries the claim, which succeeds for a target
/// whose last run is older than 24 hours and only on one replica; everything
/// else is a skipped target and costs a conditional write that matches nothing.
///
/// * `Ok(n)` is the number of targets whose run this pass made.
/// * A target whose run could not do all of its work (the broker refused a
///   reference, the downstream could not be read, AXIAM's datastore failed)
///   makes the sweep fail, with a count and no target's data. The other targets
///   still ran.
/// * A shutdown signal stops the pass between targets.
///
/// # Errors
///
/// [`AxiamError::Internal`] when the enabled targets could not be listed or a
/// run was incomplete, as described above.
pub async fn sweep_scim_reconciliation(
    reconciliation: &dyn axiam_scim::outbound::ScimReconciliation,
    shutdown: &watch::Receiver<bool>,
) -> Result<u64, AxiamError> {
    let should_stop = || *shutdown.borrow();
    let sweep = reconciliation.run_due(&should_stop).await.map_err(|_| {
        AxiamError::Internal("SCIM reconciliation could not list the enabled targets".into())
    })?;
    if sweep.failed > 0 {
        return Err(AxiamError::Internal(format!(
            "SCIM reconciliation was incomplete for {} of {} target(s) run",
            sweep.failed, sweep.reconciled
        )));
    }
    Ok(sweep.reconciled)
}

// ---------------------------------------------------------------------------
// Directory sync sweep (G-3, T23.3.5, D-31)
// ---------------------------------------------------------------------------

/// One pass of the directory sync job, as a sweep the scheduler can record.
///
/// A free function, and public, for the reason [`run_erasure_pipeline`] is one:
/// the loop that calls it is awkward to construct in a test, and the conversion
/// of the job's outcome into job health is the part worth testing directly.
///
/// * `Ok(n)` is the number of accounts the pass changed (deactivated, updated or
///   re-mapped); a pass that found nothing to do is `Ok(0)`.
/// * **Any tenant's failure makes the sweep fail** — an unreachable directory, a
///   refused search, the safety valve — with a message that names how many
///   tenants failed and the fixed tag of each, never a tenant's data. The other
///   tenants still ran; one tenant's outage is not another's.
/// * A shutdown signal abandons the pass (`Ok(0)`): every step the job takes is
///   idempotent or a compare-and-set, and the next process starts it again.
///
/// # Errors
///
/// [`AxiamError::Internal`] when the pass failed, as described above.
pub async fn sweep_directories<C: Connection + Send + Sync + 'static>(
    sync: &DirectorySyncJob<C>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<u64, AxiamError> {
    let outcome = tokio::select! {
        // A shutdown request wins over starting work: polled first.
        biased;
        _ = async {
            // Resolves on a shutdown request; a dropped sender never does.
            loop {
                if *shutdown.borrow() {
                    return;
                }
                if shutdown.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
            }
        } => {
            tracing::info!("directory sync abandoned: the process is shutting down");
            return Ok(0);
        }
        outcome = sync.run_due() => outcome,
    };
    match outcome {
        Ok(summary) => match summary.failure_message() {
            Some(message) => Err(AxiamError::Internal(message)),
            None => Ok(summary.changed()),
        },
        Err(error) => Err(AxiamError::Internal(format!(
            "directory sync could not list the tenants' directories ({})",
            error.tag()
        ))),
    }
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
/// authorized and `created_at` when it has not.
///
/// `DcrSweepWindow::days == 0` is never due. Zero means "never sweep", which
/// an operator who prunes out of band may legitimately want, and reading it as
/// "sweep everything immediately" would delete a tenant's whole client table
/// on the next tick.
///
/// # The second clock (T21.8 / MCP-05)
///
/// A row that has **never** been authorized, in a tenant whose effective
/// `dynamic_registration` is `anonymous`, is measured against
/// [`axiam_core::models::settings::DCR_UNAUTHORIZED_CLIENT_TTL_SECS`] instead
/// — an hour. That constant's own documentation says why it is a constant and
/// what promoting it to a tenant setting would cost.
///
/// Those two conditions are the whole of the change, and each is load-bearing.
///
/// **Never authorized.** The thirty-day window is sized, in
/// `DEFAULT_DCR_UNUSED_CLIENT_TTL_DAYS`'s own doc comment, for "a client
/// somebody uses monthly". A client registered and never authorized is not
/// that client: every MCP client this phase exists to serve authorizes within
/// seconds of registering, because registration is the first step of the same
/// flow. One TTL served two situations that have nothing in common, which is
/// what made `dcr_max_clients` an availability budget a stranger could spend
/// for a month. The sweeper could always tell the two apart — the row carries
/// `last_authorized_at: None` — so the fix is a second clock, not a bigger
/// quota.
///
/// **`anonymous` only.** In `initial_access_token` mode the row exists because
/// an administrator minted a handle for it and somebody redeemed it. There is
/// no unauthenticated exposure to bound, and the thirty-day clock is the right
/// one: an operator who hands somebody a registration token on Friday should
/// not find the registration gone on Monday.
///
/// Every tenant on `disabled` or `initial_access_token` — which is every
/// tenant that did not opt into `anonymous` behind D3 — takes byte for byte
/// the path it took before T21.8.
pub fn dcr_client_is_due_for_sweep(
    client: &axiam_core::models::oauth2_client::OAuth2Client,
    ttl: DcrSweepWindow,
    now: chrono::DateTime<Utc>,
) -> bool {
    if client.last_authorized_at.is_none() && ttl.mode == DynamicRegistrationMode::Anonymous {
        return now - client.created_at
            > chrono::Duration::seconds(i64::from(DCR_UNAUTHORIZED_CLIENT_TTL_SECS));
    }
    if ttl.days == 0 {
        return false;
    }
    now - dcr_client_last_seen(client) > chrono::Duration::days(i64::from(ttl.days))
}

/// Everything the sweep needs from one tenant's settings.
///
/// A struct rather than the `Option<u32>` the per-tenant cache used to hold,
/// because T21.8's second clock is selected by the tenant's registration
/// mode, and two values read from one settings row should travel together
/// rather than as two parallel maps that can disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DcrSweepWindow {
    /// `dcr_unused_client_ttl_days`. `0` never sweeps.
    pub days: u32,
    /// The tenant's effective registration mode, which decides whether the
    /// second clock applies at all. Only `anonymous` has the exposure the
    /// second clock bounds; see [`dcr_client_is_due_for_sweep`].
    pub mode: DynamicRegistrationMode,
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
/// The second clock does **not** apply here, and that is deliberate: a `cimd`
/// row is never "registered and never authorized" in the sense T21.8's window
/// is about. It exists because somebody presented a document AXIAM fetched, so
/// it has been used once by definition, and `updated_at` moves every time it
/// is used again. What bounds a stranger materialising rows is the quota
/// checked before the fetch, not a shorter window.
pub fn cimd_client_is_due_for_sweep(
    client: &axiam_core::models::oauth2_client::OAuth2Client,
    ttl: DcrSweepWindow,
    now: chrono::DateTime<Utc>,
) -> bool {
    if ttl.days == 0 {
        return false;
    }
    now - cimd_client_last_seen(client) > chrono::Duration::days(i64::from(ttl.days))
}

/// The `dcr` arm of [`sweep_unused_external_clients`], kept as a named entry
/// point because T21.4's tests and the task method both call it that.
pub async fn sweep_unused_dcr_clients<CR, TR, SR, RT, AC, PR>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    grants: &ClientGrantStores<RT, AC, PR>,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
    RT: axiam_core::repository::RefreshTokenRepository,
    AC: axiam_core::repository::AuthorizationCodeRepository,
    PR: axiam_core::repository::PushedAuthRequestRepository,
{
    sweep_unused_external_clients(
        client_repo,
        tenant_repo,
        settings_repo,
        grants,
        axiam_core::models::oauth2_client::ManagedBy::Dcr,
        now,
    )
    .await
}

/// The `cimd` arm of [`sweep_unused_external_clients`] (T21.8 / MCP-04).
pub async fn sweep_unused_cimd_clients<CR, TR, SR, RT, AC, PR>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    grants: &ClientGrantStores<RT, AC, PR>,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
    RT: axiam_core::repository::RefreshTokenRepository,
    AC: axiam_core::repository::AuthorizationCodeRepository,
    PR: axiam_core::repository::PushedAuthRequestRepository,
{
    sweep_unused_external_clients(
        client_repo,
        tenant_repo,
        settings_repo,
        grants,
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
pub async fn sweep_unused_external_clients<CR, TR, SR, RT, AC, PR>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    grants: &ClientGrantStores<RT, AC, PR>,
    managed_by: axiam_core::models::oauth2_client::ManagedBy,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
    RT: axiam_core::repository::RefreshTokenRepository,
    AC: axiam_core::repository::AuthorizationCodeRepository,
    PR: axiam_core::repository::PushedAuthRequestRepository,
{
    use axiam_core::models::oauth2_client::ManagedBy;
    use axiam_core::repository::SettingsRepository;

    type DuePredicate = fn(
        &axiam_core::models::oauth2_client::OAuth2Client,
        DcrSweepWindow,
        chrono::DateTime<Utc>,
    ) -> bool;
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

    let mut ttl_by_tenant: std::collections::HashMap<Uuid, Option<DcrSweepWindow>> =
        std::collections::HashMap::new();
    let mut removed = 0u64;

    for client in clients {
        let ttl = match ttl_by_tenant.get(&client.tenant_id) {
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
                    .map(|s| DcrSweepWindow {
                        days: s.oidc.dcr_unused_client_ttl_days,
                        mode: s.oidc.dynamic_registration,
                    }),
                    Err(_) => None,
                };
                ttl_by_tenant.insert(client.tenant_id, resolved);
                resolved
            }
        };
        // `None` is an unreadable tenant or an unreadable settings row.
        let Some(ttl) = ttl else {
            continue;
        };
        if !is_due(&client, ttl, now) {
            continue;
        }

        // #517 — the client's grants go before the row, as on an
        // administrator's delete: a `cimd` row re-materialises under the same
        // `client_id`, and a refresh token, code or pushed request left behind
        // would work again against it. A revocation that fails keeps the row
        // for the next sweep rather than leave a row-less client with live
        // grants.
        if let Err(e) = grants.revoke(client.tenant_id, &client.client_id).await {
            tracing::warn!(
                job,
                error = %e,
                client_id = %client.client_id,
                "could not revoke an unused externally registered client's grants; not \
                 deleting it this sweep"
            );
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
        // A request that read the row before the delete may have written a
        // grant between the two writes above; one more pass leaves none.
        if let Err(e) = grants.revoke(client.tenant_id, &client.client_id).await {
            tracing::warn!(
                job,
                error = %e,
                client_id = %client.client_id,
                "a swept client's grants could not be revoked a second time"
            );
        }
        removed += 1;
        tracing::info!(
            job,
            tenant_id = %client.tenant_id,
            client_id = %client.client_id,
            ttl_days = ttl.days,
            ever_authorized = client.last_authorized_at.is_some(),
            mode = %ttl.mode,
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
    erasure_steps(
        audit_repo,
        erasure_proof_repo,
        user_repo,
        tenant_id,
        user_id,
        pseudonym,
        email_hash,
        None,
    )
    .await
}

/// The three steps of [`run_erasure_pipeline`], with the SSF report (G-5, D-52)
/// between the second and the third.
///
/// The report follows the anonymization because that is the write that makes the
/// account gone — whether or not the erasure proof is then written. A proof that
/// fails to write leaves an anonymized account that no sweep selects again, so a
/// report that waited for the proof would never be sent.
#[allow(clippy::too_many_arguments)]
async fn erasure_steps<A, EP, U>(
    audit_repo: &A,
    erasure_proof_repo: &EP,
    user_repo: &U,
    tenant_id: Uuid,
    user_id: Uuid,
    pseudonym: &str,
    email_hash: &str,
    report: Option<(&dyn SsfSystemAccountSink, axiam_core::models::user::User)>,
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

    // G-5 (D-52): the account is gone; tell the receivers what it was.
    if let Some((sink, user)) = report {
        sink.account_purged(tenant_id, &user).await;
    }

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

/// [`run_erasure_pipeline`] and an SSF `account-purged` for the erased account
/// (G-5, D-52), sent once the account has been anonymized.
///
/// The account is read **before** the pipeline writes anything: the erasure
/// replaces the address, and the event's subject (`iss_sub`, or the address on
/// an `email` stream) is resolved from what the account was. Nothing is read
/// when no sink is attached or it is inactive. A failed erasure that did not get
/// as far as anonymizing reports nothing: the account is still there and still
/// due, and the next sweep tries again.
///
/// # Errors
///
/// Those of [`run_erasure_pipeline`]; the sink never adds one.
#[allow(clippy::too_many_arguments)]
pub async fn run_erasure_pipeline_reporting<A, EP, U>(
    audit_repo: &A,
    erasure_proof_repo: &EP,
    user_repo: &U,
    tenant_id: Uuid,
    user_id: Uuid,
    pseudonym: &str,
    email_hash: &str,
    sink: Option<&dyn SsfSystemAccountSink>,
) -> Result<(), AxiamError>
where
    A: AuditLogRepository,
    EP: ErasureProofRepository,
    U: UserRepository,
{
    let report = match sink {
        Some(sink) if sink.is_active() => user_repo
            .get_by_id(tenant_id, user_id)
            .await
            .ok()
            .map(|user| (sink, user)),
        _ => None,
    };
    erasure_steps(
        audit_repo,
        erasure_proof_repo,
        user_repo,
        tenant_id,
        user_id,
        pseudonym,
        email_hash,
        report,
    )
    .await
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
        "directory_external_id": user.directory_external_id,
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
        saml_pending_repo: Arc<axiam_db::SurrealPendingSamlRequestRepository<C>>,
        saml_participant_repo: Arc<axiam_db::SurrealSamlSpSessionRepository<C>>,
        saml_logout_run_repo: Arc<axiam_db::SurrealSamlLogoutRunRepository<C>>,
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
        mail_publisher: Arc<MailTransportPublisher>,
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
        // #517 — revoked for every client the sweep removes.
        client_grants: Arc<SweptClientGrants<C>>,
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
            saml_pending_repo,
            saml_participant_repo,
            saml_logout_run_repo,
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
            client_grants,
            job_health,
            directory_sync: None,
            ssf_buffer_repo: None,
            ssf_step_up_repo: None,
            ssf_sink: None,
            scim_reconciliation: None,
            ciba_request_repo: None,
            vault_revocations: None,
            last_orphan_scan: None,
            shutdown,
        }
    }

    /// Sweep the CIBA pending-request store (G-7, T23.7.1), as the
    /// `ciba_request` job.
    ///
    /// A builder step for the reason [`Self::with_ssf`] is one.
    #[must_use]
    pub fn with_ciba(mut self, repo: Arc<axiam_db::SurrealCibaRequestRepository<C>>) -> Self {
        self.ciba_request_repo = Some(repo);
        self
    }

    /// Forward to Vault the `vault_pki` revocations it does not have yet
    /// (T-470), as the `vault_revocation` job.
    ///
    /// A builder step for the reason [`Self::with_ssf`] is one.
    #[must_use]
    pub fn with_vault_revocations(mut self, certs: Arc<VaultRevocationForwarder<C>>) -> Self {
        self.vault_revocations = Some(certs);
        self
    }

    /// Run the outbound SCIM reconciliation on this scheduler (G-6, T23.6.3,
    /// D-58), as the `scim_reconcile` job.
    ///
    /// A builder step for the reason [`Self::with_directory_sync`] is one.
    #[must_use]
    pub fn with_scim_reconciliation(
        mut self,
        reconciliation: Arc<dyn axiam_scim::outbound::ScimReconciliation>,
    ) -> Self {
        self.scim_reconciliation = Some(reconciliation);
        self
    }

    /// Run the SSF sweep and report erasures to SSF receivers (G-5, T23.5.3).
    ///
    /// A builder step for the reason [`Self::with_directory_sync`] is one: the
    /// absence has a meaning and the constructor's list is long enough.
    #[must_use]
    pub fn with_ssf(
        mut self,
        buffer_repo: Arc<axiam_db::SurrealSsfEventBufferRepository<C>>,
        step_up_repo: Arc<axiam_db::SurrealSsfStepUpRepository<C>>,
        sink: Arc<dyn SsfSystemAccountSink>,
    ) -> Self {
        self.ssf_buffer_repo = Some(buffer_repo);
        self.ssf_step_up_repo = Some(step_up_repo);
        self.ssf_sink = Some(sink);
        self
    }

    /// Run the directory sync job on this scheduler (G-3, T23.3.5, D-31).
    ///
    /// A builder step rather than another constructor argument, because the
    /// absence has a meaning (no sync) and the constructor's list is long enough.
    #[must_use]
    pub fn with_directory_sync(mut self, sync: Arc<DirectorySyncJob<C>>) -> Self {
        self.directory_sync = Some(sync);
        self
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

                    // T23.2.3: expired pending SAML AuthnRequests.
                    Self::record(
                        &self.job_health,
                        "saml_authn_request",
                        self.saml_pending_repo.cleanup_expired().await,
                        tracing::Level::DEBUG,
                    );

                    // T23.2.4: the SAML single-logout participant rows and logout
                    // runs. Each is its own job in `/health/jobs`, so a stuck
                    // sweep of one is not hidden by the other.
                    Self::record(
                        &self.job_health,
                        "saml_sp_session",
                        self.saml_participant_repo.cleanup_expired().await,
                        tracing::Level::DEBUG,
                    );
                    Self::record(
                        &self.job_health,
                        "saml_logout_run",
                        self.saml_logout_run_repo.cleanup_expired().await,
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

                    // G-5 (T23.5.3, D-48): events held for a poll or paused SSF
                    // stream for more than seven days. DEBUG: an expired event
                    // is one nobody can still act on.
                    Self::record(
                        &self.job_health,
                        "ssf_event_buffer",
                        self.sweep_ssf_event_buffer().await,
                        tracing::Level::DEBUG,
                    );

                    // G-5 (T23.5.3, D-53 (1)): step-up records nobody returned
                    // for within ten minutes. DEBUG: an expired record is one
                    // no return leg may use.
                    Self::record(
                        &self.job_health,
                        "ssf_step_up",
                        self.sweep_ssf_step_up().await,
                        tracing::Level::DEBUG,
                    );

                    // G-7 (T23.7.1): CIBA requests past their expiry are
                    // marked `expired`, and deleted ten minutes later (a client
                    // still polling is told `expired_token` meanwhile). DEBUG:
                    // an expired request is one nobody can still approve or
                    // redeem.
                    Self::record(
                        &self.job_health,
                        "ciba_request",
                        self.sweep_ciba_requests().await,
                        tracing::Level::DEBUG,
                    );

                    // T-470: a `vault_pki` leaf revoked in AXIAM whose
                    // revocation Vault does not have yet — a revoke request
                    // could not reach it, or the revocation came from a bulk
                    // path. WARN on failure (`record`), since until it runs
                    // Vault's list omits a revoked certificate.
                    if let Some(certs) = &self.vault_revocations {
                        Self::record(
                            &self.job_health,
                            "vault_revocation",
                            certs.forward_pending_revocations().await,
                            tracing::Level::INFO,
                        );
                    }

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

                    // #523 (D-4) — purge deleted tenants' data, after the GDPR
                    // purge so an account erasure due in a tombstoned tenant
                    // finishes before its tenant's rows go. INFO, for the audit
                    // sweep's reason: it destroys records nothing can rebuild.
                    let scan_orphans = self
                        .last_orphan_scan
                        .is_none_or(|at| at.elapsed() >= ORPHAN_TENANT_SCAN_INTERVAL);
                    let outcome = sweep_tenant_purge(
                        self.tenant_repo.as_ref(),
                        self.audit_repo.as_ref(),
                        scan_orphans,
                    )
                    .await;
                    if scan_orphans && outcome.is_ok() {
                        self.last_orphan_scan = Some(std::time::Instant::now());
                    }
                    Self::record(
                        &self.job_health,
                        "tenant_purge",
                        outcome,
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

                    // G-3 (T23.3.5, D-31) — the directory sync, last in the tick:
                    // it talks to other people's servers and can take minutes, and
                    // nothing above should wait on it. INFO, because it changes
                    // who may sign in, and an operator asking "why can alice no
                    // longer sign in" needs to find it in the log.
                    if let Some(sync) = &self.directory_sync {
                        Self::record(
                            &self.job_health,
                            "directory_sync",
                            sweep_directories(sync, self.shutdown.clone()).await,
                            tracing::Level::INFO,
                        );
                    }

                    // G-6 (T23.6.3, D-58) — the outbound SCIM reconciliation,
                    // after the directory sync for the same reason: it talks to
                    // other people's servers. INFO, because it deprovisions
                    // accounts downstream. One log line per target per run is
                    // written by the run itself, never one per page.
                    if let Some(reconciliation) = &self.scim_reconciliation {
                        Self::record(
                            &self.job_health,
                            "scim_reconcile",
                            sweep_scim_reconciliation(reconciliation.as_ref(), &self.shutdown)
                                .await,
                            tracing::Level::INFO,
                        );
                    }
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
    pub fn record(
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

    /// Remove SSF buffer rows past their `expires_at` (G-5, T23.5.3, D-48).
    ///
    /// A size bound, not a correctness one: the poll endpoint and the resume
    /// read only unexpired rows, so a sweep that never ran would serve the
    /// right answer over a table that grows. `Ok(0)` without a buffer.
    async fn sweep_ssf_event_buffer(&self) -> Result<u64, AxiamError> {
        let Some(repo) = &self.ssf_buffer_repo else {
            return Ok(0);
        };
        repo.delete_expired(Utc::now()).await
    }

    /// Remove SSF step-up records past their ten-minute `expires_at` (G-5,
    /// T23.5.3, D-53 (1)).
    ///
    /// A size bound, not a correctness one: `take` returns only an unexpired
    /// record, so a sweep that never ran would answer correctly over a table
    /// that keeps rows nobody will return for. `Ok(0)` without the repository.
    async fn sweep_ssf_step_up(&self) -> Result<u64, AxiamError> {
        use axiam_core::repository::SsfStepUpRepository as _;
        let Some(repo) = &self.ssf_step_up_repo else {
            return Ok(0);
        };
        repo.delete_expired(Utc::now()).await
    }

    /// Mark and delete expired CIBA requests (G-7, T23.7.1).
    ///
    /// A size bound and a state bound, not a correctness one: approval and
    /// redemption both refuse a request past `expires_at` in their own `WHERE`
    /// clause, so a sweep that never ran would answer correctly over a table
    /// that keeps rows — and the user ids, binding messages and approval
    /// evidence in them — nobody can use. `Ok(0)` without the repository.
    async fn sweep_ciba_requests(&self) -> Result<u64, AxiamError> {
        use axiam_core::repository::CibaRequestRepository as _;
        let Some(repo) = &self.ciba_request_repo else {
            return Ok(0);
        };
        repo.sweep_expired(
            Utc::now(),
            chrono::Duration::seconds(axiam_oauth2::ciba::EXPIRED_RETENTION_SECS),
        )
        .await
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
            self.client_grants.as_ref(),
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
            self.client_grants.as_ref(),
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
                tracing::warn!(
                    "GDPR purge sweep skipped — AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER not set"
                );
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
    ///
    /// G-5 (D-52): the session revocations and the `account-purged` event are
    /// one cause, and the platform's own (`system`).
    async fn purge_single_user(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        pepper: [u8; 32],
    ) -> Result<(), AxiamError> {
        with_cause(
            Some(InitiatingEntity::System),
            self.purge_single_user_inner(user_id, tenant_id, pepper),
        )
        .await
    }

    async fn purge_single_user_inner(
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
        run_erasure_pipeline_reporting(
            self.audit_repo.as_ref(),
            self.erasure_proof_repo.as_ref(),
            self.user_repo.as_ref(),
            tenant_id,
            user_id,
            &pseudonym,
            &email_hash,
            self.ssf_sink.as_deref(),
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
                tracing::warn!(
                    "GDPR export sweep skipped — AXIAM__AUTH__EMAIL_ENCRYPTION_KEY not set"
                );
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
            directory_external_id: None,
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

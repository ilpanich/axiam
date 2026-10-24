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
use axiam_api_rest::handlers::gdpr::{AuditWriteSink, write_audit_with_dead_letter};
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
    AmqpNonceRepository, AssertionReplayRepository, AuditLogFilter, AuditLogRepository,
    ConsentRepository, ErasureProofRepository, ExportJobRepository, FederationLinkRepository,
    FederationLoginStateRepository, GroupRepository, MailPublisher, Pagination,
    PasswordHistoryRepository, PendingSamlRequestRepository, RoleRepository,
    SamlLogoutRunRepository, SamlSpSessionRepository, SessionRepository, SsfEventBufferRepository,
    SsoHandoffCodeRepository, TenantRepository, UserRepository, WebauthnCredentialRepository,
};
use axiam_db::repository::PurgeClaimOutcome;
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
    axiam_db::SurrealDeviceGrantRepository<C>,
    axiam_db::SurrealCibaRequestRepository<C>,
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
    // #758 (e): reads a removed role's `network:` grants for its audit row.
    permission_repo: Arc<axiam_db::SurrealPermissionRepository<C>>,
    group_repo: Arc<SurrealGroupRepository<C>>,
    webauthn_repo: Arc<SurrealWebauthnCredentialRepository<C>>,
    password_history_repo: Arc<SurrealPasswordHistoryRepository<C>>,
    // #533: the erased account's `User` certificates are revoked (never
    // deleted: their issuers' revocation lists are computed from the rows).
    cert_repo: Arc<axiam_db::SurrealCertificateRepository<C>>,
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
    /// #753: the OAuth2 refresh tokens an erasure deletes and the
    /// `oauth2_refresh_token` sweep ages out.
    refresh_token_repo: Arc<axiam_db::SurrealRefreshTokenRepository<C>>,
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
    /// D7 (#802): flushes an erased account's cached decisions after the
    /// erasure's role pass. `None` — the default, and a deployment without a
    /// decision cache — flushes nothing.
    subject_flush: Option<SubjectFlush>,
    /// G-6 (T23.6.3, D-58): the outbound SCIM reconciliation, which the
    /// `scim_reconcile` job runs once a day per enabled target (the claim in
    /// the datastore decides, so replicas do not double-run it). `None` — the
    /// default — runs no reconciliation.
    scim_reconciliation: Option<Arc<dyn axiam_scim::outbound::ScimReconciliation>>,
    /// G-7 (T23.7.1): the CIBA pending-request store, whose expired requests
    /// the `ciba_request` sweep marks `expired` and, after a retention, deletes.
    /// `None` runs no sweep.
    ciba_request_repo: Option<Arc<axiam_db::SurrealCibaRequestRepository<C>>>,
    /// #638: the shared rate-limit table, whose stale buckets the
    /// `rate_limit_bucket` sweep removes. `None` runs no sweep.
    rate_limit_bucket_repo: Option<Arc<axiam_db::SurrealRateLimitBucketRepository<C>>>,
    /// T-470: forwards to Vault the revocations of `vault_pki` leaves it does
    /// not have yet, as the `vault_revocation` job. `None` runs no sweep.
    vault_revocations: Option<Arc<VaultRevocationForwarder<C>>>,
    /// #523: when the `tenant_purge` sweep last looked for orphaned tenant ids
    /// (rows whose tenant a pre-tombstone deletion removed). `None` until the
    /// first tick, which always looks; then once per
    /// [`ORPHAN_TENANT_SCAN_INTERVAL`].
    last_orphan_scan: Option<std::time::Instant>,
    /// **Test seam, never set in production** (#598): a step run first in each
    /// tick, so a test can hold a tick open across a stop.
    step_for_tests: Option<CleanupStepForTests>,
    /// #655, #624: the tenant purges and erasures, each a task of its own that
    /// the composition root waits for after the cleanup task (see
    /// [`AuditedWork`]).
    audited: AuditedWork,
    shutdown: watch::Receiver<bool>,
}

/// A step [`CleanupTask::with_step_for_tests`] runs first in each tick.
#[doc(hidden)]
pub type CleanupStepForTests =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

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

/// How long a replica's claim on a tombstoned tenant's purge keeps the other
/// replicas off it (#610); a claim older than this is taken over.
///
/// The purge is not batched: it is one `DELETE … WHERE tenant_id = $id` per
/// tenant-scoped table, about seventy statements in sequence, each removing
/// all of the tenant's rows of its table at once (the certificate tables three
/// statements each), so even a large tenant's purge is expected to take
/// minutes; an hour leaves an order of magnitude of headroom before a purge
/// still running could be overlapped — and an overlap is safe in any case: the
/// steps are idempotent and only one purge's final `DELETE` finds the tenant
/// row, so the purge is recorded once. What the lease costs is the delay
/// after a replica dies holding a claim: the tenant waits at most an hour for
/// another replica, an erasure of data already out of every read path. Clock
/// skew between replicas, which the stamp is written by, is seconds against an
/// hour. A purge that does not finish releases its claim — one that fails, one
/// given up because the process is stopping, and (#655) one aborted or
/// panicking, from a drop guard — so the next tick, or the next start, resumes
/// it at once; only a process that ends before the release is written leaves
/// the tenant to the lease: a `SIGKILL`, or a unit cut at the stop's bound,
/// whose guard releases the claim from a spawned task that the process exit may
/// cancel (#687).
pub const TENANT_PURGE_LEASE: Duration = Duration::from_secs(60 * 60);

/// How long a unit's claim on its pending-record marker (#689) keeps a sweep
/// from recording the work itself: the tenant purge's lease, for the same
/// reasons. A unit holds the claim for the handful of statements between its
/// point of no return and its record, which the teardown bounds at seconds; a
/// unit that is cut releases it from a drop guard, so the next start records
/// the work at once, and only a process that ends before the release is
/// written — a `SIGKILL`, or a unit cut at the stop's bound, whose spawned
/// release the process exit may cancel (#687) — leaves the marker to this lease.
pub const PENDING_RECORD_LEASE: Duration = TENANT_PURGE_LEASE;

/// How long a unit's claim on an account's erasure (#738) keeps the other
/// replicas' sweeps off the account: the tenant purge's lease, for the same
/// reasons. Every replica runs the GDPR sweep, and two that read one due
/// account used to run its erasure twice — the record stayed single, but the
/// SSF `account_purged` went out twice and the later unit failed its tick on
/// the proof. Now the first claim is exclusive: a second claimant skips the
/// account without an error. A unit holds the claim from before its first
/// destructive step to the anonymization — its point of no return, which
/// clears `deletion_pending`, so no sweep selects the account again — and
/// releases it on every exit before (a failure, a stop, a cut or a panic, from
/// a drop guard), so the next sweep takes the account at once. Only a process
/// that ends before the release is written — a `SIGKILL`, or a unit cut at the
/// stop's bound, whose spawned release the process exit may cancel (#687) —
/// leaves the account to this lease.
pub const ERASURE_CLAIM_LEASE: Duration = TENANT_PURGE_LEASE;

// ---------------------------------------------------------------------------
// Shared rate-limit table (#638, R101W3-05)
// ---------------------------------------------------------------------------

const fn longest(a: u64, b: u64) -> u64 {
    if a > b { a } else { b }
}

/// The longest fixed window any writer of `rate_limit_bucket` counts in, in
/// seconds. Derived from the writers, not chosen:
///
/// - the REST and gRPC shared counters, whose window is
///   [`axiam_db::rate_limit_counter::DEFAULT_WINDOW_SECS`] (the REST layer's
///   private `WINDOW_SECS` and the gRPC layer's are each asserted equal to it
///   by their own tests; the gRPC one is read here as well);
/// - the CIBA hint cap, [`axiam_oauth2::ciba::HINT_CAP_WINDOW_SECS`].
///
/// `rg -n "increment_by" crates/` finds no other writer; a new one with a
/// longer window must be added to this expression, or the sweep deletes its
/// rows early (see [`RATE_LIMIT_BUCKET_RETENTION`] for what that costs).
pub const RATE_LIMIT_BUCKET_LONGEST_WINDOW_SECS: u64 = longest(
    axiam_oauth2::ciba::HINT_CAP_WINDOW_SECS,
    longest(
        axiam_db::rate_limit_counter::DEFAULT_WINDOW_SECS,
        axiam_api_grpc::middleware::rate_limit::WINDOW_SECS as u64,
    ),
);

/// Slack on top of two windows, covering the clock offset between a writer, a
/// reader and the datastore: one minute, far beyond what NTP leaves.
pub const RATE_LIMIT_BUCKET_CLOCK_MARGIN: Duration = Duration::from_secs(60);

/// How long after its last write a `rate_limit_bucket` row is kept: twice
/// [`RATE_LIMIT_BUCKET_LONGEST_WINDOW_SECS`], plus
/// [`RATE_LIMIT_BUCKET_CLOCK_MARGIN`].
///
/// # Why no live limiter reads a row this old
///
/// A bucket row holds the count of one fixed window `[s, s + W)`, `W` its
/// writer's window. A write lands at some `u >= s`: it is made while the
/// window is open, and a write-behind flush of the window comes later still.
/// A limiter reads a stored count in two places only:
///
/// 1. the window it belongs to, at a time `t < s + W` (the shared counters'
///    flush returns it, and the hint cap adds to it);
/// 2. the hint cap's *previous* window, at `t < s + 2W` (the one later window
///    that adds it to its own count).
///
/// From `t >= s + 2W` on, nothing reads the stored count as a count: an
/// upsert for any later window finds `window_start` older than its own and
/// starts from its delta, and a peek finds the same and answers `0` — both
/// exactly what an absent row gives. So a row is dead once `s + 2W` has
/// passed, and `s <= u`.
///
/// The sweep deletes a row only when `updated_at` (the datastore's clock at
/// the last write, `u`) is more than `2L + margin` in the past of the
/// *datastore's* clock (`time::now()`, evaluated in the selection and in the
/// `DELETE`, #676), `L >= W` being the longest window in use. The sweeping
/// replica's own clock takes no part in the comparison, so its offset from the
/// datastore is not an input. A reader at `t` (its own clock) after the sweep
/// has `t >= u + 2L + margin - offset >= s + 2W` as long as the offset between
/// the *reader's* clock and the datastore's is under the margin. No row a
/// limiter still reads is ever deleted.
///
/// If a reader's clock were off by more than the margin, the cost is a count
/// read as `0` for the rest of one window — the same thing a window boundary
/// does. For the hint cap that is a stretch that may admit up to twice the
/// allowance, so its "exactly" holds under the assumption that readers and
/// the datastore agree to within the margin (T-424).
///
/// "The datastore's clock" is one clock for the shipped single-node SurrealDB
/// (`k8s/surrealdb/statefulset.yml`, `replicas: 1`). A clustered SurrealDB
/// evaluates `time::now()` on whichever compute node runs the statement, so the
/// margin must also cover the skew between SurrealDB nodes.
///
/// The table is bounded by what was written in the last `RETENTION`; the
/// sweep makes the growth of a table that gained a row per hint, per client
/// IP and per endpoint, forever, a steady state.
pub const RATE_LIMIT_BUCKET_RETENTION: Duration = Duration::from_secs(
    2 * RATE_LIMIT_BUCKET_LONGEST_WINDOW_SECS + RATE_LIMIT_BUCKET_CLOCK_MARGIN.as_secs(),
);

/// Rows one `rate_limit_bucket` delete removes at most.
pub const RATE_LIMIT_BUCKET_SWEEP_BATCH: u32 = 500;

/// Deletes in one tick: with [`RATE_LIMIT_BUCKET_SWEEP_BATCH`], 50 000 rows,
/// after which the next tick continues. A tick is never held open by a table
/// that grew for months before this sweep existed.
pub const RATE_LIMIT_BUCKET_SWEEP_MAX_BATCHES: u32 = 100;

/// One pass of the `rate_limit_bucket` job (#638): delete the buckets whose
/// last write is older than [`RATE_LIMIT_BUCKET_RETENTION`] on the datastore's
/// clock, in batches; returns how many were removed.
///
/// Safe for any number of replicas sweeping at once: each delete re-checks
/// `updated_at` on the row it removes, so a row is removed once, and a row a
/// limiter has just written is kept. A public free function, for the reason
/// [`run_erasure_pipeline`] is.
pub async fn sweep_rate_limit_buckets<C: Connection + Send + Sync + 'static>(
    repo: &axiam_db::SurrealRateLimitBucketRepository<C>,
) -> Result<u64, AxiamError> {
    let mut removed = 0u64;
    for _ in 0..RATE_LIMIT_BUCKET_SWEEP_MAX_BATCHES {
        let n = repo
            .delete_stale(RATE_LIMIT_BUCKET_RETENTION, RATE_LIMIT_BUCKET_SWEEP_BATCH)
            .await?;
        removed += n;
        if n < u64::from(RATE_LIMIT_BUCKET_SWEEP_BATCH) {
            break;
        }
    }
    Ok(removed)
}

/// Erasure step (a), for the OAuth2 refresh tokens (#753): revoke every row
/// of the user, then delete them.
///
/// The rows carry `user_id`, `client_id`, the scopes and, since v109, the
/// device key's `dpop_jkt`; revoking left them in the table until the tenant
/// was purged. The revocation runs first so a token redeemable in the window
/// between the two statements is dead before its row goes, and both are
/// idempotent. An erasure cut before its point of no return re-runs it; one cut
/// after it (the recovery of #737) needs no more, the rows being gone already.
///
/// A free function, and public, for the reason [`run_erasure_pipeline`] is.
///
/// # Errors
///
/// The datastore error of either statement; the purge fails closed on it and
/// the next sweep retries.
pub async fn erase_oauth2_refresh_tokens<RT: axiam_core::repository::RefreshTokenRepository>(
    repo: &RT,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<u64, AxiamError> {
    repo.revoke_all_for_user(tenant_id, user_id).await?;
    repo.delete_all_for_user(tenant_id, user_id).await
}

/// Flushes one subject's cached authorization decisions, locally and, when the
/// broadcast is on, on every replica (D7): the composition root's
/// `AuthzChecker::invalidate_subject`, which logs a broadcast it cannot
/// confirm. The erasure's role pass calls it (#802).
pub type SubjectFlush = Arc<
    dyn Fn(Uuid, Uuid) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Step (b3)'s role pass (#758 (e)): unassign every direct role assignment of
/// the erased account, and write one `network_role.unassigned` row (the
/// [`axiam_authz::network_gate::AUDIT_ROLE_UNASSIGNED`] action) for each
/// **network role** it removes.
///
/// A network role here is what the gate calls a network-sensitive role: one
/// carrying at least one `network:` grant, allow or deny
/// ([`axiam_core::models::network::is_network_action`] over the role's
/// permission grants, read before the unassignment). The row has the shape the
/// REST gate writes for an administrator's unassignment (`role_id`, `role`,
/// `grantee {kind, id}`, `node`, `permissions`), tenant of the account,
/// resource the node, actor the platform (`System`, nil id) — the erasure is
/// the platform's act, and the row says so. The grantee's id is cleared again
/// by `pseudonymize_actor` when the account is anonymized, so no row names
/// the erased subject.
///
/// Each row is written after its unassignment landed, like the gate's, and only
/// when that unassignment is the one that removed the edge (#792): a re-entered
/// erasure finds no assignment left and writes none, and of two units that both
/// read one assignment (a stalled unit and its successor) one writes the row. A public free
/// function, for the reason [`run_erasure_pipeline`] is.
///
/// Last, `flush` (when the deployment caches decisions) drops the account's
/// cached decisions, so a decision evaluated before the unassignments is not
/// served, nor inserted behind them, until the TTL (#802, R112-09 (b)). It
/// runs after the group memberships of step (b3), removed just before this
/// pass, are gone too, and on a re-entered erasure as well: it is idempotent.
///
/// # Errors
///
/// The datastore error of a read or an unassignment (fail-closed: the purge
/// retries). A failed audit append is dead-lettered, not returned.
pub async fn remove_erased_users_roles<R, P, A>(
    role_repo: &R,
    permission_repo: &P,
    audit_repo: &A,
    flush: Option<&SubjectFlush>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<u64, AxiamError>
where
    R: RoleRepository,
    P: axiam_core::repository::PermissionRepository,
    A: AuditWriteSink,
{
    let assignments = role_repo
        .get_user_role_assignments(tenant_id, user_id)
        .await?;
    let mut network_rows = 0;
    for a in assignments {
        let network_permissions: Vec<serde_json::Value> = permission_repo
            .get_role_permission_grants(tenant_id, a.role.id)
            .await?
            .into_iter()
            .filter(|g| axiam_core::models::network::is_network_action(&g.permission.action))
            .map(|g| {
                serde_json::json!({
                    "action": g.permission.action,
                    "effect": g.effect.as_str(),
                    "scope_ids": g.scope_ids,
                })
            })
            .collect();
        // Only the unit whose unassignment removed the edge records it: a
        // unit stalled past the claim's lease and its successor can both have
        // read this assignment, and the second one's unassignment matches
        // nothing (`false`, not an error).
        let removed = role_repo
            .unassign_from_user(tenant_id, user_id, a.role.id, a.resource_id)
            .await?;
        if !removed || network_permissions.is_empty() {
            continue;
        }
        write_audit_with_dead_letter(
            audit_repo,
            CreateAuditLogEntry {
                tenant_id,
                actor_id: Uuid::nil(),
                actor_type: ActorType::System,
                action: axiam_authz::network_gate::AUDIT_ROLE_UNASSIGNED.to_owned(),
                resource_id: a.resource_id,
                outcome: AuditOutcome::Success,
                ip_address: None,
                metadata: Some(serde_json::json!({
                    "role_id": a.role.id,
                    "role": a.role.name,
                    "grantee": { "kind": "user", "id": user_id },
                    "node": a.resource_id.map_or_else(|| "none".to_owned(), |r| r.to_string()),
                    "permissions": network_permissions,
                    "reason": "account_erasure",
                })),
            },
        )
        .await;
        network_rows += 1;
    }
    if let Some(flush) = flush {
        flush(tenant_id, user_id).await;
    }
    Ok(network_rows)
}

/// The `oauth2_refresh_token` sweep (#753): delete the rows whose token
/// expired more than [`REFRESH_REPLAY_RETENTION`] before `now`, revoked or not,
/// in bounded batches, and return how many.
///
/// The cutoff is `expires_at`, never `revoked`: a rotated or revoked token is
/// recognised as a replay by its row until it is deleted (T-254), so a revoked
/// row whose expiry is still ahead stays.
///
/// Runs at most [`REFRESH_SWEEP_MAX_BATCHES`] batches of
/// [`REFRESH_SWEEP_BATCH`] rows, and stops between batches on a shutdown
/// signal; the next tick continues (R112W1-02). The first run after the
/// upgrade, which finds every row expired since the deployment began, thus
/// takes as many ticks as it needs and never one statement over the whole
/// backlog. Two replicas may run it at once: each batch is chosen and deleted
/// by id, and a row the other replica removed first is not counted. A public
/// free function, for the reason [`run_erasure_pipeline`] is.
///
/// # Errors
///
/// The repository's error from the batch that failed; batches already deleted
/// stay deleted.
pub async fn sweep_refresh_tokens<RT: axiam_core::repository::RefreshTokenRepository>(
    repo: &RT,
    now: chrono::DateTime<Utc>,
    shutdown: &watch::Receiver<bool>,
) -> Result<u64, AxiamError> {
    let before = now - REFRESH_REPLAY_RETENTION;
    let mut removed = 0_u64;
    for _ in 0..REFRESH_SWEEP_MAX_BATCHES {
        if *shutdown.borrow() {
            break;
        }
        let batch = repo.delete_expired(before, REFRESH_SWEEP_BATCH).await?;
        removed += batch;
        if batch < u64::from(REFRESH_SWEEP_BATCH) {
            break;
        }
    }
    Ok(removed)
}

/// Rows one batch of the `oauth2_refresh_token` sweep deletes (R112W1-02).
pub const REFRESH_SWEEP_BATCH: u32 = 500;

/// Batches one run of the `oauth2_refresh_token` sweep may take: at most
/// `BATCH * MAX_BATCHES` rows a tick, the rest at the next. Bounds the first
/// run over a table that has never been swept, as
/// [`CERTIFICATE_RETENTION_MAX_BATCHES`] does for certificates.
pub const REFRESH_SWEEP_MAX_BATCHES: u32 = 10;

/// How long a refresh-token row is kept past its `expires_at`:
/// [`axiam_oauth2::token::REFRESH_REPLAY_RETENTION_SECS`].
pub const REFRESH_REPLAY_RETENTION: chrono::TimeDelta =
    chrono::TimeDelta::seconds(axiam_oauth2::token::REFRESH_REPLAY_RETENTION_SECS);

/// Rows one batch of the `certificate_retention` sweep deletes (R101W1-05).
pub const CERTIFICATE_RETENTION_BATCH: u32 = 500;

/// Batches one run of the `certificate_retention` sweep may take: at most
/// `BATCH * MAX_BATCHES` rows a tick, the rest at the next. Bounds a first run
/// over a deployment that has never deleted a certificate row.
pub const CERTIFICATE_RETENTION_MAX_BATCHES: u32 = 20;

/// One pass of the `tenant_purge` job: purge every tombstoned tenant and, when
/// `scan_orphans`, every orphaned tenant id.
///
/// A free function, and public, for the reason [`run_erasure_pipeline`] is
/// one. Each tenant is purged by
/// [`SurrealTenantRepository::purge_tombstoned_rows`] — every tenant-scoped
/// table in the order user erasure uses, of its audit trail the rows at or
/// before the time of the export the deletion required (T-118, R1W1-04) — and
/// then [`SurrealTenantRepository::remove_purged_tenant`], its tenant row; or,
/// for an orphan, under its claim marker, by
/// [`SurrealTenantRepository::purge_orphan_rows`], which leaves the audit
/// trail to the retention sweep, and then by the same removal of the marker.
/// Audit rows the purge keeps name a tenant that no longer exists and are
/// deleted by the audit retention sweep (T-119) like any other. Each completed purge is recorded in the **system**
/// log as `tenants.purged`, beside the `tenants.deleted` record the deletion
/// wrote, with the export time used and the audit rows deleted and kept;
/// neither record is ever purged.
///
/// Every replica runs this sweep (#610). A tombstoned tenant is purged only by
/// the replica whose [`SurrealTenantRepository::claim_purge`] wins it; the
/// others skip it for [`TENANT_PURGE_LEASE`]. A tenant the purge finds already
/// purged — gone before the claim, or removed by an overlapping purge after a
/// lease ran out — is success, not a failure, and is not recorded again: only
/// the purge that removed the tenant row writes `tenants.purged`. An orphaned
/// id is claimed the same way, by a marker row
/// ([`SurrealTenantRepository::claim_orphan_purge`], R101W1-09 (a)): replicas
/// whose daily scans coincide purge and record it once, and a scan that
/// predates another replica's finished purge finds nothing left, writes no
/// marker and records nothing (#714).
///
/// Each tenant's purge, from its claim to its record, is one unit of
/// [`AuditedWork`] (#655): a task of its own, which aborting the cleanup task
/// does not cut. The sweep starts no purge once the process is stopping
/// (checked between tenants); a purge under way gives itself up at the stop as
/// long as its tenant row is still there, releasing its claim, and once the row
/// is removed it runs on to its record.
///
/// The removal leaves a `tenant_purge_pending` marker in its own transaction,
/// which the unit clears once it has recorded the purge (#689). A unit cut in
/// between leaves the marker, and every pass starts by recording what the
/// markers left standing ([`record_pending_purges`]), so the next start writes
/// the `tenants.purged` the cut unit did not, once.
///
/// * `Ok(n)` is the number of tenants (and orphaned ids) this call purged.
/// * One tenant's failure does not stop the others; any failure makes the sweep
///   fail, naming how many failed and never a tenant's data. The failed tenant
///   stays tombstoned, its claim is released, and the next pass resumes it
///   (every step is idempotent).
/// * A stop ends the pass early with `Ok`: the tenants left stay tombstoned and
///   unclaimed, and the next start purges them.
///
/// # Errors
///
/// [`AxiamError::Internal`] as above, or the datastore error that kept the
/// tombstoned tenants or the orphans from being listed (the tombstoned tenants
/// are still purged when only the orphans could not be).
pub async fn sweep_tenant_purge<C, S>(
    tenant_repo: &Arc<SurrealTenantRepository<C>>,
    audit: &Arc<S>,
    scan_orphans: bool,
    work: &AuditedWork,
) -> Result<u64, AxiamError>
where
    C: Connection,
    S: AuditWriteSink + 'static,
{
    let lease = chrono::TimeDelta::from_std(TENANT_PURGE_LEASE)
        .map_err(|e| AxiamError::Internal(format!("tenant purge lease: {e}")))?;
    // #689: first, the purges a unit removed and was cut before recording. A
    // failure here does not hold back the purges; it is reported after them.
    let record_lease = chrono::TimeDelta::from_std(PENDING_RECORD_LEASE)
        .map_err(|e| AxiamError::Internal(format!("pending record lease: {e}")))?;
    let pending_error = record_pending_purges(tenant_repo, audit.as_ref(), record_lease, work)
        .await
        .err();

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
    let due_count = due.len();
    for (started, (tenant_id, orphan)) in due.into_iter().enumerate() {
        // #655: no purge starts once the process is stopping; the tenants left
        // stay tombstoned, and the next start purges them.
        if work.stopping() {
            tracing::info!(
                purged,
                left = due_count - started,
                "tenant purge sweep stopped: the process is stopping (the rest stay tombstoned)"
            );
            break;
        }
        let (tenants, sink, unit) = (Arc::clone(tenant_repo), Arc::clone(audit), work.clone());
        let outcome = if orphan {
            work.run(purge_orphan_unit(tenants, sink, tenant_id, unit))
                .await
        } else {
            work.run(purge_tombstoned_unit(tenants, sink, tenant_id, lease, unit))
                .await
        };
        match outcome {
            Some(Ok(PurgeOutcome::Purged)) => purged += 1,
            // Another replica holds it, or it is already gone.
            Some(Ok(PurgeOutcome::Skipped)) => {}
            // Given up at the stop (or still running, and left to the
            // teardown's join): the loop's check above ends the pass.
            Some(Ok(PurgeOutcome::Abandoned)) | None if work.stopping() => {}
            Some(Ok(PurgeOutcome::Abandoned)) => {}
            // The unit panicked; its claim guard released the claim.
            None => {
                failed += 1;
                tracing::warn!(
                    %tenant_id,
                    orphan,
                    "tenant purge ended without an outcome; the tenant stays tombstoned and the \
                     next sweep resumes it"
                );
            }
            Some(Err(e)) => {
                failed += 1;
                tracing::warn!(
                    error = %e,
                    %tenant_id,
                    orphan,
                    "tenant purge incomplete; the tenant stays tombstoned and the next sweep resumes it"
                );
            }
        }
    }

    if failed > 0 {
        return Err(AxiamError::Internal(format!(
            "tenant purge was incomplete for {failed} of {} tenant(s)",
            failed + purged
        )));
    }
    if let Some(e) = scan_error.or(pending_error) {
        return Err(e);
    }
    Ok(purged)
}

/// How one tenant's purge unit ended, when it did not fail.
enum PurgeOutcome {
    /// This unit purged the tenant and wrote `tenants.purged`.
    Purged,
    /// Another replica holds the claim, or the tenant is already purged (for
    /// an orphaned id: a scan that predates its finished purge).
    Skipped,
    /// Given up because the process is stopping, before the point of no
    /// return; the tenant stays tombstoned and unclaimed.
    Abandoned,
}

/// One tombstoned tenant's purge, from its claim to its `tenants.purged`
/// record: one unit of [`AuditedWork`] (#655).
///
/// The point of no return is the removal of the tenant row: before it every
/// step is idempotent and the tenant stays tombstoned, so the unit gives up at
/// the stop and releases its claim; it never removes the row once the process
/// is stopping. After it, the record is the only thing left, and the unit
/// writes it whatever the stop says.
///
/// The tombstoned row may be an orphan purge's claim marker whose claimant
/// died or gave it up (R101W1-09 (a)): its rows are then purged as an orphan's
/// and the record says `orphan: true` (the report's `orphan`).
async fn purge_tombstoned_unit<C, S>(
    tenants: Arc<SurrealTenantRepository<C>>,
    audit: Arc<S>,
    tenant_id: Uuid,
    lease: chrono::TimeDelta,
    work: AuditedWork,
) -> Result<PurgeOutcome, AxiamError>
where
    C: Connection,
    S: AuditWriteSink,
{
    let claimed_at = Utc::now();
    if !tenants.claim_purge(tenant_id, claimed_at, lease).await? {
        return Ok(PurgeOutcome::Skipped);
    }
    // From here every exit but a removed tenant row releases the claim — the
    // awaited release below, or, for an abort or a panic, the guard's drop.
    let claim = PurgeClaim {
        tenants: Arc::clone(&tenants),
        tenant_id,
        claimed_at,
        held: true,
    };
    let rows = work
        .until_stopped(async {
            let report = tenants.purge_tombstoned_rows(tenant_id).await?;
            work.step(UnitStep::TenantRowsPurged(tenant_id)).await;
            Ok::<_, AxiamError>(report)
        })
        .await;
    let report = match rows {
        Some(Ok(report)) => report,
        // Purged by an overlapping replica: done, and recorded by the purge
        // that removed the row.
        Some(Err(AxiamError::NotFound { .. })) => {
            claim.settle();
            return Ok(PurgeOutcome::Skipped);
        }
        // Let the next tick (any replica's) retry it now rather than after
        // the lease.
        Some(Err(e)) => {
            claim.release().await;
            return Err(e);
        }
        None => {
            claim.release().await;
            return Ok(PurgeOutcome::Abandoned);
        }
    };
    // Once the process is stopping, no new crossing of the point of no return
    // starts (a crossing already being sent completes).
    if work.stopping() {
        claim.release().await;
        return Ok(PurgeOutcome::Abandoned);
    }
    let Some(record) = cross_point_of_no_return(&tenants, tenant_id, &report, claim).await? else {
        return Ok(PurgeOutcome::Skipped);
    };
    work.step(UnitStep::TenantRowRemoved(tenant_id)).await;
    record_tenant_purged(audit.as_ref(), tenant_id, false, &report).await;
    work.step(UnitStep::Recorded(tenant_id)).await;
    record.settle().await;
    Ok(PurgeOutcome::Purged)
}

/// A purge unit's point of no return (#655): remove the tenant row (or the
/// orphan's marker) and, in the same transaction, write its
/// `tenant_purge_pending` marker (#689), then settle the purge claim and hold
/// the marker's in its place. `Ok(None)` when an overlapping purge removed the
/// row first (it records the purge).
///
/// The marker carries a stamp of its own, taken here, rather than the purge
/// claim's: the claim may be as old as the purge, and a stale stamp would let
/// another replica's sweep take the marker while this unit records it.
async fn cross_point_of_no_return<C: Connection>(
    tenants: &Arc<SurrealTenantRepository<C>>,
    tenant_id: Uuid,
    report: &axiam_db::repository::tenant_purge::TenantPurgeReport,
    claim: PurgeClaim<C>,
) -> Result<Option<RecordClaim<C>>, AxiamError> {
    let stamp = Utc::now();
    match tenants.remove_purged_tenant(tenant_id, report, stamp).await {
        Ok(()) => {
            claim.settle();
            Ok(Some(RecordClaim {
                marker: PendingMarker::TenantPurge {
                    tenants: Arc::clone(tenants),
                    tenant_id,
                },
                stamp,
                held: true,
            }))
        }
        Err(AxiamError::NotFound { .. }) => {
            claim.settle();
            Ok(None)
        }
        Err(e) => {
            // The transaction may have committed before the error reached us:
            // release a marker stamped with ours, if there is one, so the next
            // sweep records the purge at once. Nothing matches otherwise.
            if let Err(release) = tenants.release_purge_record(tenant_id, stamp).await {
                tracing::warn!(
                    error = %release,
                    %tenant_id,
                    "could not release a tenant purge's pending record; it lapses with its lease"
                );
            }
            claim.release().await;
            Err(e)
        }
    }
}

/// Record the tenant purges whose `tenant_purge_pending` marker (#689) still
/// stands — a unit cut between the removal of the tenant row and the clearing
/// of its marker — and clear each marker. The first step of every
/// [`sweep_tenant_purge`] pass; none starts once the process is stopping.
///
/// Each marker is claimed first
/// ([`SurrealTenantRepository::claim_pending_purge_records`]): only one released
/// or older than `lease`, and conditionally on the claim read, so a unit still
/// recording and another replica's sweep are never both its owner. The record
/// is written unless the system log already holds a `tenants.purged` for the
/// id written since the removal (a unit cut after its record and before the
/// clearing), with what the removal stored: the record is the one the unit
/// would have written. The claim is held by the same guard a unit holds, so a
/// pass cut here releases it.
///
/// `Ok(n)` is the number of records this call wrote.
///
/// # Errors
///
/// The datastore error that kept the markers from being read or claimed, or
/// [`AxiamError::Internal`] naming how many could not be checked (each of
/// those is released for the next pass).
pub async fn record_pending_purges<C, S>(
    tenants: &Arc<SurrealTenantRepository<C>>,
    audit: &S,
    lease: chrono::TimeDelta,
    work: &AuditedWork,
) -> Result<u64, AxiamError>
where
    C: Connection,
    S: AuditWriteSink,
{
    if work.stopping() {
        return Ok(0);
    }
    let pending = tenants
        .claim_pending_purge_records(Utc::now(), lease)
        .await?;
    let (mut recorded, mut failed) = (0u64, 0u64);
    for marker in pending {
        let claim = RecordClaim {
            marker: PendingMarker::TenantPurge {
                tenants: Arc::clone(tenants),
                tenant_id: marker.tenant_id,
            },
            stamp: marker.claimed_at,
            held: true,
        };
        if work.stopping() {
            claim.release().await;
            continue;
        }
        match tenants
            .purge_recorded_since(
                marker.tenant_id,
                axiam_api_rest::handlers::tenants::TENANT_PURGED_ACTION,
                marker.purged_at,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                record_tenant_purged(audit, marker.tenant_id, false, &marker.report).await;
                recorded += 1;
                tracing::warn!(
                    tenant_id = %marker.tenant_id,
                    "recorded a tenant purge whose unit was cut before its record (#689)"
                );
                work.step(UnitStep::Recorded(marker.tenant_id)).await;
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    error = %e,
                    tenant_id = %marker.tenant_id,
                    "could not check a pending tenant purge record; the next pass retries it"
                );
                claim.release().await;
                continue;
            }
        }
        claim.settle().await;
    }
    if failed > 0 {
        return Err(AxiamError::Internal(format!(
            "{failed} pending tenant purge record(s) could not be checked"
        )));
    }
    Ok(recorded)
}

/// One orphaned tenant id's purge and its `tenants.purged` record: one unit of
/// [`AuditedWork`] (#655), claimed by a marker row (R101W1-09 (a)).
///
/// The unit arms its [`PurgeClaim`] **before**
/// [`SurrealTenantRepository::claim_orphan_purge`] writes the marker, keyed by
/// the stamp the marker will carry, so the marker is guarded from the instant
/// it exists (#714): a cut anywhere from the `CREATE` on releases the claim,
/// and the release is conditional on the stamp, so it changes nothing when the
/// `CREATE` did not land. The claim writes the marker only while the id still
/// owns a row to purge: another replica's claim, or a scan that predates a
/// finished purge, is skipped, writes nothing and records nothing. Then the
/// unit runs as [`purge_tombstoned_unit`] does: the rows
/// ([`SurrealTenantRepository::purge_orphan_rows`]), then the removal of the
/// marker ([`SurrealTenantRepository::remove_purged_tenant`]) as the point of
/// no return, and the record only when this unit removed it. Given up at the
/// stop, failed, or cut, the marker stays tombstoned with its claim released,
/// and the tombstoned-tenant sweep purges it at once as the orphan it is, and
/// records it — a marker always stands for a purge nobody has recorded.
async fn purge_orphan_unit<C, S>(
    tenants: Arc<SurrealTenantRepository<C>>,
    audit: Arc<S>,
    tenant_id: Uuid,
    work: AuditedWork,
) -> Result<PurgeOutcome, AxiamError>
where
    C: Connection,
    S: AuditWriteSink,
{
    let claimed_at = Utc::now();
    // Armed before the marker exists (#714): every exit from here but a
    // removed marker — or a claim that wrote none — releases the claim, so the
    // marker is the tombstoned-tenant sweep's at once.
    let claim = PurgeClaim {
        tenants: Arc::clone(&tenants),
        tenant_id,
        claimed_at,
        held: true,
    };
    match tenants.claim_orphan_purge(tenant_id, claimed_at).await {
        Ok(true) => {}
        // No marker of ours: another replica's, nothing left, or no orphan.
        Ok(false) => {
            claim.settle();
            tenants.orphan_claim_refusal(tenant_id).await?;
            return Ok(PurgeOutcome::Skipped);
        }
        // The marker may have landed: release it, by its stamp.
        Err(e) => {
            claim.release().await;
            return Err(e);
        }
    }
    work.step(UnitStep::OrphanClaimed(tenant_id)).await;
    let report = match work
        .until_stopped(tenants.purge_orphan_rows(tenant_id))
        .await
    {
        Some(Ok(report)) => report,
        Some(Err(e)) => {
            claim.release().await;
            return Err(e);
        }
        None => {
            claim.release().await;
            return Ok(PurgeOutcome::Abandoned);
        }
    };
    // Once the process is stopping, no new crossing of the point of no return
    // starts (a crossing already being sent completes).
    if work.stopping() {
        claim.release().await;
        return Ok(PurgeOutcome::Abandoned);
    }
    // `None`: the marker was taken over and removed by another purge, which
    // records it.
    let Some(record) = cross_point_of_no_return(&tenants, tenant_id, &report, claim).await? else {
        return Ok(PurgeOutcome::Skipped);
    };
    work.step(UnitStep::TenantRowRemoved(tenant_id)).await;
    record_tenant_purged(audit.as_ref(), tenant_id, true, &report).await;
    work.step(UnitStep::Recorded(tenant_id)).await;
    record.settle().await;
    Ok(PurgeOutcome::Purged)
}

/// Write `tenants.purged` to the system log for a purge that finished.
async fn record_tenant_purged<S: AuditWriteSink>(
    audit: &S,
    tenant_id: Uuid,
    orphan: bool,
    report: &axiam_db::repository::tenant_purge::TenantPurgeReport,
) {
    write_audit_with_dead_letter(
        audit,
        CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: axiam_api_rest::handlers::tenants::TENANT_PURGED_ACTION.to_string(),
            resource_id: Some(tenant_id),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                // An orphan's claim marker taken over after its claimant
                // died is purged as a tombstoned row, and is still an orphan.
                "orphan": orphan || report.orphan,
                "audit_exported_through": report.audit_exported_through,
                "audit_rows_deleted": report.audit_rows_deleted,
                "audit_rows_kept": report.audit_rows_kept,
            })),
        },
    )
    .await;
    tracing::info!(
        %tenant_id,
        orphan = orphan || report.orphan,
        audit_rows_deleted = report.audit_rows_deleted,
        audit_rows_kept = report.audit_rows_kept,
        "deleted tenant's data purged"
    );
}

/// A replica's claim on a tombstoned tenant's purge (#610), released on every
/// exit but a removed tenant row (#655). An orphan purge arms it before its
/// claim marker is written, so the marker is guarded from the instant it
/// exists (#714).
///
/// The purge releases it itself, awaited, where it can — a failure, or giving
/// up at the stop. Every other exit — the unit aborted at the teardown's bound,
/// a panic, a release that was itself cut — drops the guard still holding the
/// claim, and the drop spawns the release on the runtime. Without that, the
/// next start's sweep found a claim younger than [`TENANT_PURGE_LEASE`] and
/// skipped the tenant for up to an hour. That release is a spawned task, and
/// nothing waits for it: a unit cut at the teardown's bound (the one exit where
/// the guard is the only release, typically a datastore too slow to answer the
/// awaited one) is dropped inside [`AuditedWork::join`], and the process exit
/// that follows drops the runtime, which cancels the task unless it has already
/// landed. The tenant then waits out [`TENANT_PURGE_LEASE`] (#687; awaiting the
/// release at the bound was declined, since it needs a budget line of its own).
struct PurgeClaim<C: Connection> {
    tenants: Arc<SurrealTenantRepository<C>>,
    tenant_id: Uuid,
    claimed_at: chrono::DateTime<Utc>,
    held: bool,
}

impl<C: Connection> PurgeClaim<C> {
    /// Release the claim, awaited. A release cut mid-way is retried by the
    /// drop, since the claim counts as held until it has answered.
    async fn release(mut self) {
        if let Err(e) = self
            .tenants
            .release_purge_claim(self.tenant_id, self.claimed_at)
            .await
        {
            tracing::warn!(
                error = %e,
                tenant_id = %self.tenant_id,
                "could not release the tenant purge claim; it lapses with its lease"
            );
        }
        self.held = false;
    }

    /// The tenant row is gone (this purge removed it, or another did): there is
    /// nothing left to claim.
    fn settle(mut self) {
        self.held = false;
    }
}

impl<C: Connection> Drop for PurgeClaim<C> {
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        let (tenants, tenant_id, claimed_at) =
            (Arc::clone(&self.tenants), self.tenant_id, self.claimed_at);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Err(e) = tenants.release_purge_claim(tenant_id, claimed_at).await {
                        tracing::warn!(
                            error = %e,
                            %tenant_id,
                            "could not release the claim of a tenant purge that was cut; it \
                             lapses with its lease"
                        );
                    }
                });
            }
            Err(_) => tracing::warn!(
                %tenant_id,
                "the claim of a tenant purge that was cut outside a runtime lapses with its lease"
            ),
        }
    }
}

/// A unit's claim on an account's erasure (#738), held from the claim to the
/// anonymization and released on every other exit.
///
/// The unit releases it itself, awaited, where it can — a failure, or giving
/// up at the stop. Every other exit — the unit aborted at the teardown's bound,
/// a panic — drops the guard still holding the claim, and the drop spawns the
/// release on the runtime, as [`PurgeClaim`]'s does, with the same residual: a
/// release the process exit cancels leaves the account to
/// [`ERASURE_CLAIM_LEASE`]. The release is conditional on the stamp and on the
/// account still being deletion-pending, so a release after the anonymization
/// (an error past the point of no return, a cut after it) changes nothing.
struct ErasureClaim<C: Connection> {
    deletions: SurrealAccountDeletionRepository<C>,
    tenant_id: Uuid,
    user_id: Uuid,
    stamp: chrono::DateTime<Utc>,
    held: bool,
}

impl<C: Connection> ErasureClaim<C> {
    /// Release the claim, awaited.
    async fn release(mut self) {
        if let Err(e) = self
            .deletions
            .release_purge_claim(self.tenant_id, self.user_id, self.stamp)
            .await
        {
            tracing::warn!(
                error = %e,
                tenant_id = %self.tenant_id,
                user_id = %self.user_id,
                "could not release an erasure's claim; it lapses with its lease"
            );
        }
        self.held = false;
    }

    /// The account is erased: no sweep selects it again, and there is nothing
    /// left to release.
    fn settle(mut self) {
        self.held = false;
    }
}

impl<C: Connection> Drop for ErasureClaim<C> {
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        let (deletions, tenant_id, user_id, stamp) = (
            self.deletions.clone(),
            self.tenant_id,
            self.user_id,
            self.stamp,
        );
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Err(e) = deletions
                        .release_purge_claim(tenant_id, user_id, stamp)
                        .await
                    {
                        tracing::warn!(
                            error = %e,
                            %tenant_id,
                            %user_id,
                            "could not release the claim of an erasure that was cut; it lapses \
                             with its lease"
                        );
                    }
                });
            }
            Err(_) => tracing::warn!(
                %tenant_id,
                %user_id,
                "the claim of an erasure cut outside a runtime lapses with its lease"
            ),
        }
    }
}

/// A pending-record marker (#689, schema v108): the record a unit past its
/// point of no return still owes.
enum PendingMarker<C: Connection> {
    /// `tenant_purge_pending`, keyed by the purged tenant's id.
    TenantPurge {
        tenants: Arc<SurrealTenantRepository<C>>,
        tenant_id: Uuid,
    },
    /// `user.erasure_audit_pending` on the erased account.
    Erasure {
        deletions: SurrealAccountDeletionRepository<C>,
        tenant_id: Uuid,
        user_id: Uuid,
    },
}

impl<C: Connection> Clone for PendingMarker<C> {
    fn clone(&self) -> Self {
        match self {
            Self::TenantPurge { tenants, tenant_id } => Self::TenantPurge {
                tenants: Arc::clone(tenants),
                tenant_id: *tenant_id,
            },
            Self::Erasure {
                deletions,
                tenant_id,
                user_id,
            } => Self::Erasure {
                deletions: deletions.clone(),
                tenant_id: *tenant_id,
                user_id: *user_id,
            },
        }
    }
}

impl<C: Connection> PendingMarker<C> {
    fn id(&self) -> Uuid {
        match self {
            Self::TenantPurge { tenant_id, .. } => *tenant_id,
            Self::Erasure { user_id, .. } => *user_id,
        }
    }

    async fn settle(&self, stamp: chrono::DateTime<Utc>) -> Result<bool, AxiamError> {
        match self {
            Self::TenantPurge { tenants, tenant_id } => {
                tenants.settle_purge_record(*tenant_id, stamp).await
            }
            Self::Erasure {
                deletions,
                tenant_id,
                user_id,
            } => {
                deletions
                    .settle_erasure_record(*tenant_id, *user_id, stamp)
                    .await
            }
        }
    }

    async fn release(&self, stamp: chrono::DateTime<Utc>) -> Result<(), AxiamError> {
        match self {
            Self::TenantPurge { tenants, tenant_id } => {
                tenants.release_purge_record(*tenant_id, stamp).await
            }
            Self::Erasure {
                deletions,
                tenant_id,
                user_id,
            } => {
                deletions
                    .release_erasure_record(*tenant_id, *user_id, stamp)
                    .await
            }
        }
    }
}

/// A claim on a pending-record marker (#689), held from the point of no return
/// (or a sweep's claim) to the record: settled — the marker cleared, for an
/// erasure with its deletion request's completion — once the record is
/// written, and released on every other exit, so the next sweep records the
/// work at once rather than after [`PENDING_RECORD_LEASE`].
///
/// Like [`PurgeClaim`], an exit that cannot await — the unit aborted at the
/// teardown's bound, a panic — drops the guard still holding the claim, and the
/// drop spawns the release on the runtime. A unit cut at the teardown's bound
/// drops it just before the process exit drops the runtime, which cancels a
/// release that has not landed (see [`PurgeClaim`]); the marker then lapses with
/// the lease (#687).
/// Every write is conditional on `stamp`, so a marker another replica has
/// taken over is left to it.
struct RecordClaim<C: Connection> {
    marker: PendingMarker<C>,
    stamp: chrono::DateTime<Utc>,
    held: bool,
}

impl<C: Connection> RecordClaim<C> {
    /// The record is written: clear the marker. A failed clearing leaves it for
    /// the next sweep, which finds the record already written and clears it.
    async fn settle(mut self) {
        if let Err(e) = self.marker.settle(self.stamp).await {
            tracing::warn!(
                error = %e,
                id = %self.marker.id(),
                "could not clear a pending-record marker; the next sweep finds the record \
                 written and clears it"
            );
        }
        self.held = false;
    }

    /// Give the claim up, awaited, without recording.
    async fn release(mut self) {
        if let Err(e) = self.marker.release(self.stamp).await {
            tracing::warn!(
                error = %e,
                id = %self.marker.id(),
                "could not release a pending-record marker; it lapses with its lease"
            );
        }
        self.held = false;
    }
}

impl<C: Connection> Drop for RecordClaim<C> {
    fn drop(&mut self) {
        if !self.held {
            return;
        }
        let (marker, stamp) = (self.marker.clone(), self.stamp);
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if let Err(e) = marker.release(stamp).await {
                        tracing::warn!(
                            error = %e,
                            id = %marker.id(),
                            "could not release the pending-record marker of a unit that was cut; \
                             it lapses with its lease"
                        );
                    }
                });
            }
            Err(_) => tracing::warn!(
                id = %self.marker.id(),
                "the pending-record marker of a unit cut outside a runtime lapses with its lease"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Units of work that end in an audit row (#655, #624)
// ---------------------------------------------------------------------------

/// Where a unit of [`AuditedWork`] is, for a test that holds it there
/// ([`AuditedWork::with_step_for_tests`]).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitStep {
    /// A tombstoned tenant's purge has removed the tenant's rows and not yet
    /// its tenant row: before the purge's point of no return.
    TenantRowsPurged(Uuid),
    /// An erasure has anonymized the account and written its proof, and has
    /// not yet run its second revocation, completed its `account_deletion` row
    /// or written `gdpr.user_pseudonymized`: past the erasure's point of no
    /// return.
    ErasureAnonymized(Uuid),
    /// An erasure has anonymized the account — its point of no return — and
    /// not yet written its erasure proof (#737): what the next sweep writes for
    /// a unit cut here, with the second revocation and the record.
    ErasureProofOwed(Uuid),
    /// An erasure has finished steps (a)…(b4) and not yet started the erasure
    /// pipeline: the window in which a certificate bound to the account can
    /// still be issued after (b4) revoked.
    ErasurePrepared(Uuid),
    /// An orphan purge has written its claim marker and not yet started on the
    /// rows: where a cut used to find the marker with no guard to release it
    /// (#714).
    OrphanClaimed(Uuid),
    /// A tenant purge (tombstoned or orphan) has removed its tenant row — its
    /// point of no return — and written its pending-record marker, and has not
    /// yet written `tenants.purged` (#689).
    TenantRowRemoved(Uuid),
    /// A unit, or a sweep recording for a cut one, has written its record
    /// (`tenants.purged` for the tenant id, `gdpr.user_pseudonymized` for the
    /// user id) and not yet cleared the pending-record marker (#689).
    Recorded(Uuid),
}

/// A step [`AuditedWork::with_step_for_tests`] runs at each [`UnitStep`].
#[doc(hidden)]
pub type UnitStepForTests = Arc<
    dyn Fn(UnitStep) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// The cleanup task's units of work that must end in an audit row (#655,
/// #624): a tombstoned tenant's purge through its `tenants.purged` record, an
/// orphaned tenant id's purge through its record, and one account's erasure
/// through its `account_deletion` completion and its `gdpr.user_pseudonymized`
/// row.
///
/// The cleanup task runs them one at a time, each as a `tokio::spawn`ed task of
/// its own ([`Self::run`]), so aborting the cleanup task — the composition
/// root's bounded join — does not cut one. The root then waits for the unit in
/// flight with [`Self::join`], within the same bound, and aborts it past that,
/// so a replica that lost its lease writes nothing of its own code after its
/// stop's budget (a statement already sent may still commit).
///
/// Each unit has a **point of no return** — the write after which no later
/// sweep finds the work again: the removal of the tenant row; the anonymization
/// of the account. Before it, the unit gives itself up as soon as the process
/// is stopping (the tenant stays tombstoned, its claim released; the account
/// stays due), and it starts no new crossing once the stop is requested (a
/// crossing already being sent completes). So the only unit a stop can find
/// past its point of no return began crossing it before the stop was requested, and it has the whole of the teardown's window for its last
/// statements — from the stop signal through the gRPC stop, the lease release
/// and the outbound and audit drains to the end of the cleanup bound: 5 to 18 s
/// for `SIGTERM`, 2 to 13 s after a lost lease, whose stop signal comes at the
/// loss (#628). One that outlasts even that is cut; the marker its point of
/// no return left in the same transaction (#689) makes the next start's sweep
/// write the record it owed, once ([`record_owed_erasures`],
/// [`record_pending_purges`]; T-444).
#[derive(Clone)]
pub struct AuditedWork {
    stop: watch::Receiver<bool>,
    in_flight: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    step_for_tests: Option<UnitStepForTests>,
}

impl AuditedWork {
    /// Units that give themselves up when `stop` reads `true` — the cleanup
    /// task's shutdown signal. A `stop` whose sender is gone while it reads
    /// `false` never stops anything.
    #[must_use]
    pub fn new(stop: watch::Receiver<bool>) -> Self {
        Self {
            stop,
            in_flight: Arc::default(),
            step_for_tests: None,
        }
    }

    /// **Test seam, never set in production** (#655, #624): run `step` at each
    /// [`UnitStep`], so a test can hold a unit there across a stop.
    #[doc(hidden)]
    #[must_use]
    pub fn with_step_for_tests(mut self, step: Option<UnitStepForTests>) -> Self {
        self.step_for_tests = step;
        self
    }

    /// Whether the process has asked the cleanup task to stop.
    #[must_use]
    pub fn stopping(&self) -> bool {
        *self.stop.borrow()
    }

    /// Resolves once the process is stopping; never, when it cannot be.
    async fn stopped(&self) {
        let mut stop = self.stop.clone();
        if stop.wait_for(|stopping| *stopping).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// `work`'s output, or `None` when the process is stopping first: `work`
    /// is then dropped where it is. For the steps before a unit's point of no
    /// return only.
    async fn until_stopped<F: std::future::Future>(&self, work: F) -> Option<F::Output> {
        tokio::select! {
            biased;
            output = work => Some(output),
            () = self.stopped() => None,
        }
    }

    /// The test step at `at`, if one is set.
    async fn step(&self, at: UnitStep) {
        if let Some(step) = &self.step_for_tests {
            step(at).await;
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<tokio::task::JoinHandle<()>>> {
        self.in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Spawn `unit` as a task of its own and wait for its output.
    ///
    /// `None` when the process is stopping — before the unit was started, or
    /// while it runs: it is then left running for [`Self::join`] — or when the
    /// unit panicked (logged here). One unit at a time: the caller awaits this
    /// before it starts the next.
    pub async fn run<T: Send + 'static>(
        &self,
        unit: impl std::future::Future<Output = T> + Send + 'static,
    ) -> Option<T> {
        if self.stopping() {
            return None;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        *self.slot() = Some(tokio::spawn(async move {
            let _ = tx.send(unit.await);
        }));
        tokio::select! {
            biased;
            output = rx => {
                let handle = self.slot().take();
                match output {
                    Ok(output) => Some(output),
                    Err(_) => {
                        if let Some(handle) = handle
                            && let Err(e) = handle.await
                        {
                            tracing::error!(error = %e, "a cleanup unit ended without an outcome");
                        }
                        None
                    }
                }
            }
            // Left to the teardown, which waits for it.
            () = self.stopped() => None,
        }
    }

    /// Wait until `deadline` for the unit in flight, if any; past it, abort the
    /// unit — it is cut where it is — and say so with `false`. The composition
    /// root calls this once the cleanup task itself has ended or been aborted
    /// (#655, #624).
    pub async fn join(&self, deadline: tokio::time::Instant) -> bool {
        let Some(mut handle) = self.slot().take() else {
            return true;
        };
        match tokio::time::timeout_at(deadline, &mut handle).await {
            Ok(Ok(())) => true,
            Ok(Err(e)) => {
                tracing::error!(error = %e, "a cleanup unit ended without an outcome");
                true
            }
            Err(_) => {
                handle.abort();
                // Once this returns the unit has been dropped: it writes
                // nothing more, and its claim guard has run.
                let _ = handle.await;
                false
            }
        }
    }
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

/// The `certificate_retention` job (R101W1-05, #618): delete certificate rows
/// of live tenants more than eight days past their `notAfter`, in bounded
/// batches, and return how many.
///
/// A revoked row is kept for as long as its issuer's revocation list can name
/// it (the tenant purge's `KEPT_REVOCATION`, whose grace this sweep shares);
/// past it the CRL is the same without the row. Nothing deleted a certificate
/// row in a live tenant before, so a revoked one — and the PEM, subject and
/// `metadata` in it, of an account the Art. 17 purge had erased — outlived any
/// purpose for the tenant's lifetime. A deleted tenant's rows are the tenant
/// purge's, not this sweep's. Two replicas may run it at once: each batch is
/// chosen and deleted by id, and a row the other replica removed first is not
/// counted. Touches no audit row.
///
/// Runs at most [`CERTIFICATE_RETENTION_MAX_BATCHES`] batches of
/// [`CERTIFICATE_RETENTION_BATCH`] rows, and stops between batches on a
/// shutdown signal; the next tick continues. A free function, and public, for
/// the reason [`run_erasure_pipeline`] is.
///
/// # Errors
///
/// The repository's error from the batch that failed; batches already deleted
/// stay deleted.
pub async fn sweep_certificate_retention<CR>(
    cert_repo: &CR,
    shutdown: &watch::Receiver<bool>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::CertificateRepository,
{
    let mut removed = 0_u64;
    for _ in 0..CERTIFICATE_RETENTION_MAX_BATCHES {
        if *shutdown.borrow() {
            break;
        }
        let batch = cert_repo
            .delete_past_retention(CERTIFICATE_RETENTION_BATCH)
            .await?;
        removed += batch;
        if batch < u64::from(CERTIFICATE_RETENTION_BATCH) {
            break;
        }
    }
    Ok(removed)
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
pub async fn sweep_unused_dcr_clients<CR, TR, SR, RT, AC, PR, DG, CB>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    grants: &ClientGrantStores<RT, AC, PR, DG, CB>,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
    RT: axiam_core::repository::RefreshTokenRepository,
    AC: axiam_core::repository::AuthorizationCodeRepository,
    PR: axiam_core::repository::PushedAuthRequestRepository,
    DG: axiam_core::repository::DeviceGrantRepository,
    CB: axiam_core::repository::CibaRequestRepository,
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
pub async fn sweep_unused_cimd_clients<CR, TR, SR, RT, AC, PR, DG, CB>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    grants: &ClientGrantStores<RT, AC, PR, DG, CB>,
    now: chrono::DateTime<Utc>,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::OAuth2ClientRepository,
    TR: TenantRepository,
    SR: axiam_core::repository::SettingsRepository,
    RT: axiam_core::repository::RefreshTokenRepository,
    AC: axiam_core::repository::AuthorizationCodeRepository,
    PR: axiam_core::repository::PushedAuthRequestRepository,
    DG: axiam_core::repository::DeviceGrantRepository,
    CB: axiam_core::repository::CibaRequestRepository,
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
pub async fn sweep_unused_external_clients<CR, TR, SR, RT, AC, PR, DG, CB>(
    client_repo: &CR,
    tenant_repo: &TR,
    settings_repo: &SR,
    grants: &ClientGrantStores<RT, AC, PR, DG, CB>,
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
    DG: axiam_core::repository::DeviceGrantRepository,
    CB: axiam_core::repository::CibaRequestRepository,
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

/// Revoke the still-active `User` certificates of an account the Art. 17 purge
/// is erasing, and clear the free-form `metadata` of all its `User`
/// certificates, returning how many were revoked (#533, R101W1-05) — the
/// purge's step (b4).
///
/// Revoked, not deleted: each row carries `revoked_at`, so it stays on its
/// issuer's revocation list until it expires, and a `vault_pki` issuer's list
/// in Vault gets it from the cleanup job's `vault_revocation` sweep. Deleting
/// the row would make the certificate valid again to every relying party
/// outside AXIAM — the retention `docs/compliance/gdpr-compliance.md` records
/// for a deleted tenant's certificates, here for one account's.
///
/// What the list does not need is cleared, as the tenant purge clears it:
/// `metadata` is set to `{}` on every row that is the account's, in any status
/// (R101W1-05). What stays is the PEM, `subject`, `fingerprint`, the dates and
/// `user_id`; the first three are what the list is computed from and what a
/// relying party matches an entry against, and `user_id` is an internal random
/// id of an account that is anonymized in place by the next step, so it names
/// nobody once this purge has run — and it is the key a retried purge finds
/// the rows by. The rows go when a certificate retention sweep
/// ([`CleanupTask`]'s `certificate_retention`) finds them more than eight days
/// past `notAfter`.
///
/// Matches the binding (`certificate.user_id`, schema v98) and, for a row
/// without one, the older convention on the account's username and email —
/// limited to certificates created since the account was and to names no other
/// account of the tenant holds (R101W1-01), so a holder erasing their own
/// account cannot revoke a namesake's certificate — so it must run **before** `anonymize_user` overwrites them, which the purge
/// does by calling it ahead of [`run_erasure_pipeline_reporting`]. The
/// revocation comes first and the clearing second: `metadata.user_id` is one of
/// the things the convention reads. Fatal there (`?`), like the credential
/// deletions beside it: the account stays due and the next sweep retries, with
/// its names in place; both writes are idempotent.
///
/// A free function, and public, for the reason [`run_erasure_pipeline`] is.
pub async fn revoke_erased_users_certificates<CR>(
    cert_repo: &CR,
    user: &axiam_core::models::user::User,
) -> Result<u64, AxiamError>
where
    CR: axiam_core::repository::CertificateRepository,
{
    let revoked = cert_repo
        .revoke_user_certificates(
            user.tenant_id,
            user.id,
            &user.username,
            &user.email,
            user.created_at,
        )
        .await?;
    cert_repo
        .clear_user_certificates_metadata(
            user.tenant_id,
            user.id,
            &user.username,
            &user.email,
            user.created_at,
        )
        .await?;
    Ok(revoked)
}

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
///
/// [`erase_and_record`] runs the same three steps in the same order, with its
/// record marker guarded from a stamp it chose (#737).
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
    write_erasure_proof(
        erasure_proof_repo,
        tenant_id,
        user_id,
        pseudonym,
        Utc::now(),
    )
    .await
}

/// The PII-free erasure proof (D-06) of an account the erasure has anonymized.
/// A second one for the account is refused by the proof's unique index on
/// `(tenant_id, user_id)` as `AlreadyExists` ([`ERASURE_PROOF_ENTITY`]).
async fn write_erasure_proof<EP: ErasureProofRepository>(
    erasure_proof_repo: &EP,
    tenant_id: Uuid,
    user_id: Uuid,
    pseudonym: &str,
    erased_at: chrono::DateTime<Utc>,
) -> Result<(), AxiamError> {
    erasure_proof_repo
        .create(CreateErasureProof {
            pseudonym: pseudonym.to_string(),
            tenant_id,
            user_id,
            erased_at,
        })
        .await
        .map(|_proof| ())
}

/// Whether `e` is the proof's unique violation: the account has its proof.
fn is_existing_proof(e: &AxiamError) -> bool {
    matches!(e, AxiamError::AlreadyExists { entity } if entity == ERASURE_PROOF_ENTITY)
}

/// The account as it is before the erasure, for the SSF `account-purged`
/// report: read only when `sink` is attached and active.
async fn account_for_report<'s, U: UserRepository>(
    user_repo: &U,
    sink: Option<&'s dyn SsfSystemAccountSink>,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Option<(&'s dyn SsfSystemAccountSink, axiam_core::models::user::User)> {
    match sink {
        Some(sink) if sink.is_active() => user_repo
            .get_by_id(tenant_id, user_id)
            .await
            .ok()
            .map(|user| (sink, user)),
        _ => None,
    }
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
    let report = account_for_report(user_repo, sink, tenant_id, user_id).await;
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

/// The account an erasure is for, and what [`erase_and_record`] writes about
/// it.
#[derive(Debug, Clone, Copy)]
pub struct ErasureSubject<'a> {
    /// The account's tenant.
    pub tenant_id: Uuid,
    /// The account.
    pub user_id: Uuid,
    /// Its GDPR pseudonym (D-02).
    pub pseudonym: &'a str,
    /// What its address is overwritten with.
    pub email_hash: &'a str,
    /// How many of its certificates the purge revoked (#533), for the audit
    /// row.
    pub certificates_revoked: u64,
}

/// An erasure through its point of no return to its record (#624): the steps of
/// [`run_erasure_pipeline_reporting`] in its order — audit scrub,
/// anonymization, SSF report, proof — then the #668 second revocation, the
/// `gdpr.user_pseudonymized` audit row, and the `account_deletion` row marked
/// completed (#689 (i): the record first). Run inside a unit of
/// [`AuditedWork`], so a cut of the cleanup task does not reach it.
///
/// The anonymization is the point of no return: it clears `deletion_pending`,
/// so no later sweep selects the account again, and in the same transaction
/// sets the account's record marker (#689) to a stamp this call chose (#737).
/// The marker's guard is armed from that stamp **before** the write — the
/// orphan unit's pattern since #714 — so the marker is guarded from the
/// instant it exists: cleared with the completion once the audit row is
/// written, and released on every other exit, awaited where it can be and by
/// the guard's drop on a cut, so the next sweep ([`record_owed_erasures`])
/// writes at once what the erasure still owes: the proof, the second
/// revocation and the record. A release whose anonymization never landed
/// changes nothing, since it is conditional on the stamp. Until the
/// anonymization — the audit scrub — the call gives up once `work` is stopping
/// and answers `Ok(false)`: the account stays due. Past it, it runs on to the
/// audit row whatever the stop says, and answers `Ok(true)`. A free function,
/// and public, for the reason [`run_erasure_pipeline`] is one.
///
/// `Ok(false)` too, with nothing written, when another unit erased the account
/// after taking this one's claim over past its lease (#738, #784): the account
/// is read again before the scrub and left alone once it is no longer
/// deletion-pending, and the anonymization writes only a deletion-pending
/// account, so a unit that stalls after that read stops at the anonymization,
/// before the SSF report — its scrub having passed over the other unit's
/// record, which the scrub never touches. And `Ok(false)` when the erasure
/// proof turns out to exist already: the next sweep wrote it for this unit,
/// stalled past the record lease after its anonymization; this call records
/// nothing, and releases its marker, which that sweep settles.
///
/// # Errors
///
/// Those of the account's read, the scrub and the anonymization, before
/// anything is recorded; and a proof that failed to write, past the point of
/// no return, with the marker released so that the next sweep writes the
/// proof and the record. The completion and the audit row are not fallible
/// here: a failed completion is logged, and a failed audit write is
/// dead-lettered (SECHRD-12).
pub async fn erase_and_record<A, EP, U, CR, C>(
    audit_repo: &A,
    erasure_proof_repo: &EP,
    user_repo: &U,
    cert_repo: &CR,
    account_deletion_repo: &SurrealAccountDeletionRepository<C>,
    sink: Option<&dyn SsfSystemAccountSink>,
    subject: ErasureSubject<'_>,
    work: &AuditedWork,
) -> Result<bool, AxiamError>
where
    A: AuditLogRepository + AuditWriteSink,
    EP: ErasureProofRepository,
    U: UserRepository,
    CR: axiam_core::repository::CertificateRepository,
    C: Connection,
{
    let ErasureSubject {
        tenant_id,
        user_id,
        pseudonym,
        email_hash,
        certificates_revoked,
    } = subject;
    work.step(UnitStep::ErasurePrepared(user_id)).await;
    // #784: the account is read again right before the scrub, and an account
    // no longer deletion-pending is left alone — another unit erased it after
    // taking this unit's claim over, past its lease, or its deletion is done.
    // Its trail holds that unit's record, which the scrub would otherwise run
    // over. A read, so a unit that stalls between it and the scrub still gets
    // there: the scrub then leaves the record alone, and the anonymization
    // below matches nothing.
    let account = user_repo.get_by_id(tenant_id, user_id).await?;
    if !account.deletion_pending {
        tracing::info!(
            %tenant_id,
            %user_id,
            "cleanup: the account is no longer deletion-pending; another unit erased it"
        );
        return Ok(false);
    }
    // G-5 (D-52): the account as it is, read before anything is written — the
    // erasure replaces the address the report's subject is resolved from.
    let report = sink
        .filter(|sink| sink.is_active())
        .map(|sink| (sink, account));

    // (d) Pseudonymize the audit actor references: FATAL (SECHRD-06 / D-03a,
    // T-25-13) — no PII-bearing step is ever silently skipped. Idempotent and
    // before the point of no return, so it is given up where it is once the
    // process is stopping; the account stays due.
    match work
        .until_stopped(audit_repo.pseudonymize_actor(tenant_id, user_id, pseudonym))
        .await
    {
        Some(scrubbed) => {
            scrubbed?;
        }
        None => return Ok(false),
    }
    // #624: the anonymization is never started once the process is stopping.
    if work.stopping() {
        return Ok(false);
    }

    // #737: the marker's stamp is chosen here and its guard armed from it
    // before the anonymization writes it, not read back afterwards, so a cut
    // at any point from the write on releases the marker.
    let stamp = Utc::now();
    let record = RecordClaim {
        marker: PendingMarker::Erasure {
            deletions: account_deletion_repo.clone(),
            tenant_id,
            user_id,
        },
        stamp,
        held: true,
    };
    // (e) Anonymize the user row in place: the point of no return. It is the
    // only step that clears `deletion_pending`, so a failure here leaves the
    // account due for a retry. #784: it writes only a deletion-pending
    // account, so of a stalled unit and its successor one anonymizes, and
    // the other stops here, before the SSF report, with no marker of its own.
    match user_repo
        .anonymize_user_marked(tenant_id, user_id, email_hash, pseudonym, stamp)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(
                %tenant_id,
                %user_id,
                "cleanup: the account was erased by another unit before this one's anonymization"
            );
            // Nothing carries this unit's stamp; the release matches nothing.
            record.release().await;
            return Ok(false);
        }
        Err(e) => {
            // The transaction may have committed before the error reached us:
            // release a marker stamped with ours, if there is one, so the next
            // sweep finishes the erasure at once. Nothing matches otherwise.
            record.release().await;
            return Err(e);
        }
    }

    // G-5 (D-52): the account is gone; tell the receivers what it was.
    if let Some((sink, user)) = report {
        sink.account_purged(tenant_id, &user).await;
    }
    work.step(UnitStep::ErasureProofOwed(user_id)).await;

    // (g) The erasure proof, once every PII-bearing step above has succeeded:
    // a proof never certifies an erasure that did not fully happen (Pitfall 3).
    match write_erasure_proof(
        erasure_proof_repo,
        tenant_id,
        user_id,
        pseudonym,
        Utc::now(),
    )
    .await
    {
        Ok(()) => {}
        // #738: the proof is unique per account, and only this unit's
        // anonymization (#784: the only one) or the recovery of it writes one,
        // so a proof already there means this unit stalled past the record
        // lease and the next sweep wrote the proof for it. That sweep records
        // the erasure; this unit has nothing left to do and is not a failure
        // of the tick. Its marker, released, is settled with the record.
        Err(e) if is_existing_proof(&e) => {
            tracing::info!(
                %tenant_id,
                %user_id,
                "cleanup: the account's erasure proof exists already; a sweep recovered the erasure"
            );
            record.release().await;
            return Ok(false);
        }
        // Past the point of no return: the released marker makes the next
        // sweep write the proof and the record (#737).
        Err(e) => {
            record.release().await;
            return Err(e);
        }
    }
    work.step(UnitStep::ErasureAnonymized(user_id)).await;

    // (#668) A second revocation, by binding only, outside the pinned pipeline
    // order: a certificate issued for the account between (b4) and the
    // anonymization is still active. The account's names are gone by now, so
    // empty names leave only the `user_id` binding (and `metadata.user_id`) to
    // match. Best effort and idempotent: past the point of no return a failure
    // is logged and never un-records the erasure.
    match cert_repo
        .revoke_user_certificates(tenant_id, user_id, "", "", Utc::now())
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(
            %tenant_id,
            %user_id,
            revoked = n,
            "cleanup: revoked certificates issued for the erased account after its first revocation"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            %tenant_id,
            %user_id,
            "cleanup: second certificate revocation after anonymization failed"
        ),
    }

    // (h) Emit gdpr.user_pseudonymized audit event. actor_id is the
    // erased subject's own (now-anonymized) row id — a real, resolvable
    // identifier rather than a fabricated nil UUID (Task 1 fix); the row
    // still exists (anonymize-in-place preserves referential integrity),
    // so this is a legitimate audit-trail reference, not PII leakage.
    // A DB-write failure here is dead-lettered to BOTH an append-only
    // file AND a structured audit event (SECHRD-12 / D-02, T-24-61) —
    // this legally-significant record must never be silently lost.
    //
    // #689 (i): written BEFORE the request's completion. The completion
    // used to come first, so a cut between the two left a completed request
    // and no record; now a cut leaves the request pending with the account
    // anonymized, which the next sweep completes and records.
    write_audit_with_dead_letter(
        audit_repo,
        CreateAuditLogEntry {
            tenant_id,
            actor_id: user_id,
            actor_type: ActorType::System,
            action: USER_PSEUDONYMIZED_ACTION.into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "pseudonym": pseudonym,
                // #533: the account's certificates this purge revoked; a
                // count, as directory linking records its own.
                "certificates_revoked": certificates_revoked,
            })),
        },
    )
    .await;
    work.step(UnitStep::Recorded(user_id)).await;

    // (f) Complete the account_deletion row, and clear the record marker,
    // in one transaction (#689). A marker another unit has taken over — this
    // one held past the lease — is left to it; it finds the record written.
    record.settle().await;

    tracing::info!(
        pseudonym = %pseudonym,
        tenant_id = %tenant_id,
        "user purged and pseudonymized"
    );
    Ok(true)
}

/// The audit action that records an erasure.
const USER_PSEUDONYMIZED_ACTION: &str = "gdpr.user_pseudonymized";

/// The entity a duplicate erasure proof is refused as
/// (`AxiamError::AlreadyExists`, from the proof's unique index).
const ERASURE_PROOF_ENTITY: &str = "erasure_proof";

/// Finish the erasures whose record is still owed — a unit cut between the
/// anonymization and the clearing of its marker (#689) — and settle each: the
/// first step of every GDPR purge sweep; none starts once the process is
/// stopping.
///
/// [`SurrealAccountDeletionRepository::claim_owed_erasure_records`] claims
/// each owed erasure, conditionally on the marker read: a marker released by a
/// cut unit or older than `lease`, and (#689 (i)) an anonymized account whose
/// deletion request is still pending with no marker at all — an erasure cut
/// before schema v108 between its anonymization and its completion. For each,
/// it redoes the part of the erasure's tail the unit may not have reached
/// (#737), in the unit's order:
///
/// 1. the erasure proof, unless the account has one: the proof's unique index
///    refuses a second, which reads as "written already" — the unit's own, or
///    a racing sweep's. It carries the pseudonym on the row and is dated from
///    the marker the claim read, or now when the marker was released or unset;
/// 2. the #668 second revocation, by binding only (empty names), which is
///    idempotent: a certificate bound to the account between the unit's (b4)
///    and its anonymization is revoked even when the unit was cut before its
///    own pass;
/// 3. the `gdpr.user_pseudonymized` row, unless the tenant's trail already
///    holds one for the account (a unit cut after its record and before the
///    clearing), matched by its actor or by its pseudonym — before 1.1.2
///    (#784) a unit that stalled past its claim's lease ran its audit scrub
///    over the row another unit wrote and nilled its actor, which the scrub
///    no longer does: an account is erased once, so that row is this
///    erasure's. It
///    carries the pseudonym the anonymization wrote, `certificates_revoked` as
///    `null` — the unit's count lived only in the cut unit, and the second
///    pass's alone would understate it — and `recovered: true`.
///
/// Then the marker is cleared and the request completed, in one transaction.
/// The claim is held by the same guard the unit holds. A failure of step 1 or
/// 2 releases the claim, so the next sweep retries the account whole: no
/// request is completed without its proof, nor before the second revocation
/// ran.
///
/// `Ok(n)` is the number of records this call wrote.
///
/// # Errors
///
/// The datastore error that kept the owed erasures from being read or
/// claimed, or [`AxiamError::Internal`] naming how many could not be finished
/// (each of those is released for the next sweep).
pub async fn record_owed_erasures<A, EP, CR, C>(
    audit_repo: &A,
    erasure_proof_repo: &EP,
    cert_repo: &CR,
    account_deletion_repo: &SurrealAccountDeletionRepository<C>,
    lease: chrono::TimeDelta,
    work: &AuditedWork,
) -> Result<u64, AxiamError>
where
    A: AuditWriteSink,
    EP: ErasureProofRepository,
    CR: axiam_core::repository::CertificateRepository,
    C: Connection,
{
    if work.stopping() {
        return Ok(0);
    }
    let owed = account_deletion_repo
        .claim_owed_erasure_records(Utc::now(), lease)
        .await?;
    let (mut recorded, mut failed) = (0u64, 0u64);
    for erasure in owed {
        let (tenant_id, user_id) = (erasure.tenant_id, erasure.user_id);
        let claim = RecordClaim {
            marker: PendingMarker::Erasure {
                deletions: account_deletion_repo.clone(),
                tenant_id,
                user_id,
            },
            stamp: erasure.claimed_at,
            held: true,
        };
        if work.stopping() {
            claim.release().await;
            continue;
        }
        if let Err(e) = finish_owed_erasure(erasure_proof_repo, cert_repo, &erasure).await {
            failed += 1;
            tracing::warn!(
                error = %e,
                %tenant_id,
                %user_id,
                "could not finish an owed erasure; the next sweep retries it"
            );
            claim.release().await;
            continue;
        }
        match account_deletion_repo
            .erasure_recorded(
                tenant_id,
                user_id,
                &erasure.pseudonym,
                USER_PSEUDONYMIZED_ACTION,
            )
            .await
        {
            Ok(true) => {}
            Ok(false) => {
                write_audit_with_dead_letter(
                    audit_repo,
                    CreateAuditLogEntry {
                        tenant_id,
                        actor_id: user_id,
                        actor_type: ActorType::System,
                        action: USER_PSEUDONYMIZED_ACTION.into(),
                        resource_id: None,
                        outcome: AuditOutcome::Success,
                        ip_address: None,
                        metadata: Some(serde_json::json!({
                            "pseudonym": erasure.pseudonym,
                            "certificates_revoked": null,
                            "recovered": true,
                        })),
                    },
                )
                .await;
                recorded += 1;
                tracing::warn!(
                    %tenant_id,
                    %user_id,
                    "recorded an erasure whose unit was cut before its record (#689)"
                );
                work.step(UnitStep::Recorded(user_id)).await;
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    error = %e,
                    %tenant_id,
                    %user_id,
                    "could not check an owed erasure record; the next sweep retries it"
                );
                claim.release().await;
                continue;
            }
        }
        claim.settle().await;
    }
    if failed > 0 {
        return Err(AxiamError::Internal(format!(
            "{failed} owed erasure record(s) could not be finished"
        )));
    }
    Ok(recorded)
}

/// Steps 1 and 2 of [`record_owed_erasures`] for one claimed erasure (#737):
/// its proof unless it has one, then the second revocation.
async fn finish_owed_erasure<EP, CR>(
    erasure_proof_repo: &EP,
    cert_repo: &CR,
    erasure: &axiam_db::repository::OwedErasureRecord,
) -> Result<(), AxiamError>
where
    EP: ErasureProofRepository,
    CR: axiam_core::repository::CertificateRepository,
{
    let (tenant_id, user_id) = (erasure.tenant_id, erasure.user_id);
    match write_erasure_proof(
        erasure_proof_repo,
        tenant_id,
        user_id,
        &erasure.pseudonym,
        erasure.marked_at.unwrap_or_else(Utc::now),
    )
    .await
    {
        Ok(()) => tracing::warn!(
            %tenant_id,
            %user_id,
            "wrote the erasure proof of an erasure cut before it (#737)"
        ),
        Err(e) if is_existing_proof(&e) => {}
        Err(e) => return Err(e),
    }
    let revoked = cert_repo
        .revoke_user_certificates(tenant_id, user_id, "", "", Utc::now())
        .await?;
    if revoked > 0 {
        tracing::warn!(
            %tenant_id,
            %user_id,
            revoked,
            "revoked certificates bound to an erased account whose unit was cut (#737)"
        );
    }
    Ok(())
}

/// One due account's erasure under an exclusive claim (#738): claim it at the
/// claimant's own `now`, run `erasure` — the unit's steps from the first
/// destructive one to the record — and release the claim unless the account
/// was erased.
///
/// `Ok(false)`, with nothing run, when the account is no longer due (its
/// deletion was cancelled since the sweep's read, or another unit erased it)
/// or another unit holds a claim on it younger than `lease`: two sweeps that
/// read one due account erase it once, and the one that skips it reports no
/// error. Otherwise the outcome is `erasure`'s. The claim is released, awaited,
/// on every outcome but `Ok(true)`, and by its guard's drop if this future is
/// dropped — a unit cut at the teardown's bound, or a panic — so the next sweep
/// takes the account at once; the release changes nothing once the
/// anonymization has run.
///
/// A free function, and public, for the reason [`run_erasure_pipeline`] is:
/// `axiam-server`'s integration tests run two sweeps' units against one store.
///
/// # Errors
///
/// A datastore failure of the claim (nothing ran), or `erasure`'s.
pub async fn purge_under_claim<C, F>(
    deletions: &SurrealAccountDeletionRepository<C>,
    tenant_id: Uuid,
    user_id: Uuid,
    sweep_now: chrono::DateTime<Utc>,
    lease: chrono::TimeDelta,
    erasure: F,
) -> Result<bool, AxiamError>
where
    C: Connection,
    F: std::future::Future<Output = Result<bool, AxiamError>>,
{
    // The claimant's `now`, not the sweep's: the stamp starts the lease, and a
    // sweep that reaches its last account long after it read them must not
    // stamp a claim that is already old. Never earlier than the sweep's, so an
    // account due at the sweep's read is due here too.
    let stamp = Utc::now().max(sweep_now);
    match deletions
        .claim_for_purge(tenant_id, user_id, stamp, lease)
        .await?
    {
        PurgeClaimOutcome::Claimed => {}
        PurgeClaimOutcome::NotDue => {
            tracing::info!(
                %user_id,
                %tenant_id,
                "purge skipped: the account is no longer due (its deletion was cancelled, or \
                 another unit erased it)"
            );
            return Ok(false);
        }
        PurgeClaimOutcome::Held => {
            tracing::info!(
                %user_id,
                %tenant_id,
                "purge skipped: another unit holds the account's erasure"
            );
            return Ok(false);
        }
    }
    let claim = ErasureClaim {
        deletions: deletions.clone(),
        tenant_id,
        user_id,
        stamp,
        held: true,
    };
    let erased = erasure.await;
    match erased {
        Ok(true) => claim.settle(),
        _ => claim.release().await,
    }
    erased
}

/// What one account's purge needs, owned, so that it runs as a unit of
/// [`AuditedWork`] — a task of its own (#624).
struct ErasureUnit<C: Connection> {
    auth_svc: Arc<AuthSvc<C>>,
    federation_link_repo: Arc<SurrealFederationLinkRepository<C>>,
    webauthn_repo: Arc<SurrealWebauthnCredentialRepository<C>>,
    password_history_repo: Arc<SurrealPasswordHistoryRepository<C>>,
    group_repo: Arc<SurrealGroupRepository<C>>,
    role_repo: Arc<SurrealRoleRepository<C>>,
    permission_repo: Arc<axiam_db::SurrealPermissionRepository<C>>,
    cert_repo: Arc<axiam_db::SurrealCertificateRepository<C>>,
    audit_repo: Arc<SurrealAuditLogRepository<C>>,
    erasure_proof_repo: Arc<SurrealErasureProofRepository<C>>,
    user_repo: Arc<SurrealUserRepository<C>>,
    account_deletion_repo: Arc<SurrealAccountDeletionRepository<C>>,
    refresh_token_repo: Arc<axiam_db::SurrealRefreshTokenRepository<C>>,
    ssf_sink: Option<Arc<dyn SsfSystemAccountSink>>,
    subject_flush: Option<SubjectFlush>,
}

impl<C: Connection> ErasureUnit<C> {
    /// The purge of `user` (steps listed at `CleanupTask::sweep_pending_purges`),
    /// under an exclusive claim ([`purge_under_claim`], #738): `Ok(true)` once
    /// erased and recorded, `Ok(false)` when given up at the stop before the
    /// point of no return — the account stays due — when the account is no
    /// longer due at the claim (its deletion was cancelled) or another unit
    /// holds it, or when another unit turned out to have erased it.
    async fn purge(
        self,
        user: axiam_core::models::user::User,
        pepper: [u8; 32],
        now: chrono::DateTime<Utc>,
        work: AuditedWork,
    ) -> Result<bool, AxiamError> {
        // Item 11 of the 1.1.0 atomicity audit: the erasure is claimed before
        // its first destructive step, in a transaction that re-checks the
        // account is still due. A deletion cancelled since the sweep's read is
        // skipped there, before anything is revoked; once claimed, a cancel is
        // refused (`409`), so the subject is never told "cancelled" for an
        // account this purge goes on to erase. #738: the claim is exclusive,
        // for `ERASURE_CLAIM_LEASE`, so another replica's sweep that read the
        // same account skips it.
        let lease = chrono::TimeDelta::from_std(ERASURE_CLAIM_LEASE)
            .map_err(|e| AxiamError::Internal(format!("erasure claim lease: {e}")))?;
        let deletions = Arc::clone(&self.account_deletion_repo);
        let (tenant_id, user_id) = (user.tenant_id, user.id);
        purge_under_claim(
            deletions.as_ref(),
            tenant_id,
            user_id,
            now,
            lease,
            self.erase(user, pepper, work),
        )
        .await
    }

    /// The purge of a claimed account: steps (a)…(h), as
    /// [`Self::purge`] lists them.
    async fn erase(
        self,
        user: axiam_core::models::user::User,
        pepper: [u8; 32],
        work: AuditedWork,
    ) -> Result<bool, AxiamError> {
        // Steps (a)…(b4) are idempotent and leave the account due: given up
        // where they are once the process is stopping.
        let Some(certificates_revoked) = work.until_stopped(self.prepare(&user)).await else {
            return Ok(false);
        };
        let certificates_revoked = certificates_revoked?;
        if work.stopping() {
            return Ok(false);
        }

        let (user_id, tenant_id) = (user.id, user.tenant_id);
        // (c) Compute deterministic pseudonym (keyed HMAC-SHA256, D-02).
        let pseudonym = gdpr_pseudonym(&pepper, tenant_id, user_id);

        // Derive email hash for anonymize_user from tenant+user IDs (original email
        // is no longer accessible at purge time — user already marked deletion_pending).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tenant_id.as_bytes());
        h.update(user_id.as_bytes());
        let email_hash = hex::encode(h.finalize());

        // The anonymization inside is the point of no return; it is never
        // started once the process is stopping (#624).
        erase_and_record(
            self.audit_repo.as_ref(),
            self.erasure_proof_repo.as_ref(),
            self.user_repo.as_ref(),
            self.cert_repo.as_ref(),
            self.account_deletion_repo.as_ref(),
            self.ssf_sink.as_deref(),
            ErasureSubject {
                tenant_id,
                user_id,
                pseudonym: &pseudonym,
                email_hash: &email_hash,
                certificates_revoked,
            },
            &work,
        )
        .await
    }

    /// Steps (a)…(b4): sessions, federation links, credentials, the
    /// authorization graph and the account's certificates. Returns how many
    /// certificates were revoked.
    async fn prepare(&self, user: &axiam_core::models::user::User) -> Result<u64, AxiamError> {
        let (user_id, tenant_id) = (user.id, user.tenant_id);
        // (a) Revoke all sessions and OAuth2 refresh tokens, then delete the
        // refresh-token rows (#753): they name the user, the client and the
        // device key. Both are idempotent, so a re-entered erasure is safe.
        self.auth_svc
            .revoke_all_sessions(tenant_id, user_id)
            .await?;
        erase_oauth2_refresh_tokens(self.refresh_token_repo.as_ref(), tenant_id, user_id).await?;

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
        remove_erased_users_roles(
            self.role_repo.as_ref(),
            self.permission_repo.as_ref(),
            self.audit_repo.as_ref(),
            self.subject_flush.as_ref(),
            tenant_id,
            user_id,
        )
        .await?;

        // (b4) Revoke the account's `User` certificates (#533) and clear their
        // `metadata` (R101W1-05), while its username and email — which the
        // convention for a certificate issued without a `user_id` reads — are
        // still on the row. Fail-closed, like the steps above; idempotent (an
        // already revoked row is not matched, a cleared one is not rewritten).
        revoke_erased_users_certificates(self.cert_repo.as_ref(), user).await
    }
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
        permission_repo: Arc<axiam_db::SurrealPermissionRepository<C>>,
        group_repo: Arc<SurrealGroupRepository<C>>,
        webauthn_repo: Arc<SurrealWebauthnCredentialRepository<C>>,
        password_history_repo: Arc<SurrealPasswordHistoryRepository<C>>,
        // #533 — required, not a builder step, for the reason
        // `audit_retention` is: an erasure that silently skipped the account's
        // certificates is the omission this exists to make impossible.
        cert_repo: Arc<axiam_db::SurrealCertificateRepository<C>>,
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
        // #753: required, not a builder step — an absent repository would
        // silently skip the erasure's deletion.
        refresh_token_repo: Arc<axiam_db::SurrealRefreshTokenRepository<C>>,
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
            permission_repo,
            group_repo,
            webauthn_repo,
            password_history_repo,
            cert_repo,
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
            refresh_token_repo,
            job_health,
            directory_sync: None,
            ssf_buffer_repo: None,
            ssf_step_up_repo: None,
            ssf_sink: None,
            subject_flush: None,
            scim_reconciliation: None,
            ciba_request_repo: None,
            rate_limit_bucket_repo: None,
            vault_revocations: None,
            last_orphan_scan: None,
            step_for_tests: None,
            audited: AuditedWork::new(shutdown.clone()),
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

    /// Sweep the shared rate-limit table (#638), as the `rate_limit_bucket`
    /// job: see [`sweep_rate_limit_buckets`].
    ///
    /// A builder step for the reason [`Self::with_ssf`] is one.
    #[must_use]
    pub fn with_rate_limit_buckets(
        mut self,
        repo: Arc<axiam_db::SurrealRateLimitBucketRepository<C>>,
    ) -> Self {
        self.rate_limit_bucket_repo = Some(repo);
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

    /// Flush an erased account's cached authorization decisions after the
    /// erasure's role pass (D7, #802). A builder step for the reason
    /// [`Self::with_directory_sync`] is one: the absence has a meaning (no
    /// decision cache, nothing to flush).
    #[must_use]
    pub fn with_subject_flush(mut self, flush: SubjectFlush) -> Self {
        self.subject_flush = Some(flush);
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

    /// **Test seam, never set in production** (#598): run `step` first in each
    /// tick — a sweep a test controls, such as one that outlasts the stop's
    /// bound on the cleanup join.
    #[doc(hidden)]
    #[must_use]
    pub fn with_step_for_tests(mut self, step: Option<CleanupStepForTests>) -> Self {
        self.step_for_tests = step;
        self
    }

    /// **Test seam, never set in production** (#655, #624): run `step` at each
    /// [`UnitStep`] of a tenant purge or an erasure.
    #[doc(hidden)]
    #[must_use]
    pub fn with_unit_step_for_tests(mut self, step: Option<UnitStepForTests>) -> Self {
        self.audited = self.audited.with_step_for_tests(step);
        self
    }

    /// The handle the composition root joins the unit in flight through once
    /// the task has stopped ([`AuditedWork::join`]; #655, #624). Take it before
    /// [`Self::run`] consumes the task.
    #[must_use]
    pub fn audited_work(&self) -> AuditedWork {
        self.audited.clone()
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
            // A stop that arrived during a tick ends the loop here, whatever the
            // ticker says: the select below may otherwise pick a tick that is
            // already due over the shutdown change.
            if self.stop_requested() {
                tracing::info!("cleanup task received shutdown signal");
                return Ok(());
            }
            tokio::select! {
                _ = ticker.tick() => {
                    self.tick().await;
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

    /// Whether the process has asked the task to stop (#598).
    fn stop_requested(&self) -> bool {
        *self.shutdown.borrow()
    }

    /// One tick: every sweep, in order.
    ///
    /// A stop request is checked between sweeps (#598): once the process is
    /// stopping no further sweep starts, and the GDPR purge, export and tenant
    /// purge sweeps check it between users, jobs and tenants too (#655). The
    /// sweep that is running when the stop arrives finishes, or is cut where it
    /// is if it outlasts the composition root's bounded join
    /// (`ShutdownBudget::cleanup`); every sweep is re-run by the next tick, so
    /// the next start resumes what a stop left. An erasure or a tenant purge
    /// under way is a unit of [`AuditedWork`] that the cut of this task does not
    /// reach: it gives itself up at the stop before its point of no return, and
    /// after it runs on to its audit row, waited for within the same bound.
    async fn tick(&mut self) {
        if let Some(step) = &self.step_for_tests {
            step().await;
        }
        if self.stop_requested() {
            return;
        }
        // Existing federation cleanup sweeps.
        Self::record(
            &self.job_health,
            "saml_assertion_replay",
            self.replay_repo.cleanup_expired().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
        Self::record(
            &self.job_health,
            "federation_login_state",
            self.state_repo.cleanup_expired().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
        Self::record(
            &self.job_health,
            "sso_handoff_code",
            self.sso_handoff_code_repo.cleanup_expired().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
        // T23.2.3: expired pending SAML AuthnRequests.
        Self::record(
            &self.job_health,
            "saml_authn_request",
            self.saml_pending_repo.cleanup_expired().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
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

        if self.stop_requested() {
            return;
        }
        // NEW-4: sweep expired AMQP replay-protection nonces.
        Self::record(
            &self.job_health,
            "amqp_nonce_replay",
            self.amqp_nonce_repo.cleanup_expired().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
        // GDPR purge sweep (D-01..D-06, D-08).
        Self::record(
            &self.job_health,
            "gdpr_purge",
            self.sweep_pending_purges().await,
            tracing::Level::INFO,
        );

        if self.stop_requested() {
            return;
        }
        // GDPR export sweep (D-10..D-12).
        Self::record(
            &self.job_health,
            "gdpr_export",
            self.sweep_pending_exports().await,
            tracing::Level::INFO,
        );

        if self.stop_requested() {
            return;
        }
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

        if self.stop_requested() {
            return;
        }
        // T-39/T-143: drop revocation entries whose access tokens
        // have all expired. DEBUG, not INFO: unlike the audit
        // sweep this destroys nothing anyone could want back —
        // an expired entry describes only tokens that have
        // expired on their own `exp`.
        // Recorded only when the feed is on, as the directory sync
        // is only when it is configured: `/health/jobs` registers
        // it on the same condition (`job_health::sweep_jobs`).
        if self.revoked_session_repo.is_some() {
            Self::record(
                &self.job_health,
                "revocation_feed",
                self.sweep_revocation_feed().await,
                tracing::Level::DEBUG,
            );
        }

        if self.stop_requested() {
            return;
        }
        // G-5 (T23.5.3, D-48): events held for a poll or paused SSF
        // stream for more than seven days. DEBUG: an expired event
        // is one nobody can still act on.
        Self::record(
            &self.job_health,
            "ssf_event_buffer",
            self.sweep_ssf_event_buffer().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
        // G-5 (T23.5.3, D-53 (1)): step-up records nobody returned
        // for within ten minutes. DEBUG: an expired record is one
        // no return leg may use.
        Self::record(
            &self.job_health,
            "ssf_step_up",
            self.sweep_ssf_step_up().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
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

        if self.stop_requested() {
            return;
        }
        // #638: rate-limit buckets no limiter can still read. DEBUG: a
        // stale bucket is one whose window has long passed.
        Self::record(
            &self.job_health,
            "rate_limit_bucket",
            self.sweep_rate_limit_buckets().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
        // T-470: a `vault_pki` leaf revoked in AXIAM whose
        // revocation Vault does not have yet — a revoke request
        // could not reach it, or the revocation came from a bulk
        // path — and (#612) a revoked tenant signing CA its
        // parent's list in Vault does not name yet. WARN on failure
        // (`record`), since until it runs Vault's list omits a
        // revoked certificate.
        if let Some(certs) = &self.vault_revocations {
            Self::record(
                &self.job_health,
                "vault_revocation",
                certs.forward_pending_revocations().await,
                tracing::Level::INFO,
            );

            // #603: a revocation Vault has refused twelve times
            // (about a day of backoff; a CA's counted with the
            // leaves', #612) is retried every six hours
            // and the pass above no longer fails for it. A distinct
            // job, so a stuck revocation is not hidden by a green
            // `vault_revocation` and a flapping Vault is not
            // mistaken for one.
            Self::record(
                &self.job_health,
                "vault_revocation_failing",
                certs.failing_revocations().await.and_then(|failing| {
                    if failing == 0 {
                        return Ok(0);
                    }
                    Err(AxiamError::Internal(format!(
                        "{failing} certificate revocation(s) Vault has refused {} \
                         times or more; each is retried every {} hours and needs an \
                         operator (see the PKI guide)",
                        axiam_pki::vault_forward::FAILING_AFTER_ATTEMPTS,
                        axiam_pki::vault_forward::BACKOFF_CAP.as_secs() / 3600,
                    )))
                }),
                tracing::Level::INFO,
            );
        }

        if self.stop_requested() {
            return;
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

        if self.stop_requested() {
            return;
        }
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

        if self.stop_requested() {
            return;
        }
        // #523 (D-4) — purge deleted tenants' data, after the GDPR
        // purge so an account erasure due in a tombstoned tenant
        // finishes before its tenant's rows go. INFO, for the audit
        // sweep's reason: it destroys records nothing can rebuild.
        let scan_orphans = self
            .last_orphan_scan
            .is_none_or(|at| at.elapsed() >= ORPHAN_TENANT_SCAN_INTERVAL);
        let outcome = sweep_tenant_purge(
            &self.tenant_repo,
            &self.audit_repo,
            scan_orphans,
            &self.audited,
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

        if self.stop_requested() {
            return;
        }
        // R101W1-05 (#618) — delete certificate rows more than
        // eight days past `notAfter` in live tenants: the revocation
        // list no longer names them, and they carry the PEM and
        // subject of people the Art. 17 purge has since erased.
        // INFO, for the audit sweep's reason: it destroys rows
        // nothing can rebuild (though nothing can need them).
        Self::record(
            &self.job_health,
            "certificate_retention",
            self.sweep_certificate_retention().await,
            tracing::Level::INFO,
        );

        if self.stop_requested() {
            return;
        }
        // #753: refresh-token rows a week past their expiry. DEBUG: such a
        // row is one no token can redeem and no replay still needs. Placed
        // after `vault_revocation`, `tenant_purge` and
        // `certificate_retention` and bounded to a few batches (R112W1-02),
        // so the first run over a large backlog delays none of them.
        Self::record(
            &self.job_health,
            "oauth2_refresh_token",
            self.sweep_refresh_tokens().await,
            tracing::Level::DEBUG,
        );

        if self.stop_requested() {
            return;
        }
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

        if self.stop_requested() {
            return;
        }
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

        if self.stop_requested() {
            return;
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
                sweep_scim_reconciliation(reconciliation.as_ref(), &self.shutdown).await,
                tracing::Level::INFO,
            );
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

    /// Delete refresh-token rows past their expiry plus the replay-detection
    /// retention (#753): see [`sweep_refresh_tokens`].
    async fn sweep_refresh_tokens(&self) -> Result<u64, AxiamError> {
        sweep_refresh_tokens(self.refresh_token_repo.as_ref(), Utc::now(), &self.shutdown).await
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

    /// Remove the shared rate-limit table's stale buckets (#638), as the
    /// `rate_limit_bucket` job. A size bound, not a correctness one: see
    /// [`sweep_rate_limit_buckets`]. `Ok(0)` without the repository.
    async fn sweep_rate_limit_buckets(&self) -> Result<u64, AxiamError> {
        let Some(repo) = &self.rate_limit_bucket_repo else {
            return Ok(0);
        };
        sweep_rate_limit_buckets(repo).await
    }

    // -----------------------------------------------------------------------
    // Certificate retention sweep (R101W1-05, #618)
    // -----------------------------------------------------------------------

    /// The `certificate_retention` job: see [`sweep_certificate_retention`].
    async fn sweep_certificate_retention(&self) -> Result<u64, AxiamError> {
        sweep_certificate_retention(self.cert_repo.as_ref(), &self.shutdown).await
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
    /// (b4) Revoke the account's `User` certificates (#533) and clear their
    ///     `metadata` (R101W1-05) — kept, on their issuers' revocation lists,
    ///     until the certificate retention sweep deletes them eight days past
    ///     `notAfter`.
    /// (c) Compute deterministic GDPR pseudonym via `gdpr_pseudonym`.
    /// (d)/(e)/(g) Run [`run_erasure_pipeline`]: pseudonymize all audit
    ///     entries for this user (now FATAL, D-01/D-03/D-04) -> anonymize the
    ///     user row in-place (D-05) -> insert a PII-free erasure-proof
    ///     record STRICTLY LAST (D-06, D-03a/D-03b — SECHRD-06).
    /// (h) Emit `gdpr.user_pseudonymized` audit event (actor = System).
    /// (f) Mark the account_deletion row as completed, and clear the
    ///     record marker the anonymization set, in one transaction (#689).
    ///
    /// Before the due accounts, the sweep records the erasures a cut unit
    /// left owed ([`record_owed_erasures`], #689).
    ///
    /// Returns the count of users purged.
    async fn sweep_pending_purges(&self) -> Result<u64, AxiamError> {
        // #689: first, the erasures a unit anonymized and was cut before
        // recording. Needs no pepper: the pseudonym is on the row. A failure
        // here does not hold back the due erasures; it is reported after them.
        let lease = chrono::TimeDelta::from_std(PENDING_RECORD_LEASE)
            .map_err(|e| AxiamError::Internal(format!("pending record lease: {e}")))?;
        let owed_error = record_owed_erasures(
            self.audit_repo.as_ref(),
            self.erasure_proof_repo.as_ref(),
            self.cert_repo.as_ref(),
            self.account_deletion_repo.as_ref(),
            lease,
            &self.audited,
        )
        .await
        .err();

        let pepper = match self.gdpr_pepper {
            Some(p) => p,
            None => {
                tracing::warn!(
                    "GDPR purge sweep skipped — AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER not set"
                );
                return owed_error.map_or(Ok(0), Err);
            }
        };

        let now = Utc::now();
        let due = self.user_repo.find_due_for_purge(now).await?;
        let mut purged: u64 = 0;

        let due_count = due.len();
        for (started, user) in due.into_iter().enumerate() {
            // #598: no erasure starts once the process is stopping; the users
            // left are still due, and the next start purges them.
            if self.stop_requested() {
                tracing::info!(
                    purged,
                    left = due_count - started,
                    "GDPR purge sweep stopped: the process is stopping (the rest stay due)"
                );
                break;
            }
            match self.purge_single_user(&user, pepper, now).await {
                Some(Ok(true)) => purged += 1,
                // Given up at the stop before the account was anonymized (it
                // stays due), or still running and left to the teardown's join
                // (#624): the check above ends the loop.
                Some(Ok(false)) => {}
                None if self.stop_requested() => {}
                None => tracing::warn!(
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    "purge ended without an outcome — skipping"
                ),
                Some(Err(e)) => tracing::warn!(
                    error = ?e,
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    "purge failed for user — skipping"
                ),
            }
        }

        if let Some(e) = owed_error {
            return Err(e);
        }
        Ok(purged)
    }

    /// Run the full purge pipeline for a single user, as one unit of
    /// [`AuditedWork`] (#624): a task of its own, which a cut of the cleanup
    /// task does not reach.
    ///
    /// `Some(Ok(true))` once the account is erased and recorded,
    /// `Some(Ok(false))` when the purge gave itself up at the stop before the
    /// account was anonymized (it stays due), `None` when the process is
    /// stopping while it runs (the teardown waits for it) or it panicked.
    ///
    /// G-5 (D-52): the session revocations and the `account-purged` event are
    /// one cause, and the platform's own (`system`) — set inside the unit's
    /// task, which is where they run.
    async fn purge_single_user(
        &self,
        user: &axiam_core::models::user::User,
        pepper: [u8; 32],
        now: chrono::DateTime<Utc>,
    ) -> Option<Result<bool, AxiamError>> {
        let unit = ErasureUnit {
            auth_svc: Arc::clone(&self.auth_svc),
            federation_link_repo: Arc::clone(&self.federation_link_repo),
            webauthn_repo: Arc::clone(&self.webauthn_repo),
            password_history_repo: Arc::clone(&self.password_history_repo),
            group_repo: Arc::clone(&self.group_repo),
            role_repo: Arc::clone(&self.role_repo),
            permission_repo: Arc::clone(&self.permission_repo),
            cert_repo: Arc::clone(&self.cert_repo),
            audit_repo: Arc::clone(&self.audit_repo),
            erasure_proof_repo: Arc::clone(&self.erasure_proof_repo),
            user_repo: Arc::clone(&self.user_repo),
            account_deletion_repo: Arc::clone(&self.account_deletion_repo),
            refresh_token_repo: Arc::clone(&self.refresh_token_repo),
            ssf_sink: self.ssf_sink.clone(),
            subject_flush: self.subject_flush.clone(),
        };
        let (user, work) = (user.clone(), self.audited.clone());
        self.audited
            .run(with_cause(
                Some(InitiatingEntity::System),
                unit.purge(user, pepper, now, work),
            ))
            .await
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
            // #598: no export starts once the process is stopping; the jobs
            // left stay queued, and the next start processes them.
            if self.stop_requested() {
                tracing::info!(
                    processed,
                    "GDPR export sweep stopped: the process is stopping (the rest stay queued)"
                );
                break;
            }
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

/// The failure and early-exit arms of the W1 units (#689, #714, #668): a
/// datastore that cannot be reached, and a process that is stopping. The
/// integration tests in `tests/cleanup_task.rs` drive the happy paths against a
/// migrated in-memory datastore; these reach the arms that only a failing one
/// or a stop opens, through the private helpers themselves.
#[cfg(test)]
mod w1_failure_arm_tests {
    use std::io::Write;

    use axiam_db::run_migrations;
    use surrealdb::Surreal;
    use surrealdb::engine::local::{Db, Mem};

    use super::*;

    /// A datastore with no namespace selected: every query on it fails.
    async fn unreachable_db() -> Surreal<Db> {
        Surreal::new::<Mem>(()).await.expect("in-memory DB")
    }

    async fn migrated_db() -> Surreal<Db> {
        let db = unreachable_db().await;
        db.use_ns("test").use_db("test").await.expect("use ns/db");
        run_migrations(&db).await.expect("migrations");
        db
    }

    fn stopped() -> (watch::Sender<bool>, AuditedWork) {
        let (tx, rx) = watch::channel(true);
        (tx, AuditedWork::new(rx))
    }

    fn running() -> (watch::Sender<bool>, AuditedWork) {
        let (tx, rx) = watch::channel(false);
        (tx, AuditedWork::new(rx))
    }

    /// Captures what the code under test logs, on this thread.
    #[derive(Clone, Default)]
    struct Log(Arc<std::sync::Mutex<Vec<u8>>>);

    impl Write for Log {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Log {
        type Writer = Log;

        fn make_writer(&'a self) -> Log {
            self.clone()
        }
    }

    impl Log {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    fn capture() -> (Log, tracing::subscriber::DefaultGuard) {
        let log = Log::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        (log, tracing::subscriber::set_default(subscriber))
    }

    fn erasure_marker(db: &Surreal<Db>) -> (PendingMarker<Db>, Uuid) {
        let user_id = Uuid::new_v4();
        (
            PendingMarker::Erasure {
                deletions: SurrealAccountDeletionRepository::new(db.clone()),
                tenant_id: Uuid::new_v4(),
                user_id,
            },
            user_id,
        )
    }

    fn purge_marker(db: &Surreal<Db>) -> (PendingMarker<Db>, Uuid) {
        let tenant_id = Uuid::new_v4();
        (
            PendingMarker::TenantPurge {
                tenants: Arc::new(SurrealTenantRepository::new(db.clone())),
                tenant_id,
            },
            tenant_id,
        )
    }

    #[tokio::test]
    async fn a_pending_marker_names_the_record_its_unit_owes_and_reports_a_failed_write() {
        let db = unreachable_db().await;
        let (erasure, user_id) = erasure_marker(&db);
        let (purge, tenant_id) = purge_marker(&db);
        assert_eq!(
            erasure.id(),
            user_id,
            "an erasure marker is keyed by the user"
        );
        assert_eq!(
            purge.id(),
            tenant_id,
            "a purge marker is keyed by the tenant"
        );
        let stamp = Utc::now();
        for marker in [&erasure, &purge] {
            assert!(
                marker.settle(stamp).await.is_err(),
                "settle reports the failure"
            );
            assert!(
                marker.release(stamp).await.is_err(),
                "release reports the failure"
            );
        }
    }

    /// A marker that cannot be cleared or released is logged and never fatal:
    /// the next sweep finds the record written, or the lease lapses.
    #[tokio::test]
    async fn a_record_claim_that_cannot_reach_the_datastore_logs_and_lets_go() {
        let db = unreachable_db().await;
        let (log, _guard) = capture();
        let (marker, _) = erasure_marker(&db);
        RecordClaim {
            marker,
            stamp: Utc::now(),
            held: true,
        }
        .settle()
        .await;
        let (marker, _) = purge_marker(&db);
        RecordClaim {
            marker,
            stamp: Utc::now(),
            held: true,
        }
        .release()
        .await;
        let text = log.text();
        assert!(
            text.contains("could not clear a pending-record marker"),
            "{text}"
        );
        assert!(
            text.contains("could not release a pending-record marker"),
            "{text}"
        );
    }

    /// An exit that cannot await — the unit aborted at the bound — drops the
    /// guard still holding the claim, and the drop spawns the release.
    #[tokio::test]
    async fn dropping_a_held_claim_inside_a_runtime_spawns_its_release() {
        let db = unreachable_db().await;
        let (log, _guard) = capture();
        let (marker, _) = erasure_marker(&db);
        drop(RecordClaim {
            marker,
            stamp: Utc::now(),
            held: true,
        });
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        drop(PurgeClaim {
            tenants,
            tenant_id: Uuid::new_v4(),
            claimed_at: Utc::now(),
            held: true,
        });
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        let text = log.text();
        assert!(
            text.contains("could not release the pending-record marker of a unit that was cut"),
            "{text}"
        );
        assert!(
            text.contains("could not release the claim of a tenant purge that was cut"),
            "{text}"
        );
    }

    /// A claim settled before the drop releases nothing.
    #[tokio::test]
    async fn dropping_a_settled_claim_releases_nothing() {
        let db = unreachable_db().await;
        let (log, _guard) = capture();
        let (marker, _) = purge_marker(&db);
        drop(RecordClaim {
            marker,
            stamp: Utc::now(),
            held: false,
        });
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        PurgeClaim {
            tenants,
            tenant_id: Uuid::new_v4(),
            claimed_at: Utc::now(),
            held: true,
        }
        .settle();
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        assert_eq!(log.text(), "", "nothing was logged");
    }

    /// A guard dropped with no runtime to spawn on can only say so.
    #[test]
    fn dropping_a_held_claim_outside_a_runtime_logs_that_it_lapses_with_its_lease() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let db = runtime.block_on(unreachable_db());
        let (log, _guard) = capture();
        let (marker, _) = erasure_marker(&db);
        drop(RecordClaim {
            marker,
            stamp: Utc::now(),
            held: true,
        });
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        drop(PurgeClaim {
            tenants,
            tenant_id: Uuid::new_v4(),
            claimed_at: Utc::now(),
            held: true,
        });
        let text = log.text();
        assert!(
            text.contains("unit cut outside a runtime lapses with its lease"),
            "{text}"
        );
        assert!(
            text.contains("cut outside a runtime lapses with its lease"),
            "{text}"
        );
    }

    /// Once the process is stopping, no sweep starts recording.
    #[tokio::test]
    async fn the_record_sweeps_start_nothing_once_the_process_is_stopping() {
        let db = migrated_db().await;
        let (_tx, work) = stopped();
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        let audit = SurrealAuditLogRepository::new(db.clone());
        let proofs = SurrealErasureProofRepository::new(db.clone());
        let certs = axiam_db::SurrealCertificateRepository::new(db.clone());
        let deletions = SurrealAccountDeletionRepository::new(db.clone());
        let lease = chrono::TimeDelta::seconds(60);
        assert_eq!(
            record_pending_purges(&tenants, &audit, lease, &work)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            record_owed_erasures(&audit, &proofs, &certs, &deletions, lease, &work)
                .await
                .unwrap(),
            0
        );
    }

    /// A sweep that cannot read its markers fails; it does not claim to have
    /// recorded nothing.
    #[tokio::test]
    async fn the_record_sweeps_fail_when_the_datastore_cannot_be_read() {
        let db = unreachable_db().await;
        let (_tx, work) = running();
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        let audit = SurrealAuditLogRepository::new(db.clone());
        let proofs = SurrealErasureProofRepository::new(db.clone());
        let certs = axiam_db::SurrealCertificateRepository::new(db.clone());
        let deletions = SurrealAccountDeletionRepository::new(db.clone());
        let lease = chrono::TimeDelta::seconds(60);
        assert!(
            record_pending_purges(&tenants, &audit, lease, &work)
                .await
                .is_err()
        );
        assert!(
            record_owed_erasures(&audit, &proofs, &certs, &deletions, lease, &work)
                .await
                .is_err()
        );
    }

    /// #714: an orphan unit whose claim write fails releases the claim it armed
    /// before the write, by its stamp, and returns the error.
    #[tokio::test]
    async fn an_orphan_unit_whose_claim_fails_releases_what_it_armed_and_fails() {
        let db = unreachable_db().await;
        let (log, _guard) = capture();
        let (_tx, work) = running();
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        let audit = Arc::new(SurrealAuditLogRepository::new(db.clone()));
        let outcome = purge_orphan_unit(tenants, audit, Uuid::new_v4(), work).await;
        assert!(outcome.is_err());
        assert!(
            log.text()
                .contains("could not release the tenant purge claim"),
            "{}",
            log.text()
        );
    }

    /// #689: past the point of no return a failed removal releases the pending
    /// marker the transaction may have written, and the claim, and fails.
    #[tokio::test]
    async fn crossing_the_point_of_no_return_fails_cleanly_when_the_removal_fails() {
        let db = unreachable_db().await;
        let (log, _guard) = capture();
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        let tenant_id = Uuid::new_v4();
        let claim = PurgeClaim {
            tenants: Arc::clone(&tenants),
            tenant_id,
            claimed_at: Utc::now(),
            held: true,
        };
        let crossed =
            cross_point_of_no_return(&tenants, tenant_id, &Default::default(), claim).await;
        assert!(crossed.is_err());
        let text = log.text();
        assert!(
            text.contains("could not release a tenant purge's pending record"),
            "{text}"
        );
        assert!(
            text.contains("could not release the tenant purge claim"),
            "{text}"
        );
    }

    /// An overlapping purge removed the row first: nothing to record here.
    #[tokio::test]
    async fn crossing_the_point_of_no_return_yields_nothing_when_the_row_is_already_gone() {
        let db = migrated_db().await;
        let tenants = Arc::new(SurrealTenantRepository::new(db.clone()));
        let tenant_id = Uuid::new_v4();
        let claim = PurgeClaim {
            tenants: Arc::clone(&tenants),
            tenant_id,
            claimed_at: Utc::now(),
            held: true,
        };
        let crossed =
            cross_point_of_no_return(&tenants, tenant_id, &Default::default(), claim).await;
        assert!(
            matches!(crossed, Ok(None)),
            "an absent row is another purge's"
        );
    }
}

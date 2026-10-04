//! The directory sync job (G-3, T23.3.5, D-31): keeping AXIAM's directory
//! accounts in step with the directory they came from, **without ever being
//! able to grant anything**.
//!
//! # What it does, per tenant with an enabled directory
//!
//! Two kinds of run, both read-only against the directory:
//!
//! * **Full** (the first run, then every [`SyncLimits::full_interval`]): look up
//!   **every** account carrying a `directory_external_id` by that identifier —
//!   `entryUUID=<uuid>`, or `objectGUID=<binary-escaped octets>`, under
//!   `base_dn`, exactly one entry. Found: refresh the account (below). Not
//!   found: **vanished**. Only a full run concludes "vanished", because only it
//!   has asked about everyone.
//! * **Incremental** (every `sync_interval_secs`): one search for entries whose
//!   change attribute is at or after a stored watermark, acting only on entries
//!   whose identifier belongs to a marked account. Deletions are invisible to
//!   it and are left to the full run. On Active Directory the watermark is
//!   `highestCommittedUSN` read from the rootDSE of the same server; a changed
//!   `dsServiceName`, or no usable watermark, falls back to a full run.
//!
//! # What it may write (D-31)
//!
//! * A vanished or directory-disabled account becomes **`Inactive`** — never
//!   `Deleted` (an anonymised tombstone), never a hard delete. Its sessions and
//!   OAuth2 refresh tokens are revoked **through the repositories** (so the
//!   session validation cache and the revocation feed see it), its
//!   directory-sourced memberships are removed through the D-30 mapper (so the
//!   decision cache is flushed), and `account_may_act` then refuses it on every
//!   path — passkeys and the OP cookie included, which closes T-303's residual.
//!   The row, its marker and its audit trail stay.
//! * An account that is present and enabled is refreshed: its username, email
//!   and display name follow the entry (through the same cleaners just-in-time
//!   provisioning applies; a change that would collide with another account is
//!   **skipped and audited**, never applied) and its group mapping is applied.
//! * **Nothing else.** The job never re-enables an account, never creates one
//!   and never links one by name (D-28): an `Inactive` account whose entry is
//!   present and enabled is **reported** — once — as needing an administrator.
//!   It never touches an account without a marker.
//!
//! # Why it is safe to be wrong about the directory
//!
//! * **Errors change nothing.** A directory that cannot be reached, a refused
//!   search, a deadline: the run ends before anything is written (the full run
//!   reads everything first, writes second), and the state records the failure.
//!   An empty or failed search never reads as "everyone vanished": the question
//!   that was not answered is an error, not a negative answer.
//! * **The safety valve.** A full run that would deactivate more than
//!   [`SyncLimits::valve_percent`] % of the tenant's directory accounts **and**
//!   at least [`SyncLimits::valve_min_accounts`] of them applies **nothing**,
//!   audits, and reports failure. An empty search after a misconfiguration or an
//!   outage must not disable a company.
//! * **Per-user failures skip that user.** A failed mapping, a failed write:
//!   that account is left as it was and the next run is a full one.
//! * **Order of a deactivation** is revoke, remove memberships, then flip the
//!   status **last** with a compare-and-set: a failure part-way leaves the
//!   account `Active` and the next run finds it again, so there is no state in
//!   which an account is `Inactive` yet still holds what the job should have
//!   taken.
//!
//! # Scheduling and bounds
//!
//! One tenant at a time, on the server's cleanup scheduler, through the same
//! bounded pool and deadlines as every other directory use; each run is also
//! bounded by [`SyncLimits::run_deadline`]. There is **no multi-replica guard**:
//! two replicas run the same job against the same rows. Every write is
//! idempotent or a compare-and-set, so the result is the same; the cost is
//! duplicated directory reads and, for refreshes, duplicated audit rows.
//!
//! No audit row, log line or error carries a name, an address, a DN or a
//! password: accounts are named by id and entries by their immutable identifier.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryConfig, DirectoryKind, SharedDirectoryAuditSink,
    SharedDirectoryGroupMapper,
};
use axiam_core::models::directory_profile::CleanedAttributes;
use axiam_core::models::directory_sync::{
    AUDIT_ACCOUNT_DEACTIVATED, AUDIT_ACCOUNT_REAPPEARED, AUDIT_ACCOUNT_UPDATED,
    AUDIT_GROUPS_MAPPED, AUDIT_SYNC_ATTRIBUTE_SKIPPED, AUDIT_SYNC_RUN, AUDIT_SYNC_SAFETY_VALVE,
    AUDIT_SYNC_USER_SKIPPED, DirectorySyncResult, DirectorySyncState,
};
use axiam_core::models::user::{UpdateUser, User, UserStatus};
use axiam_core::repository::{
    DirectoryConfigRepository, DirectorySyncStateRepository, RefreshTokenRepository,
    SessionRepository, UserRepository,
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::authenticator::RepositoryDirectoryAuthenticator;
use crate::escape::{external_id_filter, is_usn};
use crate::sync_lookup::{DirectorySession, EntryLookup, RootDse, SyncEntry};

/// The bounds and thresholds of the job. [`Default`] is the documented values;
/// tests shrink them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncLimits {
    /// How long after the last complete full run the next one is due (24 h).
    pub full_interval: Duration,
    /// The longest one tenant's run may take, directory I/O and writes
    /// together. A run that exceeds it is abandoned; the next one is full.
    pub run_deadline: Duration,
    /// The most directory accounts one full run handles. A tenant with more is
    /// refused with an error rather than half-synced.
    pub max_accounts: usize,
    /// Accounts read from the store per page.
    pub page_size: u32,
    /// The most entries one incremental search reads; more is a prefix, the
    /// entries read are applied, and the next run is a full one.
    pub max_changed_entries: usize,
    /// The safety valve's percentage: a full run that would deactivate **more
    /// than** this share of the tenant's directory accounts is a candidate.
    pub valve_percent: usize,
    /// The safety valve's floor: …and only when it would deactivate **at
    /// least** this many.
    pub valve_min_accounts: usize,
}

impl Default for SyncLimits {
    fn default() -> Self {
        Self {
            full_interval: Duration::from_secs(24 * 60 * 60),
            run_deadline: Duration::from_secs(15 * 60),
            max_accounts: 100_000,
            page_size: 500,
            max_changed_entries: 10_000,
            valve_percent: 10,
            valve_min_accounts: 5,
        }
    }
}

/// Which kind of run was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    /// Every marked account looked up by its identifier.
    Full,
    /// The entries changed since the watermark.
    Incremental,
}

impl RunKind {
    /// The spelling audit rows use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Incremental => "incremental",
        }
    }
}

/// Why a tenant's run did not complete. None of these changed the tenant's
/// accounts, except where stated.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    /// The directory could not be used: unreachable, misconfigured, refusing the
    /// search or the service bind, or the bind secret unavailable.
    #[error("the directory could not be used for sync: {0:?}")]
    Directory(DirectoryAuthError),
    /// The state row, the account store or the configuration could not be read
    /// or written.
    #[error("the sync state or the account store failed: {0}")]
    Store(String),
    /// The full run would have deactivated too many accounts and applied
    /// nothing.
    #[error(
        "the safety valve tripped: a full run would deactivate {would_deactivate} of \
         {directory_accounts} directory accounts; nothing was applied"
    )]
    SafetyValve {
        /// Accounts the run would have deactivated.
        would_deactivate: usize,
        /// The tenant's directory accounts.
        directory_accounts: usize,
    },
    /// The tenant has more directory accounts than one run handles.
    #[error("the tenant has more than {0} directory accounts, more than one run handles")]
    TooManyAccounts(usize),
    /// The run exceeded its deadline and was abandoned part-way.
    #[error("the run exceeded its deadline")]
    Deadline,
}

impl SyncError {
    /// A short fixed tag for job health: what failed, never who.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Directory(DirectoryAuthError::Unavailable) => "directory_unavailable",
            Self::Directory(DirectoryAuthError::Misconfigured) => "directory_misconfigured",
            Self::Directory(_) => "directory_refused",
            Self::Store(_) => "store",
            Self::SafetyValve { .. } => "safety_valve",
            Self::TooManyAccounts(_) => "too_many_accounts",
            Self::Deadline => "deadline",
        }
    }
}

fn store(error: AxiamError) -> SyncError {
    SyncError::Store(error.to_string())
}

/// What one tenant's completed run did. Counts only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantReport {
    /// The tenant.
    pub tenant_id: Uuid,
    /// The kind of run that was made.
    pub run: RunKind,
    /// An incremental run was due but could not be trusted (no watermark, a
    /// different server, a previous bound hit or skipped account), so a full one
    /// was made instead.
    pub fell_back_to_full: bool,
    /// Accounts the run evaluated against a directory answer.
    pub accounts_examined: usize,
    /// Accounts set `Inactive` because their entry vanished.
    pub deactivated_vanished: usize,
    /// Accounts set `Inactive` because the directory disabled them.
    pub deactivated_disabled: usize,
    /// `Inactive` accounts reported for the first time as present and enabled.
    pub reappeared_reported: usize,
    /// Accounts whose username, email or display name was updated.
    pub attributes_updated: usize,
    /// Attribute changes not applied because they would collide.
    pub attributes_skipped: usize,
    /// Accounts whose group memberships changed.
    pub memberships_changed: usize,
    /// Accounts left as they were because the run could not decide or write for
    /// them (an ambiguous or unaskable identifier, a failed mapping or write).
    pub accounts_skipped: usize,
    /// An incremental search hit its bound; what was read was applied.
    pub bound_hit: bool,
}

impl TenantReport {
    fn new(tenant_id: Uuid, run: RunKind) -> Self {
        Self {
            tenant_id,
            run,
            fell_back_to_full: false,
            accounts_examined: 0,
            deactivated_vanished: 0,
            deactivated_disabled: 0,
            reappeared_reported: 0,
            attributes_updated: 0,
            attributes_skipped: 0,
            memberships_changed: 0,
            accounts_skipped: 0,
            bound_hit: false,
        }
    }

    /// Accounts the run changed in any way, for job-health's "affected" count.
    #[must_use]
    pub fn changed(&self) -> usize {
        self.deactivated_vanished
            + self.deactivated_disabled
            + self.attributes_updated
            + self.memberships_changed
    }
}

/// What a scheduler pass did across tenants.
#[derive(Debug, Default)]
pub struct SyncSummary {
    /// Tenants whose run completed.
    pub reports: Vec<TenantReport>,
    /// Tenants whose run failed, and why.
    pub failures: Vec<(Uuid, SyncError)>,
    /// Tenants with an enabled directory that were not due.
    pub not_due: usize,
}

impl SyncSummary {
    /// Accounts changed across every completed run.
    #[must_use]
    pub fn changed(&self) -> u64 {
        self.reports.iter().map(|r| r.changed() as u64).sum()
    }

    /// One line for job health, naming how many tenants failed and with which
    /// fixed tags — never a tenant's data.
    #[must_use]
    pub fn failure_message(&self) -> Option<String> {
        if self.failures.is_empty() {
            return None;
        }
        let tags: Vec<&str> = self.failures.iter().map(|(_, e)| e.tag()).collect();
        Some(format!(
            "directory sync failed for {} of {} tenants ({})",
            self.failures.len(),
            self.failures.len() + self.reports.len(),
            tags.join(", ")
        ))
    }
}

// ---------------------------------------------------------------------------
// The decision, as pure functions
// ---------------------------------------------------------------------------

/// What the directory said about one account.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// The full run asked and the search completed with no match.
    Vanished,
    /// The entry exists.
    Present(Box<SyncEntry>),
}

/// Why an account is deactivated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    Vanished,
    Disabled,
}

impl Reason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Vanished => "vanished",
            Self::Disabled => "disabled",
        }
    }
}

/// What to do about one account, given its status and the directory's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    /// Nothing: a tombstone, or an `Inactive` account the directory agrees is
    /// gone or disabled.
    Ignore,
    /// Set it `Inactive`.
    Deactivate(Reason),
    /// It is `Inactive` and its entry is present and enabled: say so, once.
    Reappeared,
    /// Keep it in step with its entry.
    Refresh(Box<SyncEntry>),
}

/// The whole rule of D-31, with no I/O. Note what is **absent**: no branch
/// leads to `Active`, to `Deleted`, or to any status but `Inactive`.
fn decide(status: &UserStatus, verdict: &Verdict) -> Decision {
    match status {
        // Tombstones carry no marker and are none of the job's business.
        UserStatus::Deleted | UserStatus::Anonymized => Decision::Ignore,
        UserStatus::Inactive => match verdict {
            Verdict::Present(entry) if !entry.disabled => Decision::Reappeared,
            _ => Decision::Ignore,
        },
        UserStatus::Active | UserStatus::PendingVerification | UserStatus::Locked => {
            match verdict {
                Verdict::Vanished => Decision::Deactivate(Reason::Vanished),
                Verdict::Present(entry) if entry.disabled => Decision::Deactivate(Reason::Disabled),
                Verdict::Present(entry) => Decision::Refresh(entry.clone()),
            }
        }
    }
}

/// Whether a full run that would deactivate `would_deactivate` of `total`
/// directory accounts must apply nothing (D-31): **more than** `percent` % and
/// **at least** `min`.
#[must_use]
pub fn valve_trips(would_deactivate: usize, total: usize, limits: &SyncLimits) -> bool {
    would_deactivate >= limits.valve_min_accounts
        && would_deactivate.saturating_mul(100) > total.saturating_mul(limits.valve_percent)
}

/// Which run is due, from the stored state alone.
fn choose_run(state: &DirectorySyncState, now: DateTime<Utc>, limits: &SyncLimits) -> RunKind {
    let full_due = match state.last_full_run_at {
        None => true,
        Some(last) => {
            chrono::Duration::from_std(limits.full_interval).map_or(true, |i| now - last >= i)
        }
    };
    if state.full_required || state.watermark.is_none() || full_due {
        RunKind::Full
    } else {
        RunKind::Incremental
    }
}

/// Whether a tenant is due for a run at all: the incremental schedule counts
/// from the last attempt, successful or not.
fn is_due(config: &DirectoryConfig, state: &DirectorySyncState, now: DateTime<Utc>) -> bool {
    match state.last_attempt_at {
        None => true,
        Some(last) => {
            let interval = i64::try_from(config.sync_interval_secs).unwrap_or(i64::MAX);
            now - last >= chrono::Duration::seconds(interval)
        }
    }
}

/// The later of two watermarks of the same shape. Generalized times sort
/// lexicographically; USNs are compared as numbers (their lengths differ).
fn later_watermark(a: &str, b: &str) -> String {
    if is_usn(a) && is_usn(b) {
        let (x, y) = (
            a.parse::<u128>().unwrap_or(0),
            b.parse::<u128>().unwrap_or(0),
        );
        return if x >= y { a } else { b }.to_string();
    }
    if a >= b { a } else { b }.to_string()
}

// ---------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------

/// The sync job: one instance per process, run by the cleanup scheduler.
pub struct DirectorySync<R, U, S, T, Z> {
    configs: R,
    authenticator: Arc<RepositoryDirectoryAuthenticator<R>>,
    users: U,
    sessions: S,
    refresh_tokens: T,
    states: Z,
    mapper: SharedDirectoryGroupMapper,
    audit: SharedDirectoryAuditSink,
    limits: SyncLimits,
}

/// What a full run read, before it writes anything.
struct Plan {
    /// Every marked account with the directory's verdict, in id order.
    items: Vec<(User, Verdict)>,
    /// Accounts the run could not decide for (ambiguous or unaskable).
    undecided: Vec<Uuid>,
    /// How many marked accounts the tenant has (tombstones excluded).
    directory_accounts: usize,
}

/// Which `reported` entries a run has confirmed or retired.
struct Reports {
    /// The accounts already reported, as stored.
    known: HashSet<Uuid>,
    /// The accounts reported or still reappeared in this run.
    current: HashSet<Uuid>,
}

impl<R, U, S, T, Z> DirectorySync<R, U, S, T, Z>
where
    R: DirectoryConfigRepository,
    U: UserRepository,
    S: SessionRepository,
    T: RefreshTokenRepository,
    Z: DirectorySyncStateRepository,
{
    /// A job over the given repositories.
    ///
    /// `authenticator` is the one the sign-in path uses, so the sync draws on the
    /// same bounded pool and reads the same configuration; `mapper` is the
    /// D-30 group mapper built from it, with the decision-cache slot set by the
    /// composition root.
    #[allow(clippy::too_many_arguments)] // the collaborators are the unit of work
    pub fn new(
        configs: R,
        authenticator: Arc<RepositoryDirectoryAuthenticator<R>>,
        users: U,
        sessions: S,
        refresh_tokens: T,
        states: Z,
        mapper: SharedDirectoryGroupMapper,
        audit: SharedDirectoryAuditSink,
    ) -> Self {
        Self {
            configs,
            authenticator,
            users,
            sessions,
            refresh_tokens,
            states,
            mapper,
            audit,
            limits: SyncLimits::default(),
        }
    }

    /// Replace the bounds (tests shrink them).
    #[must_use]
    pub fn with_limits(mut self, limits: SyncLimits) -> Self {
        self.limits = limits;
        self
    }

    /// The bounds in force.
    #[must_use]
    pub fn limits(&self) -> SyncLimits {
        self.limits
    }

    /// One scheduler pass: every tenant with an **enabled** directory, one at a
    /// time, each only if it is due. A tenant without a directory, or with it
    /// disabled, is never listed, so no connection is made for it.
    ///
    /// # Errors
    ///
    /// [`SyncError::Store`] when the configurations cannot be listed. A tenant's
    /// own failure is not an error here: it is in [`SyncSummary::failures`], and
    /// the next tenant still runs.
    pub async fn run_due(&self) -> Result<SyncSummary, SyncError> {
        let configs = self.configs.list_enabled().await.map_err(store)?;
        let mut summary = SyncSummary::default();
        for config in configs {
            match self.sync_tenant(&config, Utc::now()).await {
                Ok(Some(report)) => summary.reports.push(report),
                Ok(None) => summary.not_due += 1,
                // Disabled or deleted between listing and opening: the tenant
                // has no enabled directory any more, which is a skip.
                Err(SyncError::Directory(DirectoryAuthError::NotConfigured)) => {
                    summary.not_due += 1;
                }
                Err(error) => {
                    tracing::warn!(
                        target: "axiam::directory",
                        tenant_id = %config.tenant_id,
                        outcome = error.tag(),
                        "directory sync failed for a tenant; nothing was changed by the failing step"
                    );
                    summary.failures.push((config.tenant_id, error));
                }
            }
        }
        Ok(summary)
    }

    /// One tenant's pass: `Ok(None)` when it is not yet due.
    ///
    /// # Errors
    ///
    /// The [`SyncError`] that ended the run.
    pub async fn sync_tenant(
        &self,
        config: &DirectoryConfig,
        now: DateTime<Utc>,
    ) -> Result<Option<TenantReport>, SyncError> {
        let tenant_id = config.tenant_id;
        let mut state = self
            .states
            .get(tenant_id)
            .await
            .map_err(store)?
            .unwrap_or_else(|| DirectorySyncState::new(tenant_id));
        if !is_due(config, &state, now) {
            return Ok(None);
        }
        let run = choose_run(&state, now, &self.limits);
        state.last_attempt_at = Some(now);

        let outcome = tokio::time::timeout(
            self.limits.run_deadline,
            self.execute(config, &mut state, run, now),
        )
        .await;
        let (result, outcome) = match outcome {
            Ok(Ok(report)) => (
                if report.accounts_skipped > 0 {
                    DirectorySyncResult::Partial
                } else {
                    DirectorySyncResult::Ok
                },
                Ok(report),
            ),
            Ok(Err(error)) => (
                if matches!(error, SyncError::SafetyValve { .. }) {
                    DirectorySyncResult::SafetyValve
                } else {
                    DirectorySyncResult::Failed
                },
                Err(error),
            ),
            Err(_) => {
                // Abandoned part-way: some accounts may have been handled, so
                // the next run reconciles everything.
                state.full_required = true;
                (DirectorySyncResult::Failed, Err(SyncError::Deadline))
            }
        };
        state.last_result = Some(result);
        if let Err(error) = self.states.save(&state).await {
            tracing::error!(
                target: "axiam::directory",
                %tenant_id,
                %error,
                "the directory sync state could not be saved"
            );
            if outcome.is_ok() {
                return Err(store(error));
            }
        }
        outcome.map(Some)
    }

    async fn execute(
        &self,
        config: &DirectoryConfig,
        state: &mut DirectorySyncState,
        run: RunKind,
        now: DateTime<Utc>,
    ) -> Result<TenantReport, SyncError> {
        let session = match self.authenticator.open_sync(config.tenant_id).await {
            Ok(session) => session,
            Err(error) => return Err(SyncError::Directory(error)),
        };
        match run {
            RunKind::Full => self.full_run(&session, state, now, false).await,
            RunKind::Incremental => self.incremental_run(&session, state, now).await,
        }
    }

    // -----------------------------------------------------------------------
    // Full run
    // -----------------------------------------------------------------------

    async fn full_run(
        &self,
        session: &DirectorySession,
        state: &mut DirectorySyncState,
        now: DateTime<Utc>,
        fell_back: bool,
    ) -> Result<TenantReport, SyncError> {
        let config = session.config();
        let tenant_id = config.tenant_id;
        let kind = config.kind;
        let mut report = TenantReport::new(tenant_id, RunKind::Full);
        report.fell_back_to_full = fell_back;

        // Active Directory's watermark is read **before** anything is looked up:
        // any change after this point has a higher USN and is seen by the next
        // incremental run. A failed read is not a failed run; it is "no
        // watermark". A tenant with no directory accounts has nothing to resume
        // and the directory is not asked.
        let root_dse = if kind == DirectoryKind::ActiveDirectory
            && !self
                .users
                .list_directory_accounts(tenant_id, None, 1)
                .await
                .map_err(store)?
                .is_empty()
        {
            match session.read_root_dse().await {
                Ok(dse) => Some(dse),
                Err(error) => {
                    tracing::warn!(
                        target: "axiam::directory",
                        %tenant_id,
                        outcome = ?error,
                        "the rootDSE could not be read; the next incremental run will be a full one"
                    );
                    None
                }
            }
        } else {
            None
        };

        // Phase 1: read. Nothing is written until everything is known, so an
        // error anywhere in this phase leaves every account as it was.
        let plan = self.read_everything(session).await?;
        report.accounts_examined = plan.items.len();

        // The valve: counted over the decisions, before any is applied.
        let would_deactivate = plan
            .items
            .iter()
            .filter(|(user, verdict)| {
                matches!(decide(&user.status, verdict), Decision::Deactivate(_))
            })
            .count();
        if valve_trips(would_deactivate, plan.directory_accounts, &self.limits) {
            if state.last_result != Some(DirectorySyncResult::SafetyValve) {
                self.record(
                    tenant_id,
                    AUDIT_SYNC_SAFETY_VALVE,
                    None,
                    AuditOutcome::Denied,
                    serde_json::json!({
                        "run": RunKind::Full.as_str(),
                        "would_deactivate": would_deactivate,
                        "directory_accounts": plan.directory_accounts,
                        "valve_percent": self.limits.valve_percent,
                        "valve_min_accounts": self.limits.valve_min_accounts,
                        "applied": "nothing",
                    }),
                )
                .await;
            }
            tracing::error!(
                target: "axiam::directory",
                %tenant_id,
                would_deactivate,
                directory_accounts = plan.directory_accounts,
                "directory sync safety valve tripped: a full run would deactivate too many \
                 accounts; nothing was applied"
            );
            // The next attempt is a full run again, so the situation is
            // re-evaluated rather than skipped past by an incremental.
            state.full_required = true;
            return Err(SyncError::SafetyValve {
                would_deactivate,
                directory_accounts: plan.directory_accounts,
            });
        }

        // Phase 2: write. Each account is handled on its own; a failure skips
        // that account only.
        let mut reports = Reports {
            known: state.reported_user_ids.iter().copied().collect(),
            current: HashSet::new(),
        };
        let mut newest_change: Option<String> = None;
        for (user, verdict) in &plan.items {
            if let Verdict::Present(entry) = verdict
                && let Some(change) = &entry.change_value
            {
                newest_change = Some(match newest_change {
                    Some(have) => later_watermark(&have, change),
                    None => change.clone(),
                });
            }
            self.apply(
                session,
                user,
                verdict,
                RunKind::Full,
                &mut reports,
                &mut report,
            )
            .await;
        }
        report.accounts_skipped += plan.undecided.len();

        // The next incremental run resumes from here, or — with nothing to
        // resume from — is a full one.
        let (watermark, server_identity) = match kind {
            DirectoryKind::ActiveDirectory => match root_dse {
                Some(RootDse {
                    server_identity: Some(identity),
                    highest_committed_usn: Some(usn),
                }) => (Some(usn), Some(identity)),
                _ => (None, None),
            },
            DirectoryKind::OpenLdap => (newest_change, None),
        };
        state.watermark = watermark;
        state.server_identity = server_identity;
        state.full_required = report.accounts_skipped > 0;
        state.last_full_run_at = Some(now);
        // Reported accounts the run did not look at (undecided) keep their
        // entry; every other one is re-derived from what the run saw.
        for id in &plan.undecided {
            if reports.known.contains(id) {
                reports.current.insert(*id);
            }
        }
        state.reported_user_ids = sorted(reports.current);

        self.record(
            tenant_id,
            AUDIT_SYNC_RUN,
            None,
            if report.accounts_skipped > 0 {
                AuditOutcome::Failure
            } else {
                AuditOutcome::Success
            },
            serde_json::json!({
                "run": RunKind::Full.as_str(),
                "fell_back_to_full": report.fell_back_to_full,
                "accounts_examined": report.accounts_examined,
                "deactivated_vanished": report.deactivated_vanished,
                "deactivated_disabled": report.deactivated_disabled,
                "reappeared_reported": report.reappeared_reported,
                "attributes_updated": report.attributes_updated,
                "attributes_skipped": report.attributes_skipped,
                "memberships_changed": report.memberships_changed,
                "accounts_skipped": report.accounts_skipped,
            }),
        )
        .await;
        Ok(report)
    }

    /// Phase 1 of a full run: page through the tenant's marked accounts and ask
    /// the directory about each. Any directory failure ends the run.
    async fn read_everything(&self, session: &DirectorySession) -> Result<Plan, SyncError> {
        let config = session.config();
        let tenant_id = config.tenant_id;
        let id_attribute = &config.user_attribute_map.external_id;
        let mut plan = Plan {
            items: Vec::new(),
            undecided: Vec::new(),
            directory_accounts: 0,
        };
        let mut after: Option<Uuid> = None;
        loop {
            let page = self
                .users
                .list_directory_accounts(tenant_id, after, self.limits.page_size)
                .await
                .map_err(store)?;
            let Some(last) = page.last() else { break };
            after = Some(last.id);
            for user in page {
                if matches!(user.status, UserStatus::Deleted | UserStatus::Anonymized) {
                    continue;
                }
                plan.directory_accounts += 1;
                if plan.directory_accounts > self.limits.max_accounts {
                    return Err(SyncError::TooManyAccounts(self.limits.max_accounts));
                }
                let Some(marker) = user.directory_external_id.clone() else {
                    continue;
                };
                // An identifier that cannot be put in a filter is a question
                // that cannot be asked: the account is skipped, never read as
                // vanished.
                if external_id_filter(id_attribute, &marker).is_none() {
                    plan.undecided.push(user.id);
                    continue;
                }
                match session
                    .lookup_by_external_id(&marker)
                    .await
                    .map_err(SyncError::Directory)?
                {
                    EntryLookup::Found(entry) => plan.items.push((user, Verdict::Present(entry))),
                    EntryLookup::NotFound => plan.items.push((user, Verdict::Vanished)),
                    EntryLookup::Ambiguous => plan.undecided.push(user.id),
                }
            }
        }
        Ok(plan)
    }

    // -----------------------------------------------------------------------
    // Incremental run
    // -----------------------------------------------------------------------

    async fn incremental_run(
        &self,
        session: &DirectorySession,
        state: &mut DirectorySyncState,
        now: DateTime<Utc>,
    ) -> Result<TenantReport, SyncError> {
        let config = session.config();
        let tenant_id = config.tenant_id;
        let kind = config.kind;
        let Some(watermark) = state.watermark.clone() else {
            return self.full_run(session, state, now, true).await;
        };

        // Active Directory: the watermark counts one server's USNs. Read the
        // server's identity and its current high-water mark *before* searching;
        // a different server, or no readable mark, cannot be trusted.
        let mut next_watermark: Option<String> = None;
        if kind == DirectoryKind::ActiveDirectory {
            let dse = match session.read_root_dse().await {
                Ok(dse) => dse,
                Err(error) => {
                    tracing::warn!(
                        target: "axiam::directory",
                        %tenant_id,
                        outcome = ?error,
                        "the rootDSE could not be read; running a full reconciliation instead"
                    );
                    return self.full_run(session, state, now, true).await;
                }
            };
            let same_server =
                dse.server_identity.is_some() && dse.server_identity == state.server_identity;
            if !same_server || dse.highest_committed_usn.is_none() {
                tracing::info!(
                    target: "axiam::directory",
                    %tenant_id,
                    "the directory server changed or gave no watermark; running a full \
                     reconciliation instead"
                );
                return self.full_run(session, state, now, true).await;
            }
            next_watermark = dse.highest_committed_usn;
        }

        let changed = session
            .search_changed(&watermark, self.limits.max_changed_entries)
            .await
            .map_err(SyncError::Directory)?;

        let mut report = TenantReport::new(tenant_id, RunKind::Incremental);
        report.bound_hit = !changed.complete;
        let mut reports = Reports {
            known: state.reported_user_ids.iter().copied().collect(),
            current: state.reported_user_ids.iter().copied().collect(),
        };
        let mut newest = Some(watermark.clone());
        for entry in changed.entries {
            // Every entry read — marked or not — advances an OpenLDAP watermark:
            // each was changed at or after it, and the next search resumes there.
            if let Some(change) = &entry.change_value {
                newest = Some(match newest {
                    Some(have) => later_watermark(&have, change),
                    None => change.clone(),
                });
            }
            // Only an entry whose identifier belongs to a marked account is
            // acted on. A directory that changes an entry no account owns
            // creates nothing: the job never provisions and never links.
            let user = match self
                .users
                .get_by_directory_external_id(tenant_id, &entry.identity.external_id)
                .await
            {
                Ok(Some(user)) => user,
                Ok(None) => continue,
                Err(error) => {
                    tracing::warn!(
                        target: "axiam::directory",
                        %tenant_id,
                        %error,
                        "an account could not be looked up by its directory identifier"
                    );
                    report.accounts_skipped += 1;
                    continue;
                }
            };
            report.accounts_examined += 1;
            let verdict = Verdict::Present(Box::new(entry));
            self.apply(
                session,
                &user,
                &verdict,
                RunKind::Incremental,
                &mut reports,
                &mut report,
            )
            .await;
        }

        // The watermark moves only when everything it covers was handled: a
        // bound hit or a skipped account leaves it and makes the next run full.
        let clean = changed.complete && report.accounts_skipped == 0;
        if clean {
            state.watermark = match kind {
                DirectoryKind::ActiveDirectory => next_watermark.or(Some(watermark)),
                DirectoryKind::OpenLdap => newest,
            };
        }
        state.full_required = !clean;
        state.reported_user_ids = sorted(reports.current);
        Ok(report)
    }

    // -----------------------------------------------------------------------
    // Applying one decision
    // -----------------------------------------------------------------------

    /// Decide for one account and carry it out. Never returns an error: a
    /// failure skips the account (counted) and the run goes on.
    async fn apply(
        &self,
        session: &DirectorySession,
        user: &User,
        verdict: &Verdict,
        run: RunKind,
        reports: &mut Reports,
        report: &mut TenantReport,
    ) {
        let tenant_id = session.config().tenant_id;
        match decide(&user.status, verdict) {
            Decision::Ignore => {
                // Disabled or gone *and* already inactive: nothing is waiting
                // for an administrator, so nothing stays reported.
                if run == RunKind::Incremental {
                    reports.current.remove(&user.id);
                }
            }
            Decision::Reappeared => {
                reports.current.insert(user.id);
                if !reports.known.contains(&user.id) {
                    reports.known.insert(user.id);
                    report.reappeared_reported += 1;
                    self.record(
                        tenant_id,
                        AUDIT_ACCOUNT_REAPPEARED,
                        Some(user.id),
                        AuditOutcome::Denied,
                        serde_json::json!({
                            "run": run.as_str(),
                            "reason": "the directory entry is present and enabled while the \
                                       account is inactive; sync never re-enables",
                            "action": "administrator action required",
                            "directory_external_id": user.directory_external_id,
                        }),
                    )
                    .await;
                }
            }
            Decision::Deactivate(reason) => {
                reports.current.remove(&user.id);
                match self.deactivate(session, user, reason, run).await {
                    Ok(true) => match reason {
                        Reason::Vanished => report.deactivated_vanished += 1,
                        Reason::Disabled => report.deactivated_disabled += 1,
                    },
                    Ok(false) => {}
                    Err(()) => report.accounts_skipped += 1,
                }
            }
            Decision::Refresh(entry) => {
                reports.current.remove(&user.id);
                if self
                    .refresh(session, user, &entry, run, report)
                    .await
                    .is_err()
                {
                    report.accounts_skipped += 1;
                }
            }
        }
    }

    /// Revoke, remove memberships, flip the status last. `Ok(true)` when this
    /// call made the account `Inactive`; `Ok(false)` when another did; `Err`
    /// when a step failed and the account was left `Active` for the next run.
    async fn deactivate(
        &self,
        session: &DirectorySession,
        user: &User,
        reason: Reason,
        run: RunKind,
    ) -> Result<bool, ()> {
        let tenant_id = session.config().tenant_id;
        let failed = |stage: &'static str, error: String| async move {
            tracing::error!(
                target: "axiam::directory",
                %tenant_id,
                user_id = %user.id,
                stage,
                %error,
                "deactivating a directory account failed; it is left as it was and the next \
                 run retries"
            );
            self.record(
                tenant_id,
                AUDIT_ACCOUNT_DEACTIVATED,
                Some(user.id),
                AuditOutcome::Failure,
                serde_json::json!({
                    "run": run.as_str(),
                    "reason": reason.as_str(),
                    "stage": stage,
                    "directory_external_id": user.directory_external_id,
                }),
            )
            .await;
        };

        // Through the repositories, so the session validation cache and the
        // revocation feed see it (as linking does, D-28).
        if let Err(error) = self
            .sessions
            .invalidate_user_sessions(tenant_id, user.id)
            .await
        {
            failed("sessions", error.to_string()).await;
            return Err(());
        }
        if let Err(error) = self
            .refresh_tokens
            .revoke_all_for_user(tenant_id, user.id)
            .await
        {
            failed("refresh_tokens", error.to_string()).await;
            return Err(());
        }
        // The D-30 mapper, so the decision cache is flushed and manual
        // memberships are never touched.
        let removed = match self
            .mapper
            .remove_directory_memberships(tenant_id, user.id)
            .await
        {
            Ok(outcome) => outcome.removed.len(),
            Err(error) => {
                failed("memberships", format!("{error:?}")).await;
                return Err(());
            }
        };
        // Last, and as one compare-and-set: from here `account_may_act` refuses
        // the account everywhere.
        match self
            .users
            .deactivate_directory_account(tenant_id, user.id)
            .await
        {
            Ok(Some(_)) => {
                self.record(
                    tenant_id,
                    AUDIT_ACCOUNT_DEACTIVATED,
                    Some(user.id),
                    AuditOutcome::Success,
                    serde_json::json!({
                        "run": run.as_str(),
                        "reason": reason.as_str(),
                        "sessions_and_refresh_tokens_revoked": true,
                        "directory_memberships_removed": removed,
                        "directory_external_id": user.directory_external_id,
                    }),
                )
                .await;
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(error) => {
                failed("status", error.to_string()).await;
                Err(())
            }
        }
    }

    /// Keep a present, enabled account in step with its entry: group mapping
    /// first (a failure there skips the user, changing nothing), then the
    /// attributes.
    async fn refresh(
        &self,
        session: &DirectorySession,
        user: &User,
        entry: &SyncEntry,
        run: RunKind,
        report: &mut TenantReport,
    ) -> Result<(), ()> {
        let tenant_id = session.config().tenant_id;

        // The DN is the one the directory returned for this very entry.
        match self
            .mapper
            .apply_for_user(tenant_id, user.id, &entry.identity.dn)
            .await
        {
            Ok(outcome) => {
                if outcome.changed() {
                    report.memberships_changed += 1;
                    self.record(
                        tenant_id,
                        AUDIT_GROUPS_MAPPED,
                        Some(user.id),
                        AuditOutcome::Success,
                        serde_json::json!({
                            "source": "sync",
                            "run": run.as_str(),
                            "groups_added": outcome.added,
                            "groups_removed": outcome.removed,
                            "added_count": outcome.added.len(),
                            "removed_count": outcome.removed.len(),
                            "manual_memberships_left": outcome.left_manual.len(),
                            "directory_groups_resolved": outcome.directory_groups_resolved,
                            "directory_groups_mapped": outcome.directory_groups_mapped,
                        }),
                    )
                    .await;
                }
            }
            Err(error) => {
                tracing::warn!(
                    target: "axiam::directory",
                    %tenant_id,
                    user_id = %user.id,
                    outcome = ?error,
                    "the group mapping could not be applied; the account is skipped"
                );
                self.record(
                    tenant_id,
                    AUDIT_SYNC_USER_SKIPPED,
                    Some(user.id),
                    AuditOutcome::Failure,
                    serde_json::json!({
                        "run": run.as_str(),
                        "reason": "group_mapping_not_applied",
                        "directory_external_id": user.directory_external_id,
                    }),
                )
                .await;
                return Err(());
            }
        }

        self.refresh_attributes(tenant_id, user, entry, run, report)
            .await
    }

    /// Update username, email and display name to the entry's, through the
    /// cleaners provisioning uses, skipping and auditing any change that would
    /// collide with another account.
    async fn refresh_attributes(
        &self,
        tenant_id: Uuid,
        user: &User,
        entry: &SyncEntry,
        run: RunKind,
        report: &mut TenantReport,
    ) -> Result<(), ()> {
        let cleaned = CleanedAttributes::from_identity(&entry.identity);
        let mut update = UpdateUser::default();
        let mut fields: Vec<&'static str> = Vec::new();

        // An attribute the entry lacks, or carries in a form that cannot be
        // cleaned, leaves the account's value alone.
        for (field, new, current) in [
            (
                "username",
                cleaned.username.as_deref(),
                user.username.as_str(),
            ),
            ("email", cleaned.email.as_deref(), user.email.as_str()),
        ] {
            let Some(new) = new else { continue };
            if new == current {
                continue;
            }
            match self
                .users
                .find_identity_collision_excluding(tenant_id, &[new.to_string()], user.id)
                .await
            {
                Ok(None) => {
                    if field == "username" {
                        update.username = Some(new.to_string());
                    } else {
                        update.email = Some(new.to_string());
                    }
                    fields.push(field);
                }
                Ok(Some(collision)) => {
                    report.attributes_skipped += 1;
                    self.record_skip(tenant_id, user, field, Some(collision), run)
                        .await;
                }
                Err(error) => {
                    tracing::warn!(
                        target: "axiam::directory",
                        %tenant_id,
                        user_id = %user.id,
                        %error,
                        "the collision probe failed; the account's attributes are left alone"
                    );
                    return Err(());
                }
            }
        }
        if let Some(name) = cleaned.display_name.as_deref() {
            let current = user
                .metadata
                .get("oidc")
                .and_then(|oidc| oidc.get("name"))
                .and_then(serde_json::Value::as_str);
            if current != Some(name) {
                let mut metadata = if user.metadata.is_object() {
                    user.metadata.clone()
                } else {
                    serde_json::json!({})
                };
                if !metadata
                    .get("oidc")
                    .is_some_and(serde_json::Value::is_object)
                {
                    metadata["oidc"] = serde_json::json!({});
                }
                metadata["oidc"]["name"] = serde_json::Value::String(name.to_string());
                update.metadata = Some(metadata);
                fields.push("display_name");
            }
        }
        if fields.is_empty() {
            return Ok(());
        }
        match self.users.update(tenant_id, user.id, update).await {
            Ok(_) => {
                report.attributes_updated += 1;
                self.record(
                    tenant_id,
                    AUDIT_ACCOUNT_UPDATED,
                    Some(user.id),
                    AuditOutcome::Success,
                    serde_json::json!({
                        "run": run.as_str(),
                        "fields": fields,
                        "directory_external_id": user.directory_external_id,
                    }),
                )
                .await;
                Ok(())
            }
            // Another account took the name between the probe and the write: a
            // collision after all.
            Err(AxiamError::AlreadyExists { .. }) => {
                report.attributes_skipped += 1;
                self.record_skip(tenant_id, user, "username_or_email", None, run)
                    .await;
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    target: "axiam::directory",
                    %tenant_id,
                    user_id = %user.id,
                    %error,
                    "updating a directory account's attributes failed; it is skipped"
                );
                Err(())
            }
        }
    }

    async fn record_skip(
        &self,
        tenant_id: Uuid,
        user: &User,
        attribute: &str,
        collision: Option<axiam_core::models::user::IdentityCollision>,
        run: RunKind,
    ) {
        self.record(
            tenant_id,
            AUDIT_SYNC_ATTRIBUTE_SKIPPED,
            Some(user.id),
            AuditOutcome::Denied,
            serde_json::json!({
                "run": run.as_str(),
                "reason": "collision",
                "attribute": attribute,
                "existing_user_id": collision.map(|c| c.user_id.to_string()),
                "existing_attribute": collision.map(|c| c.attribute.as_str()),
                "directory_external_id": user.directory_external_id,
            }),
        )
        .await;
    }

    /// One audit row, as the system. Never fails the run: the sink logs a row it
    /// cannot write.
    async fn record(
        &self,
        tenant_id: Uuid,
        action: &str,
        resource_id: Option<Uuid>,
        outcome: AuditOutcome,
        metadata: serde_json::Value,
    ) {
        self.audit
            .record(CreateAuditLogEntry {
                tenant_id,
                actor_id: Uuid::nil(),
                actor_type: ActorType::System,
                action: action.to_string(),
                resource_id,
                outcome,
                ip_address: None,
                metadata: Some(metadata),
            })
            .await;
    }
}

fn sorted(set: HashSet<Uuid>) -> Vec<Uuid> {
    let mut ids: Vec<Uuid> = set.into_iter().collect();
    ids.sort();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::directory::DirectoryIdentity;

    fn entry(disabled: bool) -> Verdict {
        Verdict::Present(Box::new(SyncEntry {
            identity: DirectoryIdentity {
                external_id: "id".into(),
                dn: "uid=x,dc=example,dc=com".into(),
                username: None,
                email: None,
                display_name: None,
            },
            disabled,
            change_value: None,
        }))
    }

    const ACTIONABLE: [UserStatus; 3] = [
        UserStatus::Active,
        UserStatus::PendingVerification,
        UserStatus::Locked,
    ];

    #[test]
    fn a_vanished_or_disabled_account_is_deactivated_from_any_live_status() {
        for status in &ACTIONABLE {
            assert_eq!(
                decide(status, &Verdict::Vanished),
                Decision::Deactivate(Reason::Vanished)
            );
            assert_eq!(
                decide(status, &entry(true)),
                Decision::Deactivate(Reason::Disabled)
            );
        }
    }

    #[test]
    fn a_present_enabled_account_is_refreshed() {
        for status in &ACTIONABLE {
            assert!(matches!(
                decide(status, &entry(false)),
                Decision::Refresh(_)
            ));
        }
    }

    /// D-31: sync never re-enables. An inactive account is at most *reported*,
    /// and only when its entry is present and enabled.
    #[test]
    fn an_inactive_account_is_never_acted_on_only_reported() {
        assert_eq!(
            decide(&UserStatus::Inactive, &entry(false)),
            Decision::Reappeared
        );
        assert_eq!(
            decide(&UserStatus::Inactive, &entry(true)),
            Decision::Ignore
        );
        assert_eq!(
            decide(&UserStatus::Inactive, &Verdict::Vanished),
            Decision::Ignore
        );
    }

    #[test]
    fn a_tombstone_is_never_touched() {
        for status in [UserStatus::Deleted, UserStatus::Anonymized] {
            for verdict in [Verdict::Vanished, entry(true), entry(false)] {
                assert_eq!(decide(&status, &verdict), Decision::Ignore);
            }
        }
    }

    /// The structural property behind "never re-enable, never `Deleted`": no
    /// decision exists that writes any status but `Inactive`.
    #[test]
    fn no_decision_leads_anywhere_but_inactive() {
        for status in [
            UserStatus::Active,
            UserStatus::Inactive,
            UserStatus::Locked,
            UserStatus::PendingVerification,
            UserStatus::Anonymized,
            UserStatus::Deleted,
        ] {
            for verdict in [Verdict::Vanished, entry(true), entry(false)] {
                match decide(&status, &verdict) {
                    Decision::Ignore
                    | Decision::Deactivate(_)
                    | Decision::Reappeared
                    | Decision::Refresh(_) => {}
                }
            }
        }
    }

    #[test]
    fn the_valve_needs_both_more_than_the_percentage_and_at_least_the_floor() {
        let limits = SyncLimits::default();
        // 5 of 40 = 12.5 %: both conditions.
        assert!(valve_trips(5, 40, &limits));
        // 4 of 10 = 40 %, but under the floor of 5.
        assert!(!valve_trips(4, 10, &limits));
        // 5 of 50 = exactly 10 %: not *more than*.
        assert!(!valve_trips(5, 50, &limits));
        // 6 of 50 = 12 %.
        assert!(valve_trips(6, 50, &limits));
        // 5 of 60 = 8.3 %.
        assert!(!valve_trips(5, 60, &limits));
        // Nothing to deactivate never trips, whatever the size.
        assert!(!valve_trips(0, 0, &limits));
        assert!(!valve_trips(0, 1000, &limits));
        // Everyone of a hundred.
        assert!(valve_trips(100, 100, &limits));
    }

    #[test]
    fn the_valve_does_not_overflow() {
        assert!(!valve_trips(usize::MAX, usize::MAX, &SyncLimits::default()));
    }

    fn state() -> DirectorySyncState {
        DirectorySyncState::new(Uuid::nil())
    }

    #[test]
    fn the_first_run_is_full_and_so_is_one_without_a_watermark_or_after_a_skip() {
        let limits = SyncLimits::default();
        let now = Utc::now();
        assert_eq!(choose_run(&state(), now, &limits), RunKind::Full);

        let mut s = state();
        s.last_full_run_at = Some(now - chrono::Duration::hours(1));
        s.watermark = Some("42".into());
        assert_eq!(choose_run(&s, now, &limits), RunKind::Incremental);

        let mut no_mark = s.clone();
        no_mark.watermark = None;
        assert_eq!(choose_run(&no_mark, now, &limits), RunKind::Full);

        let mut skipped = s.clone();
        skipped.full_required = true;
        assert_eq!(choose_run(&skipped, now, &limits), RunKind::Full);
    }

    #[test]
    fn a_full_run_is_due_a_day_after_the_last() {
        let limits = SyncLimits::default();
        let now = Utc::now();
        let mut s = state();
        s.watermark = Some("42".into());
        s.last_full_run_at = Some(now - chrono::Duration::hours(23));
        assert_eq!(choose_run(&s, now, &limits), RunKind::Incremental);
        s.last_full_run_at = Some(now - chrono::Duration::hours(25));
        assert_eq!(choose_run(&s, now, &limits), RunKind::Full);
    }

    #[test]
    fn the_later_watermark_compares_numbers_as_numbers() {
        assert_eq!(later_watermark("99", "100"), "100");
        assert_eq!(later_watermark("1000", "99"), "1000");
        assert_eq!(
            later_watermark("20261003120000Z", "20261003130000Z"),
            "20261003130000Z"
        );
        assert_eq!(
            later_watermark("20261003130000Z", "20261003120000Z"),
            "20261003130000Z"
        );
    }

    #[test]
    fn a_failure_message_names_counts_and_tags_only() {
        let mut summary = SyncSummary::default();
        assert!(summary.failure_message().is_none());
        summary.failures.push((
            Uuid::new_v4(),
            SyncError::Directory(DirectoryAuthError::Unavailable),
        ));
        summary.failures.push((
            Uuid::new_v4(),
            SyncError::SafetyValve {
                would_deactivate: 7,
                directory_accounts: 20,
            },
        ));
        summary
            .reports
            .push(TenantReport::new(Uuid::new_v4(), RunKind::Full));
        assert_eq!(
            summary.failure_message().as_deref(),
            Some("directory sync failed for 2 of 3 tenants (directory_unavailable, safety_valve)")
        );
    }
}

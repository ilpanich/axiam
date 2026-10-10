//! Scheduled-job liveness tracking (T-129).
//!
//! Every background sweep records the outcome of each run here, and
//! `GET /health/jobs` reads it back. The threat this closes is not a job that
//! errors — those were already logged — but a job that stops running at all:
//! GDPR erasure and certificate expiry fail silently by simply not happening,
//! and nothing in an error-driven monitoring setup ever fires.
//!
//! Deliberately in-memory and per-process. A restart resets the history, and
//! two replicas each report their own. That is the correct scope: this answers
//! "is *this* process's scheduler alive", which is what a per-pod alert needs.
//! Aggregating across replicas is the monitoring system's job, and persisting
//! it would make the health of the sweep depend on the datastore the sweep is
//! there to maintain.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_api_rest::health::{JobHealthReporter, JobStatus, RequestAuditHealth};
use axiam_audit::RequestAuditLoss;
use chrono::{DateTime, Utc};

/// How many expected runs a job may miss before it is reported as stalled.
///
/// Three rather than one: a sweep that overruns its interval, or a tick
/// skipped under load, is normal and must not page anyone. Three consecutive
/// missed intervals is not noise.
const STALL_INTERVALS: u32 = 3;

/// The jobs registered at start-up, so a job that has never run once still
/// appears in `GET /health/jobs` (T-129). One list plus [`REVOCATION_FEED_JOB`],
/// read by `main` through [`sweep_jobs`]; a test pins that every name the cleanup
/// loop records is in one or the other.
pub const SWEEP_JOBS: &[&str] = &[
    "saml_assertion_replay",
    "federation_login_state",
    // P23W4-06 (#535): the SSO hand-off codes.
    "sso_handoff_code",
    "saml_authn_request",
    // G-2 (T23.2.4): the single-logout participant rows and logout runs.
    "saml_sp_session",
    "saml_logout_run",
    // G-3 (T23.3.5): the directory sync job.
    "directory_sync",
    // G-6 (T23.6.3, D-58): the outbound SCIM reconciliation.
    "scim_reconcile",
    // G-5 (T23.5.3): the SSF poll/hold buffer's seven-day expiry.
    "ssf_event_buffer",
    // G-5 (T23.5.3, D-53 (1)): the step-up record's ten-minute expiry.
    "ssf_step_up",
    // G-7 (T23.7.1): the CIBA pending-request store's expiry.
    "ciba_request",
    "amqp_nonce_replay",
    "gdpr_purge",
    "gdpr_export",
    "audit_retention",
    // P23W4-06 (#535): the dynamic-registration sweeps. DCR and CIMD are tenant
    // settings, not a process switch, so the sweeps run on every start (each
    // tenant's TTL decides what they touch) and are registered on every start.
    "dcr_unused_clients",
    "cimd_unused_clients",
    "dcr_registration_tokens",
    // #523 (D-4): deleted tenants' data, purged in user-erasure order.
    "tenant_purge",
    // T-470: `vault_pki` revocations Vault does not have yet.
    "vault_revocation",
];

/// The revocation-feed prune (T-39/T-143, P23W4-06). The one sweep in the loop
/// that a process switch (`auth.revocation_feed_enabled`) turns on: the loop
/// records it only when the feed is on, so it is registered only then. A
/// deployment without the feed has no such job, and "not in the list" is how
/// `/health/jobs` says so.
pub const REVOCATION_FEED_JOB: &str = "revocation_feed";

/// Every job to register at start (T-129): [`SWEEP_JOBS`], and the revocation
/// feed's prune when `revocation_feed_enabled`.
pub fn sweep_jobs(revocation_feed_enabled: bool) -> impl Iterator<Item = &'static str> {
    SWEEP_JOBS
        .iter()
        .copied()
        .chain(revocation_feed_enabled.then_some(REVOCATION_FEED_JOB))
}

#[derive(Default, Clone)]
struct Entry {
    last_success_at: Option<DateTime<Utc>>,
    last_failure_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    consecutive_failures: u32,
}

/// Shared, cloneable handle to the job-status table.
#[derive(Clone)]
pub struct JobHealth {
    inner: Arc<Mutex<BTreeMap<&'static str, Entry>>>,
    /// The sweep interval, used to decide what counts as stalled.
    interval: Duration,
    /// When the process started, so a job that has never run once can be
    /// distinguished from one that has stopped running. Without this, every
    /// job reads as stalled for the first few seconds after boot.
    started_at: DateTime<Utc>,
    /// The request-audit middleware's loss counters (T-108), reported beside
    /// the jobs. Not a job: it has no interval and nothing to stall.
    request_audit: Option<RequestAuditLoss>,
}

impl JobHealth {
    /// Create a tracker for sweeps running every `interval`.
    pub fn new(interval: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
            interval,
            started_at: Utc::now(),
            request_audit: None,
        }
    }

    /// Report `loss` as `request_audit` on `GET /health/jobs` (T-108).
    pub fn with_request_audit(mut self, loss: RequestAuditLoss) -> Self {
        self.request_audit = Some(loss);
        self
    }

    /// Register a job so it appears in the snapshot before its first run.
    ///
    /// Without this a job that has never once succeeded would be absent
    /// entirely, and "not in the list" is indistinguishable from "not
    /// deployed" — precisely the silence T-129 is about.
    pub fn register(&self, name: &'static str) {
        self.lock().entry(name).or_default();
    }

    /// Record a completed run.
    pub fn record(&self, name: &'static str, outcome: Result<(), String>) {
        let mut guard = self.lock();
        let entry = guard.entry(name).or_default();
        match outcome {
            Ok(()) => {
                entry.last_success_at = Some(Utc::now());
                entry.consecutive_failures = 0;
                entry.last_error = None;
            }
            Err(e) => {
                entry.last_failure_at = Some(Utc::now());
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                entry.last_error = Some(e);
            }
        }
    }

    /// A poisoned mutex must not take the server down: this table is
    /// diagnostics, and panicking here would turn a reporting bug into an
    /// outage. Recovering the guard keeps whatever data survived.
    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<&'static str, Entry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `entry` has gone longer than [`STALL_INTERVALS`] without a
    /// successful run, measured from process start when it has never had one.
    fn is_stalled(&self, entry: &Entry, now: DateTime<Utc>) -> bool {
        let budget = match chrono::Duration::from_std(self.interval * STALL_INTERVALS) {
            Ok(d) => d,
            // Only reachable with an absurd configured interval; treating that
            // as "never stalled" is the safe direction — a false alarm on a
            // liveness signal is how alerts get muted.
            Err(_) => return false,
        };
        let reference = entry.last_success_at.unwrap_or(self.started_at);
        now.signed_duration_since(reference) > budget
    }
}

impl JobHealthReporter for JobHealth {
    fn snapshot(&self) -> Vec<JobStatus> {
        let now = Utc::now();
        self.lock()
            .iter()
            .map(|(name, entry)| JobStatus {
                name: (*name).to_string(),
                last_success_at: entry.last_success_at.map(|t| t.to_rfc3339()),
                last_failure_at: entry.last_failure_at.map(|t| t.to_rfc3339()),
                last_error: entry.last_error.clone(),
                consecutive_failures: entry.consecutive_failures,
                stalled: self.is_stalled(entry, now),
            })
            .collect()
    }

    fn request_audit(&self) -> Option<RequestAuditHealth> {
        let s = self.request_audit.as_ref()?.snapshot();
        Some(RequestAuditHealth {
            dropped: s.dropped,
            failed: s.failed,
            dead_lettered: s.dead_lettered,
            not_recoverable: s.not_recoverable,
            dead_letter_configured: s.dead_letter_configured,
            dead_letter_full: s.dead_letter_full,
            last_loss_at: s.last_loss_at.map(|t| t.to_rfc3339()),
            recent_loss: s.recent_loss,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> JobHealth {
        JobHealth::new(Duration::from_secs(60))
    }

    /// Every job name `cleanup.rs` hands to `Self::record`, read from its source.
    fn recorded_by_the_cleanup_loop() -> Vec<&'static str> {
        const CALL: &str = "&self.job_health,";
        let source = include_str!("cleanup.rs");
        let names: Vec<_> = source
            .match_indices(CALL)
            .filter_map(|(at, _)| {
                let rest = source[at + CALL.len()..].trim_start().strip_prefix('"')?;
                rest.split('"').next()
            })
            .collect();
        // A scan that finds nothing would pass every assertion below vacuously.
        assert!(names.len() >= 15, "the scan reads the loop: {names:?}");
        names
    }

    /// T-384, T-129 (P23W4-06): every sweep the cleanup loop records is
    /// registered, so `/health/jobs` lists it before its first run. A job the
    /// loop records and the list forgets reads as "not deployed" — the silence
    /// T-129 exists to break — and each of the five that did (`sso_handoff_code`,
    /// `revocation_feed`, `dcr_unused_clients`, `cimd_unused_clients`,
    /// `dcr_registration_tokens`) did so until #535.
    #[test]
    fn the_slo_sweeps_are_recorded_by_the_cleanup_loop_and_registered() {
        let recorded = recorded_by_the_cleanup_loop();
        // The single-logout, SSF, SCIM and CIBA sweeps, named so that dropping
        // one from the loop fails here and not only by absence.
        for job in [
            "saml_sp_session",
            "saml_logout_run",
            "ssf_event_buffer",
            "ssf_step_up",
            "scim_reconcile",
            "ciba_request",
            // #523 (D-4): the deleted tenants' purge.
            "tenant_purge",
            // T-470: revocations forwarded to Vault.
            "vault_revocation",
        ] {
            assert!(recorded.contains(&job), "{job} is swept by the loop");
            assert!(SWEEP_JOBS.contains(&job), "{job} is registered");
        }

        // The rule: with every switch on, nothing the loop records is missing,
        // and nothing is registered that the loop never records.
        let registered: Vec<_> = sweep_jobs(true).collect();
        for job in &recorded {
            assert!(
                registered.contains(job),
                "{job} is recorded but not registered"
            );
        }
        for job in &registered {
            assert!(
                recorded.contains(job),
                "{job} is registered but never recorded"
            );
        }
    }

    /// P23W4-06 (#535): the five jobs are on the snapshot before their first
    /// run, and the revocation feed's prune is there only when the feed is on —
    /// the loop does not record it otherwise.
    #[test]
    fn the_registered_sweeps_are_listed_before_their_first_run() {
        let five = [
            "sso_handoff_code",
            "revocation_feed",
            "dcr_unused_clients",
            "cimd_unused_clients",
            "dcr_registration_tokens",
        ];
        let snapshot = |feed: bool| {
            let h = tracker();
            for job in sweep_jobs(feed) {
                h.register(job);
            }
            h.snapshot()
        };

        let on = snapshot(true);
        for job in five {
            let status = on.iter().find(|s| s.name == job).expect(job);
            assert!(status.last_success_at.is_none() && status.last_failure_at.is_none());
            assert!(!status.stalled, "{job} has just started");
        }
        let off = snapshot(false);
        assert!(!off.iter().any(|s| s.name == "revocation_feed"));
        for job in five.iter().filter(|j| **j != "revocation_feed") {
            assert!(off.iter().any(|s| s.name == *job), "{job} is always on");
        }
    }

    /// T-108: the request-audit counters ride on the reporter beside the jobs,
    /// and are absent from a tracker that was not given them.
    #[tokio::test]
    async fn the_snapshot_reports_the_request_audit_loss_counters() {
        use axiam_audit::DeadLetterWriter;
        use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};

        assert!(tracker().request_audit().is_none());

        let loss = RequestAuditLoss::new(DeadLetterWriter::disabled());
        let h = tracker().with_request_audit(loss.clone());
        let before = h.request_audit().expect("counted");
        assert_eq!((before.dropped, before.failed), (0, 0));
        assert!(!before.recent_loss && before.last_loss_at.is_none());

        let entry = || CreateAuditLogEntry {
            tenant_id: uuid::Uuid::nil(),
            actor_id: uuid::Uuid::nil(),
            actor_type: ActorType::System,
            action: "GET /x".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        };
        loss.record_dropped(entry(), "audit channel full");
        loss.record_failed(entry(), &"datastore down");
        loss.record_failed(entry(), &"datastore down");

        let after = h.request_audit().expect("counted");
        assert_eq!((after.dropped, after.failed), (1, 2));
        assert_eq!(after.not_recoverable, 3, "no file: all three are gone");
        assert!(!after.dead_letter_configured);
        assert!(!after.dead_letter_full);
        assert!(after.recent_loss && after.last_loss_at.is_some());
    }

    #[test]
    fn a_registered_job_appears_before_it_has_ever_run() {
        let h = tracker();
        h.register("gdpr_purge");
        let snap = h.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].name, "gdpr_purge");
        assert!(snap[0].last_success_at.is_none());
        assert!(!snap[0].stalled, "a job that just started is not stalled");
    }

    #[test]
    fn success_clears_the_failure_streak_and_the_error_text() {
        let h = tracker();
        h.record("audit_retention", Err("db down".into()));
        h.record("audit_retention", Err("db down".into()));
        assert_eq!(h.snapshot()[0].consecutive_failures, 2);
        assert_eq!(h.snapshot()[0].last_error.as_deref(), Some("db down"));

        h.record("audit_retention", Ok(()));
        let s = &h.snapshot()[0];
        assert_eq!(s.consecutive_failures, 0);
        assert!(s.last_error.is_none(), "a stale error reads as a live one");
        // The failure timestamp is kept on purpose: "it is working now, and it
        // last broke at T" is more useful than pretending it never broke.
        assert!(s.last_failure_at.is_some());
    }

    #[test]
    fn failures_alone_do_not_mark_a_job_stalled() {
        // Stalled means "not running". A job that runs and fails every time is
        // a different condition, reported by consecutive_failures, and
        // conflating them would hide whichever one you were not looking for.
        let h = tracker();
        for _ in 0..10 {
            h.record("cert_expiry", Err("boom".into()));
        }
        let s = &h.snapshot()[0];
        assert!(s.consecutive_failures >= 10);
        assert!(!s.stalled);
    }

    #[test]
    fn a_job_is_stalled_once_it_misses_the_configured_number_of_intervals() {
        let h = tracker();
        h.register("gdpr_purge");
        let now = Utc::now();
        let entry = Entry {
            last_success_at: Some(now - chrono::Duration::seconds(61 * 3)),
            ..Default::default()
        };
        assert!(h.is_stalled(&entry, now));

        let recent = Entry {
            last_success_at: Some(now - chrono::Duration::seconds(61)),
            ..Default::default()
        };
        assert!(
            !h.is_stalled(&recent, now),
            "one missed tick is normal under load and must not alert"
        );
    }

    #[test]
    fn a_job_that_never_succeeds_becomes_stalled_relative_to_process_start() {
        // The case that matters most: a sweep whose very first run never
        // happens. Measuring from process start is what makes that visible,
        // since there is no last_success_at to measure from.
        let h = tracker();
        h.register("gdpr_purge");
        let entry = Entry::default();
        let much_later = h.started_at + chrono::Duration::seconds(61 * 4);
        assert!(h.is_stalled(&entry, much_later));
    }
}

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

use axiam_api_rest::health::{JobHealthReporter, JobStatus};
use chrono::{DateTime, Utc};

/// How many expected runs a job may miss before it is reported as stalled.
///
/// Three rather than one: a sweep that overruns its interval, or a tick
/// skipped under load, is normal and must not page anyone. Three consecutive
/// missed intervals is not noise.
const STALL_INTERVALS: u32 = 3;

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
}

impl JobHealth {
    /// Create a tracker for sweeps running every `interval`.
    pub fn new(interval: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
            interval,
            started_at: Utc::now(),
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker() -> JobHealth {
        JobHealth::new(Duration::from_secs(60))
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

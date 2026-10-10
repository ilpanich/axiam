//! Accounting for request-audit rows that did not reach the datastore (T-108).
//!
//! The request-audit middleware hands each row to a bounded channel and a
//! worker appends it. A row is lost in two places: the channel is full when the
//! request finishes (a slow datastore, a burst), or the append fails (the
//! datastore is down or rejects the row). Both used to leave one log line each,
//! the second at WARN, and nothing an operator could alert on.
//!
//! [`RequestAuditLoss`] is the one place both are recorded. Per loss it:
//!
//! 1. counts it (`dropped` or `failed`, monotonic since the process started),
//! 2. hands the row to the [`DeadLetterWriter`] — a non-blocking queue, so the
//!    request path does no file I/O — and
//! 3. emits one ERROR line naming the counts, at most once per
//!    [`REPORT_INTERVAL`], so a flood is one line a minute rather than one per
//!    request.
//!
//! `GET /health/jobs` reads [`RequestAuditLoss::snapshot`].

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use axiam_core::models::audit::CreateAuditLogEntry;
use chrono::{DateTime, Utc};

use crate::dead_letter::DeadLetterWriter;

/// The least time between two ERROR lines about lost rows.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(60);

/// How long after the last loss `/health/jobs` still reports `recent_loss`.
///
/// The counters never go down, so they cannot say "it stopped". This window can:
/// a loss within it turns the endpoint's `status` to `degraded`, and the status
/// returns to `ok` by itself once the datastore has been taking rows again for
/// this long.
pub const RECENT_LOSS_WINDOW: Duration = Duration::from_secs(15 * 60);

/// `last_report_ms` before any line has been logged.
const NEVER: u64 = u64::MAX;

/// A point-in-time reading of [`RequestAuditLoss`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAuditLossSnapshot {
    /// Rows refused because the channel was full (or closed) when the request
    /// finished. Since process start.
    pub dropped: u64,
    /// Rows the worker took off the channel and could not append. Since process
    /// start.
    pub failed: u64,
    /// Lost rows written to the dead-letter file.
    pub dead_lettered: u64,
    /// Lost rows kept nowhere: no file is configured, or the file's queue was
    /// full, or the file had reached its budget, or it could not be written.
    pub not_recoverable: u64,
    /// Whether a dead-letter file is configured.
    pub dead_letter_configured: bool,
    /// Whether the dead-letter file has reached the request rows' share of its
    /// budget, so lost rows are refused by it (R1W2-02).
    pub dead_letter_full: bool,
    /// When the most recent row was lost, if any was.
    pub last_loss_at: Option<DateTime<Utc>>,
    /// Whether a row was lost within [`RECENT_LOSS_WINDOW`].
    pub recent_loss: bool,
}

struct Inner {
    dropped: AtomicU64,
    failed: AtomicU64,
    /// Unix milliseconds of the latest loss; 0 when none.
    last_loss_ms: AtomicI64,
    /// Milliseconds since `base` of the latest ERROR line; [`NEVER`] when none.
    last_report_ms: AtomicU64,
    /// Lost rows (dropped + failed) at the latest ERROR line, for the delta.
    reported_total: AtomicU64,
    base: Instant,
    dead_letter: DeadLetterWriter,
}

/// Shared handle to the request-audit loss counters. Cloning shares them.
#[derive(Clone)]
pub struct RequestAuditLoss {
    inner: Arc<Inner>,
}

impl RequestAuditLoss {
    /// Counters at zero, routing lost rows to `dead_letter`.
    pub fn new(dead_letter: DeadLetterWriter) -> Self {
        Self {
            inner: Arc::new(Inner {
                dropped: AtomicU64::new(0),
                failed: AtomicU64::new(0),
                last_loss_ms: AtomicI64::new(0),
                last_report_ms: AtomicU64::new(NEVER),
                reported_total: AtomicU64::new(0),
                base: Instant::now(),
                dead_letter,
            }),
        }
    }

    /// The dead-letter writer lost rows go to.
    pub fn dead_letter(&self) -> &DeadLetterWriter {
        &self.inner.dead_letter
    }

    /// A row could not be queued: the channel was full or closed. Called on the
    /// request path, so nothing here waits.
    pub fn record_dropped(&self, entry: CreateAuditLogEntry, reason: &'static str) {
        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
        self.lose(entry, reason, &reason);
    }

    /// The worker took a row off the channel and the append failed.
    pub fn record_failed(&self, entry: CreateAuditLogEntry, error: &dyn std::fmt::Display) {
        self.inner.failed.fetch_add(1, Ordering::Relaxed);
        self.lose(entry, "append failed", error);
    }

    fn lose(
        &self,
        entry: CreateAuditLogEntry,
        reason: &'static str,
        detail: &dyn std::fmt::Display,
    ) {
        self.inner
            .last_loss_ms
            .store(Utc::now().timestamp_millis(), Ordering::Relaxed);
        self.inner.dead_letter.submit(entry);
        let now_ms = self.inner.base.elapsed().as_millis() as u64;
        if self.should_report(now_ms) {
            self.report(reason, detail);
        }
    }

    /// Claim the right to log at `now_ms`; at most one caller per interval wins.
    fn should_report(&self, now_ms: u64) -> bool {
        let last = self.inner.last_report_ms.load(Ordering::Relaxed);
        if last != NEVER && now_ms.saturating_sub(last) < REPORT_INTERVAL.as_millis() as u64 {
            return false;
        }
        self.inner
            .last_report_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    fn report(&self, reason: &'static str, detail: &dyn std::fmt::Display) {
        let s = self.snapshot();
        let total = s.dropped + s.failed;
        let since_last_report = total - self.inner.reported_total.swap(total, Ordering::Relaxed);
        tracing::error!(
            target: "axiam.audit.loss",
            reason,
            detail = %detail,
            lost_since_last_report = since_last_report,
            dropped_total = s.dropped,
            failed_total = s.failed,
            dead_lettered_total = s.dead_lettered,
            not_recoverable_total = s.not_recoverable,
            dead_letter_configured = s.dead_letter_configured,
            dead_letter_full = s.dead_letter_full,
            "request audit rows are being lost (this line is logged at most once a minute; \
             GET /health/jobs `request_audit` carries the running counts)"
        );
    }

    /// The counters now.
    pub fn snapshot(&self) -> RequestAuditLossSnapshot {
        let dropped = self.inner.dropped.load(Ordering::Relaxed);
        let failed = self.inner.failed.load(Ordering::Relaxed);
        let dead_letter = &self.inner.dead_letter;
        let configured = dead_letter.is_configured();
        let last_ms = self.inner.last_loss_ms.load(Ordering::Relaxed);
        let last_loss_at = (last_ms != 0)
            .then(|| DateTime::<Utc>::from_timestamp_millis(last_ms))
            .flatten();
        let recent_loss = last_loss_at.is_some_and(|t| {
            Utc::now().signed_duration_since(t)
                < chrono::Duration::from_std(RECENT_LOSS_WINDOW).unwrap_or(chrono::Duration::MAX)
        });
        RequestAuditLossSnapshot {
            dropped,
            failed,
            dead_lettered: dead_letter.written(),
            // With no file every lost row is unrecoverable; with one, only the
            // rows the file's writer could not keep.
            not_recoverable: if configured {
                dead_letter.lost()
            } else {
                dropped + failed
            },
            dead_letter_configured: configured,
            dead_letter_full: dead_letter.is_full(),
            last_loss_at,
            recent_loss,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_is_rate_limited_to_one_per_interval() {
        let loss = RequestAuditLoss::new(DeadLetterWriter::disabled());
        let step = REPORT_INTERVAL.as_millis() as u64;
        assert!(loss.should_report(5), "the first loss is reported at once");
        assert!(!loss.should_report(5 + step - 1), "inside the interval");
        assert!(loss.should_report(5 + step), "after the interval");
        assert!(!loss.should_report(5 + step + 1));
    }
}

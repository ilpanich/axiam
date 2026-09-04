//! Visibility for a `TRUSTED_HOPS` misconfiguration (R-4, narrows T-212/T-233).
//!
//! # Why this exists
//!
//! Both rate-limit key extractors fall through to the peer address when
//! `trusted_hops >= hops.len()` — an `X-Forwarded-For` header that cannot be
//! trusted is ignored entirely, rather than indexed into. That fallback is
//! **correct** and must stay: it is what stops a client rotating a single-hop
//! XFF to mint a fresh bucket per request (SECHRD-03 / D-01d).
//!
//! What was wrong is that it happened **silently**. That silence is exactly how
//! the off-by-one T-212 describes went unnoticed: with `trusted_hops` one too
//! high, every client keyed to the proxy's address, the whole deployment shared
//! one bucket, and nothing in any log said so. The failure looks like "the rate
//! limit is mysteriously strict", which is the kind of thing an operator raises
//! the limit to fix.
//!
//! So the fallback now leaves two traces:
//!
//! - a **once-per-process** `WARN` naming the hop count seen, the `trusted_hops`
//!   in force and the rule (`proxies − 1`), so the first request that hits it
//!   explains itself in the log an operator is already reading;
//! - a counter, so a dashboard can show that every request is keying on the
//!   peer rather than on the client.
//!
//! The `WARN` is once per process on purpose. The condition fires on *every*
//! request under a misconfiguration, so one line per request would be a log
//! flood proportional to traffic — and the second line adds nothing the first
//! did not say.
//!
//! # Why a counter and not a metrics crate
//!
//! This workspace has no metrics facade. `axiam_db::metrics` and
//! `axiam_amqp::reactor::metrics` are the pattern: a process-wide relaxed
//! atomic, readable from tests and from a future `/metrics` endpoint, with the
//! Prometheus name it will be exported under written down beside it. A second
//! convention here would leave this boundary measurable by different means than
//! everything around it.
//!
//! The metric is one series with a `protocol` label:
//! `axiam_rate_limit_xff_discarded_total{protocol="rest"}` here, and
//! `{protocol="grpc"}` from the identical counter in
//! `axiam_api_grpc::middleware::rate_limit`. The two crates are siblings —
//! neither may depend on the other — so the label is expressed as two counters
//! that an exporter renders as one labelled series.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// `axiam_rate_limit_xff_discarded_total{protocol="rest"}`.
static XFF_DISCARDED: AtomicU64 = AtomicU64::new(0);

/// Whether the explanatory `WARN` has already been emitted this process.
static WARNED: AtomicBool = AtomicBool::new(false);

/// How many REST requests arrived with an `X-Forwarded-For` header that
/// `trusted_hops` discarded, so the key came from the peer address instead.
///
/// Metric name: `axiam_rate_limit_xff_discarded_total{protocol="rest"}`.
///
/// **A non-zero value is not automatically a fault.** It is a fault when it
/// tracks total request volume: that means the header is present on every
/// request and trusted on none, i.e. `trusted_hops` is too high for this
/// deployment's proxy count and every client shares one bucket. A handful,
/// against a much larger request count, is a few clients sending their own XFF
/// to a server that correctly ignores it.
pub fn xff_discarded() -> u64 {
    XFF_DISCARDED.load(Ordering::Relaxed)
}

/// Record that a present `X-Forwarded-For` header was discarded because
/// `trusted_hops` exceeded the hops available, and explain it once.
///
/// Called only on that path — a request with **no** header does not come
/// through here, because a client with no proxy in front of it is not a
/// misconfiguration and counting it would bury the signal.
pub(crate) fn record_discarded_xff(hops_seen: usize, trusted_hops: usize) {
    XFF_DISCARDED.fetch_add(1, Ordering::Relaxed);

    if !WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            protocol = "rest",
            hops_seen,
            trusted_hops,
            "X-Forwarded-For was DISCARDED and the rate-limit key fell back to the \
             connection peer: the header carried {hops_seen} hop(s) but \
             AXIAM__RATE_LIMIT__TRUSTED_HOPS is {trusted_hops}, which trusts them all. \
             If this fires on every request, every client is sharing ONE bucket keyed \
             on the proxy's address. The rule is trusted_hops = proxies - 1 \
             (one proxy in front of the server means 0). Counted as \
             axiam_rate_limit_xff_discarded_total{{protocol=\"rest\"}}; logged once per \
             process."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests below.
    ///
    /// Both statics are process-global and `cargo test` runs these on threads
    /// of one process, so a test that resets them races any test reading them.
    /// The bug that produces is intermittent and looks like a real regression,
    /// which is the worst kind to leave in a suite that guards an observability
    /// signal.
    fn lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Reset both statics so a test can assert from a known point.
    fn reset() {
        XFF_DISCARDED.store(0, Ordering::Relaxed);
        WARNED.store(false, Ordering::Relaxed);
    }

    /// The counter counts every discard; the `WARN` latch fires once.
    ///
    /// Both halves matter and they fail differently. A counter that only
    /// incremented on the first discard would show `1` under a misconfiguration
    /// that is dropping the header on every request — the exact opposite of the
    /// signal R-4 exists to give, which is "this number tracks request volume".
    /// A `WARN` that fired every time would be a log flood proportional to
    /// traffic, which is how an operator learns to filter the line out.
    #[test]
    fn every_discard_is_counted_and_only_the_first_is_warned_about() {
        let _guard = lock();
        reset();

        for _ in 0..5 {
            record_discarded_xff(1, 3);
        }
        assert_eq!(
            xff_discarded(),
            5,
            "the counter must track every discard, not only the first"
        );
        assert!(
            WARNED.load(Ordering::Relaxed),
            "the first discard must arm the once-per-process latch"
        );
    }

    /// A fresh process warns again — the latch is per-process, not permanent
    /// state on disk, so a restart re-explains the misconfiguration.
    #[test]
    fn the_warning_latch_is_per_process() {
        let _guard = lock();
        reset();
        assert!(!WARNED.load(Ordering::Relaxed));
        record_discarded_xff(2, 4);
        assert!(WARNED.load(Ordering::Relaxed));
        reset();
        assert!(
            !WARNED.load(Ordering::Relaxed),
            "a new process must be able to explain itself again"
        );
    }
}

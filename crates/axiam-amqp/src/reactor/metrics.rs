//! Reactor dispatch counters (X1 / R2.2).
//!
//! # Why atomics and a `tracing` event rather than a metrics crate
//!
//! This workspace has no metrics facade — `axiam-db::metrics` is the pattern
//! every other instrumented boundary follows: process-wide relaxed atomics,
//! readable from tests and from a future `/metrics` endpoint, plus one
//! structured `tracing` event per interesting transition so an operator gets
//! the same fact in the log stream without a scrape. Introducing a second
//! convention here would leave the reactor path measurable by different means
//! than everything around it.
//!
//! # The counters that matter, and why each exists
//!
//! `X1.2` requires that **every timeout is audited and surfaced as a metric**.
//! A timeout is audited by the gate and counted by [`record_failure`]; the
//! reason both are needed is that they answer different questions. The audit
//! record says *which* reactor failed on *which* operation and is queryable per
//! tenant; the counter says *how often*, cheaply, without reading the audit
//! table — which is the difference between a health panel that can refresh
//! every few seconds and one that cannot.
//!
//! [`dispatches`] counts only events that actually reached a chain. An event
//! with no registered reactor never increments anything: the whole point of the
//! hot-path exclusion argument is that the un-hooked path stays free, and a
//! counter increment on it would be a (tiny) measurable delta where the plan
//! promises zero.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::reactor::dispatcher::DispatchFailure;

macro_rules! counters {
    ($($vis:vis $name:ident => $static_name:ident, $metric:literal, $doc:literal;)*) => {
        $(
            static $static_name: AtomicU64 = AtomicU64::new(0);
            #[doc = $doc]
            #[doc = ""]
            #[doc = concat!("Metric name: `", $metric, "`.")]
            $vis fn $name() -> u64 {
                $static_name.load(Ordering::Relaxed)
            }
        )*
    };
}

counters! {
    pub dispatches => DISPATCHES, "axiam_reactor_dispatch_total",
        "Interceptor chains actually run (at least one enabled reactor matched).";
    pub denials => DENIALS, "axiam_reactor_deny_total",
        "Chains whose composed outcome refused the underlying operation.";
    pub mutations => MUTATIONS, "axiam_reactor_mutate_total",
        "Chains whose composed outcome carried an allow-listed patch.";
    pub step_ups => STEP_UPS, "axiam_reactor_require_mfa_total",
        "Chains that demanded step-up authentication (`login.post_auth` only).";
    pub timeouts => TIMEOUTS, "axiam_reactor_timeout_total",
        "Reactors that did not answer inside their effective window.";
    pub budget_exhaustions => BUDGET_EXHAUSTIONS, "axiam_reactor_budget_exhausted_total",
        "Reactors never contacted because the 5 000 ms chain ceiling was spent.";
    pub overloads => OVERLOADS, "axiam_reactor_overload_total",
        "Interceptions refused immediately by the per-tenant in-flight cap.";
    pub transport_failures => TRANSPORT_FAILURES, "axiam_reactor_transport_failure_total",
        "Broker or serialization failures on a round trip.";
    pub rejections => REJECTIONS, "axiam_reactor_reply_rejected_total",
        "Replies that arrived and were refused (signature, staleness, allow-list, …).";
    pub failures => FAILURES, "axiam_reactor_failure_total",
        "Every failure of any kind — the sum of the five counters above.";
    pub registry_errors => REGISTRY_ERRORS, "axiam_reactor_registry_error_total",
        "Routing-table loads that could not read the registration store.";
    pub registry_stale_serves => REGISTRY_STALE_SERVES, "axiam_reactor_registry_stale_serve_total",
        "Routing-table reads served from an expired entry because the store was unreachable.";
    pub gate_patch_rejections => GATE_PATCH_REJECTIONS, "axiam_reactor_gate_patch_rejected_total",
        "Merged patches refused by the gate's own allow-list re-check (defence in depth; \
         unreachable unless the reply validator has a hole).";
    pub chain_duration_ms_total => CHAIN_DURATION_MS_TOTAL, "axiam_reactor_chain_duration_ms_total",
        "Summed wall-clock milliseconds spent inside interceptor chains.";
}

/// Record that a chain ran, and how long it took.
pub(crate) fn record_dispatch(elapsed_ms: u64) {
    DISPATCHES.fetch_add(1, Ordering::Relaxed);
    CHAIN_DURATION_MS_TOTAL.fetch_add(elapsed_ms, Ordering::Relaxed);
}

pub(crate) fn record_denial() {
    DENIALS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_mutation() {
    MUTATIONS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_step_up() {
    STEP_UPS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_registry_error() {
    REGISTRY_ERRORS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_registry_stale_serve() {
    REGISTRY_STALE_SERVES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn record_gate_patch_rejection() {
    GATE_PATCH_REJECTIONS.fetch_add(1, Ordering::Relaxed);
}

/// Count one dispatch failure, both in its own bucket and in the total.
///
/// The per-kind split is what makes the aggregate actionable: "reactor failures
/// are up" is not a page anyone can act on, whereas "timeouts are up while
/// transport failures are flat" names the reactor rather than the broker.
pub(crate) fn record_failure(failure: &DispatchFailure) {
    FAILURES.fetch_add(1, Ordering::Relaxed);
    match failure {
        DispatchFailure::Timeout => TIMEOUTS.fetch_add(1, Ordering::Relaxed),
        DispatchFailure::BudgetExhausted => BUDGET_EXHAUSTIONS.fetch_add(1, Ordering::Relaxed),
        DispatchFailure::Overloaded => OVERLOADS.fetch_add(1, Ordering::Relaxed),
        DispatchFailure::Transport(_) => TRANSPORT_FAILURES.fetch_add(1, Ordering::Relaxed),
        DispatchFailure::Rejected(_) => REJECTIONS.fetch_add(1, Ordering::Relaxed),
    };
}

/// The stable metric-name string for a failure kind. Used in the audit record
/// and the log line so the two can be joined against the counter.
pub const fn failure_kind(failure: &DispatchFailure) -> &'static str {
    match failure {
        DispatchFailure::Timeout => "timeout",
        DispatchFailure::BudgetExhausted => "budget_exhausted",
        DispatchFailure::Overloaded => "overloaded",
        DispatchFailure::Transport(_) => "transport",
        DispatchFailure::Rejected(_) => "reply_rejected",
    }
}

/// Every counter, as `(metric_name, value)` — what a `/metrics` endpoint or a
/// health panel renders, and what a test asserts against without naming a
/// static.
pub fn snapshot() -> Vec<(&'static str, u64)> {
    vec![
        ("axiam_reactor_dispatch_total", dispatches()),
        ("axiam_reactor_deny_total", denials()),
        ("axiam_reactor_mutate_total", mutations()),
        ("axiam_reactor_require_mfa_total", step_ups()),
        ("axiam_reactor_timeout_total", timeouts()),
        ("axiam_reactor_budget_exhausted_total", budget_exhaustions()),
        ("axiam_reactor_overload_total", overloads()),
        (
            "axiam_reactor_transport_failure_total",
            transport_failures(),
        ),
        ("axiam_reactor_reply_rejected_total", rejections()),
        ("axiam_reactor_failure_total", failures()),
        ("axiam_reactor_registry_error_total", registry_errors()),
        (
            "axiam_reactor_registry_stale_serve_total",
            registry_stale_serves(),
        ),
        (
            "axiam_reactor_gate_patch_rejected_total",
            gate_patch_rejections(),
        ),
        (
            "axiam_reactor_chain_duration_ms_total",
            chain_duration_ms_total(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reactor::protocol::ReplyRejection;

    /// Counters are process-wide, so a test that asserts an absolute value
    /// would fail whenever another test in the same binary incremented first.
    /// Every assertion here is a *delta*, which is also how an operator reads
    /// a counter.
    #[test]
    fn every_failure_kind_lands_in_its_own_bucket_and_in_the_total() {
        for (failure, read) in [
            (DispatchFailure::Timeout, timeouts as fn() -> u64),
            (DispatchFailure::BudgetExhausted, budget_exhaustions),
            (DispatchFailure::Overloaded, overloads),
            (
                DispatchFailure::Transport("down".into()),
                transport_failures,
            ),
            (
                DispatchFailure::Rejected(ReplyRejection::BadSignature),
                rejections,
            ),
        ] {
            let before_kind = read();
            let before_total = failures();
            record_failure(&failure);
            assert_eq!(read(), before_kind + 1, "{failure} missed its bucket");
            assert_eq!(failures(), before_total + 1, "{failure} missed the total");
        }
    }

    #[test]
    fn the_failure_kind_label_is_stable_and_distinct() {
        let labels = [
            failure_kind(&DispatchFailure::Timeout),
            failure_kind(&DispatchFailure::BudgetExhausted),
            failure_kind(&DispatchFailure::Overloaded),
            failure_kind(&DispatchFailure::Transport(String::new())),
            failure_kind(&DispatchFailure::Rejected(ReplyRejection::Stale)),
        ];
        let mut sorted = labels.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "labels must be distinct");
        assert_eq!(failure_kind(&DispatchFailure::Timeout), "timeout");
    }

    #[test]
    fn the_snapshot_names_every_counter_exactly_once() {
        let snap = snapshot();
        let mut names: Vec<_> = snap.iter().map(|(n, _)| *n).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate metric name in the snapshot");
        assert!(names.iter().all(|n| n.starts_with("axiam_reactor_")));
    }
}

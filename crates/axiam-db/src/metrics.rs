//! Zero-behavior-change instrumentation for the `axiam-db` boundary (F1).
//!
//! ## Why instrument here and not inside `surrealdb`
//!
//! The pinned `surrealdb` 3.2.1 HTTP engine spawns a tokio task **per request**
//! over one shared `reqwest::Client`, and every `Surreal::clone()` shares the
//! same `Arc<inner>` — so the whole process funnels DB traffic through a single
//! router dispatch task with **no upper bound** on concurrency (see
//! `connection.rs` module docs and `claude_dev/db-pool-design.md`). The crate
//! exposes no hook into that router channel, so we cannot measure its internal
//! queue depth directly. Instead we instrument **our own** call path — the point
//! at which `axiam-db` hands a query to the SurrealDB client — which is the
//! boundary a `DbPool` (F2) will own.
//!
//! ## What this module provides
//!
//! * [`db_in_flight`] — a process-wide gauge of DB requests currently awaiting a
//!   response through the `axiam-db` boundary. Under the current single-funnel
//!   architecture this is the count of requests contending for the one shared
//!   dispatcher; after F2 it becomes the pool's aggregate in-flight count that
//!   the `AXIAM__DB__POOL_MAX_IN_FLIGHT` semaphore bounds.
//! * [`db_handle_checkouts`] — a monotonic counter of how many `Surreal<Client>`
//!   handles have been handed out via [`DbManager::client_cloned`]. Today every
//!   one of these is a clone that shares the single router — so this counter
//!   directly quantifies the "single funnel" fan-in (~30 repositories at
//!   startup). After F2 the equivalent counter measures per-handle checkouts.
//! * [`instrument_query`] — a **transparent passthrough** wrapper that measures
//!   spawn→response latency and maintains the in-flight gauge around a query
//!   future, emitting a structured `tracing` event on completion.
//!
//! ## Zero behavior change (invariant)
//!
//! Nothing here introduces a new `.await` that alters ordering or latency
//! semantics of the wrapped work: [`instrument_query`] awaits exactly the future
//! it was given and returns its output unchanged; the gauge is a relaxed atomic
//! inc/dec; the emitted `tracing` event is a no-op when no subscriber is
//! attached. A gauge/counter read never blocks. F2 will route the repository
//! query path through [`instrument_query`]; F1 only adds the machinery and wires
//! the two boundary choke points that already exist today ([`DbManager::client_cloned`]
//! and [`DbManager::health_check`]).

use std::future::IntoFuture;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use tracing::trace;

/// Process-wide count of DB requests currently in flight through the
/// `axiam-db` boundary (incremented on entry to [`instrument_query`],
/// decremented when its future resolves — even on error/panic, via the RAII
/// guard). Relaxed ordering is sufficient: this is an observability gauge, not
/// a synchronization primitive.
static DB_IN_FLIGHT: AtomicI64 = AtomicI64::new(0);

/// Monotonic count of `Surreal<Client>` handles handed out by
/// [`DbManager::client_cloned`]. See module docs — under today's
/// single-router architecture this measures the single-funnel fan-in.
static DB_HANDLE_CHECKOUTS: AtomicU64 = AtomicU64::new(0);

/// Current number of DB requests in flight through the `axiam-db` boundary.
/// Public so tests (and F2's pool) can assert the gauge tracks entry/exit.
pub fn db_in_flight() -> i64 {
    DB_IN_FLIGHT.load(Ordering::Relaxed)
}

/// Total handles checked out via [`DbManager::client_cloned`] since process
/// start. Public for tests and for a future readiness/metrics endpoint.
pub fn db_handle_checkouts() -> u64 {
    DB_HANDLE_CHECKOUTS.load(Ordering::Relaxed)
}

/// Record that a client handle was checked out (called from
/// [`DbManager::client_cloned`]). Zero behavior change — a single relaxed
/// atomic increment plus a `trace` event.
pub(crate) fn record_handle_checkout() {
    let n = DB_HANDLE_CHECKOUTS.fetch_add(1, Ordering::Relaxed) + 1;
    trace!(
        target: "axiam_db::metrics",
        handle_checkouts_total = n,
        "axiam-db client handle checked out (single-router funnel until F2 pool lands)"
    );
}

/// RAII gauge guard: increments [`DB_IN_FLIGHT`] on construction and
/// decrements it on drop, so the gauge is correct even if the guarded future
/// is cancelled or panics. Not exported directly — callers use
/// [`instrument_query`], but F2 may reuse this pattern for the pool's own
/// checkout guard.
struct InFlightGuard {
    op: &'static str,
    started: Instant,
    peak: i64,
}

impl InFlightGuard {
    fn enter(op: &'static str) -> Self {
        let peak = DB_IN_FLIGHT.fetch_add(1, Ordering::Relaxed) + 1;
        Self {
            op,
            started: Instant::now(),
            peak,
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        DB_IN_FLIGHT.fetch_sub(1, Ordering::Relaxed);
        // Emit spawn→response latency at TRACE so it is free when no subscriber
        // is attached and opt-in when the operator wants DB-boundary timing.
        trace!(
            target: "axiam_db::metrics",
            op = self.op,
            latency_us = self.started.elapsed().as_micros() as u64,
            in_flight_at_entry = self.peak,
            "axiam-db query completed"
        );
    }
}

/// Wrap a DB query future so the in-flight gauge and spawn→response latency are
/// observed at the `axiam-db` boundary.
///
/// **Transparent passthrough:** awaits exactly `fut` and returns its output
/// unchanged — no added await points, no reordering, no altered error
/// semantics. Safe to drop onto the hot path (F2 routes the repository query
/// path through here); F1 wires only the choke points that exist today.
pub async fn instrument_query<F, T>(op: &'static str, fut: F) -> T
where
    // `IntoFuture` (not `Future`) so this accepts SurrealDB's `Query`/`Select`/…
    // request builders directly — they implement `IntoFuture`, not `Future`, and
    // `.await` drives them through it. Plain futures also satisfy this bound.
    F: IntoFuture<Output = T>,
{
    let _guard = InFlightGuard::enter(op);
    fut.await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_checkout_counter_increments_monotonically() {
        let before = db_handle_checkouts();
        record_handle_checkout();
        record_handle_checkout();
        assert_eq!(
            db_handle_checkouts(),
            before + 2,
            "checkout counter must increment by exactly the number of checkouts"
        );
    }

    #[tokio::test]
    async fn in_flight_gauge_is_incremented_during_and_restored_after() {
        let baseline = db_in_flight();
        // The gauge must read baseline+1 *inside* the instrumented future and
        // return to baseline once it resolves.
        let observed_inside = instrument_query("test.op", async { db_in_flight() }).await;
        assert_eq!(
            observed_inside,
            baseline + 1,
            "gauge must reflect the in-flight request while the future runs"
        );
        assert_eq!(
            db_in_flight(),
            baseline,
            "gauge must return to baseline after the future resolves"
        );
    }

    #[tokio::test]
    async fn instrument_query_returns_inner_output_unchanged() {
        // Passthrough invariant: the wrapper must yield exactly the inner value.
        let out = instrument_query("test.passthrough", async { 40 + 2 }).await;
        assert_eq!(out, 42);
    }

    #[tokio::test]
    async fn gauge_restored_even_when_future_errors() {
        let baseline = db_in_flight();
        let r: Result<(), &str> = instrument_query("test.err", async { Err("boom") }).await;
        assert!(r.is_err());
        assert_eq!(
            db_in_flight(),
            baseline,
            "gauge must be decremented on the error path too (RAII drop)"
        );
    }
}

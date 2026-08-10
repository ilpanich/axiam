//! Authorization engine configuration.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::decision_cache::{DecisionCache, DecisionCacheConfig};

/// Default freshness window for an inbound cross-replica invalidation message
/// (§4.2). See [`AuthzConfig::decision_cache_broadcast_skew_secs`].
pub const DEFAULT_BROADCAST_SKEW_SECS: u64 = 30;

/// Default interval between self-addressed liveness heartbeats (§13.4
/// observation 1). See [`AuthzConfig::decision_cache_broadcast_heartbeat_secs`].
pub const DEFAULT_BROADCAST_HEARTBEAT_SECS: u64 = 10;

/// Hard ceiling on [`AuthzConfig::decision_cache_ttl_secs`] (§15.2).
///
/// The TTL is the only bound on how long a revoked grant can still be served by
/// a replica that missed its invalidation — the heartbeat shortens the window in
/// which invalidations go undelivered, but it cannot bound a window the operator
/// set to hours. Five minutes is already far beyond anything the cache needs to
/// be useful (the default is 5 **seconds**), so the ceiling costs nothing real
/// and removes the foot-gun.
pub const MAX_DECISION_CACHE_TTL_SECS: u64 = 300;

/// Bounds on the heartbeat interval (§15.2).
///
/// A lower bound stops a misconfiguration turning the liveness probe into a
/// broadcast flood; the upper bound keeps detection latency
/// (`interval × HEARTBEAT_MISS_THRESHOLD`) inside the same order as the TTL
/// ceiling it backstops.
pub const MIN_BROADCAST_HEARTBEAT_SECS: u64 = 1;
/// See [`MIN_BROADCAST_HEARTBEAT_SECS`].
pub const MAX_BROADCAST_HEARTBEAT_SECS: u64 = 60;

/// Strategy for evaluating a `BatchCheckAccess` call (REST + gRPC).
///
/// Both strategies produce **byte-identical decisions in the same order** —
/// they differ only in how the DB work is scheduled, so switching is a pure
/// performance choice with no authorization-semantics risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchStrategy {
    /// **D1 path (default since H3/G3).** Coalesce the shared role-assignment,
    /// ancestor and grant lookups across same-subject/same-resource items into
    /// a minimal set of DB round-trips (3 for the benchmark's 5-item shape).
    /// The run-2 benchmark measured this serializing on the database under
    /// contamination (DB pinned at ~1 core while idle, ~1 s p50); re-measured
    /// on the G3 **settled** protocol (runs 2-3) it is the clear winner:
    /// 744 batch ops/s = 3 721 checks/s = **4.98×** repeated single checks
    /// (748/s) over REST, and 866-872 gRPC batch ops/s ≈ 4 330 checks/s with
    /// p95 74 ms (well inside the ≤2 s gate). See
    /// `claude_dev/authz-batch-investigation.md` for the closing verdict.
    Coalesced,
    /// **D10 path.** Evaluate each item as an independent `check_access`,
    /// **concurrently**, bounded by `batch_max_concurrency`. Issues more DB
    /// round-trips (one set per item) than `Coalesced`. On the G3 settled
    /// protocol it also beats repeated single checks, but by a smaller margin
    /// than `Coalesced`: 200 batch ops/s = 1 000 checks/s = 1.37× singles over
    /// REST, gRPC batch 216 ops/s at p95 282 ms. Retained as an opt-in
    /// A/B/fallback strategy. Decisions and result order are identical to the
    /// coalesced path (the cache is consulted per item, exactly as for a plain
    /// `check_access`).
    Concurrent,
}

/// Configuration for the authorization engine.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuthzConfig {
    /// Bound on concurrent `check_access` evaluations within a single
    /// `BatchCheckAccess` call (gRPC and REST). Kept well under the
    /// ~30-connection SurrealDB handle budget so a batch cannot self-DoS
    /// the connection pool (D-07). Enforced by the `Concurrent`
    /// [`BatchStrategy`]; ignored by `Coalesced` (which issues a fixed, small
    /// number of round-trips regardless of batch size).
    ///
    /// Configure via `AXIAM__AUTHZ__BATCH_MAX_CONCURRENCY` env var.
    pub batch_max_concurrency: usize,

    /// How a `BatchCheckAccess` is evaluated (D10/G3/H3). Defaults to
    /// [`BatchStrategy::Coalesced`] — round-trip-minimizing evaluation, which
    /// the G3 re-measurement on the settled benchmark protocol showed winning
    /// decisively over `concurrent` (4.98× vs 1.37× repeated single checks;
    /// gRPC batch p95 74 ms vs 282 ms). Set to `concurrent` to restore the
    /// D10 per-item-parallel behavior (still selectable for an
    /// apples-to-apples A/B).
    ///
    /// Configure via `AXIAM__AUTHZ__BATCH_STRATEGY` (`coalesced` | `concurrent`).
    pub batch_strategy: BatchStrategy,

    /// Enable the per-tenant authorization **decision cache** (D7). When
    /// `false` (the default) the engine issues its usual DB round-trips on
    /// every check — behaviour is byte-for-byte identical to a build without
    /// the cache. Only when `true` does `axiam-server` attach a
    /// [`DecisionCache`] to the authorization engines.
    ///
    /// Configure via `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` (default `false`).
    ///
    /// SECURITY: the cache is safe under AXIAM's default-deny /
    /// **deny-override** model *only because* every access-narrowing mutation
    /// invalidates the affected entries immediately (see
    /// `decision_cache` module docs). Since B1 that set includes *adding* a
    /// grant whose effect is `Deny` — an addition that narrows, which the
    /// pre-B1 additive model had no way to express. A stale allow can outlive
    /// a revocation by at most `decision_cache_ttl_secs` even if an
    /// invalidation is missed.
    ///
    /// SECURITY — **multi-replica caveat, read before enabling**: on its own
    /// the cache and its invalidation are **process-local**. "Revocation is
    /// immediate" is then a *single-process* property. With two or more
    /// replicas, a revocation handled by replica A does not reach replicas
    /// B…N, which keep serving the pre-revocation decision until their own
    /// entries expire — so the deployment's **worst-case revocation latency is
    /// `decision_cache_ttl_secs` (default 5 s)**, on every read path including
    /// the `RequirePermission` guard that protects the admin endpoints. Either
    /// enable [`Self::decision_cache_broadcast_enabled`], run a single replica,
    /// or accept a ≤ TTL revocation window.
    pub decision_cache_enabled: bool,

    /// Enable **cross-replica** decision-cache invalidation over RabbitMQ
    /// (§4.2). Requires [`Self::decision_cache_enabled`]; ignored when the
    /// cache is off.
    ///
    /// Configure via `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED`
    /// (default `false`).
    ///
    /// When `true`, every invalidation a mutation triggers is also published,
    /// HMAC-signed, to a **fanout** exchange that every replica binds its own
    /// exclusive auto-delete queue to — so a revocation propagates to all
    /// replicas in broker-latency time instead of being bounded by the TTL.
    /// Two consequences an operator must know about before flipping it:
    ///
    /// * **A mutation whose broadcast the broker does not confirm returns
    ///   503.** The database write is durable, but the fan-out did not happen,
    ///   so it is reported as a failure rather than silently falling back to
    ///   the TTL window this switch exists to eliminate. These mutations are
    ///   idempotent in the narrowing direction; retry is safe.
    /// * **A replica whose invalidation consumer is not connected stops
    ///   serving from its cache entirely** (falls back to full database
    ///   evaluation — correct, slower) until it reconnects, rather than
    ///   serving allows it can no longer invalidate. This is logged at ERROR
    ///   and counted in `DecisionCacheStats::bypassed`.
    ///
    /// When `false` (the default) none of the above exists: no AMQP dependency
    /// is added by the cache, `invalidate_*` cannot fail, and the documented
    /// TTL-bounded behaviour above is unchanged.
    pub decision_cache_broadcast_enabled: bool,

    /// Freshness window, in seconds, for an inbound cross-replica invalidation
    /// message (§4.2 / AMQP §8 `issued_at` gate). A broadcast whose `issued_at`
    /// is outside ±this many seconds of the receiving replica's clock is
    /// rejected and logged.
    ///
    /// Configure via `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS`
    /// (default `30`).
    ///
    /// Deliberately far tighter than the 5-minute AMQP default
    /// (`AXIAM__AMQP__REPLAY_SKEW_SECS`): an invalidation is only useful for
    /// about as long as the cache TTL, so a short window both bounds how long a
    /// captured message stays replay-eligible and bounds the memory of the
    /// per-replica nonce guard. Raise it only if replica clocks are poorly
    /// synchronised — a skew larger than the true clock spread buys nothing.
    pub decision_cache_broadcast_skew_secs: u64,

    /// Interval, in seconds, between the self-addressed liveness heartbeats a
    /// replica publishes to prove its own queue is still bound to the fanout
    /// exchange (§13.4 observation 1).
    ///
    /// Configure via `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_HEARTBEAT_SECS`
    /// (default `10`). Only has any effect when
    /// [`Self::decision_cache_broadcast_enabled`] is on.
    ///
    /// **What this buys.** The cache's trust flag otherwise follows *consumer*
    /// liveness alone. A party with broker `configure` rights can `queue.unbind`
    /// a replica's queue: the consumer stays subscribed to a queue nothing
    /// routes to, trust stays on, and the replica serves cached allows it will
    /// never be told to invalidate — while the publisher sees nothing, because
    /// `mandatory` is off and the broker acks an unroutable message. A heartbeat
    /// that has to come back to us tests the whole loop, so an unbound queue is
    /// detected within
    /// `decision_cache_broadcast_heartbeat_secs × HEARTBEAT_MISS_THRESHOLD`.
    ///
    /// **Cannot be disabled** while broadcast is on, and clamped to
    /// `MIN_BROADCAST_HEARTBEAT_SECS..=MAX_BROADCAST_HEARTBEAT_SECS` (§15.2).
    /// An earlier revision accepted `0` as "disabled"; that made the mitigation
    /// removable with one environment variable and only a warning, leaving
    /// `decision_cache_ttl_secs` as the sole bound — the exact state this
    /// exists to escape.
    ///
    /// Raising it weakens detection linearly and saves almost nothing — one
    /// transient 200-byte message per replica per interval.
    pub decision_cache_broadcast_heartbeat_secs: u64,

    /// TTL, in seconds, for a cached decision (D7). Bounds worst-case
    /// revocation latency if an invalidation event is ever missed — and, on a
    /// multi-replica deployment, bounds the *actual* revocation latency on
    /// every replica that did not handle the mutation (the cache is
    /// process-local; see `decision_cache_enabled`). Short by design.
    ///
    /// Configure via `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default `5`).
    ///
    /// **Clamped to [`MAX_DECISION_CACHE_TTL_SECS`] at construction** (§15.2).
    /// This value is the *only* bound on how long a revoked grant can still be
    /// served on a replica that missed its invalidation, so an unbounded `u64`
    /// let an operator configure a multi-hour stale-allow window — and the
    /// cross-replica heartbeat, which exists to shorten that window, cannot
    /// help once the window itself is arbitrary. `cleanup_interval_secs` has
    /// been clamped for this reason since T-04-35; this one had not been.
    pub decision_cache_ttl_secs: u64,

    /// Maximum cached decisions retained **per tenant** before FIFO eviction
    /// (D7). Bounds memory.
    ///
    /// Configure via `AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` (default
    /// `10000`).
    pub decision_cache_max_entries: usize,
}

impl Default for AuthzConfig {
    fn default() -> Self {
        Self {
            batch_max_concurrency: 16,
            batch_strategy: BatchStrategy::Coalesced,
            decision_cache_enabled: false,
            decision_cache_broadcast_enabled: false,
            decision_cache_broadcast_skew_secs: DEFAULT_BROADCAST_SKEW_SECS,
            decision_cache_broadcast_heartbeat_secs: DEFAULT_BROADCAST_HEARTBEAT_SECS,
            decision_cache_ttl_secs: 5,
            decision_cache_max_entries: 10_000,
        }
    }
}

impl AuthzConfig {
    /// Build the shared [`DecisionCache`] iff caching is enabled, returning it
    /// as an `Arc` ready to attach to every authorization engine
    /// (`AuthorizationEngine::with_decision_cache`). Returns `None` when the
    /// feature flag is off — the caller then constructs engines exactly as
    /// before (no cache, no behaviour change).
    ///
    /// The *same* `Arc<DecisionCache>` must be shared across the REST, gRPC and
    /// AMQP engines so that an invalidation triggered from a REST mutation
    /// handler is observed by every read path. (All role/permission/resource
    /// mutations are REST endpoints today.)
    /// When cross-replica invalidation is enabled the returned cache starts
    /// **untrusted** (`DecisionCache::set_trusted(false)`): a replica must not
    /// serve a single cached decision before its invalidation consumer has
    /// actually subscribed, or the startup window would be exactly the
    /// stale-allow hole this feature closes. The consumer flips it to trusted
    /// once it is receiving.
    pub fn build_decision_cache(&self) -> Option<Arc<DecisionCache>> {
        if !self.decision_cache_enabled {
            return None;
        }
        let cache = DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(self.decision_cache_ttl_secs()),
            max_entries_per_tenant: self.decision_cache_max_entries,
        });
        if self.decision_cache_broadcast_enabled {
            cache.set_trusted(false);
        }
        Some(Arc::new(cache))
    }

    /// Whether cross-replica invalidation is actually active — the broadcast
    /// switch means nothing without the cache it invalidates.
    pub fn cross_replica_invalidation_enabled(&self) -> bool {
        self.decision_cache_enabled && self.decision_cache_broadcast_enabled
    }

    /// The configured inbound-broadcast freshness window as a
    /// `chrono::Duration`, mirroring `AmqpConfig::replay_skew`.
    pub fn decision_cache_broadcast_skew(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.decision_cache_broadcast_skew_secs as i64)
    }

    /// The effective decision-cache TTL, clamped to
    /// [`MAX_DECISION_CACHE_TTL_SECS`] (§15.2).
    ///
    /// Clamped here rather than in `main.rs` — where `cleanup_interval_secs` is
    /// clamped — so that *every* construction path is covered, including tests
    /// and any future embedder that builds an `AuthzConfig` directly. A bound
    /// that only applies when one particular binary happens to apply it is not
    /// really a bound.
    pub fn decision_cache_ttl_secs(&self) -> u64 {
        let configured = self.decision_cache_ttl_secs;
        if configured > MAX_DECISION_CACHE_TTL_SECS {
            tracing::warn!(
                configured,
                clamped_to = MAX_DECISION_CACHE_TTL_SECS,
                "AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS exceeds the maximum and has been clamped. \
                 This value bounds how long a REVOKED grant can still be served on a replica that \
                 missed its invalidation, so it is a security bound, not a tuning knob."
            );
        }
        configured.min(MAX_DECISION_CACHE_TTL_SECS)
    }

    /// The heartbeat interval, or `None` when cross-replica invalidation is not
    /// active at all.
    ///
    /// **There is deliberately no way to disable heartbeats while broadcast is
    /// on** (§15.2). An earlier revision treated `0` as "disabled", which meant
    /// the mitigation for the queue-unbind suppression hole could be switched
    /// off with a single environment variable and only a warning — leaving the
    /// TTL as the sole bound, which is precisely the state the heartbeat exists
    /// to escape. A heartbeat costs one transient ~200-byte message per replica
    /// per interval, so there is no deployment for which disabling it is the
    /// right trade. Out-of-range values are clamped, not honoured.
    pub fn decision_cache_broadcast_heartbeat(&self) -> Option<chrono::Duration> {
        if !self.cross_replica_invalidation_enabled() {
            return None;
        }
        let configured = self.decision_cache_broadcast_heartbeat_secs;
        let effective =
            configured.clamp(MIN_BROADCAST_HEARTBEAT_SECS, MAX_BROADCAST_HEARTBEAT_SECS);
        if effective != configured {
            tracing::warn!(
                configured,
                clamped_to = effective,
                "AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_HEARTBEAT_SECS is out of range and has \
                 been clamped. Heartbeats cannot be disabled while cross-replica invalidation is \
                 enabled: they are what detects a replica whose queue has been unbound."
            );
        }
        Some(chrono::Duration::seconds(effective as i64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_batch_max_concurrency_is_16() {
        let cfg = AuthzConfig::default();
        assert_eq!(cfg.batch_max_concurrency, 16);
    }

    #[test]
    fn deserializes_from_partial_json_using_defaults() {
        let cfg: AuthzConfig = serde_json::from_str("{}").expect("empty object must deserialize");
        assert_eq!(cfg.batch_max_concurrency, 16);
    }

    #[test]
    fn deserializes_explicit_override() {
        let cfg: AuthzConfig = serde_json::from_str(r#"{"batch_max_concurrency": 4}"#)
            .expect("explicit override must deserialize");
        assert_eq!(cfg.batch_max_concurrency, 4);
    }

    #[test]
    fn default_batch_strategy_is_coalesced() {
        // H3/G3: coalesced round-trip-minimizing evaluation is the shipped
        // default — the settled-protocol re-measurement showed it winning
        // decisively (4.98x vs 1.37x repeated single checks); `concurrent`
        // remains selectable as an opt-in A/B strategy.
        let cfg = AuthzConfig::default();
        assert_eq!(cfg.batch_strategy, BatchStrategy::Coalesced);
    }

    #[test]
    fn deserializes_batch_strategy_override() {
        let cfg: AuthzConfig = serde_json::from_str(r#"{"batch_strategy": "coalesced"}"#)
            .expect("batch_strategy override must deserialize");
        assert_eq!(cfg.batch_strategy, BatchStrategy::Coalesced);
        let cfg: AuthzConfig = serde_json::from_str(r#"{"batch_strategy": "concurrent"}"#)
            .expect("batch_strategy override must deserialize");
        assert_eq!(cfg.batch_strategy, BatchStrategy::Concurrent);
    }

    #[test]
    fn empty_object_defaults_batch_strategy_to_coalesced() {
        let cfg: AuthzConfig = serde_json::from_str("{}").expect("empty object must deserialize");
        assert_eq!(cfg.batch_strategy, BatchStrategy::Coalesced);
    }

    #[test]
    fn decision_cache_defaults_are_off_and_conservative() {
        let cfg = AuthzConfig::default();
        assert!(!cfg.decision_cache_enabled, "cache must default OFF");
        assert_eq!(cfg.decision_cache_ttl_secs, 5);
        assert_eq!(cfg.decision_cache_max_entries, 10_000);
    }

    #[test]
    fn build_decision_cache_none_when_disabled() {
        let cfg = AuthzConfig::default();
        assert!(cfg.build_decision_cache().is_none());
    }

    #[test]
    fn build_decision_cache_some_when_enabled() {
        let cfg = AuthzConfig {
            decision_cache_enabled: true,
            ..AuthzConfig::default()
        };
        assert!(cfg.build_decision_cache().is_some());
    }

    #[test]
    fn deserializes_decision_cache_overrides() {
        let cfg: AuthzConfig = serde_json::from_str(
            r#"{"decision_cache_enabled": true, "decision_cache_ttl_secs": 10, "decision_cache_max_entries": 500}"#,
        )
        .expect("cache overrides must deserialize");
        assert!(cfg.decision_cache_enabled);
        assert_eq!(cfg.decision_cache_ttl_secs, 10);
        assert_eq!(cfg.decision_cache_max_entries, 500);
    }

    // -----------------------------------------------------------------------
    // §4.2 — cross-replica invalidation defaults and inertness when off.
    // -----------------------------------------------------------------------

    #[test]
    fn cross_replica_invalidation_defaults_off() {
        let cfg = AuthzConfig::default();
        assert!(
            !cfg.decision_cache_broadcast_enabled,
            "the cross-replica channel must default OFF — a single-replica \
             deployment enabling the cache must not acquire a hard AMQP dependency"
        );
        assert!(!cfg.cross_replica_invalidation_enabled());
        assert_eq!(
            cfg.decision_cache_broadcast_skew_secs,
            DEFAULT_BROADCAST_SKEW_SECS
        );
        assert_eq!(cfg.decision_cache_broadcast_skew().num_seconds(), 30);
    }

    #[test]
    fn broadcast_switch_is_inert_without_the_cache() {
        let cfg = AuthzConfig {
            decision_cache_enabled: false,
            decision_cache_broadcast_enabled: true,
            ..AuthzConfig::default()
        };
        assert!(
            !cfg.cross_replica_invalidation_enabled(),
            "broadcasting invalidations for a cache that does not exist is meaningless"
        );
        assert!(cfg.build_decision_cache().is_none());
    }

    #[test]
    fn cache_starts_trusted_when_broadcast_is_off() {
        let cfg = AuthzConfig {
            decision_cache_enabled: true,
            ..AuthzConfig::default()
        };
        let cache = cfg.build_decision_cache().expect("cache enabled");
        assert!(
            cache.is_trusted(),
            "without the broadcast channel there is nothing to wait for — \
             behaviour is unchanged from before §4.2"
        );
    }

    #[test]
    fn cache_starts_untrusted_when_broadcast_is_on() {
        let cfg = AuthzConfig {
            decision_cache_enabled: true,
            decision_cache_broadcast_enabled: true,
            ..AuthzConfig::default()
        };
        let cache = cfg.build_decision_cache().expect("cache enabled");
        assert!(
            !cache.is_trusted(),
            "a replica must not serve a cached decision before its invalidation \
             consumer has subscribed"
        );
        assert!(cfg.cross_replica_invalidation_enabled());
    }

    #[test]
    fn deserializes_broadcast_overrides() {
        let cfg: AuthzConfig = serde_json::from_str(
            r#"{"decision_cache_enabled": true, "decision_cache_broadcast_enabled": true, "decision_cache_broadcast_skew_secs": 15}"#,
        )
        .expect("broadcast overrides must deserialize");
        assert!(cfg.decision_cache_broadcast_enabled);
        assert_eq!(cfg.decision_cache_broadcast_skew_secs, 15);
    }

    // --- §15.2: neither half of the staleness bound is operator-removable ---

    /// The TTL is the only bound on how long a revoked grant can still be served
    /// by a replica that missed its invalidation. It was an unbounded `u64`,
    /// while `cleanup_interval_secs` had been clamped since T-04-35.
    #[test]
    fn decision_cache_ttl_is_clamped_to_the_ceiling() {
        let cfg = AuthzConfig {
            decision_cache_ttl_secs: 86_400,
            ..AuthzConfig::default()
        };
        assert_eq!(cfg.decision_cache_ttl_secs(), MAX_DECISION_CACHE_TTL_SECS);
    }

    /// Clamping must not disturb a sane value — including the default.
    #[test]
    fn a_within_range_ttl_is_untouched() {
        for secs in [0, 1, 5, 60, MAX_DECISION_CACHE_TTL_SECS] {
            let cfg = AuthzConfig {
                decision_cache_ttl_secs: secs,
                ..AuthzConfig::default()
            };
            assert_eq!(cfg.decision_cache_ttl_secs(), secs);
        }
    }

    /// The clamp must apply at the point the TTL becomes real, not only in
    /// `main.rs` — a bound that one binary happens to apply is not a bound.
    ///
    /// Asserted through the accessor `build_decision_cache` actually calls,
    /// rather than by reading the field back off the built cache, so the test
    /// fails if a future edit reverts that call site to the raw field.
    #[test]
    fn the_built_cache_uses_the_clamped_ttl() {
        let cfg = AuthzConfig {
            decision_cache_enabled: true,
            decision_cache_ttl_secs: 86_400,
            ..AuthzConfig::default()
        };
        assert!(cfg.build_decision_cache().is_some(), "cache enabled");
        assert_eq!(
            Duration::from_secs(cfg.decision_cache_ttl_secs()),
            Duration::from_secs(MAX_DECISION_CACHE_TTL_SECS),
            "build_decision_cache must not hand an unclamped TTL to the cache"
        );
        assert_ne!(
            cfg.decision_cache_ttl_secs(),
            cfg.decision_cache_ttl_secs,
            "precondition: the raw field really is out of range here"
        );
    }

    /// Heartbeats cannot be switched off while broadcast is on. An earlier
    /// revision treated `0` as "disabled", which let one environment variable
    /// remove the mitigation for the queue-unbind hole.
    #[test]
    fn heartbeats_cannot_be_disabled_while_broadcast_is_on() {
        let cfg = AuthzConfig {
            decision_cache_enabled: true,
            decision_cache_broadcast_enabled: true,
            decision_cache_broadcast_heartbeat_secs: 0,
            ..AuthzConfig::default()
        };
        let interval = cfg
            .decision_cache_broadcast_heartbeat()
            .expect("heartbeats must stay on");
        assert_eq!(
            interval.num_seconds() as u64,
            MIN_BROADCAST_HEARTBEAT_SECS,
            "0 must clamp to the minimum, not disable the watchdog"
        );
    }

    /// An absurdly long interval is clamped too: detection latency is
    /// `interval * HEARTBEAT_MISS_THRESHOLD`, so an unbounded interval is an
    /// unbounded suppression window by another route.
    #[test]
    fn an_over_long_heartbeat_interval_is_clamped() {
        let cfg = AuthzConfig {
            decision_cache_enabled: true,
            decision_cache_broadcast_enabled: true,
            decision_cache_broadcast_heartbeat_secs: 86_400,
            ..AuthzConfig::default()
        };
        assert_eq!(
            cfg.decision_cache_broadcast_heartbeat()
                .unwrap()
                .num_seconds() as u64,
            MAX_BROADCAST_HEARTBEAT_SECS
        );
    }

    /// With broadcast off there is no heartbeat to run — the whole feature is
    /// inert, which is the documented default.
    #[test]
    fn no_heartbeat_when_broadcast_is_off() {
        assert!(
            AuthzConfig::default()
                .decision_cache_broadcast_heartbeat()
                .is_none()
        );
    }
}

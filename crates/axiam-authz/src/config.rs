//! Authorization engine configuration.

use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;

use crate::decision_cache::{DecisionCache, DecisionCacheConfig};

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
    /// SECURITY: the cache is safe under AXIAM's additive allow-wins /
    /// default-deny model *only because* every access-narrowing mutation
    /// invalidates the affected entries immediately (see
    /// `decision_cache` module docs). A stale allow can outlive a revocation
    /// by at most `decision_cache_ttl_secs` even if an invalidation is missed.
    ///
    /// SECURITY — **multi-replica caveat, read before enabling**: the cache and
    /// its invalidation are **process-local**. "Revocation is immediate" is a
    /// *single-process* property. With two or more replicas, a revocation
    /// handled by replica A does not reach replicas B…N, which keep serving the
    /// pre-revocation decision until their own entries expire — so the
    /// deployment's **worst-case revocation latency is
    /// `decision_cache_ttl_secs` (default 5 s)**, on every read path including
    /// the `RequirePermission` guard that protects the admin endpoints. Enable
    /// this only on a single replica, or where a ≤ TTL revocation window is
    /// acceptable.
    pub decision_cache_enabled: bool,

    /// TTL, in seconds, for a cached decision (D7). Bounds worst-case
    /// revocation latency if an invalidation event is ever missed — and, on a
    /// multi-replica deployment, bounds the *actual* revocation latency on
    /// every replica that did not handle the mutation (the cache is
    /// process-local; see `decision_cache_enabled`). Short by design.
    ///
    /// Configure via `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default `5`).
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
    pub fn build_decision_cache(&self) -> Option<Arc<DecisionCache>> {
        if !self.decision_cache_enabled {
            return None;
        }
        Some(Arc::new(DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(self.decision_cache_ttl_secs),
            max_entries_per_tenant: self.decision_cache_max_entries,
        })))
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
}

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
    /// **D1 path.** Coalesce the shared role-assignment, ancestor and grant
    /// lookups across same-subject/same-resource items into a minimal set of DB
    /// round-trips (3 for the benchmark's 5-item shape). Minimizes round-trips,
    /// but the whole batch resolves on a single task: the run-2 benchmark showed
    /// this serializes on the database (DB pinned at ~1 core while idle, ~1 s
    /// p50) and did **not** beat repeated single checks.
    Coalesced,
    /// **D10 path (default).** Evaluate each item as an independent
    /// `check_access`, **concurrently**, bounded by `batch_max_concurrency`.
    /// Issues more DB round-trips (one set per item) but recovers the
    /// parallelism that lets single checks saturate the DB — the run-2 data
    /// showed single checks pegging the DB at 745 req/s while the coalesced
    /// batch left it idle. Decisions and result order are identical to the
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

    /// How a `BatchCheckAccess` is evaluated (D10). Defaults to
    /// [`BatchStrategy::Concurrent`] — per-item parallel evaluation, which the
    /// run-2 benchmark analysis identified as the fix for the coalesced path's
    /// DB serialization. Set to `coalesced` to restore the D1 round-trip-
    /// minimizing behavior for an apples-to-apples laptop A/B.
    ///
    /// Configure via `AXIAM__AUTHZ__BATCH_STRATEGY` (`concurrent` | `coalesced`).
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
    pub decision_cache_enabled: bool,

    /// TTL, in seconds, for a cached decision (D7). Bounds worst-case
    /// revocation latency if an invalidation event is ever missed. Short by
    /// design.
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
            batch_strategy: BatchStrategy::Concurrent,
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
    fn default_batch_strategy_is_concurrent() {
        // D10: per-item parallel evaluation is the shipped default (the fix for
        // the coalesced path's DB serialization); `coalesced` is opt-in.
        let cfg = AuthzConfig::default();
        assert_eq!(cfg.batch_strategy, BatchStrategy::Concurrent);
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
    fn empty_object_defaults_batch_strategy_to_concurrent() {
        let cfg: AuthzConfig = serde_json::from_str("{}").expect("empty object must deserialize");
        assert_eq!(cfg.batch_strategy, BatchStrategy::Concurrent);
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

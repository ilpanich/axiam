//! Cross-replica decision-cache invalidation — the transport-agnostic contract.
//!
//! [`DecisionCache`] invalidation is, on its own, **process-local**: the
//! mutating replica drops its own entries and no other replica hears about it
//! (the residual recorded as §4.2 / threat-model `T-88`). This module defines
//! the seam that closes that gap without dragging a broker dependency into
//! `axiam-authz`:
//!
//! * [`InvalidationEvent`] — *what* must be dropped, expressed only in the
//!   granularity the cache already supports (whole tenant, or one subject
//!   within a tenant). No finer key is invented here; anything narrower would
//!   have to mirror the engine's inheritance rules and would be a second place
//!   to get authorization semantics wrong.
//! * [`InvalidationBroadcaster`] — *how* it reaches the other replicas. The
//!   only implementation that ships is the RabbitMQ fanout publisher in
//!   `axiam-amqp::cache_invalidation`; `axiam-authz` never links `lapin`.
//!
//! # Loop-freedom (by construction, not by convention)
//!
//! [`InvalidationEvent::apply`] takes a `&DecisionCache` and calls the cache's
//! own `invalidate_*` methods. It deliberately does **not** take an
//! `AuthorizationEngine`, whose `invalidate_*` methods are the *publishing*
//! ones. A consumer applying a received broadcast therefore has no reachable
//! path back to a publish, so a received message can never re-broadcast — the
//! echo cannot loop even if a future change gets the self-echo suppression
//! wrong.

use std::future::Future;
use std::pin::Pin;

use axiam_core::error::AxiamResult;
use uuid::Uuid;

use crate::decision_cache::DecisionCache;

/// A cache-invalidation instruction, at the granularity
/// [`DecisionCache`] already supports.
///
/// Deliberately closed (two variants, no payload beyond identifiers): an
/// invalidation message is a control-plane instruction that crosses a broker,
/// so the smaller its vocabulary, the smaller the blast radius if an attacker
/// ever gets to publish one. The worst a forged-but-verified message can do is
/// evict cache entries — never grant anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationEvent {
    /// Drop every cached decision for a tenant — the conservative,
    /// always-correct invalidation used for coarse mutations whose
    /// affected-subject set is not known without a query.
    Tenant {
        /// The tenant whose cached decisions are dropped.
        tenant_id: Uuid,
    },
    /// Drop every cached decision for one subject within a tenant — the
    /// targeted invalidation used when exactly one subject's effective
    /// permissions change.
    Subject {
        /// The tenant the subject belongs to. Also selects the per-tenant HKDF
        /// subkey the wire message is signed with, so this event cannot be
        /// replayed against another tenant.
        tenant_id: Uuid,
        /// The one subject whose cached decisions are dropped.
        subject_id: Uuid,
    },
}

impl InvalidationEvent {
    /// The tenant this event applies to. Also selects the per-tenant HKDF
    /// subkey the wire message is signed with (`axiam-amqp` §8 scheme), so an
    /// invalidation signed for tenant A can never be replayed as tenant B's.
    pub fn tenant_id(&self) -> Uuid {
        match self {
            Self::Tenant { tenant_id } | Self::Subject { tenant_id, .. } => *tenant_id,
        }
    }

    /// The subject this event narrows to, or `None` for a whole-tenant flush.
    pub fn subject_id(&self) -> Option<Uuid> {
        match self {
            Self::Tenant { .. } => None,
            Self::Subject { subject_id, .. } => Some(*subject_id),
        }
    }

    /// Apply this event to a cache. **Terminal by construction** — see the
    /// module docs: this touches the cache directly and can never re-publish.
    pub fn apply(self, cache: &DecisionCache) {
        match self {
            Self::Tenant { tenant_id } => cache.invalidate_tenant(tenant_id),
            Self::Subject {
                tenant_id,
                subject_id,
            } => cache.invalidate_subject(tenant_id, subject_id),
        }
    }
}

/// Transport for delivering an [`InvalidationEvent`] to **every other
/// replica**.
///
/// # Contract for implementors
///
/// 1. **Fan-out, not work-sharing.** Every subscribing replica must receive
///    every event. An implementation that lets one consumer win (a work queue)
///    leaves the losers serving stale allows and is worse than no channel at
///    all, because operators would believe the gap is closed.
/// 2. **Fail loudly, never silently.** `broadcast` returns `Err` when the
///    event did **not** reach the broker (no publisher confirm). The caller —
///    `AuthorizationEngine::invalidate_*` — propagates that to the mutation
///    handler, which turns it into a 503. A revocation whose fan-out did not
///    happen must not be reported to the operator as a success.
/// 3. **Authenticate.** The event is a control-plane instruction; sign it
///    rather than trusting broker ACLs alone.
///
/// The local cache is always invalidated *before* `broadcast` is awaited, so a
/// broadcast failure never leaves the mutating replica itself stale.
pub trait InvalidationBroadcaster: Send + Sync {
    /// Publish `event` to every replica, resolving only once the broker has
    /// confirmed it (or erroring if it has not).
    fn broadcast<'a>(
        &'a self,
        event: InvalidationEvent,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_cache::DecisionCacheConfig;
    use crate::types::{AccessDecision, AccessRequest};
    use std::time::Duration;

    fn request(tenant_id: Uuid, subject_id: Uuid) -> AccessRequest {
        AccessRequest {
            tenant_id,
            subject_id,
            action: "read".into(),
            resource_id: Uuid::nil(),
            scope: None,
        }
    }

    fn cache() -> DecisionCache {
        DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(60),
            max_entries_per_tenant: 100,
        })
    }

    #[test]
    fn subject_event_applies_only_to_that_subject() {
        let cache = cache();
        let tenant = Uuid::new_v4();
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        cache.insert(&request(tenant, alice), AccessDecision::Allow);
        cache.insert(&request(tenant, bob), AccessDecision::Allow);

        InvalidationEvent::Subject {
            tenant_id: tenant,
            subject_id: alice,
        }
        .apply(&cache);

        assert!(cache.get(&request(tenant, alice)).is_none());
        assert!(cache.get(&request(tenant, bob)).is_some());
    }

    #[test]
    fn tenant_event_applies_to_the_whole_tenant() {
        let cache = cache();
        let tenant = Uuid::new_v4();
        let other = Uuid::new_v4();
        cache.insert(&request(tenant, Uuid::new_v4()), AccessDecision::Allow);
        cache.insert(&request(tenant, Uuid::new_v4()), AccessDecision::Allow);
        let keep = request(other, Uuid::new_v4());
        cache.insert(&keep, AccessDecision::Allow);

        InvalidationEvent::Tenant { tenant_id: tenant }.apply(&cache);

        assert_eq!(cache.len(), 1, "only the other tenant's entry survives");
        assert!(cache.get(&keep).is_some());
    }

    #[test]
    fn accessors_agree_with_variants() {
        let t = Uuid::new_v4();
        let s = Uuid::new_v4();
        let ev = InvalidationEvent::Tenant { tenant_id: t };
        assert_eq!(ev.tenant_id(), t);
        assert_eq!(ev.subject_id(), None);
        let ev = InvalidationEvent::Subject {
            tenant_id: t,
            subject_id: s,
        };
        assert_eq!(ev.tenant_id(), t);
        assert_eq!(ev.subject_id(), Some(s));
    }
}

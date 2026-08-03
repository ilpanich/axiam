//! §4.2 — cross-replica decision-cache invalidation: transport tests.
//!
//! These exercise the broker-free seams of
//! [`axiam_amqp::cache_invalidation`] — the same separation
//! `process_authz_request` uses, so every branch is testable without a live
//! RabbitMQ. What each test pins:
//!
//! | Requirement | Test |
//! |---|---|
//! | fan-out reaches **every** replica, not one | [`one_publish_invalidates_every_subscriber`] |
//! | topology really is a fanout with per-replica queues | [`topology_is_a_fanout_with_per_replica_exclusive_queues`] |
//! | a lost broker degrades to uncached, never to stale allows | [`a_replica_that_cannot_hear_invalidations_stops_serving_its_cache`] |
//! | the publisher's own echo is a no-op and cannot loop | [`self_echo_is_a_no_op`], [`self_echo_does_not_consume_replay_capacity`] |
//! | a message failing signature verification is rejected | [`unsigned_message_is_rejected`], [`tampered_message_is_rejected`], [`wrong_key_is_rejected`], [`cross_tenant_signature_is_rejected`] |
//! | the whole thing is inert when disabled | [`disabled_channel_leaves_the_cache_exactly_as_before`] |
//!
//! **Scope limit, stated honestly:** these tests drive the message path and the
//! declared topology *parameters*; they do not stand up a RabbitMQ broker (none
//! is available in CI), so "the broker really fans out to N bound queues" is
//! covered by asserting the exchange kind and the per-replica exclusive
//! auto-delete queue options rather than by observing rabbit itself. The
//! multi-subscriber test drives N independent consumers, each with its own
//! `DecisionCache` and its own `NonceGuard`, from **one** published payload —
//! which is exactly what each of those queues would deliver.

use std::sync::Arc;
use std::time::Duration;

use axiam_amqp::cache_invalidation::{
    CacheInvalidationPublisher, InvalidationOutcome, InvalidationReject, NonceGuard,
    build_signed_invalidation, handle_invalidation, invalidation_exchange_kind,
    invalidation_queue_name, invalidation_queue_options, process_invalidation,
};
use axiam_amqp::exchanges;
use axiam_amqp::messages::{
    CURRENT_KEY_VERSION, CacheInvalidationMessage, derive_tenant_key, sign_payload,
};
use axiam_authz::invalidation::InvalidationEvent;
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_authz::{AuthzConfig, DecisionCache, DecisionCacheConfig};
use chrono::Utc;
use lapin::ExchangeKind;
use uuid::Uuid;

const MASTER_KEY: &[u8] = b"test-amqp-master-signing-key-for-cache-invalidation";

fn skew() -> chrono::Duration {
    chrono::Duration::seconds(30)
}

fn cache() -> Arc<DecisionCache> {
    Arc::new(DecisionCache::new(DecisionCacheConfig {
        // Long TTL on purpose: any invalidation observed in these tests is the
        // result of the broadcast, never of TTL expiry.
        ttl: Duration::from_secs(3600),
        max_entries_per_tenant: 1_000,
    }))
}

fn request(tenant: Uuid, subject: Uuid) -> AccessRequest {
    AccessRequest {
        tenant_id: tenant,
        subject_id: subject,
        action: "read".into(),
        resource_id: Uuid::nil(),
        scope: None,
    }
}

/// One simulated replica: its own cache, its own replica id, its own nonce
/// guard — exactly what a real replica holds behind its own fanout queue.
struct Replica {
    id: Uuid,
    cache: Arc<DecisionCache>,
    guard: NonceGuard,
}

impl Replica {
    fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            cache: cache(),
            guard: NonceGuard::new(),
        }
    }

    /// Deliver one fanout message to this replica.
    fn deliver(&self, raw: &[u8]) -> InvalidationOutcome {
        handle_invalidation(
            raw,
            &self.cache,
            MASTER_KEY,
            self.id,
            &self.guard,
            skew(),
            Utc::now(),
        )
    }
}

// ---------------------------------------------------------------------------
// 1. Fan-out shape — the decision everything else rests on
// ---------------------------------------------------------------------------

/// **The headline test.** One publish; *every* subscriber invalidated.
///
/// A work queue would satisfy "an invalidation was delivered" while leaving all
/// but one replica serving the revoked grant. Three independent replicas each
/// hold a cached `Allow` for the same subject; one signed payload is delivered
/// to all three (as a fanout exchange would); all three must lose it.
#[test]
fn one_publish_invalidates_every_subscriber() {
    let tenant = Uuid::new_v4();
    let subject = Uuid::new_v4();
    let req = request(tenant, subject);

    let publisher_id = Uuid::new_v4();
    let replicas: Vec<Replica> = (0..3).map(|_| Replica::new()).collect();

    for r in &replicas {
        r.cache.insert(&req, AccessDecision::Allow);
        assert!(
            r.cache.get(&req).is_some(),
            "precondition: every replica caches the pre-revocation allow"
        );
    }

    // ONE publish.
    let payload = build_signed_invalidation(
        MASTER_KEY,
        publisher_id,
        InvalidationEvent::Subject {
            tenant_id: tenant,
            subject_id: subject,
        },
        Utc::now(),
    )
    .expect("sign");

    for r in &replicas {
        assert_eq!(
            r.deliver(&payload),
            InvalidationOutcome::Applied(InvalidationEvent::Subject {
                tenant_id: tenant,
                subject_id: subject
            }),
            "every subscriber must apply the broadcast — a work queue would \
             satisfy only one of them and leave the rest serving a revoked grant"
        );
    }

    for (i, r) in replicas.iter().enumerate() {
        assert!(
            r.cache.get(&req).is_none(),
            "replica {i} still serves the revoked decision after the broadcast"
        );
    }
}

/// A whole-tenant flush likewise reaches every replica, and only that tenant.
#[test]
fn tenant_flush_reaches_every_subscriber_and_only_that_tenant() {
    let tenant = Uuid::new_v4();
    let other_tenant = Uuid::new_v4();
    let replicas: Vec<Replica> = (0..2).map(|_| Replica::new()).collect();

    let victim = request(tenant, Uuid::new_v4());
    let bystander = request(other_tenant, Uuid::new_v4());
    for r in &replicas {
        r.cache.insert(&victim, AccessDecision::Allow);
        r.cache.insert(&bystander, AccessDecision::Allow);
    }

    let payload = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");

    for r in &replicas {
        assert!(matches!(
            r.deliver(&payload),
            InvalidationOutcome::Applied(_)
        ));
        assert!(r.cache.get(&victim).is_none());
        assert!(
            r.cache.get(&bystander).is_some(),
            "another tenant's entries must be untouched"
        );
    }
}

/// The topology parameters that make the fan-out a fan-out.
#[test]
fn topology_is_a_fanout_with_per_replica_exclusive_queues() {
    assert_eq!(
        invalidation_exchange_kind(),
        ExchangeKind::Fanout,
        "a direct/topic exchange feeding one shared queue would deliver each \
         invalidation to exactly ONE replica"
    );
    assert_eq!(
        exchanges::AUTHZ_CACHE_INVALIDATE,
        "axiam.authz.cache.invalidate"
    );

    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    assert_ne!(invalidation_queue_name(a), invalidation_queue_name(b));
    assert!(invalidation_queue_name(a).starts_with(exchanges::AUTHZ_CACHE_INVALIDATE));

    let opts = invalidation_queue_options();
    assert!(opts.exclusive);
    assert!(opts.auto_delete);
    assert!(!opts.durable);
}

// ---------------------------------------------------------------------------
// 2. Broker unavailable — the degraded mode
// ---------------------------------------------------------------------------

/// **The availability/security trade, pinned.** A replica whose invalidation
/// consumer is not connected must fall back to uncached evaluation — correct,
/// just slower — rather than keep serving allows it can no longer invalidate.
#[test]
fn a_replica_that_cannot_hear_invalidations_stops_serving_its_cache() {
    let cache = cache();
    let req = request(Uuid::new_v4(), Uuid::new_v4());
    cache.insert(&req, AccessDecision::Allow);
    assert!(matches!(cache.get(&req), Some(AccessDecision::Allow)));

    // This is exactly what `run_cache_invalidation_consumer`'s TrustGuard does
    // on every exit path (subscribe failure, stream end, cancellation).
    cache.set_trusted(false);

    assert!(
        cache.get(&req).is_none(),
        "a disconnected replica must NOT serve a cached allow — this is the \
         silent-stale-allow failure §4.2 exists to remove"
    );
    assert!(cache.is_empty(), "losing trust flushes");

    // ... and it does not hard-fail: the engine simply re-evaluates. Writes are
    // discarded so nothing accumulates behind an unverifiable gate.
    cache.insert(&req, AccessDecision::Allow);
    assert!(cache.get(&req).is_none());

    let snap = cache.snapshot();
    assert!(!snap.trusted);
    assert!(
        snap.bypassed >= 2,
        "the degraded mode must be counted, not silent (bypassed={})",
        snap.bypassed
    );
}

/// Recovery starts from an empty cache — never from entries that survived a
/// window in which invalidations could have been missed.
#[test]
fn reconnecting_restores_service_from_a_provably_fresh_cache() {
    let cache = cache();
    let req = request(Uuid::new_v4(), Uuid::new_v4());
    cache.insert(&req, AccessDecision::Allow);

    cache.set_trusted(false);
    cache.set_trusted(true);

    assert!(cache.get(&req).is_none(), "recovery starts empty");
    cache.insert(&req, AccessDecision::Allow);
    assert!(
        matches!(cache.get(&req), Some(AccessDecision::Allow)),
        "and then serves normally again"
    );
}

/// A stale (but validly signed) message is rejected and logged — but it must
/// **not** be able to revoke trust. Otherwise one captured broadcast becomes a
/// lever for disabling every replica's cache on demand.
#[test]
fn a_stale_message_is_rejected_without_disabling_the_cache() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();
    let req = request(tenant, Uuid::new_v4());
    replica.cache.insert(&req, AccessDecision::Allow);

    let long_ago = Utc::now() - chrono::Duration::seconds(3_600);
    let payload = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        long_ago,
    )
    .expect("sign");

    assert_eq!(
        replica.deliver(&payload),
        InvalidationOutcome::Rejected(InvalidationReject::Stale)
    );
    assert!(
        replica.cache.is_trusted(),
        "trust must follow connection liveness only — never message content"
    );
    assert!(
        replica.cache.get(&req).is_some(),
        "a rejected message applies nothing"
    );
}

// ---------------------------------------------------------------------------
// 3. Self-echo
// ---------------------------------------------------------------------------

/// The fanout delivers the publisher's own message back to it. That must be a
/// no-op — the publisher already invalidated locally before publishing.
#[test]
fn self_echo_is_a_no_op() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();
    let req = request(tenant, Uuid::new_v4());
    replica.cache.insert(&req, AccessDecision::Allow);

    // Published BY this replica (origin_id == its own id).
    let echo = build_signed_invalidation(
        MASTER_KEY,
        replica.id,
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");

    assert_eq!(replica.deliver(&echo), InvalidationOutcome::SelfEcho);
    assert!(
        replica.cache.get(&req).is_some(),
        "a self-echo must not trigger a second, redundant invalidation"
    );

    // The identical event from ANOTHER replica is applied — proving the no-op
    // is due to origin matching, not to the message being inert.
    let foreign = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");
    assert!(matches!(
        replica.deliver(&foreign),
        InvalidationOutcome::Applied(_)
    ));
    assert!(replica.cache.get(&req).is_none());
}

/// A self-echo short-circuits before the replay guard, so a replica's own
/// broadcasts never consume its bounded nonce capacity. It also cannot loop:
/// `handle_invalidation` only ever calls `InvalidationEvent::apply`, which
/// touches the cache directly and has no path back to a publish.
#[test]
fn self_echo_does_not_consume_replay_capacity() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();
    for _ in 0..50 {
        let echo = build_signed_invalidation(
            MASTER_KEY,
            replica.id,
            InvalidationEvent::Tenant { tenant_id: tenant },
            Utc::now(),
        )
        .expect("sign");
        assert_eq!(replica.deliver(&echo), InvalidationOutcome::SelfEcho);
    }
    assert!(
        replica.guard.is_empty(),
        "self-echoes must not fill the replay guard"
    );
}

// ---------------------------------------------------------------------------
// 4. Message authenticity (§8 scheme)
// ---------------------------------------------------------------------------

/// Serialize a message with an arbitrary (possibly absent/wrong) signature.
fn raw_with_signature(message: &CacheInvalidationMessage) -> Vec<u8> {
    serde_json::to_vec(message).expect("serialize")
}

fn unsigned_message(origin: Uuid, tenant: Uuid) -> CacheInvalidationMessage {
    CacheInvalidationMessage {
        origin_id: origin,
        tenant_id: tenant,
        subject_id: None,
        key_version: CURRENT_KEY_VERSION,
        nonce: Uuid::new_v4(),
        issued_at: Utc::now(),
        hmac_signature: None,
    }
}

#[test]
fn unsigned_message_is_rejected() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();
    let req = request(tenant, Uuid::new_v4());
    replica.cache.insert(&req, AccessDecision::Allow);

    let raw = raw_with_signature(&unsigned_message(Uuid::new_v4(), tenant));
    assert_eq!(
        replica.deliver(&raw),
        InvalidationOutcome::Rejected(InvalidationReject::BadSignature),
        "there is no accept-when-absent path"
    );
    assert!(replica.cache.get(&req).is_some());
}

#[test]
fn wrong_key_is_rejected() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();
    let raw = build_signed_invalidation(
        b"a-completely-different-master-key",
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");

    assert_eq!(
        replica.deliver(&raw),
        InvalidationOutcome::Rejected(InvalidationReject::BadSignature)
    );
}

#[test]
fn tampered_message_is_rejected() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();
    let victim_tenant = Uuid::new_v4();

    let raw = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");

    // Repoint the invalidation at a different tenant, keeping the signature.
    let mut message: CacheInvalidationMessage = serde_json::from_slice(&raw).expect("decode");
    message.tenant_id = victim_tenant;
    let tampered = raw_with_signature(&message);

    assert_eq!(
        replica.deliver(&tampered),
        InvalidationOutcome::Rejected(InvalidationReject::BadSignature)
    );

    // Same for repointing the subject.
    let mut message: CacheInvalidationMessage = serde_json::from_slice(&raw).expect("decode");
    message.subject_id = Some(Uuid::new_v4());
    assert_eq!(
        replica.deliver(&raw_with_signature(&message)),
        InvalidationOutcome::Rejected(InvalidationReject::BadSignature)
    );
}

/// Per-tenant HKDF subkeys: a signature produced for tenant A must not verify
/// when the message claims tenant B, even from the same master key.
#[test]
fn cross_tenant_signature_is_rejected() {
    let replica = Replica::new();
    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();

    let mut message = unsigned_message(Uuid::new_v4(), tenant_b);
    // Sign the tenant-B body with tenant A's subkey.
    let canonical = serde_json::to_vec(&message).expect("canonical");
    let subkey_a = derive_tenant_key(MASTER_KEY, tenant_a, CURRENT_KEY_VERSION);
    message.hmac_signature = Some(sign_payload(&subkey_a, &canonical));

    assert_eq!(
        replica.deliver(&raw_with_signature(&message)),
        InvalidationOutcome::Rejected(InvalidationReject::BadSignature)
    );
}

#[test]
fn pre_v2_key_version_is_rejected() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();

    let mut message = unsigned_message(Uuid::new_v4(), tenant);
    message.key_version = 1;
    // Sign it correctly under v1 so the ONLY reason it fails is the floor.
    let canonical = serde_json::to_vec(&message).expect("canonical");
    let subkey = derive_tenant_key(MASTER_KEY, tenant, 1);
    message.hmac_signature = Some(sign_payload(&subkey, &canonical));

    assert_eq!(
        replica.deliver(&raw_with_signature(&message)),
        InvalidationOutcome::Rejected(InvalidationReject::KeyVersion),
        "there is no v1 grace path (NEW-4 hard cutover)"
    );
}

#[test]
fn malformed_payload_is_rejected() {
    let replica = Replica::new();
    assert_eq!(
        replica.deliver(b"not json at all"),
        InvalidationOutcome::Rejected(InvalidationReject::Malformed)
    );
}

/// A captured, validly-signed broadcast replayed inside the freshness window
/// is applied exactly once per replica — the thundering-herd lever is bounded.
#[test]
fn replayed_message_is_rejected_after_the_first_application() {
    let replica = Replica::new();
    let tenant = Uuid::new_v4();
    let raw = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");

    assert!(matches!(
        replica.deliver(&raw),
        InvalidationOutcome::Applied(_)
    ));
    for _ in 0..5 {
        assert_eq!(
            replica.deliver(&raw),
            InvalidationOutcome::Rejected(InvalidationReject::Replay)
        );
    }
}

/// Replay dedup is **per replica**. On a fanout every replica sees the same
/// nonce, so a shared store would let one replica win and make all the others
/// reject the invalidation — reintroducing the stale-allow hole everywhere but
/// on one node. This test is the regression guard for that mistake.
#[test]
fn replay_dedup_is_per_replica_not_shared() {
    let tenant = Uuid::new_v4();
    let req = request(tenant, Uuid::new_v4());
    let replicas: Vec<Replica> = (0..3).map(|_| Replica::new()).collect();
    for r in &replicas {
        r.cache.insert(&req, AccessDecision::Allow);
    }

    let raw = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");

    for (i, r) in replicas.iter().enumerate() {
        assert!(
            matches!(r.deliver(&raw), InvalidationOutcome::Applied(_)),
            "replica {i} must apply the SAME nonce the others applied"
        );
        assert!(r.cache.get(&req).is_none());
    }
}

// ---------------------------------------------------------------------------
// 5. Inert when disabled
// ---------------------------------------------------------------------------

/// With the channel off, nothing about the cache changes: it is built trusted,
/// serves immediately, and no AMQP dependency is implied.
#[test]
fn disabled_channel_leaves_the_cache_exactly_as_before() {
    let cfg = AuthzConfig {
        decision_cache_enabled: true,
        ..AuthzConfig::default()
    };
    assert!(!cfg.decision_cache_broadcast_enabled, "default OFF");
    assert!(!cfg.cross_replica_invalidation_enabled());

    let cache = cfg.build_decision_cache().expect("cache enabled");
    let req = request(Uuid::new_v4(), Uuid::new_v4());
    cache.insert(&req, AccessDecision::Allow);
    assert!(
        matches!(cache.get(&req), Some(AccessDecision::Allow)),
        "with the channel off the cache serves immediately — no consumer to wait for"
    );
    assert_eq!(cache.snapshot().bypassed, 0);
}

/// With the channel on, the cache starts inert and only serves once a consumer
/// has subscribed — the startup window is not a stale-allow hole.
#[test]
fn enabled_channel_starts_inert_until_a_consumer_subscribes() {
    let cfg = AuthzConfig {
        decision_cache_enabled: true,
        decision_cache_broadcast_enabled: true,
        ..AuthzConfig::default()
    };
    let cache = cfg.build_decision_cache().expect("cache enabled");
    let req = request(Uuid::new_v4(), Uuid::new_v4());

    cache.insert(&req, AccessDecision::Allow);
    assert!(
        cache.get(&req).is_none(),
        "no serving before the invalidation consumer is up"
    );

    // `run_cache_invalidation_consumer` does this once subscribed.
    cache.set_trusted(true);
    cache.insert(&req, AccessDecision::Allow);
    assert!(matches!(cache.get(&req), Some(AccessDecision::Allow)));
}

// ---------------------------------------------------------------------------
// 6. Envelope shape
// ---------------------------------------------------------------------------

/// The HMAC is computed over the JSON in declaration order, exactly as for
/// `AuthzRequest`. Changing the field order silently invalidates every
/// signature on the wire during a rolling upgrade.
#[test]
fn wire_field_order_is_canonical() {
    let raw = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Subject {
            tenant_id: Uuid::new_v4(),
            subject_id: Uuid::new_v4(),
        },
        Utc::now(),
    )
    .expect("sign");
    let json = String::from_utf8(raw).expect("utf8");

    let expected = [
        "origin_id",
        "tenant_id",
        "subject_id",
        "key_version",
        "nonce",
        "issued_at",
        "hmac_signature",
    ];
    let positions: Vec<usize> = expected
        .iter()
        .map(|f| json.find(&format!("\"{f}\"")).expect("field present"))
        .collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    assert_eq!(
        positions, sorted,
        "fields must serialize in declaration order"
    );
}

/// A whole-tenant broadcast omits `subject_id` entirely, and a receiver turns
/// that back into the tenant-wide event.
#[test]
fn tenant_event_round_trips_without_a_subject_field() {
    let tenant = Uuid::new_v4();
    let raw = build_signed_invalidation(
        MASTER_KEY,
        Uuid::new_v4(),
        InvalidationEvent::Tenant { tenant_id: tenant },
        Utc::now(),
    )
    .expect("sign");
    assert!(!String::from_utf8_lossy(&raw).contains("subject_id"));

    let guard = NonceGuard::new();
    assert_eq!(
        process_invalidation(&raw, MASTER_KEY, Uuid::new_v4(), &guard, skew(), Utc::now()),
        InvalidationOutcome::Applied(InvalidationEvent::Tenant { tenant_id: tenant })
    );
}

/// The publisher stamps its configured origin id into every broadcast — the
/// value the consumer must be given for self-echo suppression to work.
#[test]
fn publisher_origin_id_is_the_self_echo_key() {
    let origin = Uuid::new_v4();
    let raw = build_signed_invalidation(
        MASTER_KEY,
        origin,
        InvalidationEvent::Tenant {
            tenant_id: Uuid::new_v4(),
        },
        Utc::now(),
    )
    .expect("sign");
    let message: CacheInvalidationMessage = serde_json::from_slice(&raw).expect("decode");
    assert_eq!(message.origin_id, origin);

    // And the consumer using that same id treats it as an echo.
    let guard = NonceGuard::new();
    assert_eq!(
        process_invalidation(&raw, MASTER_KEY, origin, &guard, skew(), Utc::now()),
        InvalidationOutcome::SelfEcho
    );
}

/// Type-level guard: the publisher is the `InvalidationBroadcaster` the engine
/// takes, so the wiring in `axiam-server` cannot drift.
#[test]
fn publisher_is_an_invalidation_broadcaster() {
    fn assert_broadcaster<T: axiam_authz::InvalidationBroadcaster>() {}
    assert_broadcaster::<CacheInvalidationPublisher>();
}

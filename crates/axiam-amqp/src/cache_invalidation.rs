//! Cross-replica authorization **decision-cache invalidation** over RabbitMQ
//! (§4.2 — closes the multi-replica stale-allow residual / threat-model
//! `T-88`).
//!
//! The `axiam-authz` decision cache invalidates process-locally. On a replica
//! that did not handle the mutation, a revoked grant could stay `Allow` until
//! its entry TTL-expired (default 5 s). This module is the transport that
//! makes an invalidation reach **every** replica, built on the AMQP
//! infrastructure and the §8 signed-message scheme this crate already has,
//! rather than a parallel mechanism.
//!
//! # 1. Fan-out, not a work queue — the decision everything else rests on
//!
//! Invalidation must reach *every* replica. A work queue (many consumers on
//! one shared queue) delivers each message to exactly **one** consumer, so all
//! but one replica would stay stale — worse than no channel at all, because
//! operators would believe the gap was closed. The topology is therefore:
//!
//! ```text
//!                       ┌──────────────────────────────────────────┐
//!   mutation on         │ exchange axiam.authz.cache.invalidate     │
//!   replica A  ────────▶│ type: FANOUT, durable                     │
//!                       └───┬──────────────┬───────────────┬────────┘
//!                           │              │               │
//!            queue …invalidate.<A>   …invalidate.<B>  …invalidate.<C>
//!            exclusive, auto-delete, non-durable, one per replica
//!                           │              │               │
//!                     (self-echo:      apply to        apply to
//!                      no-op)          B's cache       C's cache
//! ```
//!
//! Every replica declares **its own** queue, named after its process-unique
//! replica id, and binds it to the fanout exchange. `exclusive` means no other
//! connection can steal from it; `auto_delete` means it disappears with the
//! replica rather than accumulating messages for a pod that will never return.
//! Nothing is durable on the queue side and messages are published transient:
//! a replica that was down has an **empty** cache when it comes back, so
//! invalidations it missed are meaningless to it.
//!
//! # 2. What happens when AMQP is unavailable — the crux
//!
//! Hard-failing every authorization check when the broker is down would be a
//! catastrophic availability regression; silently continuing to serve a cache
//! that can no longer be invalidated is the security hole this exists to
//! close. The two sides are resolved **differently**, because their failures
//! mean different things:
//!
//! * **Publish side → fail the mutation.** [`CacheInvalidationPublisher`]
//!   publishes with publisher confirms and returns `Err` unless the broker
//!   acked. `AuthorizationEngine::invalidate_*` propagates that, and the REST
//!   mutation handler returns **503**. The operator asked for a revocation;
//!   the database write is durable but the fan-out did not happen, and saying
//!   "done" would be a lie. The local cache is always invalidated *before* the
//!   publish is attempted, so the failure never leaves the mutating replica
//!   itself stale, and every one of these mutations is idempotent in the
//!   narrowing direction, so a retry is safe.
//! * **Consume side → stop trusting the local cache.** When a replica's
//!   consumer is not subscribed (startup, subscribe failure, stream end, task
//!   cancellation), it calls `DecisionCache::set_trusted(false)`: the cache is
//!   flushed and every check falls back to full database evaluation — correct,
//!   just slower — instead of serving allows it can no longer invalidate.
//!   Availability is preserved; only throughput degrades. The transition is
//!   logged at ERROR and counted in `DecisionCacheStats::bypassed`, so the
//!   degraded mode is loud rather than silent.
//!
//! **No inbound message can revoke trust** — not a stale one, not a replayed
//! one. Otherwise an attacker holding a single captured, validly-signed
//! broadcast could disable every replica's cache at will. A rejected message is
//! logged and counted; it never moves the flag.
//!
//! ## 2a. Binding liveness — the heartbeat (§13.4 observation 1)
//!
//! Consumer liveness alone is not sufficient evidence, and this was a real gap.
//! A party with broker **configure** rights can `queue.unbind` a replica's queue
//! from the fanout exchange. Nothing visibly breaks: the consumer stays
//! subscribed to a queue nothing routes to any more, so trust stays `true` and
//! the replica keeps serving cached allows it will never be told to invalidate.
//! The publisher cannot see it either — `mandatory` is off, so the broker acks
//! an unroutable message. Invalidations are silently suppressed, bounded only by
//! `decision_cache_ttl_secs`.
//!
//! Each replica therefore publishes a **self-addressed heartbeat** on an
//! interval ([`build_signed_heartbeat`]) and watches for its own to come back.
//! That round trip is the smallest thing that actually exercises the property in
//! question — publish → exchange → binding → queue → consumer — so an unbound
//! queue breaks it immediately. After
//! [`HEARTBEAT_MISS_THRESHOLD`] consecutive missed intervals, the watchdog calls
//! `set_trusted(false)` ([`InvalidationLiveness`]).
//!
//! Three properties make this safe rather than a new lever:
//!
//! * **The watchdog can only revoke, never grant.** Trust is granted in exactly
//!   one place — the consumer, on a successful `basic_consume`. A watchdog able
//!   to grant it could resurrect trust on a replica whose consumer had died.
//! * **Only our OWN heartbeat counts.** Another replica's heartbeat proves that
//!   replica can publish, which says nothing about *our* binding.
//! * **Heartbeats never touch the cache and never enter the nonce guard.** They
//!   are separated out before any [`InvalidationEvent`] is constructed, so a
//!   heartbeat has no path to `apply`; and since they arrive on a fixed interval
//!   from every replica, letting them consume the bounded nonce-guard capacity
//!   would evict real invalidation nonces and weaken replay protection.
//!
//! * **A replayed heartbeat does not count** (§15.2). Bypassing the nonce guard
//!   left a narrow path: a party with broker rights who captured one signed
//!   heartbeat could replay it inside the freshness window to keep this
//!   replica's watchdog satisfied while its queue was unbound. Acceptance is
//!   therefore bound to nonces *this* replica published and has not yet seen
//!   back ([`InvalidationLiveness::record_sent_heartbeat`]), which closes the
//!   replay without spending the shared guard's bounded capacity.
//!
//! Heartbeats **cannot be disabled** while broadcast is on. An earlier revision
//! accepted an interval of `0` as "off", which meant this whole mitigation could
//! be removed with one environment variable and only a warning — leaving the TTL
//! as the sole bound, which is the state it exists to escape. The TTL is itself
//! now clamped (`MAX_DECISION_CACHE_TTL_SECS`), so neither half of the bound is
//! operator-removable.
//!
//! # 3. Authenticity
//!
//! An invalidation is a control-plane instruction, so it carries the full §8
//! envelope ([`CacheInvalidationMessage`]): per-tenant HKDF-SHA256 subkey,
//! `key_version >= 2` hard floor, per-message `nonce`, and an `issued_at`
//! freshness window. Broker ACLs are not the only thing standing between an
//! attacker with publish rights and everyone's cache.
//!
//! The nonce is deduplicated **per replica, in memory** ([`NonceGuard`]) — see
//! [`CacheInvalidationMessage::nonce`] for why the shared durable nonce store
//! used by the authz consumer would be exactly wrong on a fanout.
//!
//! # 4. Self-echo
//!
//! A fanout delivers the message back to the publisher. The publisher stamps
//! its own `origin_id`; a consumer seeing its own id treats the delivery as a
//! **no-op** (it already invalidated locally, before publishing). It cannot
//! loop: [`InvalidationEvent::apply`] talks to the `DecisionCache` directly and
//! has no reachable path to a publish, so nothing a consumer does can emit a
//! message.
//!
//! # 5. Opt-in, default-off
//!
//! Nothing here runs unless **both** `AXIAM__AUTHZ__DECISION_CACHE_ENABLED`
//! and `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED` are true. With the
//! channel off, the decision cache behaves exactly as documented before §4.2:
//! process-local invalidation, TTL-bounded cross-replica staleness, no AMQP
//! dependency acquired by enabling the cache.

use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axiam_authz::decision_cache::DecisionCache;
use axiam_authz::invalidation::{InvalidationBroadcaster, InvalidationEvent};
use axiam_core::error::{AxiamError, AxiamResult};
use chrono::{DateTime, Utc};
use futures_lite::StreamExt;
use lapin::options::{
    BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions,
    ExchangeDeclareOptions, QueueBindOptions, QueueDeclareOptions,
};
use lapin::types::FieldTable;
use lapin::{BasicProperties, Channel, Confirmation, ExchangeKind};
use tokio::sync::Mutex as TokioMutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::connection::exchanges;
use crate::error::AmqpError;
use crate::messages::{
    CURRENT_KEY_VERSION, CacheInvalidationMessage, MIN_ACCEPTED_KEY_VERSION, derive_tenant_key,
    is_fresh, sign_payload, verify_tenant_signature,
};

/// Upper bound on nonces retained by a replica's [`NonceGuard`].
///
/// The guard only has to cover the freshness window (default 30 s), so this is
/// generous: 20 000 invalidations in 30 s is ~660 mutations/second sustained,
/// far beyond any realistic administrative mutation rate. If the bound is ever
/// hit, the oldest nonces are dropped first — a replay older than the retained
/// set is still bounded by the freshness gate, and the worst outcome remains a
/// redundant cache flush.
const NONCE_GUARD_CAPACITY: usize = 20_000;

// ---------------------------------------------------------------------------
// Topology
// ---------------------------------------------------------------------------

/// Exchange kind for [`exchanges::AUTHZ_CACHE_INVALIDATE`].
///
/// **Fanout, deliberately.** Exposed as a function rather than inlined so the
/// choice is assertable by a test: this is the single most important decision
/// in the module, and a future refactor that turned it into a direct/topic
/// exchange with a shared queue would silently reintroduce the stale-allow
/// residual on every replica but one.
pub fn invalidation_exchange_kind() -> ExchangeKind {
    ExchangeKind::Fanout
}

/// Per-replica queue name. One queue **per replica**, never a shared one.
pub fn invalidation_queue_name(replica_id: Uuid) -> String {
    format!("{}.{}", exchanges::AUTHZ_CACHE_INVALIDATE, replica_id)
}

/// Declaration options for a replica's own invalidation queue.
///
/// * `exclusive` — only this connection may consume it, so no other process
///   can take deliveries meant for this replica.
/// * `auto_delete` — it vanishes with the replica instead of accumulating
///   messages for a pod that is never coming back.
/// * not `durable` — a replica that was down has an empty cache when it
///   returns, so invalidations it missed are meaningless to it.
pub fn invalidation_queue_options() -> QueueDeclareOptions {
    QueueDeclareOptions {
        exclusive: true,
        auto_delete: true,
        durable: false,
        ..QueueDeclareOptions::default()
    }
}

/// Declare the fanout exchange, this replica's exclusive auto-delete queue, and
/// the binding between them. Returns the queue name.
pub async fn declare_cache_invalidation_topology(
    channel: &Channel,
    replica_id: Uuid,
) -> Result<String, AmqpError> {
    channel
        .exchange_declare(
            exchanges::AUTHZ_CACHE_INVALIDATE.into(),
            invalidation_exchange_kind(),
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(AmqpError::Declaration)?;

    let queue = invalidation_queue_name(replica_id);
    channel
        .queue_declare(
            queue.as_str().into(),
            invalidation_queue_options(),
            FieldTable::default(),
        )
        .await
        .map_err(AmqpError::Declaration)?;

    // Fanout ignores the routing key; bind with the empty one.
    channel
        .queue_bind(
            queue.as_str().into(),
            exchanges::AUTHZ_CACHE_INVALIDATE.into(),
            "".into(),
            QueueBindOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(AmqpError::Declaration)?;

    info!(
        exchange = exchanges::AUTHZ_CACHE_INVALIDATE,
        queue = %queue,
        "Declared authz decision-cache invalidation topology (fanout, per-replica queue)"
    );
    Ok(queue)
}

// ---------------------------------------------------------------------------
// Signing (publisher-side, broker-free)
// ---------------------------------------------------------------------------

/// Build the signed wire bytes for one invalidation broadcast.
///
/// Broker-free seam so the whole envelope — canonical form, per-tenant subkey,
/// nonce, `issued_at` — is unit-testable without RabbitMQ, mirroring
/// `process_authz_request`'s separation of decode/verify from channel I/O.
pub fn build_signed_invalidation(
    master_key: &[u8],
    origin_id: Uuid,
    event: InvalidationEvent,
    now: DateTime<Utc>,
) -> Result<Vec<u8>, AmqpError> {
    sign_message(
        master_key,
        CacheInvalidationMessage {
            origin_id,
            tenant_id: event.tenant_id(),
            subject_id: event.subject_id(),
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::new_v4(),
            issued_at: now,
            heartbeat: false,
            hmac_signature: None,
        },
    )
}

/// Tenant id stamped on a liveness heartbeat.
///
/// Heartbeats are not tenant-scoped — they carry no cache effect at all — but
/// the envelope derives its HMAC subkey from `tenant_id`, so the field must
/// hold *something*. The nil UUID is used deliberately: it is not a real
/// tenant, so even if a heartbeat were somehow mistaken for an invalidation it
/// could only ever flush a tenant that does not exist. The consumer's heartbeat
/// branch runs before any event is constructed, so that path is unreachable —
/// this is the second line of defence, not the first.
pub const HEARTBEAT_TENANT_ID: Uuid = Uuid::nil();

/// Build the signed wire bytes for one liveness heartbeat (§13.4 observation 1).
///
/// Same envelope, same signing, same freshness and replay gates as an
/// invalidation — a heartbeat is not a privileged message type, it simply
/// carries no cache effect.
/// Returns the wire bytes **and the nonce**; the caller registers the nonce as
/// outstanding so the echo can be told apart from a replay (§15.2 gap 3).
pub fn build_signed_heartbeat(
    master_key: &[u8],
    origin_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(Vec<u8>, Uuid), AmqpError> {
    let nonce = Uuid::new_v4();
    let payload = sign_message(
        master_key,
        CacheInvalidationMessage {
            origin_id,
            tenant_id: HEARTBEAT_TENANT_ID,
            subject_id: None,
            key_version: CURRENT_KEY_VERSION,
            nonce,
            issued_at: now,
            heartbeat: true,
            hmac_signature: None,
        },
    )?;
    Ok((payload, nonce))
}

/// Canonicalize, sign, and serialize one message. Shared by the invalidation and
/// heartbeat builders so the two can never drift into signing different shapes.
fn sign_message(
    master_key: &[u8],
    mut message: CacheInvalidationMessage,
) -> Result<Vec<u8>, AmqpError> {
    // Canonical body = the message with `hmac_signature` absent.
    let canonical = serde_json::to_vec(&message)
        .map_err(|e| AmqpError::Publish(format!("canonicalize invalidation: {e}")))?;
    let subkey = derive_tenant_key(master_key, message.tenant_id, message.key_version);
    message.hmac_signature = Some(sign_payload(&subkey, &canonical));

    serde_json::to_vec(&message)
        .map_err(|e| AmqpError::Publish(format!("serialize invalidation: {e}")))
}

// ---------------------------------------------------------------------------
// Per-replica replay guard
// ---------------------------------------------------------------------------

/// Bounded in-memory nonce store for one replica's invalidation consumer.
///
/// Deliberately **not** the shared durable `AmqpNonceRepository` the authz
/// consumer uses: on a fanout every replica receives the same nonce, so a
/// shared store would let exactly one replica record it and make every other
/// replica reject the invalidation as a replay — silently reintroducing the
/// stale-allow hole on all but one replica. Per-replica memory is the correct
/// scope for a broadcast.
pub struct NonceGuard {
    inner: Mutex<NonceGuardInner>,
}

#[derive(Default)]
struct NonceGuardInner {
    seen: HashSet<Uuid>,
    /// `(expiry, nonce)` in insertion order; insertion order is expiry order
    /// because every entry uses the same window.
    order: VecDeque<(DateTime<Utc>, Uuid)>,
}

impl Default for NonceGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceGuard {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NonceGuardInner::default()),
        }
    }

    /// Record `nonce`, returning `true` when it is **new** (accept the message)
    /// and `false` when it has already been seen within the window (replay).
    ///
    /// Entries are dropped once `expires_at` has passed — the freshness gate
    /// already rejects anything that old — and the set is hard-capped at
    /// [`NONCE_GUARD_CAPACITY`].
    pub fn check_and_record(
        &self,
        nonce: Uuid,
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        while let Some(&(expiry, old)) = inner.order.front() {
            if expiry > now && inner.order.len() <= NONCE_GUARD_CAPACITY {
                break;
            }
            inner.order.pop_front();
            inner.seen.remove(&old);
        }
        if !inner.seen.insert(nonce) {
            return false;
        }
        inner.order.push_back((expires_at, nonce));
        true
    }

    /// Number of retained nonces (observability / tests).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .seen
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ---------------------------------------------------------------------------
// Consumer-side processing (broker-free)
// ---------------------------------------------------------------------------

/// Why a delivery was refused. Every variant is a *drop*, never a requeue: a
/// broadcast has no second consumer to hand it to, and requeueing would
/// hot-loop against ourselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationReject {
    /// Payload did not deserialize.
    Malformed,
    /// Unsigned, or the HMAC did not verify under the tenant's subkey.
    BadSignature,
    /// `key_version` below [`MIN_ACCEPTED_KEY_VERSION`] (pre-replay-protection).
    KeyVersion,
    /// `issued_at` outside the freshness window.
    Stale,
    /// This exact nonce was already applied on this replica.
    Replay,
}

/// Outcome of processing one invalidation delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationOutcome {
    /// Verified and fresh — the caller must apply this event to the cache.
    Applied(InvalidationEvent),
    /// The replica's own broadcast, echoed back by the fanout. **No-op**: the
    /// publisher already invalidated locally before publishing, so re-applying
    /// would be redundant work on the exact code path the cache exists to make
    /// fast.
    SelfEcho,
    /// A liveness heartbeat (§13.4 observation 1). Never touches the cache.
    /// `own` distinguishes this replica's own heartbeat — the only one that
    /// carries information, since observing it proves *our* binding is intact —
    /// from another replica's, which is simply ignored. `nonce` lets the caller
    /// tell a genuine echo from a replay (§15.2 gap 3).
    Heartbeat { own: bool, nonce: Uuid },
    /// Refused; see [`InvalidationReject`].
    Rejected(InvalidationReject),
}

/// Decode, verify, freshness-check, self-echo-check and replay-check one
/// invalidation payload. **Pure** — no broker, no cache, `now` injected — so
/// every branch is unit-testable, mirroring `process_authz_request`.
///
/// Order is deliberate: signature first (nothing unauthenticated influences
/// any later step), then the version floor, then freshness, then self-echo
/// (skipping before the nonce guard so our own broadcasts do not consume its
/// capacity), then replay.
pub fn process_invalidation(
    raw: &[u8],
    master_key: &[u8],
    local_origin: Uuid,
    guard: &NonceGuard,
    skew: chrono::Duration,
    now: DateTime<Utc>,
) -> InvalidationOutcome {
    let mut message: CacheInvalidationMessage = match serde_json::from_slice(raw) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "Invalid cache-invalidation payload — dropping");
            return InvalidationOutcome::Rejected(InvalidationReject::Malformed);
        }
    };

    // §8: verify the per-tenant derived HMAC over the canonical body
    // (signature field absent). No fail-open path — an unsigned message is
    // rejected exactly like a badly-signed one.
    let received_sig = message.hmac_signature.take();
    let tenant_id = message.tenant_id;
    let key_version = message.key_version;
    let canonical = match serde_json::to_vec(&message) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "Cache-invalidation canonicalization failed — dropping");
            return InvalidationOutcome::Rejected(InvalidationReject::Malformed);
        }
    };
    if !verify_tenant_signature(
        master_key,
        tenant_id,
        key_version,
        &canonical,
        received_sig.as_deref(),
    ) {
        warn!(
            tenant_id = %tenant_id,
            "Cache-invalidation message unsigned or HMAC verification failed — rejecting"
        );
        return InvalidationOutcome::Rejected(InvalidationReject::BadSignature);
    }

    if key_version < MIN_ACCEPTED_KEY_VERSION {
        warn!(
            tenant_id = %tenant_id,
            key_version,
            "Cache-invalidation key_version below minimum — rejecting"
        );
        return InvalidationOutcome::Rejected(InvalidationReject::KeyVersion);
    }

    if !is_fresh(message.issued_at, now, skew) {
        // Logged, counted — but deliberately NOT a reason to distrust the
        // cache: see the module docs (trust follows connection liveness only,
        // so a captured message cannot be used to disable every replica's
        // cache).
        warn!(
            tenant_id = %tenant_id,
            issued_at = %message.issued_at,
            "Cache-invalidation issued_at outside freshness window — rejecting"
        );
        return InvalidationOutcome::Rejected(InvalidationReject::Stale);
    }

    // Heartbeats are separated out BEFORE the nonce guard and before any event
    // is constructed. Two reasons, both deliberate: a heartbeat must never be
    // able to reach `InvalidationEvent::apply` (so it cannot flush anything),
    // and heartbeats arrive on a fixed interval from every replica, so letting
    // them consume the bounded nonce-guard capacity would evict real
    // invalidation nonces and weaken replay protection on a busy cluster.
    if message.heartbeat {
        let own = message.origin_id == local_origin;
        debug!(own, "Cache-invalidation liveness heartbeat");
        return InvalidationOutcome::Heartbeat {
            own,
            nonce: message.nonce,
        };
    }

    if message.origin_id == local_origin {
        debug!(tenant_id = %tenant_id, "Cache-invalidation self-echo — no-op");
        return InvalidationOutcome::SelfEcho;
    }

    if !guard.check_and_record(message.nonce, message.issued_at + skew, now) {
        warn!(
            tenant_id = %tenant_id,
            nonce = %message.nonce,
            "Cache-invalidation nonce replay detected — rejecting"
        );
        return InvalidationOutcome::Rejected(InvalidationReject::Replay);
    }

    let event = match message.subject_id {
        Some(subject_id) => InvalidationEvent::Subject {
            tenant_id,
            subject_id,
        },
        None => InvalidationEvent::Tenant { tenant_id },
    };
    InvalidationOutcome::Applied(event)
}

/// [`process_invalidation`] plus application to `cache`.
///
/// The only place a received message touches state. It calls
/// [`InvalidationEvent::apply`], which talks to the `DecisionCache` directly —
/// there is no path from here back to a publish, so an echo cannot loop.
pub fn handle_invalidation(
    raw: &[u8],
    cache: &DecisionCache,
    master_key: &[u8],
    local_origin: Uuid,
    guard: &NonceGuard,
    skew: chrono::Duration,
    now: DateTime<Utc>,
) -> InvalidationOutcome {
    let outcome = process_invalidation(raw, master_key, local_origin, guard, skew, now);
    if let InvalidationOutcome::Applied(event) = outcome {
        event.apply(cache);
    }
    outcome
}

// ---------------------------------------------------------------------------
// Liveness (§13.4 observation 1)
// ---------------------------------------------------------------------------

/// How many heartbeat intervals may pass with no self-echo before this replica
/// stops trusting its cache.
///
/// Three, not one: a single missed heartbeat is far more likely to be a broker
/// hiccup or a scheduling delay than a broken binding, and revoking trust on it
/// would make every transient blip a latency cliff. Three consecutive misses is
/// long enough to be a real signal and still bounded well below any interval an
/// operator would find acceptable for a stale allow.
pub const HEARTBEAT_MISS_THRESHOLD: u32 = 3;

/// Tracks whether this replica is still *receiving* its own broadcasts.
///
/// The gap this closes (§13.4 observation 1): the cache's trust flag follows
/// **consumer liveness** — it is set when `basic_consume` succeeds and cleared
/// when the consumer exits. But a party with broker *configure* rights can
/// `queue.unbind` a replica's queue from the fanout exchange. The consumer stays
/// happily subscribed to a queue nothing is routed to any more, trust stays
/// `true`, and the replica keeps serving cached allows it will never be told to
/// invalidate. The publisher sees nothing either: with `mandatory` off, the
/// broker acks an unroutable message.
///
/// A self-addressed heartbeat is the smallest thing that actually tests the
/// property in question, because it exercises the *entire* loop — publish →
/// exchange → binding → queue → consumer. An unbound queue breaks it
/// immediately.
///
/// **This type can only ever revoke trust, never grant it.** Trust is granted in
/// exactly one place, by the consumer, on a successful `basic_consume`. A
/// watchdog that could also grant it would be able to resurrect trust on a
/// replica whose consumer had died — turning a fail-safe into a fail-open.
pub struct InvalidationLiveness {
    /// When we last saw our own broadcast come back. `None` = not subscribed.
    last_own_echo: Mutex<Option<DateTime<Utc>>>,
    /// Nonces of heartbeats this replica has published and not yet seen return
    /// (§15.2 gap 3).
    ///
    /// Heartbeats deliberately bypass the [`NonceGuard`] — they arrive on a
    /// fixed interval from every replica and would evict real invalidation
    /// nonces from its bounded capacity. But that left a narrow suppression
    /// path: a party with broker rights who captured one signed heartbeat could
    /// replay it inside the freshness window to keep this replica's watchdog
    /// satisfied while its queue was unbound — the exact adversary Obs 1 is
    /// about.
    ///
    /// Binding acceptance to nonces *we* generated closes that without touching
    /// the shared guard: a replayed heartbeat carries a nonce that was already
    /// consumed (or never issued here), so it is ignored. This is strictly
    /// cheaper than a general replay guard because the set only ever holds the
    /// handful of heartbeats currently in flight.
    outstanding: Mutex<VecDeque<Uuid>>,
}

/// Cap on [`InvalidationLiveness::outstanding`].
///
/// Only heartbeats still in flight matter, and a heartbeat that has not come
/// back within a few intervals is already a miss. A small ring keeps this
/// bounded regardless of broker behaviour — an unbound queue means every
/// published nonce goes unanswered, and the set must not grow for as long as
/// that lasts.
const MAX_OUTSTANDING_HEARTBEATS: usize = 8;

impl Default for InvalidationLiveness {
    fn default() -> Self {
        Self::new()
    }
}

impl InvalidationLiveness {
    pub fn new() -> Self {
        Self {
            last_own_echo: Mutex::new(None),
            outstanding: Mutex::new(VecDeque::new()),
        }
    }

    /// Record a heartbeat nonce this replica is about to publish (§15.2 gap 3).
    pub fn record_sent_heartbeat(&self, nonce: Uuid) {
        let mut q = self
            .outstanding
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if q.len() >= MAX_OUTSTANDING_HEARTBEATS {
            q.pop_front();
        }
        q.push_back(nonce);
    }

    /// Consume `nonce` if this replica published it and has not seen it back.
    ///
    /// Returns `false` for a nonce we never issued or already consumed — i.e.
    /// for a replayed heartbeat, which must not refresh the liveness clock.
    fn consume_outstanding(&self, nonce: Uuid) -> bool {
        let mut q = self
            .outstanding
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match q.iter().position(|n| *n == nonce) {
            Some(i) => {
                q.remove(i);
                true
            }
            None => false,
        }
    }

    /// Called by the consumer immediately after it subscribes. Starts the clock:
    /// without this, a freshly-subscribed replica would look infinitely stale
    /// and the watchdog would revoke trust before the first heartbeat round.
    pub fn mark_subscribed(&self, now: DateTime<Utc>) {
        *self.lock() = Some(now);
    }

    /// Called by the consumer when it observes its **own** heartbeat.
    ///
    /// Refreshes the liveness clock **only** for a nonce this replica actually
    /// published and has not already seen back (§15.2 gap 3), so a replayed
    /// heartbeat cannot hold the watchdog open. Returns whether it counted.
    pub fn record_own_heartbeat(&self, nonce: Uuid, now: DateTime<Utc>) -> bool {
        if !self.consume_outstanding(nonce) {
            return false;
        }
        *self.lock() = Some(now);
        true
    }

    /// Called when the consumer stops, so a reconnecting consumer cannot inherit
    /// a stale "recently alive" timestamp from its predecessor.
    pub fn mark_unsubscribed(&self) {
        *self.lock() = None;
        // A reconnecting consumer must not be able to satisfy its watchdog with
        // a heartbeat its predecessor published.
        self.outstanding
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }

    /// The last observation, if any.
    pub fn last_own_echo(&self) -> Option<DateTime<Utc>> {
        *self.lock()
    }

    /// Has the loop been silent for longer than `interval * HEARTBEAT_MISS_THRESHOLD`?
    ///
    /// `None` (not subscribed) is **not** stale: the consumer's own exit path
    /// already marked the cache untrusted, and reporting staleness here would
    /// only produce a duplicate revocation and a misleading log line.
    pub fn is_stale(&self, now: DateTime<Utc>, interval: chrono::Duration) -> bool {
        match *self.lock() {
            Some(last) => now - last > interval * (HEARTBEAT_MISS_THRESHOLD as i32),
            None => false,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<DateTime<Utc>>> {
        self.last_own_echo
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// ---------------------------------------------------------------------------
// Publisher
// ---------------------------------------------------------------------------

/// Publishes signed invalidation broadcasts to the fanout exchange.
///
/// Attached to every `AuthorizationEngine` as an
/// [`InvalidationBroadcaster`] when the channel is enabled.
pub struct CacheInvalidationPublisher {
    /// Opens publisher-confirm channels on demand.
    ///
    /// Publisher confirms are mandatory: without them the broker returns
    /// `Confirmation::NotRequested` and this publisher would report success for
    /// a message the broker never accepted, which is precisely the silent
    /// failure §4.2 exists to remove.
    channels: Arc<dyn PublisherChannelFactory>,
    /// The channel currently in use, if one is open and healthy.
    ///
    /// §13.4 observation 2: this used to be a single `Channel` created once at
    /// startup and never replaced. A channel is closed by the broker on any
    /// channel-level exception, and the consumer side is fully supervised with
    /// backoff while this side was not — so one exception made **every**
    /// access-narrowing mutation return 503 for the rest of the process
    /// lifetime. Fail-closed, so not a security hole, but a permanent
    /// availability defect that only a restart cleared.
    ///
    /// `tokio::sync::Mutex`, not `std::sync::Mutex`: the guard is held across
    /// the `.await` on the broker's confirm.
    channel: TokioMutex<Option<Channel>>,
    master_key: Vec<u8>,
    origin_id: Uuid,
}

/// Opens a publisher-confirm channel. Implemented by `AmqpManager`; a trait so
/// this module stays testable without a broker and does not depend on the
/// connection layer's concrete type.
pub trait PublisherChannelFactory: Send + Sync {
    fn open<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Channel, AmqpError>> + Send + 'a>>;
}

impl CacheInvalidationPublisher {
    pub fn new(
        channels: Arc<dyn PublisherChannelFactory>,
        master_key: Vec<u8>,
        origin_id: Uuid,
    ) -> Self {
        Self {
            channels,
            channel: TokioMutex::new(None),
            master_key,
            origin_id,
        }
    }

    /// This replica's id, as stamped into every broadcast for self-echo
    /// suppression. The consumer must be given the *same* value.
    pub fn origin_id(&self) -> Uuid {
        self.origin_id
    }

    /// Publish one invalidation and wait for the broker's confirm.
    ///
    /// # Errors
    ///
    /// Returns `Err` when the publish fails, is nacked, or is not confirmed —
    /// i.e. whenever the fan-out demonstrably did not happen. An unroutable
    /// message (no replica queues bound yet) is *not* an error: `mandatory` is
    /// off, so the broker acks and drops it, which is correct — a replica with
    /// no queue has no cache to invalidate.
    pub async fn publish_event(&self, event: InvalidationEvent) -> Result<(), AmqpError> {
        let payload =
            build_signed_invalidation(&self.master_key, self.origin_id, event, Utc::now())?;
        self.publish_payload(&payload).await
    }

    /// Publish one liveness heartbeat (§13.4 observation 1).
    ///
    /// Deliberately shares `publish_payload` with invalidations: the heartbeat
    /// must traverse the exact same path it is meant to be evidence about. A
    /// heartbeat sent over a different channel, exchange or routing key would
    /// prove something other than what the invalidations depend on.
    pub async fn publish_heartbeat(
        &self,
        liveness: &InvalidationLiveness,
    ) -> Result<(), AmqpError> {
        let (payload, nonce) =
            build_signed_heartbeat(&self.master_key, self.origin_id, Utc::now())?;
        // Registered BEFORE the publish: the fanout can deliver the echo before
        // the confirm returns, and a nonce registered afterwards could lose that
        // race and be discarded as a replay.
        liveness.record_sent_heartbeat(nonce);
        self.publish_payload(&payload).await
    }

    /// Acquire a healthy channel, publish, and await the confirm — reopening the
    /// channel if the one we hold has been closed.
    /// The lock covers only channel *acquisition*, never the broker round-trip
    /// (§15.3.4).
    ///
    /// Holding it across the confirm serialised every access-narrowing mutation
    /// in the process behind one network round-trip, with the heartbeat task
    /// contending on the same lock — a throughput cliff under a slow broker,
    /// and a regression against the pre-§13.4 code, which shared the channel
    /// with no lock at all. `lapin::Channel` is a cheap handle over shared
    /// state, so cloning it out of the slot and releasing the guard keeps the
    /// reopen logic single-threaded while letting publishes proceed
    /// concurrently — which is what the AMQP channel already supports.
    async fn publish_payload(&self, payload: &[u8]) -> Result<(), AmqpError> {
        let channel = {
            let mut slot = self.channel.lock().await;

            // Drop a channel the broker has already closed, so the next block
            // opens a fresh one instead of publishing into a dead handle.
            if slot.as_ref().is_some_and(|c| !c.status().connected()) {
                warn!("Cache-invalidation publisher channel is closed — reopening");
                *slot = None;
            }
            if slot.is_none() {
                *slot = Some(self.channels.open().await?);
            }
            slot.as_ref().expect("channel opened above").clone()
            // Guard dropped here — the confirm below is awaited unlocked.
        };

        match Self::publish_on(&channel, payload).await {
            Ok(()) => Ok(()),
            Err(e) => {
                // Any failure may have been the channel dying under us. Discard
                // it so the *next* mutation reopens rather than inheriting a
                // broken handle — the whole point of observation 2. The error is
                // still returned: this mutation genuinely did not fan out, and
                // silently retrying here would hide a broker refusing the
                // message for a reason that will recur.
                //
                // Compare-before-clear: between releasing the guard and
                // re-acquiring it, a concurrent publisher may already have
                // replaced the slot with a healthy channel. Clearing
                // unconditionally would discard that one too, and a burst of
                // failures could then thrash the slot indefinitely.
                let mut slot = self.channel.lock().await;
                if slot.as_ref().is_some_and(|c| c.id() == channel.id()) {
                    *slot = None;
                }
                Err(e)
            }
        }
    }

    async fn publish_on(channel: &Channel, payload: &[u8]) -> Result<(), AmqpError> {
        let confirm = channel
            .basic_publish(
                exchanges::AUTHZ_CACHE_INVALIDATE.into(),
                // Fanout ignores the routing key.
                "".into(),
                BasicPublishOptions::default(),
                payload,
                BasicProperties::default()
                    .with_content_type("application/json".into())
                    // Transient (1), not persistent: an invalidation is only
                    // meaningful to a live replica, and a replica that
                    // restarts comes back with an empty cache.
                    .with_delivery_mode(1),
            )
            .await
            .map_err(|e| AmqpError::Publish(format!("cache invalidation publish failed: {e}")))?;

        match confirm.await {
            Ok(Confirmation::Ack(_)) | Ok(Confirmation::NotRequested) => Ok(()),
            Ok(Confirmation::Nack(_)) => Err(AmqpError::Publish(
                "cache invalidation broadcast was nacked by the broker".to_string(),
            )),
            Err(e) => Err(AmqpError::Publish(format!(
                "cache invalidation broadcast not confirmed by the broker: {e}"
            ))),
        }
    }
}

impl InvalidationBroadcaster for CacheInvalidationPublisher {
    fn broadcast<'a>(
        &'a self,
        event: InvalidationEvent,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>> {
        Box::pin(async move {
            self.publish_event(event).await.map_err(|e| {
                error!(
                    error = %e,
                    tenant_id = %event.tenant_id(),
                    "Cross-replica cache invalidation could NOT be broadcast — failing the \
                     mutation; the database write is durable but other replicas were not told, \
                     so the revocation has not fully taken effect. Retry is safe."
                );
                AxiamError::ServiceUnavailable(format!(
                    "authorization cache invalidation could not be broadcast to other replicas: \
                     {e}. The change was written but has not fully taken effect — retry."
                ))
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Consumer
// ---------------------------------------------------------------------------

/// Marks the cache untrusted whenever the consumer is not running — on every
/// exit path including an error return, a panic, or the task being dropped
/// mid-await. Making this a `Drop` guard rather than a line at the end of the
/// function is what stops a future edit from introducing an early `return`
/// that leaves the cache trusted with no consumer behind it.
struct TrustGuard(Arc<DecisionCache>, Option<Arc<InvalidationLiveness>>);

impl Drop for TrustGuard {
    fn drop(&mut self) {
        self.0.set_trusted(false);
        // Clear the liveness clock too, so a reconnecting consumer cannot
        // inherit its predecessor's "recently alive" timestamp and look healthy
        // before it has actually observed anything.
        if let Some(liveness) = &self.1 {
            liveness.mark_unsubscribed();
        }
    }
}

/// Run this replica's invalidation consumer until the stream ends.
///
/// Declares the topology, subscribes, marks the cache **trusted**, then applies
/// every verified broadcast. On any exit — subscribe failure, stream end,
/// cancellation — the cache is marked **untrusted** again, so the replica falls
/// back to uncached (correct, slower) evaluation instead of serving allows it
/// can no longer invalidate.
///
/// Callers should supervise this in a reconnect loop with backoff; each call is
/// one connection's worth of consuming.
pub async fn run_cache_invalidation_consumer(
    channel: Channel,
    cache: Arc<DecisionCache>,
    master_key: Vec<u8>,
    replica_id: Uuid,
    skew: chrono::Duration,
    liveness: Option<Arc<InvalidationLiveness>>,
) -> Result<(), AmqpError> {
    // Armed before anything can fail: from here on, every exit path leaves the
    // cache untrusted.
    let _trust = TrustGuard(Arc::clone(&cache), liveness.clone());

    let queue = declare_cache_invalidation_topology(&channel, replica_id).await?;

    let mut consumer = channel
        .basic_consume(
            queue.as_str().into(),
            format!("axiam-cache-invalidation-{replica_id}")
                .as_str()
                .into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
        .map_err(AmqpError::Channel)?;

    // Only now — subscribed and receiving — may this replica serve from cache.
    // This is the ONLY place trust is granted; the liveness watchdog can revoke
    // it but never restore it, so a dead consumer can never be papered over.
    cache.set_trusted(true);
    if let Some(liveness) = &liveness {
        // Start the clock here rather than at the first heartbeat: otherwise a
        // freshly-subscribed replica looks infinitely stale and the watchdog
        // would revoke trust before the first heartbeat round completes.
        liveness.mark_subscribed(Utc::now());
    }
    info!(
        queue = %queue,
        replica_id = %replica_id,
        "AuthZ decision-cache invalidation consumer subscribed (cross-replica fan-out live)"
    );

    let guard = NonceGuard::new();

    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "Error receiving cache-invalidation delivery");
                continue;
            }
        };

        let outcome = handle_invalidation(
            &delivery.data,
            &cache,
            &master_key,
            replica_id,
            &guard,
            skew,
            Utc::now(),
        );

        match outcome {
            InvalidationOutcome::Applied(event) => {
                debug!(
                    tenant_id = %event.tenant_id(),
                    subject_id = ?event.subject_id(),
                    "Applied cross-replica cache invalidation"
                );
                let _ = delivery.acker.ack(BasicAckOptions::default()).await;
            }
            InvalidationOutcome::SelfEcho => {
                let _ = delivery.acker.ack(BasicAckOptions::default()).await;
            }
            InvalidationOutcome::Heartbeat { own, nonce } => {
                // Only our OWN heartbeat is evidence: it is the one that proves
                // *this* replica's queue is still bound to the exchange. Another
                // replica's heartbeat proves only that the other replica can
                // publish, which says nothing about our binding.
                if let Some(liveness) = &liveness
                    && own
                    && !liveness.record_own_heartbeat(nonce, Utc::now())
                {
                    // A correctly-signed, fresh heartbeat carrying our origin id
                    // but a nonce we did not issue (or already saw) is a replay.
                    // It must not refresh the liveness clock — that is the
                    // suppression path §15.2 gap 3 names — and it is worth a log
                    // line, because in normal operation it cannot happen.
                    warn!(
                        %nonce,
                        "Replayed or unrecognised own-heartbeat nonce — ignoring; \
                         this does not refresh cache-invalidation liveness"
                    );
                }
                let _ = delivery.acker.ack(BasicAckOptions::default()).await;
            }
            InvalidationOutcome::Rejected(reason) => {
                // Drop, never requeue: a broadcast has no other consumer to
                // hand it to, so requeueing would hot-loop against ourselves.
                warn!(?reason, "Rejected cache-invalidation delivery");
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
            }
        }
    }

    warn!("AuthZ decision-cache invalidation consumer stream ended");
    Ok(())
    // `_trust` drops here → cache marked untrusted.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exchange_is_fanout_not_a_work_queue() {
        // The single most important decision in this module. A direct/topic
        // exchange feeding one shared queue would deliver each invalidation to
        // exactly ONE replica and leave every other replica stale.
        assert_eq!(invalidation_exchange_kind(), ExchangeKind::Fanout);
    }

    #[test]
    fn each_replica_gets_its_own_exclusive_auto_delete_queue() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_ne!(
            invalidation_queue_name(a),
            invalidation_queue_name(b),
            "replicas must not share a queue — a shared queue is a work queue"
        );
        let opts = invalidation_queue_options();
        assert!(opts.exclusive, "no other connection may steal deliveries");
        assert!(opts.auto_delete, "queue must vanish with the replica");
        assert!(
            !opts.durable,
            "a restarted replica has an empty cache; missed invalidations are meaningless"
        );
    }

    #[test]
    fn nonce_guard_accepts_once_and_rejects_the_replay() {
        let guard = NonceGuard::new();
        let now = Utc::now();
        let n = Uuid::new_v4();
        assert!(guard.check_and_record(n, now + chrono::Duration::seconds(30), now));
        assert!(!guard.check_and_record(n, now + chrono::Duration::seconds(30), now));
        assert!(
            guard.check_and_record(Uuid::new_v4(), now + chrono::Duration::seconds(30), now),
            "a different nonce is unaffected"
        );
    }

    #[test]
    fn nonce_guard_expires_entries_and_stays_bounded() {
        let guard = NonceGuard::new();
        let t0 = Utc::now();
        let n = Uuid::new_v4();
        assert!(guard.check_and_record(n, t0 + chrono::Duration::seconds(30), t0));
        assert_eq!(guard.len(), 1);

        // Past the window: the entry is reaped, so the same nonce is accepted
        // again — harmless, because the freshness gate rejects the message
        // before the guard is ever consulted.
        let later = t0 + chrono::Duration::seconds(31);
        assert!(guard.check_and_record(
            Uuid::new_v4(),
            later + chrono::Duration::seconds(30),
            later
        ));
        assert_eq!(guard.len(), 1, "expired nonce reaped");

        for _ in 0..(NONCE_GUARD_CAPACITY + 500) {
            guard.check_and_record(Uuid::new_v4(), later + chrono::Duration::seconds(30), later);
        }
        assert!(
            guard.len() <= NONCE_GUARD_CAPACITY + 1,
            "guard must stay bounded, got {}",
            guard.len()
        );
    }
}

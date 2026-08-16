//! The production lapin [`ReactorTransport`] (X1 / R2.4).
//!
//! `dispatcher.rs` decides what a chain of reactors *means*; this module is the
//! only part of X1 that knows a broker exists. It replaces
//! [`super::dispatcher::UnavailableReactorTransport`], which every deployment
//! composed while this file did not exist and which resolved every dispatch
//! through the registration's failure policy.
//!
//! # Topology, and the one place it departs from a literal reading of §22.1
//!
//! `sdks/CONTRACT.md` §22.1 defines the topology this module declares:
//!
//! | Element | Value |
//! |---|---|
//! | Exchange | [`REACTOR_EXCHANGE`], type **topic**, durable |
//! | Routing key | [`routing_key`] — `<tenant_id>.<event>` |
//! | Per-reactor queue | [`queue_name`] — `axiam.reactor.q.<tenant>.<reactor>`, durable |
//!
//! **The server declares all three; an actor declares nothing.** That is the
//! rule §22.1 states and the reason it states it: a reactor that can bind is a
//! reactor that can bind itself to `*.token.pre_issue` and read another
//! tenant's issuance events. [`LapinReactorTransport::declare_reactor_topology`]
//! is where the server holds that capability, and it is called on the dispatch
//! path so a queue that was deleted out from under a live registration repairs
//! itself rather than silently swallowing every event.
//!
//! **An `intercept` round trip publishes to the reactor's queue directly (the
//! default exchange), not through the topic exchange**, and this is deliberate
//! rather than a shortcut. The routing key is per `(tenant, event)`, so a
//! publish through the exchange reaches *every* reactor registered for that
//! event at once. [`run_chain`](super::dispatcher::run_chain) dispatches
//! sequentially in priority order, each reactor seeing what the previous ones
//! patched, and it correlates exactly one reply per event. Fanning one
//! `correlation_id` out to the whole chain would mean the first reply to arrive
//! is consumed as the reply of whichever reactor the chain is currently
//! waiting on — priority order decided by message timing, and a low-priority
//! reactor able to answer in a high-priority reactor's place. Addressing the
//! queue is what makes the dispatch 1:1 and the ordering the declared one.
//!
//! The exchange and the bindings are still declared, for every registration and
//! every event it names, because §22.1 says the server owns them and because
//! [`LapinReactorTransport::publish_listen`]'s fan-out and any operator
//! inspecting the topology both depend on them existing.
//!
//! # Reply correlation
//!
//! One **exclusive, broker-named reply queue per process**, one consumer task,
//! and a `correlation_id → oneshot::Sender` map. A round trip costs one publish
//! and one map insert; it does not declare a queue. (A reply queue per round
//! trip — what `tests/reactor_containerized_test.rs`'s test-only transport did
//! before this module existed — is fine for five ignored tests and is a queue
//! churn of one declare, one consume and one delete per login in production.)
//!
//! Replies are routed by the `correlation_id` **inside the body**, which is
//! what §22.1 says the server authenticates, rather than by the AMQP property.
//! Routing is not trust: the chain re-checks the correlation, the tenant, the
//! event and the HMAC in [`ReactorReply::into_outcome`], so the worst a reactor
//! can do by naming a correlation it was not given is fail a round trip that
//! its own failure policy then resolves.
//!
//! # What a broker outage costs
//!
//! Nothing is retried at this layer and nothing is queued. A dispatch while the
//! transport has no live session fails **immediately** as
//! [`DispatchFailure::Transport`] rather than burning the reactor's whole
//! `timeout_ms` waiting for a reply that cannot arrive — the registration's
//! `failure_policy` then decides, which is the same closed set §22.8 puts a
//! timeout in. A supervisor task re-establishes the session with backoff in the
//! background.
//!
//! [`ReactorTransport::can_dispatch`] stays `true` throughout, including while
//! disconnected. It reports the transport's *capability*, not its health; a
//! `false` on a broker blip would refuse reactor registrations for the duration
//! of the outage, turning a broker problem into an admin-API problem.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use chrono::Utc;
use futures_lite::StreamExt;
use lapin::options::{
    BasicConsumeOptions, BasicPublishOptions, ExchangeDeclareOptions, QueueBindOptions,
    QueueDeclareOptions,
};
use lapin::types::{AMQPValue, FieldTable};
use lapin::{BasicProperties, Channel, ExchangeKind};
use tokio::sync::oneshot;
use uuid::Uuid;

use axiam_core::models::reactor::Reactor;

use crate::connection::AmqpManager;
use crate::error::AmqpError;

use super::dispatcher::{DispatchFailure, ReactorTransport};
use super::protocol::{
    REACTOR_EXCHANGE, ReactorEventMessage, ReactorReply, queue_name, routing_key,
};

/// How long a per-reactor queue survives with no consumer and no activity
/// (`x-expires`), in milliseconds — seven days.
///
/// Reactor queues are durable and are **not** auto-delete: a registration's
/// queue must outlive its actor's restarts, or every reconnect would race the
/// server's next publish. That makes them the one piece of X1 topology that
/// can accumulate, because deleting a registration through the admin API does
/// not currently reach this transport to delete its queue.
///
/// `x-expires` bounds that without new plumbing: a queue nobody consumes and
/// nothing touches for seven days is reclaimed by the broker, and a *live*
/// registration is never affected because an attached consumer is "use". A
/// registration whose actor really has been offline for a week loses a queue
/// that only held expired events anyway (see [`Self::round_trip`]'s per-message
/// expiration), and [`LapinReactorTransport::declare_reactor_topology`]
/// recreates it on the next dispatch.
const REACTOR_QUEUE_UNUSED_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1_000;

/// Bound on messages held for an offline reactor (`x-max-length`).
///
/// An interceptor's events carry a per-message expiration and drop themselves,
/// so this is really a bound on `listen` fan-out to an actor that is not
/// running. Overflow drops from the head (the oldest), which is the right end
/// to lose: a listener that has fallen 10 000 events behind is not going to
/// catch up, and the newest events are the ones with any remaining value.
const REACTOR_QUEUE_MAX_LENGTH: i64 = 10_000;

/// Backoff bounds for the reply-consumer supervisor.
const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// The failure text a dispatch carries when the transport has no live broker
/// session. Named so an operator can grep for it, exactly as
/// [`super::dispatcher::REACTOR_TRANSPORT_UNAVAILABLE`] is.
pub const REACTOR_TRANSPORT_DISCONNECTED: &str =
    "the AMQP reactor transport has no live broker session";

/// One live broker session: the channel everything is published on and the
/// reply queue replies come back to.
///
/// Held together because they are only ever valid together — a reply queue is
/// exclusive to the connection that declared it, so a channel replacement that
/// kept the old queue name would address a queue that no longer exists.
#[derive(Clone)]
struct Session {
    channel: Channel,
    reply_queue: String,
}

/// State shared between the transport and its supervisor task.
struct Shared {
    /// `None` until the supervisor establishes a session, and again after it
    /// loses one.
    session: RwLock<Option<Session>>,
    /// In-flight round trips, keyed by the `correlation_id` the reply must
    /// carry in its body.
    pending: Mutex<HashMap<Uuid, oneshot::Sender<Vec<u8>>>>,
    /// Which event bindings each reactor's queue currently has, as this
    /// process declared them. Cleared whenever the session is lost, because
    /// the next session must re-declare from scratch rather than trust a
    /// cache written against a channel that is gone.
    declared: Mutex<HashMap<Uuid, Vec<String>>>,
}

impl Shared {
    fn new() -> Self {
        Self {
            session: RwLock::new(None),
            pending: Mutex::new(HashMap::new()),
            declared: Mutex::new(HashMap::new()),
        }
    }

    /// Snapshot the current session, if any.
    ///
    /// Returns a clone rather than a guard: every caller needs it across an
    /// `await`, and holding a lock across one is how a transport deadlocks
    /// itself under load.
    fn session(&self) -> Option<Session> {
        match self.session.read() {
            Ok(g) => g.clone(),
            // A poisoned lock means a panic happened while the supervisor was
            // swapping the session. Reading through it is safe — the value is
            // either the old session or the new one, both valid — and refusing
            // to dispatch would be strictly worse than dispatching on a
            // session that may be one generation stale, which fails as a
            // transport error and resolves through the failure policy anyway.
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn set_session(&self, session: Option<Session>) {
        match self.session.write() {
            Ok(mut g) => *g = session,
            Err(poisoned) => *poisoned.into_inner() = session,
        }
    }

    fn pending_map(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, oneshot::Sender<Vec<u8>>>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn declared_map(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, Vec<String>>> {
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drop every waiting round trip. Each sender's `Drop` wakes its receiver
    /// with an error, so an in-flight dispatch learns the session died at once
    /// instead of waiting out its `timeout_ms` for a reply that can no longer
    /// be delivered.
    fn abandon_all_pending(&self) {
        let abandoned = self.pending_map().drain().count();
        if abandoned > 0 {
            tracing::warn!(
                target: "axiam::reactor",
                abandoned,
                "reactor reply session lost; in-flight dispatches fail now rather \
                 than waiting out their timeouts"
            );
        }
    }
}

/// The lapin [`ReactorTransport`] `axiam-server` composes.
///
/// Cheap to clone; every clone shares one session, one pending map and one
/// topology cache.
#[derive(Clone)]
pub struct LapinReactorTransport {
    shared: Arc<Shared>,
    /// The AMQP master key. Events are signed with the tenant subkey derived
    /// from it (§8 v2), the same derivation the chain uses to verify replies.
    signing_key: Arc<Vec<u8>>,
}

impl LapinReactorTransport {
    /// Build the transport and spawn the supervisor that keeps its broker
    /// session alive.
    ///
    /// **Infallible on purpose.** The alternative — returning a `Result` that
    /// `axiam-server` unwraps — would make a broker that happens to be slow at
    /// boot into a server that refuses to start, and a reactor transport is
    /// not a dependency worth refusing to serve logins over. Until the first
    /// session is established every dispatch fails as
    /// [`REACTOR_TRANSPORT_DISCONNECTED`] and the registration's
    /// `failure_policy` decides, which is exactly what happens during any later
    /// broker outage. A tenant with no registered reactor is unaffected either
    /// way: the gate never reaches a transport for it.
    pub fn start(amqp: Arc<AmqpManager>, signing_key: Vec<u8>) -> Self {
        let shared = Arc::new(Shared::new());
        tokio::spawn(supervise(Arc::clone(&amqp), Arc::clone(&shared)));
        Self {
            shared,
            signing_key: Arc::new(signing_key),
        }
    }

    /// Whether a broker session is currently established.
    ///
    /// This is *health*, and deliberately not what
    /// [`ReactorTransport::can_dispatch`] answers — see the module docs.
    /// Exposed for readiness reporting and for tests.
    pub fn is_connected(&self) -> bool {
        self.shared.session().is_some()
    }

    /// Declare the topology §22.1 makes the server responsible for: the topic
    /// exchange, this reactor's durable queue, and one binding per event in
    /// its registration.
    ///
    /// Idempotent, and self-correcting in both directions — an event removed
    /// from a registration has its binding **unbound**, because leaving it
    /// would keep delivering an event the operator un-subscribed from. The
    /// per-process cache means the steady state costs one map lookup; the
    /// declares themselves only happen on the first dispatch to a reactor,
    /// after its `events` change, or after a reconnect.
    ///
    /// Public because this is also the operation the admin registration path
    /// should perform at create/update time, so the queue exists before the
    /// first event rather than at it.
    pub async fn declare_reactor_topology(&self, reactor: &Reactor) -> Result<(), AmqpError> {
        let Some(session) = self.shared.session() else {
            return Err(AmqpError::Publish(
                REACTOR_TRANSPORT_DISCONNECTED.to_string(),
            ));
        };
        declare_reactor_topology_on(&session.channel, &self.shared, reactor).await
    }

    /// Serialize, publish, and map every failure onto [`DispatchFailure`].
    ///
    /// `expiration` is `Some(ms)` for an interception and `None` for a
    /// listener: an interception the broker could not deliver inside the
    /// reactor's window is worthless, because the chain has already resolved
    /// the dispatch through the failure policy and will reject the late reply
    /// as stale (§22.3). Letting the broker drop it is cheaper and safer than
    /// handing an actor an event about a decision that was made minutes ago.
    async fn publish(
        &self,
        session: &Session,
        reactor: &Reactor,
        msg: &ReactorEventMessage,
        reply_to: Option<&str>,
        expiration: Option<u32>,
    ) -> Result<(), DispatchFailure> {
        let body =
            serde_json::to_vec(msg).map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        let mut props = BasicProperties::default()
            .with_content_type("application/json".into())
            // Echoed for the standard AMQP RPC convention's sake (§22.1). The
            // server authenticates the copy inside the signed body, never
            // this one.
            .with_correlation_id(msg.correlation_id.to_string().into());
        if let Some(reply_to) = reply_to {
            props = props.with_reply_to(reply_to.into());
        }
        if let Some(ms) = expiration {
            props = props.with_expiration(ms.to_string().into());
        }

        let confirm = session
            .channel
            .basic_publish(
                // The default exchange, addressing the reactor's queue by
                // name — see the module docs on why an interception is not
                // fanned out through the topic exchange.
                "".into(),
                queue_name(reactor.tenant_id, reactor.id).into(),
                BasicPublishOptions::default(),
                &body,
                props,
            )
            .await
            .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        // Publisher confirms are enabled on this channel, so awaiting the
        // confirmation turns "the broker refused this" into a transport
        // failure now rather than into a timeout `timeout_ms` from now. It is
        // a broker-local acknowledgement, not a reactor round trip.
        let confirmation = confirm
            .await
            .map_err(|e| DispatchFailure::Transport(e.to_string()))?;
        if confirmation.is_nack() {
            return Err(DispatchFailure::Transport(
                "broker nacked the reactor event".into(),
            ));
        }
        Ok(())
    }
}

impl ReactorTransport for LapinReactorTransport {
    async fn round_trip(
        &self,
        reactor: &Reactor,
        event: &'static str,
        correlation_id: Uuid,
        payload: serde_json::Value,
        timeout_ms: u32,
    ) -> Result<ReactorReply, DispatchFailure> {
        let Some(session) = self.shared.session() else {
            // Fail now, not in `timeout_ms`. A reactor's budget is the caller's
            // latency, and spending it waiting for a broker we know we are not
            // connected to would make a broker outage look like every reactor
            // in the deployment becoming slow.
            return Err(DispatchFailure::Transport(
                REACTOR_TRANSPORT_DISCONNECTED.to_string(),
            ));
        };

        // `timeout_ms` bounds the WHOLE round trip, not just the wait for a
        // reply.
        //
        // Everything below this line talks to the broker, and none of it is
        // instantaneous: a declare is an RPC, and a publish on a confirm
        // channel waits for the broker's ack. Since `AmqpManager` dials with
        // `enable_auto_recover`, a channel whose connection is being recovered
        // makes those calls *wait* for recovery rather than fail — which is
        // the right behaviour for a background consumer and the wrong one on
        // the login path. `run_chain` enforces `MAX_CHAIN_BUDGET_MS` only
        // *between* reactors, so an unbounded await in here is an unbounded
        // login, which is precisely the failure the whole timeout design
        // exists to prevent. Each step therefore gets what is left of the
        // budget, and running out is a `Timeout` like any other.
        let budget = Duration::from_millis(u64::from(timeout_ms));
        let started = std::time::Instant::now();
        let remaining = || budget.saturating_sub(started.elapsed());

        tokio::time::timeout(
            remaining(),
            declare_reactor_topology_on(&session.channel, &self.shared, reactor),
        )
        .await
        .map_err(|_| DispatchFailure::Timeout)?
        .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        let msg = ReactorEventMessage::signed(
            &self.signing_key,
            reactor.tenant_id,
            event,
            correlation_id,
            payload,
            timeout_ms,
            Utc::now(),
        )
        .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        // Register before publishing: a reactor fast enough to answer between
        // the publish and the registration would otherwise have its reply
        // dropped as uncorrelated.
        let (tx, rx) = oneshot::channel();
        self.shared.pending_map().insert(correlation_id, tx);
        // From here every exit path must deregister, or a timed-out dispatch
        // leaks an entry for the process lifetime.
        let _guard = PendingGuard {
            shared: Arc::clone(&self.shared),
            correlation_id,
        };

        tokio::time::timeout(
            remaining(),
            self.publish(
                &session,
                reactor,
                &msg,
                Some(&session.reply_queue),
                Some(timeout_ms),
            ),
        )
        .await
        .map_err(|_| DispatchFailure::Timeout)??;

        match tokio::time::timeout(remaining(), rx).await {
            Ok(Ok(body)) => serde_json::from_slice::<ReactorReply>(&body)
                .map_err(|e| DispatchFailure::Transport(e.to_string())),
            // The sender was dropped: the session died under us (see
            // `abandon_all_pending`).
            Ok(Err(_)) => Err(DispatchFailure::Transport(
                REACTOR_TRANSPORT_DISCONNECTED.to_string(),
            )),
            Err(_) => Err(DispatchFailure::Timeout),
        }
    }

    async fn publish_listen(
        &self,
        reactor: &Reactor,
        event: &'static str,
        payload: serde_json::Value,
    ) -> Result<(), DispatchFailure> {
        let Some(session) = self.shared.session() else {
            return Err(DispatchFailure::Transport(
                REACTOR_TRANSPORT_DISCONNECTED.to_string(),
            ));
        };

        // Bounded by the registration's own `timeout_ms` for the same reason
        // `round_trip` is (see the comment there): nothing about being
        // fire-and-forget makes a broker RPC instantaneous, and the fan-out
        // this exists for would run at a hook site. A listener that cannot
        // affect an outcome must also be unable to affect a latency.
        let budget = Duration::from_millis(u64::from(reactor.timeout_ms));
        let started = std::time::Instant::now();

        tokio::time::timeout(
            budget,
            declare_reactor_topology_on(&session.channel, &self.shared, reactor),
        )
        .await
        .map_err(|_| DispatchFailure::Timeout)?
        .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        // `timeout_ms` is carried so a listener sees the same body shape an
        // interceptor does, but nothing waits on it and no `reply_to` is set:
        // a reply to a listen event has nowhere to go, which is the wire-level
        // statement of "a listener cannot affect an outcome".
        let msg = ReactorEventMessage::signed(
            &self.signing_key,
            reactor.tenant_id,
            event,
            Uuid::new_v4(),
            payload,
            reactor.timeout_ms,
            Utc::now(),
        )
        .map_err(|e| DispatchFailure::Transport(e.to_string()))?;

        // Addressed to the reactor's queue, one message per registration —
        // not fanned out through the exchange, which would deliver one copy
        // per bound listener for every listener the caller iterates over.
        tokio::time::timeout(
            budget.saturating_sub(started.elapsed()),
            self.publish(&session, reactor, &msg, None, None),
        )
        .await
        .map_err(|_| DispatchFailure::Timeout)?
    }
}

/// Deregisters an in-flight round trip however it ends — reply, timeout,
/// cancellation, or the caller being dropped mid-`await`.
///
/// A `Drop` guard rather than removal at each exit because the interesting
/// path is the one there is no code for: the whole login future being
/// cancelled while a reactor round trip is outstanding.
struct PendingGuard {
    shared: Arc<Shared>,
    correlation_id: Uuid,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.shared.pending_map().remove(&self.correlation_id);
    }
}

/// [`LapinReactorTransport::declare_reactor_topology`]'s body, taking the
/// channel explicitly so the round-trip path can reuse a session it has
/// already snapshotted.
async fn declare_reactor_topology_on(
    channel: &Channel,
    shared: &Shared,
    reactor: &Reactor,
) -> Result<(), AmqpError> {
    let wanted: Vec<String> = reactor.events.clone();

    // Fast path: this process already declared exactly these bindings on this
    // session. The steady state of a hot login path is this map lookup.
    if shared
        .declared_map()
        .get(&reactor.id)
        .is_some_and(|have| *have == wanted)
    {
        return Ok(());
    }

    let queue = queue_name(reactor.tenant_id, reactor.id);

    // Durable and NOT auto-delete: the queue must outlive the actor's
    // restarts. RabbitMQ 4 also refuses a transient non-exclusive declare
    // outright, taking the connection down with it.
    let mut args = FieldTable::default();
    args.insert(
        "x-expires".into(),
        AMQPValue::LongLongInt(REACTOR_QUEUE_UNUSED_TTL_MS),
    );
    args.insert(
        "x-max-length".into(),
        AMQPValue::LongLongInt(REACTOR_QUEUE_MAX_LENGTH),
    );

    channel
        .queue_declare(
            queue.clone().into(),
            QueueDeclareOptions {
                durable: true,
                ..QueueDeclareOptions::default()
            },
            args,
        )
        .await
        .map_err(AmqpError::Declaration)?;

    // Bind every event the registration names, and unbind the ones it no
    // longer does. The second half matters: an operator who removes
    // `login.post_auth` from a registration has un-subscribed from it, and a
    // stale binding would keep delivering it.
    let previous = shared
        .declared_map()
        .get(&reactor.id)
        .cloned()
        .unwrap_or_default();

    for event in &wanted {
        channel
            .queue_bind(
                queue.clone().into(),
                REACTOR_EXCHANGE.into(),
                routing_key(reactor.tenant_id, event).into(),
                QueueBindOptions::default(),
                FieldTable::default(),
            )
            .await
            .map_err(AmqpError::Declaration)?;
    }
    for event in previous.iter().filter(|e| !wanted.contains(e)) {
        channel
            .queue_unbind(
                queue.clone().into(),
                REACTOR_EXCHANGE.into(),
                routing_key(reactor.tenant_id, event).into(),
                FieldTable::default(),
            )
            .await
            .map_err(AmqpError::Declaration)?;
    }

    shared.declared_map().insert(reactor.id, wanted);
    tracing::debug!(
        target: "axiam::reactor",
        tenant_id = %reactor.tenant_id,
        reactor_id = %reactor.id,
        queue = %queue,
        events = ?reactor.events,
        "declared reactor topology"
    );
    Ok(())
}

/// Declare the reactor exchange. Idempotent; called once per session.
async fn declare_exchange(channel: &Channel) -> Result<(), AmqpError> {
    channel
        .exchange_declare(
            REACTOR_EXCHANGE.into(),
            // Topic, because the routing key is `<tenant>.<event>` and a
            // listener fan-out selects on both halves.
            ExchangeKind::Topic,
            ExchangeDeclareOptions {
                durable: true,
                ..ExchangeDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(AmqpError::Declaration)
}

/// Establish one session and pump replies until it dies.
///
/// Returns `Ok(())` when the reply stream ended cleanly (the broker closed the
/// consumer) and `Err` when it could not be established at all — the caller
/// treats both as "reconnect", and only distinguishes them in the log.
async fn run_reply_session(amqp: &AmqpManager, shared: &Shared) -> Result<(), AmqpError> {
    // Confirms so a publish that the broker refuses fails at once rather than
    // as a timeout one reactor budget later.
    let channel = amqp.create_publisher_channel().await?;
    declare_exchange(&channel).await?;

    // Broker-named, exclusive, auto-delete: one reply queue for this process,
    // gone the moment this connection is. Exclusive is also what keeps a
    // transient declare legal on RabbitMQ 4, which refuses transient
    // non-exclusive queues.
    let reply_queue = channel
        .queue_declare(
            "".into(),
            QueueDeclareOptions {
                exclusive: true,
                auto_delete: true,
                ..QueueDeclareOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(AmqpError::Declaration)?;
    let reply_queue_name = reply_queue.name().as_str().to_string();

    let mut consumer = channel
        .basic_consume(
            reply_queue_name.clone().into(),
            "axiam-reactor-replies".into(),
            // No ack: a reply is only useful to the round trip that is waiting
            // for it right now. Redelivering one after a crash would hand a
            // decision to a request that no longer exists.
            BasicConsumeOptions {
                no_ack: true,
                ..BasicConsumeOptions::default()
            },
            FieldTable::default(),
        )
        .await
        .map_err(AmqpError::Channel)?;

    shared.set_session(Some(Session {
        channel,
        reply_queue: reply_queue_name.clone(),
    }));
    tracing::info!(
        target: "axiam::reactor",
        reply_queue = %reply_queue_name,
        "X1 reactor transport connected"
    );

    while let Some(delivery) = consumer.next().await {
        let delivery = delivery.map_err(AmqpError::Channel)?;
        route_reply(shared, delivery.data);
    }
    Ok(())
}

/// Hand one reply body to the round trip waiting on its `correlation_id`.
///
/// Routed by the body's field rather than the AMQP property because that is
/// the one §22.1 makes normative — an SDK that copies the correlation only into
/// the property produces a reply the server discards, and routing by the
/// property would quietly accept it and then fail the chain's check instead,
/// which is a much harder thing to debug from the SDK side.
fn route_reply(shared: &Shared, body: Vec<u8>) {
    #[derive(serde::Deserialize)]
    struct CorrelationOnly {
        correlation_id: Uuid,
    }

    let Ok(head) = serde_json::from_slice::<CorrelationOnly>(&body) else {
        tracing::warn!(
            target: "axiam::reactor",
            "discarded a reactor reply with no readable correlation_id in its body"
        );
        return;
    };

    match shared.pending_map().remove(&head.correlation_id) {
        Some(tx) => {
            // The receiver being gone means the round trip already timed out;
            // §22.3 says an SDK runtime SHOULD abandon a reply rather than
            // send it late, and this is the server side of that — the late
            // reply is dropped, not applied.
            let _ = tx.send(body);
        }
        None => tracing::debug!(
            target: "axiam::reactor",
            correlation_id = %head.correlation_id,
            "discarded a reactor reply nothing was waiting for (late, duplicate, or forged)"
        ),
    }
}

/// Keep a reply session alive for the process lifetime.
///
/// Never takes the process down and never gives up: the same discipline
/// `axiam-server` applies to the cache-invalidation consumer. A reactor
/// transport that exited on a broker blip would leave every dispatch resolving
/// through `failure_policy` forever, with a restart as the only cure.
async fn supervise(amqp: Arc<AmqpManager>, shared: Arc<Shared>) {
    let mut backoff = RECONNECT_BACKOFF_START;
    loop {
        match run_reply_session(&amqp, &shared).await {
            Ok(()) => tracing::error!(
                target: "axiam::reactor",
                "X1 reactor reply consumer exited; reconnecting"
            ),
            Err(e) => tracing::error!(
                target: "axiam::reactor",
                error = %e,
                "X1 reactor transport session failed; reconnecting"
            ),
        }

        // A session that actually came up resets the backoff, so a broker that
        // restarts twice in a day does not leave the transport reconnecting on
        // a 30-second cadence forever. Read before the teardown below clears
        // it.
        let was_established = shared.session().is_some();

        // Order matters: stop advertising a session first, so no further
        // dispatch publishes into a dead channel, then release the ones
        // already waiting, then drop the topology cache so the next session
        // re-declares rather than trusting declares made on a gone channel.
        shared.set_session(None);
        shared.abandon_all_pending();
        shared.declared_map().clear();

        if was_established {
            backoff = RECONNECT_BACKOFF_START;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::reactor::{FailurePolicy, ReactorMode};

    fn reactor(events: &[&str]) -> Reactor {
        Reactor {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "t".into(),
            description: String::new(),
            events: events.iter().map(|e| (*e).to_string()).collect(),
            mode: ReactorMode::Intercept,
            priority: 0,
            timeout_ms: 500,
            failure_policy: FailurePolicy::FailClosed,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_seen_at: None,
        }
    }

    /// A transport with no broker session and no supervisor.
    ///
    /// Built by hand rather than through [`LapinReactorTransport::start`],
    /// which would spawn a task that keeps trying to connect — these tests are
    /// about what the transport does *while* there is nothing to talk to, and
    /// a supervisor racing them would make that a timing question.
    fn disconnected() -> LapinReactorTransport {
        LapinReactorTransport {
            shared: Arc::new(Shared::new()),
            signing_key: Arc::new(b"k".to_vec()),
        }
    }

    /// The capability/health split (SEC-101): a transport that is merged but
    /// momentarily disconnected must still say it can dispatch, or a broker
    /// outage becomes a registration outage.
    #[tokio::test]
    async fn a_disconnected_transport_still_reports_that_it_can_dispatch() {
        let t = disconnected();
        assert!(t.can_dispatch());
        assert!(!t.is_connected());
    }

    /// A dispatch with no session must fail immediately rather than spend the
    /// reactor's whole budget waiting for a reply that cannot arrive.
    #[tokio::test]
    async fn a_dispatch_without_a_session_fails_at_once_rather_than_timing_out() {
        let t = disconnected();
        let r = reactor(&["token.pre_issue"]);

        let started = std::time::Instant::now();
        let err = t
            .round_trip(
                &r,
                "token.pre_issue",
                Uuid::new_v4(),
                serde_json::json!({}),
                5_000,
            )
            .await
            .unwrap_err();

        assert_eq!(
            err,
            DispatchFailure::Transport(REACTOR_TRANSPORT_DISCONNECTED.to_string())
        );
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "a disconnected transport must not burn the reactor's timeout budget"
        );
    }

    /// A `listen` publish takes the same fail-fast path as an interception.
    /// It carries no reply and produces no outcome, but silently reporting
    /// success for an event that was never published would make a listener's
    /// absence indistinguishable from a listener with nothing to say.
    #[tokio::test]
    async fn a_listen_publish_without_a_session_also_fails_rather_than_reporting_success() {
        let t = disconnected();
        let mut r = reactor(&["token.pre_issue"]);
        r.mode = ReactorMode::Listen;

        let err = t
            .publish_listen(&r, "token.pre_issue", serde_json::json!({}))
            .await
            .unwrap_err();
        assert_eq!(
            err,
            DispatchFailure::Transport(REACTOR_TRANSPORT_DISCONNECTED.to_string())
        );
    }

    /// Declaring topology needs a channel, so it reports the disconnection
    /// rather than pretending the queue is there. This is the arm the
    /// registration path would hit if it declared at create/update time
    /// during a broker outage.
    #[tokio::test]
    async fn declaring_topology_without_a_session_is_an_error_not_a_silent_success() {
        let t = disconnected();
        let err = t
            .declare_reactor_topology(&reactor(&["token.pre_issue"]))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AmqpError::Publish(ref m) if m == REACTOR_TRANSPORT_DISCONNECTED),
            "expected a disconnected-transport error, got {err:?}"
        );
    }

    /// A body that is not a reactor reply at all must be dropped without
    /// disturbing anything waiting. The reply queue is exclusive to this
    /// process, so this is mostly a broker or SDK bug rather than an attack —
    /// but the consumer task must not die on it either way, because the task
    /// dying takes every subsequent dispatch down with it.
    #[test]
    fn a_reply_body_that_is_not_json_is_discarded_without_disturbing_waiters() {
        let shared = Shared::new();
        let waiting = Uuid::new_v4();
        let (tx, mut rx) = oneshot::channel();
        shared.pending_map().insert(waiting, tx);

        route_reply(&shared, b"this is not json".to_vec());
        route_reply(&shared, serde_json::to_vec(&serde_json::json!({})).unwrap());
        route_reply(
            &shared,
            serde_json::to_vec(&serde_json::json!({"correlation_id": "not-a-uuid"})).unwrap(),
        );

        assert_eq!(
            shared.pending_map().len(),
            1,
            "an unreadable reply must not evict a waiting round trip"
        );
        assert!(rx.try_recv().is_err(), "the waiter must still be waiting");
    }

    /// Every lock in [`Shared`] recovers from poisoning rather than
    /// propagating a panic.
    ///
    /// This matters more here than in most places: these locks sit on the
    /// login path, and a `unwrap()` on a poisoned lock would turn one panicked
    /// dispatch into every subsequent dispatch panicking — a single transient
    /// fault escalated into a permanent, process-wide outage of exactly the
    /// hook sites reactors guard.
    #[test]
    fn a_poisoned_lock_is_recovered_rather_than_propagated() {
        let shared = Arc::new(Shared::new());

        // The panic hook is silenced first so three *expected* panics do not
        // print three backtraces into a passing test's output.
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let s = Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let _held = s.pending.lock().unwrap();
            panic!("poison `pending` while holding it");
        })
        .join();

        let s = Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let _held = s.declared.lock().unwrap();
            panic!("poison `declared` while holding it");
        })
        .join();

        let s = Arc::clone(&shared);
        let _ = std::thread::spawn(move || {
            let _held = s.session.write().unwrap();
            panic!("poison `session` while holding it");
        })
        .join();

        std::panic::set_hook(hook);

        // The premise: all three really are poisoned, so the assertions below
        // are exercising the recovery and not a no-op.
        assert!(shared.pending.is_poisoned());
        assert!(shared.declared.is_poisoned());
        assert!(shared.session.is_poisoned());

        // …and all three accessors still work.
        shared
            .pending_map()
            .insert(Uuid::new_v4(), oneshot::channel().0);
        assert_eq!(shared.pending_map().len(), 1);

        shared
            .declared_map()
            .insert(Uuid::new_v4(), vec!["e".into()]);
        assert_eq!(shared.declared_map().len(), 1);

        assert!(shared.session().is_none());
        shared.set_session(None);
        assert!(shared.session().is_none());
    }

    /// A reply nothing is waiting for is dropped, not applied — the server
    /// side of §22.3's "abandon rather than answer late".
    #[test]
    fn a_reply_with_no_waiting_round_trip_is_discarded() {
        let shared = Shared::new();
        let body = serde_json::to_vec(&serde_json::json!({
            "correlation_id": Uuid::new_v4(),
        }))
        .unwrap();
        route_reply(&shared, body);
        assert!(shared.pending_map().is_empty());
    }

    #[test]
    fn a_reply_is_routed_to_the_round_trip_named_in_its_body() {
        let shared = Shared::new();
        let correlation_id = Uuid::new_v4();
        let (tx, mut rx) = oneshot::channel();
        shared.pending_map().insert(correlation_id, tx);

        let body = serde_json::to_vec(&serde_json::json!({
            "correlation_id": correlation_id,
            "decision": "allow",
        }))
        .unwrap();
        route_reply(&shared, body.clone());

        assert_eq!(rx.try_recv().unwrap(), body);
        assert!(
            shared.pending_map().is_empty(),
            "a delivered reply must clear its slot"
        );
    }

    /// Losing the session must wake every in-flight dispatch immediately.
    #[tokio::test]
    async fn losing_the_session_wakes_in_flight_dispatches_instead_of_stranding_them() {
        let shared = Shared::new();
        let (tx, rx) = oneshot::channel::<Vec<u8>>();
        shared.pending_map().insert(Uuid::new_v4(), tx);

        shared.abandon_all_pending();

        assert!(rx.await.is_err(), "the waiter must be woken, not stranded");
    }

    /// The guard is what makes a timed-out or cancelled dispatch stop
    /// occupying a slot.
    #[test]
    fn the_pending_guard_deregisters_on_every_exit_path() {
        let shared = Arc::new(Shared::new());
        let correlation_id = Uuid::new_v4();
        let (tx, _rx) = oneshot::channel();
        shared.pending_map().insert(correlation_id, tx);

        {
            let _guard = PendingGuard {
                shared: Arc::clone(&shared),
                correlation_id,
            };
        }

        assert!(shared.pending_map().is_empty());
    }

    /// A reactor's declared bindings are cached per process, so the hot path
    /// costs a map lookup rather than a broker round trip.
    #[test]
    fn identical_bindings_short_circuit_the_declare() {
        let shared = Shared::new();
        let r = reactor(&["token.pre_issue", "login.post_auth"]);
        shared.declared_map().insert(r.id, r.events.clone());

        assert!(
            shared
                .declared_map()
                .get(&r.id)
                .is_some_and(|have| *have == r.events)
        );

        // …and a registration whose events changed does not.
        let mut changed = r.clone();
        changed.events = vec!["token.pre_issue".into()];
        assert!(
            shared
                .declared_map()
                .get(&changed.id)
                .is_none_or(|have| *have != changed.events)
        );
    }
}

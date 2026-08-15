//! Reactors (X1) — AMQP-native extension actors.
//!
//! See [`axiam_core::models::reactor`] for the event registry and the domain
//! model; this module is the wire protocol, the dispatch chain, and the gate
//! that joins them to a routing table, a concurrency bound, the audit trail and
//! a set of counters.
//!
//! The split across the two crates is the design: `axiam-auth`,
//! `axiam-oauth2` and the REST handlers call reactors through `ReactorGate`,
//! which lives in `axiam-core`, so the crates that issue tokens and sessions
//! never learn that a message broker is involved.
//!
//! | Module | What it owns |
//! |---|---|
//! | [`protocol`] | The signed bodies and every rule for accepting a reply |
//! | [`dispatcher`] | What a chain of reactors *means* (order, merge, policy) |
//! | [`gate`] | What the five hook sites call: routing, cap, audit, metrics |
//! | [`metrics`] | The counters an operator reads |

pub mod dispatcher;
pub mod gate;
pub mod metrics;
pub mod protocol;

pub use dispatcher::{
    ChainResult, DEFAULT_MAX_IN_FLIGHT, DispatchFailure, InFlightLimiter, MAX_CHAIN_BUDGET_MS,
    NoopReactorGate, REACTOR_TRANSPORT_UNAVAILABLE, ReactorTransport, UnavailableReactorTransport,
    resolve_failure, run_chain,
};
pub use gate::{
    AUDIT_ACTION_DENIED, AUDIT_ACTION_FAILURE, AUDIT_ACTION_MUTATED, DEFAULT_ROUTING_TTL,
    DispatchingReactorGate, EmptyReactorSource, NoopAuditSink, ReactorAuditSink, ReactorGateConfig,
    ReactorRoutingTable, ReactorSource, RepositoryAuditSink, RepositoryReactorSource,
};
pub use protocol::{
    REACTOR_EXCHANGE, ReactorEventMessage, ReactorReply, ReplyDecision, ReplyRejection, queue_name,
    routing_key,
};

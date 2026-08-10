//! Reactors (X1) — AMQP-native extension actors.
//!
//! See [`axiam_core::models::reactor`] for the event registry and the domain
//! model; this module is the wire protocol and the dispatch chain.
//!
//! The split across the two crates is the design: `axiam-auth` and
//! `axiam-oauth2` call reactors through `ReactorGate`, which lives in
//! `axiam-core`, so the crates that issue tokens and sessions never learn that
//! a message broker is involved.

pub mod dispatcher;
pub mod protocol;

pub use dispatcher::{
    ChainResult, DEFAULT_MAX_IN_FLIGHT, DispatchFailure, InFlightLimiter, MAX_CHAIN_BUDGET_MS,
    NoopReactorGate, ReactorTransport, run_chain,
};
pub use protocol::{
    REACTOR_EXCHANGE, ReactorEventMessage, ReactorReply, ReplyDecision, ReplyRejection, queue_name,
    routing_key,
};

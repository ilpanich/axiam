//! The shared outbound dispatcher's AMQP machinery (D-36, T23.5.1).
//!
//! Everything here is parameterised by [`axiam_core::outbound::OutboundKind`];
//! nothing here knows what a webhook, a Security Event Token or a SCIM
//! operation is. The ports live in `axiam_core::outbound` (layer 0) and are
//! documented there, including the three steps that add a kind.
//!
//! | Piece | Module |
//! |---|---|
//! | per-kind queue names and declaration arguments | [`topology`] |
//! | bounded exponential retry policy and its env vars | [`retry`] |
//! | the bytes on the queue | [`wire`] |
//! | enqueue (implements `OutboundPublisher`) | [`publisher`] |
//! | deliverer registry, the consume loop and its supervisor | [`consumer`] |
//!
//! The webhook kind keeps exactly the names, arguments, wire format and
//! environment variables it had before the extraction. Renaming any of them
//! would drop in-flight messages on upgrade or make the broker refuse a
//! redeclaration; `topology::tests` pins them byte for byte.

pub mod consumer;
pub mod publisher;
pub mod retry;
pub mod topology;
pub mod wire;

pub use consumer::{
    OutboundConsumerError, OutboundDeliverers, run_outbound_consumer, spawn_outbound_consumer,
};
pub use publisher::AmqpOutboundPublisher;
pub use retry::{OutboundRetryConfig, backoff_ttl_ms};
pub use topology::{OutboundTopology, QueueSpec};

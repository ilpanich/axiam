//! The shared outbound dispatcher's ports (D-36, T23.5.1).
//!
//! AXIAM pushes work to systems it does not control: webhooks today, Shared
//! Signals Framework push (G-5) and outbound SCIM operations (G-6) next. All of
//! them need the same machinery: a durable queue, one attempt per delivery,
//! bounded exponential retry, a dead-letter queue, an audit trail. That
//! machinery is in `axiam-amqp`; the protocol that decides *what one attempt
//! does* lives in the crate that owns the protocol. This module is the seam
//! between the two, and it is layer 0 so that every protocol crate, whichever
//! layer it sits in, can reach it.
//!
//! # The three pieces
//!
//! * [`OutboundMessage`] — the envelope that travels through the queue.
//! * [`OutboundPublisher`] — *enqueue* a message. What a producer holds.
//! * [`OutboundDeliverer`] — make *one attempt* at delivering a message and
//!   report [`DeliveryOutcome`]. What a protocol crate implements.
//!
//! Retry, backoff, the attempt counter, the maximum-attempts decision and the
//! dead-letter queue are **not** the deliverer's business. A deliverer never
//! sleeps, never counts attempts and never republishes; it reports what
//! happened and the consumer loop decides.
//!
//! # Adding a kind (SSF push, outbound SCIM)
//!
//! 1. Add one line to the `outbound_kinds!` invocation below:
//!    `SsfPush => "ssf_push"`. The slug fixes the kind's queue names
//!    (`axiam.ssf_push`, `.retry`, `.dlq`), its env-var prefix
//!    (`AXIAM__SSF_PUSH__MAX_ATTEMPTS`, `..._BACKOFF_BASE_MS`,
//!    `..._BACKOFF_CEILING_MS`) and its audit action prefix
//!    (`ssf_push.delivery_succeeded`, `.delivery_attempt`, `.delivery_failed`).
//! 2. Implement [`OutboundDeliverer`] in the crate that owns the protocol,
//!    returning that kind from [`OutboundDeliverer::kind`].
//! 3. In `axiam-server`: call `AmqpManager::declare_outbound_topology(kind)`,
//!    register the deliverer in `axiam_amqp::outbound::OutboundDeliverers`, and
//!    run `axiam_amqp::outbound::run_outbound_consumer` for the kind.
//!
//! No change to `axiam-amqp`'s loop, topology or publisher is needed.
//!
//! # Implementing [`OutboundDeliverer`]
//!
//! ```
//! use axiam_core::outbound::{
//!     DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundKind,
//!     OutboundMessage,
//! };
//!
//! struct Discarding;
//!
//! impl OutboundDeliverer for Discarding {
//!     fn kind(&self) -> OutboundKind {
//!         OutboundKind::Webhook
//!     }
//!
//!     fn deliver_attempt<'a>(
//!         &'a self,
//!         msg: &'a OutboundMessage,
//!     ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
//!         Box::pin(async move {
//!             if msg.payload.is_null() {
//!                 // Never going to succeed; do not burn the retry budget.
//!                 return Ok(DeliveryOutcome::DeadLetter { reason: "empty payload".into() });
//!             }
//!             Ok(DeliveryOutcome::Delivered { response_status: Some(204) })
//!         })
//!     }
//! }
//! ```

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Declares [`OutboundKind`] from `Variant => "slug"` pairs.
///
/// A macro so that adding a kind is one line: the enum, its serde names,
/// [`OutboundKind::ALL`] and [`OutboundKind::as_str`] cannot drift apart.
macro_rules! outbound_kinds {
    ($( $(#[$meta:meta])* $variant:ident => $slug:literal ),+ $(,)?) => {
        /// What an outbound delivery is *for*; selects the queue topology, the
        /// retry configuration and the [`OutboundDeliverer`].
        ///
        /// The slug ([`Self::as_str`]) is load-bearing: it is the serde name,
        /// the queue-name stem, the env-var prefix and the audit-action prefix.
        /// **Never change an existing slug** — that renames queues that hold
        /// in-flight messages and drops them on upgrade.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum OutboundKind {
            $( $(#[$meta])* #[serde(rename = $slug)] $variant ),+
        }

        impl OutboundKind {
            /// Every kind, for code that has to cover them all (topology
            /// declaration, consumer start-up, tests).
            pub const ALL: &'static [OutboundKind] = &[ $( OutboundKind::$variant ),+ ];

            /// The kind's stable slug: lower-case ASCII letters, digits and
            /// underscores only (it becomes part of a queue name and an
            /// environment-variable name).
            pub const fn as_str(self) -> &'static str {
                match self { $( OutboundKind::$variant => $slug ),+ }
            }
        }
    };
}

outbound_kinds! {
    /// HMAC-signed JSON POST to a tenant-registered webhook URL.
    Webhook => "webhook",
}

impl OutboundKind {
    /// Resolve a slug back to its kind.
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.as_str() == slug)
    }
}

impl std::fmt::Display for OutboundKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The envelope for one outbound delivery, as it travels through the queue.
///
/// Fields are the superset every kind needs; a kind that does not use one
/// leaves it at a neutral value (e.g. `Uuid::nil()`, `Value::Null`). The
/// envelope never carries a secret: a deliverer resolves the signing material
/// itself from `target_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OutboundMessage {
    /// Selects the queue, retry configuration and deliverer.
    pub kind: OutboundKind,
    /// Owning tenant. Every deliverer lookup is scoped by it; an envelope
    /// without it would force a cross-tenant lookup.
    pub tenant_id: Uuid,
    /// What is being delivered *to*: the webhook id for
    /// [`OutboundKind::Webhook`]; the stream id for SSF push; the target id for
    /// outbound SCIM. Also the `resource_id` of the delivery audit records.
    pub target_id: Uuid,
    /// Identifies this logical delivery across all of its attempts.
    pub delivery_id: Uuid,
    /// The event name (`user.created`, ...). Free text to the dispatcher.
    pub event_type: String,
    /// The event body. Opaque to the dispatcher.
    pub payload: serde_json::Value,
    /// Attempts already made; `0` on first enqueue. Owned by the consumer
    /// loop, which increments it on every republish to the retry queue.
    pub attempt: u32,
}

/// What a single delivery attempt achieved. See [`OutboundDeliverer`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The receiver accepted the message. The delivery is acknowledged and
    /// never attempted again.
    Delivered {
        /// The receiver's protocol status (an HTTP status code), if the
        /// protocol has one. Recorded in the success audit entry as `status`.
        response_status: Option<u16>,
    },
    /// This attempt failed in a way that may succeed later (receiver down,
    /// non-2xx, timeout, SSRF guard refused a name that may re-resolve). The
    /// loop retries with backoff until the kind's maximum attempts, then
    /// dead-letters.
    Retry {
        /// Why; recorded in the audit entry as `error`. Must not contain
        /// secrets.
        reason: String,
    },
    /// This message can never succeed (it is malformed, or its target is
    /// permanently gone). The loop dead-letters it now, without spending the
    /// remaining attempts.
    DeadLetter {
        /// Why; recorded in the audit entry as `error`. Must not contain
        /// secrets.
        reason: String,
    },
}

/// Failure to enqueue, or a deliverer that could not even report an outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OutboundError {
    /// The message could not be encoded or the broker did not confirm it.
    #[error("outbound enqueue failed: {0}")]
    Enqueue(String),
    /// Bytes taken off a queue are not a valid message for that queue's kind.
    /// The consumer loop dead-letters these without retrying.
    #[error("outbound message malformed: {0}")]
    Malformed(String),
    /// A deliverer failed before it could classify the attempt. The consumer
    /// loop treats this exactly like [`DeliveryOutcome::Retry`].
    #[error("outbound delivery failed: {0}")]
    Delivery(String),
}

/// A boxed, `Send` future: the return type that keeps the ports object-safe
/// (`Arc<dyn OutboundPublisher>` / `Arc<dyn OutboundDeliverer>`) without a
/// dependency on an async-trait crate in layer 0.
pub type OutboundFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Enqueue an outbound delivery. The producer side of the dispatcher.
///
/// Best-effort from the caller's point of view: a producer is a side effect of
/// some other operation (a revocation, a user update) and must not fail that
/// operation because the broker is unavailable. Log the error and carry on, as
/// `WebhookDeliveryService::emit` does.
///
/// Implementations route by [`OutboundMessage::kind`] and must enqueue the
/// message with `attempt` as given (producers pass `0`). The enqueue is
/// durable: `Ok(())` means the broker confirmed it.
pub trait OutboundPublisher: Send + Sync {
    /// Durably enqueue `msg` for its kind's consumer.
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>>;
}

/// Make one delivery attempt. The protocol side of the dispatcher.
///
/// One implementation per [`OutboundKind`], living in the crate that owns the
/// protocol (webhooks in `axiam-api-rest`, SSF push in `axiam-oauth2`).
/// Registered with the consumer loop by `axiam-server`.
///
/// # Contract
///
/// * **Exactly one attempt.** No retry loop, no sleep, no republish, no
///   attempt counting. The consumer loop owns all of those, so that backoff
///   and dead-lettering behave identically for every kind.
/// * **Classify, do not decide.** Return [`DeliveryOutcome::Retry`] for
///   anything that may succeed later, and [`DeliveryOutcome::DeadLetter`] only
///   for what can never succeed. Whether a retry is still affordable is the
///   loop's call.
/// * **Errors are retries.** An `Err` is treated as [`DeliveryOutcome::Retry`]
///   with the error's text as the reason.
/// * **Be idempotent-friendly.** At-least-once delivery means the same
///   `delivery_id` can arrive twice (a crash between delivery and ack). Send
///   `delivery_id` to the receiver so it can deduplicate.
/// * **No secrets in reasons.** `reason` strings go to the audit log.
/// * **Cancel-safe.** The future may be dropped when the consumer stops.
pub trait OutboundDeliverer: Send + Sync {
    /// The kind this deliverer serves. The consumer loop refuses to start for
    /// a kind with no registered deliverer.
    fn kind(&self) -> OutboundKind;

    /// Attempt delivery of `msg` once and report what happened.
    fn deliver_attempt<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn webhook_slug_is_pinned() {
        // The slug is the queue-name stem, the env-var prefix and the audit
        // prefix; renaming it drops in-flight webhook messages on upgrade.
        assert_eq!(OutboundKind::Webhook.as_str(), "webhook");
        assert_eq!(
            serde_json::to_string(&OutboundKind::Webhook).unwrap(),
            "\"webhook\""
        );
    }

    #[test]
    fn every_slug_is_safe_for_queue_and_env_names() {
        for kind in OutboundKind::ALL {
            let slug = kind.as_str();
            assert!(!slug.is_empty());
            assert!(
                slug.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "slug {slug:?} must be [a-z0-9_]+"
            );
        }
    }

    #[test]
    fn slugs_are_unique_and_round_trip() {
        for kind in OutboundKind::ALL {
            assert_eq!(OutboundKind::from_slug(kind.as_str()), Some(*kind));
            assert_eq!(kind.to_string(), kind.as_str());
        }
        let mut slugs: Vec<_> = OutboundKind::ALL.iter().map(|k| k.as_str()).collect();
        slugs.sort_unstable();
        slugs.dedup();
        assert_eq!(slugs.len(), OutboundKind::ALL.len());
        assert_eq!(OutboundKind::from_slug("nope"), None);
    }

    #[test]
    fn envelope_round_trips() {
        let msg = OutboundMessage {
            kind: OutboundKind::Webhook,
            tenant_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            delivery_id: Uuid::new_v4(),
            event_type: "user.created".into(),
            payload: serde_json::json!({"a": 1}),
            attempt: 3,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<OutboundMessage>(&json).unwrap(), msg);
    }

    /// The ports must stay object-safe: `axiam-server` and the protocol crates
    /// hold them as `Arc<dyn ...>`.
    #[tokio::test]
    async fn ports_are_object_safe() {
        struct P;
        impl OutboundPublisher for P {
            fn enqueue<'a>(
                &'a self,
                _msg: &'a OutboundMessage,
            ) -> OutboundFuture<'a, Result<(), OutboundError>> {
                Box::pin(async { Ok(()) })
            }
        }
        struct D;
        impl OutboundDeliverer for D {
            fn kind(&self) -> OutboundKind {
                OutboundKind::Webhook
            }
            fn deliver_attempt<'a>(
                &'a self,
                _msg: &'a OutboundMessage,
            ) -> OutboundFuture<'a, Result<DeliveryOutcome, OutboundError>> {
                Box::pin(async {
                    Ok(DeliveryOutcome::Delivered {
                        response_status: None,
                    })
                })
            }
        }
        let msg = OutboundMessage {
            kind: OutboundKind::Webhook,
            tenant_id: Uuid::nil(),
            target_id: Uuid::nil(),
            delivery_id: Uuid::nil(),
            event_type: String::new(),
            payload: serde_json::Value::Null,
            attempt: 0,
        };
        let p: Arc<dyn OutboundPublisher> = Arc::new(P);
        let d: Arc<dyn OutboundDeliverer> = Arc::new(D);
        p.enqueue(&msg).await.unwrap();
        assert_eq!(d.kind(), OutboundKind::Webhook);
        assert_eq!(
            d.deliver_attempt(&msg).await.unwrap(),
            DeliveryOutcome::Delivered {
                response_status: None
            }
        );
    }
}

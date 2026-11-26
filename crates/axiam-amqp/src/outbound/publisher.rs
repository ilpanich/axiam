//! Enqueue and re-enqueue outbound messages.

use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Channel, Confirmation};
use tracing::error;

use axiam_core::outbound::{OutboundError, OutboundFuture, OutboundMessage, OutboundPublisher};

use super::topology::OutboundTopology;
use super::wire;
use crate::error::AmqpError;
use crate::internal_envelope::InternalSigner;

/// Publishes outbound messages to their kind's primary or retry queue.
///
/// Implements the core [`OutboundPublisher`] port (enqueue to the primary
/// queue), and additionally exposes [`Self::publish_retry`] for the consumer
/// loop's TTL-delayed republish. Use `AmqpManager::create_publisher_channel` to
/// obtain a channel with publisher confirms enabled before wrapping it here.
///
/// SA-14 (N3): every message is sealed in the server-only signed envelope;
/// the consume loop refuses anything else.
#[derive(Clone)]
pub struct AmqpOutboundPublisher {
    channel: Channel,
    signer: InternalSigner,
}

/// Properties of a primary-queue publish: JSON, persistent.
pub(crate) fn primary_properties() -> BasicProperties {
    BasicProperties::default()
        .with_content_type("application/json".into())
        .with_delivery_mode(2) // persistent
}

/// Properties of a retry-queue publish: as [`primary_properties`] plus the
/// per-message TTL after which the broker dead-letters it back to the primary.
pub(crate) fn retry_properties(ttl_ms: u64) -> BasicProperties {
    primary_properties().with_expiration(ttl_ms.to_string().into())
}

impl AmqpOutboundPublisher {
    /// Wrap a confirm-enabled publisher channel; `signer` seals every message.
    pub fn new(channel: Channel, signer: InternalSigner) -> Self {
        Self { channel, signer }
    }

    async fn publish_to(
        &self,
        queue: &str,
        msg: &OutboundMessage,
        properties: BasicProperties,
        issued_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AmqpError> {
        let payload = wire::seal(&self.signer, msg, issued_at).map_err(|e| {
            error!(kind = %msg.kind, error = %e, "Failed to serialize outbound message");
            AmqpError::Publish(e.to_string())
        })?;

        // The default (nameless) exchange routes by queue name.
        let confirm = self
            .channel
            .basic_publish(
                "".into(),
                queue.into(),
                BasicPublishOptions::default(),
                &payload,
                properties,
            )
            .await
            .map_err(|e| AmqpError::Publish(e.to_string()))?;

        match confirm.await {
            Ok(Confirmation::Nack(_)) => Err(AmqpError::Publish(format!(
                "broker nacked {} publish",
                msg.kind
            ))),
            Err(e) => {
                error!(kind = %msg.kind, error = %e, "Outbound publish not confirmed by broker");
                Err(AmqpError::Publish(e.to_string()))
            }
            Ok(_) => Ok(()),
        }
    }

    /// Publish to the kind's primary queue (first attempt, or a message that
    /// already dead-lettered back from the retry queue).
    pub async fn publish(&self, msg: &OutboundMessage) -> Result<(), AmqpError> {
        let topology = OutboundTopology::for_kind(msg.kind);
        self.publish_to(
            &topology.primary,
            msg,
            primary_properties(),
            chrono::Utc::now(),
        )
        .await
    }

    /// Publish to the kind's retry queue with a per-message TTL of `ttl_ms`.
    /// RabbitMQ dead-letters the message back to the primary queue once the TTL
    /// expires; no consumer is ever attached to the retry queue, so no slot is
    /// held for the delay.
    ///
    /// The copy's `issued_at` is the time its TTL expires, not the publish
    /// time: it re-enters the primary queue then, and a backoff longer than the
    /// freshness window must not make it stale on arrival (SA-14).
    pub async fn publish_retry(&self, msg: &OutboundMessage, ttl_ms: u64) -> Result<(), AmqpError> {
        let topology = OutboundTopology::for_kind(msg.kind);
        self.publish_to(
            &topology.retry,
            msg,
            retry_properties(ttl_ms),
            retry_issued_at(chrono::Utc::now(), ttl_ms),
        )
        .await
    }
}

/// When a retry copy published at `now` with TTL `ttl_ms` becomes current.
pub(crate) fn retry_issued_at(
    now: chrono::DateTime<chrono::Utc>,
    ttl_ms: u64,
) -> chrono::DateTime<chrono::Utc> {
    i64::try_from(ttl_ms)
        .ok()
        .and_then(chrono::Duration::try_milliseconds)
        .and_then(|ttl| now.checked_add_signed(ttl))
        .unwrap_or(now)
}

impl OutboundPublisher for AmqpOutboundPublisher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            self.publish(msg)
                .await
                .map_err(|e| OutboundError::Enqueue(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primary_publish_is_persistent_json_without_expiration() {
        let props = primary_properties();
        assert_eq!(props.delivery_mode(), &Some(2));
        assert_eq!(
            props.content_type().as_ref().map(|s| s.to_string()),
            Some("application/json".to_string())
        );
        assert!(props.expiration().is_none());
    }

    /// SA-14: a retry copy is current when it comes back, not when it left.
    #[test]
    fn a_retry_copy_is_issued_at_its_ttl_expiry() {
        let now = chrono::Utc::now();
        assert_eq!(
            retry_issued_at(now, 3_600_000),
            now + chrono::Duration::hours(1)
        );
    }

    #[test]
    fn retry_publish_carries_the_ttl_as_expiration() {
        let props = retry_properties(30_000);
        assert_eq!(props.delivery_mode(), &Some(2));
        assert_eq!(
            props.expiration().as_ref().map(|s| s.to_string()),
            Some("30000".to_string())
        );
    }
}

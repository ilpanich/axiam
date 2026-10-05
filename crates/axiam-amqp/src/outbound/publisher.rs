//! Enqueue and re-enqueue outbound messages.

use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Channel, Confirmation};
use tracing::error;

use axiam_core::outbound::{OutboundError, OutboundFuture, OutboundMessage, OutboundPublisher};

use super::topology::OutboundTopology;
use super::wire;
use crate::error::AmqpError;

/// Publishes outbound messages to their kind's primary or retry queue.
///
/// Implements the core [`OutboundPublisher`] port (enqueue to the primary
/// queue), and additionally exposes [`Self::publish_retry`] for the consumer
/// loop's TTL-delayed republish. Use `AmqpManager::create_publisher_channel` to
/// obtain a channel with publisher confirms enabled before wrapping it here.
#[derive(Clone)]
pub struct AmqpOutboundPublisher {
    channel: Channel,
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
    /// Wrap a confirm-enabled publisher channel.
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }

    async fn publish_to(
        &self,
        queue: &str,
        msg: &OutboundMessage,
        properties: BasicProperties,
    ) -> Result<(), AmqpError> {
        let payload = wire::encode(msg).map_err(|e| {
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
        self.publish_to(&topology.primary, msg, primary_properties())
            .await
    }

    /// Publish to the kind's retry queue with a per-message TTL of `ttl_ms`.
    /// RabbitMQ dead-letters the message back to the primary queue once the TTL
    /// expires; no consumer is ever attached to the retry queue, so no slot is
    /// held for the delay.
    pub async fn publish_retry(&self, msg: &OutboundMessage, ttl_ms: u64) -> Result<(), AmqpError> {
        let topology = OutboundTopology::for_kind(msg.kind);
        self.publish_to(&topology.retry, msg, retry_properties(ttl_ms))
            .await
    }
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

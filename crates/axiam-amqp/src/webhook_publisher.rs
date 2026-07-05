//! Publisher for webhook delivery messages (CORR-03/D-07).
//!
//! `WebhookPublisher` puts one `WebhookMessage` per matching webhook onto
//! the `axiam.webhook` primary queue (`publish`) or, on retry, the
//! `axiam.webhook.retry` delay queue (`publish_retry`, per-message TTL) so
//! RabbitMQ's native TTL + dead-letter-exchange pair schedules the delay —
//! no external scheduler, no in-process `tokio::time::sleep` tying up a
//! consumer slot (D-07/Pitfall 5). Mirrors `MailOutboundPublisher`'s shape.

use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Channel, Confirmation};
use tracing::error;

use crate::connection::queues;
use crate::error::AmqpError;
use crate::messages::WebhookMessage;

/// Publishes webhook delivery messages to the primary/retry queues
/// (CORR-03/D-07).
///
/// Use `AmqpManager::create_publisher_channel` to obtain a channel with
/// publisher confirms enabled before wrapping it here.
#[derive(Clone)]
pub struct WebhookPublisher {
    channel: Channel,
}

impl WebhookPublisher {
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }

    async fn publish_to(
        &self,
        queue: &str,
        msg: &WebhookMessage,
        properties: BasicProperties,
    ) -> Result<(), AmqpError> {
        let payload = serde_json::to_vec(msg).map_err(|e| {
            error!(error = %e, "Failed to serialize WebhookMessage");
            AmqpError::Publish(e.to_string())
        })?;

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
            Ok(Confirmation::Nack(_)) => {
                Err(AmqpError::Publish("broker nacked webhook publish".into()))
            }
            Err(e) => {
                error!(error = %e, "Webhook publish not confirmed by broker");
                Err(AmqpError::Publish(e.to_string()))
            }
            Ok(_) => Ok(()),
        }
    }

    /// Publish a webhook delivery message to the primary `axiam.webhook`
    /// queue (first attempt, or a message that already dead-lettered back
    /// from the retry queue after its TTL expired).
    pub async fn publish(&self, msg: &WebhookMessage) -> Result<(), AmqpError> {
        self.publish_to(
            queues::WEBHOOK,
            msg,
            BasicProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2), // persistent
        )
        .await
    }

    /// Publish a webhook delivery message to the `axiam.webhook.retry` queue
    /// with a per-message TTL of `ttl_ms`. RabbitMQ dead-letters the message
    /// back to the primary `axiam.webhook` queue via the default exchange
    /// once the TTL expires — no consumer is ever attached to the retry
    /// queue, so no slot is held for the delay duration (D-07/Pitfall 5).
    pub async fn publish_retry(&self, msg: &WebhookMessage, ttl_ms: u64) -> Result<(), AmqpError> {
        self.publish_to(
            queues::WEBHOOK_RETRY,
            msg,
            BasicProperties::default()
                .with_content_type("application/json".into())
                .with_delivery_mode(2)
                .with_expiration(ttl_ms.to_string().into()),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    fn sample_message() -> WebhookMessage {
        WebhookMessage {
            webhook_id: Uuid::new_v4(),
            delivery_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            event_type: "user.created".to_string(),
            payload: json!({"key": "value"}),
            attempt: 0,
        }
    }

    #[test]
    fn webhook_message_serializes_all_fields() {
        let msg = sample_message();
        let json = serde_json::to_string(&msg).expect("serialize");
        assert!(json.contains("webhook_id"));
        assert!(json.contains("delivery_id"));
        assert!(json.contains("tenant_id"));
        assert!(json.contains("event_type"));
        assert!(json.contains("payload"));
        assert!(json.contains("attempt"));
    }

    #[test]
    fn webhook_message_round_trips() {
        let msg = sample_message();
        let json = serde_json::to_string(&msg).expect("serialize");
        let decoded: WebhookMessage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.webhook_id, msg.webhook_id);
        assert_eq!(decoded.delivery_id, msg.delivery_id);
        assert_eq!(decoded.tenant_id, msg.tenant_id);
        assert_eq!(decoded.event_type, msg.event_type);
        assert_eq!(decoded.attempt, msg.attempt);
    }

    /// `with_expiration` on `BasicProperties` is the exact mechanism
    /// `publish_retry` sets a per-message TTL through — proves the
    /// stringified `ttl_ms` round-trips through `BasicProperties` unchanged,
    /// without needing a live broker.
    #[test]
    fn publish_retry_expiration_matches_ttl_ms() {
        let ttl_ms: u64 = 30_000;
        let props = BasicProperties::default().with_expiration(ttl_ms.to_string().into());
        assert_eq!(
            props.expiration().as_ref().map(|s| s.to_string()),
            Some(ttl_ms.to_string())
        );
    }
}

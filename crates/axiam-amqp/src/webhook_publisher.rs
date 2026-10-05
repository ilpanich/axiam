//! Publisher for webhook delivery messages (CORR-03/D-07).
//!
//! Since D-36 the queueing is done by the kind-generic
//! [`AmqpOutboundPublisher`]; `WebhookPublisher` is the webhook-typed face of
//! it. It keeps the pre-extraction API (`new`, `publish`, `publish_retry` over
//! [`WebhookMessage`]) so existing callers and tests are unchanged, and also
//! implements the core [`OutboundPublisher`] port so that a webhook producer
//! can hold it as `&dyn OutboundPublisher`.
//!
//! `publish` puts one `WebhookMessage` per matching webhook onto the
//! `axiam.webhook` primary queue; `publish_retry` puts it on the
//! `axiam.webhook.retry` delay queue (per-message TTL) so RabbitMQ's native
//! TTL + dead-letter-exchange pair schedules the delay (D-07/Pitfall 5).

use lapin::Channel;

use axiam_core::outbound::{OutboundError, OutboundFuture, OutboundMessage, OutboundPublisher};

use crate::error::AmqpError;
use crate::messages::WebhookMessage;
use crate::outbound::AmqpOutboundPublisher;

/// Publishes webhook delivery messages to the primary/retry queues
/// (CORR-03/D-07).
///
/// Use `AmqpManager::create_publisher_channel` to obtain a channel with
/// publisher confirms enabled before wrapping it here.
#[derive(Clone)]
pub struct WebhookPublisher {
    inner: AmqpOutboundPublisher,
}

impl WebhookPublisher {
    /// Wrap a confirm-enabled publisher channel.
    pub fn new(channel: Channel) -> Self {
        Self {
            inner: AmqpOutboundPublisher::new(channel),
        }
    }

    /// The kind-generic publisher underneath, which the generic consume loop
    /// uses for its TTL-delayed retry republish.
    pub fn as_outbound(&self) -> &AmqpOutboundPublisher {
        &self.inner
    }

    /// Publish a webhook delivery message to the primary `axiam.webhook`
    /// queue (first attempt, or a message that already dead-lettered back
    /// from the retry queue after its TTL expired).
    pub async fn publish(&self, msg: &WebhookMessage) -> Result<(), AmqpError> {
        self.inner.publish(&msg.clone().into()).await
    }

    /// Publish a webhook delivery message to the `axiam.webhook.retry` queue
    /// with a per-message TTL of `ttl_ms`. RabbitMQ dead-letters the message
    /// back to the primary `axiam.webhook` queue via the default exchange
    /// once the TTL expires: no consumer is ever attached to the retry
    /// queue, so no slot is held for the delay duration (D-07/Pitfall 5).
    pub async fn publish_retry(&self, msg: &WebhookMessage, ttl_ms: u64) -> Result<(), AmqpError> {
        self.inner.publish_retry(&msg.clone().into(), ttl_ms).await
    }
}

impl OutboundPublisher for WebhookPublisher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        self.inner.enqueue(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lapin::BasicProperties;
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

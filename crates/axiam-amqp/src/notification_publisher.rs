//! Publisher for notification events to the `axiam.notifications` queue.

use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Channel};
use tracing::error;

use crate::connection::queues;
use crate::error::AmqpError;
use crate::messages::NotificationEvent;

/// Publishes notification events to the `axiam.notifications` queue.
#[derive(Clone)]
pub struct NotificationPublisher {
    channel: Channel,
}

impl NotificationPublisher {
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }

    /// Publish a notification event.
    pub async fn publish(&self, event: &NotificationEvent) -> Result<(), AmqpError> {
        let payload = serde_json::to_vec(event).map_err(|e| {
            error!(error = %e, "Failed to serialize notification event");
            AmqpError::Publish(e.to_string())
        })?;

        self.channel
            .basic_publish(
                "".into(),
                queues::NOTIFICATIONS.into(),
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default().with_content_type("application/json".into()),
            )
            .await
            .map_err(|e| AmqpError::Publish(e.to_string()))?;

        Ok(())
    }
}

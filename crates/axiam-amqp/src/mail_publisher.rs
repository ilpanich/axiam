//! Publisher for outbound mail messages to the `axiam.mail.outbound` queue.
//!
//! `MailOutboundPublisher` implements `axiam_core::repository::MailPublisher`
//! so that any crate that depends on `axiam-core` (but not `axiam-amqp`) can
//! accept a `&impl MailPublisher` as a generic parameter without coupling to
//! the AMQP infrastructure layer.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::mail::OutboundMailMessage;
use axiam_core::repository::MailPublisher;
use lapin::options::BasicPublishOptions;
use lapin::{BasicProperties, Channel, Confirmation};
use tracing::error;

use crate::connection::queues;
use crate::error::AmqpError;

/// Publishes outbound mail messages to the `axiam.mail.outbound` queue (D-14).
///
/// Use `create_publisher_channel` on the `AmqpManager` to obtain a channel
/// with publisher confirms enabled before wrapping it here.
#[derive(Clone)]
pub struct MailOutboundPublisher {
    channel: Channel,
}

impl MailOutboundPublisher {
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }

    async fn publish_inner(&self, msg: OutboundMailMessage) -> Result<(), AmqpError> {
        let payload = serde_json::to_vec(&msg).map_err(|e| {
            error!(error = %e, "Failed to serialize OutboundMailMessage");
            AmqpError::Publish(e.to_string())
        })?;

        let confirm = self
            .channel
            .basic_publish(
                "".into(),
                queues::MAIL_OUTBOUND.into(),
                BasicPublishOptions::default(),
                &payload,
                BasicProperties::default()
                    .with_content_type("application/json".into())
                    .with_delivery_mode(2), // persistent
            )
            .await
            .map_err(|e| AmqpError::Publish(e.to_string()))?;

        match confirm.await {
            Ok(Confirmation::Nack(_)) => {
                Err(AmqpError::Publish("broker nacked mail publish".into()))
            }
            Err(e) => {
                error!(error = %e, "Mail publish not confirmed by broker");
                Err(AmqpError::Publish(e.to_string()))
            }
            Ok(_) => Ok(()),
        }
    }
}

impl MailPublisher for MailOutboundPublisher {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        self.publish_inner(msg)
            .await
            .map_err(|e| AxiamError::Internal(e.to_string()))
    }
}

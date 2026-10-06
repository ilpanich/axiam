//! Choosing the transport for outbound delivery and transactional mail
//! (T23.8.1, G-8, D-59).
//!
//! With the broker (`AXIAM__AMQP__ENABLED=true`, the default) the four outbound
//! kinds ride durable AMQP queues and mail rides `axiam.mail.outbound`. Without
//! it they ride the in-process dispatcher and the in-process mail channel of
//! `axiam-amqp`. The composition root picks **once, at start-up**; every
//! producer keeps the same port (`Arc<dyn OutboundPublisher>`, `MailPublisher`)
//! and every deliverer is the same one, so nothing downstream branches on the
//! profile.

use std::collections::HashMap;
use std::sync::Arc;

use axiam_amqp::{
    AmqpManager, AmqpOutboundPublisher, InProcessMailPublisher, InProcessOutbound,
    MailOutboundPublisher, OutboundDeliverers, OutboundRetryConfig, spawn_in_process_consumer,
    spawn_outbound_consumer,
};
use axiam_core::error::AxiamResult;
use axiam_core::models::mail::OutboundMailMessage;
use axiam_core::outbound::{OutboundKind, OutboundPublisher};
use axiam_core::repository::{AuditLogRepository, MailPublisher};

/// The transport behind the four outbound kinds.
pub enum OutboundTransport {
    /// Durable AMQP queues: one publisher channel per kind, a supervised
    /// consumer per kind.
    Amqp {
        /// The shared broker connection.
        manager: Arc<AmqpManager>,
        /// The publisher per kind, kept so the kind's consumer can use it for
        /// its TTL-delayed retry republish.
        publishers: HashMap<OutboundKind, AmqpOutboundPublisher>,
    },
    /// The minimal profile: bounded in-process queues, lost on restart.
    InProcess(InProcessOutbound),
}

impl OutboundTransport {
    /// The broker-backed transport.
    pub fn amqp(manager: Arc<AmqpManager>) -> Self {
        Self::Amqp {
            manager,
            publishers: HashMap::new(),
        }
    }

    /// The broker-less transport.
    pub fn in_process() -> Self {
        Self::InProcess(InProcessOutbound::new())
    }

    /// The publisher producers of `kind` hold. Call it once per kind, before
    /// [`Self::spawn_consumer`]: with AMQP it opens that kind's confirm-enabled
    /// publisher channel (a failure here is a boot failure, as it always was).
    pub async fn publisher(&mut self, kind: OutboundKind) -> Arc<dyn OutboundPublisher> {
        match self {
            Self::Amqp {
                manager,
                publishers,
            } => {
                let channel = manager
                    .create_publisher_channel()
                    .await
                    .unwrap_or_else(|e| {
                        panic!("Failed to create the AMQP {kind} publisher channel: {e}")
                    });
                let publisher = AmqpOutboundPublisher::new(channel);
                publishers.insert(kind, publisher.clone());
                Arc::new(publisher)
            }
            Self::InProcess(hub) => Arc::new(hub.publisher()),
        }
    }

    /// Start the consumer of `kind`: the supervised AMQP loop, or the in-process
    /// one. `audit_repo` receives the same `<slug>.delivery_*` rows either way.
    pub fn spawn_consumer<A>(
        &mut self,
        kind: OutboundKind,
        deliverers: OutboundDeliverers,
        audit_repo: A,
        cfg: OutboundRetryConfig,
    ) where
        A: AuditLogRepository + 'static,
    {
        match self {
            Self::Amqp {
                manager,
                publishers,
            } => {
                let publisher = publishers
                    .get(&kind)
                    .unwrap_or_else(|| panic!("no AMQP publisher was created for kind {kind}"))
                    .clone();
                // CQ-B53: the supervisor never exits the process; see
                // `spawn_outbound_consumer` for the reconnect backoff.
                spawn_outbound_consumer(
                    Arc::clone(manager),
                    kind,
                    deliverers,
                    publisher,
                    audit_repo,
                    cfg,
                );
            }
            Self::InProcess(hub) => {
                let end = hub
                    .take_consumer_end(kind)
                    .unwrap_or_else(|| panic!("the in-process {kind} queue was already consumed"));
                spawn_in_process_consumer(end, &deliverers, audit_repo, cfg)
                    .unwrap_or_else(|e| panic!("cannot start the in-process {kind} consumer: {e}"));
            }
        }
    }
}

/// The mail publisher every producer holds: the broker's, or the in-process
/// channel's. One concrete, cheaply cloned type, so the REST state, the audit
/// notification sink, the CIBA notifier and the cleanup task need no generics
/// of their own.
#[derive(Clone)]
pub enum MailTransportPublisher {
    /// Publishes to `axiam.mail.outbound`.
    Amqp(MailOutboundPublisher),
    /// Sends on the in-process bounded channel (minimal profile).
    InProcess(InProcessMailPublisher),
}

impl MailPublisher for MailTransportPublisher {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        match self {
            Self::Amqp(p) => p.publish(msg).await,
            Self::InProcess(p) => p.publish(msg).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_amqp::in_process_mail_channel;
    use axiam_core::models::mail::MailType;

    fn mail() -> OutboundMailMessage {
        OutboundMailMessage {
            mail_type: MailType::PasswordReset,
            tenant_id: uuid::Uuid::new_v4(),
            org_id: uuid::Uuid::new_v4(),
            user_id: uuid::Uuid::new_v4(),
            to_address: String::new(),
            template_context: serde_json::json!({}),
            attempt_count: 0,
            enqueued_at: chrono::Utc::now(),
        }
    }

    /// The in-process arm of the mail publisher reaches the channel's queue.
    #[tokio::test]
    async fn the_in_process_mail_publisher_delivers_to_the_channel() {
        let (publisher, _queue) = in_process_mail_channel();
        let publisher = MailTransportPublisher::InProcess(publisher);
        publisher.publish(mail()).await.unwrap();
        assert!(
            MailTransportPublisher::InProcess(InProcessMailPublisher::disabled())
                .publish(mail())
                .await
                .is_err()
        );
    }

    /// Every kind gets a publisher and a consumer end from the in-process
    /// transport, and each kind's end is handed out once.
    #[tokio::test]
    async fn the_in_process_transport_serves_every_kind() {
        let mut transport = OutboundTransport::in_process();
        for kind in OutboundKind::ALL {
            let _ = transport.publisher(*kind).await;
        }
        let OutboundTransport::InProcess(hub) = &mut transport else {
            unreachable!()
        };
        for kind in OutboundKind::ALL {
            assert!(hub.take_consumer_end(*kind).is_some());
            assert!(hub.take_consumer_end(*kind).is_none());
        }
    }
}

//! AMQP consumer for audit event ingestion from external services.

use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;
use futures_lite::StreamExt;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions};
use lapin::types::FieldTable;
use tracing::{error, info, warn};

use crate::connection::queues;
use crate::messages::AuditEventMessage;

fn parse_actor_type(s: &str) -> Option<ActorType> {
    match s {
        "User" | "user" => Some(ActorType::User),
        "ServiceAccount" | "service_account" => Some(ActorType::ServiceAccount),
        "System" | "system" => Some(ActorType::System),
        _ => None,
    }
}

fn parse_outcome(s: &str) -> Option<AuditOutcome> {
    match s {
        "Success" | "success" => Some(AuditOutcome::Success),
        "Failure" | "failure" => Some(AuditOutcome::Failure),
        "Denied" | "denied" => Some(AuditOutcome::Denied),
        _ => None,
    }
}

/// Start consuming audit events from `axiam.audit.events` and persisting them.
pub async fn start_audit_consumer<A>(channel: Channel, audit_repo: A)
where
    A: AuditLogRepository + 'static,
{
    info!("Starting audit event AMQP consumer");

    let mut consumer = match channel
        .basic_consume(
            queues::AUDIT_EVENTS.into(),
            "axiam-audit-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to start audit event consumer");
            return;
        }
    };

    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "Error receiving audit event delivery");
                continue;
            }
        };

        let tag = delivery.delivery_tag;

        let msg: AuditEventMessage = match serde_json::from_slice(&delivery.data) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    error = %e,
                    delivery_tag = tag,
                    "Invalid audit event payload, nacking"
                );
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                continue;
            }
        };

        let actor_type = match parse_actor_type(&msg.actor_type) {
            Some(t) => t,
            None => {
                warn!(
                    actor_type = %msg.actor_type,
                    delivery_tag = tag,
                    "Unknown actor_type in audit event, nacking"
                );
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                continue;
            }
        };

        let outcome = match parse_outcome(&msg.outcome) {
            Some(o) => o,
            None => {
                warn!(
                    outcome = %msg.outcome,
                    delivery_tag = tag,
                    "Unknown outcome in audit event, nacking"
                );
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
                continue;
            }
        };

        let entry = CreateAuditLogEntry {
            tenant_id: msg.tenant_id,
            actor_id: msg.actor_id,
            actor_type,
            action: msg.action,
            resource_id: msg.resource_id,
            outcome,
            ip_address: msg.ip_address,
            metadata: msg.metadata,
        };

        if let Err(e) = audit_repo.append(entry).await {
            error!(
                error = %e,
                delivery_tag = tag,
                "Failed to persist audit event"
            );
            let _ = delivery.acker.nack(BasicNackOptions::default()).await;
            continue;
        }

        if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
            error!(error = %e, delivery_tag = tag, "Failed to ack audit delivery");
        }
    }

    warn!("Audit event AMQP consumer stream ended");
}

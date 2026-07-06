//! AMQP consumer for audit event ingestion from external services.

use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;
use futures_lite::StreamExt;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions};
use lapin::types::FieldTable;
use tracing::{error, info, warn};

use crate::connection::queues;
use crate::messages::{AuditEventMessage, verify_tenant_signature};

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
///
/// SEC-022/055/SECHRD-08: Every `AuditEventMessage` is verified before
/// processing — the per-tenant subkey is derived from `master_signing_key` +
/// the message's `tenant_id` + `key_version`, then the `hmac_signature` is
/// checked against it. Messages with an invalid or missing signature are
/// nacked and never processed; there is no fail-open path (D-05c).
pub async fn start_audit_consumer<A>(channel: Channel, audit_repo: A, master_signing_key: Vec<u8>)
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

        let mut msg: AuditEventMessage = match serde_json::from_slice(&delivery.data) {
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

        // SEC-022/055/SECHRD-08: Verify the per-tenant derived HMAC
        // signature. Unsigned or invalid-signature messages are always
        // rejected — there is no fail-open path (D-05c, T-25-20).
        let received_sig = msg.hmac_signature.take();
        let tenant_id = msg.tenant_id;
        let key_version = msg.key_version;
        let canonical_bytes = serde_json::to_vec(&msg).unwrap_or_else(|_| delivery.data.clone());
        let valid = verify_tenant_signature(
            &master_signing_key,
            tenant_id,
            key_version,
            &canonical_bytes,
            received_sig.as_deref(),
        );
        if !valid {
            warn!(
                delivery_tag = tag,
                tenant_id = %tenant_id,
                "AuditEventMessage unsigned or HMAC verification failed — rejecting (SEC-022/055/SECHRD-08)"
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
                "Failed to persist audit event, nacking (dead-letter)"
            );
            // requeue: false — dead-letter the message instead of silently
            // dropping it or requeuing (CQ-B05 / REQ-14 AC-5).
            let _ = delivery
                .acker
                .nack(BasicNackOptions {
                    requeue: false,
                    ..BasicNackOptions::default()
                })
                .await;
            continue;
        }

        if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
            error!(error = %e, delivery_tag = tag, "Failed to ack audit delivery");
        }
    }

    warn!("Audit event AMQP consumer stream ended");
}

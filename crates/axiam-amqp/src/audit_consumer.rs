//! AMQP consumer for audit event ingestion from external services.

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AmqpNonceRepository, AuditLogRepository};
use chrono::Utc;
use futures_lite::StreamExt;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions};
use lapin::types::FieldTable;
use tracing::{error, info, warn};

use crate::connection::queues;
use crate::messages::{
    AuditEventMessage, MIN_ACCEPTED_KEY_VERSION, is_fresh, verify_tenant_signature,
};

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
///
/// NEW-4 (hard cutover): after a valid signature, the message is additionally
/// rejected (nack, requeue:false) when its `key_version` is below
/// [`MIN_ACCEPTED_KEY_VERSION`], its `issued_at` is outside the ±`replay_skew`
/// freshness window, or its `nonce` has already been consumed (a duplicate in
/// the durable `nonce_repo` store is a replay). There is no v1 grace path.
pub async fn start_audit_consumer<A, N>(
    channel: Channel,
    audit_repo: A,
    master_signing_key: Vec<u8>,
    nonce_repo: N,
    replay_skew: chrono::Duration,
) where
    A: AuditLogRepository + 'static,
    N: AmqpNonceRepository + 'static,
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

        // NEW-4 (hard cutover): reject pre-v2 messages that predate the
        // mandatory nonce/issued_at replay-protection fields.
        if key_version < MIN_ACCEPTED_KEY_VERSION {
            warn!(
                delivery_tag = tag,
                tenant_id = %tenant_id,
                key_version,
                "AuditEventMessage key_version below minimum — rejecting (NEW-4 replay protection)"
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

        // NEW-4: reject stale/future messages outside the freshness window.
        let now = Utc::now();
        if !is_fresh(msg.issued_at, now, replay_skew) {
            warn!(
                delivery_tag = tag,
                tenant_id = %tenant_id,
                issued_at = %msg.issued_at,
                "AuditEventMessage issued_at outside freshness window — rejecting (NEW-4)"
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

        // NEW-4: durable nonce dedup. Insert-or-conflict; a ReplayDetected
        // conflict means this exact signed message was already consumed. The
        // nonce only needs to outlive the freshness window (issued_at + skew).
        let nonce_expires_at = msg.issued_at + replay_skew;
        match nonce_repo
            .insert_nonce(tenant_id, msg.nonce, nonce_expires_at)
            .await
        {
            Ok(()) => {}
            Err(AxiamError::ReplayDetected) => {
                warn!(
                    delivery_tag = tag,
                    tenant_id = %tenant_id,
                    nonce = %msg.nonce,
                    "AuditEventMessage nonce replay detected — rejecting (NEW-4)"
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
            Err(e) => {
                error!(
                    error = %e,
                    delivery_tag = tag,
                    tenant_id = %tenant_id,
                    "Failed to record AuditEventMessage nonce — rejecting (dead-letter, NEW-4)"
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

//! AMQP consumer for audit event ingestion from external services.

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{
    ActorType, AuditOutcome, CreateAuditLogEntry, is_valid_audit_action, reserved_action_namespace,
};
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

/// The metadata key the consumer stamps on every row it ingests (#741).
///
/// Server-owned: written after the producer's metadata is merged, so a
/// producer-supplied value is overwritten. The server's own writers never set
/// it. (`metadata.source` is not usable for this: the directory, SCIM and SAML
/// admin writers already use it for other meanings.)
pub const INGESTED_VIA_KEY: &str = "ingested_via";

/// The value of [`INGESTED_VIA_KEY`] on a row ingested over AMQP.
pub const INGESTED_VIA_AMQP: &str = "amqp";

/// Key under which a producer's metadata is kept when it is not a JSON object
/// and so has no place to carry the stamp beside it.
pub const PRODUCER_METADATA_KEY: &str = "producer_metadata";

/// Merge the provenance stamp into a producer's metadata.
///
/// An object keeps its keys and gains `ingested_via: "amqp"`, overwriting any
/// the producer supplied. Absent metadata or `null` becomes `{ingested_via}`.
/// Any other JSON value (array, string, number, bool) is kept, not dropped,
/// under `producer_metadata` beside the stamp.
fn stamp_ingested(metadata: Option<serde_json::Value>) -> serde_json::Value {
    use serde_json::{Map, Value};
    let mut map = match metadata {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(m)) => m,
        Some(other) => {
            let mut m = Map::new();
            m.insert(PRODUCER_METADATA_KEY.into(), other);
            m
        }
    };
    map.insert(
        INGESTED_VIA_KEY.into(),
        Value::String(INGESTED_VIA_AMQP.into()),
    );
    Value::Object(map)
}

/// Outcome of processing a single AMQP audit-event delivery.
///
/// Return type of the broker-free [`process_audit_event`] seam. The pure
/// decode/verify/replay/parse/persist logic decides the fate of the delivery,
/// and the thin consumer loop translates it into `ack`/`nack` channel I/O.
#[derive(Debug)]
pub enum AuditIngestOutcome {
    /// The event was verified, fresh, non-replayed, well-formed, and was
    /// successfully appended to the audit log — the caller must `ack`.
    Ack,
    /// The delivery must be rejected with `nack(requeue: false)` — malformed
    /// payload, unsigned/invalid signature, key_version below the minimum,
    /// stale/future `issued_at`, an action in a namespace the server reserves
    /// for its control records (`tenants.*`, `gdpr.*`; R101W3-03), a replayed
    /// nonce, a nonce-store error, an unknown `actor_type`/`outcome`, or a
    /// persistence failure. Every one of these is the same `requeue: false`
    /// nack.
    NackDrop,
}

/// Decode, verify, replay-check, parse, and persist a single serialized
/// [`AuditEventMessage`], returning the [`AuditIngestOutcome`] the consumer
/// loop should enact. This is a behavior-preserving extraction of the
/// per-message body of [`start_audit_consumer`]'s `while let` loop — the loop
/// now only performs channel I/O (consume, ack/nack) around this function.
///
/// `now` is injected (the loop passes `Utc::now()`) so the NEW-4 freshness gate
/// is deterministically testable. All rejection paths return
/// [`AuditIngestOutcome::NackDrop`], matching the original `nack(requeue:
/// false)` branches exactly; the sole success path returns
/// [`AuditIngestOutcome::Ack`] after the append succeeds.
pub async fn process_audit_event<A, N>(
    raw: &[u8],
    audit_repo: &A,
    master_signing_key: &[u8],
    nonce_repo: &N,
    replay_skew: chrono::Duration,
    now: chrono::DateTime<Utc>,
) -> AuditIngestOutcome
where
    A: AuditLogRepository,
    N: AmqpNonceRepository,
{
    let mut msg: AuditEventMessage = match serde_json::from_slice(raw) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "Invalid audit event payload, nacking");
            return AuditIngestOutcome::NackDrop;
        }
    };

    // SEC-022/055/SECHRD-08: Verify the per-tenant derived HMAC signature.
    // Unsigned or invalid-signature messages are always rejected — there is
    // no fail-open path (D-05c, T-25-20).
    let received_sig = msg.hmac_signature.take();
    let tenant_id = msg.tenant_id;
    let key_version = msg.key_version;
    let canonical_bytes = serde_json::to_vec(&msg).unwrap_or_else(|_| raw.to_vec());
    let valid = verify_tenant_signature(
        master_signing_key,
        tenant_id,
        key_version,
        &canonical_bytes,
        received_sig.as_deref(),
    );
    if !valid {
        warn!(
            tenant_id = %tenant_id,
            "AuditEventMessage unsigned or HMAC verification failed — rejecting (SEC-022/055/SECHRD-08)"
        );
        return AuditIngestOutcome::NackDrop;
    }

    // NEW-4 (hard cutover): reject pre-v2 messages that predate the
    // mandatory nonce/issued_at replay-protection fields.
    if key_version < MIN_ACCEPTED_KEY_VERSION {
        warn!(
            tenant_id = %tenant_id,
            key_version,
            "AuditEventMessage key_version below minimum — rejecting (NEW-4 replay protection)"
        );
        return AuditIngestOutcome::NackDrop;
    }

    // NEW-4: reject stale/future messages outside the freshness window.
    if !is_fresh(msg.issued_at, now, replay_skew) {
        warn!(
            tenant_id = %tenant_id,
            issued_at = %msg.issued_at,
            "AuditEventMessage issued_at outside freshness window — rejecting (NEW-4)"
        );
        return AuditIngestOutcome::NackDrop;
    }

    // R110W3-09 (#682): an action is printable ASCII with at most one inner
    // space. A lookalike of a reserved action (leading space, Cyrillic or
    // full-width letters, a zero-width joiner) escapes the namespace test below
    // yet reads as a control record in the console. Refused before the nonce is
    // recorded; the log names the length, never the action.
    if !is_valid_audit_action(&msg.action) {
        warn!(
            tenant_id = %tenant_id,
            action_len = msg.action.len(),
            "AuditEventMessage action outside printable ASCII — rejecting (R110W3-09)"
        );
        return AuditIngestOutcome::NackDrop;
    }

    // R101W3-03 (#637): the server's control records are the server's alone.
    // A `tenants.audit_exported` receipt authorises a tenant's deletion and
    // bounds what its purge deletes; `tenants.deleted` / `tenants.purged` and
    // the `gdpr.*` records are evidence the server reads back. A tenant's
    // producers hold its signing subkey, so a valid signature does not make
    // one of these theirs to write. Refused before the nonce is recorded; the
    // log names the namespace, never the action or the payload.
    if let Some(namespace) = reserved_action_namespace(&msg.action) {
        warn!(
            tenant_id = %tenant_id,
            reserved_namespace = namespace,
            "AuditEventMessage carries an action reserved for the server's control records — rejecting (R101W3-03)"
        );
        return AuditIngestOutcome::NackDrop;
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
                tenant_id = %tenant_id,
                nonce = %msg.nonce,
                "AuditEventMessage nonce replay detected — rejecting (NEW-4)"
            );
            return AuditIngestOutcome::NackDrop;
        }
        Err(e) => {
            error!(
                error = %e,
                tenant_id = %tenant_id,
                "Failed to record AuditEventMessage nonce — rejecting (dead-letter, NEW-4)"
            );
            return AuditIngestOutcome::NackDrop;
        }
    }

    let actor_type = match parse_actor_type(&msg.actor_type) {
        Some(t) => t,
        None => {
            warn!(
                actor_type = %msg.actor_type,
                "Unknown actor_type in audit event, nacking"
            );
            return AuditIngestOutcome::NackDrop;
        }
    };

    let outcome = match parse_outcome(&msg.outcome) {
        Some(o) => o,
        None => {
            warn!(
                outcome = %msg.outcome,
                "Unknown outcome in audit event, nacking"
            );
            return AuditIngestOutcome::NackDrop;
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
        // #741: stamped after the producer's metadata, so it cannot override.
        metadata: Some(stamp_ingested(msg.metadata)),
    };

    if let Err(e) = audit_repo.append(entry).await {
        error!(
            error = %e,
            "Failed to persist audit event, nacking (dead-letter)"
        );
        // requeue: false — dead-letter the message instead of silently
        // dropping it or requeuing (CQ-B05 / REQ-14 AC-5).
        return AuditIngestOutcome::NackDrop;
    }

    AuditIngestOutcome::Ack
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

        // Decode/verify/replay-check/parse/persist off the channel (broker-free,
        // unit-tested via `process_audit_event`). The loop only translates the
        // returned outcome into channel I/O below.
        match process_audit_event(
            &delivery.data,
            &audit_repo,
            &master_signing_key,
            &nonce_repo,
            replay_skew,
            Utc::now(),
        )
        .await
        {
            AuditIngestOutcome::Ack => {
                if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
                    error!(error = %e, delivery_tag = tag, "Failed to ack audit delivery");
                }
            }
            AuditIngestOutcome::NackDrop => {
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
            }
        }
    }

    warn!("Audit event AMQP consumer stream ended");
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_stamp_overwrites_a_producer_supplied_key() {
        let out = stamp_ingested(Some(json!({"ingested_via": "server", "k": 1})));
        assert_eq!(out, json!({"ingested_via": "amqp", "k": 1}));
    }

    #[test]
    fn absent_and_null_metadata_become_the_stamp_alone() {
        assert_eq!(stamp_ingested(None), json!({"ingested_via": "amqp"}));
        assert_eq!(
            stamp_ingested(Some(json!(null))),
            json!({"ingested_via": "amqp"})
        );
    }

    #[test]
    fn non_object_metadata_is_kept_under_producer_metadata() {
        assert_eq!(
            stamp_ingested(Some(json!([1, 2]))),
            json!({"producer_metadata": [1, 2], "ingested_via": "amqp"})
        );
    }
}

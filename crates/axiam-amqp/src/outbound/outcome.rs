//! The outcome table: **the one place** that decides what a delivery attempt's
//! result means, shared by the AMQP consume loop ([`super::consumer`]) and the
//! in-process dispatcher ([`super::inprocess`], the minimal profile, G-8).
//!
//! A deliverer reports a [`DeliveryOutcome`] (or errors); [`decide`] turns that,
//! the message and the kind's retry policy into a [`Verdict`] carrying the audit
//! row to write. Neither transport re-implements any of it: they differ only in
//! how they *carry out* the verdict (AMQP: ack, republish to the TTL retry
//! queue, nack to the DLQ; in-process: drop, delayed re-dispatch, audit row
//! only).
//!
//! | Outcome | Verdict | Audit record (`<slug>.` prefix) |
//! |---|---|---|
//! | `Delivered` | [`Verdict::Delivered`] | `delivery_succeeded` (success) |
//! | `Retry`, or a deliverer `Err`, with attempts left | [`Verdict::Retry`] with `attempt + 1` and TTL [`backoff_ttl_ms`] | `delivery_attempt` (failure) |
//! | `Retry` / `Err` with no attempts left | [`Verdict::DeadLetter`] | `delivery_failed` (failure) |
//! | `DeadLetter` | [`Verdict::DeadLetter`], immediately | `delivery_failed` (failure) |
//!
//! The audit vocabulary (`<slug>.delivery_succeeded`, `.delivery_attempt`,
//! `.delivery_failed`, their metadata keys and the system actor) is built here
//! and nowhere else.
//!
//! A fourth action, `<slug>.delivery_abandoned` ([`abandoned_entry`]), is not an
//! outcome of an attempt: the minimal profile's in-process dispatcher writes it
//! for a delivery it lost without a verdict (queued or waiting for a retry when
//! the process stopped, or refused at enqueue). It is deliberately **not**
//! `delivery_failed`: that row is what a tenant's `scim_delivery_failed`
//! notification rule matches, and a stop is not a downstream outage.

use tracing::warn;
use uuid::Uuid;

use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::outbound::{DeliveryOutcome, OutboundError, OutboundMessage};

use super::retry::{OutboundRetryConfig, backoff_ttl_ms};

/// What to do with a delivery after one attempt.
#[derive(Debug, Clone)]
pub(crate) enum Verdict {
    /// Done. Acknowledge, and write the success row.
    Delivered {
        /// The `<slug>.delivery_succeeded` row.
        audit: CreateAuditLogEntry,
    },
    /// Try again later: enqueue `next` (the message with `attempt + 1`) after
    /// `ttl_ms`, then write the attempt row.
    Retry {
        /// The message to re-dispatch, `attempt` already incremented.
        next: OutboundMessage,
        /// The bounded exponential backoff before it re-enters the queue.
        ttl_ms: u64,
        /// The `<slug>.delivery_attempt` row.
        audit: CreateAuditLogEntry,
    },
    /// Terminal. Write the failure row; the transport parks the message (AMQP:
    /// the DLQ) or drops it (in-process: the row is the whole record).
    DeadLetter {
        /// The `<slug>.delivery_failed` row.
        audit: CreateAuditLogEntry,
    },
}

/// A deliverer that errors instead of classifying the attempt is a retry.
pub(crate) fn classify(result: Result<DeliveryOutcome, OutboundError>) -> DeliveryOutcome {
    match result {
        Ok(outcome) => outcome,
        Err(e) => DeliveryOutcome::Retry {
            reason: e.to_string(),
        },
    }
}

/// Build a delivery audit entry. `actor_id` uses the `Uuid::nil()`
/// system-actor convention: no human or service account initiated the attempt.
pub(crate) fn audit_entry(
    msg: &OutboundMessage,
    action_suffix: &str,
    outcome: AuditOutcome,
    metadata: serde_json::Value,
) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id: msg.tenant_id,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: format!("{}.{action_suffix}", msg.kind.as_str()),
        resource_id: Some(msg.target_id),
        outcome,
        ip_address: None,
        metadata: Some(metadata),
    }
}

/// The terminal failure row, also written by a transport that has to give up on
/// a delivery for a reason of its own (the in-process dispatcher's retry
/// capacity). Same action, same metadata keys as an exhausted delivery.
pub(crate) fn failed_entry(msg: &OutboundMessage, error_detail: &str) -> CreateAuditLogEntry {
    audit_entry(
        msg,
        "delivery_failed",
        AuditOutcome::Failure,
        serde_json::json!({
            "delivery_id": msg.delivery_id,
            "attempt": msg.attempt + 1,
            "error": error_detail,
            "next_retry_in_ms": null,
        }),
    )
}

/// The terminal row of a delivery the in-process dispatcher lost without a
/// verdict (P23W5-A4): `<slug>.delivery_abandoned`, outcome `Failure`, with one
/// of the dispatcher's fixed reasons. `attempts_made` is how many attempts ran
/// before the loss (`0` for a message never attempted).
///
/// Not `delivery_failed` on purpose: `NotificationEventType::from_audit_action`
/// maps only `scim_push.delivery_failed`, so this row mails nobody.
pub(crate) fn abandoned_entry(msg: &OutboundMessage, reason: &str) -> CreateAuditLogEntry {
    audit_entry(
        msg,
        "delivery_abandoned",
        AuditOutcome::Failure,
        serde_json::json!({
            "delivery_id": msg.delivery_id,
            "attempts_made": msg.attempt,
            "reason": reason,
        }),
    )
}

/// Decide what one attempt's `outcome` means for `msg` under `cfg`.
pub(crate) fn decide(
    msg: &OutboundMessage,
    outcome: DeliveryOutcome,
    cfg: &OutboundRetryConfig,
) -> Verdict {
    match outcome {
        DeliveryOutcome::Delivered { response_status } => {
            let mut metadata = serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempt": msg.attempt + 1,
            });
            if let (Some(status), Some(map)) = (response_status, metadata.as_object_mut()) {
                map.insert("status".into(), serde_json::json!(status));
            }
            Verdict::Delivered {
                audit: audit_entry(msg, "delivery_succeeded", AuditOutcome::Success, metadata),
            }
        }
        DeliveryOutcome::Retry { reason } => decide_failure(msg, true, reason, cfg),
        DeliveryOutcome::DeadLetter { reason } => decide_failure(msg, false, reason, cfg),
    }
}

/// Retry-or-exhaust: shared by every "this attempt did not succeed" outcome.
fn decide_failure(
    msg: &OutboundMessage,
    retryable: bool,
    error_detail: String,
    cfg: &OutboundRetryConfig,
) -> Verdict {
    let kind = msg.kind;
    let next_attempt = msg.attempt + 1;

    if retryable && next_attempt < cfg.max_attempts {
        let ttl_ms = backoff_ttl_ms(next_attempt, cfg);
        let mut next = msg.clone();
        next.attempt = next_attempt;
        Verdict::Retry {
            next,
            ttl_ms,
            audit: audit_entry(
                msg,
                "delivery_attempt",
                AuditOutcome::Failure,
                serde_json::json!({
                    "delivery_id": msg.delivery_id,
                    "attempt": next_attempt,
                    "error": error_detail,
                    "next_retry_in_ms": ttl_ms,
                }),
            ),
        }
    } else {
        warn!(
            %kind,
            target_id = %msg.target_id,
            delivery_id = %msg.delivery_id,
            attempt = next_attempt,
            max_attempts = cfg.max_attempts,
            error = %error_detail,
            "Outbound delivery exhausted retries or cannot succeed; dead-lettering"
        );
        Verdict::DeadLetter {
            audit: failed_entry(msg, &error_detail),
        }
    }
}

#[cfg(test)]
pub(crate) mod table {
    //! The outcome table as data, so that **both** transports' tests assert
    //! against the very same expectations (G-8: "the same outcome table, the
    //! same audit vocabulary").

    use super::*;
    use axiam_core::outbound::OutboundKind;

    /// The shape of a verdict, without its payload.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Shape {
        Delivered,
        Retry,
        DeadLetter,
    }

    /// One row: an attempt result for a message at `attempt`, and what the
    /// table says follows.
    pub(crate) struct Case {
        pub name: &'static str,
        pub attempt: u32,
        pub result: Result<DeliveryOutcome, OutboundError>,
        pub shape: Shape,
        pub action: &'static str,
        pub success: bool,
    }

    /// The retry policy every table row is evaluated under.
    pub(crate) const CFG: OutboundRetryConfig = OutboundRetryConfig {
        max_attempts: 3,
        backoff_base_ms: 100,
        backoff_ceiling_ms: 10_000,
    };

    pub(crate) fn message(kind: OutboundKind, attempt: u32) -> OutboundMessage {
        OutboundMessage {
            kind,
            tenant_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            delivery_id: Uuid::new_v4(),
            event_type: "user.created".into(),
            payload: serde_json::json!({"hello": "world"}),
            attempt,
        }
    }

    pub(crate) fn cases() -> Vec<Case> {
        let retry = |reason: &str| {
            Ok(DeliveryOutcome::Retry {
                reason: reason.into(),
            })
        };
        vec![
            Case {
                name: "delivered",
                attempt: 0,
                result: Ok(DeliveryOutcome::Delivered {
                    response_status: Some(204),
                }),
                shape: Shape::Delivered,
                action: "delivery_succeeded",
                success: true,
            },
            Case {
                name: "delivered after a retry",
                attempt: 1,
                result: Ok(DeliveryOutcome::Delivered {
                    response_status: None,
                }),
                shape: Shape::Delivered,
                action: "delivery_succeeded",
                success: true,
            },
            Case {
                name: "retry with attempts left",
                attempt: 0,
                result: retry("non-2xx status: 503"),
                shape: Shape::Retry,
                action: "delivery_attempt",
                success: false,
            },
            Case {
                name: "retry on the last affordable attempt",
                attempt: CFG.max_attempts - 2,
                result: retry("still down"),
                shape: Shape::Retry,
                action: "delivery_attempt",
                success: false,
            },
            Case {
                name: "retry with no attempts left",
                attempt: CFG.max_attempts - 1,
                result: retry("still down"),
                shape: Shape::DeadLetter,
                action: "delivery_failed",
                success: false,
            },
            Case {
                name: "deliverer error is a retry",
                attempt: 0,
                result: Err(OutboundError::Delivery("lookup failed".into())),
                shape: Shape::Retry,
                action: "delivery_attempt",
                success: false,
            },
            Case {
                name: "deliverer error on the last attempt",
                attempt: CFG.max_attempts - 1,
                result: Err(OutboundError::Delivery("boom".into())),
                shape: Shape::DeadLetter,
                action: "delivery_failed",
                success: false,
            },
            Case {
                name: "dead letter skips the remaining attempts",
                attempt: 0,
                result: Ok(DeliveryOutcome::DeadLetter {
                    reason: "target gone".into(),
                }),
                shape: Shape::DeadLetter,
                action: "delivery_failed",
                success: false,
            },
        ]
    }

    /// The shape of the verdict `decide` returns.
    pub(crate) fn shape_of(verdict: &Verdict) -> Shape {
        match verdict {
            Verdict::Delivered { .. } => Shape::Delivered,
            Verdict::Retry { .. } => Shape::Retry,
            Verdict::DeadLetter { .. } => Shape::DeadLetter,
        }
    }

    /// The audit row inside a verdict.
    pub(crate) fn audit_of(verdict: &Verdict) -> &CreateAuditLogEntry {
        match verdict {
            Verdict::Delivered { audit }
            | Verdict::Retry { audit, .. }
            | Verdict::DeadLetter { audit } => audit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::table::{CFG, Shape, audit_of, cases, message, shape_of};
    use super::*;
    use axiam_core::outbound::OutboundKind;

    #[test]
    fn every_row_of_the_table_decides_as_documented() {
        for case in cases() {
            for kind in OutboundKind::ALL {
                let msg = message(*kind, case.attempt);
                let verdict = decide(&msg, classify(case.result.clone()), &CFG);
                assert_eq!(shape_of(&verdict), case.shape, "{}", case.name);
                let audit = audit_of(&verdict);
                assert_eq!(
                    audit.action,
                    format!("{}.{}", kind.as_str(), case.action),
                    "{}",
                    case.name
                );
                assert_eq!(
                    matches!(audit.outcome, AuditOutcome::Success),
                    case.success,
                    "{}",
                    case.name
                );
                assert_eq!(audit.tenant_id, msg.tenant_id);
                assert_eq!(audit.resource_id, Some(msg.target_id));
                assert_eq!(audit.actor_id, Uuid::nil());
                assert!(matches!(audit.actor_type, ActorType::System));
                assert!(audit.ip_address.is_none());
            }
        }
    }

    #[test]
    fn a_retry_carries_the_incremented_attempt_and_the_backoff_ttl() {
        for attempt in [0u32, 1] {
            let msg = message(OutboundKind::Webhook, attempt);
            let verdict = decide(
                &msg,
                DeliveryOutcome::Retry {
                    reason: "non-2xx status: 503".into(),
                },
                &CFG,
            );
            let Verdict::Retry {
                next,
                ttl_ms,
                audit,
            } = verdict
            else {
                panic!("expected a retry");
            };
            assert_eq!(next.attempt, attempt + 1);
            assert_eq!(ttl_ms, backoff_ttl_ms(attempt + 1, &CFG));
            assert_eq!(
                audit.metadata,
                Some(serde_json::json!({
                    "delivery_id": msg.delivery_id,
                    "attempt": attempt + 1,
                    "error": "non-2xx status: 503",
                    "next_retry_in_ms": ttl_ms,
                }))
            );
            // Only `attempt` differs between the message and its retry copy.
            assert_eq!(next.delivery_id, msg.delivery_id);
            assert_eq!(next.payload, msg.payload);
        }
        assert_ne!(backoff_ttl_ms(1, &CFG), backoff_ttl_ms(2, &CFG));
    }

    #[test]
    fn success_metadata_omits_a_missing_protocol_status() {
        let msg = message(OutboundKind::Webhook, 0);
        let with = decide(
            &msg,
            DeliveryOutcome::Delivered {
                response_status: Some(204),
            },
            &CFG,
        );
        assert_eq!(
            audit_of(&with).metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id, "attempt": 1, "status": 204
            }))
        );
        let without = decide(
            &msg,
            DeliveryOutcome::Delivered {
                response_status: None,
            },
            &CFG,
        );
        assert_eq!(
            audit_of(&without).metadata,
            Some(serde_json::json!({"delivery_id": msg.delivery_id, "attempt": 1}))
        );
    }

    #[test]
    fn exhaustion_metadata_has_a_null_next_retry() {
        let msg = message(OutboundKind::SsfPush, CFG.max_attempts - 1);
        let verdict = decide(
            &msg,
            DeliveryOutcome::Retry {
                reason: "still down".into(),
            },
            &CFG,
        );
        assert_eq!(shape_of(&verdict), Shape::DeadLetter);
        assert_eq!(
            audit_of(&verdict).metadata,
            Some(serde_json::json!({
                "delivery_id": msg.delivery_id,
                "attempt": CFG.max_attempts,
                "error": "still down",
                "next_retry_in_ms": null,
            }))
        );
    }

    #[test]
    fn audit_entry_uses_the_system_actor_and_the_kind_prefix() {
        let msg = message(OutboundKind::Webhook, 0);
        let entry = audit_entry(
            &msg,
            "delivery_attempt",
            AuditOutcome::Failure,
            serde_json::json!({"x": 1}),
        );
        assert_eq!(entry.tenant_id, msg.tenant_id);
        assert_eq!(entry.actor_id, Uuid::nil());
        assert!(matches!(entry.actor_type, ActorType::System));
        assert_eq!(entry.action, "webhook.delivery_attempt");
        assert_eq!(entry.resource_id, Some(msg.target_id));
        assert!(entry.ip_address.is_none());
    }
}

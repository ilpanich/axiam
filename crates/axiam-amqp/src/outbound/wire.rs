//! The bytes on the queue.
//!
//! The webhook kind keeps its pre-extraction wire format: the JSON of
//! [`WebhookMessage`] (`webhook_id`, `delivery_id`, `tenant_id`, `event_type`,
//! `payload`, `attempt`). That is not tidiness: during a rolling upgrade an old
//! replica can consume what a new replica published and the reverse, and the
//! queues already hold messages written by the old code. Both directions must
//! parse, so the bytes must not change.
//!
//! Every other kind travels as the plain JSON of
//! [`OutboundMessage`](axiam_core::outbound::OutboundMessage), which carries its
//! own `kind`. A new kind needs no code here; it takes the generic path by
//! default.

use axiam_core::outbound::{OutboundError, OutboundKind, OutboundMessage};

use crate::messages::WebhookMessage;

impl From<WebhookMessage> for OutboundMessage {
    fn from(m: WebhookMessage) -> Self {
        Self {
            kind: OutboundKind::Webhook,
            tenant_id: m.tenant_id,
            target_id: m.webhook_id,
            delivery_id: m.delivery_id,
            event_type: m.event_type,
            payload: m.payload,
            attempt: m.attempt,
        }
    }
}

fn to_webhook_message(msg: &OutboundMessage) -> WebhookMessage {
    WebhookMessage {
        webhook_id: msg.target_id,
        delivery_id: msg.delivery_id,
        tenant_id: msg.tenant_id,
        event_type: msg.event_type.clone(),
        payload: msg.payload.clone(),
        attempt: msg.attempt,
    }
}

/// Serialise `msg` for its kind's queue.
pub fn encode(msg: &OutboundMessage) -> Result<Vec<u8>, OutboundError> {
    let bytes = if msg.kind == OutboundKind::Webhook {
        serde_json::to_vec(&to_webhook_message(msg))
    } else {
        serde_json::to_vec(msg)
    };
    bytes.map_err(|e| OutboundError::Enqueue(format!("serialize {} message: {e}", msg.kind)))
}

/// Parse bytes taken off `kind`'s queue.
///
/// A generic-envelope message whose own `kind` differs from the queue's is
/// refused: it was published to the wrong queue and must not reach another
/// kind's deliverer.
pub fn decode(kind: OutboundKind, data: &[u8]) -> Result<OutboundMessage, OutboundError> {
    if kind == OutboundKind::Webhook {
        return serde_json::from_slice::<WebhookMessage>(data)
            .map(OutboundMessage::from)
            .map_err(|e| OutboundError::Malformed(e.to_string()));
    }
    let msg: OutboundMessage =
        serde_json::from_slice(data).map_err(|e| OutboundError::Malformed(e.to_string()))?;
    if msg.kind != kind {
        return Err(OutboundError::Malformed(format!(
            "message of kind {} on the {kind} queue",
            msg.kind
        )));
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn webhook_msg() -> OutboundMessage {
        OutboundMessage {
            kind: OutboundKind::Webhook,
            tenant_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            delivery_id: Uuid::new_v4(),
            event_type: "user.created".into(),
            payload: serde_json::json!({"k": "v"}),
            attempt: 2,
        }
    }

    /// The webhook bytes are exactly what the pre-extraction code wrote.
    #[test]
    fn webhook_bytes_equal_the_legacy_webhook_message() {
        let msg = webhook_msg();
        let legacy = serde_json::to_vec(&WebhookMessage {
            webhook_id: msg.target_id,
            delivery_id: msg.delivery_id,
            tenant_id: msg.tenant_id,
            event_type: msg.event_type.clone(),
            payload: msg.payload.clone(),
            attempt: msg.attempt,
        })
        .unwrap();
        assert_eq!(encode(&msg).unwrap(), legacy);
        let text = String::from_utf8(legacy).unwrap();
        assert!(text.contains("\"webhook_id\""), "{text}");
        assert!(!text.contains("target_id"), "{text}");
        assert!(!text.contains("\"kind\""), "{text}");
    }

    /// A message written by the old code, in flight at upgrade, still parses.
    #[test]
    fn legacy_in_flight_webhook_message_decodes() {
        let (w, d, t) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let raw = format!(
            r#"{{"webhook_id":"{w}","delivery_id":"{d}","tenant_id":"{t}","event_type":"user.created","payload":{{"a":1}},"attempt":3}}"#
        );
        let msg = decode(OutboundKind::Webhook, raw.as_bytes()).unwrap();
        assert_eq!(msg.kind, OutboundKind::Webhook);
        assert_eq!(msg.target_id, w);
        assert_eq!(msg.delivery_id, d);
        assert_eq!(msg.tenant_id, t);
        assert_eq!(msg.attempt, 3);
        assert_eq!(msg.payload, serde_json::json!({"a": 1}));
    }

    #[test]
    fn webhook_round_trips() {
        let msg = webhook_msg();
        assert_eq!(
            decode(OutboundKind::Webhook, &encode(&msg).unwrap()).unwrap(),
            msg
        );
    }

    #[test]
    fn garbage_is_malformed() {
        let err = decode(OutboundKind::Webhook, b"not json").unwrap_err();
        assert!(matches!(err, OutboundError::Malformed(_)), "{err:?}");
    }
}

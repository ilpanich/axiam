//! Per-kind queue names and declaration arguments.
//!
//! Every [`OutboundKind`] owns a sibling trio of durable queues, derived from
//! its slug:
//!
//! | Queue | Name for slug `s` | Dead-letters to |
//! |---|---|---|
//! | primary | `axiam.<s>` | the DLQ (on a terminal `nack`, `requeue=false`) |
//! | retry | `axiam.<s>.retry` | the primary (when the per-message TTL expires) |
//! | DLQ | `axiam.<s>.dlq` | nowhere; replayable |
//!
//! All three use the **default (nameless) exchange** with an explicit
//! `x-dead-letter-routing-key`, which is the form RabbitMQ routes correctly
//! (a bare queue *name* in `x-dead-letter-exchange`, as the older queues in
//! `AmqpManager::declare_queues` have it, silently drops dead-lettered
//! messages). No consumer is ever attached to the retry queue; the broker, not
//! an in-process sleep, schedules the delay.

use lapin::types::{AMQPValue, FieldTable};

use axiam_core::outbound::OutboundKind;

/// The three queue names of one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundTopology {
    /// The kind these queues serve.
    pub kind: OutboundKind,
    /// Primary queue; the consumer reads this one. `axiam.<slug>`.
    pub primary: String,
    /// Retry-delay queue. `axiam.<slug>.retry`.
    pub retry: String,
    /// Terminal dead-letter queue. `axiam.<slug>.dlq`.
    pub dlq: String,
}

/// One queue to declare: its name and where it dead-letters, if anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueSpec {
    /// Queue name; also the routing key on the default exchange.
    pub name: String,
    /// `x-dead-letter-routing-key`, sent with `x-dead-letter-exchange = ""`.
    /// `None` for the DLQ, which has no dead-letter arguments at all.
    pub dead_letter_routing_key: Option<String>,
}

impl QueueSpec {
    /// The `queue.declare` arguments.
    ///
    /// Must equal, argument for argument, what an already-running broker holds:
    /// RabbitMQ refuses to redeclare a queue with different arguments
    /// (`PRECONDITION_FAILED`), which would stop the server booting on upgrade.
    pub fn arguments(&self) -> FieldTable {
        let mut args = FieldTable::default();
        if let Some(routing_key) = &self.dead_letter_routing_key {
            args.insert(
                "x-dead-letter-exchange".into(),
                AMQPValue::LongString("".into()),
            );
            args.insert(
                "x-dead-letter-routing-key".into(),
                AMQPValue::LongString(routing_key.as_str().into()),
            );
        }
        args
    }
}

impl OutboundTopology {
    /// The topology for `kind`, derived from its slug.
    pub fn for_kind(kind: OutboundKind) -> Self {
        let slug = kind.as_str();
        Self {
            kind,
            primary: format!("axiam.{slug}"),
            retry: format!("axiam.{slug}.retry"),
            dlq: format!("axiam.{slug}.dlq"),
        }
    }

    /// The queues in declaration order: the DLQ target first, then the primary
    /// (which dead-letters to it), then the retry queue (which dead-letters to
    /// the primary). A queue must exist before another names it.
    pub fn queue_specs(&self) -> [QueueSpec; 3] {
        [
            QueueSpec {
                name: self.dlq.clone(),
                dead_letter_routing_key: None,
            },
            QueueSpec {
                name: self.primary.clone(),
                dead_letter_routing_key: Some(self.dlq.clone()),
            },
            QueueSpec {
                name: self.retry.clone(),
                dead_letter_routing_key: Some(self.primary.clone()),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::queues;

    /// The webhook names, **byte for byte** (D-36). They name durable queues
    /// that hold in-flight messages across an upgrade; a change here drops
    /// those messages. These literals are deliberately not derived from
    /// anything.
    #[test]
    fn webhook_names_are_pinned_byte_for_byte() {
        let t = OutboundTopology::for_kind(OutboundKind::Webhook);
        assert_eq!(t.primary.as_bytes(), b"axiam.webhook");
        assert_eq!(t.retry.as_bytes(), b"axiam.webhook.retry");
        assert_eq!(t.dlq.as_bytes(), b"axiam.webhook.dlq");
        // ... and they are the constants the rest of the workspace uses.
        assert_eq!(t.primary, queues::WEBHOOK);
        assert_eq!(t.retry, queues::WEBHOOK_RETRY);
        assert_eq!(t.dlq, queues::WEBHOOK_DLQ);
    }

    /// The declaration the broker already holds: DLQ plain; primary
    /// dead-letters to the DLQ and retry dead-letters to the primary, both via
    /// the default exchange (`""`) with an explicit routing key; declared in
    /// that order.
    #[test]
    fn webhook_declaration_is_pinned() {
        let specs = OutboundTopology::for_kind(OutboundKind::Webhook).queue_specs();
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["axiam.webhook.dlq", "axiam.webhook", "axiam.webhook.retry"]
        );

        assert!(
            specs[0].arguments().inner().is_empty(),
            "DLQ has no DLX args"
        );

        let expect = |spec: &QueueSpec, routing_key: &str| {
            let args = spec.arguments();
            let inner = args.inner();
            assert_eq!(inner.len(), 2, "exactly the two dead-letter arguments");
            assert_eq!(
                inner.get("x-dead-letter-exchange"),
                Some(&AMQPValue::LongString("".into()))
            );
            assert_eq!(
                inner.get("x-dead-letter-routing-key"),
                Some(&AMQPValue::LongString(routing_key.into()))
            );
        };
        expect(&specs[1], "axiam.webhook.dlq");
        expect(&specs[2], "axiam.webhook");
    }

    /// Every kind gets its own trio, disjoint from every other kind's: one
    /// kind's backlog must never delay another's (the reason D-36 rejected a
    /// shared queue with a discriminator).
    #[test]
    fn every_kind_has_a_disjoint_sibling_topology() {
        let mut seen = std::collections::HashSet::new();
        for kind in OutboundKind::ALL {
            let t = OutboundTopology::for_kind(*kind);
            for name in [t.primary, t.retry, t.dlq] {
                assert!(name.starts_with("axiam."), "{name}");
                assert!(seen.insert(name.clone()), "{name} is used by two kinds");
            }
        }
        assert_eq!(seen.len(), OutboundKind::ALL.len() * 3);
    }
}

//! Notification dispatcher — matches audit events to notification rules
//! and enqueues outbound mail messages for each matched recipient (T19.13).
//!
//! The dispatcher calls `mail_publisher.publish(...)` once per matched
//! (event, recipient) pair.  On publish error the error is logged and
//! execution continues — fire-and-forget (D-14).

use axiam_core::error::AxiamResult;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::notification_rule::NotificationEventType;
use axiam_core::repository::{MailPublisher, NotificationRuleRepository};
use chrono::Utc;
use uuid::Uuid;

/// Dispatches audit events to matching notification rules by enqueuing
/// one `OutboundMailMessage(Notification)` per matched recipient.
pub struct NotificationDispatcher<N: NotificationRuleRepository> {
    rule_repo: N,
}

impl<N: NotificationRuleRepository> NotificationDispatcher<N> {
    /// Create a new dispatcher backed by the given rule repository.
    pub fn new(rule_repo: N) -> Self {
        Self { rule_repo }
    }

    /// Match an audit event against notification rules and enqueue one
    /// `OutboundMailMessage` per matched recipient.
    ///
    /// `tenant_id` and `org_id` are used to populate the mail message
    /// context so the consumer can resolve the correct email config.
    ///
    /// Returns `Ok(enqueued_count)` where count is the number of messages
    /// successfully handed to `mail_publisher`.  Publish errors are logged
    /// and do **not** propagate — callers get a successful result even if
    /// some (or all) enqueue calls fail.
    ///
    /// Returns `Ok(0)` if no rules match or the action/outcome does not map
    /// to any known notification event type.
    pub async fn dispatch(
        &self,
        tenant_id: Uuid,
        org_id: Uuid,
        action: &str,
        outcome: &str,
        actor_id: Option<Uuid>,
        details: &str,
        mail_publisher: &impl MailPublisher,
    ) -> AxiamResult<usize> {
        let event_types = NotificationEventType::from_audit_action(action, outcome);
        if event_types.is_empty() {
            return Ok(0);
        }

        // Collect all event type strings and query once (avoids N+1).
        let event_strings: Vec<String> = event_types.iter().map(|e| e.to_db_string()).collect();
        let rules = self
            .rule_repo
            .get_by_events(tenant_id, &event_strings)
            .await?;

        let mut enqueued = 0usize;
        for rule in rules {
            if rule.recipient_emails.is_empty() {
                continue;
            }
            // Find the first matching event type for this rule.
            let matched_event = event_types
                .iter()
                .find(|et| rule.events.contains(*et))
                .map(|et| et.to_db_string());

            let event_name = match matched_event {
                Some(name) => name,
                None => continue,
            };

            // Enqueue one OutboundMailMessage per recipient.
            for recipient in &rule.recipient_emails {
                let msg = OutboundMailMessage {
                    mail_type: MailType::Notification,
                    tenant_id,
                    org_id,
                    user_id: actor_id.unwrap_or(Uuid::nil()),
                    to_address: recipient.clone(),
                    template_context: serde_json::json!({
                        "event": event_name,
                        "details": details,
                        "action": action,
                        "outcome": outcome,
                    }),
                    attempt_count: 0,
                    enqueued_at: Utc::now(),
                };
                match mail_publisher.publish(msg).await {
                    Ok(()) => {
                        enqueued += 1;
                        tracing::debug!(
                            event = %event_name,
                            recipient = %recipient,
                            "notification mail enqueued"
                        );
                    }
                    Err(e) => {
                        // Fire-and-forget: log and continue (D-14).
                        tracing::warn!(
                            error = %e,
                            event = %event_name,
                            "failed to enqueue notification mail; skipping recipient"
                        );
                    }
                }
            }
        }

        Ok(enqueued)
    }
}

// ---------------------------------------------------------------------------
// Audit-stream adapter
// ---------------------------------------------------------------------------

/// Connects a [`NotificationDispatcher`] to the audit event stream.
///
/// This is the piece that was missing. `NotificationDispatcher` was complete,
/// tested, and exported — and constructed nowhere outside its own crate, so no
/// notification rule an administrator configured had any effect. The rules were
/// stored, listed by the API and rendered in the admin UI; nothing consulted
/// them.
///
/// Implements [`crate::middleware::AuditEventSink`] so
/// `AuditMiddleware::spawn_with_sink` can drive it on the audit worker's task,
/// off the request path.
pub struct NotificationSink<N: NotificationRuleRepository, P: MailPublisher> {
    dispatcher: NotificationDispatcher<N>,
    mail_publisher: P,
}

impl<N: NotificationRuleRepository, P: MailPublisher> NotificationSink<N, P> {
    /// Build a sink over a rule repository and a mail publisher.
    pub fn new(rule_repo: N, mail_publisher: P) -> Self {
        Self {
            dispatcher: NotificationDispatcher::new(rule_repo),
            mail_publisher,
        }
    }
}

impl<N, P> crate::middleware::AuditEventSink for NotificationSink<N, P>
where
    N: NotificationRuleRepository + 'static,
    P: MailPublisher + 'static,
{
    fn on_event<'a>(
        &'a self,
        event: &'a crate::middleware::AuditEvent,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let entry = &event.entry;

            // Rules are looked up by tenant; a nil tenant is an event the
            // middleware could attribute to nobody (an unauthenticated request
            // to a handler that sets no `AuditAttribution`). Skipping it here
            // avoids a repository round-trip per health-adjacent request.
            if entry.tenant_id.is_nil() {
                return;
            }

            let outcome = format!("{:?}", entry.outcome);
            let actor_id = if entry.actor_id.is_nil() {
                None
            } else {
                Some(entry.actor_id)
            };

            // The rendered body's `details`. Deliberately the action and the
            // HTTP status only: an audit notification goes to whatever addresses
            // an administrator typed into a rule, which are not necessarily
            // addresses cleared to see request contents (D-16).
            let details = format!("{} ({outcome})", entry.action);

            match self
                .dispatcher
                .dispatch(
                    entry.tenant_id,
                    event.org_id,
                    &entry.action,
                    &outcome,
                    actor_id,
                    &details,
                    &self.mail_publisher,
                )
                .await
            {
                Ok(0) => {}
                Ok(n) => tracing::debug!(
                    enqueued = n,
                    action = %entry.action,
                    "notification rule matched; mail enqueued"
                ),
                // Swallowed on purpose: the audit entry is already written, and
                // `AuditEventSink` is best-effort by contract.
                Err(e) => tracing::warn!(
                    error = %e,
                    action = %entry.action,
                    "failed to dispatch notification rules for an audit event"
                ),
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::mail::OutboundMailMessage;
    use axiam_core::models::notification_rule::{
        CreateNotificationRule, NotificationEventType, NotificationRule, UpdateNotificationRule,
    };
    use axiam_core::repository::{
        MailPublisher, NotificationRuleRepository, PaginatedResult, Pagination,
    };
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Mock rule repository
    // -----------------------------------------------------------------------

    #[derive(Clone)]
    struct MockRuleRepo {
        rules: Arc<Vec<NotificationRule>>,
    }

    impl MockRuleRepo {
        fn new(rules: Vec<NotificationRule>) -> Self {
            Self {
                rules: Arc::new(rules),
            }
        }

        fn empty() -> Self {
            Self::new(vec![])
        }
    }

    impl NotificationRuleRepository for MockRuleRepo {
        async fn create(&self, _input: CreateNotificationRule) -> AxiamResult<NotificationRule> {
            unimplemented!("not needed for notification tests")
        }

        async fn get_by_id(&self, _tenant_id: Uuid, _id: Uuid) -> AxiamResult<NotificationRule> {
            unimplemented!()
        }

        async fn list(
            &self,
            _tenant_id: Uuid,
            _pagination: Pagination,
        ) -> AxiamResult<PaginatedResult<NotificationRule>> {
            unimplemented!()
        }

        async fn update(
            &self,
            _tenant_id: Uuid,
            _id: Uuid,
            _input: UpdateNotificationRule,
        ) -> AxiamResult<NotificationRule> {
            unimplemented!()
        }

        async fn delete(&self, _tenant_id: Uuid, _id: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }

        async fn get_by_event(
            &self,
            _tenant_id: Uuid,
            _event_type: &str,
        ) -> AxiamResult<Vec<NotificationRule>> {
            unimplemented!()
        }

        async fn get_by_events(
            &self,
            tenant_id: Uuid,
            event_types: &[String],
        ) -> AxiamResult<Vec<NotificationRule>> {
            let _ = (tenant_id, event_types);
            Ok(self.rules.as_ref().clone())
        }
    }

    // -----------------------------------------------------------------------
    // Mock mail publisher
    // -----------------------------------------------------------------------

    #[derive(Clone, Default)]
    struct RecordingPublisher {
        sent: Arc<Mutex<Vec<OutboundMailMessage>>>,
    }

    impl RecordingPublisher {
        fn new() -> Self {
            Self {
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }

        fn messages(&self) -> Vec<OutboundMailMessage> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl MailPublisher for RecordingPublisher {
        async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
            self.sent.lock().unwrap().push(msg);
            Ok(())
        }
    }

    /// Mail publisher that always fails, to exercise the fire-and-forget
    /// error branch in `dispatch`.
    struct FailingPublisher;

    impl MailPublisher for FailingPublisher {
        async fn publish(&self, _msg: OutboundMailMessage) -> AxiamResult<()> {
            Err(axiam_core::error::AxiamError::Internal(
                "publish failed".into(),
            ))
        }
    }

    fn make_rule(recipients: Vec<&str>) -> NotificationRule {
        NotificationRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-rule".into(),
            description: "test rule for notifications".into(),
            events: vec![NotificationEventType::LoginFailure],
            recipient_emails: recipients.into_iter().map(|s| s.to_string()).collect(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// No matching event types → 0 messages enqueued.
    #[tokio::test]
    async fn notification_no_match_returns_zero() {
        let repo = MockRuleRepo::new(vec![make_rule(vec!["admin@example.com"])]);
        let dispatcher = NotificationDispatcher::new(repo);
        let publisher = RecordingPublisher::new();

        // "user.updated" with "success" does not map to LoginFailure.
        let count = dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "user.updated",
                "success",
                None,
                "details",
                &publisher,
            )
            .await
            .unwrap();

        assert_eq!(count, 0);
        assert_eq!(publisher.count(), 0);
    }

    /// Matching event → one message per recipient enqueued with MailType::Notification.
    #[tokio::test]
    async fn notification_enqueues_per_recipient() {
        let rule = make_rule(vec!["alice@example.com", "bob@example.com"]);
        let repo = MockRuleRepo::new(vec![rule]);
        let dispatcher = NotificationDispatcher::new(repo);
        let publisher = RecordingPublisher::new();

        // "POST /api/v1/auth/login" + "Failure" → LoginFailure event type
        let count = dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                Some(Uuid::new_v4()),
                "too many attempts",
                &publisher,
            )
            .await
            .unwrap();

        assert_eq!(count, 2, "expected 2 messages (one per recipient)");
        assert_eq!(publisher.count(), 2);

        let msgs = publisher.messages();
        assert!(
            msgs.iter()
                .all(|m| matches!(m.mail_type, MailType::Notification))
        );
        let addresses: Vec<&str> = msgs.iter().map(|m| m.to_address.as_str()).collect();
        assert!(addresses.contains(&"alice@example.com"));
        assert!(addresses.contains(&"bob@example.com"));
    }

    /// Empty recipient list → nothing enqueued.
    #[tokio::test]
    async fn notification_empty_recipients_skipped() {
        let rule = make_rule(vec![]);
        let repo = MockRuleRepo::new(vec![rule]);
        let dispatcher = NotificationDispatcher::new(repo);
        let publisher = RecordingPublisher::new();

        let count = dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                None,
                "",
                &publisher,
            )
            .await
            .unwrap();

        assert_eq!(count, 0);
        assert_eq!(publisher.count(), 0);
    }

    /// No rules configured → 0 messages enqueued.
    #[tokio::test]
    async fn notification_no_rules_returns_zero() {
        let repo = MockRuleRepo::empty();
        let dispatcher = NotificationDispatcher::new(repo);
        let publisher = RecordingPublisher::new();

        let count = dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                None,
                "",
                &publisher,
            )
            .await
            .unwrap();

        assert_eq!(count, 0);
    }

    /// A rule returned by the repository whose events do not intersect the
    /// event types derived from the audit action is skipped (the inner
    /// `matched_event == None` branch).
    #[tokio::test]
    async fn notification_rule_without_matching_event_is_skipped() {
        // Action/outcome maps to `LoginFailure`, but the rule only lists
        // `PasswordChanged`, so no event matches and the recipient is skipped.
        let rule = NotificationRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "mismatch-rule".into(),
            description: "rule whose events do not match the query".into(),
            events: vec![NotificationEventType::PasswordChanged],
            recipient_emails: vec!["nobody@example.com".into()],
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let repo = MockRuleRepo::new(vec![rule]);
        let dispatcher = NotificationDispatcher::new(repo);
        let publisher = RecordingPublisher::new();

        let count = dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                None,
                "details",
                &publisher,
            )
            .await
            .unwrap();

        assert_eq!(count, 0, "non-matching rule must enqueue nothing");
        assert_eq!(publisher.count(), 0);
    }

    /// Publish errors are logged and swallowed (fire-and-forget, D-14): the
    /// dispatcher still returns `Ok`, with a count that excludes the failed
    /// enqueue attempts.
    #[tokio::test]
    async fn notification_publish_error_is_swallowed() {
        let rule = make_rule(vec!["alice@example.com", "bob@example.com"]);
        let repo = MockRuleRepo::new(vec![rule]);
        let dispatcher = NotificationDispatcher::new(repo);
        let publisher = FailingPublisher;

        let count = dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                Some(Uuid::new_v4()),
                "too many attempts",
                &publisher,
            )
            .await
            .unwrap();

        // Both publishes failed, so nothing counted, but dispatch still succeeds.
        assert_eq!(count, 0, "failed publishes must not be counted");
    }

    // -----------------------------------------------------------------------
    // NotificationSink — the audit-stream adapter
    // -----------------------------------------------------------------------

    use crate::middleware::{AuditEvent, AuditEventSink};
    use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};

    fn entry(tenant_id: Uuid, action: &str, outcome: AuditOutcome) -> CreateAuditLogEntry {
        CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::new_v4(),
            actor_type: ActorType::User,
            action: action.to_string(),
            resource_id: None,
            outcome,
            ip_address: Some("203.0.113.7".into()),
            metadata: None,
        }
    }

    /// The regression this whole adapter exists for: a rule that matches an
    /// audit event produces mail. `NotificationDispatcher` could always do this;
    /// nothing ever called it, because nothing connected it to the audit stream.
    #[tokio::test]
    async fn a_matching_audit_event_enqueues_mail_for_every_recipient() {
        let tenant_id = Uuid::new_v4();
        let org_id = Uuid::new_v4();
        let repo = MockRuleRepo::new(vec![make_rule(vec![
            "soc@example.com",
            "oncall@example.com",
        ])]);
        let publisher = RecordingPublisher::new();
        let sink = NotificationSink::new(repo, publisher.clone());

        sink.on_event(&AuditEvent {
            entry: entry(tenant_id, "POST /api/v1/auth/login", AuditOutcome::Failure),
            org_id,
        })
        .await;

        assert_eq!(publisher.count(), 2, "one message per configured recipient");
        let msgs = publisher.messages();
        assert!(msgs.iter().all(|m| m.mail_type == MailType::Notification));
        assert!(msgs.iter().all(|m| m.tenant_id == tenant_id));
        assert!(
            msgs.iter().all(|m| m.org_id == org_id),
            "the organization must reach the message so the consumer can resolve \
             the effective email config"
        );

        let addresses: Vec<_> = msgs.iter().map(|m| m.to_address.as_str()).collect();
        assert!(addresses.contains(&"soc@example.com"));
        assert!(addresses.contains(&"oncall@example.com"));
    }

    /// `AuditOutcome`'s `Debug` form is what `from_audit_action` matches on
    /// ("Failure", "Success", "Denied"). If the sink formatted the outcome any
    /// other way, every rule would silently stop matching.
    #[tokio::test]
    async fn the_outcome_is_formatted_the_way_the_event_table_matches_on() {
        let repo = MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]);
        let publisher = RecordingPublisher::new();
        let sink = NotificationSink::new(repo, publisher.clone());

        // Success on the same path maps to no event; only Failure does.
        sink.on_event(&AuditEvent {
            entry: entry(
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                AuditOutcome::Success,
            ),
            org_id: Uuid::new_v4(),
        })
        .await;
        assert_eq!(publisher.count(), 0);

        sink.on_event(&AuditEvent {
            entry: entry(
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                AuditOutcome::Failure,
            ),
            org_id: Uuid::new_v4(),
        })
        .await;
        assert_eq!(publisher.count(), 1);
    }

    /// A nil tenant is an event the middleware could attribute to nobody. Rules
    /// are looked up by tenant, so there is nothing to match — and short-cutting
    /// saves a repository round-trip on every unattributable request.
    #[tokio::test]
    async fn an_unattributed_event_is_skipped_without_touching_the_repository() {
        let repo = MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]);
        let publisher = RecordingPublisher::new();
        let sink = NotificationSink::new(repo, publisher.clone());

        sink.on_event(&AuditEvent {
            entry: entry(
                Uuid::nil(),
                "POST /api/v1/auth/login",
                AuditOutcome::Failure,
            ),
            org_id: Uuid::nil(),
        })
        .await;

        assert_eq!(publisher.count(), 0);
    }

    /// A publisher outage must not escape the sink: the audit entry is already
    /// written by the time this runs, and `AuditEventSink` is best-effort by
    /// contract. `on_event` returns `()` — this test is that the future
    /// completes rather than panicking.
    #[tokio::test]
    async fn a_publisher_failure_is_swallowed() {
        let repo = MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]);
        let sink = NotificationSink::new(repo, FailingPublisher);

        sink.on_event(&AuditEvent {
            entry: entry(
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                AuditOutcome::Failure,
            ),
            org_id: Uuid::new_v4(),
        })
        .await;
    }

    /// The rendered `details` names the action and its outcome and nothing else.
    /// These emails go to whatever addresses an administrator typed into a rule,
    /// which are not necessarily cleared to see request contents (D-16).
    #[tokio::test]
    async fn the_details_carry_the_action_and_outcome_only() {
        let repo = MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]);
        let publisher = RecordingPublisher::new();
        let sink = NotificationSink::new(repo, publisher.clone());

        sink.on_event(&AuditEvent {
            entry: entry(
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                AuditOutcome::Failure,
            ),
            org_id: Uuid::new_v4(),
        })
        .await;

        let msg = publisher.messages().into_iter().next().unwrap();
        let details = msg.template_context["details"].as_str().unwrap();
        assert!(details.contains("POST /api/v1/auth/login"));
        assert!(details.contains("Failure"));
        assert!(
            !details.contains("203.0.113.7"),
            "the client IP must not reach a rule's recipients"
        );
    }
}

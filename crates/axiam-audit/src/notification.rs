//! Notification dispatcher — matches audit events to notification rules.
//!
//! The dispatcher queries active notification rules for a tenant and
//! returns the list of matched rules with their recipients. Actual
//! email delivery is deferred to TODO(T19): wire EmailService +
//! template resolution + org_id lookup.

use axiam_core::error::AxiamResult;
use axiam_core::models::notification_rule::NotificationEventType;
use axiam_core::repository::NotificationRuleRepository;
use uuid::Uuid;

/// Dispatches audit events to matching notification rules.
///
/// Returns the list of matched (event_name, recipient_emails) pairs.
/// The caller is responsible for actually sending emails.
pub struct NotificationDispatcher<N: NotificationRuleRepository> {
    rule_repo: N,
}

impl<N: NotificationRuleRepository> NotificationDispatcher<N> {
    /// Create a new dispatcher backed by the given rule repository.
    pub fn new(rule_repo: N) -> Self {
        Self { rule_repo }
    }

    /// Match an audit event against notification rules and return
    /// the event names and their recipient lists.
    ///
    /// Returns an empty vec if no rules match or the action/outcome
    /// does not map to any known notification event type.
    pub async fn dispatch(
        &self,
        tenant_id: Uuid,
        action: &str,
        outcome: &str,
        _actor_id: Option<Uuid>,
        _details: &str,
    ) -> AxiamResult<Vec<(String, Vec<String>)>> {
        let event_types = NotificationEventType::from_audit_action(action, outcome);

        let mut results = Vec::new();
        for event_type in event_types {
            let event_str = event_type.to_db_string();
            let rules = self.rule_repo.get_by_event(tenant_id, &event_str).await?;

            for rule in rules {
                if !rule.recipient_emails.is_empty() {
                    results.push((event_str.clone(), rule.recipient_emails));
                }
            }
        }

        // TODO(T19): Send actual emails via EmailService with
        // template resolution and org_id lookup.

        Ok(results)
    }
}

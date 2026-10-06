//! One `scim_delivery_failed` notification per target per hour (W5 F4 review,
//! T-418, D-73).
//!
//! The outbound dispatcher writes `scim_push.delivery_failed` for every
//! dead-lettered SCIM delivery, and the consumer's audit log is a
//! [`NotifyingAuditLog`], so a tenant's notification rule for
//! `scim_delivery_failed` sees each of those rows (D-58). A downstream that is
//! down past its retry budget, or that refuses AXIAM's credential, dead-letters
//! **every** reference — the whole tenant at the next reconciliation — and the
//! rule used to mail each recipient once per row.
//!
//! [`ScimFailureNotificationGate`] lets one row per target per
//! [`FAILURE_NOTIFICATION_INTERVAL_SECS`] through, claimed in the datastore
//! with a conditional write on `scim_target_state.failure_notified_at`
//! ([`ScimTargetStateRepository::claim_failure_notification`]), so replicas
//! agree. Every row is still appended, and `dead_lettered_total` still counts
//! every dead letter: the console's `state` shows the size of an outage the
//! one mail announces.
//!
//! [`scim_dead_letter_audit`] builds the wrapper the composition root gives the
//! `scim_push` consumer, so that the composition and its test are one thing.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_audit::{AuditEventSink, NotificationGate, NotifyingAuditLog};
use axiam_core::models::audit::CreateAuditLogEntry;
use axiam_core::models::scim_target::{
    FAILURE_NOTIFICATION_INTERVAL_SECS, SCIM_DEAD_LETTER_AUDIT_ACTION,
};
use axiam_core::repository::ScimTargetStateRepository;

/// The [`NotificationGate`] of the `scim_push` consumer's audit log.
pub struct ScimFailureNotificationGate<S> {
    states: S,
    interval_secs: i64,
}

impl<S> ScimFailureNotificationGate<S> {
    /// A gate over the targets' delivery state, one notification per target
    /// per [`FAILURE_NOTIFICATION_INTERVAL_SECS`].
    pub fn new(states: S) -> Self {
        Self {
            states,
            interval_secs: FAILURE_NOTIFICATION_INTERVAL_SECS,
        }
    }
}

impl<S: ScimTargetStateRepository + 'static> NotificationGate for ScimFailureNotificationGate<S> {
    fn admit<'a>(
        &'a self,
        entry: &'a CreateAuditLogEntry,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            // Only the dead letter is coalesced; any other notifiable row this
            // log ever writes goes through as it did.
            if entry.action != SCIM_DEAD_LETTER_AUDIT_ACTION {
                return true;
            }
            // The dispatcher's row names the target as its resource. One that
            // does not cannot be coalesced, and is not a dead letter this
            // dispatcher wrote: no notification.
            let Some(target_id) = entry.resource_id else {
                return false;
            };
            match self
                .states
                .claim_failure_notification(
                    entry.tenant_id,
                    target_id,
                    chrono::Utc::now(),
                    self.interval_secs,
                )
                .await
            {
                Ok(claimed) => claimed,
                Err(error) => {
                    // Fail closed into silence, not into a flood: the row is
                    // appended either way and `state` still counts it.
                    tracing::warn!(
                        %error,
                        tenant_id = %entry.tenant_id,
                        %target_id,
                        "the SCIM failure notification could not be claimed; not notifying"
                    );
                    false
                }
            }
        })
    }
}

/// The audit log the `scim_push` consumer writes through: every row appended
/// to `audit`, a dead letter handed to `sink` (the tenant's notification rules)
/// at most once per target per hour.
pub fn scim_dead_letter_audit<A, T, S>(
    audit: A,
    sink: Arc<dyn AuditEventSink>,
    tenants: T,
    states: S,
) -> NotifyingAuditLog<A, T>
where
    S: ScimTargetStateRepository + 'static,
{
    NotifyingAuditLog::new(
        audit,
        sink,
        tenants,
        Arc::new(ScimFailureNotificationGate::new(states)),
    )
}

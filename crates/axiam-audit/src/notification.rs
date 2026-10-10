//! Notification dispatcher — matches audit events to notification rules
//! and enqueues outbound mail messages for each matched recipient (T19.13).
//!
//! The dispatcher calls `mail_publisher.publish(...)` once per recipient of a
//! matched rule whose **window** the event opens (#551, T-117): of the events
//! of one kind that match one rule, the first in the rule's `window_minutes`
//! is mailed and the rest are counted, and the next mail says how many were
//! not sent. The window is claimed in the datastore, so replicas agree. On
//! publish error the error is logged and execution continues —
//! fire-and-forget (D-14).
//!
//! A replica writes the window once when it learns the window is open, not once
//! per event (R1W2-01): until the window it was told about ends, it counts
//! matching events in memory and hands the count back with one write at its
//! next claim or flush. Every replica writing every event of a burst into one
//! record is what serialized them all.

use axiam_core::error::AxiamResult;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::models::notification_rule::{NotificationEventType, NotificationWindowClaim};
use axiam_core::repository::{
    MailPublisher, NotificationRuleRepository, NotificationWindowRepository,
};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use uuid::Uuid;

/// A window's key: `(tenant, rule, event)`.
type WindowKey = (Uuid, Uuid, String);

/// What this replica knows of one window (R1W2-01).
#[derive(Debug, Default)]
struct LocalWindow {
    /// When the window this replica was last told about ends; `None` when it
    /// does not know.
    open_until: Option<DateTime<Utc>>,
    /// Events this replica counted and has not yet written to the window.
    uncounted: u64,
}

/// Dispatches audit events to matching notification rules by enqueuing
/// one `OutboundMailMessage(Notification)` per matched recipient, at most
/// once per rule, event and window.
pub struct NotificationDispatcher<N: NotificationRuleRepository, W: NotificationWindowRepository> {
    rule_repo: N,
    windows: W,
    /// The windows this replica knows to be open, and its unwritten counts.
    /// Emptied by every [`Self::flush_local_counts`], so it holds at most the
    /// windows claimed since the last one.
    local: Mutex<HashMap<WindowKey, LocalWindow>>,
}

impl<N: NotificationRuleRepository, W: NotificationWindowRepository> NotificationDispatcher<N, W> {
    /// Create a new dispatcher backed by the given rule repository and the
    /// rules' notification windows. There is deliberately no constructor
    /// without the windows: a rule for an event an attacker can raise at will
    /// would mail its recipients once per event (T-117).
    pub fn new(rule_repo: N, windows: W) -> Self {
        Self {
            rule_repo,
            windows,
            local: Mutex::new(HashMap::new()),
        }
    }

    fn local(&self) -> MutexGuard<'_, HashMap<WindowKey, LocalWindow>> {
        // The map holds counts, not invariants a panicking holder could have
        // broken half-way: keep using it.
        self.local
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Write every count this replica holds in memory to its window, and forget
    /// the windows it knew to be open, so that the next event of each claims
    /// again and learns the window as it now stands.
    ///
    /// The audit middleware's sink task calls this every
    /// [`crate::middleware::SINK_FLUSH_INTERVAL`] and when it stops, so a
    /// replica that sees no further event still delivers its count to the next
    /// mail, and a burst costs each replica at most two writes per window and
    /// interval: this one and the next claim. A count that cannot be written is
    /// kept for the next flush.
    pub async fn flush_local_counts(&self) {
        let held = std::mem::take(&mut *self.local());
        for ((tenant_id, rule_id, event), window) in held {
            if window.uncounted == 0 {
                continue;
            }
            if let Err(e) = self
                .windows
                .add_uncounted(tenant_id, rule_id, &event, window.uncounted)
                .await
            {
                tracing::warn!(
                    error = %e,
                    event = %event,
                    rule_id = %rule_id,
                    uncounted = window.uncounted,
                    "a notification window's count could not be written; kept for the next flush"
                );
                self.local()
                    .entry((tenant_id, rule_id, event))
                    .or_default()
                    .uncounted += window.uncounted;
            }
        }
    }

    /// Claim the window of `(tenant_id, rule_id, event)` for one event. `Some`
    /// with the count to report when this event opens it; `None` when it was
    /// counted — in the datastore, or here in memory — and is not mailed.
    async fn claim_window(
        &self,
        tenant_id: Uuid,
        rule_id: Uuid,
        event: &str,
        window_secs: i64,
    ) -> Option<u64> {
        let now = Utc::now();
        let key = (tenant_id, rule_id, event.to_string());

        // Inside a window this replica knows to be open: count it here, write
        // nothing. Past the end of the one it knew, take what was counted in
        // it, for the write below. (Not knowing — a contended or failed claim
        // — keeps the count for the flush: that window is still open.)
        let carried = {
            let mut local = self.local();
            let window = local.entry(key.clone()).or_default();
            match window.open_until.take() {
                Some(end) if now < end => {
                    window.open_until = Some(end);
                    window.uncounted += 1;
                    return None;
                }
                Some(_) => std::mem::take(&mut window.uncounted),
                None => 0,
            }
        };

        // The window this replica knew has ended: its count goes to the
        // datastore before the claim, so the mail that opens the next window
        // reports it.
        if carried > 0
            && let Err(e) = self
                .windows
                .add_uncounted(tenant_id, rule_id, event, carried)
                .await
        {
            tracing::warn!(
                error = %e,
                event = %event,
                rule_id = %rule_id,
                "a notification window's count could not be written; kept for the next flush"
            );
            self.local().entry(key.clone()).or_default().uncounted += carried;
        }

        let claim = self
            .windows
            .claim(tenant_id, rule_id, event, now, window_secs)
            .await;
        let mut local = self.local();
        let window = local.entry(key).or_default();
        match claim {
            Ok(NotificationWindowClaim::Opened { suppressed }) => {
                window.open_until = Some(now + Duration::seconds(window_secs));
                Some(suppressed)
            }
            Ok(NotificationWindowClaim::Counted { open_until }) => {
                window.open_until = Some(open_until);
                tracing::debug!(
                    event = %event,
                    rule_id = %rule_id,
                    "notification window open; event counted, not mailed"
                );
                None
            }
            // Another claimant wrote the window in this instant, so it is open;
            // nothing was written for this event, so it is counted here.
            Ok(NotificationWindowClaim::Contended) => {
                window.uncounted += 1;
                tracing::debug!(
                    event = %event,
                    rule_id = %rule_id,
                    "notification window contended; event counted in memory, not mailed"
                );
                None
            }
            // Silence, not a flood (D-73); the event is still counted, here.
            Err(e) => {
                window.uncounted += 1;
                tracing::warn!(
                    error = %e,
                    event = %event,
                    rule_id = %rule_id,
                    "the notification window could not be claimed; not notifying"
                );
                None
            }
        }
    }

    /// Match an audit event against notification rules and enqueue one
    /// `OutboundMailMessage` per recipient of each matched rule whose window
    /// this event opens.
    ///
    /// `tenant_id` and `org_id` are used to populate the mail message
    /// context so the consumer can resolve the correct email config.
    ///
    /// Returns `Ok(enqueued_count)` where count is the number of messages
    /// successfully handed to `mail_publisher`.  Publish errors are logged
    /// and do **not** propagate — callers get a successful result even if
    /// some (or all) enqueue calls fail.
    ///
    /// Returns `Ok(0)` if no rules match, the action/outcome does not map
    /// to any known notification event type, or every matched rule's window
    /// was already open (the event was counted instead).
    ///
    /// # The window (#551, T-117)
    ///
    /// For each matched rule the window of `(tenant, rule, event)` is claimed
    /// before anything is published. An event that opens it is mailed, and
    /// the mail carries `suppressed_count`: the events the window before it
    /// counted and did not mail. An event inside an open window is counted
    /// and not mailed. A claim that fails is not mailed either — silence, not
    /// a flood, as the background gate decides (D-73); the audit row exists
    /// either way.
    ///
    /// Inside a window this replica already knows to be open, the event is
    /// counted in memory and nothing is written (R1W2-01); so is an event whose
    /// claim kept losing a write conflict, or failed. Those counts reach the
    /// datastore at this replica's next claim of the window or its next
    /// [`Self::flush_local_counts`], and from there the next mail. A count that
    /// arrives after another replica has already opened the next window is
    /// reported by the mail after that one: late, never lost while the process
    /// runs.
    ///
    /// An event raised by an AXIAM background process
    /// ([`NotificationEventType::is_system_event`]) is not windowed here: its
    /// producer's [`NotificationGate`] already coalesced it (one
    /// `scim_delivery_failed` per target per hour, D-73), and windowing it again
    /// per rule would fold a second target's outage into the first's.
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

        // Built once for the whole dispatch: it is the same for every rule and
        // every recipient, and it is the one place `username` is decided.
        //
        // `username` is present ONLY when there is no actor to name. The mail
        // consumer resolves it from `user_id` and its answer is the better one,
        // but a message's own context is overlaid on top of what the consumer
        // resolved — so supplying a placeholder unconditionally would mask every
        // real actor. It cannot be a JSON `null` either: the consumer
        // stringifies non-string values, so a null would arrive as the literal
        // word "null". The key has to be genuinely absent, which is why this is
        // assembled rather than written as one `json!` literal.
        //
        // Supplying nothing at all would instead leave the consumer's generic
        // "unknown" on the events an administrator most wants alerting on — a
        // failed login, a lockout — which have no authenticated actor by
        // definition.
        // `event` and the window's two keys are not here: they vary per rule,
        // and are inserted into the clone below.
        let mut context = serde_json::Map::new();
        context.insert("details".into(), details.into());
        context.insert("action".into(), action.into());
        context.insert("outcome".into(), outcome.into());
        if actor_id.is_none() {
            // An event AXIAM itself raises (a dead-lettered delivery) has no
            // caller at all, authenticated or not; saying so would send an
            // administrator looking for an intruder.
            let who = if event_types.iter().all(|e| e.is_system_event()) {
                "AXIAM (an automated process)"
            } else {
                "an unauthenticated caller"
            };
            context.insert("username".into(), who.into());
        }

        let mut enqueued = 0usize;
        for rule in rules {
            if rule.recipient_emails.is_empty() {
                continue;
            }
            // Find the first matching event type for this rule.
            let Some(matched) = event_types
                .iter()
                .copied()
                .find(|et| rule.events.contains(et))
            else {
                continue;
            };
            let event_name = matched.to_db_string();

            let (suppressed, window_note) = if matched.is_system_event() {
                (
                    0,
                    "Raised by an AXIAM background process, which limits how often it \
                     alerts on its own; the audit log has every row."
                        .to_string(),
                )
            } else {
                let window_secs = i64::from(rule.window_minutes) * 60;
                let Some(suppressed) = self
                    .claim_window(tenant_id, rule.id, &event_name, window_secs)
                    .await
                else {
                    continue;
                };
                (
                    suppressed,
                    window_note(&event_name, rule.window_minutes, suppressed),
                )
            };

            let mut context = context.clone();
            context.insert("event".into(), event_name.clone().into());
            context.insert("suppressed_count".into(), suppressed.to_string().into());
            context.insert("window_note".into(), window_note.into());
            let template_context = serde_json::Value::Object(context);

            // Enqueue one OutboundMailMessage per recipient.
            for recipient in &rule.recipient_emails {
                let msg = OutboundMailMessage {
                    mail_type: MailType::Notification,
                    tenant_id,
                    org_id,
                    user_id: actor_id.unwrap_or(Uuid::nil()),
                    to_address: recipient.clone(),
                    template_context: template_context.clone(),
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

/// The sentence a windowed mail carries about its window (#551): how often the
/// rule mails this event and, when the window before this one counted any, how
/// many were not mailed.
fn window_note(event: &str, window_minutes: u32, suppressed: u64) -> String {
    let every = if window_minutes == 1 {
        "minute".to_string()
    } else {
        format!("{window_minutes} minutes")
    };
    let mut note = format!(
        "This rule mails {event} at most once every {every}; further {event} events \
         in that time are counted, not mailed, and the next alert reports them."
    );
    if suppressed > 0 {
        note.push_str(&format!(
            " Not mailed in the previous window: {suppressed} {event} event{}.",
            if suppressed == 1 { "" } else { "s" }
        ));
    }
    note
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
/// `AuditMiddleware::spawn_with_sink` can drive it on a task of its own, off
/// the request path and off the audit worker (R1W2-01).
pub struct NotificationSink<
    N: NotificationRuleRepository,
    W: NotificationWindowRepository,
    P: MailPublisher,
> {
    dispatcher: NotificationDispatcher<N, W>,
    mail_publisher: P,
}

impl<N: NotificationRuleRepository, W: NotificationWindowRepository, P: MailPublisher>
    NotificationSink<N, W, P>
{
    /// Build a sink over a rule repository, the rules' notification windows
    /// (#551) and a mail publisher.
    pub fn new(rule_repo: N, windows: W, mail_publisher: P) -> Self {
        Self {
            dispatcher: NotificationDispatcher::new(rule_repo, windows),
            mail_publisher,
        }
    }
}

impl<N: NotificationRuleRepository, W: NotificationWindowRepository, P: MailPublisher>
    NotificationSink<N, W, P>
{
    /// Write the window counts this replica holds in memory (R1W2-01) — see
    /// [`NotificationDispatcher::flush_local_counts`].
    pub async fn flush_local_counts(&self) {
        self.dispatcher.flush_local_counts().await;
    }
}

impl<N, W, P> crate::middleware::AuditEventSink for NotificationSink<N, W, P>
where
    N: NotificationRuleRepository + 'static,
    W: NotificationWindowRepository + 'static,
    P: MailPublisher + 'static,
{
    /// Only a row attributed to a tenant whose action and outcome name a
    /// notification event: no rule could match any other, so the rest never
    /// take a place in the sink's queue.
    fn wants(&self, event: &crate::middleware::AuditEvent) -> bool {
        let entry = &event.entry;
        !entry.tenant_id.is_nil()
            && !NotificationEventType::from_audit_action(
                &entry.action,
                &format!("{:?}", entry.outcome),
            )
            .is_empty()
    }

    fn flush(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(self.flush_local_counts())
    }

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
// Audit rows that are not HTTP requests
// ---------------------------------------------------------------------------

/// An [`AuditLogRepository`] that lets the notification rules see the rows it
/// appends.
///
/// [`NotificationSink`] is driven by [`crate::AuditMiddleware`]'s worker, which
/// only ever sees HTTP requests. A row a background process writes straight to
/// the repository — the outbound dispatcher's `scim_push.delivery_failed`, the
/// record of a dead letter — never reaches it, so a rule an administrator
/// configured for that event (T19.13's mechanism, D-58: no second channel)
/// would match nothing in a running server. The consumer that writes it is
/// given this wrapper instead of the bare repository.
///
/// Only a row that **maps to a notification event** costs anything beyond the
/// append: the [`NotificationGate`] is asked whether it may notify now, the
/// tenant's organization is looked up (mail needs it to resolve the email
/// configuration) and the sink is called, after the append has succeeded and
/// with its failures swallowed, exactly as the middleware's worker does. Every
/// other method is the inner repository's.
///
/// **Every row is appended; only the notification is gated.** A background
/// process can write the same notifiable row thousands of times in a minute —
/// one dead letter per reference while a downstream is down — and a rule
/// mails each recipient once per row it sees (W5 F4 review, T-418). The gate
/// is how a wrapper's owner coalesces them; there is deliberately no
/// constructor without one.
pub struct NotifyingAuditLog<A, T> {
    inner: A,
    sink: std::sync::Arc<dyn crate::middleware::AuditEventSink>,
    tenants: T,
    gate: std::sync::Arc<dyn NotificationGate>,
}

impl<A, T> NotifyingAuditLog<A, T> {
    /// Wrap `inner`; `tenants` resolves a row's organization, and `gate`
    /// decides which notifiable rows reach `sink`.
    pub fn new(
        inner: A,
        sink: std::sync::Arc<dyn crate::middleware::AuditEventSink>,
        tenants: T,
        gate: std::sync::Arc<dyn NotificationGate>,
    ) -> Self {
        Self {
            inner,
            sink,
            tenants,
            gate,
        }
    }
}

/// Decides whether a notifiable audit row a background process appended may
/// reach the notification rules **now** (W5 F4 review, T-418, D-73).
///
/// Called only for a row that maps to a notification event, after it was
/// appended. `false` drops the notification, never the row. An implementation
/// must not fail open into a flood: when it cannot decide, it should say
/// `false` and log once.
pub trait NotificationGate: Send + Sync {
    /// Whether `entry` may be handed to the notification sink.
    fn admit<'a>(
        &'a self,
        entry: &'a axiam_core::models::audit::CreateAuditLogEntry,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>>;
}

impl<A, T> axiam_core::repository::AuditLogRepository for NotifyingAuditLog<A, T>
where
    A: axiam_core::repository::AuditLogRepository,
    T: axiam_core::repository::TenantRepository,
{
    async fn append(
        &self,
        input: axiam_core::models::audit::CreateAuditLogEntry,
    ) -> AxiamResult<axiam_core::models::audit::AuditLogEntry> {
        let appended = self.inner.append(input.clone()).await?;
        let outcome = format!("{:?}", input.outcome);
        let notifiable = !input.tenant_id.is_nil()
            && !NotificationEventType::from_audit_action(&input.action, &outcome).is_empty();
        if notifiable && self.gate.admit(&input).await {
            let org_id = match self.tenants.get_by_id(input.tenant_id).await {
                Ok(tenant) => tenant.organization_id,
                Err(error) => {
                    tracing::warn!(
                        %error,
                        tenant_id = %input.tenant_id,
                        "a notifiable audit row's organization could not be resolved"
                    );
                    Uuid::nil()
                }
            };
            self.sink
                .on_event(&crate::middleware::AuditEvent {
                    entry: input,
                    org_id,
                })
                .await;
        }
        Ok(appended)
    }

    fn list(
        &self,
        tenant_id: Uuid,
        filter: axiam_core::repository::AuditLogFilter,
        pagination: axiam_core::repository::Pagination,
    ) -> impl std::future::Future<
        Output = AxiamResult<
            axiam_core::repository::PaginatedResult<axiam_core::models::audit::AuditLogEntry>,
        >,
    > + Send {
        self.inner.list(tenant_id, filter, pagination)
    }

    fn list_system(
        &self,
        filter: axiam_core::repository::AuditLogFilter,
        pagination: axiam_core::repository::Pagination,
    ) -> impl std::future::Future<
        Output = AxiamResult<
            axiam_core::repository::PaginatedResult<axiam_core::models::audit::AuditLogEntry>,
        >,
    > + Send {
        self.inner.list_system(filter, pagination)
    }

    fn get_by_ids(
        &self,
        tenant_id: Uuid,
        ids: &[Uuid],
    ) -> impl std::future::Future<
        Output = AxiamResult<Vec<axiam_core::models::audit::AuditLogEntry>>,
    > + Send {
        self.inner.get_by_ids(tenant_id, ids)
    }

    fn pseudonymize_actor(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        pseudonym: &str,
    ) -> impl std::future::Future<Output = AxiamResult<u64>> + Send {
        self.inner.pseudonymize_actor(tenant_id, user_id, pseudonym)
    }

    fn prune_older_than(
        &self,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> impl std::future::Future<Output = AxiamResult<u64>> + Send {
        self.inner.prune_older_than(cutoff)
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
        MailPublisher, NotificationRuleRepository, NotificationWindowRepository, PaginatedResult,
        Pagination,
    };
    use chrono::DateTime;
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
    // In-memory notification windows (the datastore's are tested in
    // `axiam-db` and, end to end, in `axiam-server`'s
    // `notification_window_test`)
    // -----------------------------------------------------------------------

    /// `(tenant, rule, event)` → when the window opened, events counted in it.
    type Windows = std::collections::HashMap<(Uuid, Uuid, String), (DateTime<Utc>, u64)>;

    /// The windows, and how many writes — claims and added counts — they took.
    #[derive(Clone, Default)]
    struct MemWindows {
        open: Arc<Mutex<Windows>>,
        claims: Arc<std::sync::atomic::AtomicUsize>,
        adds: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MemWindows {
        fn claims(&self) -> usize {
            self.claims.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn adds(&self) -> usize {
            self.adds.load(std::sync::atomic::Ordering::SeqCst)
        }

        /// Move every window back by `secs`, as that much time passing would.
        fn age(&self, secs: i64) {
            for (opened_at, _) in self.open.lock().unwrap().values_mut() {
                *opened_at -= chrono::Duration::seconds(secs);
            }
        }
    }

    impl NotificationWindowRepository for MemWindows {
        async fn claim(
            &self,
            tenant_id: Uuid,
            rule_id: Uuid,
            event: &str,
            now: DateTime<Utc>,
            window_secs: i64,
        ) -> AxiamResult<NotificationWindowClaim> {
            self.claims
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            let key = (tenant_id, rule_id, event.to_string());
            let window = chrono::Duration::seconds(window_secs);
            match open.get_mut(&key) {
                Some((opened_at, suppressed)) if *opened_at > now - window => {
                    *suppressed += 1;
                    Ok(NotificationWindowClaim::Counted {
                        open_until: *opened_at + window,
                    })
                }
                other => {
                    let carried = other.map_or(0, |(_, suppressed)| *suppressed);
                    open.insert(key, (now, 0));
                    Ok(NotificationWindowClaim::Opened {
                        suppressed: carried,
                    })
                }
            }
        }

        async fn add_uncounted(
            &self,
            tenant_id: Uuid,
            rule_id: Uuid,
            event: &str,
            count: u64,
        ) -> AxiamResult<()> {
            self.adds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some((_, suppressed)) =
                self.open
                    .lock()
                    .unwrap()
                    .get_mut(&(tenant_id, rule_id, event.to_string()))
            {
                *suppressed += count;
            }
            Ok(())
        }
    }

    /// A window record every claim loses to another claimant's write.
    #[derive(Clone, Default)]
    struct ContendedWindows {
        added: Arc<Mutex<Vec<u64>>>,
    }

    impl NotificationWindowRepository for ContendedWindows {
        async fn claim(
            &self,
            _tenant_id: Uuid,
            _rule_id: Uuid,
            _event: &str,
            _now: DateTime<Utc>,
            _window_secs: i64,
        ) -> AxiamResult<NotificationWindowClaim> {
            Ok(NotificationWindowClaim::Contended)
        }

        async fn add_uncounted(
            &self,
            _tenant_id: Uuid,
            _rule_id: Uuid,
            _event: &str,
            count: u64,
        ) -> AxiamResult<()> {
            self.added.lock().unwrap().push(count);
            Ok(())
        }
    }

    /// A datastore that cannot be reached.
    struct FailingWindows;

    impl NotificationWindowRepository for FailingWindows {
        async fn claim(
            &self,
            _tenant_id: Uuid,
            _rule_id: Uuid,
            _event: &str,
            _now: DateTime<Utc>,
            _window_secs: i64,
        ) -> AxiamResult<NotificationWindowClaim> {
            Err(axiam_core::error::AxiamError::Internal(
                "datastore unavailable".into(),
            ))
        }

        async fn add_uncounted(
            &self,
            _tenant_id: Uuid,
            _rule_id: Uuid,
            _event: &str,
            _count: u64,
        ) -> AxiamResult<()> {
            Err(axiam_core::error::AxiamError::Internal(
                "datastore unavailable".into(),
            ))
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
            window_minutes: 15,
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
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());
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
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());
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
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());
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
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());
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
            window_minutes: 15,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let repo = MockRuleRepo::new(vec![rule]);
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());
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
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());
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
        let sink = NotificationSink::new(repo, MemWindows::default(), publisher.clone());

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
        let sink = NotificationSink::new(repo, MemWindows::default(), publisher.clone());

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
        let sink = NotificationSink::new(repo, MemWindows::default(), publisher.clone());

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
        let sink = NotificationSink::new(repo, MemWindows::default(), FailingPublisher);

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
        let sink = NotificationSink::new(repo, MemWindows::default(), publisher.clone());

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

    #[tokio::test]
    async fn an_unauthenticated_actor_is_named_rather_than_left_unknown() {
        // A failed login has no authenticated actor by definition, and it is
        // exactly the event an administrator most wants alerting on. The mail
        // consumer's generic fallback would render "Actor: unknown"; saying what
        // actually happened is more use to the reader.
        let repo = MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]);
        let publisher = RecordingPublisher::new();
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());

        dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                None, // no actor
                "details",
                &publisher,
            )
            .await
            .unwrap();

        let msg = publisher.messages().into_iter().next().unwrap();
        assert_eq!(
            msg.template_context["username"].as_str(),
            Some("an unauthenticated caller")
        );
    }

    #[tokio::test]
    async fn a_known_actor_is_left_for_the_consumer_to_resolve() {
        // The complement. The consumer resolves `username` from `user_id` and
        // its value is the better one, but the message's own context is overlaid
        // on top — so the placeholder has to be dropped when there is a real
        // actor, or it would win and the alert would name nobody.
        let repo = MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]);
        let publisher = RecordingPublisher::new();
        let dispatcher = NotificationDispatcher::new(repo, MemWindows::default());

        let actor = Uuid::new_v4();
        dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                Some(actor),
                "details",
                &publisher,
            )
            .await
            .unwrap();

        let msg = publisher.messages().into_iter().next().unwrap();
        // Genuinely absent, not null. The consumer stringifies non-string
        // values, so a null would arrive as the literal word "null" and mask the
        // name it resolved from `user_id`.
        assert!(
            msg.template_context
                .as_object()
                .unwrap()
                .get("username")
                .is_none(),
            "a resolvable actor must be left to the consumer, not overlaid"
        );
        assert_eq!(msg.user_id, actor);
    }

    /// G-6 (D-58): a rule for `scim_delivery_failed` matches the row the outbound
    /// dispatcher writes on a dead letter, and mails every recipient. The
    /// actor line says an AXIAM process raised it, not "an unauthenticated
    /// caller".
    #[tokio::test]
    async fn a_scim_dead_letter_mails_every_recipient_of_a_matching_rule() {
        let mut rule = make_rule(vec!["soc@example.com", "oncall@example.com"]);
        rule.events = vec![NotificationEventType::ScimDeliveryFailed];
        let publisher = RecordingPublisher::new();
        let dispatcher =
            NotificationDispatcher::new(MockRuleRepo::new(vec![rule]), MemWindows::default());

        let count = dispatcher
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "scim_push.delivery_failed",
                "Failure",
                None,
                "scim_push.delivery_failed (Failure)",
                &publisher,
            )
            .await
            .unwrap();

        assert_eq!(count, 2);
        let msgs = publisher.messages();
        assert!(
            msgs.iter()
                .all(|m| matches!(m.mail_type, MailType::Notification))
        );
        let context = msgs[0].template_context.as_object().unwrap();
        assert_eq!(context["event"], "scim_delivery_failed");
        assert_eq!(context["action"], "scim_push.delivery_failed");
        assert_eq!(context["username"], "AXIAM (an automated process)");

        // A rule that did not ask for the event is not mailed.
        let other = NotificationDispatcher::new(
            MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]),
            MemWindows::default(),
        );
        let quiet = RecordingPublisher::new();
        other
            .dispatch(
                Uuid::new_v4(),
                Uuid::new_v4(),
                "scim_push.delivery_failed",
                "Failure",
                None,
                "",
                &quiet,
            )
            .await
            .unwrap();
        // The mock returns every rule; the dispatcher's own match drops it.
        assert_eq!(quiet.count(), 0);
    }

    // -----------------------------------------------------------------------
    // The notification window (#551, T-117)
    // -----------------------------------------------------------------------

    async fn login_failure(
        dispatcher: &NotificationDispatcher<MockRuleRepo, impl NotificationWindowRepository>,
        tenant_id: Uuid,
        publisher: &RecordingPublisher,
    ) -> usize {
        dispatcher
            .dispatch(
                tenant_id,
                Uuid::new_v4(),
                "POST /api/v1/auth/login",
                "Failure",
                None,
                "POST /api/v1/auth/login (Failure)",
                publisher,
            )
            .await
            .unwrap()
    }

    /// The first event of a window is mailed, with a count of zero and the
    /// sentence that says how the rule batches; the rest of the window is
    /// counted, not mailed.
    #[tokio::test]
    async fn the_first_event_of_a_window_is_mailed_and_the_rest_are_counted() {
        let dispatcher = NotificationDispatcher::new(
            MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]),
            MemWindows::default(),
        );
        let publisher = RecordingPublisher::new();
        let tenant_id = Uuid::new_v4();

        assert_eq!(login_failure(&dispatcher, tenant_id, &publisher).await, 1);
        for _ in 0..9 {
            assert_eq!(login_failure(&dispatcher, tenant_id, &publisher).await, 0);
        }
        assert_eq!(publisher.count(), 1);
        let context = publisher.messages()[0].template_context.clone();
        assert_eq!(context["suppressed_count"], "0");
        assert!(
            context["window_note"]
                .as_str()
                .unwrap()
                .contains("at most once every 15 minutes")
        );
    }

    /// A window that cannot be claimed mails nobody: silence, not a flood
    /// (the D-73 rule). The audit row was written before the sink ran.
    #[tokio::test]
    async fn a_window_that_cannot_be_claimed_mails_nobody() {
        let dispatcher = NotificationDispatcher::new(
            MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]),
            FailingWindows,
        );
        let publisher = RecordingPublisher::new();
        assert_eq!(
            login_failure(&dispatcher, Uuid::new_v4(), &publisher).await,
            0
        );
        assert_eq!(publisher.count(), 0);
    }

    /// A background process's event is not windowed again: its producer's
    /// gate coalesced it per target (D-73), and a rule window would fold a
    /// second target's outage into the first's. Even a store that cannot be
    /// reached does not stop it.
    #[tokio::test]
    async fn a_system_event_keeps_its_own_gate_and_is_not_windowed() {
        let mut rule = make_rule(vec!["soc@example.com"]);
        rule.events = vec![NotificationEventType::ScimDeliveryFailed];
        let dispatcher = NotificationDispatcher::new(MockRuleRepo::new(vec![rule]), FailingWindows);
        let publisher = RecordingPublisher::new();
        for _ in 0..2 {
            dispatcher
                .dispatch(
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                    "scim_push.delivery_failed",
                    "Failure",
                    None,
                    "scim_push.delivery_failed (Failure)",
                    &publisher,
                )
                .await
                .unwrap();
        }
        assert_eq!(publisher.count(), 2);
        let context = publisher.messages()[0].template_context.clone();
        assert_eq!(context["suppressed_count"], "0");
        assert!(
            context["window_note"]
                .as_str()
                .unwrap()
                .contains("background process")
        );
    }

    /// R1W2-01: eight replicas sharing one window, handed a burst between
    /// them, write it once each — not once per event — and the next window's
    /// mail still carries every event of the burst but the one mailed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn eight_replicas_write_a_window_once_each_not_once_per_event() {
        let windows = MemWindows::default();
        let rule = make_rule(vec!["soc@example.com"]);
        let tenant_id = Uuid::new_v4();
        let publisher = RecordingPublisher::new();
        let replicas: Vec<_> = (0..8)
            .map(|_| {
                Arc::new(NotificationDispatcher::new(
                    MockRuleRepo::new(vec![rule.clone()]),
                    windows.clone(),
                ))
            })
            .collect();

        let mut burst = tokio::task::JoinSet::new();
        for replica in &replicas {
            let (replica, publisher) = (Arc::clone(replica), publisher.clone());
            burst.spawn(async move {
                for _ in 0..125 {
                    login_failure(&replica, tenant_id, &publisher).await;
                }
            });
        }
        burst.join_all().await;
        assert_eq!(publisher.count(), 1, "the window is opened once");
        assert_eq!(windows.claims(), 8, "one claim per replica, not per event");

        // Each replica's flush writes its count once.
        for replica in &replicas {
            replica.flush_local_counts().await;
        }
        assert_eq!(windows.adds(), 8);

        windows.age(15 * 60);
        login_failure(&replicas[0], tenant_id, &publisher).await;
        let sent = publisher.messages();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].template_context["suppressed_count"], "999");
    }

    /// R1W2-01: when the window a replica knows has ended, the next event hands
    /// the replica's count back before it claims, so the mail that opens the
    /// next window reports it — with no flush in between.
    #[tokio::test]
    async fn a_count_kept_in_memory_reaches_the_mail_that_opens_the_next_window() {
        let windows = MemWindows::default();
        let rule = make_rule(vec!["soc@example.com"]);
        let rule_id = rule.id;
        let dispatcher =
            NotificationDispatcher::new(MockRuleRepo::new(vec![rule]), windows.clone());
        let publisher = RecordingPublisher::new();
        let tenant_id = Uuid::new_v4();

        for _ in 0..10 {
            login_failure(&dispatcher, tenant_id, &publisher).await;
        }
        assert_eq!(windows.claims(), 1, "nine events counted in memory");

        // The window ends, in the datastore and for this replica.
        windows.age(15 * 60);
        dispatcher
            .local()
            .get_mut(&(tenant_id, rule_id, "login_failure".to_string()))
            .expect("the replica knows the window")
            .open_until = Some(Utc::now());
        login_failure(&dispatcher, tenant_id, &publisher).await;

        let sent = publisher.messages();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].template_context["suppressed_count"], "9");
    }

    /// R1W2-01: a claim that keeps losing a write conflict mails nobody and
    /// writes nothing; the replica counts the event and hands the count back
    /// at its flush.
    #[tokio::test]
    async fn a_contended_claim_is_counted_in_memory_and_written_at_the_flush() {
        let windows = ContendedWindows::default();
        let dispatcher = NotificationDispatcher::new(
            MockRuleRepo::new(vec![make_rule(vec!["soc@example.com"])]),
            windows.clone(),
        );
        let publisher = RecordingPublisher::new();
        let tenant_id = Uuid::new_v4();
        for _ in 0..5 {
            assert_eq!(login_failure(&dispatcher, tenant_id, &publisher).await, 0);
        }
        assert_eq!(publisher.count(), 0);
        assert!(windows.added.lock().unwrap().is_empty());
        dispatcher.flush_local_counts().await;
        assert_eq!(
            *windows.added.lock().unwrap(),
            vec![5],
            "one write for all five"
        );
    }

    #[test]
    fn the_window_note_names_the_count_only_when_there_is_one() {
        let quiet = window_note("login_failure", 15, 0);
        assert!(quiet.contains("at most once every 15 minutes"));
        assert!(!quiet.contains("previous window"));
        assert!(
            window_note("login_failure", 1, 1)
                .ends_with("Not mailed in the previous window: 1 login_failure event.")
        );
        assert!(
            window_note("login_failure", 60, 99)
                .ends_with("Not mailed in the previous window: 99 login_failure events.")
        );
        assert!(window_note("login_failure", 1, 0).contains("at most once every minute"));
    }
}

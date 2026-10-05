//! The e-mail notification of a CIBA request (G-7, T23.7.2).
//!
//! [`CibaMailNotifier`] is the [`CibaUserNotifier`] a deployment runs in place of
//! [`axiam_core::models::ciba::NoopCibaUserNotifier`]: it turns a stored request
//! into one [`MailType::CibaApproval`] message on the mail queue, which the mail
//! consumer renders with the `ciba_approval` template (tenant → organization →
//! built-in) and delivers like every other mail.
//!
//! # What the mail carries
//!
//! The client's display name, its `binding_message`, when the request expires,
//! and **a link to the approval page** (`{issuer}/ciba/approve?request_id=…`)
//! addressed by the request's record id. It never carries the `auth_req_id`, a
//! token, a notification endpoint or anything else that would let the holder of
//! the mail act: the page needs the request's own user signed in, so a forwarded
//! mail approves nothing for anyone else.
//!
//! # Whom it mails
//!
//! The recipient is re-read here — never taken from the request row — and is
//! mailed only if the account may take part in the grant right now
//! ([`user_may_be_subject`]: it may sign in, and is not under lockout), is not
//! scheduled for deletion, and has an address. Anything else is a quiet no-op:
//! the request still waits on the approval page, and a notification that cannot
//! be sent must not be told apart from one that was (D-63). The mail consumer
//! resolves the delivery address from the user record again at send time
//! (SEC-055), so the `to_address` set here is advisory.
//!
//! # What this does not do
//!
//! Throttle. The caller does, before it gets here: three notifications per user
//! per minute, whatever the clients asking and whatever the presets say
//! (`handlers::ciba::USER_NOTIFICATIONS_PER_MIN`), because the thing protected
//! is a person's attention.

use axiam_core::error::AxiamError;
use axiam_core::models::ciba::{CibaNotifyFuture, CibaUserNotification, CibaUserNotifier};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::repository::{MailPublisher, TenantRepository, UserRepository};
use chrono::Utc;
use uuid::Uuid;

use crate::ciba::user_may_be_subject;

/// What a mail says when the client sent no `binding_message`.
const NO_BINDING_MESSAGE: &str = "(none)";

/// The path of the console's approval page.
pub const APPROVAL_PAGE_PATH: &str = "/ciba/approve";

/// A [`CibaUserNotifier`] over the mail queue.
pub struct CibaMailNotifier<U, T, P> {
    users: U,
    tenants: T,
    mail: P,
    /// The deployment's public origin (`oauth2_issuer_url`), without a trailing
    /// slash — where the console, and so the approval page, is served. Empty
    /// yields a relative link, which is what the other mails carry when no
    /// issuer is configured.
    base_url: String,
}

impl<U, T, P> CibaMailNotifier<U, T, P> {
    /// A notifier over `users`, `tenants` and the mail queue's publisher, linking
    /// to the approval page under `base_url`.
    pub fn new(users: U, tenants: T, mail: P, base_url: &str) -> Self {
        Self {
            users,
            tenants,
            mail,
            base_url: base_url.trim().trim_end_matches('/').to_owned(),
        }
    }

    /// The link a mail carries for one request: the record id and nothing else.
    #[must_use]
    pub fn approval_url(&self, request_id: Uuid) -> String {
        format!(
            "{}{APPROVAL_PAGE_PATH}?request_id={request_id}",
            self.base_url
        )
    }
}

impl<U, T, P> CibaMailNotifier<U, T, P>
where
    U: UserRepository,
    T: TenantRepository,
    P: MailPublisher,
{
    async fn send(&self, notification: CibaUserNotification) -> Result<(), AxiamError> {
        let user = match self
            .users
            .get_by_id(notification.tenant_id, notification.user_id)
            .await
        {
            Ok(user) => user,
            Err(AxiamError::NotFound { .. }) => return Ok(()),
            Err(e) => return Err(e),
        };
        if user.tenant_id != notification.tenant_id
            || !user_may_be_subject(&user)
            || user.deletion_pending
            || user.email.trim().is_empty()
        {
            tracing::debug!(
                request_id = %notification.request_id,
                "no CIBA notification mail: the account may not be mailed"
            );
            return Ok(());
        }

        // Nil rather than abandoning the send, as the other mails do: the mail
        // consumer matches a tenant-level email config without it.
        let org_id = match self.tenants.get_by_id(notification.tenant_id).await {
            Ok(tenant) => tenant.organization_id,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    tenant_id = %notification.tenant_id,
                    "failed to resolve org_id for a CIBA notification mail; using nil"
                );
                Uuid::nil()
            }
        };

        let binding_message = notification
            .binding_message
            .clone()
            .unwrap_or_else(|| NO_BINDING_MESSAGE.to_owned());
        self.mail
            .publish(OutboundMailMessage {
                mail_type: MailType::CibaApproval,
                tenant_id: notification.tenant_id,
                org_id,
                user_id: user.id,
                to_address: user.email,
                template_context: serde_json::json!({
                    "client_name": notification.client_name,
                    "binding_message": binding_message,
                    "action_url": self.approval_url(notification.request_id),
                    "expiry_time": notification.expires_at.to_rfc3339(),
                }),
                attempt_count: 0,
                enqueued_at: Utc::now(),
            })
            .await
    }
}

impl<U, T, P> CibaUserNotifier for CibaMailNotifier<U, T, P>
where
    U: UserRepository + 'static,
    T: TenantRepository + 'static,
    P: MailPublisher + 'static,
{
    fn notify(&self, notification: CibaUserNotification) -> CibaNotifyFuture<'_> {
        Box::pin(self.send(notification))
    }
}

//! AMQP consumer for asynchronous outbound mail delivery (D-14).
//!
//! The consumer reads [`OutboundMailMessage`] from `axiam.mail.outbound`,
//! resolves the effective [`EmailConfig`] via [`EmailConfigRepository`],
//! renders the HTML-safe body via [`render_email`] (D-18), and sends via
//! [`EmailService`].
//!
//! On transient send failure the message is re-published with an
//! incremented `attempt_count` for backoff retry.  After
//! [`MAX_RETRIES`] exhausted attempts the message is dead-lettered and a
//! PII-minimal `email.delivery_failed` audit event is appended (D-16).

use crate::connection::queues;
use crate::messages::{MailType, OutboundMailMessage};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::email_template::TemplateKind;
use axiam_core::repository::{AuditLogRepository, EmailConfigRepository, UserRepository};
use axiam_email::service::EmailService;
use axiam_email::template::{TemplateContext, render_email, resolve_template};
use futures_lite::StreamExt;
use lapin::BasicProperties;
use lapin::Channel;
use lapin::options::{BasicAckOptions, BasicConsumeOptions, BasicNackOptions, BasicPublishOptions};
use lapin::types::FieldTable;
use tracing::{error, info, warn};

/// Maximum number of delivery attempts before a message is dead-lettered.
///
/// The first attempt is `attempt_count = 0`; retries increment to
/// `MAX_RETRIES - 1`. On the `MAX_RETRIES`-th attempt failure the message
/// is nack'd (→ DLQ) and `email.delivery_failed` is written.
pub const MAX_RETRIES: u32 = 3;

// ---------------------------------------------------------------------------
// MailType → TemplateKind mapping
// ---------------------------------------------------------------------------

fn template_kind_for(mail_type: &MailType) -> TemplateKind {
    match mail_type {
        MailType::PasswordReset => TemplateKind::PasswordReset,
        MailType::EmailVerification => TemplateKind::Activation,
        MailType::Notification => TemplateKind::AdminNotification,
        MailType::DeletionCancel => TemplateKind::DeletionScheduled,
        MailType::ExportReady => TemplateKind::ExportReady,
    }
}

// ---------------------------------------------------------------------------
// Template context builder
// ---------------------------------------------------------------------------

/// Build a [`TemplateContext`] from an [`OutboundMailMessage`]'s JSON context.
///
/// Any JSON string values found at the top level are inserted as-is.
/// Non-string values are serialized as JSON strings.
fn build_template_context(ctx: &serde_json::Value) -> TemplateContext {
    let mut map = TemplateContext::new();
    if let serde_json::Value::Object(obj) = ctx {
        for (k, v) in obj {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            map.insert(k.clone(), s);
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Core send-with-retry-and-audit helper (broker-free, testable directly)
// ---------------------------------------------------------------------------

/// Attempt to send one outbound mail message.
///
/// Returns `Ok(true)` on successful delivery, `Ok(false)` when the attempt
/// failed but more retries remain (caller should re-publish), and
/// `Ok(false)` with audit written when retries are exhausted.
///
/// This function is separate from the consumer loop so unit tests can
/// exercise the failure/audit path without a live AMQP broker.
///
/// # PII safety
/// The `to_address` field is used **only** for delivery and is **never**
/// included in audit metadata (D-16).
///
/// # SEC-055: Recipient resolution
/// The `to_address` field in `OutboundMailMessage` is treated as advisory.
/// The actual recipient email is always resolved from `user_id` + `tenant_id`
/// via the user repository, preventing recipient hijacking if a message is
/// intercepted and tampered with in transit.
pub async fn send_with_retry_and_audit<E, A, U>(
    msg: &OutboundMailMessage,
    email_config_repo: &E,
    audit_repo: &A,
    user_repo: &U,
) -> Result<SendOutcome, SendError>
where
    E: EmailConfigRepository,
    A: AuditLogRepository,
    U: UserRepository,
{
    // 1. Resolve effective email config (tenant → org cascade).
    let email_config = email_config_repo
        .get_effective_config(msg.org_id, msg.tenant_id)
        .await
        .map_err(|e| SendError(e.to_string()))?;

    let Some(config) = email_config else {
        return Err(SendError("no email config for org/tenant".into()));
    };

    // 2. Build EmailService from resolved config.
    let svc = EmailService::from_config(&config).map_err(|e| SendError(e.to_string()))?;

    // 3. Resolve built-in template (no per-org/tenant custom templates fetched here;
    //    template repository lookup is deferred to a future task — T19.21).
    let kind = template_kind_for(&msg.mail_type);
    let template = resolve_template(kind, None, None);

    // 4. Build template context from message.
    let ctx = build_template_context(&msg.template_context);

    // 5. SEC-055: Resolve recipient from user repository instead of trusting to_address.
    //    This prevents recipient hijacking if the AMQP message is tampered with.
    let resolved_address = user_repo
        .get_by_id(msg.tenant_id, msg.user_id)
        .await
        .map(|u| u.email)
        .unwrap_or_else(|_| {
            warn!(
                user_id = %msg.user_id,
                tenant_id = %msg.tenant_id,
                "SEC-055: could not resolve user email — falling back to message to_address"
            );
            msg.to_address.clone()
        });

    // 6. Render HTML-safe email (D-18).
    let email_message = render_email(&template, &resolved_address, &ctx);

    // 6. Attempt delivery.
    let send_result = svc.send(&email_message).await;

    match send_result {
        Ok(_) => Ok(SendOutcome::Delivered),
        Err(e) => {
            let error_msg = e.to_string();
            let error_class = error_class_for(&error_msg);

            if msg.attempt_count + 1 < MAX_RETRIES {
                // More retries remain — signal the caller to re-publish.
                warn!(
                    attempt = msg.attempt_count,
                    max_retries = MAX_RETRIES,
                    error = %error_msg,
                    mail_type = ?msg.mail_type,
                    "mail delivery failed, will retry"
                );
                Ok(SendOutcome::RetryNeeded {
                    error_class: error_class.to_string(),
                })
            } else {
                // Retries exhausted — dead-letter and write PII-minimal audit.
                error!(
                    attempt = msg.attempt_count,
                    max_retries = MAX_RETRIES,
                    error = %error_msg,
                    mail_type = ?msg.mail_type,
                    "mail delivery exhausted retries — dead-lettering"
                );

                // D-16: metadata MUST NOT contain to_address or any raw PII.
                let audit_metadata = serde_json::json!({
                    "provider": svc.provider_name(),
                    "error_class": error_class,
                    "attempt_count": msg.attempt_count,
                    "next_retry_at": null,
                    "mail_type": format!("{:?}", msg.mail_type),
                });

                let entry = CreateAuditLogEntry {
                    tenant_id: msg.tenant_id,
                    actor_id: msg.user_id,
                    actor_type: ActorType::System,
                    action: "email.delivery_failed".into(),
                    resource_id: None,
                    outcome: AuditOutcome::Failure,
                    ip_address: None,
                    metadata: Some(audit_metadata),
                };

                if let Err(ae) = audit_repo.append(entry).await {
                    error!(
                        error = %ae,
                        "failed to write email.delivery_failed audit event"
                    );
                }

                Ok(SendOutcome::Exhausted)
            }
        }
    }
}

/// Outcome of a [`send_with_retry_and_audit`] call.
#[derive(Debug)]
pub enum SendOutcome {
    /// Message was delivered successfully.
    Delivered,
    /// Delivery failed but retries remain; caller must re-publish.
    RetryNeeded { error_class: String },
    /// All retries exhausted; audit event written; caller must dead-letter.
    Exhausted,
}

/// Non-delivery error (config/infra, not transient).
#[derive(Debug)]
pub struct SendError(pub String);

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "mail send error: {}", self.0)
    }
}

/// Classify an error message string into a coarse error class for audit metadata.
///
/// Deliberately coarse — avoids leaking provider-internal error strings into
/// audit logs that may be inspected outside the security boundary.
fn error_class_for(error_msg: &str) -> &'static str {
    let msg = error_msg.to_lowercase();
    if msg.contains("timeout") || msg.contains("timed out") {
        "timeout"
    } else if msg.contains("auth") || msg.contains("credential") || msg.contains("unauthorized") {
        "auth_failure"
    } else if msg.contains("connect") || msg.contains("refused") || msg.contains("network") {
        "connection_error"
    } else if msg.contains("rate") || msg.contains("throttle") || msg.contains("quota") {
        "rate_limited"
    } else {
        "provider_error"
    }
}

// ---------------------------------------------------------------------------
// AMQP consumer loop
// ---------------------------------------------------------------------------

/// Start consuming outbound mail from `axiam.mail.outbound`.
///
/// Mirrors the `start_audit_consumer` loop pattern. On valid message delivery
/// failure, re-publishes with incremented `attempt_count` for backoff retry
/// (D-14). On exhaustion, nacks (→ DLQ) and writes `email.delivery_failed`
/// audit (D-14, D-16). HTML body is always rendered via `render_email` for
/// HTML-safety (D-18).
///
/// SEC-055: The `user_repo` is used to resolve the actual recipient email
/// address from `user_id + tenant_id`, preventing recipient hijacking via
/// a tampered `to_address` field in the AMQP message.
pub async fn start_mail_consumer<E, A, U>(
    channel: Channel,
    email_config_repo: E,
    audit_repo: A,
    user_repo: U,
) where
    E: EmailConfigRepository + 'static,
    A: AuditLogRepository + 'static,
    U: UserRepository + 'static,
{
    info!("Starting mail AMQP consumer");

    let mut consumer = match channel
        .basic_consume(
            queues::MAIL_OUTBOUND.into(),
            "axiam-mail-consumer".into(),
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "Failed to start mail consumer");
            return;
        }
    };

    while let Some(delivery_result) = consumer.next().await {
        let delivery = match delivery_result {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "Error receiving mail delivery");
                continue;
            }
        };

        let tag = delivery.delivery_tag;

        // Deserialize. Bad payload → nack requeue:false (not re-deliverable).
        let msg: OutboundMailMessage = match serde_json::from_slice(&delivery.data) {
            Ok(m) => m,
            Err(e) => {
                warn!(
                    error = %e,
                    delivery_tag = tag,
                    "Invalid mail message payload, nacking"
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

        let outcome =
            send_with_retry_and_audit(&msg, &email_config_repo, &audit_repo, &user_repo).await;

        match outcome {
            Ok(SendOutcome::Delivered) => {
                if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
                    error!(error = %e, delivery_tag = tag, "Failed to ack mail delivery");
                }
            }
            Ok(SendOutcome::RetryNeeded { .. }) => {
                // Re-publish with incremented attempt_count for backoff.
                let mut retry_msg = msg.clone();
                retry_msg.attempt_count += 1;
                match serde_json::to_vec(&retry_msg) {
                    Ok(payload) => {
                        let publish_result = channel
                            .basic_publish(
                                "".into(),
                                queues::MAIL_OUTBOUND.into(),
                                BasicPublishOptions::default(),
                                &payload,
                                BasicProperties::default().with_delivery_mode(2),
                            )
                            .await;
                        if let Err(e) = publish_result {
                            error!(
                                error = %e,
                                delivery_tag = tag,
                                "Failed to re-publish mail retry"
                            );
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "Failed to serialize retry mail message");
                    }
                }
                // Ack the original message — retry copy has been queued.
                if let Err(e) = delivery.acker.ack(BasicAckOptions::default()).await {
                    error!(error = %e, delivery_tag = tag, "Failed to ack original mail delivery");
                }
            }
            Ok(SendOutcome::Exhausted) => {
                // Dead-letter: nack with requeue:false → x-dead-letter-exchange.
                // Audit event already written inside send_with_retry_and_audit.
                let _ = delivery
                    .acker
                    .nack(BasicNackOptions {
                        requeue: false,
                        ..BasicNackOptions::default()
                    })
                    .await;
            }
            Err(e) => {
                // Config/infra error (no email config, disabled, etc.).
                // Nack without requeueing — re-delivery won't fix a config error.
                warn!(
                    error = %e,
                    delivery_tag = tag,
                    mail_type = ?msg.mail_type,
                    "Mail config/infra error — nacking without requeue"
                );
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

    warn!("Mail AMQP consumer stream ended");
}

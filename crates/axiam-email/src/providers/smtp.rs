//! SMTP email provider using `lettre`.

use std::future::Future;
use std::pin::Pin;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::SmtpConfig;
use lettre::message::{Mailbox, MessageBuilder};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};

/// SMTP email provider using `lettre` with STARTTLS or implicit TLS.
pub struct SmtpProvider {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpProvider {
    pub fn new(config: &SmtpConfig) -> Result<Self, AxiamError> {
        let creds = Credentials::new(config.username.clone(), config.password.clone());

        let transport = if config.starttls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                .map_err(|e| AxiamError::EmailConfig(format!("SMTP STARTTLS relay error: {e}")))?
                .port(config.port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(|e| AxiamError::EmailConfig(format!("SMTP relay error: {e}")))?
                .port(config.port)
                .credentials(creds)
                .build()
        };

        Ok(Self { transport })
    }
}

impl EmailProvider for SmtpProvider {
    fn send(
        &self,
        from_name: &str,
        from_email: &str,
        reply_to: Option<&str>,
        message: &EmailMessage,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<SendResult>> + Send + '_>> {
        let from_name = from_name.to_string();
        let from_email = from_email.to_string();
        let reply_to = reply_to.map(str::to_string);
        let message = message.clone();

        Box::pin(async move {
            let from_mailbox: Mailbox = format!("{from_name} <{from_email}>")
                .parse()
                .map_err(|e| AxiamError::EmailConfig(format!("invalid from address: {e}")))?;

            let to_mailbox: Mailbox = message
                .to
                .parse()
                .map_err(|e| AxiamError::EmailConfig(format!("invalid to address: {e}")))?;

            let mut builder = MessageBuilder::new()
                .from(from_mailbox)
                .to(to_mailbox)
                .subject(&message.subject);

            if let Some(ref rt) = reply_to {
                let rt_mailbox: Mailbox = rt.parse().map_err(|e| {
                    AxiamError::EmailConfig(format!("invalid reply-to address: {e}"))
                })?;
                builder = builder.reply_to(rt_mailbox);
            }

            let email = match (&message.html_body, &message.text_body) {
                (Some(html), Some(text)) => {
                    use lettre::message::MultiPart;
                    builder
                        .multipart(MultiPart::alternative_plain_html(
                            text.clone(),
                            html.clone(),
                        ))
                        .map_err(|e| {
                            AxiamError::EmailDelivery(format!(
                                "failed to build multipart email: {e}"
                            ))
                        })?
                }
                (Some(html), None) => {
                    use lettre::message::header::ContentType;
                    builder
                        .header(ContentType::TEXT_HTML)
                        .body(html.clone())
                        .map_err(|e| {
                            AxiamError::EmailDelivery(format!("failed to build HTML email: {e}"))
                        })?
                }
                (None, Some(text)) => builder.body(text.clone()).map_err(|e| {
                    AxiamError::EmailDelivery(format!("failed to build text email: {e}"))
                })?,
                (None, None) => return Err(AxiamError::EmailDelivery("email has no body".into())),
            };

            let response = self
                .transport
                .send(email)
                .await
                .map_err(|e| AxiamError::EmailDelivery(format!("SMTP send failed: {e}")))?;

            Ok(SendResult {
                message_id: response.message().next().map(str::to_string),
            })
        })
    }

    fn provider_name(&self) -> &'static str {
        "smtp"
    }
}

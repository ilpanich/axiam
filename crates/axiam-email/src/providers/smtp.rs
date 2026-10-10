//! SMTP email provider using `lettre`.

use std::future::Future;
use std::pin::Pin;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::SmtpConfig;
use lettre::message::{Mailbox, MessageBuilder};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

use crate::egress::{EmailEgress, PROVIDER_UNREACHABLE};
use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};

/// SMTP email provider using `lettre` with STARTTLS or implicit TLS, held to
/// the deployment's outbound address policy at every send (#529).
pub struct SmtpProvider {
    host: String,
    port: u16,
    credentials: Credentials,
    starttls: bool,
    /// Built once from the configured host: the name the server's certificate
    /// must carry, whatever address the connection is pinned to.
    tls: TlsParameters,
    egress: EmailEgress,
}

impl SmtpProvider {
    /// A provider for `config`. Nothing is resolved or dialled here; an
    /// unusable host name for the TLS check is refused now.
    pub fn new(config: &SmtpConfig, egress: EmailEgress) -> Result<Self, AxiamError> {
        let host = config.host.trim().to_string();
        let tls_name = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let tls = TlsParameters::new(tls_name)
            .map_err(|e| AxiamError::EmailConfig(format!("SMTP TLS parameters error: {e}")))?;
        Ok(Self {
            host,
            port: config.port,
            credentials: Credentials::new(config.username.clone(), config.password.clone()),
            starttls: config.starttls,
            tls,
            egress,
        })
    }

    /// The transport for one send: the host resolved once and vetted by the
    /// address guard, the TCP connection opened to the vetted address — an IP
    /// literal, so `lettre` resolves nothing — and TLS checked against the
    /// configured host.
    ///
    /// What `relay()` / `starttls_relay()` did, minus their own resolution:
    /// implicit TLS (SMTPS, typically port 465) wraps the connection from the
    /// start; STARTTLS (typically port 587) connects in plaintext and upgrades.
    /// Neither falls back to cleartext.
    async fn pinned_transport(&self) -> AxiamResult<AsyncSmtpTransport<Tokio1Executor>> {
        let target = self.egress.smtp_target(&self.host, self.port).await?;
        let address = target.addresses[0];
        let tls = if self.starttls {
            Tls::Required(self.tls.clone())
        } else {
            Tls::Wrapper(self.tls.clone())
        };
        Ok(
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(address.ip().to_string())
                .port(address.port())
                .credentials(self.credentials.clone())
                .tls(tls)
                .build(),
        )
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
                .map_err(|e| AxiamError::EmailDelivery(format!("invalid to address: {e}")))?;

            let mut builder = MessageBuilder::new()
                .from(from_mailbox)
                .to(to_mailbox)
                .subject(&message.subject);

            if let Some(ref rt) = reply_to {
                let rt_mailbox: Mailbox = rt.parse().map_err(|e| {
                    AxiamError::EmailDelivery(format!("invalid reply-to address: {e}"))
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

            let transport = self.pinned_transport().await?;
            let response = transport.send(email).await.map_err(|e| {
                if e.is_permanent() || e.is_transient() {
                    // The server's own answer to a command (a rejected sender,
                    // failed authentication): it reached a vetted SMTP server.
                    AxiamError::EmailDelivery(format!("SMTP send failed: {e}"))
                } else {
                    // Refused, reset, timed out or a failed handshake: one
                    // answer, so the failure is no port scanner (#529).
                    tracing::warn!(
                        target: "axiam::email",
                        error = %e,
                        "the SMTP server could not be reached"
                    );
                    AxiamError::EmailDelivery(format!("smtp: {PROVIDER_UNREACHABLE}"))
                }
            })?;

            Ok(SendResult {
                message_id: response.message().next().map(str::to_string),
            })
        })
    }

    fn provider_name(&self) -> &'static str {
        "smtp"
    }
}

//! Brevo (formerly Sendinblue) email provider (REST API).

use std::future::Future;
use std::pin::Pin;

use crate::egress::EmailEgress;
use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::ApiProviderConfig;

const DEFAULT_API_URL: &str = "https://api.brevo.com/v3/smtp/email";

pub struct BrevoProvider {
    egress: EmailEgress,
    api_key: String,
    api_url: String,
}

impl BrevoProvider {
    pub fn new(config: &ApiProviderConfig, egress: EmailEgress) -> AxiamResult<Self> {
        Ok(Self {
            egress,
            api_key: config.api_key.clone(),
            api_url: config
                .api_url
                .clone()
                .unwrap_or_else(|| DEFAULT_API_URL.to_string()),
        })
    }
}

impl EmailProvider for BrevoProvider {
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
            let mut body = serde_json::json!({
                "sender": {
                    "name": from_name,
                    "email": from_email,
                },
                "to": [{"email": message.to}],
                "subject": message.subject,
            });

            if let Some(ref html) = message.html_body {
                body["htmlContent"] = serde_json::Value::String(html.clone());
            }
            if let Some(ref text) = message.text_body {
                body["textContent"] = serde_json::Value::String(text.clone());
            }
            if let Some(rt) = reply_to {
                body["replyTo"] = serde_json::json!({"email": rt});
            }

            let resp = self
                .egress
                .post("Brevo", &self.api_url, |client, url| {
                    client
                        .post(url)
                        .header("api-key", &self.api_key)
                        .header("Accept", "application/json")
                        .json(&body)
                })
                .await?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_else(|_| "unknown".into());
                return Err(AxiamError::EmailDelivery(format!(
                    "Brevo returned {status}: {text}"
                )));
            }

            let resp_json: serde_json::Value = resp.json().await.unwrap_or_default();
            let message_id = resp_json["messageId"].as_str().map(str::to_string);

            Ok(SendResult { message_id })
        })
    }

    fn provider_name(&self) -> &'static str {
        "brevo"
    }
}

//! SendGrid email provider (REST API).

use std::future::Future;
use std::pin::Pin;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::ApiProviderConfig;
use reqwest::Client;

use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};

const DEFAULT_API_URL: &str = "https://api.sendgrid.com/v3/mail/send";

pub struct SendGridProvider {
    client: Client,
    api_key: String,
    api_url: String,
}

impl SendGridProvider {
    pub fn new(config: &ApiProviderConfig) -> Self {
        Self {
            client: Client::new(),
            api_key: config.api_key.clone(),
            api_url: config
                .api_url
                .clone()
                .unwrap_or_else(|| DEFAULT_API_URL.to_string()),
        }
    }
}

impl EmailProvider for SendGridProvider {
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
            let mut content = Vec::new();
            if let Some(ref text) = message.text_body {
                content.push(serde_json::json!({
                    "type": "text/plain",
                    "value": text,
                }));
            }
            if let Some(ref html) = message.html_body {
                content.push(serde_json::json!({
                    "type": "text/html",
                    "value": html,
                }));
            }

            let mut body = serde_json::json!({
                "personalizations": [{
                    "to": [{"email": message.to}],
                }],
                "from": {
                    "email": from_email,
                    "name": from_name,
                },
                "subject": message.subject,
                "content": content,
            });

            if let Some(rt) = reply_to {
                body["reply_to"] = serde_json::json!({"email": rt});
            }

            let resp = self
                .client
                .post(&self.api_url)
                .bearer_auth(&self.api_key)
                .json(&body)
                .send()
                .await
                .map_err(|e| AxiamError::EmailDelivery(format!("SendGrid request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_else(|_| "unknown".into());
                return Err(AxiamError::EmailDelivery(format!(
                    "SendGrid returned {status}: {text}"
                )));
            }

            let message_id = resp
                .headers()
                .get("x-message-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);

            Ok(SendResult { message_id })
        })
    }

    fn provider_name(&self) -> &'static str {
        "sendgrid"
    }
}

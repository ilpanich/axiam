//! Resend email provider (REST API).

use std::future::Future;
use std::pin::Pin;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::ApiProviderConfig;
use reqwest::Client;

use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};

const DEFAULT_API_URL: &str = "https://api.resend.com/emails";

pub struct ResendProvider {
    client: Client,
    api_key: String,
    api_url: String,
}

impl ResendProvider {
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

impl EmailProvider for ResendProvider {
    fn send(
        &self,
        from_name: &str,
        from_email: &str,
        reply_to: Option<&str>,
        message: &EmailMessage,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<SendResult>> + Send + '_>> {
        let from = format!("{from_name} <{from_email}>");
        let reply_to = reply_to.map(str::to_string);
        let message = message.clone();

        Box::pin(async move {
            let mut body = serde_json::json!({
                "from": from,
                "to": [message.to],
                "subject": message.subject,
            });

            if let Some(ref html) = message.html_body {
                body["html"] = serde_json::Value::String(html.clone());
            }
            if let Some(ref text) = message.text_body {
                body["text"] = serde_json::Value::String(text.clone());
            }
            if let Some(rt) = reply_to {
                body["reply_to"] = serde_json::Value::String(rt);
            }

            let resp = self
                .client
                .post(&self.api_url)
                .bearer_auth(&self.api_key)
                .json(&body)
                .send()
                .await
                .map_err(|e| AxiamError::EmailDelivery(format!("Resend request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_else(|_| "unknown".into());
                return Err(AxiamError::EmailDelivery(format!(
                    "Resend returned {status}: {text}"
                )));
            }

            let resp_json: serde_json::Value = resp.json().await.unwrap_or_default();
            let message_id = resp_json["id"].as_str().map(str::to_string);

            Ok(SendResult { message_id })
        })
    }

    fn provider_name(&self) -> &'static str {
        "resend"
    }
}

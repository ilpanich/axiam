//! Postmark email provider (REST API).

use std::future::Future;
use std::pin::Pin;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::email::ApiProviderConfig;
use reqwest::Client;

use super::build_http_client;
use crate::message::EmailMessage;
use crate::provider::{EmailProvider, SendResult};

const DEFAULT_API_URL: &str = "https://api.postmarkapp.com/email";

pub struct PostmarkProvider {
    client: Client,
    api_key: String,
    api_url: String,
}

impl PostmarkProvider {
    pub fn new(config: &ApiProviderConfig) -> AxiamResult<Self> {
        Ok(Self {
            client: build_http_client()?,
            api_key: config.api_key.clone(),
            api_url: config
                .api_url
                .clone()
                .unwrap_or_else(|| DEFAULT_API_URL.to_string()),
        })
    }
}

impl EmailProvider for PostmarkProvider {
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
                "From": from,
                "To": message.to,
                "Subject": message.subject,
            });

            if let Some(ref html) = message.html_body {
                body["HtmlBody"] = serde_json::Value::String(html.clone());
            }
            if let Some(ref text) = message.text_body {
                body["TextBody"] = serde_json::Value::String(text.clone());
            }
            if let Some(rt) = reply_to {
                body["ReplyTo"] = serde_json::Value::String(rt);
            }

            let resp = self
                .client
                .post(&self.api_url)
                .header("X-Postmark-Server-Token", &self.api_key)
                .header("Accept", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| AxiamError::EmailDelivery(format!("Postmark request failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_else(|_| "unknown".into());
                return Err(AxiamError::EmailDelivery(format!(
                    "Postmark returned {status}: {text}"
                )));
            }

            let resp_json: serde_json::Value = resp.json().await.unwrap_or_default();
            let message_id = resp_json["MessageID"].as_str().map(str::to_string);

            Ok(SendResult { message_id })
        })
    }

    fn provider_name(&self) -> &'static str {
        "postmark"
    }
}

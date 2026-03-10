//! Webhook delivery service — async HTTP delivery with HMAC-SHA256 signing
//! and exponential backoff retry.

use axiam_core::repository::WebhookRepository;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Async webhook delivery service.
///
/// Fetches matching webhooks from the repository and spawns background
/// tasks to deliver the payload with HMAC-SHA256 signed headers.
#[derive(Clone)]
pub struct WebhookDeliveryService<W> {
    repo: W,
    client: reqwest::Client,
}

impl<W: WebhookRepository + Clone + 'static> WebhookDeliveryService<W> {
    pub fn new(repo: W) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");
        Self { repo, client }
    }

    /// Fire webhook deliveries for the given event type and payload.
    ///
    /// Spawns a background task per matching webhook. Does not block.
    pub fn deliver(&self, tenant_id: Uuid, event_type: String, payload: serde_json::Value) {
        let repo = self.repo.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            let webhooks = match repo.get_by_event(tenant_id, &event_type).await {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!(
                        %tenant_id, %event_type,
                        "failed to fetch webhooks: {e}"
                    );
                    return;
                }
            };

            for webhook in webhooks {
                let client = client.clone();
                let event_type = event_type.clone();
                let payload = payload.clone();

                tokio::spawn(async move {
                    let delivery_id = Uuid::new_v4();
                    let body = serde_json::to_string(&payload).unwrap_or_default();

                    let signature = compute_signature(&webhook.secret_hash, &body);

                    let max_retries = webhook.retry_policy.max_retries;
                    let initial_delay = webhook.retry_policy.initial_delay_secs;
                    let multiplier = webhook.retry_policy.backoff_multiplier;

                    for attempt in 0..=max_retries {
                        if attempt > 0 {
                            let delay_secs =
                                (initial_delay as f64) * multiplier.powi((attempt - 1) as i32);
                            tokio::time::sleep(std::time::Duration::from_secs_f64(delay_secs))
                                .await;
                        }

                        let result = client
                            .post(&webhook.url)
                            .header("Content-Type", "application/json")
                            .header("X-Axiam-Signature", &signature)
                            .header("X-Axiam-Event", &event_type)
                            .header("X-Axiam-Delivery", delivery_id.to_string())
                            .body(body.clone())
                            .send()
                            .await;

                        match result {
                            Ok(resp) if resp.status().is_success() => {
                                tracing::info!(
                                    webhook_id = %webhook.id,
                                    %delivery_id,
                                    %event_type,
                                    attempt,
                                    status = %resp.status(),
                                    "webhook delivered"
                                );
                                return;
                            }
                            Ok(resp) => {
                                tracing::warn!(
                                    webhook_id = %webhook.id,
                                    %delivery_id,
                                    %event_type,
                                    attempt,
                                    status = %resp.status(),
                                    "webhook delivery failed"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    webhook_id = %webhook.id,
                                    %delivery_id,
                                    %event_type,
                                    attempt,
                                    error = %e,
                                    "webhook delivery error"
                                );
                            }
                        }
                    }

                    tracing::error!(
                        webhook_id = %webhook.id,
                        %delivery_id,
                        %event_type,
                        "webhook delivery exhausted all retries"
                    );
                });
            }
        });
    }
}

/// Compute HMAC-SHA256 signature of the body using the shared secret.
fn compute_signature(secret: &str, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_is_deterministic() {
        let sig1 = compute_signature("secret", "hello");
        let sig2 = compute_signature("secret", "hello");
        assert_eq!(sig1, sig2);
        assert!(!sig1.is_empty());
    }

    #[test]
    fn different_secrets_produce_different_signatures() {
        let sig1 = compute_signature("secret1", "hello");
        let sig2 = compute_signature("secret2", "hello");
        assert_ne!(sig1, sig2);
    }
}

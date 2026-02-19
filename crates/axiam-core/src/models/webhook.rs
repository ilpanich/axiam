//! Webhook domain model.
//!
//! Webhooks enable real-time event delivery to external systems
//! via HTTPS POST with HMAC-SHA256 signature verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Retry policy for failed webhook deliveries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial delay between retries in seconds.
    pub initial_delay_secs: u64,
    /// Multiplier for exponential backoff.
    pub backoff_multiplier: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay_secs: 10,
            backoff_multiplier: 2.0,
        }
    }
}

/// A registered webhook endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: Uuid,
    /// The tenant this webhook belongs to.
    pub tenant_id: Uuid,
    /// The HTTPS URL to deliver events to.
    pub url: String,
    /// Event types this webhook is subscribed to (e.g., `["user.created", "auth.login"]`).
    pub events: Vec<String>,
    /// HMAC-SHA256 shared secret for signing payloads.
    pub secret_hash: String,
    pub enabled: bool,
    pub retry_policy: RetryPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Fields required to create a new webhook.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWebhook {
    pub tenant_id: Uuid,
    pub url: String,
    pub events: Vec<String>,
    /// The raw secret (will be hashed before storage).
    pub secret: String,
    pub retry_policy: Option<RetryPolicy>,
}

/// Fields that can be updated on an existing webhook.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateWebhook {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub retry_policy: Option<RetryPolicy>,
}

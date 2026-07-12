//! Webhook domain model.
//!
//! Webhooks enable real-time event delivery to external systems
//! via HTTPS POST with HMAC-SHA256 signature verification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Retry policy for failed webhook deliveries.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
#[derive(Clone, Serialize, Deserialize)]
pub struct Webhook {
    pub id: Uuid,
    /// The tenant this webhook belongs to.
    pub tenant_id: Uuid,
    /// The HTTPS URL to deliver events to.
    pub url: String,
    /// Event types this webhook is subscribed to (e.g., `["user.created", "auth.login"]`).
    pub events: Vec<String>,
    /// HMAC-SHA256 shared secret for signing payloads (stored server-side
    /// AES-256-GCM encrypted, never returned in API responses).
    #[serde(skip_serializing)]
    pub secret: String,
    pub enabled: bool,
    pub retry_policy: RetryPolicy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Manual `Debug` impl (SEC-067 / SECHRD-09 / D-06): redacts the HMAC secret
/// so `{:?}` never prints the encrypted secret, mirroring `FederationConfig`.
impl std::fmt::Debug for Webhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Webhook")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("url", &self.url)
            .field("events", &self.events)
            .field("secret", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .field("retry_policy", &self.retry_policy)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Fields required to create a new webhook.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateWebhook {
    pub tenant_id: Uuid,
    pub url: String,
    pub events: Vec<String>,
    /// HMAC-SHA256 shared secret for signing payloads.
    pub secret: String,
    pub retry_policy: Option<RetryPolicy>,
}

/// Manual `Debug` impl (SEC-067): `CreateWebhook.secret` is the **plaintext**
/// HMAC secret at this stage, so redact it from `{:?}` to keep it out of logs.
impl std::fmt::Debug for CreateWebhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateWebhook")
            .field("tenant_id", &self.tenant_id)
            .field("url", &self.url)
            .field("events", &self.events)
            .field("secret", &"[REDACTED]")
            .field("retry_policy", &self.retry_policy)
            .finish()
    }
}

/// Fields that can be updated on an existing webhook.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct UpdateWebhook {
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub retry_policy: Option<RetryPolicy>,
    /// New HMAC-SHA256 shared secret (already encrypted by the caller before
    /// reaching the repository — D-02 secret rotation). `None` leaves the
    /// stored secret untouched.
    pub secret: Option<String>,
}

/// Manual `Debug` impl (SEC-067): redact the rotated secret from `{:?}`.
impl std::fmt::Debug for UpdateWebhook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateWebhook")
            .field("url", &self.url)
            .field("events", &self.events)
            .field("enabled", &self.enabled)
            .field("retry_policy", &self.retry_policy)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

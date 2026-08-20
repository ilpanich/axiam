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

#[cfg(test)]
mod tests {
    use super::*;

    // The three `Debug` impls in this file are hand-written for one reason
    // (SEC-067 / SECHRD-09 / D-06): a webhook's HMAC secret must never reach a
    // log line. That makes them security controls, not formatting niceties —
    // and a derived `Debug` accidentally restored by a later refactor would
    // reintroduce the leak silently, because nothing else in the system would
    // change. So each one is asserted the same way: the secret is absent, the
    // marker is present, and the fields an operator actually needs to identify
    // the webhook survive.

    const SECRET: &str = "s3cr3t-hmac-key-do-not-log";

    fn webhook() -> Webhook {
        Webhook {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            url: "https://hooks.example.test/axiam".into(),
            events: vec!["user.created".into(), "auth.login".into()],
            secret: SECRET.into(),
            enabled: true,
            retry_policy: RetryPolicy::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn webhook_debug_redacts_the_secret_but_keeps_the_identifying_fields() {
        let w = webhook();
        let rendered = format!("{w:?}");

        assert!(
            !rendered.contains(SECRET),
            "the HMAC secret reached a Debug rendering: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        // Redaction must not cost observability: an operator reading a log
        // line has to be able to tell WHICH webhook it is, or the redaction
        // just moves the incident from "leaked secret" to "undiagnosable".
        assert!(rendered.contains(&w.id.to_string()));
        assert!(rendered.contains(&w.tenant_id.to_string()));
        assert!(rendered.contains("https://hooks.example.test/axiam"));
        assert!(rendered.contains("user.created"));
        assert!(rendered.contains("Webhook"));
    }

    #[test]
    fn create_webhook_debug_redacts_the_plaintext_secret() {
        // This one is the most dangerous of the three: at CreateWebhook stage
        // the secret is still PLAINTEXT, before the repository encrypts it.
        let c = CreateWebhook {
            tenant_id: Uuid::new_v4(),
            url: "https://hooks.example.test/axiam".into(),
            events: vec!["user.created".into()],
            secret: SECRET.into(),
            retry_policy: None,
        };
        let rendered = format!("{c:?}");

        assert!(
            !rendered.contains(SECRET),
            "the PLAINTEXT secret reached a Debug rendering: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("CreateWebhook"));
        assert!(rendered.contains("https://hooks.example.test/axiam"));
    }

    #[test]
    fn update_webhook_debug_distinguishes_a_rotation_from_an_untouched_secret() {
        // `UpdateWebhook.secret` is an Option and its Debug maps Some(_) to the
        // marker rather than printing a fixed string unconditionally. That
        // distinction is load-bearing: an operator debugging a rotation needs
        // to see THAT a new secret was supplied without seeing what it is, and
        // a `None` must not look like a rotation that happened.
        let rotating = UpdateWebhook {
            url: Some("https://hooks.example.test/new".into()),
            secret: Some(SECRET.into()),
            ..Default::default()
        };
        let rendered = format!("{rotating:?}");
        assert!(
            !rendered.contains(SECRET),
            "rotated secret leaked: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("https://hooks.example.test/new"));

        let untouched = UpdateWebhook {
            enabled: Some(false),
            ..Default::default()
        };
        let rendered = format!("{untouched:?}");
        assert!(
            !rendered.contains("[REDACTED]"),
            "a patch that rotates nothing must not read as a rotation: {rendered}"
        );
        assert!(rendered.contains("None"));
    }

    #[test]
    fn the_default_retry_policy_is_the_documented_one() {
        // These three numbers are the delivery contract for every webhook
        // registered without an explicit policy, so they are pinned rather
        // than left to whatever a later edit makes them.
        let p = RetryPolicy::default();
        assert_eq!(p.max_retries, 5);
        assert_eq!(p.initial_delay_secs, 10);
        assert!((p.backoff_multiplier - 2.0).abs() < f64::EPSILON);

        // Exponential backoff with these values must actually grow, and the
        // last attempt must land somewhere a human would call "gave up after
        // a few minutes" rather than "gave up instantly" or "next week".
        let mut delay = p.initial_delay_secs as f64;
        let mut total = 0.0;
        for _ in 0..p.max_retries {
            total += delay;
            delay *= p.backoff_multiplier;
        }
        assert!(total > 60.0 && total < 3600.0, "total backoff was {total}s");
    }

    #[test]
    fn a_webhook_serialises_without_its_secret() {
        // `#[serde(skip_serializing)]` is the other half of the same rule: the
        // secret must not leave the process in an API response either.
        let json = serde_json::to_string(&webhook()).expect("serialises");
        assert!(!json.contains(SECRET), "secret reached the wire: {json}");
        assert!(json.contains("hooks.example.test"));
    }
}

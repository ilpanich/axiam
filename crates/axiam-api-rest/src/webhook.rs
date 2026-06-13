//! Webhook delivery service — async HTTP delivery with HMAC-SHA256 signing
//! and exponential backoff retry.
//!
//! SEC-019: The URL host is re-resolved at each delivery attempt and rejected
//! if it resolves to a private/loopback/link-local IP (DNS rebinding defence).
//! SEC-031: The webhook secret is stored AES-256-GCM encrypted; it is decrypted
//! in memory for HMAC computation and never serialised in API responses.

use axiam_core::repository::WebhookRepository;
use axiam_auth::crypto::{aes256gcm_decrypt, aes256gcm_encrypt};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Error type for webhook delivery helper operations.
#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("invalid URL")]
    InvalidUrl,
    #[error("failed to resolve host")]
    ResolveFailed,
    #[error("SSRF blocked: resolved IP is private/loopback/link-local")]
    SsrfBlocked,
    #[error("secret decrypt failed: {0}")]
    SecretDecrypt(String),
}

/// Returns `true` for IPv4/IPv6 addresses that must never be contacted
/// from a server-side webhook delivery.
///
/// Covers: RFC1918 private ranges, loopback (127/8 and ::1), link-local
/// (169.254/16 and fe80::/10), and broadcast (255.255.255.255).
/// Does NOT use unstable `is_global` — all checks are stable API.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fe80::/10 link-local range — not a stable method, checked manually
                || (v6.segments()[0] & 0xffc0 == 0xfe80)
                // fc00::/7 unique-local range
                || (v6.segments()[0] & 0xfe00 == 0xfc00)
        }
    }
}

/// Resolve the host in `url` and return an error if any resolved IP is
/// private/loopback/link-local (SEC-019 — DNS rebinding defence).
///
/// Called at the **start of each delivery attempt** so that a rebind that
/// occurs after webhook creation is still caught.
async fn resolve_and_validate_host(url: &str) -> Result<(), WebhookError> {
    let parsed = url::Url::parse(url).map_err(|_| WebhookError::InvalidUrl)?;
    let host = parsed.host_str().ok_or(WebhookError::InvalidUrl)?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| WebhookError::ResolveFailed)?;

    for addr in addrs {
        if is_private_ip(addr.ip()) {
            return Err(WebhookError::SsrfBlocked);
        }
    }
    Ok(())
}

/// Async webhook delivery service.
///
/// Fetches matching webhooks from the repository and spawns background
/// tasks to deliver the payload with HMAC-SHA256 signed headers.
#[derive(Clone)]
pub struct WebhookDeliveryService<W> {
    repo: W,
    client: reqwest::Client,
    /// AES-256-GCM key used to decrypt webhook secrets stored at rest.
    /// Corresponds to `AXIAM__PKI__ENCRYPTION_KEY` (SEC-031).
    encryption_key: [u8; 32],
}

impl<W: WebhookRepository + Clone + 'static> WebhookDeliveryService<W> {
    pub fn new(repo: W, encryption_key: [u8; 32]) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build reqwest client");
        Self {
            repo,
            client,
            encryption_key,
        }
    }

    /// Fire webhook deliveries for the given event type and payload.
    ///
    /// Spawns a background task per matching webhook. Does not block.
    pub fn deliver(&self, tenant_id: Uuid, event_type: String, payload: serde_json::Value) {
        let repo = self.repo.clone();
        let client = self.client.clone();
        let encryption_key = self.encryption_key;

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

                    // SEC-031: Decrypt the stored secret before HMAC computation.
                    let plaintext_secret = match aes256gcm_decrypt(&encryption_key, &webhook.secret)
                    {
                        Ok(bytes) => match String::from_utf8(bytes) {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::error!(
                                    webhook_id = %webhook.id,
                                    "webhook secret is not valid UTF-8 after decrypt: {e}"
                                );
                                return;
                            }
                        },
                        Err(e) => {
                            tracing::error!(
                                webhook_id = %webhook.id,
                                "failed to decrypt webhook secret: {e}"
                            );
                            return;
                        }
                    };

                    let signature = compute_signature(&plaintext_secret, &body);

                    let max_retries = webhook.retry_policy.max_retries;
                    let initial_delay = webhook.retry_policy.initial_delay_secs;
                    let multiplier = webhook.retry_policy.backoff_multiplier;

                    for attempt in 0..=max_retries {
                        if attempt > 0 {
                            let delay_secs =
                                (initial_delay as f64) * multiplier.powi((attempt - 1) as i32);
                            // Clamp to avoid panic on negative/infinite/NaN values.
                            let delay_secs = delay_secs.clamp(0.0, 3600.0);
                            tokio::time::sleep(std::time::Duration::from_secs_f64(delay_secs))
                                .await;
                        }

                        // SEC-019: Re-resolve host at each delivery attempt to defeat
                        // DNS rebinding attacks. Abort all retries on SSRF block.
                        if let Err(e) = resolve_and_validate_host(&webhook.url).await {
                            tracing::warn!(
                                webhook_id = %webhook.id,
                                %delivery_id,
                                error = %e,
                                "SSRF check failed — aborting all delivery retries"
                            );
                            return;
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

/// Encrypt a webhook secret with AES-256-GCM for storage (SEC-031).
pub fn encrypt_webhook_secret(
    key: &[u8; 32],
    plaintext_secret: &str,
) -> Result<String, axiam_auth::error::AuthError> {
    aes256gcm_encrypt(key, plaintext_secret.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

    // ---- SSRF protection tests (SEC-019) ----

    #[test]
    fn webhook_ssrf_loopback_v4_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(is_private_ip(ip), "127.0.0.1 must be blocked");
    }

    #[test]
    fn webhook_ssrf_rfc1918_10x_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(is_private_ip(ip), "10.x must be blocked");
    }

    #[test]
    fn webhook_ssrf_rfc1918_172_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        assert!(is_private_ip(ip), "172.16.x must be blocked");
    }

    #[test]
    fn webhook_ssrf_rfc1918_192168_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(is_private_ip(ip), "192.168.x must be blocked");
    }

    #[test]
    fn webhook_ssrf_link_local_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1));
        assert!(is_private_ip(ip), "169.254.x link-local must be blocked");
    }

    #[test]
    fn webhook_ssrf_broadcast_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
        assert!(is_private_ip(ip), "broadcast must be blocked");
    }

    #[test]
    fn webhook_ssrf_loopback_v6_blocked() {
        let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_private_ip(ip), "::1 must be blocked");
    }

    #[test]
    fn webhook_ssrf_link_local_v6_blocked() {
        // fe80::1
        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert!(is_private_ip(ip), "fe80:: link-local must be blocked");
    }

    #[test]
    fn webhook_ssrf_public_ipv4_allowed() {
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com
        assert!(!is_private_ip(ip), "public IP must be allowed");
    }

    #[test]
    fn webhook_ssrf_invalid_url_rejected() {
        // Synchronous check — just verify parsing fails
        let result = url::Url::parse("not-a-url");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn webhook_ssrf_resolve_loopback_url_blocked() {
        // 127.0.0.1 resolves directly to loopback
        let result = resolve_and_validate_host("http://127.0.0.1/evil").await;
        assert!(
            matches!(result, Err(WebhookError::SsrfBlocked)),
            "127.0.0.1 must be SSRF-blocked, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn webhook_ssrf_resolve_rfc1918_url_blocked() {
        let result = resolve_and_validate_host("http://10.0.0.1/evil").await;
        assert!(
            matches!(result, Err(WebhookError::SsrfBlocked)),
            "10.x must be SSRF-blocked, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn webhook_ssrf_resolve_192168_blocked() {
        let result = resolve_and_validate_host("http://192.168.1.1/test").await;
        assert!(
            matches!(result, Err(WebhookError::SsrfBlocked)),
            "192.168.x must be blocked"
        );
    }

    // SEC-031: round-trip encrypt/decrypt of webhook secret
    #[test]
    fn webhook_secret_encrypt_decrypt_round_trip() {
        let key = [0x42u8; 32];
        let secret = "super-secret-hmac-key";
        let encrypted = encrypt_webhook_secret(&key, secret).expect("encrypt");
        assert_ne!(encrypted, secret, "encrypted value must differ from plaintext");

        let decrypted_bytes = aes256gcm_decrypt(&key, &encrypted).expect("decrypt");
        let decrypted = String::from_utf8(decrypted_bytes).expect("utf8");
        assert_eq!(decrypted, secret);
    }
}

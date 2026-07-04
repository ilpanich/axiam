//! Webhook delivery service — async HTTP delivery with HMAC-SHA256 signing
//! and exponential backoff retry.
//!
//! SEC-019/SECHRD-02: Delivery is routed through the shared
//! `axiam_federation::ssrf::guarded_fetch` guard, which resolves the host
//! fresh on every attempt, rejects private/loopback/link-local resolved
//! addresses (DNS-rebinding defence), and — critically — pins the exact
//! validated `IpAddr` into the connection via a fresh single-use client, so
//! `reqwest` cannot independently re-resolve DNS between the SSRF check and
//! the actual send (D-01c; this closes the pin gap the previous
//! `resolve_and_validate_host` + separate `client.post()` pair left open).
//! SEC-031: The webhook secret is stored AES-256-GCM encrypted; it is decrypted
//! in memory for HMAC computation and never serialised in API responses.

use axiam_auth::crypto::{aes256gcm_decrypt, aes256gcm_encrypt};
use axiam_core::repository::WebhookRepository;
use axiam_federation::ssrf::{self, SsrfError};
use hmac::{Hmac, Mac};
use sha2::Sha256;
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
    #[error("secret encrypt failed: {0}")]
    SecretEncrypt(String),
    #[error("webhook encryption key is not configured (AXIAM__PKI__ENCRYPTION_KEY unset)")]
    EncryptionKeyMissing,
}

impl From<WebhookError> for crate::error::AxiamApiError {
    fn from(err: WebhookError) -> Self {
        match err {
            // D-01/SEC-059: fail-closed, not an internal 500 — the caller can
            // retry once an operator configures the key. Never leaks crypto
            // internals, just states the subsystem is unavailable.
            WebhookError::EncryptionKeyMissing => {
                axiam_core::error::AxiamError::ServiceUnavailable(
                    "webhook subsystem unavailable: encryption key not configured".to_string(),
                )
                .into()
            }
            other => axiam_core::error::AxiamError::Crypto(other.to_string()).into(),
        }
    }
}

/// Maps the shared guard's error type onto `WebhookError` so a blocked or
/// unresolvable delivery target flows through the existing fail-closed
/// `From<WebhookError> for AxiamApiError` mapping — never a panic or a raw
/// 500 (D-01a: single shared guard, single error-mapping style).
impl From<SsrfError> for WebhookError {
    fn from(err: SsrfError) -> Self {
        match err {
            SsrfError::InvalidUrl => WebhookError::InvalidUrl,
            SsrfError::ResolveFailed => WebhookError::ResolveFailed,
            SsrfError::Blocked => WebhookError::SsrfBlocked,
            // A request/client-build/redirect failure at send time is not
            // itself an SSRF verdict — surface it as a resolve failure so it
            // still fails closed rather than panicking or leaking internals.
            SsrfError::ClientBuildFailed
            | SsrfError::RequestFailed(_)
            | SsrfError::TooManyRedirects => WebhookError::ResolveFailed,
        }
    }
}

/// Async webhook delivery service.
///
/// Fetches matching webhooks from the repository and spawns background
/// tasks to deliver the payload with HMAC-SHA256 signed headers.
#[derive(Clone)]
pub struct WebhookDeliveryService<W> {
    repo: W,
    /// AES-256-GCM key used to encrypt/decrypt webhook secrets stored at
    /// rest. Corresponds to `AXIAM__PKI__ENCRYPTION_KEY` (SEC-031/SEC-059).
    /// `None` when the env var is unset — the server still boots (this is
    /// an optional subsystem), but registration (`encrypt_secret`) and
    /// delivery (`deliver`) both refuse to operate rather than falling
    /// back to an all-zero/constant key.
    encryption_key: Option<[u8; 32]>,
}

impl<W: WebhookRepository + Clone + 'static> WebhookDeliveryService<W> {
    pub fn new(repo: W, encryption_key: Option<[u8; 32]>) -> Self {
        // No `reqwest::Client` is stored here any more: `ssrf::guarded_fetch`
        // (D-01c) builds a fresh, single-use, IP-pinned client per delivery
        // attempt, so a long-lived pooled client here would sit unused for
        // sends and only invite drift back toward the un-pinned pre-25-02
        // behavior.
        Self {
            repo,
            encryption_key,
        }
    }

    /// Encrypt a plaintext webhook secret with AES-256-GCM for storage
    /// (SEC-031/D-02). Fail-closed: returns `WebhookError::EncryptionKeyMissing`
    /// when no encryption key is configured, rather than storing the secret
    /// in plaintext or falling back to a constant key.
    pub fn encrypt_secret(&self, plaintext: &str) -> Result<String, WebhookError> {
        let key = self
            .encryption_key
            .ok_or(WebhookError::EncryptionKeyMissing)?;
        encrypt_webhook_secret(&key, plaintext)
            .map_err(|e| WebhookError::SecretEncrypt(e.to_string()))
    }

    /// Fire webhook deliveries for the given event type and payload.
    ///
    /// Spawns a background task per matching webhook. Does not block.
    pub fn deliver(&self, tenant_id: Uuid, event_type: String, payload: serde_json::Value) {
        let repo = self.repo.clone();
        let encryption_key = self.encryption_key;

        tokio::spawn(async move {
            // D-01/SEC-059: refuse delivery (log + return) when no encryption
            // key is configured — never decrypt stored secrets with a
            // placeholder/all-zero key.
            let Some(encryption_key) = encryption_key else {
                tracing::error!(
                    %tenant_id, %event_type,
                    "webhook delivery refused: encryption key not configured \
                     (AXIAM__PKI__ENCRYPTION_KEY unset)"
                );
                return;
            };

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

                        // SEC-019/SECHRD-02: `guarded_fetch` resolves the host
                        // fresh on this attempt, rejects a private/loopback/
                        // link-local resolved address, and pins the exact
                        // validated IpAddr into a fresh single-use client for
                        // the POST — no separate, independently-resolving
                        // `client.post()` call remains, so `reqwest` cannot
                        // re-resolve DNS between the check and the send
                        // (D-01c). `allow_private=false`: this is the
                        // production delivery path, never the test seam.
                        let body_for_send = body.clone();
                        let delivery_id_header = delivery_id.to_string();
                        let signature_header = signature.clone();
                        let event_type_header = event_type.clone();
                        let result = ssrf::guarded_fetch(&webhook.url, false, move |c, u| {
                            c.post(u)
                                .header("Content-Type", "application/json")
                                .header("X-Axiam-Signature", &signature_header)
                                .header("X-Axiam-Event", &event_type_header)
                                .header("X-Axiam-Delivery", &delivery_id_header)
                                .body(body_for_send.clone())
                        })
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
                            // SSRF block/invalid-url/resolve-failure is a
                            // fail-closed verdict on the target itself —
                            // retrying would just repeat the same rejection,
                            // so abort all remaining attempts (preserves the
                            // pre-existing "abort on SSRF block" behavior).
                            Err(
                                e @ (SsrfError::Blocked
                                | SsrfError::InvalidUrl
                                | SsrfError::ResolveFailed),
                            ) => {
                                let webhook_err: WebhookError = e.into();
                                tracing::warn!(
                                    webhook_id = %webhook.id,
                                    %delivery_id,
                                    error = %webhook_err,
                                    "SSRF check failed — aborting all delivery retries"
                                );
                                return;
                            }
                            // A transport-level failure (connection refused,
                            // timeout, TLS error, too-many-redirects) is not
                            // an SSRF verdict — allow the existing
                            // exponential-backoff retry loop to try again.
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

    // ---- SSRF protection tests (SEC-019/SECHRD-02) ----
    //
    // These exercise the shared `axiam_federation::ssrf` guard directly
    // (rather than a local duplicate) to prove webhook.rs genuinely forwards
    // to it and no byte-identical copy of the classification logic remains
    // (D-01a). Guard-internal edge cases already have their own coverage in
    // `axiam_federation::ssrf`'s test module (25-01).

    #[test]
    fn webhook_ssrf_loopback_v4_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert!(ssrf::is_disallowed_ip(ip), "127.0.0.1 must be blocked");
    }

    #[test]
    fn webhook_ssrf_rfc1918_10x_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(ssrf::is_disallowed_ip(ip), "10.x must be blocked");
    }

    #[test]
    fn webhook_ssrf_rfc1918_172_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        assert!(ssrf::is_disallowed_ip(ip), "172.16.x must be blocked");
    }

    #[test]
    fn webhook_ssrf_rfc1918_192168_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(ssrf::is_disallowed_ip(ip), "192.168.x must be blocked");
    }

    #[test]
    fn webhook_ssrf_link_local_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1));
        assert!(
            ssrf::is_disallowed_ip(ip),
            "169.254.x link-local must be blocked"
        );
    }

    #[test]
    fn webhook_ssrf_broadcast_blocked() {
        let ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
        assert!(ssrf::is_disallowed_ip(ip), "broadcast must be blocked");
    }

    #[test]
    fn webhook_ssrf_loopback_v6_blocked() {
        let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        assert!(ssrf::is_disallowed_ip(ip), "::1 must be blocked");
    }

    #[test]
    fn webhook_ssrf_link_local_v6_blocked() {
        // fe80::1
        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert!(
            ssrf::is_disallowed_ip(ip),
            "fe80:: link-local must be blocked"
        );
    }

    #[test]
    fn webhook_ssrf_public_ipv4_allowed() {
        let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)); // example.com
        assert!(!ssrf::is_disallowed_ip(ip), "public IP must be allowed");
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
        let result = ssrf::resolve_and_pick("127.0.0.1", 443, false).await;
        assert!(
            matches!(result, Err(SsrfError::Blocked)),
            "127.0.0.1 must be SSRF-blocked, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn webhook_ssrf_resolve_rfc1918_url_blocked() {
        let result = ssrf::resolve_and_pick("10.0.0.1", 443, false).await;
        assert!(
            matches!(result, Err(SsrfError::Blocked)),
            "10.x must be SSRF-blocked, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn webhook_ssrf_resolve_192168_blocked() {
        let result = ssrf::resolve_and_pick("192.168.1.1", 443, false).await;
        assert!(
            matches!(result, Err(SsrfError::Blocked)),
            "192.168.x must be blocked"
        );
    }

    /// SECHRD-02: a blocked target must map through `WebhookError::SsrfBlocked`
    /// (and therefore the existing fail-closed `AxiamApiError` mapping), not a
    /// panic or a generic error — proving the `From<SsrfError> for WebhookError`
    /// bridge added in this plan.
    #[test]
    fn ssrf_error_blocked_maps_to_webhook_error_ssrf_blocked() {
        let err: WebhookError = SsrfError::Blocked.into();
        assert!(matches!(err, WebhookError::SsrfBlocked));
    }

    // SEC-031: round-trip encrypt/decrypt of webhook secret
    #[test]
    fn webhook_secret_encrypt_decrypt_round_trip() {
        let key = [0x42u8; 32];
        let secret = "super-secret-hmac-key";
        let encrypted = encrypt_webhook_secret(&key, secret).expect("encrypt");
        assert_ne!(
            encrypted, secret,
            "encrypted value must differ from plaintext"
        );

        let decrypted_bytes = aes256gcm_decrypt(&key, &encrypted).expect("decrypt");
        let decrypted = String::from_utf8(decrypted_bytes).expect("utf8");
        assert_eq!(decrypted, secret);
    }
}

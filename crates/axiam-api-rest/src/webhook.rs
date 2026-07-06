//! Webhook delivery service — split into a publish-only `emit()` and a
//! single-attempt `deliver_once()` (CORR-03/D-06/D-07).
//!
//! The old `deliver()` was a detached `tokio::spawn` running an in-process
//! `tokio::time::sleep` exponential-backoff retry loop with ZERO call
//! sites — it died on process restart and never actually ran (CORR-03).
//! `emit()` now only publishes one `axiam_amqp::WebhookMessage` per matching
//! webhook onto the durable `axiam.webhook` AMQP topology (declared via
//! `axiam_amqp::connection::declare_webhook_topology`); `deliver_once()` is
//! the single-attempt HTTP delivery the AMQP consumer (wired in 26-07)
//! drives per (re)delivery. Retry scheduling is now owned by RabbitMQ's
//! native per-message TTL + dead-letter-exchange pair on the retry queue,
//! not by an in-process sleep (D-07).
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
//!
//! D-10: signatures use the Stripe-style signed-timestamp scheme
//! (`X-Axiam-Timestamp` + `X-Axiam-Signature: t=<unix>,v1=<hex>`) rather
//! than a body-only HMAC, so a receiver can enforce a replay window and a
//! forged signature can't be produced from the body alone (T-26-03-01). No
//! SDK (Rust/TS/Go/Python/Java/C#/PHP) implements a webhook-signature
//! verification helper today (confirmed via `grep -rn` across `sdks/` for
//! `X-Axiam-Signature`/`WebhookSignature`/`verify_webhook` — only hits are
//! the CRUD schema in `sdks/openapi.json`), so there is nothing downstream
//! to update for this format change.

use axiam_auth::crypto::{aes256gcm_decrypt, aes256gcm_encrypt};
use axiam_core::repository::WebhookRepository;
use axiam_federation::ssrf::{self, SsrfError};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::StatusCode;
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
    /// The webhook row could not be fetched (not found, or a repository
    /// error) when `deliver_once` tried to resolve it by ID. Distinct from
    /// the crypto-flavored variants above so a consumer (26-07) can tell a
    /// missing/deleted webhook apart from a decrypt failure.
    #[error("webhook lookup failed: {0}")]
    WebhookLookupFailed(String),
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
            WebhookError::WebhookLookupFailed(msg) => {
                axiam_core::error::AxiamError::WebhookDelivery(msg).into()
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

/// Webhook delivery service.
///
/// `emit()` publishes matching-webhook delivery messages onto the durable
/// `axiam.webhook` AMQP topology; `deliver_once()` performs a single
/// SSRF-guarded HTTP attempt for the AMQP consumer (26-07) to drive per
/// (re)delivery.
#[derive(Clone)]
pub struct WebhookDeliveryService<W> {
    repo: W,
    /// AES-256-GCM key used to encrypt/decrypt webhook secrets stored at
    /// rest. Corresponds to `AXIAM__PKI__ENCRYPTION_KEY` (SEC-031/SEC-059).
    /// `None` when the env var is unset — the server still boots (this is
    /// an optional subsystem), but registration (`encrypt_secret`) and
    /// delivery (`deliver_once`) both refuse to operate rather than falling
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

    /// Publish-only replacement for the old `deliver()` (D-06): fetches the
    /// webhooks matching `event_type` for `tenant_id` and publishes ONE
    /// `axiam_amqp::WebhookMessage` per webhook via the injected
    /// `WebhookPublisher`. Performs no HTTP call and does not spawn a
    /// detached task — the AMQP consumer (wired in 26-07) drives
    /// `deliver_once` per (re)delivery.
    pub async fn emit(
        &self,
        publisher: &axiam_amqp::WebhookPublisher,
        tenant_id: Uuid,
        event_type: String,
        payload: serde_json::Value,
    ) {
        let webhooks = match self.repo.get_by_event(tenant_id, &event_type).await {
            Ok(w) => w,
            Err(e) => {
                tracing::error!(
                    %tenant_id, %event_type,
                    "failed to fetch webhooks for emit: {e}"
                );
                return;
            }
        };

        for webhook in webhooks {
            let msg = axiam_amqp::WebhookMessage {
                webhook_id: webhook.id,
                delivery_id: Uuid::new_v4(),
                tenant_id,
                event_type: event_type.clone(),
                payload: payload.clone(),
                attempt: 0,
            };

            if let Err(e) = publisher.publish(&msg).await {
                tracing::error!(
                    webhook_id = %webhook.id,
                    %tenant_id, %event_type,
                    "failed to publish webhook delivery message: {e}"
                );
            }
        }
    }

    /// Single-attempt webhook delivery (D-06/D-07). Decrypts the stored
    /// secret, computes the Stripe-style signed-timestamp signature (D-10),
    /// and performs exactly one `ssrf::guarded_fetch` POST. Contains NO
    /// retry loop and NO in-process delay — AMQP TTL+DLX (declared via
    /// `axiam_amqp::connection::AmqpManager::declare_webhook_topology`) now
    /// owns retry scheduling. Returns `Ok(StatusCode)` (which may be a
    /// non-2xx status) or `Err(WebhookError)` and leaves the ack/nack/
    /// republish-to-retry-queue decision to the caller (the AMQP consumer,
    /// wired in 26-07).
    ///
    /// `tenant_id` scopes the webhook lookup — `WebhookRepository::get_by_id`
    /// is tenant-scoped per AXIAM's multi-tenant data-isolation model. The
    /// caller resolves it from the `WebhookMessage.tenant_id` field this
    /// plan adds to the DTO (not present in the original plan sketch, which
    /// omitted it — added here because tenant-scoping the lookup is a
    /// correctness/data-isolation requirement, not optional).
    pub async fn deliver_once(
        &self,
        tenant_id: Uuid,
        webhook_id: Uuid,
        delivery_id: Uuid,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<StatusCode, WebhookError> {
        // D-01/SEC-059: refuse delivery (fail-closed) when no encryption key
        // is configured — never decrypt stored secrets with a
        // placeholder/all-zero key.
        let encryption_key = self
            .encryption_key
            .ok_or(WebhookError::EncryptionKeyMissing)?;

        let webhook = self
            .repo
            .get_by_id(tenant_id, webhook_id)
            .await
            .map_err(|e| WebhookError::WebhookLookupFailed(e.to_string()))?;

        let body = serde_json::to_string(payload).unwrap_or_default();

        // SEC-031: Decrypt the stored secret before HMAC computation.
        let plaintext_secret = match aes256gcm_decrypt(&encryption_key, &webhook.secret) {
            Ok(bytes) => String::from_utf8(bytes)
                .map_err(|e| WebhookError::SecretDecrypt(format!("secret not valid UTF-8: {e}")))?,
            Err(e) => return Err(WebhookError::SecretDecrypt(e.to_string())),
        };

        let timestamp = Utc::now().timestamp();
        let signature = compute_signature_v2(&plaintext_secret, timestamp, &body);

        // SEC-019/SECHRD-02: `guarded_fetch` resolves the host fresh on this
        // attempt, rejects a private/loopback/link-local resolved address,
        // and pins the exact validated IpAddr into a fresh single-use client
        // for the POST — no separate, independently-resolving `client.post()`
        // call remains, so `reqwest` cannot re-resolve DNS between the check
        // and the send (D-01c). `allow_private=false`: this is the
        // production delivery path, never the test seam.
        let body_for_send = body.clone();
        let timestamp_header = timestamp.to_string();
        let signature_header = signature.clone();
        let event_type_header = event_type.to_string();
        let delivery_id_header = delivery_id.to_string();
        let result = ssrf::guarded_fetch(&webhook.url, false, move |c, u| {
            c.post(u)
                .header("Content-Type", "application/json")
                .header("X-Axiam-Timestamp", &timestamp_header)
                .header("X-Axiam-Signature", &signature_header)
                .header("X-Axiam-Event", &event_type_header)
                .header("X-Axiam-Delivery", &delivery_id_header)
                .body(body_for_send.clone())
        })
        .await;

        match result {
            Ok(resp) => {
                let status = resp.status();
                tracing::info!(
                    webhook_id = %webhook_id,
                    %delivery_id,
                    %event_type,
                    %status,
                    "webhook delivery attempt completed"
                );
                Ok(status)
            }
            Err(e) => {
                let webhook_err: WebhookError = e.into();
                tracing::warn!(
                    webhook_id = %webhook_id,
                    %delivery_id,
                    %event_type,
                    error = %webhook_err,
                    "webhook delivery attempt failed"
                );
                Err(webhook_err)
            }
        }
    }
}

/// Compute the Stripe-style signed-timestamp signature (D-10): HMAC-SHA256
/// over the ASCII string `<timestamp>.<body>` using the per-webhook secret,
/// returned as `t=<unix_seconds>,v1=<hex>`. Binding the timestamp into the
/// signed payload (not just the body) lets a receiver enforce a replay
/// window, and prevents a body-only forgery that doesn't need to also guess
/// a valid timestamp (T-26-03-01).
fn compute_signature_v2(secret: &str, timestamp: i64, body: &str) -> String {
    let signed_payload = format!("{timestamp}.{body}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(signed_payload.as_bytes());
    format!(
        "t={timestamp},v1={}",
        hex::encode(mac.finalize().into_bytes())
    )
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
    fn signature_v2_is_deterministic() {
        let sig1 = compute_signature_v2("secret", 1_700_000_000, "hello");
        let sig2 = compute_signature_v2("secret", 1_700_000_000, "hello");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn signature_v2_different_secrets_produce_different_signatures() {
        let sig1 = compute_signature_v2("secret1", 1_700_000_000, "hello");
        let sig2 = compute_signature_v2("secret2", 1_700_000_000, "hello");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn signature_v2_matches_stripe_style_format() {
        let sig = compute_signature_v2("secret", 1_700_000_000, "hello");
        let re = regex_lite_match_t_v1(&sig);
        assert!(
            re,
            "signature must match ^t=\\d+,v1=[0-9a-f]{{64}}$, got: {sig}"
        );
    }

    #[test]
    fn signature_v2_different_timestamps_produce_different_signatures() {
        let sig1 = compute_signature_v2("secret", 1_700_000_000, "hello");
        let sig2 = compute_signature_v2("secret", 1_700_000_001, "hello");
        assert_ne!(
            sig1, sig2,
            "binding the timestamp into the signed payload must change the signature"
        );
    }

    /// Minimal hand-rolled matcher for `^t=\d+,v1=[0-9a-f]{64}$` — avoids
    /// pulling in a `regex` dependency for a single test assertion.
    fn regex_lite_match_t_v1(s: &str) -> bool {
        let Some(rest) = s.strip_prefix("t=") else {
            return false;
        };
        let Some((digits, rest)) = rest.split_once(",v1=") else {
            return false;
        };
        !digits.is_empty()
            && digits.chars().all(|c| c.is_ascii_digit())
            && rest.len() == 64
            && rest.chars().all(|c| c.is_ascii_hexdigit())
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

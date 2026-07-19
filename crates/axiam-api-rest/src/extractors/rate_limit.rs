//! Rate-limit key extractor using X-Forwarded-For header (per D-02, SEC-048).
//!
//! SEC-048: The extractor selects the *rightmost untrusted* hop from the
//! X-Forwarded-For header to prevent IP-spoofing based rate-limit evasion.
//! The `trusted_hops` value should equal the number of trusted reverse-proxy
//! hops (e.g. 1 for a single nginx/ingress in front of the server).
//!
//! Example:
//!   X-Forwarded-For: <attacker-ip>, <real-client-ip>, <trusted-proxy-ip>
//!   trusted_hops = 1 → selects <real-client-ip> (skip 1 from right)
//!
//! Falls back to the direct peer address when the header is absent, unparseable,
//! or has fewer hops than `trusted_hops` (a client cannot manufacture extra
//! trusted hops to force a fallback to an attacker-controlled entry: when there
//! are not enough hops to trust, the XFF header is ignored entirely and the key
//! is derived from `peer_addr()`).
//!
//! **nginx/ingress requirement**: The upstream proxy MUST append the real client
//! IP to the RIGHT of X-Forwarded-For (not inject it at position 0) for this to
//! be effective. With `proxy_add_x_forwarded_for` in nginx this is the default
//! behaviour — the real client is the RIGHTMOST trusted entry, not the leftmost.

use actix_governor::governor::NotUntil;
use actix_governor::governor::clock::{Clock, DefaultClock, QuantaInstant};
use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::HttpMessage;
use actix_web::HttpResponse;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::{ContentType, RETRY_AFTER};
use std::net::IpAddr;

use crate::config::rate_limit::RateLimitKeyMode;

/// Extracts client IP from X-Forwarded-For header, falls back to peer address.
///
/// `trusted_hops` controls how many rightmost entries in the XFF header to skip
/// (they come from trusted proxies). The selected entry is the **rightmost
/// untrusted** hop — `idx = len - 1 - trusted_hops` — which is correct for a
/// single trusted reverse proxy that right-appends the real client IP (nginx
/// `proxy_add_x_forwarded_for`). `trusted_hops = 1` selects the client IP a
/// single proxy appended; `trusted_hops = 0` selects the rightmost entry
/// verbatim. (SEC-070: earlier doc text wrongly described this as using the
/// *leftmost* entry — the leftmost is the most attacker-controllable position
/// and is never used.)
#[derive(Debug, Clone, Default)]
pub struct XForwardedForKeyExtractor {
    /// Number of trusted reverse-proxy hops to skip from the right of
    /// the X-Forwarded-For list. Set to the number of load-balancers/
    /// ingress proxies between the client and this server.
    ///
    /// Default: 0 (rightmost entry). NOTE: when the server is exposed directly
    /// (no proxy), a client can still set XFF to mint fresh rate-limit buckets;
    /// deploy behind a proxy that overwrites/right-appends XFF and set
    /// `trusted_hops` to the proxy count so the untrusted client value is
    /// skipped.
    pub trusted_hops: usize,
}

impl XForwardedForKeyExtractor {
    /// Create an extractor that uses the rightmost-untrusted hop.
    /// `trusted_hops` = number of trusted proxy entries from the right.
    pub fn with_trusted_hops(trusted_hops: usize) -> Self {
        Self { trusted_hops }
    }
}

impl KeyExtractor for XForwardedForKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        if let Some(forwarded_for) = req.headers().get("X-Forwarded-For")
            && let Ok(val) = forwarded_for.to_str()
        {
            let hops: Vec<&str> = val.split(',').map(str::trim).collect();
            // Select the rightmost-untrusted hop.
            // hops = [client, proxy1, ..., trusted_proxy]
            // trusted_hops=1 → index = len - 1 - 1 = len - 2
            if self.trusted_hops < hops.len() {
                let idx = hops.len() - 1 - self.trusted_hops;
                if let Ok(ip) = hops[idx].parse::<IpAddr>() {
                    return Ok(ip);
                }
            }
            // Fewer hops than trusted_hops requires: the header cannot be
            // trusted at all (an attacker could otherwise rotate it to get a
            // fresh bucket per request via the old `hops[0]` fallback — SECHRD-03).
            // Fall through to peer_addr() below instead of indexing into XFF.
        }
        req.peer_addr()
            .map(|addr| addr.ip())
            .ok_or_else(|| SimpleKeyExtractionError::new("no peer address"))
    }

    /// Returns a JSON 429 response with Retry-After header per D-03.
    ///
    /// Body: `{"error":"rate_limit_exceeded","retry_after":<seconds>}`
    fn exceed_rate_limit_response(
        &self,
        negative: &NotUntil<QuantaInstant>,
        mut response: actix_web::HttpResponseBuilder,
    ) -> HttpResponse {
        let wait_secs = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        response
            .content_type(ContentType::json())
            .insert_header((RETRY_AFTER, wait_secs.to_string()))
            .body(format!(
                r#"{{"error":"rate_limit_exceeded","retry_after":{}}}"#,
                wait_secs
            ))
    }
}

// ---------------------------------------------------------------------------
// D8 — client-identity-aware keying (token/introspect/revoke only)
// ---------------------------------------------------------------------------

/// Request-extension carrying the `client_id` (if any) parsed from the
/// request body by
/// [`crate::middleware::rate_limit_shared::RateLimitShared`]'s
/// client-identity-aware constructor, so [`ClientAwareKeyExtractor`] (used
/// by the in-memory `Governor` on the SAME resource) doesn't need to peek
/// the body a second time.
///
/// Ordering guarantee this relies on: in `server.rs`, `RateLimitShared` is
/// always the OUTER `.wrap()` (last one added — see the module docs on
/// `RateLimitShared`), so it always runs BEFORE the `Governor` middleware
/// and always inserts this extension (`None` when no `client_id` could be
/// parsed, or when the configured key mode is `ip`) before delegating.
/// `Governor`'s [`ClientAwareKeyExtractor`] treats a *missing* extension
/// (e.g. if the two middlewares were ever mis-ordered) identically to
/// `None` — it falls back to the IP key, never panics.
#[derive(Debug, Clone, Default)]
pub struct RateLimitClientId(pub Option<String>);

/// Parses the `client_id` field out of an `application/x-www-form-urlencoded`
/// body — the ONLY client-authentication style AXIAM's `/oauth2/token`,
/// `/oauth2/revoke`, and `/oauth2/introspect` handlers accept
/// (`client_secret_post`, RFC 6749 §2.3.1; see `handlers::oauth2` and
/// `axiam_oauth2::token::{TokenRequest, RevokeRequest, IntrospectRequest}`,
/// all form-decoded via `web::Form<..>`).
///
/// Returns `None` for a missing/empty/unparseable `client_id` — the caller
/// (the rate limiter) must fail SAFE by falling back to the IP key rather
/// than reject the request outright; rejecting a malformed body is the
/// handler's job (it returns a proper RFC 6749 `invalid_request` error),
/// not the rate limiter's.
pub fn extract_form_client_id(body: &[u8]) -> Option<String> {
    url::form_urlencoded::parse(body)
        .find(|(k, _)| k == "client_id")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.is_empty())
}

/// D8 key extractor for the token/introspect/revoke endpoints: honors
/// `AXIAM__RATE_LIMIT__KEY` (`ip` | `client_id` | `ip_client_id`) to key the
/// in-memory `Governor` bucket on the OAuth2 `client_id`, the `(ip,
/// client_id)` pair, or (default, unchanged behavior) IP alone.
///
/// **Never wire this onto `/auth/login` or any other endpoint without a
/// client identity** — see [`crate::config::rate_limit::RateLimitKeyMode`]
/// for why login is structurally excluded (it authenticates a user, not an
/// OAuth2 client; there is no `client_id` to key on at that point).
#[derive(Debug, Clone)]
pub struct ClientAwareKeyExtractor {
    /// Always computed alongside the client_id — used verbatim in `Ip`
    /// mode, and as a namespace-safety prefix in `IpClientId` mode.
    pub ip_extractor: XForwardedForKeyExtractor,
    pub key_mode: RateLimitKeyMode,
}

impl ClientAwareKeyExtractor {
    pub fn new(ip_extractor: XForwardedForKeyExtractor, key_mode: RateLimitKeyMode) -> Self {
        Self {
            ip_extractor,
            key_mode,
        }
    }
}

impl KeyExtractor for ClientAwareKeyExtractor {
    type Key = String;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        let ip = self.ip_extractor.extract(req)?;

        let client_id = req
            .extensions()
            .get::<RateLimitClientId>()
            .and_then(|c| c.0.clone());

        Ok(match (self.key_mode, client_id) {
            // `ip` mode, or no client_id available (fail-safe fallback):
            // identical to the pre-D8 IP-only key.
            (RateLimitKeyMode::Ip, _) | (_, None) => ip.to_string(),
            (RateLimitKeyMode::ClientId, Some(cid)) => format!("client:{cid}"),
            (RateLimitKeyMode::IpClientId, Some(cid)) => format!("{ip}:client:{cid}"),
        })
    }

    /// Same 429 contract as [`XForwardedForKeyExtractor`] — clients must
    /// see one consistent rate-limit response shape regardless of which key
    /// mode rejected the request.
    fn exceed_rate_limit_response(
        &self,
        negative: &NotUntil<QuantaInstant>,
        mut response: actix_web::HttpResponseBuilder,
    ) -> HttpResponse {
        let wait_secs = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        response
            .content_type(ContentType::json())
            .insert_header((RETRY_AFTER, wait_secs.to_string()))
            .body(format!(
                r#"{{"error":"rate_limit_exceeded","retry_after":{}}}"#,
                wait_secs
            ))
    }
}

#[cfg(test)]
mod client_aware_tests {
    use super::*;
    use actix_web::test::TestRequest;
    use std::net::SocketAddr;

    const PEER_A: &str = "203.0.113.9:1";
    const PEER_B: &str = "203.0.113.10:2";

    fn req_with_client_id(peer: &str, client_id: Option<&str>) -> ServiceRequest {
        let req = TestRequest::get()
            .peer_addr(peer.parse::<SocketAddr>().unwrap())
            .to_srv_request();
        req.extensions_mut()
            .insert(RateLimitClientId(client_id.map(str::to_owned)));
        req
    }

    #[test]
    fn ip_mode_ignores_client_id_and_matches_plain_ip_extractor() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::Ip,
        );
        let req = req_with_client_id(PEER_A, Some("client-a"));

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "203.0.113.9");
    }

    #[test]
    fn client_id_mode_gives_independent_buckets_per_client_under_one_ip() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );

        let req_a = req_with_client_id(PEER_A, Some("client-a"));
        let req_b = req_with_client_id(PEER_A, Some("client-b"));

        let key_a = extractor.extract(&req_a).unwrap();
        let key_b = extractor.extract(&req_b).unwrap();

        assert_ne!(
            key_a, key_b,
            "distinct client_ids behind the SAME IP must get distinct buckets (D8 NAT fix)"
        );
        assert!(!key_a.contains("203.0.113.9"));
    }

    #[test]
    fn client_id_mode_gives_same_bucket_for_same_client_from_different_ips() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );

        let req_a = req_with_client_id(PEER_A, Some("client-a"));
        let req_b = req_with_client_id(PEER_B, Some("client-a"));

        assert_eq!(
            extractor.extract(&req_a).unwrap(),
            extractor.extract(&req_b).unwrap()
        );
    }

    #[test]
    fn ip_client_id_mode_distinguishes_both_dimensions() {
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::IpClientId,
        );

        let same_client_diff_ip_a = req_with_client_id(PEER_A, Some("client-a"));
        let same_client_diff_ip_b = req_with_client_id(PEER_B, Some("client-a"));
        let diff_client_same_ip = req_with_client_id(PEER_A, Some("client-b"));

        let key1 = extractor.extract(&same_client_diff_ip_a).unwrap();
        let key2 = extractor.extract(&same_client_diff_ip_b).unwrap();
        let key3 = extractor.extract(&diff_client_same_ip).unwrap();

        assert_ne!(
            key1, key2,
            "same client_id from different IPs must differ in ip_client_id mode"
        );
        assert_ne!(
            key1, key3,
            "different client_id from same IP must differ in ip_client_id mode"
        );
    }

    #[test]
    fn missing_client_id_falls_back_to_ip_even_in_client_id_mode() {
        // Fail-SAFE: malformed/no client_id must not disable rate limiting —
        // it must still be limited, just by the coarser IP key.
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );
        let req = req_with_client_id(PEER_A, None);

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "203.0.113.9");
    }

    #[test]
    fn missing_extension_entirely_falls_back_to_ip() {
        // Defense in depth: if RateLimitShared never ran (mis-ordering bug),
        // the extractor must not panic — it degrades to IP-only, matching
        // pre-D8 behavior rather than failing open or crashing.
        let extractor = ClientAwareKeyExtractor::new(
            XForwardedForKeyExtractor::default(),
            RateLimitKeyMode::ClientId,
        );
        let req = TestRequest::get()
            .peer_addr(PEER_A.parse::<SocketAddr>().unwrap())
            .to_srv_request();

        let key = extractor.extract(&req).unwrap();
        assert_eq!(key, "203.0.113.9");
    }

    #[test]
    fn extract_form_client_id_parses_and_rejects_empty() {
        assert_eq!(
            extract_form_client_id(
                b"grant_type=client_credentials&client_id=abc123&client_secret=s"
            ),
            Some("abc123".to_string())
        );
        assert_eq!(extract_form_client_id(b"client_id=&grant_type=x"), None);
        assert_eq!(extract_form_client_id(b"grant_type=x"), None);
        assert_eq!(extract_form_client_id(b""), None);
    }
}

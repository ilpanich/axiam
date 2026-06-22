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
//! or has fewer hops than `trusted_hops`.
//!
//! **nginx/ingress requirement**: The upstream proxy MUST append the real client
//! IP to X-Forwarded-For (not inject it at position 0) for this to be effective.
//! With `proxy_add_x_forwarded_for` in nginx this is the default behaviour.

use actix_governor::governor::NotUntil;
use actix_governor::governor::clock::{Clock, DefaultClock, QuantaInstant};
use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::HttpResponse;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::{ContentType, RETRY_AFTER};
use std::net::IpAddr;

/// Extracts client IP from X-Forwarded-For header, falls back to peer address.
///
/// `trusted_hops` controls how many rightmost entries in the XFF header to skip
/// (they come from trusted proxies). A value of 0 uses the leftmost entry
/// (original behaviour); 1 skips 1 trusted hop from the right.
#[derive(Debug, Clone, Default)]
pub struct XForwardedForKeyExtractor {
    /// Number of trusted reverse-proxy hops to skip from the right of
    /// the X-Forwarded-For list. Set to the number of load-balancers/
    /// ingress proxies between the client and this server.
    ///
    /// Default: 0 (use leftmost; compatible with previous behaviour).
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
            let idx = if self.trusted_hops < hops.len() {
                hops.len() - 1 - self.trusted_hops
            } else {
                // Fewer hops than expected: fall through to peer address.
                0
            };
            if let Ok(ip) = hops[idx].parse::<IpAddr>() {
                return Ok(ip);
            }
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

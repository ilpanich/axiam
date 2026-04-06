//! Rate-limit key extractor using X-Forwarded-For header (per D-02).

use actix_governor::governor::NotUntil;
use actix_governor::governor::clock::{Clock, DefaultClock, QuantaInstant};
use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
use actix_web::HttpResponse;
use actix_web::dev::ServiceRequest;
use actix_web::http::header::{ContentType, RETRY_AFTER};
use std::net::IpAddr;

/// Extracts client IP from X-Forwarded-For header, falls back to peer address.
///
/// Per D-02: use the leftmost non-private IP in X-Forwarded-For, falling back
/// to the direct peer address when the header is absent or unparseable.
#[derive(Debug, Clone)]
pub struct XForwardedForKeyExtractor;

impl KeyExtractor for XForwardedForKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        if let Some(forwarded_for) = req.headers().get("X-Forwarded-For")
            && let Ok(val) = forwarded_for.to_str()
            && let Some(first) = val.split(',').next()
            && let Ok(ip) = first.trim().parse::<IpAddr>()
        {
            return Ok(ip);
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

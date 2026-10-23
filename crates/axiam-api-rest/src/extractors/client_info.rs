//! Shared, capped helpers for extracting client IP and User-Agent from a request.
//!
//! Lengths are capped to prevent oversized strings from entering audit logs or
//! being stored in the database.  IPv6 with zone ID fits in 45 chars; a
//! reasonable User-Agent fits in 512.

use actix_web::HttpRequest;
use axiam_core::forwarded_for::{TrustedProxies, forwarded_for_header, select_client_ip};

/// Maximum length for an IP address string (IPv6 with zone ID = 45 chars).
pub const MAX_IP_LEN: usize = 45;
/// Maximum length for a User-Agent string.
pub const MAX_UA_LEN: usize = 512;

/// Extract the client IP by the rate limiters' rule, capped to [`MAX_IP_LEN`].
///
/// The rightmost untrusted `X-Forwarded-For` hop under
/// `AXIAM__RATE_LIMIT__TRUSTED_HOPS`, read only from a peer inside
/// `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` (every peer with the list empty);
/// otherwise the transport peer ([`axiam_core::forwarded_for::select_client_ip`]).
/// The audit rows and the `http.client_ip` log field follow the same rule
/// (#752, T-212), so a row, a log line and a rate-limit bucket name one address.
///
/// # What this still is not
///
/// With `TRUSTED_PROXIES` empty (the default) every peer's header is read, so
/// behind no appending proxy the value is whatever the caller typed. List the
/// proxies in front of the server to close that; on an **unauthenticated** path
/// [`peer_ip`] is still the stricter choice (SEC-087, §22.3).
pub fn client_ip(req: &HttpRequest) -> Option<String> {
    client_ip_with(
        req,
        axiam_core::forwarded_for::configured_trusted_hops(),
        &TrustedProxies::configured(),
    )
}

/// [`client_ip`] under an explicit rule — the seam tests inject instead of
/// mutating the process environment.
pub fn client_ip_with(
    req: &HttpRequest,
    trusted_hops: usize,
    trusted_proxies: &TrustedProxies,
) -> Option<String> {
    // Every field line, not the first (#796).
    let forwarded_for = forwarded_for_header(
        req.headers()
            .get_all("X-Forwarded-For")
            .map(|v| v.as_bytes()),
    );
    select_client_ip(
        forwarded_for.as_deref(),
        req.peer_addr().map(|addr| addr.ip()),
        trusted_hops,
        trusted_proxies,
    )
    .ip
    .map(|ip| ip.to_string().chars().take(MAX_IP_LEN).collect())
}

/// Extract the **transport peer address**, capped to [`MAX_IP_LEN`].
///
/// Unlike [`client_ip`], this ignores `X-Forwarded-For` / `X-Real-IP` entirely
/// and reports the address the connection actually came from. Behind a trusted
/// reverse proxy that is the proxy's own address, which is why [`client_ip`]
/// remains the right choice on authenticated paths.
///
/// Use this on **unauthenticated** endpoints, where the forwarding headers are
/// caller-supplied and therefore forgeable (SEC-087): an attacker who can pick
/// the IP written to an audit row can make an operator act against an innocent
/// host. Callers that want both should record this as the trusted value and
/// keep [`client_ip`] alongside it, explicitly labelled untrusted.
pub fn peer_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .peer_addr()
        .map(|s| s.chars().take(MAX_IP_LEN).collect())
}

/// Extract the `User-Agent` header value, capped to [`MAX_UA_LEN`].
pub fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(MAX_UA_LEN).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;

    fn proxies() -> TrustedProxies {
        TrustedProxies::parse("10.0.0.0/8").unwrap()
    }

    /// The `network_decide` decision rows (and every other handler row) take
    /// their `ip_address` from here, so they follow the limiters' rule (#752).
    #[test]
    fn an_unlisted_peer_is_recorded_as_itself() {
        let req = TestRequest::get()
            .peer_addr("203.0.113.7:1".parse().unwrap())
            .insert_header(("X-Forwarded-For", "1.2.3.4"))
            .to_http_request();
        assert_eq!(
            client_ip_with(&req, 0, &proxies()).as_deref(),
            Some("203.0.113.7")
        );
    }

    /// #796: RFC 9110 joins repeated field lines. A listed proxy that adds
    /// its own line (HAProxy's `option forwardfor`) is read through that
    /// line, not through the client's forged first one.
    #[test]
    fn every_forwarded_for_line_is_read() {
        let req = TestRequest::get()
            .peer_addr("10.0.0.9:1".parse().unwrap())
            .append_header(("X-Forwarded-For", "6.6.6.6"))
            .append_header(("X-Forwarded-For", "198.51.100.5"))
            .to_http_request();
        assert_eq!(
            client_ip_with(&req, 0, &proxies()).as_deref(),
            Some("198.51.100.5")
        );
        // A line that is not visible ASCII makes the header absent: the peer.
        let req = TestRequest::get()
            .peer_addr("10.0.0.9:1".parse().unwrap())
            .append_header(("X-Forwarded-For", "198.51.100.5"))
            .append_header((
                "X-Forwarded-For",
                actix_web::http::header::HeaderValue::from_bytes(b"6.6.6.6\xff").unwrap(),
            ))
            .to_http_request();
        assert_eq!(
            client_ip_with(&req, 0, &proxies()).as_deref(),
            Some("10.0.0.9")
        );
    }

    #[test]
    fn a_listed_peer_yields_the_rightmost_untrusted_hop() {
        let req = TestRequest::get()
            .peer_addr("10.0.0.9:1".parse().unwrap())
            .insert_header(("X-Forwarded-For", "9.9.9.9, 198.51.100.5, 10.0.0.2"))
            .to_http_request();
        assert_eq!(
            client_ip_with(&req, 1, &proxies()).as_deref(),
            Some("198.51.100.5")
        );
    }
}

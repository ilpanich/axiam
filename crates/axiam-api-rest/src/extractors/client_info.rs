//! Shared, capped helpers for extracting client IP and User-Agent from a request.
//!
//! Lengths are capped to prevent oversized strings from entering audit logs or
//! being stored in the database.  IPv6 with zone ID fits in 45 chars; a
//! reasonable User-Agent fits in 512.

use actix_web::HttpRequest;

/// Maximum length for an IP address string (IPv6 with zone ID = 45 chars).
pub const MAX_IP_LEN: usize = 45;
/// Maximum length for a User-Agent string.
pub const MAX_UA_LEN: usize = 512;

/// Extract the real client IP from [`ConnectionInfo`], capped to [`MAX_IP_LEN`].
///
/// Uses `realip_remote_addr` which respects the `X-Forwarded-For` / `X-Real-IP`
/// headers as trusted by the Actix-Web server configuration.
pub fn client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|s| s.chars().take(MAX_IP_LEN).collect())
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

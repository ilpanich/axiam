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

/// Extract the `User-Agent` header value, capped to [`MAX_UA_LEN`].
pub fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(MAX_UA_LEN).collect())
}

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

/// Extract the client IP as *asserted by the request*, capped to [`MAX_IP_LEN`].
///
/// Uses `realip_remote_addr`, which returns the first entry of `X-Forwarded-For`
/// (else `X-Real-IP`, else the peer address).
///
/// # This value is not validated by Actix-Web
///
/// An earlier version of this doc said the headers are honoured "as trusted by
/// the Actix-Web server configuration". That is wrong, and worth correcting
/// rather than softening: Actix-Web has **no trusted-proxy list**. It reads the
/// forwarding headers whenever they are present, so behind no proxy — or behind
/// one that does not overwrite them — this value is whatever the caller typed.
///
/// It is still the right choice on an **authenticated** path behind a proxy
/// that does overwrite `X-Forwarded-For`, which is the deployment this is for.
/// On an **unauthenticated** path use [`peer_ip`] instead, or record this one
/// under a name that marks it untrusted (SEC-087, §22.3).
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

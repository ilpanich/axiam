//! Transport-URL security guard (X-2): reject plaintext (non-TLS) endpoint
//! URLs at construction time.
//!
//! Every AXIAM transport (REST over HTTPS, gRPC over HTTPS, AMQP over AMQPS)
//! must run over TLS — CONTRACT.md §6 mandates TLS 1.3 for all external
//! communication and the SDK forwards tenant identifiers / CSRF tokens /
//! bearer cookies that must never traverse a cleartext link. A plaintext
//! `http://` / `amqp://` base URL is therefore refused up front rather than
//! silently accepted.
//!
//! The single, deliberate exception is a loopback host (`localhost`,
//! `127.0.0.1`, `::1`) so local development / integration tests against a
//! non-TLS dev server still work. This is the only escape hatch; there is no
//! flag to disable the check for a routable host.

/// Returns `true` if `host` is a loopback / localhost literal — the sole
/// allowed exception to the plaintext-transport ban.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    // `url` reports an IPv6 host without the surrounding brackets, but accept
    // the bracketed form too in case a raw authority string is passed in.
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]"
}

/// Validate that `scheme` is the required TLS scheme (`secure_scheme`), unless
/// `host` is a loopback address. On rejection returns a human-readable reason
/// (never containing any secret) suitable for wrapping in an [`crate::AxiamError`].
///
/// `label` names the transport for the error message (e.g. `"base_url"`,
/// `"gRPC base_url"`, `"AMQP url"`).
pub(crate) fn ensure_secure_scheme(
    label: &str,
    scheme: &str,
    host: Option<&str>,
    secure_scheme: &str,
) -> Result<(), String> {
    if scheme.eq_ignore_ascii_case(secure_scheme) {
        return Ok(());
    }
    if host.is_some_and(is_loopback_host) {
        // Loopback dev exception: a non-TLS scheme is tolerated only because
        // the traffic never leaves the local host.
        return Ok(());
    }
    Err(format!(
        "{label} must use the encrypted `{secure_scheme}://` scheme (got \
         `{scheme}://`); plaintext transport is refused because it would expose \
         tenant identifiers, CSRF tokens, and session cookies — the only \
         exception is a loopback host (localhost/127.0.0.1/::1) for local \
         development (X-2, CONTRACT.md §6)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_accepted() {
        assert!(ensure_secure_scheme("base_url", "https", Some("example.com"), "https").is_ok());
    }

    #[test]
    fn plaintext_routable_host_is_rejected() {
        let err = ensure_secure_scheme("base_url", "http", Some("example.com"), "https")
            .expect_err("plaintext http against a routable host must be rejected");
        assert!(err.contains("https"));
        // The reason must not leak anything odd; it should name the schemes.
        assert!(err.contains("http"));
    }

    #[test]
    fn plaintext_loopback_is_allowed() {
        for host in ["localhost", "127.0.0.1", "::1", "[::1]", "LOCALHOST"] {
            assert!(
                ensure_secure_scheme("base_url", "http", Some(host), "https").is_ok(),
                "loopback host {host} must be allowed over plaintext for dev"
            );
        }
    }

    #[test]
    fn amqps_scheme_enforced_for_amqp() {
        assert!(ensure_secure_scheme("AMQP url", "amqps", Some("broker"), "amqps").is_ok());
        assert!(ensure_secure_scheme("AMQP url", "amqp", Some("broker"), "amqps").is_err());
        assert!(ensure_secure_scheme("AMQP url", "amqp", Some("localhost"), "amqps").is_ok());
    }

    #[test]
    fn scheme_comparison_is_case_insensitive() {
        assert!(ensure_secure_scheme("base_url", "HTTPS", Some("example.com"), "https").is_ok());
    }
}

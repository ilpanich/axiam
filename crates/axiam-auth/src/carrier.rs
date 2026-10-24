//! Where on a request an access token travels, decided once.
//!
//! Two readers look for the caller's access token: the audit middleware (to name
//! the actor in the request row) and the REST extractors (to authenticate the
//! request). They used to apply opposite precedence — the middleware read the
//! `Authorization` header and ignored the cookie whenever a header existed, the
//! extractors read the cookie and ignored the header — so a request carrying a
//! valid `axiam_access` cookie and an unrelated header (`Authorization: Basic …`,
//! a proxy's own credential) was admitted as the cookie's user and recorded as
//! `System` with a nil tenant (#751, R111-01). Both now call
//! [`access_token_carrier`].
//!
//! The helper takes the two raw header values rather than a request, because
//! this crate does not depend on actix; each caller reads its own request type.

/// The channel an access token was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// The `axiam_access` cookie (browser clients, the admin UI).
    Cookie,
    /// `Authorization: Bearer <token>`.
    Bearer,
    /// `Authorization: DPoP <token>` (RFC 9449 §7.1).
    Dpop,
}

/// Name of the cookie that carries the access token.
pub const ACCESS_COOKIE: &str = "axiam_access";

/// Pick the token a request presents: the `axiam_access` cookie first, then an
/// `Authorization` header with a `Bearer` or `DPoP` scheme.
///
/// Returns `None` when neither carries a candidate — an absent or empty cookie,
/// and a header with another scheme (`Basic`), no scheme, or no credentials. A
/// header that is not a token carrier therefore never shadows the cookie. The
/// candidate is not verified here; the caller validates it.
pub fn access_token_carrier<'a>(
    cookie: Option<&'a str>,
    authorization: Option<&'a str>,
) -> Option<(Carrier, &'a str)> {
    if let Some(value) = cookie.map(str::trim).filter(|v| !v.is_empty()) {
        return Some((Carrier::Cookie, value));
    }
    let header = authorization?.trim();
    let mut parts = header.splitn(2, char::is_whitespace);
    let scheme = parts.next().unwrap_or("");
    let credentials = parts.next().unwrap_or("").trim();
    if credentials.is_empty() {
        return None;
    }
    // Case-insensitive scheme, RFC 9110 §11.1.
    if scheme.eq_ignore_ascii_case("bearer") {
        Some((Carrier::Bearer, credentials))
    } else if scheme.eq_ignore_ascii_case("dpop") {
        Some((Carrier::Dpop, credentials))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_wins_over_any_header() {
        assert_eq!(
            access_token_carrier(Some("c"), Some("Bearer h")),
            Some((Carrier::Cookie, "c"))
        );
        assert_eq!(
            access_token_carrier(Some("c"), Some("Basic eDp5")),
            Some((Carrier::Cookie, "c"))
        );
    }

    #[test]
    fn header_schemes_are_case_insensitive() {
        assert_eq!(
            access_token_carrier(None, Some("bEaReR  t")),
            Some((Carrier::Bearer, "t"))
        );
        assert_eq!(
            access_token_carrier(None, Some("dpop t")),
            Some((Carrier::Dpop, "t"))
        );
    }

    #[test]
    fn non_carriers_yield_nothing() {
        assert_eq!(access_token_carrier(None, Some("Basic eDp5")), None);
        assert_eq!(access_token_carrier(None, Some("Bearer   ")), None);
        assert_eq!(access_token_carrier(None, Some("Bearer")), None);
        assert_eq!(access_token_carrier(Some("  "), None), None);
        assert_eq!(access_token_carrier(None, None), None);
    }

    #[test]
    fn empty_cookie_falls_through_to_the_header() {
        assert_eq!(
            access_token_carrier(Some(""), Some("Bearer h")),
            Some((Carrier::Bearer, "h"))
        );
    }
}

/// What the session extractor decided about a request's access token, left in
/// the request's extensions for the audit middleware to read after the handler
/// (#758 (c), D-12).
///
/// The middleware verifies a token's signature and expiry to name the actor in
/// the request row; it does not apply the extractor's further checks (audience,
/// session, `client_id`-minted refusal, DPoP). `authenticated` on the row used
/// to mean only "the signature checked out", so a device-grant token refused
/// `403` at `/api/v1/device/verify` was recorded `authenticated: true`. It now
/// means the extractor's verdict wherever the extractor ran. Lives here, in the
/// lowest crate the middleware and the extractors both reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthVerdict {
    /// The extractor admitted the credential (the active-tenant decision that
    /// follows is about what the principal asked for, not about the token).
    Admitted,
    /// The extractor refused the credential itself (`401`/`403`).
    Refused,
}

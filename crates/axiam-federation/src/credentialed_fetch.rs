//! The one-hop rule for requests that carry a credential (R1W2-04, T-112).
//!
//! The four calls that send AXIAM's client secret, an authorization code, a
//! PKCE verifier or a user's access token to an IdP — the OIDC and OAuth2
//! token exchanges, the OAuth2 userinfo call and GitHub's verified-email call —
//! go through [`crate::ssrf::guarded_fetch_no_redirect`]. That guard returns a
//! `3xx` to the caller instead of following it, so a redirect never re-sends the
//! body or the `Authorization` header to the `Location`. What remains is to
//! refuse the `3xx`: a token or userinfo endpoint has no business redirecting,
//! and reading a redirect's body as if it were the answer would only produce a
//! confusing parse error further down.
//!
//! Discovery, JWKS and metadata fetches carry no credential and keep the
//! redirect-following [`crate::ssrf::guarded_fetch`].

/// The wording every refusal starts with.
pub(crate) const REDIRECT_NOT_FOLLOWED: &str = "redirect not followed";

/// `Some(reason)` when `response` is a `3xx`, `None` otherwise.
///
/// `what` names the call (`"token endpoint"`, `"userinfo endpoint"`) and
/// `endpoint` is the **configured** URL it was sent to. The reason carries the
/// endpoint's host and path only: not its query (a configured endpoint may carry
/// one), not the `Location` header (attacker-chosen, and it may carry the very
/// credential the redirect was meant to collect) and not the response body.
pub(crate) fn redirect_refusal(
    what: &str,
    endpoint: &str,
    response: &reqwest::Response,
) -> Option<String> {
    if !response.status().is_redirection() {
        return None;
    }
    Some(format!(
        "{REDIRECT_NOT_FOLLOWED}: the {what} {} answered HTTP {}",
        endpoint_label(endpoint),
        response.status().as_u16()
    ))
}

/// `host[:port]/path` of `endpoint`, without scheme, userinfo, query or
/// fragment. An unparseable value yields a placeholder rather than the raw
/// string, which could itself hold a secret.
fn endpoint_label(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(u) => {
            let host = u.host_str().unwrap_or("?");
            match u.port() {
                Some(p) => format!("{host}:{p}{}", u.path()),
                None => format!("{host}{}", u.path()),
            }
        }
        Err(_) => "<unparseable endpoint>".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::endpoint_label;

    #[test]
    fn the_label_is_host_and_path_and_nothing_else() {
        assert_eq!(
            endpoint_label("https://user:pw@idp.example.com/oauth/token?api_key=s3cr3t#frag"),
            "idp.example.com/oauth/token"
        );
        assert_eq!(
            endpoint_label("http://127.0.0.1:8080/token"),
            "127.0.0.1:8080/token"
        );
        assert_eq!(endpoint_label("not a url"), "<unparseable endpoint>");
    }
}

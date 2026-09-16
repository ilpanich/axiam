//! Redirect-URI matching (T21.2).
//!
//! One function, [`redirect_uri_matches`], used by every place that asks
//! whether a presented `redirect_uri` is one this client registered: the
//! authorization endpoint, the PAR endpoint, and — through them — the
//! authorization code, which stores what was presented rather than what was
//! registered.
//!
//! # Why a function and not `Vec::contains`
//!
//! Until T21.2 the question was answered by `client.redirect_uris.contains()`,
//! a byte-for-byte string comparison, everywhere. That is exactly right for
//! every URI a server or a mobile app registers, and it is unimplementable for
//! the one client family AXIAM did not serve: a desktop application that
//! listens on `http://127.0.0.1:{a port the operating system chose}/callback`.
//! The port is not knowable at registration time, so RFC 8252 §7.3 says the
//! authorization server
//!
//! > MUST allow any port to be specified at the time of the request for
//! > loopback IP redirect URIs, to accommodate clients that obtain an
//! > available ephemeral port from the operating system at the time of the
//! > request.
//!
//! This module is that allowance and nothing else. Everything outside the
//! loopback case keeps the old comparison, byte for byte — including the
//! degenerate cases (an unparseable registered URI, a trailing slash, a
//! percent-encoding difference), which is why the non-loopback path compares
//! the *strings* rather than the parsed URLs. Normalising them would be a
//! behaviour change for every existing client, which is precisely what I1
//! forbids, and a redirect matcher is the last place to introduce one: the
//! comparison is what stands between an authorization code and an attacker's
//! server.
//!
//! # The three hosts, and why they are not interchangeable
//!
//! `127.0.0.1`, `[::1]` and `localhost` each match only themselves. RFC 8252
//! §8.3 recommends the literal IP forms over the name — `localhost` resolves
//! through a resolver an attacker may influence — but it does not forbid the
//! name, and the two desktop clients this work exists for disagree: VS Code
//! registers `http://127.0.0.1/…` and Claude Code registers
//! `http://localhost/…`. Treating them as one would silently widen every
//! registration to a host the operator did not write down, so each client
//! registers what it actually uses and gets exactly that.

use url::Url;

/// The three hosts RFC 8252 §7.3's port allowance applies to.
///
/// `url::Url::host_str` serialises an IPv6 literal with its brackets, so the
/// bracketed form is what this list compares against.
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];

/// Whether `host` is one of the three loopback hosts.
fn is_loopback_host(host: &str) -> bool {
    LOOPBACK_HOSTS.iter().any(|h| h.eq_ignore_ascii_case(host))
}

/// Whether a **registered** URI takes RFC 8252 §7.3's port allowance.
///
/// Scheme *and* host, not host alone (I6). `https://localhost:8443/cb` keeps
/// exact matching: RFC 8252's allowance is written for the loopback
/// interface's `http` redirect, the one case where TLS is neither available
/// nor needed because the connection never leaves the machine. An `https`
/// registration means the operator wrote a TLS endpoint down, and a port is
/// part of which endpoint that is.
fn takes_port_allowance(registered: &Url) -> bool {
    registered.scheme() == "http" && registered.host_str().is_some_and(is_loopback_host)
}

/// Whether `presented` is the registered redirect URI `registered`.
///
/// Exact string equality, except that a registered loopback `http` URI accepts
/// any port (RFC 8252 §7.3). Everything else about the two URIs — scheme,
/// host, path, query, fragment and userinfo — must still be identical, so the
/// allowance widens the registration by exactly one component and never by a
/// path, a query parameter or a host.
///
/// Note what a registered loopback URI with an explicit port does: it also
/// accepts any port. RFC 8252 §7.3 phrases the rule as a property of *loopback
/// redirect URIs*, not of port-less ones, and a client that registered
/// `http://127.0.0.1:8080/callback` because that is what it used on the
/// developer's machine would otherwise be refused the ephemeral port the rule
/// exists to permit.
pub fn redirect_uri_matches(registered: &str, presented: &str) -> bool {
    if registered == presented {
        return true;
    }

    // Parse only when the fast path failed, and only to answer the loopback
    // question. An unparseable registered URI cannot take the allowance and
    // has already been compared as a string, so it is refused here exactly as
    // `contains()` refused it.
    let (Ok(reg), Ok(pres)) = (Url::parse(registered), Url::parse(presented)) else {
        return false;
    };

    if !takes_port_allowance(&reg) {
        return false;
    }

    // The presented URI must be the same loopback endpoint. `host_str` is
    // compared rather than `host()` so that `127.0.0.1` and `localhost` stay
    // distinct: `Host::Domain("localhost")` and `Host::Ipv4(127.0.0.1)` are
    // already different values, and the string comparison says so in a form a
    // reader can check against the registration.
    reg.scheme() == pres.scheme()
        && reg.host_str() == pres.host_str()
        && reg.path() == pres.path()
        && reg.query() == pres.query()
        && reg.fragment() == pres.fragment()
        && reg.username() == pres.username()
        && reg.password() == pres.password()
}

/// Whether any of `registered` matches `presented`.
///
/// The list form the call sites actually use. Kept here rather than written
/// out at each of them so that the loopback rule cannot be applied at one
/// endpoint and forgotten at another — the failure mode that makes PAR and
/// authorize disagree about what a client registered.
pub fn any_redirect_uri_matches(registered: &[String], presented: &str) -> bool {
    registered
        .iter()
        .any(|candidate| redirect_uri_matches(candidate, presented))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registered_loopback_uri_accepts_any_port() {
        for host in ["127.0.0.1", "[::1]", "localhost"] {
            let registered = format!("http://{host}/callback");
            for port in ["1024", "49152", "65535"] {
                let presented = format!("http://{host}:{port}/callback");
                assert!(
                    redirect_uri_matches(&registered, &presented),
                    "{registered} must accept {presented} (RFC 8252 §7.3)"
                );
            }
            // And the port-less form still matches itself.
            assert!(redirect_uri_matches(&registered, &registered));
        }
    }

    #[test]
    fn a_registered_loopback_uri_with_an_explicit_port_also_accepts_any_port() {
        // RFC 8252 §7.3's rule is about loopback URIs, not about port-less
        // ones. A client that registered the port it used in development must
        // still get the ephemeral port it uses in production.
        let registered = "http://127.0.0.1:8080/callback";
        for presented in [
            "http://127.0.0.1:53127/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:8080/callback",
        ] {
            assert!(
                redirect_uri_matches(registered, presented),
                "{registered} must accept {presented}"
            );
        }
    }

    #[test]
    fn the_allowance_widens_the_port_and_nothing_else() {
        let registered = "http://127.0.0.1/callback";
        for presented in [
            // Path.
            "http://127.0.0.1:5000/callback/",
            "http://127.0.0.1:5000/Callback",
            "http://127.0.0.1:5000/callback/../evil",
            "http://127.0.0.1:5000/",
            // Query — absent in the registration, present here.
            "http://127.0.0.1:5000/callback?next=https://evil.example",
            // Fragment.
            "http://127.0.0.1:5000/callback#x",
            // Userinfo.
            "http://user@127.0.0.1:5000/callback",
            // Scheme.
            "https://127.0.0.1:5000/callback",
            // Host — a different loopback spelling is a different host.
            "http://localhost:5000/callback",
            "http://[::1]:5000/callback",
            // Host — not loopback at all.
            "http://127.0.0.2:5000/callback",
            "http://evil.example:5000/callback",
        ] {
            assert!(
                !redirect_uri_matches(registered, presented),
                "{registered} must NOT accept {presented}"
            );
        }
    }

    #[test]
    fn a_registered_query_must_be_presented_unchanged() {
        let registered = "http://127.0.0.1/callback?app=axiam";
        assert!(redirect_uri_matches(
            registered,
            "http://127.0.0.1:41234/callback?app=axiam"
        ));
        for presented in [
            "http://127.0.0.1:41234/callback",
            "http://127.0.0.1:41234/callback?app=other",
            "http://127.0.0.1:41234/callback?app=axiam&extra=1",
        ] {
            assert!(
                !redirect_uri_matches(registered, presented),
                "{registered} must NOT accept {presented}"
            );
        }
    }

    #[test]
    fn https_uris_are_still_matched_exactly() {
        // I6: the port allowance is scoped to `http` loopback registrations.
        // Everything else keeps the byte-for-byte comparison
        // `redirect_uris.contains()` performed before T21.2 — including an
        // `https` URI whose host happens to be a loopback host.
        for registered in [
            "https://app.example.com/callback",
            "https://localhost/callback",
            "https://127.0.0.1/callback",
            "https://[::1]/callback",
        ] {
            assert!(redirect_uri_matches(registered, registered));
            let with_port = registered.replacen("/callback", ":8443/callback", 1);
            assert!(
                !redirect_uri_matches(registered, &with_port),
                "{registered} must NOT accept {with_port}"
            );
        }
        assert!(!redirect_uri_matches(
            "https://app.example.com/callback",
            "https://app.example.com/callback/"
        ));
        assert!(!redirect_uri_matches(
            "https://app.example.com/callback",
            "https://app.example.com.evil.test/callback"
        ));
    }

    #[test]
    fn a_custom_scheme_uri_is_matched_exactly() {
        // Mobile apps register `com.example.app:/oauth2redirect` (RFC 8252
        // §7.1). Nothing about that form parses as loopback, and nothing about
        // it changes.
        let registered = "com.example.app:/oauth2redirect";
        assert!(redirect_uri_matches(registered, registered));
        assert!(!redirect_uri_matches(registered, "com.example.app:/other"));
    }

    #[test]
    fn an_unparseable_registration_matches_only_itself() {
        // `validate_redirect_uris` refuses these at the admin API, so this is
        // about a row that predates it or arrived another way. The old
        // `contains()` compared it as a string and so does this.
        let registered = "not a url";
        assert!(redirect_uri_matches(registered, "not a url"));
        assert!(!redirect_uri_matches(registered, "http://127.0.0.1/cb"));
        assert!(!redirect_uri_matches("http://127.0.0.1/cb", "not a url"));
    }

    #[test]
    fn the_list_form_agrees_with_the_single_form() {
        let registered = vec![
            "https://app.example.com/callback".to_string(),
            "http://127.0.0.1/callback".to_string(),
        ];
        assert!(any_redirect_uri_matches(
            &registered,
            "http://127.0.0.1:60123/callback"
        ));
        assert!(any_redirect_uri_matches(
            &registered,
            "https://app.example.com/callback"
        ));
        assert!(!any_redirect_uri_matches(
            &registered,
            "http://localhost:60123/callback"
        ));
        assert!(!any_redirect_uri_matches(&[], "http://127.0.0.1/callback"));
    }
}

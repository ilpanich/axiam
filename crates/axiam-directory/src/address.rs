//! The address guard: where a tenant's directory may be, and the one address a
//! connection may use (T23.3.7, D-19, closes T-300).
//!
//! A tenant administrator chooses the directory URL. Unchecked, that turns
//! every directory sign-in into a connection AXIAM opens to an address of the
//! tenant's choosing — its own loopback services, the cloud metadata endpoint,
//! the pod network — and the time a failure takes tells an open port from a
//! closed one.
//!
//! # The rule ([`AddressPolicy::check`])
//!
//! The host is resolved (an IP-literal host is used as written) and **every**
//! address it resolves to must pass, or the directory is refused:
//!
//! | Class ([`axiam_core::ip_class`]) | Answer |
//! |---|---|
//! | global unicast | admitted |
//! | loopback, unspecified, link-local (incl. `169.254.169.254`, `fe80::/10`), multicast, special-purpose | **refused, always** |
//! | private — RFC 1918, CGNAT `100.64/10`, ULA `fc00::/7` | refused **unless** inside a network the operator listed in [`ALLOWED_PRIVATE_NETWORKS_ENV`] |
//! | a cloud metadata endpoint inside a private range (`fd00:ec2::254`, `100.100.100.200`) | refused, whatever the list says |
//! | an address of this host on a port AXIAM itself listens on | refused |
//!
//! IPv4-mapped IPv6 addresses are judged as the IPv4 address they denote. The
//! rule itself — policy, resolution, pinning — is `axiam_pki::address`, shared
//! with the SMTP email provider since #529 and re-exported here; this module
//! keeps what is the directory's own: the URL form, the default ports, the
//! IPv6-literal refusal and the allow-list variable. The classification is the
//! one `guarded_fetch` uses; only the policy differs —
//! corporate directories live on private networks, so private ranges are
//! admissible here where they are not for an outbound HTTP fetch, and only by
//! the operator.
//!
//! An IPv6-literal URL (`ldaps://[2001:db8::1]`) is refused too
//! ([`GuardError::Ipv6Literal`]): no certificate check can be done against it
//! (T-293), so such a directory could never be used.
//!
//! # Pinning
//!
//! [`guard`] returns the vetted addresses, and the connector
//! (`DirectoryClient::connect`) opens its TCP socket to one of **those**
//! `SocketAddr`s and hands the stream to `ldap3`; nothing resolves the name a
//! second time. The TLS server name stays the URL's host, so certificate
//! verification is unchanged. DNS rebinding between the check and the connect
//! is therefore impossible within one connection, and because the guard runs
//! again at **every** connect — the pool, the user bind, group lookup, the sync
//! job — a name that is re-pointed after the configuration was saved is caught
//! at the next connection.
//!
//! # The allow-list is the operator's, and is a residual
//!
//! It is deployment configuration, never tenant-editable. Inside the networks
//! it lists, any tenant administrator can point the connector at any host and
//! port; what that buys is a TLS handshake (or a 31-byte StartTLS request)
//! against a host that must then present a certificate chaining to the
//! tenant's anchors before anything else is sent, answered to the user as the
//! same generic failure. Keep it to the networks directories actually live in
//! (decision D-32 says why it is a network list, not a host list as
//! `AXIAM__PKI__SSRF_ALLOWED_HOSTS` is).

use std::net::IpAddr;
use std::sync::Arc;

pub use axiam_pki::address::{
    AddressPolicy, GuardError, GuardedTarget, MAX_RESOLVED_ADDRESSES, ResolveFuture, Resolver,
    SystemResolver, parse_allowed_networks,
};
use url::{Host, Url};

/// The environment variable that lists the private networks a tenant's
/// directory may be in: comma-separated CIDR blocks (`10.20.0.0/16`,
/// `fd12:3456::/48`) or single addresses. Unset or empty — the default — admits
/// no private address at all.
pub const ALLOWED_PRIVATE_NETWORKS_ENV: &str = "AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS";

/// Default ports when the URL names none.
const LDAP_PORT: u16 = 389;
const LDAPS_PORT: u16 = 636;

/// A fixed sentence for the operator's log line (the connector's `Failure`
/// carries `&'static str` only), worded for the directory.
#[must_use]
pub const fn operator_reason(error: &GuardError) -> &'static str {
    match error {
        GuardError::InvalidUrl => "the directory URL has no usable host",
        GuardError::Ipv6Literal => "an IPv6-literal directory URL cannot be certificate-checked",
        GuardError::Unresolvable => "the directory host could not be resolved",
        GuardError::TooManyAddresses => "the directory host resolves to too many addresses",
        GuardError::Loopback => "the directory host resolves to a loopback address (refused)",
        GuardError::Unspecified => {
            "the directory host resolves to an unspecified address (refused)"
        }
        GuardError::LinkLocal => {
            "the directory host resolves to a link-local or metadata address (refused)"
        }
        GuardError::Multicast => "the directory host resolves to a multicast address (refused)",
        GuardError::SpecialPurpose => {
            "the directory host resolves to a special-purpose address (refused)"
        }
        GuardError::Metadata => "the directory host resolves to a cloud metadata address (refused)",
        GuardError::PrivateNotAllowed => {
            "the directory host resolves to a private address outside \
             AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS (refused)"
        }
        GuardError::OwnListener => {
            "the directory host resolves to one of AXIAM's own listeners (refused)"
        }
    }
}

/// Resolve `url`'s host and judge every address under `policy`
/// ([`axiam_pki::address::guard_host`]). Pure policy plus resolution: no LDAP
/// traffic, no socket opened. The management routes call it before a
/// configuration is saved; the connector calls it again at every connect.
///
/// # Errors
///
/// A [`GuardError`]: the URL has no usable host, is an IPv6 literal, the name
/// does not resolve, or any address it resolves to is refused.
pub async fn guard(
    url: &str,
    policy: &AddressPolicy,
    resolver: &dyn Resolver,
) -> Result<GuardedTarget, GuardError> {
    let parsed = Url::parse(url).map_err(|_| GuardError::InvalidUrl)?;
    let port = parsed.port().unwrap_or(if parsed.scheme() == "ldaps" {
        LDAPS_PORT
    } else {
        LDAP_PORT
    });
    let host = match parsed.host() {
        None | Some(Host::Domain("")) => return Err(GuardError::InvalidUrl),
        Some(Host::Ipv6(_)) => return Err(GuardError::Ipv6Literal),
        Some(Host::Ipv4(v4)) => v4.to_string(),
        // `url` parses IP literals only for its "special" schemes (http and
        // friends); under `ldap`/`ldaps` a dotted quad arrives as a domain. The
        // shared guard uses it as written rather than handing it to a resolver.
        Some(Host::Domain(name)) if name.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) => {
            return Err(GuardError::Ipv6Literal);
        }
        Some(Host::Domain(name)) => name.to_string(),
    };
    axiam_pki::address::guard_host(&host, port, policy, resolver).await
}

/// The guard's inputs, shared by everything that opens a directory connection.
#[derive(Clone)]
pub struct NetworkGuard {
    /// The deployment's policy.
    pub policy: Arc<AddressPolicy>,
    /// The resolver.
    pub resolver: Arc<dyn Resolver>,
}

impl Default for NetworkGuard {
    fn default() -> Self {
        Self {
            policy: Arc::new(AddressPolicy::new()),
            resolver: Arc::new(SystemResolver),
        }
    }
}

impl NetworkGuard {
    /// [`guard`] under this policy and resolver.
    ///
    /// # Errors
    ///
    /// See [`guard`].
    pub async fn guard(&self, url: &str) -> Result<GuardedTarget, GuardError> {
        guard(url, &self.policy, self.resolver.as_ref()).await
    }
}

impl std::fmt::Debug for NetworkGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkGuard")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Only the directory's own part is tested here — the URL form, its default
/// ports and the IPv6-literal refusal. The rule itself is tested where it
/// lives (`axiam_pki::address`), and end to end through the connector in
/// `tests/connector_guard_test.rs`.
#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::Mutex;

    /// Answers each name from a table; counts the questions.
    struct Table {
        answers: Vec<(&'static str, Vec<IpAddr>)>,
        asked: Mutex<usize>,
    }

    impl Resolver for Table {
        fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
            *self.asked.lock().unwrap() += 1;
            let found = self
                .answers
                .iter()
                .find(|(name, _)| *name == host)
                .map(|(_, ips)| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
            Box::pin(async move {
                found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
            })
        }
    }

    fn table(answers: Vec<(&'static str, Vec<&str>)>) -> Table {
        Table {
            answers: answers
                .into_iter()
                .map(|(name, ips)| (name, ips.iter().map(|ip| ip.parse().unwrap()).collect()))
                .collect(),
            asked: Mutex::new(0),
        }
    }

    async fn verdict(url: &str, resolver: &Table) -> Result<(), GuardError> {
        guard(url, &AddressPolicy::new(), resolver)
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn literal_hosts_are_judged_as_written_under_either_scheme() {
        let none = table(vec![]);
        for (url, expected) in [
            ("ldaps://127.0.0.1", GuardError::Loopback),
            ("ldap://127.8.9.10:389", GuardError::Loopback),
            ("ldaps://0.0.0.0", GuardError::Unspecified),
            ("ldaps://169.254.169.254", GuardError::LinkLocal),
            ("ldaps://224.0.0.1", GuardError::Multicast),
            ("ldaps://10.20.0.5", GuardError::PrivateNotAllowed),
        ] {
            assert_eq!(verdict(url, &none).await, Err(expected), "{url}");
        }
        assert_eq!(
            *none.asked.lock().unwrap(),
            0,
            "a literal is never resolved"
        );
    }

    #[tokio::test]
    async fn a_public_address_is_admitted_and_its_port_defaults_by_scheme() {
        let named = table(vec![("ldap.example.com", vec!["93.184.216.34"])]);
        let ldaps = guard("ldaps://ldap.example.com", &AddressPolicy::new(), &named)
            .await
            .unwrap();
        assert_eq!(ldaps.port, 636);
        assert_eq!(ldaps.addresses, vec!["93.184.216.34:636".parse().unwrap()]);
        let starttls = guard("ldap://ldap.example.com", &AddressPolicy::new(), &named)
            .await
            .unwrap();
        assert_eq!(starttls.port, 389);
        let explicit = guard(
            "ldaps://ldap.example.com:3269",
            &AddressPolicy::new(),
            &named,
        )
        .await
        .unwrap();
        assert_eq!(explicit.port, 3269);
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_loopback_is_refused() {
        let named = table(vec![("innocent.test", vec!["127.0.0.1"])]);
        assert_eq!(
            verdict("ldaps://innocent.test", &named).await,
            Err(GuardError::Loopback)
        );
    }

    #[tokio::test]
    async fn ipv6_literals_and_hostless_urls_are_refused_without_resolving() {
        let named = table(vec![]);
        assert_eq!(
            verdict("ldaps://[2606:4700:4700::1111]", &named).await,
            Err(GuardError::Ipv6Literal)
        );
        assert_eq!(
            verdict("not a url", &named).await,
            Err(GuardError::InvalidUrl)
        );
        assert_eq!(*named.asked.lock().unwrap(), 0);
    }

    #[test]
    fn every_refusal_has_an_operator_sentence() {
        for error in [
            GuardError::InvalidUrl,
            GuardError::Ipv6Literal,
            GuardError::Unresolvable,
            GuardError::TooManyAddresses,
            GuardError::Loopback,
            GuardError::Unspecified,
            GuardError::LinkLocal,
            GuardError::Multicast,
            GuardError::SpecialPurpose,
            GuardError::Metadata,
            GuardError::PrivateNotAllowed,
            GuardError::OwnListener,
        ] {
            assert!(
                operator_reason(&error).starts_with("the directory")
                    || operator_reason(&error).starts_with("an IPv6")
            );
            assert!(!error.to_string().is_empty());
        }
    }
}

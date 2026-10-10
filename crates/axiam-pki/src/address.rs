//! The connector address guard: where a server an administrator names may be,
//! and the one address a connection to it may use (T23.3.7, D-19, D-32;
//! T-300, T-473).
//!
//! Two outbound connectors open raw TCP connections to a host an administrator
//! chooses: the directory connector (`axiam-directory`, LDAP) and the SMTP
//! email provider (`axiam-email`). Unchecked, either turns a configuration
//! field into a connection AXIAM opens to an address of the administrator's
//! choosing — its own loopback services, the cloud metadata endpoint, the pod
//! network — and the way a failure looks tells an open port from a closed one.
//! Both hold the host to this one rule; each keeps its own allow-list
//! variable, because the networks a directory lives in and the networks a mail
//! relay lives in are different decisions.
//!
//! # The rule ([`AddressPolicy::check`])
//!
//! The host is resolved (an IP-literal host is used as written) and **every**
//! address it resolves to must pass, or the host is refused:
//!
//! | Class ([`axiam_core::ip_class`]) | Answer |
//! |---|---|
//! | global unicast | admitted |
//! | loopback, unspecified, link-local (incl. `169.254.169.254`, `fe80::/10`), multicast, special-purpose | **refused, always** |
//! | private — RFC 1918, CGNAT `100.64/10`, ULA `fc00::/7` | refused **unless** inside a network the operator listed for the connector |
//! | a cloud metadata endpoint inside a private range (`fd00:ec2::254`, `100.100.100.200`) | refused, whatever the list says |
//! | an address of this host on a port AXIAM itself listens on | refused |
//!
//! IPv4-mapped IPv6 addresses are judged as the IPv4 address they denote. The
//! classification is the one [`crate::ssrf::guarded_fetch`] uses; only the
//! policy differs — directories and mail relays live on private networks, so
//! private ranges are admissible here where they are not for an outbound HTTP
//! fetch, and only by the operator.
//!
//! # Pinning
//!
//! [`guard_host`] returns the vetted addresses, and the connector opens its TCP
//! socket to one of **those** `SocketAddr`s; nothing resolves the name a second
//! time. The TLS server name stays the configured host, so certificate
//! verification is unchanged. DNS rebinding between the check and the connect
//! is therefore impossible within one connection, and because the guard runs
//! again at **every** connect, a name that is re-pointed after the
//! configuration was saved is caught at the next connection.
//!
//! # The allow-list is the operator's, and is a residual
//!
//! It is deployment configuration, never tenant-editable. Inside the networks
//! it lists, any administrator can point the connector at any host and port;
//! what that buys is a TLS handshake (or a plaintext protocol greeting before
//! one, for StartTLS) against a host that must then present a certificate the
//! connector accepts before any credential is sent. Keep it to the networks
//! the servers actually live in (decision D-32 says why it is a network list,
//! not a host list as `AXIAM__PKI__SSRF_ALLOWED_HOSTS` is).
//!
//! Moved here from `axiam_directory::address` by #529 so the directory and the
//! email provider share one implementation rather than two copies; this crate
//! is the lowest both may depend on that already carries a runtime
//! (`axiam-core` deliberately has none).

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;

use axiam_core::ip_class::{IpClass, IpNetwork, canonical, classify, is_never_allowed};

/// Most addresses one host may resolve to before the guard stops looking: a
/// directory or mail relay name is a handful of servers, not a CDN.
pub const MAX_RESOLVED_ADDRESSES: usize = 32;

/// Why an address, or a whole host, was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// The configured address could not be parsed or names no host.
    #[error("the address names no usable host")]
    InvalidUrl,
    /// The host is a bracketed IPv6 literal in a URL, which the directory
    /// connector cannot name-check.
    #[error("an IPv6-literal URL cannot be certificate-checked; name the server by a host name")]
    Ipv6Literal,
    /// The name did not resolve, or resolved to nothing.
    #[error("the host could not be resolved")]
    Unresolvable,
    /// The name resolved to more addresses than [`MAX_RESOLVED_ADDRESSES`].
    #[error("the host resolves to too many addresses")]
    TooManyAddresses,
    /// An address is loopback.
    #[error("the host resolves to a loopback address")]
    Loopback,
    /// An address is unspecified (`0.0.0.0/8`, `::`).
    #[error("the host resolves to an unspecified address")]
    Unspecified,
    /// An address is link-local (`169.254/16`, `fe80::/10`).
    #[error("the host resolves to a link-local address")]
    LinkLocal,
    /// An address is multicast.
    #[error("the host resolves to a multicast address")]
    Multicast,
    /// An address is in a special-purpose block nothing legitimate lives in.
    #[error("the host resolves to a special-purpose address")]
    SpecialPurpose,
    /// An address is a cloud metadata endpoint inside a private range.
    #[error("the host resolves to a cloud metadata address")]
    Metadata,
    /// An address is private and outside every network the operator listed.
    #[error("the host resolves to a private address outside the deployment's allowed networks")]
    PrivateNotAllowed,
    /// An address is this host's own, on a port AXIAM listens on.
    #[error("the host resolves to one of AXIAM's own listeners")]
    OwnListener,
}

impl GuardError {
    /// The machine-readable name of the rule, for an audit row or a log field.
    #[must_use]
    pub const fn rule(&self) -> &'static str {
        match self {
            Self::InvalidUrl => "address_guard.invalid_url",
            Self::Ipv6Literal => "address_guard.ipv6_literal",
            Self::Unresolvable => "address_guard.unresolvable",
            Self::TooManyAddresses => "address_guard.too_many_addresses",
            Self::Loopback => "address_guard.loopback",
            Self::Unspecified => "address_guard.unspecified",
            Self::LinkLocal => "address_guard.link_local",
            Self::Multicast => "address_guard.multicast",
            Self::SpecialPurpose => "address_guard.special_purpose",
            Self::Metadata => "address_guard.metadata",
            Self::PrivateNotAllowed => "address_guard.private_not_allowed",
            Self::OwnListener => "address_guard.own_listener",
        }
    }

    /// Whether the refusal is the configuration's fault (`true`) rather than a
    /// resolver that could not answer (`false`, worth a retry later).
    #[must_use]
    pub const fn is_policy(&self) -> bool {
        !matches!(self, Self::Unresolvable)
    }
}

/// A deployment's rule for one connector's addresses. Built once at
/// composition from deployment configuration; tenants cannot change it.
#[derive(Debug, Clone, Default)]
pub struct AddressPolicy {
    allowed_private: Vec<IpNetwork>,
    listener_ports: Vec<u16>,
    admit_loopback: bool,
}

impl AddressPolicy {
    /// The strict policy: no private network admitted, no listener known.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit private addresses inside `networks` (the operator's allow-list
    /// for this connector). Only addresses of the private class ever consult
    /// the list: a network that also covers loopback, link-local or public
    /// space admits nothing more than its private part, and never a metadata
    /// endpoint.
    #[must_use]
    pub fn with_allowed_private_networks(mut self, networks: Vec<IpNetwork>) -> Self {
        self.allowed_private = networks;
        self
    }

    /// The ports AXIAM's own listeners are bound to (REST, gRPC). An address
    /// of this host on one of them is refused, so a connector cannot be
    /// pointed back at AXIAM itself.
    #[must_use]
    pub fn with_listener_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.listener_ports = ports.into_iter().collect();
        self.listener_ports.sort_unstable();
        self.listener_ports.dedup();
        self
    }

    /// **Tests only.** Admit loopback addresses, so an in-process test server
    /// on `127.0.0.1` can be reached; every other rule still applies
    /// (link-local, metadata, private ranges, listener ports). Never called by
    /// production code: the composition root builds its policies with
    /// [`Self::new`], and a grep for this name finds every exception.
    #[doc(hidden)]
    #[must_use]
    pub fn admitting_loopback_for_tests(mut self) -> Self {
        self.admit_loopback = true;
        self
    }

    /// The networks admitted.
    #[must_use]
    pub fn allowed_private_networks(&self) -> &[IpNetwork] {
        &self.allowed_private
    }

    /// The listener ports refused on this host's addresses.
    #[must_use]
    pub fn listener_ports(&self) -> &[u16] {
        &self.listener_ports
    }

    /// Judge one resolved address.
    ///
    /// # Errors
    ///
    /// The [`GuardError`] naming the rule `address` breaks.
    pub fn check(&self, address: SocketAddr) -> Result<(), GuardError> {
        let ip = canonical(address.ip());
        match classify(ip) {
            IpClass::Global => {}
            IpClass::Loopback if self.admit_loopback => {}
            IpClass::Loopback => return Err(GuardError::Loopback),
            IpClass::Unspecified => return Err(GuardError::Unspecified),
            IpClass::LinkLocal => return Err(GuardError::LinkLocal),
            IpClass::Multicast => return Err(GuardError::Multicast),
            IpClass::SpecialPurpose => return Err(GuardError::SpecialPurpose),
            IpClass::Private => {
                if is_never_allowed(ip) {
                    return Err(GuardError::Metadata);
                }
                if !self.allowed_private.iter().any(|net| net.contains(ip)) {
                    return Err(GuardError::PrivateNotAllowed);
                }
            }
        }
        if self.listener_ports.contains(&address.port()) && is_local_address(ip) {
            return Err(GuardError::OwnListener);
        }
        Ok(())
    }
}

/// Whether `ip` is an address of this host: loopback, or one an unprivileged
/// socket can bind to (binding fails with `EADDRNOTAVAIL` for an address no
/// local interface holds). No packet is sent. A host configured for non-local
/// binds (`net.ipv4.ip_nonlocal_bind`) reads every address as local, which
/// only widens the listener-port refusal — the safe direction.
fn is_local_address(ip: IpAddr) -> bool {
    ip.is_loopback() || std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// Parse an allow-list variable's comma-separated form. Returns the blocks
/// that parsed and the entries that did not (for the startup log; an entry
/// that does not parse admits nothing, so a typo fails closed).
#[must_use]
pub fn parse_allowed_networks(raw: &str) -> (Vec<IpNetwork>, Vec<String>) {
    let mut networks = Vec::new();
    let mut rejected = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        match entry.parse::<IpNetwork>() {
            Ok(network) if !networks.contains(&network) => networks.push(network),
            Ok(_) => {}
            Err(_) => rejected.push(entry.to_string()),
        }
    }
    (networks, rejected)
}

/// A boxed resolution future.
pub type ResolveFuture<'a> = Pin<Box<dyn Future<Output = io::Result<Vec<SocketAddr>>> + Send + 'a>>;

/// Turns a host name into addresses. The production resolver is
/// [`SystemResolver`]; tests script answers (including a name that answers
/// differently each time, to prove a connector never resolves twice).
pub trait Resolver: Send + Sync {
    /// Resolve `host` (a domain name, never an IP literal), with `port` on
    /// every address.
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a>;
}

/// The operating system's resolver (`getaddrinfo`, through Tokio).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        Box::pin(async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) })
    }
}

/// A host that passed the guard: the name the certificate must carry and the
/// addresses a connection may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedTarget {
    /// The configured host, as the TLS server name.
    pub host: String,
    /// The port.
    pub port: u16,
    /// Every address the host resolved to, each one vetted. A connection uses
    /// one of these and nothing else.
    pub addresses: Vec<SocketAddr>,
}

/// Whether `host` is an IP literal (a bracketed IPv6 literal included), so a
/// refusal that names the address's class reveals nothing the administrator
/// did not type (F4 P23W3-04).
#[must_use]
pub fn is_ip_literal(host: &str) -> bool {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok()
}

/// Resolve `host` once and judge every address under `policy`. Pure policy
/// plus resolution: no protocol traffic, no socket opened. An IP-literal host
/// (either family, bracketed or not) is used as written and never handed to
/// the resolver.
///
/// # Errors
///
/// A [`GuardError`]: the host is empty, the name does not resolve, or any
/// address it resolves to is refused.
pub async fn guard_host(
    host: &str,
    port: u16,
    policy: &AddressPolicy,
    resolver: &dyn Resolver,
) -> Result<GuardedTarget, GuardError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(GuardError::InvalidUrl);
    }
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    let addresses = match literal.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => resolver
            .resolve(host, port)
            .await
            .map_err(|_| GuardError::Unresolvable)?,
    };
    if addresses.is_empty() {
        return Err(GuardError::Unresolvable);
    }
    if addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(GuardError::TooManyAddresses);
    }
    let mut vetted = Vec::with_capacity(addresses.len());
    for address in addresses {
        policy.check(address)?;
        // Pin the canonical form: `::ffff:a.b.c.d` is dialled as `a.b.c.d`,
        // the address that was judged.
        let pinned = SocketAddr::new(canonical(address.ip()), port);
        if !vetted.contains(&pinned) {
            vetted.push(pinned);
        }
    }
    Ok(GuardedTarget {
        host: host.to_string(),
        port,
        addresses: vetted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
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

    async fn verdict(
        host: &str,
        port: u16,
        policy: &AddressPolicy,
        resolver: &Table,
    ) -> Result<(), GuardError> {
        guard_host(host, port, policy, resolver).await.map(|_| ())
    }

    #[tokio::test]
    async fn every_always_refused_class_is_refused_in_both_families_and_mapped_form() {
        let none = table(vec![]);
        let strict = AddressPolicy::new();
        for (host, expected) in [
            ("127.0.0.1", GuardError::Loopback),
            ("127.8.9.10", GuardError::Loopback),
            ("::1", GuardError::Loopback),
            ("[::1]", GuardError::Loopback),
            ("0.0.0.0", GuardError::Unspecified),
            ("169.254.169.254", GuardError::LinkLocal),
            ("169.254.170.2", GuardError::LinkLocal),
            ("224.0.0.1", GuardError::Multicast),
            ("192.0.2.10", GuardError::SpecialPurpose),
            ("255.255.255.255", GuardError::SpecialPurpose),
        ] {
            assert_eq!(
                verdict(host, 25, &strict, &none).await,
                Err(expected),
                "{host}"
            );
        }
        assert_eq!(
            *none.asked.lock().unwrap(),
            0,
            "literals are never resolved"
        );
        let named = table(vec![
            ("v6-loopback.test", vec!["::1"]),
            ("mapped-loopback.test", vec!["::ffff:127.0.0.1"]),
            ("v6-unspecified.test", vec!["::"]),
            ("v6-link-local.test", vec!["fe80::1"]),
            ("mapped-metadata.test", vec!["::ffff:169.254.169.254"]),
            ("v6-multicast.test", vec!["ff02::1"]),
            ("v6-compatible.test", vec!["::10.0.0.1"]),
        ]);
        for (host, expected) in [
            ("v6-loopback.test", GuardError::Loopback),
            ("mapped-loopback.test", GuardError::Loopback),
            ("v6-unspecified.test", GuardError::Unspecified),
            ("v6-link-local.test", GuardError::LinkLocal),
            ("mapped-metadata.test", GuardError::LinkLocal),
            ("v6-multicast.test", GuardError::Multicast),
            ("v6-compatible.test", GuardError::SpecialPurpose),
        ] {
            assert_eq!(
                verdict(host, 25, &strict, &named).await,
                Err(expected),
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn always_refused_classes_stay_refused_with_the_widest_allow_list() {
        let everything = AddressPolicy::new().with_allowed_private_networks(vec![
            "0.0.0.0/0".parse().unwrap(),
            "::/0".parse().unwrap(),
        ]);
        let named = table(vec![
            ("aws-v6-metadata.test", vec!["fd00:ec2::254"]),
            ("alibaba-metadata.test", vec!["100.100.100.200"]),
        ]);
        for (host, expected) in [
            ("127.0.0.1", GuardError::Loopback),
            ("169.254.169.254", GuardError::LinkLocal),
            ("0.0.0.0", GuardError::Unspecified),
            ("aws-v6-metadata.test", GuardError::Metadata),
            ("alibaba-metadata.test", GuardError::Metadata),
        ] {
            assert_eq!(
                verdict(host, 587, &everything, &named).await,
                Err(expected),
                "{host}"
            );
        }
    }

    #[tokio::test]
    async fn a_private_address_is_refused_without_the_allow_list_and_admitted_inside_it() {
        let named = table(vec![
            ("dc.corp.test", vec!["10.20.0.5", "10.20.0.6"]),
            ("ula.corp.test", vec!["fd12:3456::10"]),
            ("cgnat.corp.test", vec!["100.64.1.1"]),
        ]);
        let strict = AddressPolicy::new();
        for host in [
            "dc.corp.test",
            "ula.corp.test",
            "cgnat.corp.test",
            "10.20.0.5",
            "192.168.1.1",
        ] {
            assert_eq!(
                verdict(host, 587, &strict, &named).await,
                Err(GuardError::PrivateNotAllowed),
                "{host}"
            );
        }
        let (networks, rejected) =
            parse_allowed_networks("10.20.0.0/16, fd12:3456::/32 ,100.64.0.0/10,, nonsense/8");
        assert_eq!(rejected, vec!["nonsense/8".to_string()]);
        let policy = AddressPolicy::new().with_allowed_private_networks(networks);
        let admitted = guard_host("dc.corp.test", 587, &policy, &named)
            .await
            .unwrap();
        assert_eq!(admitted.host, "dc.corp.test");
        assert_eq!(admitted.port, 587);
        assert_eq!(admitted.addresses.len(), 2);
        for host in ["ula.corp.test", "cgnat.corp.test", "10.20.0.5"] {
            assert_eq!(verdict(host, 587, &policy, &named).await, Ok(()), "{host}");
        }
        assert_eq!(
            verdict("192.168.1.1", 587, &policy, &named).await,
            Err(GuardError::PrivateNotAllowed),
            "outside the listed networks is still refused"
        );
    }

    #[tokio::test]
    async fn one_refused_address_refuses_the_whole_host_and_unresolvable_is_its_own_answer() {
        let named = table(vec![("mixed.test", vec!["93.184.216.34", "127.0.0.1"])]);
        let strict = AddressPolicy::new();
        assert_eq!(
            verdict("mixed.test", 25, &strict, &named).await,
            Err(GuardError::Loopback)
        );
        let err = verdict("unknown.test", 25, &strict, &named)
            .await
            .unwrap_err();
        assert_eq!(err, GuardError::Unresolvable);
        assert!(!err.is_policy());
        assert_eq!(
            verdict("  ", 25, &strict, &named).await,
            Err(GuardError::InvalidUrl)
        );
    }

    #[tokio::test]
    async fn a_public_address_is_admitted_and_pinned_in_canonical_form() {
        let named = table(vec![(
            "smtp.example.com",
            vec!["93.184.216.34", "::ffff:93.184.216.34"],
        )]);
        let admitted = guard_host("smtp.example.com", 465, &AddressPolicy::new(), &named)
            .await
            .unwrap();
        assert_eq!(
            admitted.addresses,
            vec!["93.184.216.34:465".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn too_many_addresses_are_refused() {
        let many: Vec<&str> = vec!["93.184.216.34"; MAX_RESOLVED_ADDRESSES + 1];
        let named = table(vec![("cdn.test", many)]);
        assert_eq!(
            verdict("cdn.test", 25, &AddressPolicy::new(), &named).await,
            Err(GuardError::TooManyAddresses)
        );
    }

    #[tokio::test]
    async fn an_own_listener_port_on_a_local_address_is_refused_and_other_ports_are_not() {
        // The loopback seam admits 127.0.0.1, so the listener rule is what is
        // left to refuse AXIAM's own port on it.
        let policy = AddressPolicy::new()
            .admitting_loopback_for_tests()
            .with_listener_ports([8090, 50051]);
        let none = table(vec![]);
        assert_eq!(
            verdict("127.0.0.1", 8090, &policy, &none).await,
            Err(GuardError::OwnListener)
        );
        assert_eq!(
            verdict("127.0.0.1", 50051, &policy, &none).await,
            Err(GuardError::OwnListener)
        );
        assert_eq!(verdict("127.0.0.1", 587, &policy, &none).await, Ok(()));
        // A remote public address on the same port is somebody else's server.
        assert_eq!(verdict("93.184.216.34", 8090, &policy, &none).await, Ok(()));
        assert_eq!(policy.listener_ports(), &[8090, 50051]);
    }

    #[test]
    fn ip_literals_are_recognised_in_every_spelling() {
        for host in ["10.0.0.1", "::1", "[::1]", "[2001:db8::1]", " 127.0.0.1 "] {
            assert!(is_ip_literal(host), "{host}");
        }
        for host in ["smtp.example.com", "10.0.0.1.example", "", "[smtp]"] {
            assert!(!is_ip_literal(host), "{host}");
        }
    }

    #[test]
    fn every_refusal_has_a_rule_and_a_sentence() {
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
            assert!(error.rule().starts_with("address_guard."));
            assert!(!error.to_string().is_empty());
        }
    }
}

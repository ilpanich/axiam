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
//! classification is the one `guarded_fetch` uses; only the policy differs —
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

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

use axiam_core::ip_class::{IpClass, IpNetwork, canonical, classify, is_never_allowed};
use url::{Host, Url};

/// The environment variable that lists the private networks a tenant's
/// directory may be in: comma-separated CIDR blocks (`10.20.0.0/16`,
/// `fd12:3456::/48`) or single addresses. Unset or empty — the default — admits
/// no private address at all.
pub const ALLOWED_PRIVATE_NETWORKS_ENV: &str = "AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS";

/// Most addresses one host may resolve to before the guard stops looking: a
/// directory name is a handful of domain controllers, not a CDN.
pub const MAX_RESOLVED_ADDRESSES: usize = 32;

/// Default ports when the URL names none.
const LDAP_PORT: u16 = 389;
const LDAPS_PORT: u16 = 636;

/// Why an address, or a whole directory host, was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuardError {
    /// The URL could not be parsed or names no host.
    #[error("the directory URL has no usable host")]
    InvalidUrl,
    /// The host is a bracketed IPv6 literal, which cannot be name-checked.
    #[error(
        "an IPv6-literal directory URL cannot be certificate-checked; name the directory by a \
         host name"
    )]
    Ipv6Literal,
    /// The name did not resolve, or resolved to nothing.
    #[error("the directory host could not be resolved")]
    Unresolvable,
    /// The name resolved to more addresses than [`MAX_RESOLVED_ADDRESSES`].
    #[error("the directory host resolves to too many addresses")]
    TooManyAddresses,
    /// An address is loopback.
    #[error("the directory host resolves to a loopback address")]
    Loopback,
    /// An address is unspecified (`0.0.0.0/8`, `::`).
    #[error("the directory host resolves to an unspecified address")]
    Unspecified,
    /// An address is link-local (`169.254/16`, `fe80::/10`).
    #[error("the directory host resolves to a link-local address")]
    LinkLocal,
    /// An address is multicast.
    #[error("the directory host resolves to a multicast address")]
    Multicast,
    /// An address is in a special-purpose block nothing legitimate lives in.
    #[error("the directory host resolves to a special-purpose address")]
    SpecialPurpose,
    /// An address is a cloud metadata endpoint inside a private range.
    #[error("the directory host resolves to a cloud metadata address")]
    Metadata,
    /// An address is private and outside every network the operator listed.
    #[error(
        "the directory host resolves to a private address outside the deployment's allowed \
         networks"
    )]
    PrivateNotAllowed,
    /// An address is this host's own, on a port AXIAM listens on.
    #[error("the directory host resolves to one of AXIAM's own listeners")]
    OwnListener,
}

impl GuardError {
    /// A fixed sentence for the operator's log line (the connector's
    /// `Failure` carries `&'static str` only).
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::InvalidUrl => "the directory URL has no usable host",
            Self::Ipv6Literal => "an IPv6-literal directory URL cannot be certificate-checked",
            Self::Unresolvable => "the directory host could not be resolved",
            Self::TooManyAddresses => "the directory host resolves to too many addresses",
            Self::Loopback => "the directory host resolves to a loopback address (refused)",
            Self::Unspecified => "the directory host resolves to an unspecified address (refused)",
            Self::LinkLocal => {
                "the directory host resolves to a link-local or metadata address (refused)"
            }
            Self::Multicast => "the directory host resolves to a multicast address (refused)",
            Self::SpecialPurpose => {
                "the directory host resolves to a special-purpose address (refused)"
            }
            Self::Metadata => "the directory host resolves to a cloud metadata address (refused)",
            Self::PrivateNotAllowed => {
                "the directory host resolves to a private address outside \
                 AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS (refused)"
            }
            Self::OwnListener => {
                "the directory host resolves to one of AXIAM's own listeners (refused)"
            }
        }
    }

    /// Whether the refusal is the configuration's fault (`true`) rather than a
    /// resolver that could not answer (`false`, worth a retry later).
    #[must_use]
    pub const fn is_policy(&self) -> bool {
        !matches!(self, Self::Unresolvable)
    }
}

/// The deployment's rule for directory addresses. Built once at composition
/// from deployment configuration; tenants cannot change it.
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

    /// Admit private addresses inside `networks` (the operator's
    /// [`ALLOWED_PRIVATE_NETWORKS_ENV`]). Only addresses of the private class
    /// ever consult the list: a network that also covers loopback, link-local
    /// or public space admits nothing more than its private part, and never a
    /// metadata endpoint.
    #[must_use]
    pub fn with_allowed_private_networks(mut self, networks: Vec<IpNetwork>) -> Self {
        self.allowed_private = networks;
        self
    }

    /// The ports AXIAM's own listeners are bound to (REST, gRPC). An address
    /// of this host on one of them is refused, so a directory cannot be
    /// pointed back at AXIAM itself.
    #[must_use]
    pub fn with_listener_ports(mut self, ports: impl IntoIterator<Item = u16>) -> Self {
        self.listener_ports = ports.into_iter().collect();
        self.listener_ports.sort_unstable();
        self.listener_ports.dedup();
        self
    }

    /// **Tests only.** Admit loopback addresses, so the in-process test
    /// directory on `127.0.0.1` can be reached; every other rule still applies
    /// (link-local, metadata, private ranges, listener ports). Never called by
    /// production code: the composition root builds its policy with
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

/// Parse [`ALLOWED_PRIVATE_NETWORKS_ENV`]'s comma-separated form. Returns the
/// blocks that parsed and the entries that did not (for the startup log; an
/// entry that does not parse admits nothing, so a typo fails closed).
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
/// differently each time, to prove the connector never resolves twice).
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

/// A directory host that passed the guard: the name the certificate must carry
/// and the addresses a connection may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardedTarget {
    /// The URL's host, as the TLS server name.
    pub host: String,
    /// The port.
    pub port: u16,
    /// Every address the host resolved to, each one vetted. A connection uses
    /// one of these and nothing else.
    pub addresses: Vec<SocketAddr>,
}

/// Resolve `url`'s host and judge every address under `policy`. Pure policy
/// plus resolution: no LDAP traffic, no socket opened. The management routes
/// call it before a configuration is saved; the connector calls it again at
/// every connect.
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
    let (host, addresses) = match parsed.host() {
        None => return Err(GuardError::InvalidUrl),
        Some(Host::Domain("")) => return Err(GuardError::InvalidUrl),
        Some(Host::Ipv6(_)) => return Err(GuardError::Ipv6Literal),
        Some(Host::Ipv4(v4)) => (v4.to_string(), vec![SocketAddr::new(IpAddr::V4(v4), port)]),
        // `url` parses IPv4 literals only for its "special" schemes (http and
        // friends); under `ldap`/`ldaps` a dotted quad arrives as a domain. Use
        // it as written rather than handing it to a resolver.
        Some(Host::Domain(name)) if name.parse::<IpAddr>().is_ok() => {
            let ip: IpAddr = name.parse().map_err(|_| GuardError::InvalidUrl)?;
            if ip.is_ipv6() {
                return Err(GuardError::Ipv6Literal);
            }
            (name.to_string(), vec![SocketAddr::new(ip, port)])
        }
        Some(Host::Domain(name)) => {
            let addresses = resolver
                .resolve(name, port)
                .await
                .map_err(|_| GuardError::Unresolvable)?;
            (name.to_string(), addresses)
        }
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
        host,
        port,
        addresses: vetted,
    })
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

    fn strict() -> AddressPolicy {
        AddressPolicy::new()
    }

    async fn verdict(
        url: &str,
        policy: &AddressPolicy,
        resolver: &Table,
    ) -> Result<(), GuardError> {
        guard(url, policy, resolver).await.map(|_| ())
    }

    #[tokio::test]
    async fn every_always_refused_class_is_refused_in_both_families_and_mapped_form() {
        let none = table(vec![]);
        let cases: &[(&str, GuardError)] = &[
            ("ldaps://127.0.0.1", GuardError::Loopback),
            ("ldaps://127.8.9.10:636", GuardError::Loopback),
            ("ldaps://0.0.0.0", GuardError::Unspecified),
            ("ldaps://169.254.169.254", GuardError::LinkLocal),
            ("ldaps://169.254.170.2", GuardError::LinkLocal),
            ("ldaps://224.0.0.1", GuardError::Multicast),
            ("ldaps://192.0.2.10", GuardError::SpecialPurpose),
            ("ldaps://255.255.255.255", GuardError::SpecialPurpose),
        ];
        for (url, expected) in cases {
            assert_eq!(
                verdict(url, &strict(), &none).await,
                Err(expected.clone()),
                "{url}"
            );
        }
        // The same classes reached through a name, in IPv6 and IPv4-mapped form.
        let named = table(vec![
            ("v6-loopback.test", vec!["::1"]),
            ("mapped-loopback.test", vec!["::ffff:127.0.0.1"]),
            ("v6-unspecified.test", vec!["::"]),
            ("v6-link-local.test", vec!["fe80::1"]),
            ("mapped-metadata.test", vec!["::ffff:169.254.169.254"]),
            ("v6-multicast.test", vec!["ff02::1"]),
            ("mapped-multicast.test", vec!["::ffff:224.0.0.5"]),
            ("v6-compatible.test", vec!["::10.0.0.1"]),
        ]);
        let cases: &[(&str, GuardError)] = &[
            ("ldaps://v6-loopback.test", GuardError::Loopback),
            ("ldaps://mapped-loopback.test", GuardError::Loopback),
            ("ldaps://v6-unspecified.test", GuardError::Unspecified),
            ("ldaps://v6-link-local.test", GuardError::LinkLocal),
            ("ldaps://mapped-metadata.test", GuardError::LinkLocal),
            ("ldaps://v6-multicast.test", GuardError::Multicast),
            ("ldaps://mapped-multicast.test", GuardError::Multicast),
            ("ldaps://v6-compatible.test", GuardError::SpecialPurpose),
        ];
        for (url, expected) in cases {
            assert_eq!(
                verdict(url, &strict(), &named).await,
                Err(expected.clone()),
                "{url}"
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
        for (url, expected) in [
            ("ldaps://127.0.0.1", GuardError::Loopback),
            ("ldaps://169.254.169.254", GuardError::LinkLocal),
            ("ldaps://0.0.0.0", GuardError::Unspecified),
            ("ldaps://aws-v6-metadata.test", GuardError::Metadata),
            ("ldaps://alibaba-metadata.test", GuardError::Metadata),
        ] {
            assert_eq!(
                verdict(url, &everything, &named).await,
                Err(expected),
                "{url}"
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
        for url in [
            "ldaps://dc.corp.test",
            "ldaps://ula.corp.test",
            "ldaps://cgnat.corp.test",
            "ldaps://10.20.0.5",
            "ldaps://192.168.1.1",
        ] {
            assert_eq!(
                verdict(url, &strict(), &named).await,
                Err(GuardError::PrivateNotAllowed),
                "{url}"
            );
        }
        let (networks, rejected) =
            parse_allowed_networks("10.20.0.0/16, fd12:3456::/32 ,100.64.0.0/10,, nonsense/8");
        assert_eq!(rejected, vec!["nonsense/8".to_string()]);
        let policy = AddressPolicy::new().with_allowed_private_networks(networks);
        let admitted = guard("ldaps://dc.corp.test", &policy, &named)
            .await
            .unwrap();
        assert_eq!(admitted.host, "dc.corp.test");
        assert_eq!(admitted.port, 636);
        assert_eq!(admitted.addresses.len(), 2);
        for url in [
            "ldap://ula.corp.test:3389",
            "ldaps://cgnat.corp.test",
            "ldaps://10.20.0.5",
        ] {
            assert_eq!(verdict(url, &policy, &named).await, Ok(()), "{url}");
        }
        // Outside the listed networks is still refused.
        assert_eq!(
            verdict("ldaps://192.168.1.1", &policy, &named).await,
            Err(GuardError::PrivateNotAllowed)
        );
    }

    #[tokio::test]
    async fn a_public_address_is_admitted_and_its_port_defaults_by_scheme() {
        let named = table(vec![("ldap.example.com", vec!["93.184.216.34"])]);
        let ldaps = guard("ldaps://ldap.example.com", &strict(), &named)
            .await
            .unwrap();
        assert_eq!(ldaps.port, 636);
        assert_eq!(ldaps.addresses, vec!["93.184.216.34:636".parse().unwrap()]);
        let starttls = guard("ldap://ldap.example.com", &strict(), &named)
            .await
            .unwrap();
        assert_eq!(starttls.port, 389);
    }

    #[tokio::test]
    async fn one_refused_address_refuses_the_whole_host() {
        let named = table(vec![("mixed.test", vec!["93.184.216.34", "127.0.0.1"])]);
        assert_eq!(
            verdict("ldaps://mixed.test", &strict(), &named).await,
            Err(GuardError::Loopback)
        );
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_loopback_is_refused_and_unresolvable_is_its_own_answer() {
        let named = table(vec![("innocent.test", vec!["127.0.0.1"])]);
        assert_eq!(
            verdict("ldaps://innocent.test", &strict(), &named).await,
            Err(GuardError::Loopback)
        );
        let err = verdict("ldaps://unknown.test", &strict(), &named)
            .await
            .unwrap_err();
        assert_eq!(err, GuardError::Unresolvable);
        assert!(!err.is_policy());
    }

    #[tokio::test]
    async fn ipv6_literals_and_hostless_urls_are_refused_without_resolving() {
        let named = table(vec![]);
        assert_eq!(
            verdict("ldaps://[2606:4700:4700::1111]", &strict(), &named).await,
            Err(GuardError::Ipv6Literal)
        );
        assert_eq!(
            verdict("not a url", &strict(), &named).await,
            Err(GuardError::InvalidUrl)
        );
        assert_eq!(*named.asked.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn too_many_addresses_are_refused() {
        let many: Vec<&str> = vec!["93.184.216.34"; MAX_RESOLVED_ADDRESSES + 1];
        let named = table(vec![("cdn.test", many)]);
        assert_eq!(
            verdict("ldaps://cdn.test", &strict(), &named).await,
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
            verdict("ldaps://127.0.0.1:8090", &policy, &none).await,
            Err(GuardError::OwnListener)
        );
        assert_eq!(
            verdict("ldap://127.0.0.1:50051", &policy, &none).await,
            Err(GuardError::OwnListener)
        );
        assert_eq!(
            verdict("ldaps://127.0.0.1:636", &policy, &none).await,
            Ok(())
        );
        // A remote public address on the same port is somebody else's server.
        assert_eq!(
            verdict("ldaps://93.184.216.34:8090", &policy, &none).await,
            Ok(())
        );
        assert_eq!(policy.listener_ports(), &[8090, 50051]);
    }

    #[test]
    fn the_mapped_form_is_pinned_as_the_ipv4_address_it_denotes() {
        let policy = AddressPolicy::new();
        let mapped: SocketAddr = "[::ffff:93.184.216.34]:636".parse().unwrap();
        assert_eq!(policy.check(mapped), Ok(()));
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
            assert!(!error.reason().is_empty());
            assert!(!error.to_string().is_empty());
        }
    }
}

//! Which transport peers may speak for the client in `X-Forwarded-For`
//! (T-212, R110-01, #711, #686).
//!
//! Every per-address rate limit keys a request on the rightmost untrusted
//! `X-Forwarded-For` hop (`AXIAM__RATE_LIMIT__TRUSTED_HOPS`). That is right
//! behind an appending proxy, and wrong on a connection that reaches the
//! listener with no proxy in front: there nothing appends to the header, the
//! rightmost entry is whatever the caller wrote, and a caller who rotates it
//! gets a fresh bucket per request.
//!
//! [`TrustedProxies`] (`AXIAM__RATE_LIMIT__TRUSTED_PROXIES`, a comma-separated
//! list of CIDR blocks) names the peers whose header is read at all. A request
//! from a listed peer is keyed exactly as before, under `TRUSTED_HOPS`; a
//! request from any other peer is keyed on the peer, whatever it wrote. With
//! the list empty — the default — every peer's header is read, which is what
//! the server did before the list existed: the shipped topologies all put an
//! appending proxy in front, and one of them (`k8s/`) re-encrypts to the
//! server's native TLS listener, so "native TLS on" does not mean "no proxy".
//! The boot `WARN` of [`TrustedProxies::boot_warning`] is the empty list's
//! other half.
//!
//! The REST and gRPC extractors are siblings that may not depend on each
//! other, so the variable and the rule live here, below both, and both read
//! [`TrustedProxies::configured`] — one parse per process.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use crate::ip_class::{IpNetwork, IpNetworkError};

/// The environment variable that holds the list.
pub const TRUSTED_PROXIES_VAR: &str = "AXIAM__RATE_LIMIT__TRUSTED_PROXIES";

/// The peers whose `X-Forwarded-For` is honoured; empty means every peer's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Arc<[IpNetwork]>);

/// An entry of the list that is not a CIDR block or an address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{TRUSTED_PROXIES_VAR}: entry `{entry}` is not a CIDR block or an IP address: {reason}")]
pub struct TrustedProxiesError {
    /// The entry as written.
    pub entry: String,
    /// Why it did not parse.
    pub reason: IpNetworkError,
}

impl TrustedProxies {
    /// The list `raw` names: CIDR blocks or bare addresses (a host block),
    /// separated by commas; blank entries are skipped.
    ///
    /// # Errors
    ///
    /// The first entry that does not parse, host bits below the prefix
    /// included (`10.0.0.1/8` is refused rather than widened).
    pub fn parse(raw: &str) -> Result<Self, TrustedProxiesError> {
        raw.split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .parse::<IpNetwork>()
                    .map_err(|reason| TrustedProxiesError {
                        entry: entry.to_owned(),
                        reason,
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|networks| Self(networks.into()))
    }

    /// The list `AXIAM__RATE_LIMIT__TRUSTED_PROXIES` names (empty when unset).
    ///
    /// # Errors
    ///
    /// As [`TrustedProxies::parse`]. The composition root calls this once at
    /// boot and refuses to start on an error.
    pub fn from_env() -> Result<Self, TrustedProxiesError> {
        std::env::var(TRUSTED_PROXIES_VAR)
            .map_or_else(|_| Ok(Self::default()), |raw| Self::parse(&raw))
    }

    /// The process-wide list every extractor reads, parsed once.
    ///
    /// A value that does not parse is read as the empty list here: the
    /// composition root has already refused to start on it
    /// ([`TrustedProxies::from_env`]), so this arm is reached only by an
    /// embedding that skipped that check.
    #[must_use]
    pub fn configured() -> Self {
        static CONFIGURED: OnceLock<TrustedProxies> = OnceLock::new();
        CONFIGURED
            .get_or_init(|| Self::from_env().unwrap_or_default())
            .clone()
    }

    /// Whether no peer is named, i.e. every peer's header is read.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The blocks, in the order written.
    #[must_use]
    pub fn networks(&self) -> &[IpNetwork] {
        &self.0
    }

    /// Whether a request from `peer` may name its client in `X-Forwarded-For`.
    ///
    /// Always with the list empty; otherwise only when `peer` is inside one of
    /// the blocks. A request with no known peer is never honoured under a
    /// list: there is nothing to check it against.
    #[must_use]
    pub fn honours_forwarded_for(&self, peer: Option<IpAddr>) -> bool {
        self.is_empty() || peer.is_some_and(|peer| self.0.iter().any(|block| block.contains(peer)))
    }

    /// The boot `WARN` for this list on a server whose native TLS listener is
    /// `native_tls`, or `None` when there is nothing to warn about.
    ///
    /// The case is the empty list on a native TLS listener: a client that must
    /// reach that listener directly (the FreeRADIUS recipe's mutual TLS ends
    /// at AXIAM) writes the header nothing appends to, and so chooses its own
    /// rate-limit key on every route — while the proxy that re-encrypts to the
    /// same listener (`k8s/`) needs its header read. Only the operator knows
    /// which peers are which; the list is how they say so.
    #[must_use]
    pub fn boot_warning(&self, native_tls: bool) -> Option<&'static str> {
        (native_tls && self.is_empty()).then_some(
            "native TLS is on and AXIAM__RATE_LIMIT__TRUSTED_PROXIES is empty: \
             X-Forwarded-For is read from every peer, so a client that reaches this \
             listener with no appending proxy in front chooses its own rate-limit key \
             on every per-address limiter (T-212). List the proxies in front of the \
             server (CIDR blocks); every other peer is then keyed on its own address. \
             Both listeners read the list. See docs/deployment/README.md, \
             \"Deriving TRUSTED_HOPS\"",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("literal parses")
    }

    #[test]
    fn parses_blocks_and_bare_addresses_and_skips_blank_entries() {
        let list = TrustedProxies::parse(" 10.0.0.0/8, ,192.0.2.7,fd00::/8 ,").expect("parses");
        let written: Vec<String> = list.networks().iter().map(ToString::to_string).collect();
        assert_eq!(written, ["10.0.0.0/8", "192.0.2.7/32", "fd00::/8"]);
    }

    #[test]
    fn an_unparseable_entry_is_refused_by_name() {
        for (raw, entry) in [
            ("10.0.0.0/8,proxy.internal", "proxy.internal"),
            ("10.0.0.1/8", "10.0.0.1/8"),
            ("10.0.0.0/33", "10.0.0.0/33"),
        ] {
            let error = TrustedProxies::parse(raw).expect_err(raw);
            assert_eq!(error.entry, entry, "{raw}");
            assert!(error.to_string().contains(TRUSTED_PROXIES_VAR), "{error}");
        }
    }

    #[test]
    fn the_empty_list_honours_every_peer() {
        let list = TrustedProxies::parse("").expect("parses");
        assert!(list.is_empty());
        assert!(list.honours_forwarded_for(Some(ip("203.0.113.9"))));
        assert!(list.honours_forwarded_for(None));
    }

    #[test]
    fn a_list_honours_only_the_peers_inside_it() {
        let list = TrustedProxies::parse("10.42.0.0/16,2001:db8::1").expect("parses");
        assert!(list.honours_forwarded_for(Some(ip("10.42.7.1"))));
        assert!(list.honours_forwarded_for(Some(ip("::ffff:10.42.7.1"))));
        assert!(list.honours_forwarded_for(Some(ip("2001:db8::1"))));
        assert!(!list.honours_forwarded_for(Some(ip("10.43.0.1"))));
        assert!(!list.honours_forwarded_for(Some(ip("2001:db8::2"))));
        assert!(!list.honours_forwarded_for(None));
    }

    #[test]
    fn the_boot_warning_is_for_the_empty_list_on_native_tls_only() {
        let empty = TrustedProxies::default();
        let listed = TrustedProxies::parse("10.0.0.0/8").expect("parses");
        assert!(empty.boot_warning(true).is_some());
        assert!(empty.boot_warning(false).is_none());
        assert!(listed.boot_warning(true).is_none());
        assert!(listed.boot_warning(false).is_none());
    }

    /// The variable is unset in the test environment, which reads as the empty
    /// list (every peer's header is honoured); the process-wide list agrees and
    /// is parsed once, so two reads are the same list.
    #[test]
    fn an_unset_variable_reads_as_the_empty_list_and_the_configured_list_agrees() {
        if std::env::var_os(TRUSTED_PROXIES_VAR).is_some() {
            return; // the environment names a list; the cases above cover parsing
        }
        assert!(
            TrustedProxies::from_env()
                .expect("unset is not an error")
                .is_empty()
        );
        let configured = TrustedProxies::configured();
        assert!(configured.is_empty());
        assert_eq!(configured, TrustedProxies::configured());
        assert!(
            configured.honours_forwarded_for(None),
            "no list: every request is honoured"
        );
    }
}

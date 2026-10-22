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

use std::env::VarError;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};

use crate::ip_class::{IpNetwork, IpNetworkError};

/// The environment variable that holds the list.
pub const TRUSTED_PROXIES_VAR: &str = "AXIAM__RATE_LIMIT__TRUSTED_PROXIES";

/// The peers whose `X-Forwarded-For` is honoured; empty means every peer's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Arc<[IpNetwork]>);

/// Why the list could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrustedProxiesError {
    /// An entry of the list that is not a CIDR block or an address.
    #[error(
        "{TRUSTED_PROXIES_VAR}: entry `{entry}` is not a CIDR block or an IP address: {reason}"
    )]
    Entry {
        /// The entry as written.
        entry: String,
        /// Why it did not parse.
        reason: IpNetworkError,
    },
    /// The variable is set, but its value is not valid Unicode. The bytes are
    /// not echoed: they are not known to be printable, and a half-read list
    /// must not be guessed at.
    #[error("{TRUSTED_PROXIES_VAR}: the value is not valid UTF-8")]
    NotUnicode,
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
                    .map_err(|reason| TrustedProxiesError::Entry {
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
    /// As [`TrustedProxies::from_lookup`]. The composition root calls this once
    /// at boot and refuses to start on an error.
    pub fn from_env() -> Result<Self, TrustedProxiesError> {
        Self::from_lookup(|name| std::env::var(name))
    }

    /// [`TrustedProxies::from_env`] over any lookup of a variable by name, so
    /// the refusals are testable without the process environment.
    ///
    /// An unset variable is the empty list. A value that is not valid Unicode
    /// is an error, not an unset variable: reading it as empty would honour
    /// every peer's `X-Forwarded-For` while the operator believes a list is in
    /// force (R111W2-02, #732).
    ///
    /// # Errors
    ///
    /// [`TrustedProxiesError::NotUnicode`] for a non-Unicode value, otherwise
    /// as [`TrustedProxies::parse`].
    pub fn from_lookup(
        lookup: impl FnOnce(&str) -> Result<String, VarError>,
    ) -> Result<Self, TrustedProxiesError> {
        match lookup(TRUSTED_PROXIES_VAR) {
            Ok(raw) => Self::parse(&raw),
            Err(VarError::NotPresent) => Ok(Self::default()),
            Err(VarError::NotUnicode(_)) => Err(TrustedProxiesError::NotUnicode),
        }
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

    /// The boot `WARN` for this list on a server whose REST listener is on
    /// native TLS when `native_tls`, or `None` when there is nothing to warn
    /// about. The REST-only reading of [`Self::boot_warning_for`].
    #[must_use]
    pub fn boot_warning(&self, native_tls: bool) -> Option<&'static str> {
        self.boot_warning_for(native_tls, false)
    }

    /// The boot `WARN` for this list given which listeners terminate TLS in
    /// the process (`rest_tls`: `server.tls.enabled`; `grpc_tls`: the gRPC
    /// listener's certificate pair is set), or `None` when there is nothing to
    /// warn about. The message names each listener that is on native TLS.
    ///
    /// The case is the empty list on a native TLS listener: a client that must
    /// reach that listener directly (the FreeRADIUS recipe's mutual TLS ends
    /// at AXIAM, and the gRPC device topology's does too) writes the header
    /// nothing appends to, and so chooses its own rate-limit key on every
    /// route — while the proxy that re-encrypts to the same listener (`k8s/`)
    /// needs its header read. Only the operator knows which peers are which;
    /// the list is how they say so.
    #[must_use]
    pub fn boot_warning_for(&self, rest_tls: bool, grpc_tls: bool) -> Option<&'static str> {
        macro_rules! warning {
            ($on:literal) => {
                concat!(
                    "native TLS is on (",
                    $on,
                    ") and AXIAM__RATE_LIMIT__TRUSTED_PROXIES is empty: \
                     X-Forwarded-For is read from every peer, so a client that reaches \
                     that listener with no appending proxy in front chooses its own \
                     rate-limit key on every per-address limiter (T-212). List the \
                     proxies in front of the server (CIDR blocks); every other peer is \
                     then keyed on its own address. Both listeners read the list. See \
                     docs/deployment/README.md, \"Deriving TRUSTED_HOPS\""
                )
            };
        }
        if !self.is_empty() {
            return None;
        }
        match (rest_tls, grpc_tls) {
            (false, false) => None,
            (true, false) => Some(warning!("REST listener")),
            (false, true) => Some(warning!("gRPC listener")),
            (true, true) => Some(warning!("REST and gRPC listeners")),
        }
    }
}

/// `AXIAM__RATE_LIMIT__TRUSTED_HOPS`, or `0` when it is unset or unparseable.
///
/// The one reading of the variable every consumer of the client-address rule
/// uses (the REST limiters, the audit rows, the log fields). Read per call.
#[must_use]
pub fn configured_trusted_hops() -> usize {
    std::env::var("AXIAM__RATE_LIMIT__TRUSTED_HOPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// The address a request is attributed to, and what the caller claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedClientIp {
    /// The rule's address: `None` only with no peer and no usable header.
    pub ip: Option<IpAddr>,
    /// `Some(hops seen)` when the header was discarded because
    /// `trusted_hops >= hops` (the R-4 misconfiguration signal).
    pub discarded_hops: Option<usize>,
}

/// The address a per-address rate limit keys a request on, and the one audit
/// rows and log fields record (SEC-048, T-212, #711, #752).
///
/// `peer`, the transport peer, when `trusted_proxies` does not honour its
/// header. Otherwise the **rightmost untrusted** `X-Forwarded-For` hop —
/// `hops[len - 1 - trusted_hops]` — when the header has more hops than
/// `trusted_hops` and that entry parses as an address; otherwise `peer`. A
/// header too short to reach past the trusted hops is ignored entirely rather
/// than indexed from the left (SECHRD-03).
#[must_use]
pub fn select_client_ip(
    forwarded_for: Option<&str>,
    peer: Option<IpAddr>,
    trusted_hops: usize,
    trusted_proxies: &TrustedProxies,
) -> SelectedClientIp {
    if !trusted_proxies.honours_forwarded_for(peer) {
        return SelectedClientIp {
            ip: peer,
            discarded_hops: None,
        };
    }
    let mut discarded_hops = None;
    if let Some(val) = forwarded_for {
        let hops: Vec<&str> = val.split(',').map(str::trim).collect();
        if trusted_hops < hops.len() {
            let idx = hops.len() - 1 - trusted_hops;
            if let Ok(ip) = hops[idx].parse::<IpAddr>() {
                return SelectedClientIp {
                    ip: Some(ip),
                    discarded_hops: None,
                };
            }
        } else {
            discarded_hops = Some(hops.len());
        }
    }
    SelectedClientIp {
        ip: peer,
        discarded_hops,
    }
}

/// The leftmost `X-Forwarded-For` entry as the caller asserted it, when it
/// differs from `recorded` (the address [`select_client_ip`] chose). `None`
/// when the header is absent, empty, or names the recorded address. Cut to
/// 45 characters, an IPv6 address with a zone id.
#[must_use]
pub fn forwarded_for_claimed(
    forwarded_for: Option<&str>,
    recorded: Option<IpAddr>,
) -> Option<String> {
    let first = forwarded_for?.split(',').next()?.trim();
    if first.is_empty() {
        return None;
    }
    if first
        .parse::<IpAddr>()
        .ok()
        .is_some_and(|ip| Some(ip) == recorded)
    {
        return None;
    }
    Some(first.chars().take(45).collect())
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
            assert!(
                matches!(&error, TrustedProxiesError::Entry { entry: e, .. } if e == entry),
                "{raw}: {error}"
            );
            assert!(error.to_string().contains(TRUSTED_PROXIES_VAR), "{error}");
        }
    }

    #[cfg(unix)]
    fn non_utf8() -> std::ffi::OsString {
        use std::os::unix::ffi::OsStringExt;
        std::ffi::OsString::from_vec(b"10.0.0.0/8,\xff\xfe".to_vec())
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_value_is_refused_without_echoing_it() {
        let error = TrustedProxies::from_lookup(|name| {
            assert_eq!(name, TRUSTED_PROXIES_VAR);
            Err(VarError::NotUnicode(non_utf8()))
        })
        .expect_err("a non-UTF-8 value must not read as an empty list");
        assert_eq!(error, TrustedProxiesError::NotUnicode);
        let shown = error.to_string();
        assert!(shown.contains(TRUSTED_PROXIES_VAR), "{shown}");
        assert!(
            !shown.contains("10.0.0.0") && !shown.contains('\u{fffd}'),
            "{shown}"
        );
    }

    #[test]
    fn the_lookup_twin_reads_absent_valid_and_unparsable_values() {
        let absent = TrustedProxies::from_lookup(|_| Err(VarError::NotPresent)).expect("absent");
        assert!(absent.is_empty());
        let valid =
            TrustedProxies::from_lookup(|_| Ok("10.0.0.0/8, 192.0.2.7".into())).expect("valid");
        assert_eq!(
            valid,
            TrustedProxies::parse("10.0.0.0/8,192.0.2.7").unwrap()
        );
        assert_eq!(valid.networks().len(), 2);
        let bad = TrustedProxies::from_lookup(|_| Ok("10.0.0.0/8,proxy.internal".into()))
            .expect_err("unparsable entry");
        assert!(
            matches!(bad, TrustedProxiesError::Entry { ref entry, .. } if entry == "proxy.internal")
        );
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

    /// #731: the decision is on both listeners; REST TLS off and gRPC TLS on
    /// still warns, and the message names the gRPC listener.
    #[test]
    fn the_boot_warning_covers_the_grpc_listener() {
        let empty = TrustedProxies::default();
        let listed = TrustedProxies::parse("10.0.0.0/8").expect("parses");
        let grpc_only = empty.boot_warning_for(false, true).expect("gRPC TLS warns");
        assert!(grpc_only.contains("gRPC listener"));
        assert!(!grpc_only.contains("REST"));
        assert!(grpc_only.contains("AXIAM__RATE_LIMIT__TRUSTED_PROXIES"));
        let rest_only = empty.boot_warning_for(true, false).expect("REST TLS warns");
        assert!(rest_only.contains("REST listener") && !rest_only.contains("gRPC"));
        let both = empty.boot_warning_for(true, true).expect("both warn");
        assert!(both.contains("REST and gRPC listeners"));
        assert!(empty.boot_warning_for(false, false).is_none());
        assert!(listed.boot_warning_for(false, true).is_none());
        assert!(listed.boot_warning_for(true, true).is_none());
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

    #[test]
    fn select_client_ip_follows_the_rule_and_reports_the_claim() {
        let listed = TrustedProxies::parse("10.0.0.0/8").unwrap();
        let outside = Some(ip("203.0.113.7"));
        let selected = select_client_ip(Some("1.2.3.4"), outside, 0, &listed);
        assert_eq!(selected.ip, outside);
        assert_eq!(
            forwarded_for_claimed(Some("1.2.3.4"), selected.ip).as_deref(),
            Some("1.2.3.4")
        );

        let inside = Some(ip("10.0.0.9"));
        let selected = select_client_ip(Some("9.9.9.9, 198.51.100.5"), inside, 0, &listed);
        assert_eq!(selected.ip, Some(ip("198.51.100.5")));
        assert_eq!(
            forwarded_for_claimed(Some("198.51.100.5"), selected.ip),
            None
        );
        assert_eq!(forwarded_for_claimed(None, selected.ip), None);
        // Too few hops: the header is discarded and the peer recorded.
        let short = select_client_ip(Some("9.9.9.9"), inside, 1, &listed);
        assert_eq!((short.ip, short.discarded_hops), (inside, Some(1)));
    }
}

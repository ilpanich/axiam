//! IP address classification shared by every outbound-connection guard.
//!
//! Two guards decide whether AXIAM may open a connection to an address that
//! somebody other than the operator chose:
//!
//! * `axiam_pki::ssrf` (`guarded_fetch`) for every outbound HTTP fetch to an
//!   administrator- or IdP-supplied URL (JWKS, discovery, token exchange, SAML
//!   metadata, webhooks, the FIDO MDS BLOB);
//! * `axiam_directory::address` for the LDAP / Active Directory connector, whose
//!   host a tenant administrator chooses (G-3, T-300).
//!
//! They differ in **policy** — the HTTP guard refuses every non-global address
//! unless the operator named the host; the directory guard admits private
//! ranges the operator listed, because corporate directories live there — but
//! they must never differ in **classification**. An address that one of them
//! reads as loopback and the other as public is the gap an attacker looks for,
//! so the classification lives here, once, below both (layer 0), and each guard
//! applies its own policy to the [`IpClass`] it gets back.
//!
//! The classifier was written for the HTTP guard (SECHRD-02, SEC-094, SEC-107)
//! and moved here unchanged in substance when the directory connector needed
//! it (T23.3.7); [`is_disallowed_ip`] is the predicate `guarded_fetch` has
//! always applied, and its table test moved with it.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// What kind of destination an address is.
///
/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are classified as the IPv4
/// address they denote (SEC-094); see [`canonical`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpClass {
    /// Globally routable unicast: the only class every guard admits by default.
    Global,
    /// `127.0.0.0/8`, `::1`.
    Loopback,
    /// `0.0.0.0/8` ("this network"; `0.0.0.0` reaches the local host on Linux)
    /// and `::`.
    Unspecified,
    /// `169.254.0.0/16` — which holds the cloud metadata services — and
    /// `fe80::/10`.
    LinkLocal,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// The ranges private networks are built from: RFC 1918 (`10/8`,
    /// `172.16/12`, `192.168/16`), RFC 6598 CGNAT (`100.64/10`) and IPv6
    /// unique-local addresses (`fc00::/7`). The one class a guard may admit by
    /// operator configuration.
    Private,
    /// Every other non-global block: documentation, benchmarking, reserved and
    /// broadcast, IETF protocol assignments, the deprecated 6to4 relay anycast
    /// and IPv6 site-local, discard-only, Teredo / ORCHID, local-use NAT64, the
    /// deprecated IPv4-compatible `::/96`, and any 6to4 or NAT64 address that
    /// embeds a non-global IPv4 address. Nothing legitimate is reached there.
    SpecialPurpose,
}

/// `ip`, with an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) folded to the
/// IPv4 address it denotes.
///
/// On a dual-stack host, connecting to `::ffff:a.b.c.d` reaches `a.b.c.d`, so a
/// guard must reason about — and compare, and pin — the IPv4 form (SEC-094).
/// The deprecated IPv4-*compatible* form (`::a.b.c.d`) is **not** folded:
/// nothing legitimate resolves to it, and [`classify`] calls it
/// [`IpClass::SpecialPurpose`] outright.
#[must_use]
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Classify `ip` (after [`canonical`]).
#[must_use]
pub fn classify(ip: IpAddr) -> IpClass {
    match canonical(ip) {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

/// IPv4 classification.
///
/// | Range | RFC | Class |
/// |---|---|---|
/// | `0.0.0.0/8` | RFC 1122 | unspecified ("this network") |
/// | `127.0.0.0/8` | RFC 1122 | loopback (the whole /8) |
/// | `169.254.0.0/16` | RFC 3927 | link-local — **the cloud metadata service** |
/// | `224.0.0.0/4` | RFC 5771 | multicast |
/// | `10/8`, `172.16/12`, `192.168/16` | RFC 1918 | private |
/// | `100.64.0.0/10` | RFC 6598 | private (CGNAT shared address space) |
/// | `192.0.0.0/24` | RFC 6890 | special (IETF protocol assignments) |
/// | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 | special (documentation) |
/// | `192.88.99.0/24` | RFC 7526 | special (deprecated 6to4 relay anycast) |
/// | `198.18.0.0/15` | RFC 2544 | special (benchmarking) |
/// | `240.0.0.0/4` | RFC 1112 | special (reserved, incl. `255.255.255.255`) |
///
/// `Ipv4Addr::is_shared`, `is_documentation`, `is_benchmarking` and
/// `is_reserved` are still unstable, hence the octet arithmetic.
fn classify_v4(v4: Ipv4Addr) -> IpClass {
    let o = v4.octets();
    if o[0] == 0 {
        IpClass::Unspecified
    } else if v4.is_loopback() {
        IpClass::Loopback
    } else if v4.is_link_local() {
        IpClass::LinkLocal
    } else if v4.is_multicast() {
        IpClass::Multicast
    } else if v4.is_private() || (o[0] == 100 && (o[1] & 0xc0) == 0x40) {
        IpClass::Private
    } else if (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24
        || o[0] >= 240
    // 240.0.0.0/4 reserved + broadcast
    {
        IpClass::SpecialPurpose
    } else {
        IpClass::Global
    }
}

/// The IPv4 address carried in segments `hi` and `lo`.
fn embedded_v4(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

/// IPv6 classification. Callers reach this only through [`classify`], which
/// has already folded `::ffff:a.b.c.d`.
fn classify_v6(v6: Ipv6Addr) -> IpClass {
    let s = v6.segments();

    // ::/96 — the deprecated IPv4-compatible form, which also holds `::` and
    // `::1`. `IpAddr::to_canonical` does not fold it (it delegates to
    // `to_ipv4_mapped`), which is why it is handled by hand.
    if s[..6].iter().all(|&segment| segment == 0) {
        return if v6.is_unspecified() {
            IpClass::Unspecified
        } else if v6.is_loopback() {
            IpClass::Loopback
        } else {
            IpClass::SpecialPurpose
        };
    }

    // 6to4, 2002::/16 (RFC 3056): bits 16..48 are an IPv4 address. The prefix
    // as a whole maps the entire public IPv4 space, so classify what it embeds:
    // `2002:7f00:1::1` is 127.0.0.1, `2002:a9fe:a9fe::1` the metadata service.
    if s[0] == 0x2002 && classify_v4(embedded_v4(s[1], s[2])) != IpClass::Global {
        return IpClass::SpecialPurpose;
    }
    // NAT64 well-known prefix, 64:ff9b::/96 (RFC 6052): the low 32 bits are the
    // IPv4 destination. Same reasoning.
    if s[..6] == [0x0064, 0xff9b, 0, 0, 0, 0]
        && classify_v4(embedded_v4(s[6], s[7])) != IpClass::Global
    {
        return IpClass::SpecialPurpose;
    }

    if v6.is_multicast() {
        IpClass::Multicast // ff00::/8
    } else if (s[0] & 0xffc0) == 0xfe80 {
        IpClass::LinkLocal // fe80::/10
    } else if (s[0] & 0xfe00) == 0xfc00 {
        IpClass::Private // fc00::/7 unique-local
    } else if (s[0] & 0xffc0) == 0xfec0 // fec0::/10 site-local (deprecated, RFC 3879)
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // 100::/64 discard-only
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // 64:ff9b:1::/48 local NAT64
        // 2001::/23 IETF protocol assignments (RFC 2928): Teredo 2001::/32,
        // benchmarking 2001:2::/48, ORCHIDv2 2001:20::/28. Teredo embeds both
        // a server and an (obfuscated) client IPv4 address.
        || (s[0] == 0x2001 && (s[1] & 0xfe00) == 0x0000)
        || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 documentation
        || (s[0] == 0x3fff && (s[1] & 0xf000) == 0)
    // 3fff::/20 documentation (RFC 9637)
    {
        IpClass::SpecialPurpose
    } else {
        IpClass::Global
    }
}

/// Returns `true` for IP addresses that must never be contacted from a
/// server-side outbound fetch to an admin/IdP-supplied URL: every class but
/// [`IpClass::Global`].
///
/// # SEC-094 — canonicalisation happens first
///
/// The predicate this replaced matched on the `IpAddr` variant as it arrived
/// from `getaddrinfo`. An `AAAA` record may legally contain an IPv4-mapped
/// address (`::ffff:169.254.169.254`), which matched none of the v6 arms, and
/// the v4 arms were never consulted; the address was then *pinned*, so the
/// pinning that closes the DNS-rebind window guaranteed the attacker's address
/// was the one dialled. [`classify`] folds the mapped form before anything
/// else, and rejects the deprecated IPv4-compatible `::/96` outright.
#[must_use]
pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    classify(ip) != IpClass::Global
}

/// Addresses that stay unreachable **whatever an operator's exception list
/// says** (SEC-107).
///
/// An exception exists so an operator can reach their own internal IdP or
/// directory. It does not exist so a poisoned DNS answer for that name can
/// reach the cloud metadata service, the one destination on the
/// private-address map that turns SSRF into credential theft:
///
/// | Address | Who |
/// |---|---|
/// | `169.254.0.0/16` | AWS / GCP / Azure IMDS (`169.254.169.254`) — the whole range, because `169.254.170.2` (ECS task roles) is in it too |
/// | `fe80::/10` | the IPv6 link-local equivalent |
/// | `fd00:ec2::254` | AWS IMDS over IPv6 (inside the unique-local range a directory allow-list may admit) |
/// | `100.100.100.200` | Alibaba Cloud metadata (inside CGNAT, likewise) |
/// | `192.0.0.192` | Oracle Cloud metadata |
/// | `::/96` | the deprecated IPv4-compatible encoding — a second spelling of everything above |
///
/// Canonicalisation runs first, so `::ffff:169.254.169.254` is refused too.
#[must_use]
pub fn is_never_allowed(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => {
            v4.is_link_local()
                || v4 == Ipv4Addr::new(100, 100, 100, 200)
                || v4 == Ipv4Addr::new(192, 0, 0, 192)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            (s[0] & 0xffc0 == 0xfe80)
                || s[..6].iter().all(|&segment| segment == 0)
                || v6 == Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
        }
    }
}

/// A CIDR block: an address and a prefix length (`10.0.0.0/8`,
/// `fd12:3456::/32`). A bare address is a host block (`/32`, `/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNetwork {
    network: IpAddr,
    prefix: u8,
}

/// Why a CIDR block did not parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IpNetworkError {
    /// The address part is not an IPv4 or IPv6 address.
    #[error("not an IP address")]
    Address,
    /// The prefix length is not a number, or is longer than the address.
    #[error("the prefix length is not valid for the address family")]
    Prefix,
    /// Bits are set below the prefix (`10.0.0.1/8`): almost always a typo for
    /// a narrower block, so it is refused rather than silently widened.
    #[error("host bits are set below the prefix length")]
    HostBits,
}

impl IpNetwork {
    /// The block `network/prefix`.
    ///
    /// # Errors
    ///
    /// [`IpNetworkError::Prefix`] when `prefix` exceeds the family's width,
    /// [`IpNetworkError::HostBits`] when `network` has bits set below it.
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, IpNetworkError> {
        let network = canonical(network);
        let width = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > width {
            return Err(IpNetworkError::Prefix);
        }
        let block = Self { network, prefix };
        if block.masked(network) != network {
            return Err(IpNetworkError::HostBits);
        }
        Ok(block)
    }

    /// The network address.
    #[must_use]
    pub fn network(&self) -> IpAddr {
        self.network
    }

    /// The prefix length.
    #[must_use]
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    fn masked(&self, ip: IpAddr) -> IpAddr {
        match ip {
            IpAddr::V4(v4) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
            }
            IpAddr::V6(v6) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        }
    }

    /// Whether `ip` (after [`canonical`]) is inside this block. An address of
    /// the other family never is.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (self.network, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                self.masked(ip) == self.network
            }
            _ => false,
        }
    }
}

impl FromStr for IpNetwork {
    type Err = IpNetworkError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim();
        let (address, prefix) = match raw.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (raw, None),
        };
        let address: IpAddr = address.parse().map_err(|_| IpNetworkError::Address)?;
        let width = if canonical(address).is_ipv4() {
            32
        } else {
            128
        };
        let prefix = match prefix {
            None => width,
            Some(digits) if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) => {
                digits.parse().map_err(|_| IpNetworkError::Prefix)?
            }
            Some(_) => return Err(IpNetworkError::Prefix),
        };
        Self::new(address, prefix)
    }
}

impl std::fmt::Display for IpNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(literal: &str) -> IpAddr {
        literal.parse().expect("literal parses")
    }

    /// SEC-094 — the regression the review reproduced: an `AAAA` record
    /// carrying an IPv4-mapped internal address passed the guard and was then
    /// *pinned* into the connection. Every literal named in the write-up.
    #[test]
    fn sec094_ipv4_mapped_ipv6_is_blocked() {
        for literal in [
            "::ffff:127.0.0.1",       // loopback
            "::ffff:169.254.169.254", // IMDS
            "::ffff:10.0.0.1",        // RFC1918
            "::ffff:192.168.1.1",     // RFC1918
            "::ffff:172.16.0.1",      // RFC1918
            "::ffff:0.0.0.0",         // unspecified
            "::ffff:255.255.255.255", // broadcast
            "::ffff:100.64.0.1",      // CGNAT
        ] {
            assert!(
                is_disallowed_ip(ip(literal)),
                "{literal}: IPv4-mapped IPv6 must be canonicalised and blocked (SEC-094)"
            );
        }
    }

    /// SEC-094 — table-driven classification over every family the guards are
    /// responsible for, as `guarded_fetch` has always applied it.
    #[test]
    fn sec094_is_disallowed_ip_table() {
        // (literal, expect_blocked, why)
        let cases: &[(&str, bool, &str)] = &[
            // ---- IPv4: must be blocked -------------------------------------
            ("0.0.0.0", true, "unspecified"),
            ("0.1.2.3", true, "0.0.0.0/8 'this network'"),
            ("10.0.0.1", true, "RFC1918 10/8"),
            ("172.16.0.1", true, "RFC1918 172.16/12"),
            ("172.31.255.254", true, "RFC1918 172.16/12 upper edge"),
            ("192.168.1.1", true, "RFC1918 192.168/16"),
            ("100.64.0.1", true, "RFC6598 CGNAT lower edge"),
            ("100.127.255.254", true, "RFC6598 CGNAT upper edge"),
            ("127.0.0.1", true, "loopback"),
            ("127.1.2.3", true, "loopback — the whole /8"),
            ("169.254.169.254", true, "link-local / cloud metadata"),
            ("192.0.0.1", true, "RFC6890 IETF protocol assignments"),
            ("192.0.2.1", true, "RFC5737 TEST-NET-1"),
            ("192.88.99.1", true, "deprecated 6to4 relay anycast"),
            ("198.18.0.1", true, "RFC2544 benchmarking"),
            ("198.19.255.254", true, "RFC2544 benchmarking upper edge"),
            ("198.51.100.1", true, "RFC5737 TEST-NET-2"),
            ("203.0.113.1", true, "RFC5737 TEST-NET-3"),
            ("224.0.0.1", true, "multicast"),
            ("239.255.255.255", true, "multicast upper edge"),
            ("240.0.0.1", true, "RFC1112 reserved"),
            ("255.255.255.255", true, "broadcast"),
            // ---- IPv4: must be allowed (routable public) -------------------
            ("1.1.1.1", false, "public"),
            ("8.8.8.8", false, "public"),
            (
                "93.184.216.34",
                false,
                "public — the pre-existing webhook case",
            ),
            ("100.63.255.255", false, "just BELOW the CGNAT block"),
            ("100.128.0.1", false, "just ABOVE the CGNAT block"),
            ("172.15.255.255", false, "just below RFC1918 172.16/12"),
            ("172.32.0.1", false, "just above RFC1918 172.16/12"),
            ("198.17.255.255", false, "just below the benchmarking /15"),
            ("198.20.0.1", false, "just above the benchmarking /15"),
            ("223.255.255.255", false, "just below multicast"),
            // ---- IPv4-mapped IPv6 (SEC-094): classified as their v4 --------
            ("::ffff:127.0.0.1", true, "mapped loopback"),
            ("::ffff:169.254.169.254", true, "mapped IMDS"),
            ("::ffff:10.0.0.1", true, "mapped RFC1918"),
            ("::ffff:192.168.1.1", true, "mapped RFC1918"),
            ("::ffff:100.64.0.1", true, "mapped CGNAT"),
            (
                "::ffff:93.184.216.34",
                false,
                "mapped PUBLIC address stays reachable — AI_V4MAPPED is legitimate",
            ),
            // ---- IPv4-compatible ::/96 (deprecated, always blocked) --------
            ("::", true, "unspecified"),
            ("::1", true, "loopback"),
            ("::127.0.0.1", true, "IPv4-compatible loopback"),
            ("::169.254.169.254", true, "IPv4-compatible IMDS"),
            (
                "::93.184.216.34",
                true,
                "IPv4-compatible form is deprecated (RFC4291) — blocked wholesale",
            ),
            // ---- IPv6: must be blocked -------------------------------------
            ("fe80::1", true, "link-local fe80::/10"),
            ("febf:ffff::1", true, "link-local upper edge"),
            ("fec0::1", true, "deprecated site-local fec0::/10 (RFC3879)"),
            ("fc00::1", true, "unique-local fc00::/7"),
            ("fd00::1", true, "unique-local"),
            ("fdff:ffff::1", true, "unique-local upper edge"),
            ("ff02::1", true, "multicast — all-nodes"),
            ("ff05::1:3", true, "multicast — site-local DHCP servers"),
            ("100::1", true, "100::/64 discard-only (RFC6666)"),
            ("2001:db8::1", true, "documentation (RFC3849)"),
            ("3fff::1", true, "documentation (RFC9637)"),
            ("3fff:0fff::1", true, "documentation upper edge"),
            ("2001::1", true, "Teredo, inside 2001::/23"),
            ("2001:2::1", true, "IPv6 benchmarking, inside 2001::/23"),
            ("2001:20::1", true, "ORCHIDv2, inside 2001::/23"),
            ("64:ff9b::7f00:1", true, "NAT64 embedding 127.0.0.1"),
            (
                "64:ff9b::a9fe:a9fe",
                true,
                "NAT64 embedding 169.254.169.254",
            ),
            ("64:ff9b::a00:1", true, "NAT64 embedding 10.0.0.1"),
            ("64:ff9b:1::1", true, "RFC8215 local-use NAT64 prefix"),
            ("2002:7f00:1::1", true, "6to4 embedding 127.0.0.1"),
            ("2002:a9fe:a9fe::1", true, "6to4 embedding 169.254.169.254"),
            ("2002:a00:1::1", true, "6to4 embedding 10.0.0.1"),
            ("2002:c0a8:101::1", true, "6to4 embedding 192.168.1.1"),
            ("2002:6440:1::1", true, "6to4 embedding CGNAT 100.64.0.1"),
            // ---- IPv6: must be allowed -------------------------------------
            (
                "2606:4700:4700::1111",
                false,
                "public — Cloudflare resolver",
            ),
            (
                "2001:4860:4860::8888",
                false,
                "public — Google resolver, 2001:4860 is outside /23",
            ),
            ("2400::1", false, "public GUA"),
            (
                "64:ff9b::5db8:d822",
                false,
                "NAT64 embedding a PUBLIC v4 (93.184.216.34)",
            ),
            (
                "2002:5db8:d822::1",
                false,
                "6to4 embedding a PUBLIC v4 (93.184.216.34)",
            ),
            (
                "3ffe::1",
                false,
                "just below the 3fff::/20 documentation block",
            ),
            (
                "4000::1",
                false,
                "just above the 3fff::/20 documentation block",
            ),
            ("fbff:ffff::1", false, "just below fc00::/7"),
            ("fe00::1", false, "just below fe80::/10"),
        ];

        let mut failures = Vec::new();
        for (literal, expect_blocked, why) in cases {
            let actual = is_disallowed_ip(ip(literal));
            if actual != *expect_blocked {
                failures.push(format!(
                    "  {literal:<26} expected blocked={expect_blocked:<5} got={actual:<5} ({why})"
                ));
            }
        }
        assert!(
            failures.is_empty(),
            "is_disallowed_ip misclassified {} address(es):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }

    /// T23.3.7 — the classes a policy is written against. The directory guard
    /// admits `Private` by operator configuration and nothing else that is not
    /// `Global`, so the boundary between `Private` and the rest is pinned here.
    #[test]
    fn classes_are_the_ones_each_policy_is_written_against() {
        let cases: &[(&str, IpClass)] = &[
            ("127.0.0.1", IpClass::Loopback),
            ("127.255.0.9", IpClass::Loopback),
            ("::1", IpClass::Loopback),
            ("::ffff:127.0.0.1", IpClass::Loopback),
            ("0.0.0.0", IpClass::Unspecified),
            ("0.9.9.9", IpClass::Unspecified),
            ("::", IpClass::Unspecified),
            ("169.254.169.254", IpClass::LinkLocal),
            ("::ffff:169.254.169.254", IpClass::LinkLocal),
            ("fe80::1", IpClass::LinkLocal),
            ("224.0.0.251", IpClass::Multicast),
            ("ff02::fb", IpClass::Multicast),
            ("10.1.2.3", IpClass::Private),
            ("172.16.5.4", IpClass::Private),
            ("192.168.0.10", IpClass::Private),
            ("100.64.0.1", IpClass::Private),
            ("fd12:3456::1", IpClass::Private),
            ("::ffff:10.0.0.1", IpClass::Private),
            ("fec0::1", IpClass::SpecialPurpose),
            ("::10.0.0.1", IpClass::SpecialPurpose),
            ("2002:a00:1::1", IpClass::SpecialPurpose),
            ("64:ff9b::7f00:1", IpClass::SpecialPurpose),
            ("192.0.2.1", IpClass::SpecialPurpose),
            ("255.255.255.255", IpClass::SpecialPurpose),
            ("93.184.216.34", IpClass::Global),
            ("2606:4700:4700::1111", IpClass::Global),
        ];
        for (literal, expected) in cases {
            assert_eq!(classify(ip(literal)), *expected, "{literal}");
        }
    }

    #[test]
    fn metadata_endpoints_are_never_allowed_and_internal_hosts_are_not_on_that_list() {
        for literal in [
            "169.254.169.254",
            "169.254.170.2",
            "::ffff:169.254.169.254",
            "fd00:ec2::254",
            "100.100.100.200",
            "192.0.0.192",
            "fe80::1",
            "::1",
        ] {
            assert!(is_never_allowed(ip(literal)), "{literal}");
        }
        for literal in ["10.0.0.1", "192.168.1.10", "172.16.0.5", "fd12:3456::1"] {
            assert!(!is_never_allowed(ip(literal)), "{literal}");
        }
    }

    #[test]
    fn a_cidr_block_parses_contains_and_refuses_what_it_should() {
        let ten: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert!(ten.contains(ip("10.255.0.1")));
        assert!(ten.contains(ip("::ffff:10.1.1.1")), "mapped form is folded");
        assert!(!ten.contains(ip("11.0.0.1")));
        assert!(!ten.contains(ip("fd00::1")), "other family");
        assert_eq!(ten.to_string(), "10.0.0.0/8");

        let ula: IpNetwork = " fd12:3456::/32 ".parse().unwrap();
        assert!(ula.contains(ip("fd12:3456:ffff::1")));
        assert!(!ula.contains(ip("fd12:3457::1")));

        let host: IpNetwork = "192.168.1.10".parse().unwrap();
        assert_eq!(host.prefix(), 32);
        assert!(host.contains(ip("192.168.1.10")));
        assert!(!host.contains(ip("192.168.1.11")));

        let everything: IpNetwork = "0.0.0.0/0".parse().unwrap();
        assert!(everything.contains(ip("8.8.8.8")));

        assert_eq!(
            "10.0.0.1/8".parse::<IpNetwork>(),
            Err(IpNetworkError::HostBits)
        );
        assert_eq!(
            "10.0.0.0/33".parse::<IpNetwork>(),
            Err(IpNetworkError::Prefix)
        );
        assert_eq!(
            "10.0.0.0/".parse::<IpNetwork>(),
            Err(IpNetworkError::Prefix)
        );
        assert_eq!(
            "10.0.0.0/+8".parse::<IpNetwork>(),
            Err(IpNetworkError::Prefix)
        );
        assert_eq!(
            "corp.example/8".parse::<IpNetwork>(),
            Err(IpNetworkError::Address)
        );
    }
}

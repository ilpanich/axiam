//! The name fence for `Server` certificates (S-7, DF-001).
//!
//! A leaf carrying `subjectAltName: DNS:login.example.com`, signed by a tenant
//! CA under the organization root, is trusted by **every** relying party that
//! trusts that root. So the question "may this caller put this name in a
//! certificate" is answered here, once, from a list an organization
//! administrator wrote — `server_cert_allowed_names` in the settings hierarchy
//! — and never from the request or from a CSR.
//!
//! # The three entry forms
//!
//! | Entry | Matches | Does not match |
//! |---|---|---|
//! | `.lakeside.internal` | `a.lakeside.internal`, `a.b.lakeside.internal`, `*.lakeside.internal` | `lakeside.internal`, `xlakeside.internal` |
//! | `lakeside.internal` | `lakeside.internal` only | `a.lakeside.internal`, `*.lakeside.internal` |
//! | `10.0.0.0/8`, `fd00::/8`, `10.0.0.5` | an IP SAN of the same family inside the prefix | the other family; an IPv4-mapped IPv6 address |
//!
//! A leading dot means **strictly below**: the apex is a different name, often
//! the organization's own, and a tenant trusted with `api.` hosts is not
//! thereby trusted with it. List the apex without the dot when it is meant.
//! Matching is on label boundaries, so a suffix can never match the tail of a
//! longer label.
//!
//! # What is normalised and what is refused
//!
//! * **Case** — DNS names compare case-insensitively (RFC 4343); both sides are
//!   lowercased before comparison.
//! * **A trailing dot** — refused, in entries and in requests. A certificate's
//!   `dNSName` carries none (RFC 5280 §4.2.1.6's preferred name syntax), and
//!   stripping one silently would be AXIAM deciding what the caller meant.
//! * **Unicode (IDNA U-labels)** — refused, with the A-label form named as the
//!   remedy. A `dNSName` is an `IA5String`; `xn--…` labels are ordinary ASCII
//!   and match byte for byte. AXIAM performs no IDNA conversion, because two
//!   spellings of one name are two chances for a matcher to disagree with the
//!   relying party.
//! * **Wildcards** — only a whole leftmost `*` label in a **request**, matched
//!   by a suffix entry at or above the rest (`*.a.x` by `.a.x` or `.x`). Never
//!   in an entry: `.x` is how "everything under x" is written. Partial labels
//!   (`a*.x`) and bare `*` are refused.
//! * **IPv4-mapped IPv6** (`::ffff:10.0.0.5`) — refused in requests and in
//!   entries. The same host has two encodings in a SAN, and a relying party
//!   comparing one against the other is exactly where a fence leaks; write the
//!   IPv4 address.
//! * **A DNS name that parses as an IPv4 address** — refused; it is an IP SAN.
//!
//! # Tighten-only
//!
//! A tenant override may name only entries some organization entry
//! [covers](allowed_name_covers): remove one, or narrow a suffix or a prefix.
//! When the organization baseline later shrinks under an existing override,
//! the effective list is the [intersection](intersect_allowed_names) of the
//! two — never the tenant list, and never the organization's wider one.

use std::net::IpAddr;

use crate::error::{AxiamError, AxiamResult};
use crate::models::certificate::{CertificateType, SubjectAltName};

/// The field name, as the settings API spells it, for messages.
pub const FIELD: &str = "server_cert_allowed_names";

/// How many SANs a single certificate may carry. A bound, not a policy: it
/// keeps one request from making the fence walk an unbounded list.
pub const MAX_SUBJECT_ALT_NAMES: usize = 100;

/// One parsed allow-list entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowedName {
    /// A single host name, lowercased.
    Exact(String),
    /// Every name strictly below this one, lowercased, stored without the dot.
    Suffix(String),
    /// An IP prefix of either family.
    Cidr(IpCidr),
}

/// An IP network in canonical form: host bits are zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = mask_u32(self.prefix);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = mask_u128(self.prefix);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }

    fn covers(&self, other: &IpCidr) -> bool {
        self.prefix <= other.prefix && self.contains(other.network)
    }
}

fn mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask_u128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// A name a caller asked to put in a certificate, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestedName {
    /// A host name, lowercased; may start with a `*` label.
    Dns(String),
    /// An IP address, never IPv4-mapped.
    Ip(IpAddr),
}

impl RequestedName {
    /// Parse a DNS name as a caller wrote it.
    pub fn dns(raw: &str) -> Result<Self, String> {
        let name = raw.trim();
        check_dns_name(name, true).map(Self::Dns)
    }

    /// Parse an IP address as a caller wrote it.
    pub fn ip(raw: &str) -> Result<Self, String> {
        let ip: IpAddr = raw
            .trim()
            .parse()
            .map_err(|_| format!("{raw:?} is not an IP address"))?;
        refuse_v4_mapped(ip, raw)?;
        Ok(Self::Ip(ip))
    }

    /// Parse a common name for a `Server` certificate: an IP address if it
    /// reads as one, a DNS name otherwise.
    pub fn common_name(raw: &str) -> Result<Self, String> {
        if raw.trim().parse::<IpAddr>().is_ok() {
            Self::ip(raw)
        } else {
            Self::dns(raw)
        }
    }
}

fn refuse_v4_mapped(ip: IpAddr, raw: &str) -> Result<(), String> {
    if let IpAddr::V6(v6) = ip
        && v6.to_ipv4_mapped().is_some()
    {
        return Err(format!(
            "{raw:?} is an IPv4-mapped IPv6 address; write the IPv4 address itself, so the \
             certificate and the allow-list carry one encoding of the host"
        ));
    }
    Ok(())
}

/// Validate a DNS name and return it lowercased. `wildcard` admits a whole
/// leftmost `*` label.
fn check_dns_name(name: &str, wildcard: bool) -> Result<String, String> {
    if name.is_empty() {
        return Err("a DNS name must not be empty".into());
    }
    if !name.is_ascii() {
        return Err(format!(
            "{name:?} is not ASCII; write internationalised labels in their A-label \
             (punycode, xn--…) form"
        ));
    }
    if name.ends_with('.') {
        return Err(format!(
            "{name:?} ends with a dot; write the name without the trailing root label"
        ));
    }
    if name.len() > 253 {
        return Err(format!("{name:?} is longer than 253 characters"));
    }
    if name.parse::<std::net::Ipv4Addr>().is_ok() {
        return Err(format!(
            "{name:?} is an IPv4 address; request it as an ip name"
        ));
    }
    let lower = name.to_ascii_lowercase();
    let labels: Vec<&str> = lower.split('.').collect();
    for (i, label) in labels.iter().enumerate() {
        if i == 0 && *label == "*" {
            if !wildcard {
                return Err(format!(
                    "{name:?} is a wildcard; an allow-list entry names everything under a \
                     domain as .example.com"
                ));
            }
            if labels.len() < 2 {
                return Err(format!("{name:?} is a wildcard with nothing under it"));
            }
            continue;
        }
        if label.is_empty() || label.len() > 63 {
            return Err(format!(
                "{name:?} has an empty label or one longer than 63 characters"
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(format!(
                "{name:?} is not a host name: labels are letters, digits and inner hyphens, \
                 and a wildcard is a whole leftmost * label"
            ));
        }
    }
    Ok(lower)
}

/// Parse one allow-list entry.
pub fn parse_allowed_name(raw: &str) -> Result<AllowedName, String> {
    let entry = raw.trim();
    if entry.is_empty() {
        return Err("an entry must not be empty".into());
    }
    if let Some((addr, prefix)) = entry.split_once('/') {
        let ip: IpAddr = addr
            .parse()
            .map_err(|_| format!("{raw:?} is not a CIDR prefix (10.0.0.0/8, fd00::/8)"))?;
        refuse_v4_mapped(ip, raw)?;
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| format!("{raw:?} has no numeric prefix length"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("{raw:?} has a prefix longer than {max}"));
        }
        let cidr = IpCidr {
            network: ip,
            prefix,
        };
        let canonical = match ip {
            IpAddr::V4(v4) => IpAddr::V4((u32::from(v4) & mask_u32(prefix)).into()),
            IpAddr::V6(v6) => IpAddr::V6((u128::from(v6) & mask_u128(prefix)).into()),
        };
        if canonical != ip {
            return Err(format!(
                "{raw:?} has host bits set; write {canonical}/{prefix}"
            ));
        }
        return Ok(AllowedName::Cidr(cidr));
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        refuse_v4_mapped(ip, raw)?;
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return Ok(AllowedName::Cidr(IpCidr {
            network: ip,
            prefix,
        }));
    }
    if let Some(rest) = entry.strip_prefix('.') {
        if rest.is_empty() {
            return Err(format!("{raw:?} names every host; name a domain"));
        }
        return check_dns_name(rest, false).map(AllowedName::Suffix);
    }
    check_dns_name(entry, false).map(AllowedName::Exact)
}

/// Every problem with an allow-list, as operator sentences prefixed with the
/// field name. Empty when the list is valid — and the empty list is valid: it
/// is the shipped default, and it means no `Server` certificate is issued.
pub fn validate_allowed_names(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|e| parse_allowed_name(e).err())
        .map(|why| format!("{FIELD}: {why}"))
        .collect()
}

/// Whether `entry` admits `name`. See the module table.
pub fn allowed_name_matches(entry: &AllowedName, name: &RequestedName) -> bool {
    match (entry, name) {
        (AllowedName::Exact(host), RequestedName::Dns(n)) => host == n,
        (AllowedName::Suffix(s), RequestedName::Dns(n)) => match n.strip_prefix("*.") {
            // A wildcard covers every single label under `rest`, which is
            // inside the suffix iff `rest` is the suffix or below it.
            Some(rest) => rest == s || is_strictly_below(rest, s),
            None => is_strictly_below(n, s),
        },
        (AllowedName::Cidr(c), RequestedName::Ip(ip)) => c.contains(*ip),
        _ => false,
    }
}

fn is_strictly_below(name: &str, suffix: &str) -> bool {
    name.len() > suffix.len() + 1
        && name.ends_with(suffix)
        && name.as_bytes()[name.len() - suffix.len() - 1] == b'.'
}

/// Whether `name` is admitted by any entry of `allowed`. Entries that do not
/// parse match nothing — a hand-edited row fails closed.
pub fn is_name_allowed(allowed: &[String], name: &RequestedName) -> bool {
    allowed
        .iter()
        .filter_map(|e| parse_allowed_name(e).ok())
        .any(|e| allowed_name_matches(&e, name))
}

/// Whether `outer` admits every name `inner` admits: the tighten-only
/// relation a tenant entry must stand in to some organization entry.
pub fn allowed_name_covers(outer: &AllowedName, inner: &AllowedName) -> bool {
    match (outer, inner) {
        (AllowedName::Exact(a), AllowedName::Exact(b)) => a == b,
        (AllowedName::Suffix(s), AllowedName::Exact(h)) => is_strictly_below(h, s),
        (AllowedName::Suffix(s), AllowedName::Suffix(t)) => s == t || is_strictly_below(t, s),
        (AllowedName::Cidr(o), AllowedName::Cidr(i)) => o.covers(i),
        _ => false,
    }
}

/// The tenant entries no organization entry covers — the ones that would
/// widen the baseline. Unparseable tenant entries are reported too.
pub fn uncovered_allowed_names(org: &[String], tenant: &[String]) -> Vec<String> {
    let org: Vec<AllowedName> = org
        .iter()
        .filter_map(|e| parse_allowed_name(e).ok())
        .collect();
    tenant
        .iter()
        .filter(|t| match parse_allowed_name(t) {
            Ok(t) => !org.iter().any(|o| allowed_name_covers(o, &t)),
            Err(_) => true,
        })
        .cloned()
        .collect()
}

/// The names both lists admit, as a list of entries.
///
/// Every pair of entries is either nested (one covers the other) or disjoint,
/// for all three forms, so the intersection is the narrower entry of each
/// nested pair. Order follows the tenant list; duplicates are dropped.
pub fn intersect_allowed_names(tenant: &[String], org: &[String]) -> Vec<String> {
    let org: Vec<(AllowedName, &String)> = org
        .iter()
        .filter_map(|e| parse_allowed_name(e).ok().map(|p| (p, e)))
        .collect();
    let mut out: Vec<String> = Vec::new();
    for raw in tenant {
        let Ok(t) = parse_allowed_name(raw) else {
            continue;
        };
        for (o, o_raw) in &org {
            let meet = if allowed_name_covers(o, &t) {
                Some(raw)
            } else if allowed_name_covers(&t, o) {
                Some(*o_raw)
            } else {
                None
            };
            if let Some(m) = meet
                && !out.contains(m)
            {
                out.push(m.clone());
            }
        }
    }
    out
}

/// The fence both leaf paths run before anything is signed.
///
/// Returns the validated SANs, in request order with duplicates dropped, for
/// the issuing path to put in the certificate. Every refusal is a `400`
/// naming the offending name and never listing the allow-list:
///
/// * a non-`Server` request carrying SANs — only `Server` certificates name
///   hosts;
/// * a `Server` request while `allowed` is empty — the I1: nothing is issued
///   until an organization administrator lists names;
/// * a `Server` request with no SANs — a TLS client reads the SAN list and
///   nothing else (RFC 6125 §6.4.4; webpki ignores the CN entirely);
/// * a SAN, or the common name, that is malformed or not admitted.
///
/// The common name of a non-`Server` certificate is not checked: it is an
/// identifier (`device-001`, a service account id), and the `clientAuth`
/// profile plus the absence of any SAN is what keeps it out of TLS server use.
pub fn check_leaf_names(
    cert_type: &CertificateType,
    common_name: &str,
    sans: &[SubjectAltName],
    allowed: &[String],
) -> AxiamResult<Vec<RequestedName>> {
    let refuse = |message: String| AxiamError::Validation { message };

    if *cert_type != CertificateType::Server {
        if sans.is_empty() {
            return Ok(Vec::new());
        }
        return Err(refuse(format!(
            "subject_alt_names is accepted only for cert_type Server; a {cert_type:?} \
             certificate authenticates a client and names no host"
        )));
    }
    if allowed.is_empty() {
        return Err(refuse(format!(
            "Server certificates cannot be issued in this tenant: {FIELD} is empty. An \
             organization administrator lists the DNS suffixes and IP prefixes AXIAM may \
             issue server certificates for in the organization settings"
        )));
    }
    if sans.is_empty() {
        return Err(refuse(
            "a Server certificate needs at least one subject_alt_names entry: TLS clients \
             match the host against the SAN list and ignore the common name"
                .into(),
        ));
    }
    if sans.len() > MAX_SUBJECT_ALT_NAMES {
        return Err(refuse(format!(
            "subject_alt_names carries {} entries; at most {MAX_SUBJECT_ALT_NAMES} are accepted",
            sans.len()
        )));
    }

    let mut names: Vec<RequestedName> = Vec::with_capacity(sans.len());
    for san in sans {
        let (parsed, raw) = match san {
            SubjectAltName::Dns(n) => (RequestedName::dns(n), n),
            SubjectAltName::Ip(n) => (RequestedName::ip(n), n),
        };
        let name = parsed.map_err(|why| refuse(format!("subject_alt_names: {why}")))?;
        if !is_name_allowed(allowed, &name) {
            return Err(refuse(format!(
                "subject_alt_names: {raw:?} is not admitted by this tenant's {FIELD}"
            )));
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }

    let cn = RequestedName::common_name(common_name)
        .map_err(|why| refuse(format!("the common name of a Server certificate: {why}")))?;
    if !is_name_allowed(allowed, &cn) {
        return Err(refuse(format!(
            "the common name {common_name:?} is not admitted by this tenant's {FIELD}"
        )));
    }

    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(entries: &[&str], name: RequestedName) -> bool {
        let list: Vec<String> = entries.iter().map(|s| s.to_string()).collect();
        is_name_allowed(&list, &name)
    }

    fn dns(n: &str) -> RequestedName {
        RequestedName::dns(n).unwrap()
    }

    fn ip(n: &str) -> RequestedName {
        RequestedName::ip(n).unwrap()
    }

    #[test]
    fn a_leading_dot_matches_strictly_below_on_a_label_boundary() {
        let e = [".lakeside.internal"];
        assert!(allowed(&e, dns("a.lakeside.internal")));
        assert!(allowed(&e, dns("a.b.lakeside.internal")));
        assert!(
            !allowed(&e, dns("lakeside.internal")),
            "the apex is not below itself"
        );
        assert!(
            !allowed(&e, dns("xlakeside.internal")),
            "not a label boundary"
        );
        assert!(!allowed(&e, dns("lakeside.internal.evil.com")));
    }

    #[test]
    fn an_entry_without_a_dot_is_that_host_only() {
        let e = ["lakeside.internal"];
        assert!(allowed(&e, dns("lakeside.internal")));
        assert!(!allowed(&e, dns("a.lakeside.internal")));
        assert!(!allowed(&e, dns("*.lakeside.internal")));
    }

    #[test]
    fn case_is_ignored_on_both_sides() {
        assert!(allowed(
            &[".Lakeside.INTERNAL"],
            dns("API.lakeside.Internal")
        ));
        assert_eq!(
            dns("API.Example.COM"),
            RequestedName::Dns("api.example.com".into())
        );
    }

    #[test]
    fn a_trailing_dot_is_refused_in_requests_and_entries() {
        assert!(RequestedName::dns("api.lakeside.internal.").is_err());
        assert!(parse_allowed_name(".lakeside.internal.").is_err());
        assert!(parse_allowed_name("lakeside.internal.").is_err());
    }

    #[test]
    fn unicode_is_refused_and_a_labels_match_bytewise() {
        let err = RequestedName::dns("shop.bücher.example").unwrap_err();
        assert!(err.contains("A-label"), "{err}");
        assert!(parse_allowed_name(".bücher.example").is_err());
        assert!(allowed(
            &[".xn--bcher-kva.example"],
            dns("shop.xn--bcher-kva.example")
        ));
        assert!(!allowed(
            &[".xn--bcher-kva.example"],
            dns("shop.bucher.example")
        ));
    }

    #[test]
    fn a_wildcard_is_a_whole_leftmost_label_matched_by_a_suffix_at_or_above_it() {
        assert!(allowed(&[".lakeside.internal"], dns("*.lakeside.internal")));
        assert!(allowed(
            &[".lakeside.internal"],
            dns("*.a.lakeside.internal")
        ));
        assert!(!allowed(
            &[".a.lakeside.internal"],
            dns("*.lakeside.internal")
        ));
        assert!(RequestedName::dns("a*.lakeside.internal").is_err());
        assert!(RequestedName::dns("*").is_err());
        assert!(RequestedName::dns("a.*.lakeside.internal").is_err());
        assert!(parse_allowed_name("*.lakeside.internal").is_err());
        assert!(parse_allowed_name(".").is_err());
    }

    #[test]
    fn cidrs_match_their_family_only() {
        let e = ["10.0.0.0/8", "fd00::/8"];
        assert!(allowed(&e, ip("10.1.2.3")));
        assert!(!allowed(&e, ip("11.0.0.1")));
        assert!(allowed(&e, ip("fd12::1")));
        assert!(!allowed(&e, ip("fe80::1")));
        assert!(
            allowed(&["10.0.0.5"], ip("10.0.0.5")),
            "a bare address is a /32"
        );
        assert!(!allowed(&["10.0.0.5"], ip("10.0.0.6")));
        assert!(!allowed(&["::/0"], ip("10.0.0.5")), "v6 never covers v4");
    }

    #[test]
    fn ipv4_mapped_ipv6_is_refused_in_requests_and_entries() {
        let err = RequestedName::ip("::ffff:10.0.0.5").unwrap_err();
        assert!(err.contains("IPv4-mapped"), "{err}");
        assert!(parse_allowed_name("::ffff:0:0/96").is_err());
        assert!(parse_allowed_name("::ffff:10.0.0.5").is_err());
    }

    #[test]
    fn malformed_entries_are_refused_with_the_remedy() {
        assert!(
            parse_allowed_name("10.0.0.1/8")
                .unwrap_err()
                .contains("10.0.0.0/8")
        );
        assert!(parse_allowed_name("10.0.0.0/33").is_err());
        assert!(parse_allowed_name("https://x.example").is_err());
        assert!(parse_allowed_name("").is_err());
        assert!(
            RequestedName::dns("10.0.0.5").is_err(),
            "an IPv4 literal is an ip name"
        );
    }

    #[test]
    fn an_empty_list_admits_nothing_and_a_bad_stored_entry_fails_closed() {
        assert!(!allowed(&[], dns("a.example.com")));
        assert!(!allowed(&["*.example.com"], dns("a.example.com")));
    }

    fn server_sans(v: &[SubjectAltName]) -> AxiamResult<Vec<RequestedName>> {
        check_leaf_names(
            &CertificateType::Server,
            "api.lakeside.internal",
            v,
            &[".lakeside.internal".to_string(), "10.0.0.0/8".to_string()],
        )
    }

    #[test]
    fn the_fence_admits_listed_names_and_refuses_the_rest() {
        let ok = server_sans(&[
            SubjectAltName::Dns("api.lakeside.internal".into()),
            SubjectAltName::Ip("10.0.0.5".into()),
            SubjectAltName::Dns("API.lakeside.internal".into()),
        ])
        .unwrap();
        assert_eq!(ok.len(), 2, "the case-folded duplicate is dropped");
        assert!(server_sans(&[SubjectAltName::Dns("login.example.com".into())]).is_err());
        assert!(server_sans(&[SubjectAltName::Ip("192.168.0.1".into())]).is_err());
        assert!(
            server_sans(&[]).is_err(),
            "a Server leaf names at least one host"
        );
    }

    #[test]
    fn the_fence_checks_the_common_name_too() {
        let err = check_leaf_names(
            &CertificateType::Server,
            "login.example.com",
            &[SubjectAltName::Dns("api.lakeside.internal".into())],
            &[".lakeside.internal".to_string()],
        )
        .unwrap_err();
        assert!(err.to_string().contains("common name"), "{err}");
    }

    #[test]
    fn with_an_empty_list_no_server_certificate_passes() {
        let err = check_leaf_names(
            &CertificateType::Server,
            "api.lakeside.internal",
            &[SubjectAltName::Dns("api.lakeside.internal".into())],
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains(FIELD), "{err}");
    }

    #[test]
    fn only_server_certificates_carry_sans_and_the_rest_are_untouched() {
        for t in [
            CertificateType::User,
            CertificateType::Service,
            CertificateType::Device,
        ] {
            assert!(
                check_leaf_names(
                    &t,
                    "device-001",
                    &[SubjectAltName::Dns("a.x".into())],
                    &[".x".into()]
                )
                .is_err()
            );
            // I4: today's request — no SANs, any CN, any list — passes as today.
            assert_eq!(
                check_leaf_names(&t, "login.example.com", &[], &[]).unwrap(),
                vec![]
            );
        }
    }

    #[test]
    fn a_tenant_may_remove_or_narrow_and_may_not_add_or_widen() {
        let org: Vec<String> = [".lakeside.internal", "10.0.0.0/8", "lakeside.internal"]
            .map(String::from)
            .to_vec();
        let ok = |t: &[&str]| {
            uncovered_allowed_names(&org, &t.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };
        assert!(ok(&[".lakeside.internal"]).is_empty(), "keep");
        assert!(ok(&[]).is_empty(), "remove all");
        assert!(
            ok(&[".a.lakeside.internal", "api.lakeside.internal"]).is_empty(),
            "narrow"
        );
        assert!(
            ok(&["10.1.0.0/16", "10.1.2.3"]).is_empty(),
            "narrow a prefix"
        );
        assert_eq!(ok(&[".internal"]), vec![".internal"], "widen a suffix");
        assert_eq!(ok(&["8.0.0.0/7"]), vec!["8.0.0.0/7"], "widen a prefix");
        assert_eq!(ok(&[".example.com"]), vec![".example.com"], "add");
        assert_eq!(ok(&["*.x"]), vec!["*.x"], "unparseable is uncovered");
    }

    #[test]
    fn the_intersection_never_exceeds_either_side() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        // The org shrinks under a tenant that narrowed to `.a`: `.a` goes, and
        // the org's other entry does not appear in its place.
        assert_eq!(
            intersect_allowed_names(&s(&[".a.x"]), &s(&[".b.x"])),
            Vec::<String>::new()
        );
        // The org narrows below the tenant's entry: the narrower one survives.
        assert_eq!(
            intersect_allowed_names(&s(&[".a.x"]), &s(&[".b.a.x", ".c.y"])),
            s(&[".b.a.x"])
        );
        assert_eq!(
            intersect_allowed_names(&s(&["10.0.0.0/8", ".x"]), &s(&["10.1.0.0/16", ".x"])),
            s(&["10.1.0.0/16", ".x"])
        );
    }
}

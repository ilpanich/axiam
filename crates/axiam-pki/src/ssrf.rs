//! Shared SSRF guard — resolve-once-and-pin outbound fetch helper.
//!
//! Generalizes the byte-identical guard logic previously duplicated in
//! `jwks_cache::is_private_jwks_ip`/`validate_jwks_url` and
//! `axiam-api-rest::webhook::is_private_ip`/`resolve_and_validate_host`
//! (SECHRD-02 / D-01a DRY) into one reusable module, and — critically —
//! adds IP **pinning**, which neither prior guard did: both validated the
//! resolved `IpAddr` and then let `reqwest` re-resolve DNS independently at
//! send time, leaving a DNS-rebind TOCTOU window open between validation and
//! connect (D-01c closes this).
//!
//! Use [`guarded_fetch`] for every outbound fetch to an admin/IdP-supplied
//! URL (JWKS, OIDC discovery, OIDC token exchange, SAML metadata, webhook
//! delivery). It:
//!
//! 1. Resolves the host (A + AAAA) fresh — no cross-request DNS caching
//!    (D-01c).
//! 2. Rejects the fetch if ANY resolved address is non-globally-routable
//!    (D-01a) — unless the caller opted into the `allow_private` test seam
//!    (see below). [`is_disallowed_ip`] enumerates the families and, since
//!    SEC-094, canonicalises the IPv4-in-IPv6 encodings first: an `AAAA`
//!    record carrying `::ffff:169.254.169.254` used to pass this step and
//!    then be *pinned* by step 3.
//! 3. Pins the exact validated `IpAddr` into a fresh, single-use
//!    `reqwest::Client` via `ClientBuilder::resolve()`, so the socket that
//!    is actually opened is the one that was validated — not a second,
//!    independently-resolved address (D-01c).
//! 4. Disables `reqwest`'s automatic redirect following and instead
//!    manually re-runs the FULL guard (resolve → validate → pin → send)
//!    against the `Location` target, bounded to [`MAX_HOPS`] hops (D-01b).
//!
//! ## The `allow_private` test seam only applies to the first hop
//!
//! `allow_private` exists solely so integration tests can point a guarded
//! fetch at a loopback mock server (mirrors the pre-existing
//! `JwksCache::new_allow_private_networks` seam). It is honored **only for
//! the very first hop** of [`guarded_fetch`] — every redirect hop after that
//! is always validated with the strict (production) check, regardless of
//! `allow_private`. A `Location` header is attacker-influenced response
//! data, not the admin-configured URL the caller opted to trust; holding it
//! to the same relaxed standard as the test seam would silently defeat the
//! redirect-bypass defense this module exists to provide (D-01b: "re-run
//! the full SSRF guard against the redirect target").

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

/// Maximum number of redirect hops [`guarded_fetch`] will follow before
/// giving up. Each hop re-runs the full guard against the `Location` target.
const MAX_HOPS: u8 = 3;

/// Errors produced by the shared SSRF guard.
#[derive(Debug, thiserror::Error)]
pub enum SsrfError {
    #[error("invalid URL")]
    InvalidUrl,
    #[error("failed to resolve host")]
    ResolveFailed,
    #[error("SSRF blocked: resolved IP is private/loopback/link-local/unspecified")]
    Blocked,
    #[error("failed to build HTTP client")]
    ClientBuildFailed,
    #[error("HTTP request failed: {0}")]
    RequestFailed(String),
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("SSRF blocked: non-HTTPS scheme not permitted for IdP fetches")]
    InsecureScheme,
    #[error("SSRF blocked: response body exceeds the {0}-byte cap")]
    ResponseTooLarge(usize),
}

/// Maximum acceptable `Content-Length` for a guarded IdP response (SEC-069).
/// Discovery/metadata/token/JWKS documents are small; a multi-GB body is a
/// memory-exhaustion DoS vector. JWKS additionally applies its own 512 KiB
/// read cap downstream; this is the coarse first line of defence for all four
/// federation fetch types.
const MAX_RESPONSE_BYTES: usize = 5 * 1024 * 1024;

/// Returns `true` for IPv4 addresses that must never be contacted from a
/// server-side outbound fetch (SEC-094).
///
/// | Range | RFC | Why |
/// |---|---|---|
/// | `0.0.0.0/8` | RFC 1122 | "this network"; `0.0.0.0` reaches localhost on Linux |
/// | `10/8`, `172.16/12`, `192.168/16` | RFC 1918 | private |
/// | `100.64.0.0/10` | RFC 6598 | CGNAT shared address space — carrier-internal |
/// | `127.0.0.0/8` | RFC 1122 | loopback (the whole /8, not just `127.0.0.1`) |
/// | `169.254.0.0/16` | RFC 3927 | link-local — **the cloud metadata service** |
/// | `192.0.0.0/24` | RFC 6890 | IETF protocol assignments (incl. `192.0.0.8` etc.) |
/// | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | RFC 5737 | documentation |
/// | `192.88.99.0/24` | RFC 7526 | deprecated 6to4 relay anycast |
/// | `198.18.0.0/15` | RFC 2544 | benchmarking |
/// | `224.0.0.0/4` | RFC 5771 | multicast |
/// | `240.0.0.0/4` | RFC 1112 | reserved, incl. `255.255.255.255` broadcast |
///
/// `Ipv4Addr::is_shared`, `is_documentation`, `is_benchmarking` and
/// `is_reserved` are all still unstable (`#![feature(ip)]`), hence the
/// hand-rolled octet arithmetic.
fn is_disallowed_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || o[0] == 0 // 0.0.0.0/8 — not merely `is_unspecified()`
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24
        || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24
        || o[0] >= 240 // 240.0.0.0/4 reserved + broadcast
}

/// Returns `true` for IPv6 addresses that must never be contacted.
///
/// Callers reach this only via [`is_disallowed_ip`], which has already dealt
/// with the two `::`-prefixed IPv4-in-IPv6 forms — `::ffff:a.b.c.d` is
/// canonicalised to [`is_disallowed_ipv4`], `::a.b.c.d` is rejected outright.
/// What is left here is either genuinely-v6 or a *transition* encoding, and the
/// transition encodings are handled explicitly below because each one can name
/// an internal v4 host.
fn is_disallowed_ipv6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();

    // 6to4, 2002::/16 (RFC 3056): bits 16..48 are the IPv4 address of the
    // 6to4 site. `2002:7f00:0001::1` is 127.0.0.1; `2002:a9fe:a9fe::1` is the
    // metadata service. The prefix as a whole cannot be blocked (it maps the
    // ENTIRE public IPv4 space), so classify the address it embeds.
    if s[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        );
        if is_disallowed_ipv4(embedded) {
            return true;
        }
    }

    // NAT64 well-known prefix, 64:ff9b::/96 (RFC 6052): low 32 bits are the
    // IPv4 destination. Same reasoning as 6to4 — classify what it embeds.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        let embedded = Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        );
        if is_disallowed_ipv4(embedded) {
            return true;
        }
    }

    v6.is_loopback()                            // ::1
        || v6.is_unspecified()                  // ::
        || v6.is_multicast()                    // ff00::/8
        || (s[0] & 0xffc0) == 0xfe80            // fe80::/10 link-local
        || (s[0] & 0xffc0) == 0xfec0            // fec0::/10 site-local (deprecated, RFC3879)
        || (s[0] & 0xfe00) == 0xfc00            // fc00::/7 unique-local
        || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // 100::/64 discard-only
        || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001)    // 64:ff9b:1::/48 local NAT64
        // 2001::/23 IETF protocol assignments (RFC 2928): Teredo 2001::/32,
        // benchmarking 2001:2::/48, ORCHIDv2 2001:20::/28. Teredo in
        // particular embeds BOTH a server and an (obfuscated) client IPv4
        // address; the whole /23 is non-global-unicast, so block it outright.
        || (s[0] == 0x2001 && (s[1] & 0xfe00) == 0x0000)
        || (s[0] == 0x2001 && s[1] == 0x0db8)   // 2001:db8::/32 documentation
        || (s[0] == 0x3fff && (s[1] & 0xf000) == 0) // 3fff::/20 documentation (RFC 9637)
}

/// Returns `true` for IP addresses that must never be contacted from a
/// server-side outbound fetch to an admin/IdP-supplied URL.
///
/// # SEC-094 — canonicalisation happens FIRST
///
/// The predicate this replaced matched on the `IpAddr` variant as it arrived
/// from `getaddrinfo`. An `AAAA` record may legally contain an IPv4-mapped
/// address (`::ffff:169.254.169.254`), whose `segments()[0]` is `0x0000`: it
/// matched none of the v6 arms, and the v4 arms were never consulted because
/// the value was an `IpAddr::V6`. The address then went straight into
/// `ClientBuilder::resolve()`, so the pinning that closes the DNS-rebind
/// window (D-01c) *guaranteed* the attacker's address was the one dialled —
/// and on a dual-stack host `connect()` to `::ffff:a.b.c.d` reaches the IPv4
/// destination.
///
/// Both IPv4-in-IPv6 embeddings are folded before classification:
///
/// * `::ffff:0:0/96` — IPv4-mapped. Legitimate: `getaddrinfo` with
///   `AI_V4MAPPED` returns it for real v4 hosts, so it is *canonicalised*
///   (checked as the v4 address it denotes) rather than rejected outright.
/// * `::/96` — IPv4-compatible, deprecated by RFC 4291 §2.5.5.1. Rejected
///   outright; nothing legitimate resolves to it. Note that
///   `IpAddr::to_canonical` does **not** fold this form (it delegates to
///   `to_ipv4_mapped`, not `to_ipv4`), which is why it is handled here by
///   hand.
pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // ::ffff:a.b.c.d — classify as the v4 address it denotes.
            Some(v4) => is_disallowed_ipv4(v4),
            None => {
                // ::/96 (IPv4-compatible, deprecated) — always rejected. `::`
                // and `::1` fall in this range too and are disallowed anyway.
                if is_ipv4_compatible_v6(v6) {
                    return true;
                }
                is_disallowed_ipv6(v6)
            }
        },
    }
}

/// `::/96` — the deprecated IPv4-compatible form, plus `::` and `::1`.
fn is_ipv4_compatible_v6(v6: Ipv6Addr) -> bool {
    let s = v6.segments();
    s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0
}

/// Resolve `host:port` (A + AAAA), reject if ANY resolved address is
/// disallowed, and return ONE validated address to pin into the connection.
///
/// `allow_private`, when `true`, skips the disallow check entirely. This
/// exists solely to preserve the pre-existing loopback mock-server
/// integration-test seam (mirrors `JwksCache::new_allow_private_networks`);
/// it MUST be `false` in production code paths.
pub async fn resolve_and_pick(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<IpAddr, SsrfError> {
    let addrs: Vec<IpAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| SsrfError::ResolveFailed)?
        .map(|a| a.ip())
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::ResolveFailed);
    }

    if !allow_private && addrs.iter().any(|ip| is_disallowed_ip(*ip)) {
        return Err(SsrfError::Blocked);
    }

    Ok(addrs[0])
}

/// Build a fresh, single-use client pinned to `ip` for `host`.
///
/// No connection pooling/caching across requests — a new `Client` is built
/// per guarded fetch (D-01c: "fresh per request", so a rebind between two
/// calls minutes apart can never reuse a stale pinned connection). Automatic
/// redirect following is disabled (D-01b) — [`guarded_fetch`] re-validates
/// and re-issues each hop explicitly instead of trusting `reqwest` to follow
/// a `Location` header unchecked.
pub fn pinned_client(host: &str, ip: IpAddr, port: u16) -> Result<reqwest::Client, SsrfError> {
    reqwest::Client::builder()
        .resolve(host, SocketAddr::new(ip, port))
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| SsrfError::ClientBuildFailed)
}

/// Orchestrates resolve + pin + fetch + bounded manual redirect
/// re-validation (D-01b), using the default [`MAX_RESPONSE_BYTES`] cap.
///
/// `allow_private` is honored only for the first hop — see the module docs
/// for why redirect targets are always strictly validated regardless of the
/// caller's test-seam opt-in.
///
/// `build_request` builds the actual request (e.g. `|c, u| c.get(u)` or
/// `|c, u| c.post(u).form(&params)`) against the freshly pinned client for
/// the current hop's URL.
pub async fn guarded_fetch(
    url: &str,
    allow_private: bool,
    build_request: impl Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, SsrfError> {
    guarded_fetch_with_cap(url, allow_private, MAX_RESPONSE_BYTES, build_request).await
}

/// Same as [`guarded_fetch`], but with an explicit Content-Length cap
/// instead of the hard-coded default [`MAX_RESPONSE_BYTES`] (SEC-069).
///
/// Added for the FIDO MDS3 BLOB fetch path (D2/D10, X3): the BLOB is
/// legitimately ~10 MB, well over the 5 MiB default every other guarded
/// fetch type (JWKS, OIDC discovery, token, SAML metadata, webhook
/// delivery) uses. This does **not** change the cap for any of those
/// existing callers — [`guarded_fetch`] still always uses
/// `MAX_RESPONSE_BYTES`; only a caller that deliberately opts in by naming
/// its own cap (e.g. `axiam_pki::mds::MDS_MAX_BLOB_BYTES`) gets a larger one.
pub async fn guarded_fetch_with_cap(
    url: &str,
    allow_private: bool,
    max_response_bytes: usize,
    build_request: impl Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, SsrfError> {
    let mut current = url.to_string();

    for hop in 0..MAX_HOPS {
        let parsed = url::Url::parse(&current).map_err(|_| SsrfError::InvalidUrl)?;
        let host = parsed.host_str().ok_or(SsrfError::InvalidUrl)?.to_string();
        let port = parsed.port_or_known_default().unwrap_or(443);

        // Only the first hop honors the caller's test seam; every redirect
        // hop thereafter is always strictly validated (module docs above).
        let hop_allow_private = allow_private && hop == 0;

        // SEC-069: enforce HTTPS for every hop. A plaintext `http://` IdP
        // endpoint (admin-misconfigured, or an attacker-supplied redirect)
        // would carry the decrypted client_secret / bearer material in the
        // clear. `http` is tolerated only behind the private-network test seam
        // (loopback/dev), exactly like the address checks.
        if parsed.scheme() != "https" && !hop_allow_private {
            return Err(SsrfError::InsecureScheme);
        }

        let ip = resolve_and_pick(&host, port, hop_allow_private).await?;
        let client = pinned_client(&host, ip, port)?;

        let resp = build_request(&client, &current)
            .send()
            .await
            .map_err(|e| SsrfError::RequestFailed(e.to_string()))?;

        if resp.status().is_redirection() {
            let location = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .ok_or(SsrfError::InvalidUrl)?
                .to_string();
            current = parsed
                .join(&location)
                .map_err(|_| SsrfError::InvalidUrl)?
                .to_string();
            continue;
        }

        // SEC-069: reject an over-large advertised body before the caller
        // buffers it. This is the coarse Content-Length gate; body readers that
        // need a hard guarantee against a lying/chunked response still apply
        // their own streaming cap (JWKS: 512 KiB).
        if let Some(len) = resp.content_length()
            && len > max_response_bytes as u64
        {
            return Err(SsrfError::ResponseTooLarge(max_response_bytes));
        }

        return Ok(resp);
    }

    Err(SsrfError::TooManyRedirects)
}

/// Read a response body with a hard streaming cap, aborting as soon as `cap`
/// is exceeded — WITHOUT buffering the rest of the body first (CQ-B23).
///
/// This replaces the previous "buffer the whole body via `.bytes()`, then
/// check `.len()` against the cap" pattern used by discovery/token-exchange
/// reads. That pattern still let a malicious or misconfigured endpoint force
/// full in-memory buffering of an arbitrarily large response before the
/// existing size check ever ran (the coarse `Content-Length`-based check in
/// [`guarded_fetch`] above only catches endpoints that both send the header
/// AND tell the truth about it — a chunked, no-`Content-Length` response
/// bypasses it entirely). Reading chunk-by-chunk with a running byte count
/// bounds peak memory use to ~`cap` bytes regardless.
///
/// Uses `reqwest::Response::chunk()` (always available, unlike
/// `bytes_stream()` which needs the `stream` cargo feature this workspace
/// does not enable) so no new dependency/feature is required.
pub async fn read_capped_body(
    mut response: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, SsrfError> {
    let mut buf = Vec::with_capacity(cap.min(64 * 1024));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| SsrfError::RequestFailed(e.to_string()))?
    {
        buf.extend_from_slice(&chunk);
        if buf.len() > cap {
            return Err(SsrfError::ResponseTooLarge(cap));
        }
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
            let ip: IpAddr = literal.parse().expect("literal parses");
            assert!(
                is_disallowed_ip(ip),
                "{literal}: IPv4-mapped IPv6 must be canonicalised and blocked (SEC-094)"
            );
        }
    }

    /// SEC-094 — table-driven classification over every family the guard is
    /// responsible for. `expect_blocked` is the assertion; the comment on each
    /// row is why.
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
            let ip: IpAddr = literal.parse().unwrap_or_else(|e| {
                panic!("test table literal {literal:?} does not parse: {e}");
            });
            let actual = is_disallowed_ip(ip);
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

    /// SEC-094 — end-to-end: the mapped form must be rejected by
    /// `resolve_and_pick`, i.e. before `pinned_client` can pin it. Uses a
    /// literal host (no DNS) so the test is hermetic; a hostile `AAAA` record
    /// reaches the identical code path.
    #[tokio::test]
    async fn sec094_mapped_literal_host_is_blocked_before_pinning() {
        for host in ["::ffff:169.254.169.254", "::ffff:127.0.0.1"] {
            let result = resolve_and_pick(host, 443, false).await;
            assert!(
                matches!(result, Err(SsrfError::Blocked)),
                "{host} must be Blocked, not pinned; got: {result:?}"
            );
        }
    }

    /// SECHRD-02 negative test (SC #1): an OIDC discovery document whose
    /// `token_endpoint` resolves to a loopback address must be rejected
    /// before any request is sent.
    #[tokio::test]
    async fn ssrf_rejects_loopback_token_endpoint() {
        let result = resolve_and_pick("localhost", 443, false).await;
        assert!(
            matches!(result, Err(SsrfError::Blocked)),
            "expected loopback host to be blocked, got: {result:?}"
        );

        let result = resolve_and_pick("127.0.0.1", 443, false).await;
        assert!(
            matches!(result, Err(SsrfError::Blocked)),
            "expected loopback IP to be blocked, got: {result:?}"
        );
    }

    /// SECHRD-02 / D-01b negative test (SC #1): a 302 whose `Location`
    /// resolves to an internal address is rejected, not silently followed.
    ///
    /// The initial hop uses the `allow_private=true` test seam to reach a
    /// loopback mock server (mirrors `JwksCache::new_allow_private_networks`);
    /// the redirect hop must still be blocked, proving it is re-validated
    /// against the strict check rather than inheriting the seam.
    #[tokio::test]
    async fn ssrf_rejects_redirect_to_internal() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                // https target so the redirect hop is rejected by the ADDRESS
                // re-validation (SsrfError::Blocked), independent of the
                // SEC-069 scheme check — that scheme enforcement has its own
                // test below.
                let response = b"HTTP/1.1 302 Found\r\n\
                    Location: https://10.0.0.5/internal\r\n\
                    Content-Length: 0\r\n\
                    Connection: close\r\n\r\n";
                let _ = stream.write_all(response).await;
            }
        });

        let url = format!("http://127.0.0.1:{}/token", addr.port());

        let result = guarded_fetch(&url, true, |c, u| c.get(u)).await;
        assert!(
            matches!(result, Err(SsrfError::Blocked)),
            "expected redirect to internal address to be blocked, got: {result:?}"
        );
    }

    /// SEC-069: a plaintext `http://` endpoint is rejected on a non-seam hop
    /// (the redirect target below is a routable public host, so it is not
    /// address-blocked — only the scheme gate rejects it).
    #[tokio::test]
    async fn ssrf_rejects_plaintext_redirect_target() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = b"HTTP/1.1 302 Found\r\n\
                    Location: http://example.com/downgraded\r\n\
                    Content-Length: 0\r\n\
                    Connection: close\r\n\r\n";
                let _ = stream.write_all(response).await;
            }
        });

        let url = format!("http://127.0.0.1:{}/token", addr.port());
        let result = guarded_fetch(&url, true, |c, u| c.get(u)).await;
        assert!(
            matches!(result, Err(SsrfError::InsecureScheme)),
            "expected a plaintext redirect target to be rejected by the scheme gate, got: {result:?}"
        );
    }

    /// SEC-069: a plaintext first hop with no private-network seam is rejected
    /// by the scheme gate (before any DNS resolution).
    #[tokio::test]
    async fn ssrf_rejects_plaintext_first_hop() {
        let result = guarded_fetch("http://example.com/x", false, |c, u| c.get(u)).await;
        assert!(
            matches!(result, Err(SsrfError::InsecureScheme)),
            "expected a plaintext first hop (no seam) to be rejected, got: {result:?}"
        );
    }

    /// D2/D10 (X3): `guarded_fetch_with_cap` accepts a response whose
    /// advertised Content-Length exceeds the default [`MAX_RESPONSE_BYTES`]
    /// but is within the caller-supplied cap — proving the MDS BLOB fetch
    /// path (~10 MB, opting into a 32 MiB cap) is not silently rejected by
    /// the coarse gate the default-cap `guarded_fetch` would apply.
    #[tokio::test]
    async fn guarded_fetch_with_cap_allows_body_over_default_cap_but_within_custom_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");
        // Bigger than MAX_RESPONSE_BYTES (5 MiB) would allow via `guarded_fetch`.
        let big_len = MAX_RESPONSE_BYTES + 1024;

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                // Only the headers matter for this test — `guarded_fetch_with_cap`
                // decides from Content-Length before the body is ever read.
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {big_len}\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let url = format!("http://127.0.0.1:{}/big", addr.port());

        // Default cap: rejected.
        let default_result = guarded_fetch(&url, true, |c, u| c.get(u)).await;
        assert!(
            matches!(default_result, Err(SsrfError::ResponseTooLarge(cap)) if cap == MAX_RESPONSE_BYTES),
            "expected the default cap to reject a body this large, got: {default_result:?}"
        );

        // MDS-sized cap: accepted (the coarse Content-Length gate passes;
        // the connection is dropped afterward so `.send()` may itself race
        // with `Connection: close`, which is irrelevant to what this test
        // is asserting — that the cap comparison itself used our larger
        // value, not the default).
        let mds_cap = MAX_RESPONSE_BYTES + 2 * 1024 * 1024;
        let capped_result = guarded_fetch_with_cap(&url, true, mds_cap, |c, u| c.get(u)).await;
        assert!(
            !matches!(capped_result, Err(SsrfError::ResponseTooLarge(_))),
            "expected a body within the custom cap to pass the Content-Length gate, got: {capped_result:?}"
        );
    }

    /// CQ-B23: a body within the cap is read in full.
    #[tokio::test]
    async fn read_capped_body_allows_body_within_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");
        let body = b"{\"hello\":\"world\"}";

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(body).await;
            }
        });

        let url = format!("http://127.0.0.1:{}/small", addr.port());
        let response = reqwest::Client::new().get(&url).send().await.unwrap();
        let result = read_capped_body(response, 1024).await;

        assert_eq!(result.expect("body within cap must be read"), body);
    }

    /// CQ-B23: a body exceeding the cap is rejected — via a chunked,
    /// no-`Content-Length` response so the ONLY thing that can catch it is
    /// the streaming running-byte-count check, not the coarse
    /// `Content-Length` gate in [`guarded_fetch`] (which this test bypasses
    /// by calling `read_capped_body` directly on a plain `reqwest` response).
    #[tokio::test]
    async fn read_capped_body_rejects_body_over_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        const CAP: usize = 16;

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local_addr");

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                // Chunked transfer-encoding, no Content-Length: a body far
                // larger than CAP, split across multiple chunks so the
                // reader must actually stream (not just look at one read).
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let chunk = "x".repeat(32);
                for _ in 0..8 {
                    let framed = format!("{:x}\r\n{}\r\n", chunk.len(), chunk);
                    let _ = stream.write_all(framed.as_bytes()).await;
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
            }
        });

        let url = format!("http://127.0.0.1:{}/big", addr.port());
        let response = reqwest::Client::new().get(&url).send().await.unwrap();
        let result = read_capped_body(response, CAP).await;

        assert!(
            matches!(result, Err(SsrfError::ResponseTooLarge(CAP))),
            "expected ResponseTooLarge({CAP}), got: {result:?}"
        );
    }
}

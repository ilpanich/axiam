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

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
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

// ---------------------------------------------------------------------------
// SEC-107 — the operator's same-network exception
// ---------------------------------------------------------------------------

/// The environment variable that names the exception hosts.
///
/// Comma-separated **host names or literal IPs**, matched exactly. Unset or
/// empty — the default, and what every deployment gets until an operator
/// decides otherwise — means the address rule admits no exceptions at all.
pub const ALLOWED_HOSTS_ENV: &str = "AXIAM__PKI__SSRF_ALLOWED_HOSTS";

static ALLOWED_HOSTS: OnceLock<BTreeSet<String>> = OnceLock::new();

/// Install the operator's SSRF host exception list (SEC-107).
///
/// # Why an exception exists at all
///
/// The address rule is a *network-topology* control being used as a *trust*
/// control, and in real deployments the two diverge: a Kubernetes-internal
/// Keycloak or Entra proxy at `10.x` is a perfectly legitimate IdP, and so is
/// an internal webhook consumer, an internal MDS mirror, or an air-gapped
/// deployment where *everything* is RFC1918. With no exception at all, an
/// operator's only recourse is to run AXIAM outside the guard's assumptions or
/// to patch the binary — and a guard that gets patched around protects nobody.
/// It has already cost this project measurable work (R5.4's cross-vendor
/// Keycloak test cannot use the containerized server for exactly this reason).
///
/// # Why it is a host list and not a switch or a CIDR range
///
/// A boolean `SSRF_ALLOW_PRIVATE=true` is the `verify_peer: false` of this
/// module: it appears in a dev compose file, works, and travels unchanged into
/// production. A CIDR exception can be *widened by a DNS answer* — allow
/// `10.0.0.0/8` and any hostname an admin can set now reaches anything in it.
/// A host exception cannot: the operator names the exact destination they
/// intend to reach, and a DNS answer for some *other* host is still blocked.
///
/// # The four properties that keep it from being a hole
///
/// 1. **Default-empty.** Nothing is exempt unless this is called with a
///    non-empty list. It is a `OnceLock`, so it is set once at composition and
///    cannot be re-armed later by anything.
/// 2. **Exact match only.** ASCII-lowercased equality — no wildcards, no
///    suffix matching, no "ends with .internal". `*.corp` cannot be spelled.
/// 3. **First hop only.** Redirect targets are always validated strictly, for
///    the reason the module docs give about `allow_private`: a `Location`
///    header is attacker-influenced response data, not the URL the operator
///    chose to trust.
/// 4. **The metadata services stay unreachable** — [`is_never_allowed`]. An
///    operator asking for their `10.x` IdP is not asking for
///    `169.254.169.254`, and an allowlisted host whose DNS is poisoned onto a
///    metadata endpoint is exactly the attack this control would otherwise
///    re-open. That includes SEC-094's IPv4-mapped spelling, because the
///    canonicalisation runs before this check, not after it.
///
/// Returns the number of entries installed. Calling it twice is a no-op on the
/// second call (the `OnceLock` keeps the first list), which is deliberate:
/// re-arming a security exception at runtime is not a feature.
pub fn set_allowed_hosts<I: IntoIterator<Item = String>>(hosts: I) -> usize {
    let set: BTreeSet<String> = hosts
        .into_iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    let _ = ALLOWED_HOSTS.set(set);
    allowed_hosts().len()
}

/// Parse the comma-separated [`ALLOWED_HOSTS_ENV`] form.
pub fn parse_allowed_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

/// The installed exception list. Empty until [`set_allowed_hosts`] is called.
pub fn allowed_hosts() -> &'static BTreeSet<String> {
    static EMPTY: OnceLock<BTreeSet<String>> = OnceLock::new();
    ALLOWED_HOSTS
        .get()
        .unwrap_or_else(|| EMPTY.get_or_init(BTreeSet::new))
}

/// Whether `host` is one the operator explicitly named (SEC-107).
fn host_is_allowlisted(host: &str) -> bool {
    let set = allowed_hosts();
    !set.is_empty() && set.contains(&host.trim().to_ascii_lowercase())
}

// The address classification — which families are loopback, link-local,
// private, special-purpose or global, SEC-094's canonicalisation of the
// IPv4-in-IPv6 encodings, and SEC-107's never-allowed metadata endpoints — lives
// in `axiam_core::ip_class` since T23.3.7, so the directory connector's address
// guard (T-300) classifies exactly as this one does. The policy stays here.
// `is_disallowed_ip` is re-exported because callers outside this crate (the
// webhook tests among them) have always reached it as `ssrf::is_disallowed_ip`.
pub use axiam_core::ip_class::is_disallowed_ip;
use axiam_core::ip_class::is_never_allowed;

/// Resolve `host:port` (A + AAAA), reject if ANY resolved address is
/// disallowed, and return ONE validated address to pin into the connection.
///
/// `allow_private`, when `true`, skips the disallow check entirely. This
/// exists solely to preserve the pre-existing loopback mock-server
/// integration-test seam (mirrors `JwksCache::new_allow_private_networks`);
/// it MUST be `false` in production code paths.
///
/// SEC-107: a host the operator named through [`set_allowed_hosts`] is also
/// exempt from the address rule — but only from the *address* rule, only on
/// this hop, and never for a metadata endpoint ([`is_never_allowed`]). Every
/// use of the exception is logged at WARN with the host and the address it
/// resolved to, so a poisoned answer for an allowlisted name leaves a record
/// rather than passing silently.
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

    if allow_private {
        return Ok(addrs[0]);
    }

    if let Some(bad) = addrs.iter().find(|ip| is_disallowed_ip(**ip)) {
        // The exception is evaluated only once the strict rule has already
        // said no, so an allowlisted host that resolves to a public address
        // costs nothing and logs nothing.
        if !host_is_allowlisted(host) {
            return Err(SsrfError::Blocked);
        }
        if let Some(forbidden) = addrs.iter().find(|ip| is_never_allowed(**ip)) {
            tracing::error!(
                host,
                address = %forbidden,
                "SSRF: {host} is on {ALLOWED_HOSTS_ENV} but resolved to a cloud metadata \
                 endpoint; refusing. An allowlist entry exempts a host from the \
                 private-address rule, never from this one — treat this as a possible \
                 DNS poisoning attempt against a trusted name."
            );
            return Err(SsrfError::Blocked);
        }
        tracing::warn!(
            host,
            address = %bad,
            "SSRF: allowing a non-routable address because {host} is named in \
             {ALLOWED_HOSTS_ENV}"
        );
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

/// One guarded hop that **never follows a redirect** (G-5, T23.5.3, D-53 (9)).
///
/// The same resolve (A + AAAA, fresh), refusal of any non-global address, HTTPS
/// requirement (waived only with `allow_private`, the test seam), IP pinning and
/// `Content-Length` cap as [`guarded_fetch`], on the one URL it is given. A `3xx`
/// is **returned to the caller as a response** — its `Location` is not resolved,
/// not validated and not fetched — so a caller that must not send a body or a
/// credential anywhere but the address it was given (an SSF push, whose
/// `Authorization` header would otherwise follow a redirect) can refuse a
/// redirect by construction instead of by inspecting a later hop.
///
/// [`guarded_fetch`] and [`guarded_fetch_with_cap`] are unchanged.
pub async fn guarded_fetch_no_redirect(
    url: &str,
    allow_private: bool,
    build_request: impl Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, SsrfError> {
    let parsed = url::Url::parse(url).map_err(|_| SsrfError::InvalidUrl)?;
    let host = parsed.host_str().ok_or(SsrfError::InvalidUrl)?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    // SEC-069, as on the first hop of `guarded_fetch`.
    if parsed.scheme() != "https" && !allow_private {
        return Err(SsrfError::InsecureScheme);
    }

    let ip = resolve_and_pick(&host, port, allow_private).await?;
    let client = pinned_client(&host, ip, port)?;
    let resp = build_request(&client, url)
        .send()
        .await
        .map_err(|e| SsrfError::RequestFailed(e.to_string()))?;

    if let Some(len) = resp.content_length()
        && len > MAX_RESPONSE_BYTES as u64
    {
        return Err(SsrfError::ResponseTooLarge(MAX_RESPONSE_BYTES));
    }
    Ok(resp)
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

    // -- SEC-107: the operator's same-network exception --------------------

    /// One test, not four, because the allowlist is a process-global
    /// `OnceLock` — it is set once at composition and cannot be re-armed,
    /// which is one of the four properties that keep it from being a hole.
    ///
    /// The hosts named here (`10.0.0.1`, `169.254.169.254`) are used by no
    /// other test in this binary, so installing them cannot make some other
    /// test's blocked address pass. `localhost` and the `::ffff:` literals
    /// that `ssrf_rejects_loopback_token_endpoint` and
    /// `sec094_mapped_literal_host_is_blocked_before_pinning` rely on are
    /// deliberately NOT allowlisted.
    #[tokio::test]
    async fn sec107_the_host_allowlist_is_exact_scoped_and_cannot_reach_metadata() {
        // Default-empty: nothing is exempt until an operator says so.
        assert!(
            allowed_hosts().is_empty(),
            "the allowlist must start empty; some other test installed one"
        );
        assert!(matches!(
            resolve_and_pick("10.0.0.1", 443, false).await,
            Err(SsrfError::Blocked)
        ));

        let installed = set_allowed_hosts(parse_allowed_hosts(
            "  10.0.0.1 , 169.254.169.254 ,, 10.0.0.1 ",
        ));
        assert_eq!(installed, 2, "entries are trimmed and de-duplicated");

        // 1. The named host reaches its private address.
        assert_eq!(
            resolve_and_pick("10.0.0.1", 443, false)
                .await
                .expect("an allowlisted host may resolve to a private address"),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );

        // 2. Exact match only — no suffix or wildcard semantics. A sibling
        //    address in the same /8 is a different host and stays blocked, so
        //    the exception cannot be widened into a CIDR by accident.
        for other in ["10.0.0.2", "192.168.1.1", "127.0.0.1", "localhost"] {
            assert!(
                matches!(
                    resolve_and_pick(other, 443, false).await,
                    Err(SsrfError::Blocked)
                ),
                "{other} was never named and must stay blocked"
            );
        }

        // 3. An allowlist entry never reaches a cloud metadata endpoint, even
        //    when the operator names it outright — which is also what a
        //    poisoned DNS answer for a trusted name looks like.
        assert!(matches!(
            resolve_and_pick("169.254.169.254", 443, false).await,
            Err(SsrfError::Blocked)
        ));

        // 4. And SEC-094 is not re-opened by SEC-107: the mapped spelling is
        //    canonicalised before the metadata check, so it is refused too.
        assert!(is_never_allowed(
            "::ffff:169.254.169.254".parse::<IpAddr>().unwrap()
        ));
        for addr in [
            "169.254.169.254",
            "169.254.170.2",
            "fd00:ec2::254",
            "100.100.100.200",
            "192.0.0.192",
            "fe80::1",
            "::1",
        ] {
            assert!(
                is_never_allowed(addr.parse::<IpAddr>().unwrap()),
                "{addr} must be unreachable through the allowlist"
            );
        }
        // A genuinely-internal IdP address is NOT on that list — the
        // exception has to be able to do its job.
        for addr in ["10.0.0.1", "192.168.1.10", "172.16.0.5", "fd12:3456::1"] {
            assert!(!is_never_allowed(addr.parse::<IpAddr>().unwrap()));
        }

        // 5. Set-once: a second call cannot re-arm it.
        set_allowed_hosts(vec!["evil.example".to_string()]);
        assert!(!allowed_hosts().contains("evil.example"));
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

    // -- D-53 (9): one guarded hop that returns a redirect instead of following it --

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn no_redirect_returns_a_3xx_and_never_fetches_its_target() {
        let target = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&target)
            .await;
        let origin = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("Location", target.uri().as_str()),
            )
            .expect(1)
            .mount(&origin)
            .await;

        // The test seam admits the first (only) hop to loopback.
        let response = guarded_fetch_no_redirect(&origin.uri(), true, |c, u| c.post(u).body("x"))
            .await
            .expect("a 3xx is a response, not an error");
        assert_eq!(response.status().as_u16(), 307);
        assert_eq!(
            response.headers().get("location").map(|v| v.as_bytes()),
            Some(target.uri().as_bytes())
        );
        // `expect(0)` is verified when the server drops: the target saw nothing.
        target.verify().await;
        origin.verify().await;
    }

    /// A redirect to an address the guard refuses is returned, not fetched and
    /// not judged: its `Location` is never resolved.
    #[tokio::test]
    async fn no_redirect_returns_a_redirect_to_an_internal_address_without_fetching_it() {
        let origin = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://169.254.169.254/latest/meta-data"),
            )
            .mount(&origin)
            .await;
        let response = guarded_fetch_no_redirect(&origin.uri(), true, |c, u| c.post(u))
            .await
            .expect("returned, not an SSRF error");
        assert_eq!(response.status().as_u16(), 302);
    }

    /// The one hop gets the whole guard.
    #[tokio::test]
    async fn no_redirect_keeps_the_guard_on_the_one_hop() {
        for url in [
            "https://127.0.0.1:9/x",
            "https://localhost:9/x",
            // Not 10.0.0.1 or the metadata address: the SEC-107 test installs
            // the process-wide allow-list with exactly those.
            "https://192.168.7.7/x",
            "https://172.20.1.1/x",
        ] {
            let result = guarded_fetch_no_redirect(url, false, |c, u| c.get(u)).await;
            assert!(
                matches!(result, Err(SsrfError::Blocked)),
                "{url} must be blocked, got {result:?}"
            );
        }
        // Plaintext is refused before anything resolves.
        let result =
            guarded_fetch_no_redirect("http://93.184.216.34/x", false, |c, u| c.get(u)).await;
        assert!(matches!(result, Err(SsrfError::InsecureScheme)));
        let result = guarded_fetch_no_redirect("not a url", false, |c, u| c.get(u)).await;
        assert!(matches!(result, Err(SsrfError::InvalidUrl)));
    }

    #[tokio::test]
    async fn no_redirect_honours_the_content_length_cap() {
        let origin = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(vec![b'a'; MAX_RESPONSE_BYTES + 1]),
            )
            .mount(&origin)
            .await;
        let result = guarded_fetch_no_redirect(&origin.uri(), true, |c, u| c.get(u)).await;
        assert!(matches!(result, Err(SsrfError::ResponseTooLarge(_))));
    }

    #[tokio::test]
    async fn no_redirect_returns_an_ordinary_answer_unchanged() {
        let origin = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&origin)
            .await;
        let response = guarded_fetch_no_redirect(&origin.uri(), true, |c, u| c.post(u))
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 202);
    }
}

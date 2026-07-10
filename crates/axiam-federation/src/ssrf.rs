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
//! 2. Rejects the fetch if ANY resolved address is
//!    loopback/private/link-local/ULA/unspecified (D-01a) — unless the
//!    caller opted into the `allow_private` test seam (see below).
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

use std::net::{IpAddr, SocketAddr};
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

/// Returns `true` for IP addresses that must never be contacted from a
/// server-side outbound fetch to an admin/IdP-supplied URL.
///
/// Covers: RFC1918 private ranges, loopback (127/8 and ::1), link-local
/// (169.254/16 and fe80::/10), broadcast (255.255.255.255), and unspecified
/// (0.0.0.0 / ::). Lifted byte-identical from the two pre-existing
/// duplicate copies (`jwks_cache::is_private_jwks_ip`,
/// `webhook::is_private_ip`) — this is the D-01a dedup target.
pub fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0 == 0xfe80) // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00 == 0xfc00) // unique-local fc00::/7
        }
    }
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
/// re-validation (D-01b).
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
            && len > MAX_RESPONSE_BYTES as u64
        {
            return Err(SsrfError::ResponseTooLarge(MAX_RESPONSE_BYTES));
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

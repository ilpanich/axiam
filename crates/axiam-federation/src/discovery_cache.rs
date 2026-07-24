//! OIDC discovery-document cache (plan A4 / CQ-B23).
//!
//! - 1-hour TTL — return the cached document if `fetched_at + 1h > now`.
//! - 24-hour stale-while-revalidate — if the discovery endpoint is
//!   unreachable but the cache entry is no older than 24 h past TTL, serve
//!   the stale document with a WARN log rather than surfacing an error.
//!
//! Modeled directly on [`crate::jwks_cache::JwksCache`]: same
//! `Arc<RwLock<map>>` shape, the same TTL/stale-window constants, and the
//! same `allow_private_networks` SSRF test seam (mirrored, not shared,
//! because `OidcFederationService::discover` needs its own cache instance
//! distinct from the JWKS cache — see `oidc.rs`).
//!
//! Keyed by `metadata_url` rather than `(tenant_id, federation_config_id)`:
//! unlike JWKS lookups (which key by the per-config tuple passed in
//! explicitly by `verify_id_token`), an OIDC discovery document is a pure
//! function of the metadata_url alone, so keying by URL is both sufficient
//! and naturally dedupes configs/tenants that happen to share a
//! metadata_url.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::error::FederationError;
use crate::oidc::OidcDiscoveryDocument;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Discovery-document cache TTL (1 hour) — mirrors `jwks_cache::TTL`.
pub const TTL: Duration = Duration::from_secs(3600);

/// Stale-while-revalidate window (24 h past TTL) — mirrors
/// `jwks_cache::STALE_WINDOW`.
pub const STALE_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// Maximum discovery document response body size: 256 KiB.
///
/// Prevents a malicious or misconfigured metadata endpoint from sending an
/// unbounded response that exhausts server memory. A legitimate discovery
/// document is typically well under 10 KiB. Enforced via a streaming,
/// running-byte-count cap (see [`fetch_discovery_document`]) rather than
/// buffer-then-check, so a lying/chunked response can never force full
/// buffering before the cap is noticed.
const MAX_DISCOVERY_SIZE: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DiscoveryCacheEntry {
    pub doc: OidcDiscoveryDocument,
    /// When the document was last successfully fetched.
    pub fetched_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Cache type alias
// ---------------------------------------------------------------------------

pub type DiscoveryCacheMap = HashMap<String, DiscoveryCacheEntry>;

// ---------------------------------------------------------------------------
// DiscoveryCache
// ---------------------------------------------------------------------------

/// Process-wide OIDC discovery-document cache keyed by `metadata_url`.
///
/// Uses a [`tokio::sync::RwLock`] so it can be shared across async handlers
/// without blocking the executor — identical shape to
/// [`crate::jwks_cache::JwksCache`].
///
/// The second field is the SEC-054 SSRF policy: when `false` (the default
/// and the only value used in production), metadata URLs that resolve to a
/// private/loopback IP are rejected. It is `true` only for integration tests
/// that serve discovery documents from a loopback mock server.
#[derive(Clone)]
pub struct DiscoveryCache(pub(crate) Arc<RwLock<DiscoveryCacheMap>>, pub(crate) bool);

impl DiscoveryCache {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())), false)
    }

    /// Test-only seam: construct a cache that permits metadata URLs
    /// resolving to private/loopback IPs, bypassing the SEC-054 SSRF guard.
    ///
    /// This exists solely so cross-crate integration tests can point the
    /// discovery fetcher at a loopback mock server (e.g. wiremock on
    /// `127.0.0.1`). It MUST NOT be used in production code — production
    /// always constructs via [`DiscoveryCache::new`], which keeps the SSRF
    /// guard active.
    #[doc(hidden)]
    pub fn new_allow_private_networks() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())), true)
    }

    /// Test-only seam: insert a cache entry directly so integration tests can
    /// seed stale entries (e.g. to exercise stale-while-revalidate). Keeps
    /// the inner map encapsulated (`pub(crate)`) while allowing cross-crate
    /// tests.
    #[doc(hidden)]
    pub async fn insert_for_test(&self, key: String, entry: DiscoveryCacheEntry) {
        self.0.write().await.insert(key, entry);
    }

    /// Return the discovery document for the given metadata URL, fetching
    /// if needed.
    ///
    /// 1. Cache hit within 1-h TTL → return cached document (no HTTP).
    /// 2. Cache miss or TTL expired → attempt fetch.
    ///    - On success: update entry, return document.
    ///    - On failure AND entry is within 24-h stale window → WARN + return stale document.
    ///    - On failure AND no usable cached entry → propagate error.
    pub async fn get_or_fetch(
        &self,
        http: &reqwest::Client,
        metadata_url: &str,
    ) -> Result<OidcDiscoveryDocument, FederationError> {
        let now = Utc::now();

        // --- Fast path: cache hit within TTL ---
        {
            let guard = self.0.read().await;
            if let Some(entry) = guard.get(metadata_url) {
                // Compare expiry directly to handle sub-millisecond clock jitter
                // (to_std() returns Err for negative durations — fetched_at in the
                // future by a tiny amount — which would falsely miss the cache).
                let ttl_chrono = chrono::Duration::from_std(TTL).unwrap_or_default();
                if entry.fetched_at + ttl_chrono > now {
                    return Ok(entry.doc.clone());
                }
            }
        }

        // --- Slow path: attempt a fresh fetch ---
        match fetch_discovery_document(http, metadata_url, self.1).await {
            Ok(doc) => {
                let mut guard = self.0.write().await;
                let entry =
                    guard
                        .entry(metadata_url.to_string())
                        .or_insert_with(|| DiscoveryCacheEntry {
                            doc: doc.clone(),
                            fetched_at: now,
                        });
                entry.doc = doc.clone();
                entry.fetched_at = now;
                Ok(doc)
            }
            Err(fetch_err) => {
                // Check for stale-while-revalidate.
                let guard = self.0.read().await;
                if let Some(entry) = guard.get(metadata_url) {
                    let stale_window_chrono =
                        chrono::Duration::from_std(STALE_WINDOW).unwrap_or_default();
                    if entry.fetched_at + stale_window_chrono > now {
                        tracing::warn!(
                            metadata_url,
                            "serving stale OIDC discovery document while IdP unreachable"
                        );
                        return Ok(entry.doc.clone());
                    }
                }
                Err(fetch_err)
            }
        }
    }
}

impl Default for DiscoveryCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

/// Fetch and parse the OIDC discovery document from the provider.
///
/// Moved out of `oidc.rs::discover` (plan A4 / CQ-B23) so the fetch itself
/// lives alongside the cache that fronts it, mirroring
/// `jwks_cache::fetch_jwks`.
async fn fetch_discovery_document(
    // Retained for API stability of `get_or_fetch` — no longer used directly:
    // `ssrf::guarded_fetch` builds its own fresh, IP-pinned client per
    // request rather than reusing an injected pooled client (see
    // `jwks_cache::fetch_jwks`'s identical comment).
    _http: &reqwest::Client,
    metadata_url: &str,
    allow_private_networks: bool,
) -> Result<OidcDiscoveryDocument, FederationError> {
    // SECHRD-02: route the discovery-document GET through the shared,
    // IP-pinning SSRF guard (D-01a/b/c). Production always fails closed
    // against private/loopback/link-local addresses and internal redirect
    // targets — `allow_private_networks=false`.
    let response =
        crate::ssrf::guarded_fetch(metadata_url, allow_private_networks, |c, u| c.get(u))
            .await
            .map_err(|e| FederationError::DiscoveryFailed(e.to_string()))?;

    if !response.status().is_success() {
        return Err(FederationError::DiscoveryFailed(format!(
            "HTTP {} from discovery endpoint",
            response.status()
        )));
    }

    // CQ-B23: stream the body with a running-byte-count cap instead of
    // buffering the whole response and checking `.len()` afterward — a
    // malicious endpoint that lies about (or omits) `Content-Length` could
    // otherwise force full buffering before the existing check ever ran.
    let bytes = crate::ssrf::read_capped_body(response, MAX_DISCOVERY_SIZE)
        .await
        .map_err(|e| match e {
            crate::ssrf::SsrfError::ResponseTooLarge(cap) => FederationError::DiscoveryFailed(
                format!("Discovery document too large (max {cap} bytes)"),
            ),
            other => {
                FederationError::DiscoveryFailed(format!("Failed to read response body: {other}"))
            }
        })?;

    let doc: OidcDiscoveryDocument = serde_json::from_slice(&bytes).map_err(|e| {
        FederationError::DiscoveryFailed(format!("Failed to parse discovery document: {e}"))
    })?;

    // Validate that critical endpoints in the discovery document use HTTPS.
    // A compromised/malicious discovery endpoint could return http:// URLs,
    // leaking client_secret during token exchange. Skipped under the same
    // test-only `allow_private_networks` seam as above — a loopback wiremock
    // IdP serves plain HTTP.
    for (name, url) in [
        ("authorization_endpoint", &doc.authorization_endpoint),
        ("token_endpoint", &doc.token_endpoint),
        ("jwks_uri", &doc.jwks_uri),
    ] {
        let parsed = url::Url::parse(url).map_err(|e| {
            FederationError::DiscoveryFailed(format!("{name} is not a valid URL: {e}"))
        })?;
        if !allow_private_networks && parsed.scheme() != "https" {
            return Err(FederationError::DiscoveryFailed(format!(
                "{name} must use HTTPS, got: {url}"
            )));
        }
    }

    Ok(doc)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as CDuration;

    fn test_doc() -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/auth".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: None,
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        }
    }

    /// Insert a cache entry with a custom `fetched_at`.
    async fn insert_entry(
        cache: &DiscoveryCache,
        key: &str,
        fetched_at: DateTime<Utc>,
        doc: OidcDiscoveryDocument,
    ) {
        let mut guard = cache.0.write().await;
        guard.insert(key.to_string(), DiscoveryCacheEntry { doc, fetched_at });
    }

    /// CQ-B23: a second `get_or_fetch` for the same metadata_url within the
    /// 1-h TTL must be served from cache — no HTTP call is made. Mirrors
    /// `jwks_cache::tests::cache_hit_within_ttl` (the cache key here IS the
    /// fetch URL, so pointing it at an unreachable address and still getting
    /// `Ok` proves the fast path never attempted a real fetch).
    #[tokio::test]
    async fn cache_hit_within_ttl() {
        let cache = DiscoveryCache::new();
        // Use a URL that would fail if actually called (port 0 → connection refused).
        let key = "http://127.0.0.1:0/discovery-unreachable";

        // Insert an entry fresh right now.
        insert_entry(&cache, key, Utc::now(), test_doc()).await;

        let http = reqwest::Client::new();
        let result = cache.get_or_fetch(&http, key).await;

        // Must return the cached entry without making an HTTP call.
        assert!(
            result.is_ok(),
            "expected cached result, got error: {result:?}"
        );
        assert_eq!(result.unwrap().issuer, test_doc().issuer);
    }

    #[tokio::test]
    async fn stale_while_revalidate_on_fetch_err() {
        let cache = DiscoveryCache::new();
        let key = "http://127.0.0.1:0/discovery-unreachable";

        // Insert an entry that is past 1-h TTL but within 24-h stale window.
        let fetched_at = Utc::now() - CDuration::minutes(90);
        insert_entry(&cache, key, fetched_at, test_doc()).await;

        let http = reqwest::Client::new();
        // The fetch will fail because the URL is unreachable.
        let result = cache.get_or_fetch(&http, key).await;

        // Should return cached (stale) document rather than propagating the error.
        assert!(
            result.is_ok(),
            "expected stale document to be served, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn cache_miss_beyond_stale_window_propagates_error() {
        let cache = DiscoveryCache::new();
        let key = "http://127.0.0.1:0/discovery-unreachable";

        // Insert an entry that is past both the TTL AND the 24-h stale window.
        let fetched_at = Utc::now() - CDuration::hours(25);
        insert_entry(&cache, key, fetched_at, test_doc()).await;

        let http = reqwest::Client::new();
        let result = cache.get_or_fetch(&http, key).await;

        assert!(
            result.is_err(),
            "expected fetch error to propagate once stale window has also elapsed: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // R5 additions — real-fetch happy path, TTL-expiry refetch, and the
    // `fetch_discovery_document` error arms (via wiremock + the
    // `allow_private_networks` seam so a loopback mock IdP is reachable).
    // -----------------------------------------------------------------------

    fn doc_json(base: &str) -> serde_json::Value {
        serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
        })
    }

    #[tokio::test]
    async fn cold_fetch_populates_cache_then_serves_from_cache() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc_json(&base)))
            // Exactly one HTTP hit across both get_or_fetch calls.
            .expect(1)
            .mount(&server)
            .await;

        let cache = DiscoveryCache::new_allow_private_networks();
        let http = reqwest::Client::new();
        let url = format!("{base}/.well-known/openid-configuration");

        let first = cache.get_or_fetch(&http, &url).await.expect("cold fetch");
        assert_eq!(first.issuer, base);
        assert_eq!(first.jwks_uri, format!("{base}/jwks"));

        // Second call within TTL: served from cache, no second HTTP request.
        let second = cache.get_or_fetch(&http, &url).await.expect("cache hit");
        assert_eq!(second.issuer, base);

        server.verify().await;
    }

    #[tokio::test]
    async fn ttl_expired_entry_triggers_refetch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(doc_json(&base)))
            // Stale entry is past TTL → exactly one live refetch happens.
            .expect(1)
            .mount(&server)
            .await;

        let cache = DiscoveryCache::new_allow_private_networks();
        let url = format!("{base}/.well-known/openid-configuration");

        // Seed a stale entry (past 1-h TTL) with a distinguishable issuer.
        let mut stale = test_doc();
        stale.issuer = "https://stale-issuer.example.com".to_string();
        insert_entry(&cache, &url, Utc::now() - CDuration::minutes(90), stale).await;

        let http = reqwest::Client::new();
        let refreshed = cache.get_or_fetch(&http, &url).await.expect("refetch");
        // The stale issuer must have been replaced by the freshly fetched one.
        assert_eq!(refreshed.issuer, base);

        server.verify().await;
    }

    #[tokio::test]
    async fn fetch_non_success_status_propagates_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let cache = DiscoveryCache::new_allow_private_networks();
        let http = reqwest::Client::new();
        let url = format!("{base}/.well-known/openid-configuration");
        let err = cache
            .get_or_fetch(&http, &url)
            .await
            .expect_err("404 with no cached entry must error");
        assert!(
            matches!(err, FederationError::DiscoveryFailed(ref m) if m.contains("404")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_invalid_json_propagates_parse_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<<not json>>"))
            .mount(&server)
            .await;

        let cache = DiscoveryCache::new_allow_private_networks();
        let http = reqwest::Client::new();
        let url = format!("{base}/.well-known/openid-configuration");
        let err = cache
            .get_or_fetch(&http, &url)
            .await
            .expect_err("unparseable discovery document must error");
        assert!(
            matches!(err, FederationError::DiscoveryFailed(ref m) if m.contains("parse")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_oversized_body_is_rejected() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = server.uri();
        // Body larger than MAX_DISCOVERY_SIZE (256 KiB) → capped read rejects it
        // before any parse is attempted.
        let big = "a".repeat(300 * 1024);
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string(big))
            .mount(&server)
            .await;

        let cache = DiscoveryCache::new_allow_private_networks();
        let http = reqwest::Client::new();
        let url = format!("{base}/.well-known/openid-configuration");
        let err = cache
            .get_or_fetch(&http, &url)
            .await
            .expect_err("oversized body must be rejected");
        assert!(
            matches!(err, FederationError::DiscoveryFailed(ref m) if m.contains("too large")),
            "got: {err:?}"
        );
    }
}

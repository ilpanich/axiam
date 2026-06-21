//! JWKS cache with D-01/D-02/D-03 semantics.
//!
//! - D-01: 1-hour TTL — return cached keys if `fetched_at + 1h > now`.
//! - D-02: Single forced refetch on unknown kid, rate-limited to 1 per 60 s.
//! - D-03: 24-hour stale-while-revalidate — if the IdP is unreachable but
//!   the cache entry is no older than 24 h past TTL, serve stale keys with
//!   a WARN log rather than surfacing an error.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use jsonwebtoken::jwk::JwkSet;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::FederationError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// D-01: JWKS cache TTL (1 hour).
pub const TTL: Duration = Duration::from_secs(3600);

/// D-03: Stale-while-revalidate window (24 h past TTL).
pub const STALE_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// D-02: Minimum interval between forced refetches for an unknown kid.
pub const FORCED_REFETCH_COOLDOWN: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct JwksCacheEntry {
    pub keys: JwkSet,
    /// When the keys were last successfully fetched.
    pub fetched_at: DateTime<Utc>,
    /// Last time a forced refetch was attempted (unknown-kid path).
    pub last_refetch_attempt: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Cache type alias
// ---------------------------------------------------------------------------

pub type JwksCacheMap = HashMap<(Uuid, Uuid), JwksCacheEntry>;

// ---------------------------------------------------------------------------
// JwksCache
// ---------------------------------------------------------------------------

/// Process-wide JWKS cache keyed by `(tenant_id, federation_config_id)`.
///
/// Uses a [`tokio::sync::RwLock`] so it can be shared across async handlers
/// without blocking the executor.
///
/// The second field is the SEC-054 SSRF policy: when `false` (the default and
/// the only value used in production), JWKS URLs that resolve to a
/// private/loopback IP are rejected. It is `true` only for integration tests
/// that serve JWKS from a loopback mock server.
#[derive(Clone)]
pub struct JwksCache(pub(crate) Arc<RwLock<JwksCacheMap>>, pub(crate) bool);

impl JwksCache {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())), false)
    }

    /// Test-only seam: construct a cache that permits JWKS URLs resolving to
    /// private/loopback IPs, bypassing the SEC-054 SSRF guard.
    ///
    /// This exists solely so cross-crate integration tests can point the JWKS
    /// fetcher at a loopback mock server (e.g. wiremock on `127.0.0.1`). It
    /// MUST NOT be used in production code — production always constructs via
    /// [`JwksCache::new`], which keeps the SSRF guard active.
    #[doc(hidden)]
    pub fn new_allow_private_networks() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())), true)
    }

    /// Test-only seam: insert a cache entry directly so integration tests can
    /// seed stale entries (e.g. to exercise stale-while-revalidate). Keeps the
    /// inner map encapsulated (`pub(crate)`) while allowing cross-crate tests.
    #[doc(hidden)]
    pub async fn insert_for_test(&self, key: (Uuid, Uuid), entry: JwksCacheEntry) {
        self.0.write().await.insert(key, entry);
    }

    /// Return JWKS for the given key, fetching if needed.
    ///
    /// 1. Cache hit within 1-h TTL → return cached keys (no HTTP).
    /// 2. Cache miss or TTL expired → attempt fetch.
    ///    - On success: update entry, return keys.
    ///    - On failure AND entry is within 24-h stale window → WARN + return stale keys.
    ///    - On failure AND no usable cached entry → propagate error.
    pub async fn get_or_fetch(
        &self,
        http: &reqwest::Client,
        key: (Uuid, Uuid),
        jwks_uri: &str,
    ) -> Result<JwkSet, FederationError> {
        let now = Utc::now();

        // --- Fast path: cache hit within TTL ---
        {
            let guard = self.0.read().await;
            if let Some(entry) = guard.get(&key) {
                // Compare expiry directly to handle sub-millisecond clock jitter
                // (to_std() returns Err for negative durations — fetched_at in the
                // future by a tiny amount — which would falsely miss the cache).
                let ttl_chrono = chrono::Duration::from_std(TTL).unwrap_or_default();
                if entry.fetched_at + ttl_chrono > now {
                    return Ok(entry.keys.clone());
                }
            }
        }

        // --- Slow path: attempt a fresh fetch ---
        match fetch_jwks(http, jwks_uri, self.1).await {
            Ok(jwks) => {
                let mut guard = self.0.write().await;
                let entry = guard.entry(key).or_insert_with(|| JwksCacheEntry {
                    keys: jwks.clone(),
                    fetched_at: now,
                    last_refetch_attempt: None,
                });
                entry.keys = jwks.clone();
                entry.fetched_at = now;
                Ok(jwks)
            }
            Err(fetch_err) => {
                // Check for stale-while-revalidate.
                let guard = self.0.read().await;
                if let Some(entry) = guard.get(&key) {
                    let stale_window_chrono =
                        chrono::Duration::from_std(STALE_WINDOW).unwrap_or_default();
                    if entry.fetched_at + stale_window_chrono > now {
                        tracing::warn!(jwks_uri, "serving stale JWKS while IdP unreachable");
                        return Ok(entry.keys.clone());
                    }
                }
                Err(fetch_err)
            }
        }
    }

    /// Force a refetch when the caller encounters an unknown kid.
    ///
    /// Rate-limited: if a forced refetch was attempted within
    /// [`FORCED_REFETCH_COOLDOWN`], return `Err(JwksKidUnknown)` immediately
    /// without issuing any HTTP request.
    pub async fn force_refetch_if_allowed(
        &self,
        http: &reqwest::Client,
        key: (Uuid, Uuid),
        jwks_uri: &str,
    ) -> Result<JwkSet, FederationError> {
        let now = Utc::now();

        // Check rate-limit window (read lock).
        {
            let guard = self.0.read().await;
            if let Some(entry) = guard.get(&key)
                && let Some(last_attempt) = entry.last_refetch_attempt
            {
                let cooldown_chrono =
                    chrono::Duration::from_std(FORCED_REFETCH_COOLDOWN).unwrap_or_default();
                if last_attempt + cooldown_chrono > now {
                    return Err(FederationError::JwksKidUnknown);
                }
            }
        }

        // Update last_refetch_attempt before the fetch so that concurrent
        // callers also see the cooldown.
        {
            let mut guard = self.0.write().await;
            let entry = guard.entry(key).or_insert_with(|| JwksCacheEntry {
                keys: JwkSet { keys: vec![] },
                fetched_at: DateTime::UNIX_EPOCH,
                last_refetch_attempt: None,
            });
            entry.last_refetch_attempt = Some(now);
        }

        // Perform the fetch.
        match fetch_jwks(http, jwks_uri, self.1).await {
            Ok(jwks) => {
                let mut guard = self.0.write().await;
                if let Some(entry) = guard.get_mut(&key) {
                    entry.keys = jwks.clone();
                    entry.fetched_at = now;
                }
                Ok(jwks)
            }
            Err(_) => Err(FederationError::JwksKidUnknown),
        }
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Private helper
// ---------------------------------------------------------------------------

/// Maximum JWKS response body size: 512 KiB.
///
/// SEC-054: Prevents a malicious or misconfigured IdP from sending an
/// unbounded response that exhausts server memory. A legitimate JWKS
/// document with a dozen keys is typically < 10 KiB.
const MAX_JWKS_BODY_BYTES: usize = 512 * 1024;

/// Returns `true` for IP addresses that must not be contacted as JWKS endpoints.
///
/// SEC-054: Prevents SSRF via malicious JWKS URL pointing to internal services.
fn is_private_jwks_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0 == 0xfe80) // link-local fe80::/10
                || (v6.segments()[0] & 0xfe00 == 0xfc00) // unique-local fc00::/7
        }
    }
}

/// Validate that the JWKS URL does not resolve to a private/loopback IP (SEC-054).
///
/// When `allow_private_networks` is `true` (integration tests only) the check
/// is skipped so a loopback mock server can be used. Production always passes
/// `false`.
async fn validate_jwks_url(
    jwks_uri: &str,
    allow_private_networks: bool,
) -> Result<(), FederationError> {
    if allow_private_networks {
        return Ok(());
    }
    let parsed = url::Url::parse(jwks_uri)
        .map_err(|_| FederationError::JwksFetchFailed("invalid JWKS URL".into()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FederationError::JwksFetchFailed("JWKS URL has no host".into()))?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    let addrs = tokio::net::lookup_host((host, port)).await.map_err(|e| {
        FederationError::JwksFetchFailed(format!("JWKS host resolution failed: {e}"))
    })?;

    for addr in addrs {
        if is_private_jwks_ip(addr.ip()) {
            return Err(FederationError::JwksFetchFailed(format!(
                "SSRF blocked: JWKS URL '{jwks_uri}' resolves to a private/loopback IP"
            )));
        }
    }
    Ok(())
}

async fn fetch_jwks(
    http: &reqwest::Client,
    jwks_uri: &str,
    allow_private_networks: bool,
) -> Result<JwkSet, FederationError> {
    // SEC-054: Block JWKS URLs that resolve to private/loopback IPs.
    validate_jwks_url(jwks_uri, allow_private_networks).await?;

    let response = http
        .get(jwks_uri)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| FederationError::JwksFetchFailed(format!("HTTP request failed: {e}")))?;

    let response = response
        .error_for_status()
        .map_err(|e| FederationError::JwksFetchFailed(format!("IdP returned error: {e}")))?;

    // SEC-054: Cap the response body size before parsing JSON.
    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| FederationError::JwksFetchFailed(format!("Failed to read JWKS body: {e}")))?;

    if body_bytes.len() > MAX_JWKS_BODY_BYTES {
        return Err(FederationError::JwksFetchFailed(format!(
            "JWKS response body too large: {} bytes (max {})",
            body_bytes.len(),
            MAX_JWKS_BODY_BYTES
        )));
    }

    serde_json::from_slice::<JwkSet>(&body_bytes)
        .map_err(|e| FederationError::JwksFetchFailed(format!("Failed to parse JWKS: {e}")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as CDuration;

    fn test_key() -> (Uuid, Uuid) {
        (Uuid::new_v4(), Uuid::new_v4())
    }

    fn empty_jwks() -> JwkSet {
        JwkSet { keys: vec![] }
    }

    /// Insert a cache entry with a custom `fetched_at`.
    async fn insert_entry(
        cache: &JwksCache,
        key: (Uuid, Uuid),
        fetched_at: DateTime<Utc>,
        jwks: JwkSet,
    ) {
        let mut guard = cache.0.write().await;
        guard.insert(
            key,
            JwksCacheEntry {
                keys: jwks,
                fetched_at,
                last_refetch_attempt: None,
            },
        );
    }

    #[tokio::test]
    async fn cache_hit_within_ttl() {
        let cache = JwksCache::new();
        let k = test_key();

        // Insert an entry fresh right now.
        insert_entry(&cache, k, Utc::now(), empty_jwks()).await;

        // Use a URL that would fail if actually called (port 0 → connection refused).
        let http = reqwest::Client::new();
        let result = cache
            .get_or_fetch(&http, k, "http://127.0.0.1:0/jwks-unreachable")
            .await;

        // Must return the cached entry without making an HTTP call.
        assert!(
            result.is_ok(),
            "expected cached result, got error: {result:?}"
        );
    }

    #[tokio::test]
    async fn stale_while_revalidate_on_fetch_err() {
        let cache = JwksCache::new();
        let k = test_key();

        // Insert an entry that is past 1-h TTL but within 24-h stale window.
        let fetched_at = Utc::now() - CDuration::minutes(90);
        insert_entry(&cache, k, fetched_at, empty_jwks()).await;

        let http = reqwest::Client::new();
        // The fetch will fail because the URL is unreachable.
        let result = cache
            .get_or_fetch(&http, k, "http://127.0.0.1:0/jwks-unreachable")
            .await;

        // Should return cached (stale) keys rather than propagating the error.
        assert!(
            result.is_ok(),
            "expected stale keys to be served, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn forced_refetch_rate_limited() {
        let cache = JwksCache::new();
        let k = test_key();

        let http = reqwest::Client::new();

        // First call — will attempt a fetch (fails) but records last_refetch_attempt.
        let _ = cache
            .force_refetch_if_allowed(&http, k, "http://127.0.0.1:0/jwks-unreachable")
            .await;

        // Second call within 60 s — MUST return JwksKidUnknown without HTTP.
        let result = cache
            .force_refetch_if_allowed(&http, k, "http://127.0.0.1:0/jwks-unreachable")
            .await;

        assert!(
            matches!(result, Err(FederationError::JwksKidUnknown)),
            "expected JwksKidUnknown (rate-limited), got: {result:?}"
        );
    }
}

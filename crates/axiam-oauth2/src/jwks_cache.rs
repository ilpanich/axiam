//! In-process JWKS cache with RFC 7232 conditional-GET (ETag) support (B3).
//!
//! ## Baseline finding this module addresses
//!
//! Before this module existed, `GET /oauth2/jwks` called
//! [`crate::oidc::build_jwks`] fresh on every single request: PEM strip →
//! base64 decode → SHA-256(kid) → JSON-serialize, with zero HTTP caching
//! headers. The benchmark's low 0.062 cpu·ms/req for that endpoint is
//! simply because that computation is cheap (a 44-byte Ed25519 SPKI, no
//! I/O) — it was never evidence of caching. This module adds a real
//! in-process cache plus `ETag`/`If-None-Match`/304 support so repeat
//! requests (the overwhelming majority in practice — relying parties are
//! expected to poll `jwks_uri` on an interval, not per-request) skip the
//! recompute and the response body entirely.
//!
//! ## Not the same thing as `axiam_federation::jwks_cache::JwksCache`
//!
//! That cache stores REMOTE identity providers' JWKS documents fetched
//! during OIDC federation login (keyed by `(tenant_id, federation_config_id)`,
//! TTL-based, with stale-while-revalidate). This module caches AXIAM's OWN
//! signing-key JWKS — the document AXIAM *serves* at `GET /oauth2/jwks` —
//! and invalidates itself based on the input key material rather than a
//! wall-clock TTL. The two are unrelated and live in different crates.
//!
//! ## Known limitations (documented per B3, not fixed here)
//!
//! - **No key-rotation mechanism exists today.** `AuthConfig` loads
//!   `jwt_public_key_pem` once at process startup from config/env and it
//!   never changes for the life of the process — there is no reachable
//!   code path that swaps it at runtime. In practice this cache is
//!   therefore built exactly once per process. It is still keyed by a hash
//!   of the input PEM (rather than being unconditionally "build once and
//!   never touch again") so that IF a future rotation mechanism starts
//!   swapping the PEM string held by the caller between calls, this cache
//!   picks the change up automatically on the very next [`JwksCache::get`]
//!   call — no code in that future rotation path needs to know this cache
//!   exists or call anything special. [`JwksCache::invalidate`] is also
//!   provided for a caller that wants to force an eager rebuild instead of
//!   waiting for the input hash to differ.
//! - **The endpoint is not actually per-tenant.** `GET /oauth2/jwks` serves
//!   ONE global key set sourced from the server-wide `AuthConfig`, despite
//!   living under the tenant-aware API surface. Every tenant is served the
//!   same signing key today; this cache mirrors that reality (it is a
//!   single-slot cache, not a per-tenant map).

use std::sync::RwLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::oidc::build_jwks;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn default_max_age_secs() -> u64 {
    300
}

/// Configuration for the `GET /oauth2/jwks` HTTP caching headers (B3).
///
/// Mirrors the `#[serde(default)]` style used by `axiam_auth::config::AuthConfig`
/// so it composes into the same `config`-crate-driven env var plumbing.
///
/// The field is named `max_age_secs` in Rust for readability at call sites
/// (`config.max_age_secs`), but is deserialized under the key
/// `jwks_cache_max_age_secs` so that, nested one level under the server's
/// `oauth2` config section, it is reachable via the env var
/// `AXIAM__OAUTH2__JWKS_CACHE_MAX_AGE_SECS`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct JwksCacheConfig {
    /// `max-age` value (seconds) advertised in the `Cache-Control` header on
    /// `GET /oauth2/jwks` responses. Default: 300 (5 minutes). Override via
    /// `AXIAM__OAUTH2__JWKS_CACHE_MAX_AGE_SECS`.
    #[serde(rename = "jwks_cache_max_age_secs")]
    pub max_age_secs: u64,
}

impl Default for JwksCacheConfig {
    fn default() -> Self {
        Self {
            max_age_secs: default_max_age_secs(),
        }
    }
}

impl JwksCacheConfig {
    /// Render the `Cache-Control` header value for this config, e.g.
    /// `"public, max-age=300"`.
    pub fn cache_control_header(&self) -> String {
        format!("public, max-age={}", self.max_age_secs)
    }
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/// A cached, pre-serialized JWKS response plus the hash of the PEM it was
/// built from (the self-invalidation key).
struct CacheEntry {
    /// SHA-256 of the source PEM this entry was built from. When a `get()`
    /// call is made with a PEM that hashes differently, the entry is stale
    /// and gets rebuilt.
    pem_hash: [u8; 32],
    /// Pre-serialized JSON body of the `JwksDocument`, cached verbatim so
    /// repeat requests skip `serde_json` re-serialization too.
    body: String,
    /// Strong, quoted ETag: `"` + hex(SHA-256(body))[..16 bytes as hex] + `"`.
    etag: String,
}

/// Outcome of a [`JwksCache::get`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwksCacheResponse {
    /// No conditional match (or no `If-None-Match` sent): the caller should
    /// respond `200 OK` with this body and this `ETag`.
    Fresh { body: String, etag: String },
    /// The client's `If-None-Match` matched the current ETag: the caller
    /// should respond `304 Not Modified` with this `ETag` and an empty body.
    NotModified { etag: String },
}

/// Thread-safe, single-slot, in-process cache for AXIAM's own JWKS
/// response (see module docs for the distinction from
/// `axiam_federation::jwks_cache::JwksCache`).
///
/// Self-invalidates when the input PEM changes (compared by SHA-256 hash,
/// not by string equality, to keep the stored key small and avoid retaining
/// PEM copies longer than necessary). [`JwksCache::invalidate`] forces an
/// eager rebuild on the next `get()` regardless of whether the PEM changed.
pub struct JwksCache {
    inner: RwLock<Option<CacheEntry>>,
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksCache {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(None),
        }
    }

    /// Drop the cached entry unconditionally. The next [`JwksCache::get`]
    /// call will rebuild from scratch (still hitting the fast path again on
    /// every subsequent call, as long as the PEM does not change).
    pub fn invalidate(&self) {
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *guard = None;
    }

    /// Get the (possibly cached) JWKS response for `pem`, honoring an
    /// optional `If-None-Match` request header value.
    ///
    /// - Cache hit (PEM hash unchanged): served from the cached, already
    ///   serialized body — no re-parsing, no re-serialization.
    /// - Cache miss (first call, PEM changed, or after [`JwksCache::invalidate`]):
    ///   rebuilds via [`build_jwks`], serializes once, computes the ETag,
    ///   and stores the new entry. On a build error (malformed PEM), the
    ///   error is returned and the existing cache entry (if any) is left
    ///   untouched — a bad key never evicts a previously good one.
    ///
    /// `if_none_match` is compared per RFC 7232 §3.2: a `*` always matches;
    /// a comma-separated list of (optionally `W/`-prefixed) entity-tags
    /// matches if any entry equals the current strong ETag once its `W/`
    /// prefix (if any) is stripped.
    pub fn get(
        &self,
        pem: &str,
        if_none_match: Option<&str>,
    ) -> Result<JwksCacheResponse, String> {
        let pem_hash = sha256(pem.as_bytes());

        // Fast path: an existing entry built from the same PEM.
        {
            let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = guard.as_ref() {
                if entry.pem_hash == pem_hash {
                    return Ok(respond(entry, if_none_match));
                }
            }
        }

        // Slow path: (re)build. Do NOT touch the cache until this succeeds,
        // so a malformed key never evicts a previously-good cached entry.
        let doc = build_jwks(pem)?;
        let body = serde_json::to_string(&doc).map_err(|e| format!("JWKS serialize: {e}"))?;
        let etag = format!("\"{}\"", hex::encode(&sha256(body.as_bytes())[..16]));

        let entry = CacheEntry {
            pem_hash,
            body,
            etag,
        };
        let response = respond(&entry, if_none_match);

        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        *guard = Some(entry);

        Ok(response)
    }
}

fn respond(entry: &CacheEntry, if_none_match: Option<&str>) -> JwksCacheResponse {
    if let Some(header) = if_none_match {
        if if_none_match_matches(header, &entry.etag) {
            return JwksCacheResponse::NotModified {
                etag: entry.etag.clone(),
            };
        }
    }
    JwksCacheResponse::Fresh {
        body: entry.body.clone(),
        etag: entry.etag.clone(),
    }
}

/// RFC 7232 §3.2 `If-None-Match` comparison (weak comparison, as required
/// for use with `GET`): `*` matches unconditionally; otherwise the header
/// is a comma-separated list of entity-tags, each optionally prefixed with
/// `W/` for a weak validator. A match is found if any listed tag — with its
/// `W/` prefix stripped, if present — equals `current_etag` exactly.
fn if_none_match_matches(header: &str, current_etag: &str) -> bool {
    let header = header.trim();
    if header == "*" {
        return true;
    }
    header.split(',').any(|raw| {
        let candidate = raw.trim();
        let stripped = candidate.strip_prefix("W/").unwrap_or(candidate);
        stripped == current_etag
    })
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const PEM_A: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

    // A second, distinct Ed25519 SubjectPublicKeyInfo (different 32-byte raw
    // key), used to simulate key rotation.
    const PEM_B: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAGCxCNpcTHjOYiJ3r54SLgtpqvhkRvAcFNq0MrqpoMU=
-----END PUBLIC KEY-----";

    #[test]
    fn default_max_age_is_300() {
        let cfg = JwksCacheConfig::default();
        assert_eq!(cfg.max_age_secs, 300);
        assert_eq!(cfg.cache_control_header(), "public, max-age=300");
    }

    #[test]
    fn custom_max_age_renders_header() {
        let cfg = JwksCacheConfig {
            max_age_secs: 60,
        };
        assert_eq!(cfg.cache_control_header(), "public, max-age=60");
    }

    #[test]
    fn fresh_response_has_body_and_etag_with_no_if_none_match() {
        let cache = JwksCache::new();
        let resp = cache.get(PEM_A, None).unwrap();
        match resp {
            JwksCacheResponse::Fresh { body, etag } => {
                assert!(body.contains("\"kty\":\"OKP\""));
                assert!(etag.starts_with('"') && etag.ends_with('"'));
                // 16 bytes of SHA-256 hex-encoded = 32 hex chars, plus 2 quotes.
                assert_eq!(etag.len(), 34);
            }
            other => panic!("expected Fresh, got {other:?}"),
        }
    }

    #[test]
    fn fresh_response_on_non_matching_if_none_match() {
        let cache = JwksCache::new();
        let resp = cache.get(PEM_A, Some("\"not-the-etag\"")).unwrap();
        assert!(matches!(resp, JwksCacheResponse::Fresh { .. }));
    }

    #[test]
    fn not_modified_on_matching_etag() {
        let cache = JwksCache::new();
        let etag = match cache.get(PEM_A, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };
        let resp = cache.get(PEM_A, Some(&etag)).unwrap();
        assert_eq!(resp, JwksCacheResponse::NotModified { etag });
    }

    #[test]
    fn not_modified_on_weak_prefixed_matching_etag() {
        let cache = JwksCache::new();
        let etag = match cache.get(PEM_A, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };
        let weak = format!("W/{etag}");
        let resp = cache.get(PEM_A, Some(&weak)).unwrap();
        assert_eq!(resp, JwksCacheResponse::NotModified { etag });
    }

    #[test]
    fn not_modified_on_wildcard() {
        let cache = JwksCache::new();
        cache.get(PEM_A, None).unwrap();
        let resp = cache.get(PEM_A, Some("*")).unwrap();
        assert!(matches!(resp, JwksCacheResponse::NotModified { .. }));
    }

    #[test]
    fn not_modified_on_comma_separated_list_containing_the_etag() {
        let cache = JwksCache::new();
        let etag = match cache.get(PEM_A, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };
        let header = format!("\"deadbeef\", {etag}, \"other\"");
        let resp = cache.get(PEM_A, Some(&header)).unwrap();
        assert_eq!(resp, JwksCacheResponse::NotModified { etag });
    }

    #[test]
    fn etag_changes_on_key_rotation_and_stale_etag_no_longer_304s() {
        let cache = JwksCache::new();
        let etag_a = match cache.get(PEM_A, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };

        // Simulate rotation: caller now passes a different PEM.
        let etag_b = match cache.get(PEM_B, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };

        assert_ne!(etag_a, etag_b, "ETag must change when the key material changes");

        // The pre-rotation ETag must no longer produce a 304 against the
        // now-current (post-rotation) cache state.
        let resp = cache.get(PEM_B, Some(&etag_a)).unwrap();
        assert!(matches!(resp, JwksCacheResponse::Fresh { .. }));

        // But the fresh, post-rotation ETag still 304s.
        let resp = cache.get(PEM_B, Some(&etag_b)).unwrap();
        assert_eq!(resp, JwksCacheResponse::NotModified { etag: etag_b });
    }

    #[test]
    fn invalidate_forces_rebuild_and_still_serves_correctly() {
        let cache = JwksCache::new();
        let etag_before = match cache.get(PEM_A, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };

        cache.invalidate();

        // Same PEM, same deterministic kid/etag — invalidation just forces
        // a rebuild, it does not change the computed result.
        let etag_after = match cache.get(PEM_A, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };
        assert_eq!(etag_before, etag_after);

        // And conditional requests against the rebuilt entry still work.
        let resp = cache.get(PEM_A, Some(&etag_after)).unwrap();
        assert_eq!(
            resp,
            JwksCacheResponse::NotModified {
                etag: etag_after
            }
        );
    }

    #[test]
    fn malformed_key_errors_without_poisoning_the_cache() {
        let cache = JwksCache::new();

        // Seed the cache with a good entry.
        let good_etag = match cache.get(PEM_A, None).unwrap() {
            JwksCacheResponse::Fresh { etag, .. } => etag,
            _ => unreachable!(),
        };

        // A malformed PEM (not valid base64 / wrong length) must error...
        let err = cache.get("not a real pem", None);
        assert!(err.is_err());

        // ...and must NOT have evicted the previously-good entry: the same
        // good PEM still round-trips through the cache correctly afterward.
        let resp = cache.get(PEM_A, Some(&good_etag)).unwrap();
        assert_eq!(
            resp,
            JwksCacheResponse::NotModified {
                etag: good_etag
            }
        );
    }
}

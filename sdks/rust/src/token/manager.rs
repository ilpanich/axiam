//! `TokenManager` — holds the SDK's current access/refresh token state.
//!
//! CONTRACT.md §7: tokens are wrapped in [`crate::Sensitive`] immediately on
//! extraction from the cookie jar and never leave that wrapper except via
//! `pub(crate)`-only accessors.
//!
//! A fast, non-blocking cached-token read primitive
//! ([`TokenManager::cached_access_token`]) is provided for the sync gRPC
//! interceptor (RESEARCH.md Pitfall 3): `tonic::service::Interceptor::call`
//! is synchronous and must never `.lock().await` the async single-flight
//! refresh mutex owned by [`crate::token::refresh_guard`].

use std::sync::{Arc, RwLock};

use tokio::sync::Mutex;

use crate::Sensitive;

/// The cookie name AXIAM sets for the access token (CONTRACT.md §4, D-05).
pub const COOKIE_ACCESS: &str = "axiam_access";
/// The cookie name AXIAM sets for the refresh token.
pub const COOKIE_REFRESH: &str = "axiam_refresh";
/// The cookie name AXIAM sets for the (non-`HttpOnly`) CSRF token (§3).
pub const COOKIE_CSRF: &str = "axiam_csrf";

/// In-memory token state guarded by the async single-flight refresh mutex.
///
/// The [`Mutex`] itself is the single-flight gate for
/// [`crate::token::refresh_guard::refresh_if_needed`] — see that module for
/// the double-check pattern.
pub(crate) struct TokenState {
    pub(crate) access: Option<Sensitive<String>>,
    pub(crate) refresh: Option<Sensitive<String>>,
    /// `exp` claim (Unix timestamp) decoded from the verified access token —
    /// never a hardcoded duration (RESEARCH.md Open Question #2).
    pub(crate) exp: Option<i64>,
    /// Resolved tenant UUID, cached after the first successful login/verify
    /// so gRPC (16-03) can reuse it for `x-tenant-id` metadata without
    /// re-decoding the token (RESEARCH.md Open Question #1).
    pub(crate) tenant_id: Option<uuid::Uuid>,
}

/// Holds the SDK's current token state plus a fast, lock-free cached read
/// path for synchronous callers (e.g. the future gRPC interceptor in 16-03).
pub struct TokenManager {
    pub(crate) state: Arc<Mutex<TokenState>>,
    /// Non-blocking cached copy of the current access token, kept in sync
    /// with `state.access` under the same critical sections. Read via
    /// [`TokenManager::cached_access_token`] without ever touching the
    /// async mutex.
    fast_access_cache: Arc<RwLock<Option<Sensitive<String>>>>,
}

impl Default for TokenManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenManager {
    /// Construct an empty (unauthenticated) token manager.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(TokenState {
                access: None,
                refresh: None,
                exp: None,
                tenant_id: None,
            })),
            fast_access_cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Fast, non-blocking read of the currently cached access token.
    ///
    /// Safe to call from a synchronous context (e.g. a `tonic` interceptor);
    /// never blocks on the async refresh mutex (RESEARCH.md Pitfall 3).
    pub fn cached_access_token(&self) -> Option<Sensitive<String>> {
        self.fast_access_cache
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(|s| s.clone_inner()))
    }

    /// Store a freshly-obtained access/refresh token pair plus derived
    /// expiry and tenant id, updating both the authoritative async state and
    /// the fast-read cache atomically with respect to concurrent readers of
    /// the async lock (callers already hold `state.lock().await`, or use
    /// [`TokenManager::set_tokens`] for a fresh top-level assignment such as
    /// after login/verify_mfa).
    pub async fn set_tokens(
        &self,
        access: Sensitive<String>,
        refresh: Option<Sensitive<String>>,
        exp: Option<i64>,
        tenant_id: Option<uuid::Uuid>,
    ) {
        let mut guard = self.state.lock().await;
        if let Ok(mut cache) = self.fast_access_cache.write() {
            *cache = Some(access.clone_inner());
        }
        guard.access = Some(access);
        if refresh.is_some() {
            guard.refresh = refresh;
        }
        if exp.is_some() {
            guard.exp = exp;
        }
        if tenant_id.is_some() {
            guard.tenant_id = tenant_id;
        }
    }

    /// Clear all token state (used by `logout`).
    pub async fn clear(&self) {
        let mut guard = self.state.lock().await;
        guard.access = None;
        guard.refresh = None;
        guard.exp = None;
        if let Ok(mut cache) = self.fast_access_cache.write() {
            *cache = None;
        }
    }

    /// The resolved tenant UUID, if known (populated after the first
    /// successful login/verify_mfa decodes the access token's `tenant_id`
    /// claim).
    pub async fn tenant_id(&self) -> Option<uuid::Uuid> {
        self.state.lock().await.tenant_id
    }

    /// The `exp` claim (Unix timestamp) of the current access token, if any.
    pub async fn exp(&self) -> Option<i64> {
        self.state.lock().await.exp
    }

    /// Access the shared state handle for the single-flight refresh guard.
    pub(crate) fn state_handle(&self) -> Arc<Mutex<TokenState>> {
        Arc::clone(&self.state)
    }

    /// Access the fast-cache handle for the single-flight refresh guard.
    pub(crate) fn fast_cache_handle(&self) -> Arc<RwLock<Option<Sensitive<String>>>> {
        Arc::clone(&self.fast_access_cache)
    }
}

/// Extract the `axiam_access` cookie value directly out of a
/// [`reqwest::cookie::Jar`], wrapping it in [`Sensitive`] immediately
/// (RESEARCH.md Pattern 1 — `HttpOnly` has no effect on a non-browser
/// in-process cookie jar).
#[cfg(feature = "rest")]
pub fn extract_access_token_from_jar(
    jar: &reqwest::cookie::Jar,
    base_url: &url::Url,
) -> Option<Sensitive<String>> {
    extract_cookie_from_jar(jar, base_url, COOKIE_ACCESS)
}

/// Extract the `axiam_refresh` cookie value directly out of the jar.
#[cfg(feature = "rest")]
pub fn extract_refresh_token_from_jar(
    jar: &reqwest::cookie::Jar,
    base_url: &url::Url,
) -> Option<Sensitive<String>> {
    extract_cookie_from_jar(jar, base_url, COOKIE_REFRESH)
}

/// Extract the (non-`HttpOnly`) `axiam_csrf` cookie value out of the jar, for
/// §3 CSRF forwarding.
#[cfg(feature = "rest")]
pub fn extract_csrf_token_from_jar(
    jar: &reqwest::cookie::Jar,
    base_url: &url::Url,
) -> Option<String> {
    // The CSRF cookie is not secret (it is deliberately JS-readable, §3), so
    // it is read as a plain `String` rather than wrapped in `Sensitive<T>`.
    use reqwest::cookie::CookieStore;

    let header = jar.cookies(base_url)?;
    let raw = header.to_str().ok()?;
    raw.split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(&format!("{COOKIE_CSRF}=")))
        .map(|v| v.to_string())
}

#[cfg(feature = "rest")]
fn extract_cookie_from_jar(
    jar: &reqwest::cookie::Jar,
    base_url: &url::Url,
    name: &str,
) -> Option<Sensitive<String>> {
    use reqwest::cookie::CookieStore;

    let header = jar.cookies(base_url)?;
    let raw = header.to_str().ok()?;
    raw.split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
        .map(|v| Sensitive::new(v.to_string()))
}

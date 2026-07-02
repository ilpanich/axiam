//! Single-flight refresh guard (CONTRACT.md §9).
//!
//! Guarantees exactly one underlying `POST /api/v1/auth/refresh` HTTP call
//! even under concurrent callers, via the [`tokio::sync::Mutex`] itself as
//! the single-flight gate: the FIRST caller to acquire the lock performs the
//! refresh; every other caller blocks on the same lock and, upon acquiring
//! it, re-checks (double-check) whether a *newer* token already exists
//! before deciding whether to refresh again.
//!
//! A 401 on the refresh call itself is `AxiamError::Auth` with **no** retry
//! loop (§9.3) — the caller must re-authenticate from scratch.

use crate::token::manager::TokenManager;
use crate::AxiamError;
use crate::Sensitive;

/// The shape of a successful `POST /api/v1/auth/refresh` outcome, decoupled
/// from any particular transport response type so this module has no
/// `reqwest` dependency of its own beyond what the caller-supplied closure
/// requires.
pub struct RefreshedTokens {
    pub access: Sensitive<String>,
    pub refresh: Option<Sensitive<String>>,
    pub exp: Option<i64>,
    pub tenant_id: Option<uuid::Uuid>,
}

impl TokenManager {
    /// Drive the single-flight refresh: `do_refresh` performs the actual
    /// network call and is invoked **at most once** across any number of
    /// concurrent callers observing the same expired `observed_access_token`.
    ///
    /// `do_refresh` receives the current refresh token (already unwrapped
    /// from `Sensitive`, since it must be sent as the request body/cookie)
    /// and must return the new token triple on success.
    pub async fn refresh_if_needed<F, Fut>(
        &self,
        observed_access_token: &str,
        do_refresh: F,
    ) -> Result<Sensitive<String>, AxiamError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<RefreshedTokens, AxiamError>>,
    {
        let state = self.state_handle();
        let fast_cache = self.fast_cache_handle();
        let mut guard = state.lock().await;

        // Double-check: if another concurrent caller already refreshed while
        // we waited for the lock, the current access token differs from what
        // this caller observed failing — just return the new one, no
        // refresh call needed.
        if let Some(current) = &guard.access {
            if current.expose() != observed_access_token {
                return Ok(current.clone_inner());
            }
        }

        // We are the single in-flight refresher.
        let refresh_token = guard
            .refresh
            .as_ref()
            .ok_or_else(|| AxiamError::Auth {
                message: "no refresh token available; re-authentication required".into(),
            })?
            .expose()
            .clone();

        // §9.3: a 401 on the refresh call itself is AuthError with NO retry
        // loop — `do_refresh`'s `Result` is propagated as-is.
        let new_tokens = do_refresh(refresh_token).await?;

        guard.access = Some(new_tokens.access.clone_inner());
        if new_tokens.refresh.is_some() {
            guard.refresh = new_tokens.refresh;
        }
        if new_tokens.exp.is_some() {
            guard.exp = new_tokens.exp;
        }
        if new_tokens.tenant_id.is_some() {
            guard.tenant_id = new_tokens.tenant_id;
        }

        if let Ok(mut cache) = fast_cache.write() {
            *cache = Some(new_tokens.access.clone_inner());
        }

        Ok(new_tokens.access)
    }
}

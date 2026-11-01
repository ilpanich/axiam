//! G-C (#818) — what a **refused** refresh-token replay does besides refusing.
//!
//! T-254 made every presentation of an already-rotated refresh token visible:
//! marked on the session, audited as `oauth2.refresh_token_replayed`. It did
//! not revoke anything. This module is where the token endpoint learns, per
//! tenant, whether it now should: the tenant's effective
//! `oauth2.refresh_reuse_response` (the organization baseline merged with the
//! tenant override), `revoke_session` unless somebody chose `refuse`.
//!
//! # Why a port
//!
//! For the reason [`crate::scope_ceiling::ExternalClientScopePolicy`] is one:
//! the settings live in a repository `TokenService` has no type parameter for,
//! and the composition root builds one value over the settings repository.
//!
//! # Read only on the refusal path
//!
//! The policy is asked only after a replay has been recognised and refused, so
//! a grant that succeeds — every honest request — pays nothing for it.
//!
//! # A read that fails, or no port at all, means the default
//!
//! Unlike the scope ceiling, a failed read here does not refuse anything: the
//! refusal has already been decided. It falls back to
//! [`RefreshReuseResponse::default`], `revoke_session`, which is both the
//! system default (D-N2) and the stricter of the two values — a datastore
//! fault can make the endpoint revoke where a tenant asked it only to refuse,
//! never the reverse. A service built without a port ([`default_policy`])
//! behaves the same way.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_core::error::AxiamResult;
use axiam_core::models::settings::RefreshReuseResponse;
use uuid::Uuid;

/// Where a tenant's effective `oauth2.refresh_reuse_response` is read from.
pub trait RefreshReusePolicy: Send + Sync {
    /// The tenant's **effective** response to a refused refresh-token replay.
    ///
    /// An `Err` is a failed read; the caller falls back to the default.
    fn refresh_reuse_response<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<RefreshReuseResponse>> + Send + 'a>>;
}

/// The shared form every service holds.
pub type SharedRefreshReusePolicy = Arc<dyn RefreshReusePolicy>;

/// A policy that answers the same response for every tenant.
///
/// What a service holds until its composition root wires the settings-backed
/// one, and what a test uses to pin either behaviour.
#[derive(Debug, Clone, Copy)]
pub struct FixedRefreshReusePolicy(pub RefreshReuseResponse);

impl RefreshReusePolicy for FixedRefreshReusePolicy {
    fn refresh_reuse_response<'a>(
        &'a self,
        _tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<RefreshReuseResponse>> + Send + 'a>> {
        let response = self.0;
        Box::pin(async move { Ok(response) })
    }
}

/// The policy a service holds when nothing else is wired: the system default,
/// `revoke_session`, for every tenant.
pub fn default_policy() -> SharedRefreshReusePolicy {
    fixed(RefreshReuseResponse::default())
}

/// A [`SharedRefreshReusePolicy`] answering `response` for every tenant.
pub fn fixed(response: RefreshReuseResponse) -> SharedRefreshReusePolicy {
    Arc::new(FixedRefreshReusePolicy(response))
}

/// The response to apply for `tenant_id`, never failing: a failed read is
/// logged and answered with the default (see the module documentation).
pub async fn resolve(policy: &dyn RefreshReusePolicy, tenant_id: Uuid) -> RefreshReuseResponse {
    match policy.refresh_reuse_response(tenant_id).await {
        Ok(response) => response,
        Err(e) => {
            let fallback = RefreshReuseResponse::default();
            tracing::error!(
                error = %e,
                %tenant_id,
                fallback = fallback.as_str(),
                "oauth2: could not read the tenant's refresh_reuse_response; applying the default"
            );
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamError;

    struct Failing;

    impl RefreshReusePolicy for Failing {
        fn refresh_reuse_response<'a>(
            &'a self,
            _tenant_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = AxiamResult<RefreshReuseResponse>> + Send + 'a>> {
            Box::pin(async { Err(AxiamError::Database("settings unreadable".into())) })
        }
    }

    #[tokio::test]
    async fn an_unwired_service_revokes_by_default() {
        assert_eq!(
            resolve(default_policy().as_ref(), Uuid::new_v4()).await,
            RefreshReuseResponse::RevokeSession
        );
    }

    #[tokio::test]
    async fn a_fixed_policy_answers_what_it_was_given() {
        assert_eq!(
            resolve(fixed(RefreshReuseResponse::Refuse).as_ref(), Uuid::new_v4()).await,
            RefreshReuseResponse::Refuse
        );
    }

    #[tokio::test]
    async fn a_failed_read_falls_back_to_the_stricter_default() {
        assert_eq!(
            resolve(&Failing, Uuid::new_v4()).await,
            RefreshReuseResponse::RevokeSession,
            "a datastore fault may make the endpoint revoke, never stop it revoking"
        );
    }
}

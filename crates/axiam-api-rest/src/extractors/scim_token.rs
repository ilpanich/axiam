//! Resolution of SCIM provisioning tokens into a principal.
//!
//! See `claude_dev/scim-provisioning-token-design.md`. This module holds the
//! *resolution* half — turning a presented handle into a `(tenant, user)` pair
//! — because it needs `axiam-db`, which `axiam-scim` deliberately does not
//! depend on. The extractor that consumes it lives in `axiam_scim::auth`
//! alongside the JWT arm it sits beside.

use std::future::Future;
use std::pin::Pin;

use axiam_core::models::scim_token::ScimToken;
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{ScimTokenRepository, UserRepository};
use axiam_db::{SurrealScimTokenRepository, SurrealUserRepository};
use chrono::Utc;
use surrealdb::Connection;
use uuid::Uuid;

/// A principal resolved from a provisioning token.
///
/// Deliberately not an [`crate::AuthenticatedUser`]: that type carries
/// `ValidatedClaims`, the payload of a JWT this server signed. A provisioning
/// token is not a JWT and has no claims. Fabricating a claims set so the type
/// would fit would put a lie in the one place — the authenticated principal —
/// where a lie is most expensive.
#[derive(Debug, Clone, Copy)]
pub struct ScimTokenPrincipal {
    /// The token row's id — for the audit trail and the `last_used_at` stamp.
    pub token_id: Uuid,
    /// The tenant user the token authenticates as. RBAC is evaluated against
    /// this, never against anything stored on the token row.
    pub user_id: Uuid,
    pub tenant_id: Uuid,
}

/// Object-safe seam over the token lookup, so the `/scim/v2` extractor stays
/// free of the DB `Connection` generic.
///
/// Mirrors the boxed-future pattern [`crate::SessionValidator`] uses for the
/// identical reason: the underlying repository methods are RPITIT `async fn`
/// and are not dyn-safe on their own.
pub trait ScimTokenResolver: Send + Sync {
    /// Resolve a presented handle.
    ///
    /// `None` for every rejection — unknown handle, revoked, expired, or a
    /// bound user who is no longer active. The arms are deliberately
    /// indistinguishable to the caller: the wire answer is one 401 either way,
    /// and returning a reason would let somebody probing handles learn which
    /// of their guesses named a real credential.
    fn resolve<'a>(
        &'a self,
        raw_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<ScimTokenPrincipal>> + Send + 'a>>;

    /// Best-effort `last_used_at` stamp, after a request is accepted.
    fn touch<'a>(
        &'a self,
        tenant_id: Uuid,
        token_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// SurrealDB-backed [`ScimTokenResolver`].
pub struct SurrealScimTokenResolver<C: Connection + Clone> {
    tokens: SurrealScimTokenRepository<C>,
    users: SurrealUserRepository<C>,
}

impl<C: Connection + Clone> SurrealScimTokenResolver<C> {
    pub fn new(tokens: SurrealScimTokenRepository<C>, users: SurrealUserRepository<C>) -> Self {
        Self { tokens, users }
    }

    /// The bound user must still be able to log in.
    ///
    /// Checked on every request rather than only at mint time: a provisioning
    /// token outlives almost everything else in the system, and a deactivated
    /// provisioner whose credential kept working would make deactivation a
    /// suggestion. RBAC is checked separately and later — this is only about
    /// the principal still existing.
    async fn bound_user_is_active(&self, tenant_id: Uuid, user_id: Uuid) -> bool {
        match self.users.get_by_id(tenant_id, user_id).await {
            Ok(user) => user.status == UserStatus::Active,
            Err(_) => false,
        }
    }
}

impl<C: Connection + Clone + 'static> ScimTokenResolver for SurrealScimTokenResolver<C> {
    fn resolve<'a>(
        &'a self,
        raw_token: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<ScimTokenPrincipal>> + Send + 'a>> {
        Box::pin(async move {
            let hash = axiam_auth::token::hash_refresh_token(raw_token);
            let token: ScimToken = self.tokens.get_by_token_hash(&hash).await.ok()??;

            if !token.is_usable(Utc::now()) {
                // Logged at the point of refusal because the wire response
                // cannot say it: an operator debugging "Okta stopped syncing"
                // needs to find "revoked" or "expired" somewhere, and this is
                // the only place that knows.
                tracing::info!(
                    target: "axiam::audit",
                    event = "scim.token_rejected",
                    tenant_id = %token.tenant_id,
                    token_id = %token.id,
                    revoked = token.revoked_at.is_some(),
                    "provisioning token is revoked or expired"
                );
                return None;
            }

            if !self
                .bound_user_is_active(token.tenant_id, token.user_id)
                .await
            {
                tracing::info!(
                    target: "axiam::audit",
                    event = "scim.token_rejected",
                    tenant_id = %token.tenant_id,
                    token_id = %token.id,
                    reason = "bound_user_inactive",
                    "provisioning token names a user who is not active"
                );
                return None;
            }

            Some(ScimTokenPrincipal {
                token_id: token.id,
                user_id: token.user_id,
                tenant_id: token.tenant_id,
            })
        })
    }

    fn touch<'a>(
        &'a self,
        tenant_id: Uuid,
        token_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            // Deliberately swallowed: failing a provisioning request because a
            // usage timestamp could not be written would turn an
            // observability feature into an outage.
            let _ = self.tokens.touch_last_used(tenant_id, token_id).await;
        })
    }
}

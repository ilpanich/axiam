//! AXIAM REST API — HTTP extractors, authorization guards, server bootstrap,
//! and error handling.

pub mod authz;
pub mod backchannel_logout;
pub mod config;
pub mod error;
pub mod extractors;
pub mod handlers;
pub mod health;
pub mod middleware;
pub mod openapi;
pub mod permissions;
pub mod reactor_hooks;
pub mod server;
pub mod state;
pub mod tenant_org_cache;
pub mod token_exchange;
pub mod uma;
pub mod webhook;
pub mod webhook_consumer;

pub use authz::{AuthzChecker, AuthzData, RequirePermission};
pub use config::{RateLimitConfig, RateLimitPosture, RateLimitProfile, ServerConfig};
pub use error::AxiamApiError;
pub use extractors::auth::{AuthenticatedUser, SessionValidator};
pub use extractors::cert_auth::{CertificateAuthenticated, VerifiedClientCert};
pub use extractors::scim_token::{ScimTokenPrincipal, ScimTokenResolver, SurrealScimTokenResolver};
pub use extractors::tenant::TenantContext;
pub use health::HealthChecker;
pub use openapi::ApiDoc;
pub use server::{
    api_v1_routes, build_cors, build_governor, health_routes, openapi_routes,
    register_api_v1_routes,
};
pub use state::AppState;

#[cfg(test)]
mod tests;

/// Re-applies the mTLS trust anchor bundle to the running TLS listener.
///
/// # Why a trait here rather than a call there
///
/// The handler that flags a CA as a trust anchor runs *inside* the server that
/// would have to reload, and `axiam-api-rest` sits below `axiam-server` in the
/// crate layering, so it cannot name the listener. This is the seam: the server
/// registers an implementation at startup, and the handler asks for one.
///
/// Boxed future because the implementation reads the CA rows, and the
/// repository methods are native `async fn` — the same reason
/// [`crate::authz::AuthzChecker`] is shaped this way.
pub trait TrustAnchorReloader: Send + Sync {
    /// Rebuild the anchor set from the database, write the bundle, and install
    /// it on the live listener.
    ///
    /// Returns how many anchors are now trusted, or `None` when this process
    /// has no TLS listener doing client authentication — a plaintext
    /// deployment, or one whose operator set `client_auth = off`. `None` is not
    /// a failure: there is nothing to reload into, and the caller reports that
    /// the change is stored and will apply when TLS is enabled.
    ///
    /// # Errors
    ///
    /// A bundle that cannot be parsed or an anchor webpki refuses. The live
    /// anchor set is left unchanged in that case — the replacement is built
    /// completely before anything is swapped, so a bad reload cannot leave the
    /// listener trusting nothing.
    fn reload<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = axiam_core::error::AxiamResult<Option<usize>>>
                + Send
                + 'a,
        >,
    >;
}

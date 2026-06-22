//! gRPC auth interceptor — validates bearer JWT on every inbound request.
//!
//! SEC-003: Any caller that reaches the authorization service must present a
//! cryptographically verified bearer token.  The interceptor extracts the
//! `authorization` metadata header, strips the `Bearer ` prefix, delegates
//! to `axiam_auth::token::validate_access_token`, and — on success — stores
//! the [`ValidatedClaims`] in the request extensions so downstream service
//! handlers can derive `tenant_id`/`subject_id` from verified claims rather
//! than trusting the request body.

use axiam_auth::config::AuthConfig;
use axiam_auth::token::validate_access_token;
use tonic::service::Interceptor;
use tonic::{Request, Status};

/// Tonic interceptor that enforces bearer JWT authentication.
///
/// Clone-safe: `AuthConfig` derives `Clone`, so `AuthInterceptor` can be
/// cloned for each new connection (Tonic 0.14 requirement for
/// `with_interceptor`).
#[derive(Clone)]
pub struct AuthInterceptor {
    auth_config: AuthConfig,
}

impl AuthInterceptor {
    /// Create a new interceptor backed by the given [`AuthConfig`].
    pub fn new(auth_config: AuthConfig) -> Self {
        Self { auth_config }
    }
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: Request<()>) -> Result<Request<()>, Status> {
        let token = req
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| Status::unauthenticated("missing bearer token"))?;

        let claims = validate_access_token(token, &self.auth_config)
            .map_err(|_| Status::unauthenticated("invalid or expired token"))?;

        req.extensions_mut().insert(claims);
        Ok(req)
    }
}

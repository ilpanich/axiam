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
use axiam_auth::token::{AUD_M2M, AUD_USER, validate_access_token};
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

        // §17.2 residual 2: the audience policy on this transport used to be
        // entirely implicit. `decode_access_token` accepts both audiences, and
        // deliberately **skips** the audience check altogether when the claim
        // is absent (the D-20 pre-Phase-4 back-compat window) — so a token
        // with no `aud` reached the authorization service with no narrowing
        // applied and nothing recorded about it. The REST extractors gate that
        // same case on `allow_missing_aud_as_user` and warn on every use; this
        // transport did neither.
        //
        // gRPC accepts **both** audiences on purpose, and that is now stated
        // rather than inherited: this is the low-latency check surface for a
        // service mesh, so machine callers are the norm, while user tokens
        // reach it through SDK callers doing the same checks. What is fixed
        // here is the *unstated* third case.
        match claims.0.aud.as_deref() {
            Some(AUD_USER) | Some(AUD_M2M) => {}
            None => {
                if !self.auth_config.allow_missing_aud_as_user {
                    return Err(Status::unauthenticated("aud required"));
                }
                tracing::warn!(
                    token_jti = %claims.0.jti,
                    "grpc: accepted access token without aud — backward-compat window active"
                );
            }
            Some(_) => return Err(Status::unauthenticated("unknown audience")),
        }

        req.extensions_mut().insert(claims);
        Ok(req)
    }
}

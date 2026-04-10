//! Global authorization middleware — default-deny for all non-public paths.
//!
//! [`AuthzMiddleware`] implements the first layer of defense-in-depth (D-01,
//! D-03):
//!
//! - Public paths (from [`PUBLIC_PATHS`]) pass through without any credential
//!   check.
//! - All other paths require a JWT to be present in either the `axiam_access`
//!   cookie or the `Authorization` header. Missing credentials → **401**.
//! - When credentials are present the request is forwarded to the handler.
//!   The per-handler [`RequirePermission`] guard then performs the actual
//!   permission check (D-02), returning **403** on denial.
//!
//! [`RequirePermission`]: crate::authz::RequirePermission

use std::future::{Future, Ready, ready};
use std::pin::Pin;

use actix_web::Error;
use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use axiam_core::error::AxiamError;

use crate::error::AxiamApiError;
use crate::middleware::csrf::COOKIE_ACCESS;
use crate::permissions::PUBLIC_PATHS;

// ---------------------------------------------------------------------------
// Public-path check
// ---------------------------------------------------------------------------

/// Returns `true` if `path` is in the public-path allowlist and should be
/// allowed through without credential validation.
///
/// Matching rules:
/// - Entries ending with `*` are **prefix-matched** (the `*` is stripped).
/// - All other entries are compared with `==` (exact match).
pub fn is_public_path(path: &str) -> bool {
    for &entry in PUBLIC_PATHS {
        if let Some(prefix) = entry.strip_suffix('*') {
            if path.starts_with(prefix) {
                return true;
            }
        } else {
            if path == entry {
                return true;
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/// Global authorization middleware.
///
/// Wrap API scopes with `.wrap(AuthzMiddleware)` in `server.rs`.
pub struct AuthzMiddleware;

impl<S, B> Transform<S, ServiceRequest> for AuthzMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = AuthzMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthzMiddlewareService { inner: service }))
    }
}

// ---------------------------------------------------------------------------
// Inner service
// ---------------------------------------------------------------------------

pub struct AuthzMiddlewareService<S> {
    inner: S,
}

impl<S, B> Service<ServiceRequest> for AuthzMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_owned();

        // 1. Public paths pass through unconditionally.
        if is_public_path(&path) {
            let fut = self.inner.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // 2. Check for credential presence (cookie OR Authorization header).
        let has_cookie = req.cookie(COOKIE_ACCESS).is_some();
        let has_bearer = req.headers().contains_key("Authorization");

        if !has_cookie && !has_bearer {
            // No credentials → 401 Unauthorized.
            let error: actix_web::Error = AxiamApiError(AxiamError::AuthenticationFailed {
                reason: "authentication required".into(),
            })
            .into();
            return Box::pin(async move {
                let res = req.error_response(error);
                Ok(res.map_into_right_body())
            });
        }

        // 3. Credentials present — forward to handler for permission check.
        let fut = self.inner.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::is_public_path;

    #[test]
    fn public_paths_are_recognized() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/auth/login"));
        assert!(is_public_path("/.well-known/openid-configuration"));
        assert!(is_public_path("/oauth2/token"));
        assert!(is_public_path("/api/docs/openapi.json")); // prefix match via /api/docs/*
        assert!(is_public_path("/api/v1/admin/bootstrap"));
    }

    #[test]
    fn protected_paths_are_not_public() {
        assert!(!is_public_path("/api/v1/users"));
        assert!(!is_public_path("/api/v1/roles"));
        assert!(!is_public_path("/api/v1/permissions"));
        assert!(!is_public_path("/api/v1/settings"));
    }
}

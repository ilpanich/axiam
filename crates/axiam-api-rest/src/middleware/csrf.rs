//! CSRF double-submit cookie middleware and cookie builder helpers.
//!
//! The [`CsrfMiddleware`] rejects state-changing requests that lack a valid
//! `X-CSRF-Token` header matching the `axiam_csrf` cookie value.
//! Comparison uses constant-time equality to prevent timing attacks (D-01).
//!
//! Cookie helpers build the three auth cookies (`axiam_access`,
//! `axiam_refresh`, `axiam_csrf`) with the security attributes specified
//! in the UI-SPEC design decisions (D-05 through D-09).

use std::future::{Future, Ready, ready};
use std::pin::Pin;

use actix_web::Error;
use actix_web::body::EitherBody;
use actix_web::cookie::{Cookie, SameSite, time::Duration};
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use axiam_core::error::AxiamError;
use subtle::ConstantTimeEq;

use crate::error::AxiamApiError;

// ---------------------------------------------------------------------------
// Cookie names and header
// ---------------------------------------------------------------------------

pub const COOKIE_ACCESS: &str = "axiam_access";
pub const COOKIE_REFRESH: &str = "axiam_refresh";
pub const COOKIE_CSRF: &str = "axiam_csrf";
pub const HEADER_CSRF: &str = "X-CSRF-Token";

// ---------------------------------------------------------------------------
// Exempt path suffixes — no CSRF token needed on these endpoints
// ---------------------------------------------------------------------------

/// Path suffixes that are exempt from CSRF validation.
///
/// These are either unauthenticated endpoints (login, MFA flows) that do not
/// yet have a CSRF cookie, or token-based OAuth2 flows that use their own
/// security model.
const CSRF_EXEMPT_SUFFIXES: &[&str] = &[
    "/api/v1/auth/login",
    "/api/v1/auth/mfa/verify",
    "/api/v1/auth/mfa/setup/enroll",
    "/api/v1/auth/mfa/setup/confirm",
    "/api/v1/auth/device",
    // Password reset request + confirm are unauthenticated and token-based:
    // the caller has no session and therefore no CSRF cookie yet (same model
    // as /login). Without these, a forgotten-password reset is CSRF-blocked (403).
    "/api/v1/auth/reset",
    "/api/v1/auth/reset/confirm",
];

/// Path prefixes that are exempt from CSRF validation (OAuth2).
const CSRF_EXEMPT_PREFIXES: &[&str] = &["/oauth2/"];

fn is_csrf_exempt(path: &str) -> bool {
    for suffix in CSRF_EXEMPT_SUFFIXES {
        if path.ends_with(suffix) {
            return true;
        }
    }
    for prefix in CSRF_EXEMPT_PREFIXES {
        if path.starts_with(prefix) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Middleware factory
// ---------------------------------------------------------------------------

/// CSRF double-submit cookie middleware.
///
/// Safe methods (GET, HEAD, OPTIONS) pass through unconditionally.
/// State-changing methods require `X-CSRF-Token` to match the `axiam_csrf`
/// cookie value, compared with constant-time equality.
pub struct CsrfMiddleware;

impl<S, B> Transform<S, ServiceRequest> for CsrfMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = CsrfMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(CsrfMiddlewareService { inner: service }))
    }
}

pub struct CsrfMiddlewareService<S> {
    inner: S,
}

impl<S, B> Service<ServiceRequest> for CsrfMiddlewareService<S>
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
        // Safe methods — always exempt.
        let method = req.method().clone();
        if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
            let fut = self.inner.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Exempt paths (login, MFA flows, OAuth2).
        let path = req.path().to_owned();
        if is_csrf_exempt(&path) {
            let fut = self.inner.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Extract CSRF cookie and header.
        let cookie_value = req.cookie(COOKIE_CSRF).map(|c| c.value().to_owned());

        let header_value = req
            .headers()
            .get(HEADER_CSRF)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        // Validate — both must be present and equal (constant-time).
        let valid = match (cookie_value, header_value) {
            (Some(cookie), Some(header)) => cookie.as_bytes().ct_eq(header.as_bytes()).into(),
            _ => false,
        };

        if !valid {
            let error: actix_web::Error = AxiamApiError(AxiamError::AuthorizationDenied {
                reason: "CSRF validation failed".into(),
            })
            .into();
            return Box::pin(async move {
                let res = req.error_response(error);
                Ok(res.map_into_right_body())
            });
        }

        let fut = self.inner.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

/// Generate a cryptographically random CSRF token (32 bytes, hex-encoded).
pub fn generate_csrf_token() -> String {
    let bytes: [u8; 32] = rand::random();
    hex::encode(bytes)
}

/// Build the `axiam_access` httpOnly cookie (per D-05).
///
/// - `httpOnly(true)` — not accessible from JavaScript
/// - `Secure` — HTTPS only
/// - `SameSite::Strict` — no cross-site sending
/// - `path("/")` — all paths
pub fn access_cookie(token: &str, max_age_secs: u64) -> Cookie<'static> {
    Cookie::build(COOKIE_ACCESS, token.to_owned())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}

/// Build the `axiam_refresh` httpOnly cookie (per D-06).
///
/// Path-scoped to the refresh endpoint to minimise exposure surface.
pub fn refresh_cookie(token: &str, max_age_secs: u64) -> Cookie<'static> {
    Cookie::build(COOKIE_REFRESH, token.to_owned())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/api/v1/auth/refresh")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}

/// Build the `axiam_csrf` JS-readable cookie (per D-07, D-09).
///
/// - `httpOnly(false)` — JavaScript must read this to send `X-CSRF-Token`
/// - `Secure` — HTTPS only
/// - `SameSite::Strict` — no cross-site sending
/// - `path("/")` — all paths; lifetime matches the access token
pub fn csrf_cookie(token: &str, max_age_secs: u64) -> Cookie<'static> {
    Cookie::build(COOKIE_CSRF, token.to_owned())
        .http_only(false)
        .secure(true)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}

/// Clear the `axiam_access` cookie (Max-Age=0, per D-08).
pub fn clear_access_cookie() -> Cookie<'static> {
    let mut c = Cookie::build(COOKIE_ACCESS, "").path("/").finish();
    c.make_removal();
    c
}

/// Clear the `axiam_refresh` cookie.
pub fn clear_refresh_cookie() -> Cookie<'static> {
    let mut c = Cookie::build(COOKIE_REFRESH, "")
        .path("/api/v1/auth/refresh")
        .finish();
    c.make_removal();
    c
}

/// Clear the `axiam_csrf` cookie.
pub fn clear_csrf_cookie() -> Cookie<'static> {
    let mut c = Cookie::build(COOKIE_CSRF, "").path("/").finish();
    c.make_removal();
    c
}

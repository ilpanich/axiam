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
    // The OPAQUE endpoints are exempt on exactly the same grounds as /login:
    // the caller is unauthenticated and has no `axiam_csrf` cookie to echo.
    // This is a separate registry from `permissions::PUBLIC_PATHS` and both
    // must cover a route for it to work unauthenticated — omitting it here
    // gives a 403 before the handler ever runs.
    "/api/v1/auth/opaque/register/start",
    "/api/v1/auth/opaque/login/start",
    "/api/v1/auth/opaque/login/finish",
    "/api/v1/auth/mfa/verify",
    "/api/v1/auth/mfa/setup/enroll",
    "/api/v1/auth/mfa/setup/confirm",
    // WebAuthn **authentication** — the passkey and security-key equivalents of
    // /login, and unauthenticated for the same reason: these ceremonies *are*
    // the authentication, so the caller holds no session and has no
    // `axiam_csrf` cookie to echo. They were listed in `permissions::
    // PUBLIC_PATHS` but not here, and both registries must cover a route: the
    // result was a `403 CSRF validation failed` on
    // `/webauthn/authenticate/start` before the handler ever ran, which made
    // passkey sign-in impossible from a browser with no prior session.
    //
    // The **registration** pair is deliberately NOT exempt. Adding a passkey is
    // done by a user who is already signed in and therefore does carry the
    // cookie, and an exemption there would let any site silently enrol its own
    // authenticator onto a logged-in victim's account — account takeover by
    // exactly the request forgery this middleware exists to stop.
    "/api/v1/auth/webauthn/authenticate/start",
    "/api/v1/auth/webauthn/authenticate/finish",
    "/api/v1/auth/webauthn/authenticate/discoverable/start",
    "/api/v1/auth/webauthn/authenticate/discoverable/finish",
    "/api/v1/auth/device",
    // Password reset request + confirm are unauthenticated and token-based:
    // the caller has no session and therefore no CSRF cookie yet (same model
    // as /login). Without these, a forgotten-password reset is CSRF-blocked (403).
    "/api/v1/auth/reset",
    "/api/v1/auth/reset/confirm",
    // Bootstrap is a one-time endpoint called before any session exists.
    // It is protected by the AXIAM_BOOTSTRAP_ADMIN_EMAIL env gate instead (D-10).
    "/api/v1/admin/bootstrap",
    // 28-05/CQ-B40: the four first-time-SSO public endpoints (D-22,
    // handlers/federation.rs) are unauthenticated by design — same model as
    // /login and /reset/confirm above: the caller has no prior session and
    // therefore no `axiam_csrf` cookie to echo back. Without these entries a
    // first-time OIDC/SAML SSO login is CSRF-blocked (403) before the
    // handler ever runs, even though the route is correctly listed in
    // PUBLIC_PATHS (AuthzMiddleware bypass is a separate registry from this
    // one — both must cover a route for it to work unauthenticated).
    "/api/v1/auth/federation/oidc/start",
    "/api/v1/auth/federation/oidc/callback",
    "/api/v1/auth/federation/saml/login",
    "/api/v1/auth/federation/saml/acs",
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

/// Whether a request authenticates by bearer token ALONE.
///
/// Split out as a pure function so the condition can be pinned by tests: it is
/// the exemption that decides whether CSRF validation runs at all, and the case
/// that matters is the one where BOTH are present.
///
/// * bearer + no session cookie → exempt. There is no ambient credential to
///   abuse and no double-submit cookie the caller could echo.
/// * bearer + a session cookie → **not** exempt. That is precisely the shape a
///   cross-site attacker would craft to escape the exemption: the browser
///   supplies the cookie, the attacker supplies the header.
/// * no bearer → not exempt, whatever the cookies say.
fn is_bearer_only(authorization: Option<&str>, has_session_cookie: bool) -> bool {
    if has_session_cookie {
        return false;
    }
    authorization.is_some_and(|v| v.trim_start().to_ascii_lowercase().starts_with("bearer "))
}

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

        // Bearer-only callers carry no ambient credential, so there is nothing
        // for CSRF to protect and nothing they could echo back.
        //
        // CSRF is an attack on credentials the browser attaches BY ITSELF — the
        // session cookie. A request authenticated solely by an `Authorization`
        // header has no such credential: a cross-site page cannot set that
        // header on a victim's behalf, and the double-submit cookie it would
        // have to echo does not exist. Demanding one is unsatisfiable rather
        // than protective, and it made the machine-facing surface unreachable
        // for exactly the callers it was built for — a service account's
        // `client_credentials` token could not `POST /api/v1/authz/check`,
        // whose `AuthenticatedPrincipal` extractor exists to accept the
        // `axiam:m2m` audience.
        //
        // The condition is deliberately narrow: the session cookie must be
        // ABSENT as well. A request that carries both a session cookie and a
        // bearer header is exactly the shape a cross-site attacker would craft
        // to escape this exemption — the browser supplies the cookie, the
        // attacker supplies the header — so it stays subject to validation.
        let has_session_cookie = req.cookie(COOKIE_ACCESS).is_some()
            || req.cookie(COOKIE_REFRESH).is_some()
            || req.cookie(COOKIE_CSRF).is_some();
        let auth_header = req
            .headers()
            .get(actix_web::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if is_bearer_only(auth_header, has_session_cookie) {
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
                action: None,
                resource_id: None,
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
/// - `Secure` — controlled by `cookie_secure`; must be `true` in production
/// - `SameSite::Strict` — no cross-site sending
/// - `path("/")` — all paths
///
/// `cookie_secure` should be read from `AuthConfig::cookie_secure` (D-18).
pub fn access_cookie(token: &str, max_age_secs: u64, cookie_secure: bool) -> Cookie<'static> {
    Cookie::build(COOKIE_ACCESS, token.to_owned())
        .http_only(true)
        .secure(cookie_secure)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}

/// Build the `axiam_refresh` httpOnly cookie (per D-06).
///
/// Path-scoped to the refresh endpoint to minimise exposure surface.
///
/// `cookie_secure` should be read from `AuthConfig::cookie_secure` (D-18).
pub fn refresh_cookie(token: &str, max_age_secs: u64, cookie_secure: bool) -> Cookie<'static> {
    Cookie::build(COOKIE_REFRESH, token.to_owned())
        .http_only(true)
        .secure(cookie_secure)
        .same_site(SameSite::Strict)
        .path("/api/v1/auth/refresh")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}

/// Build the `axiam_csrf` JS-readable cookie (per D-07, D-09).
///
/// - `httpOnly(false)` — JavaScript must read this to send `X-CSRF-Token`
/// - `Secure` — controlled by `cookie_secure`; must be `true` in production
/// - `SameSite::Strict` — no cross-site sending
/// - `path("/")` — all paths; lifetime matches the access token
///
/// `cookie_secure` should be read from `AuthConfig::cookie_secure` (D-18).
pub fn csrf_cookie(token: &str, max_age_secs: u64, cookie_secure: bool) -> Cookie<'static> {
    Cookie::build(COOKIE_CSRF, token.to_owned())
        .http_only(false)
        .secure(cookie_secure)
        .same_site(SameSite::Strict)
        .path("/")
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}

// A removal cookie is still a `Set-Cookie` the browser parses and stores until
// it expires, so it must mirror **every** attribute of the cookie it clears —
// not just `path`. Emitting a bare `Path=/` removal for a cookie that was set
// `HttpOnly; Secure; SameSite=Strict` leaves the (empty-valued) cookie
// JS-readable, cross-site-sendable and cleartext-transmissible for the life of
// the response, and makes the removal itself depend on transport the setters
// explicitly do not trust: browsers refuse to let a non-`Secure` cookie from an
// insecure origin overwrite a `Secure` one ("Leave Secure Cookies Alone").
//
// Rather than restate each setter's attributes here — a second copy that can
// drift from the first, which is precisely the bug being fixed — every removal
// is built by calling its own setter and then expiring the result.
// `Cookie::make_removal` rewrites only value, `Max-Age` and `Expires`, so
// `HttpOnly`, `Secure`, `SameSite` and `Path` are mirrored by construction.

/// Clear the `axiam_access` cookie (Max-Age=0, per D-08).
///
/// Built from [`access_cookie`], so it mirrors its attributes; `cookie_secure`
/// must be the same `AuthConfig::cookie_secure` value used to set it (D-18).
pub fn clear_access_cookie(cookie_secure: bool) -> Cookie<'static> {
    let mut c = access_cookie("", 0, cookie_secure);
    c.make_removal();
    c
}

/// Clear the `axiam_refresh` cookie.
///
/// Built from [`refresh_cookie`], so it mirrors its attributes — including the
/// `/api/v1/auth/refresh` path scope, since a removal on a different path would
/// not match the cookie.
pub fn clear_refresh_cookie(cookie_secure: bool) -> Cookie<'static> {
    let mut c = refresh_cookie("", 0, cookie_secure);
    c.make_removal();
    c
}

/// Clear the `axiam_csrf` cookie.
///
/// Built from [`csrf_cookie`], so it mirrors its attributes — including
/// `httpOnly(false)`, which is deliberate there (D-07: JavaScript reads this one
/// to populate `X-CSRF-Token`) and is therefore kept here too.
pub fn clear_csrf_cookie(cookie_secure: bool) -> Cookie<'static> {
    let mut c = csrf_cookie("", 0, cookie_secure);
    c.make_removal();
    c
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // The bearer exemption (B-05). Before it, a service account's
    // `client_credentials` token could not POST to /api/v1/authz/check — the
    // one REST surface `AuthenticatedPrincipal` was widened to accept the
    // `axiam:m2m` audience for — because it has no cookie to echo and never
    // could have one.
    #[test]
    fn bearer_without_a_session_cookie_is_exempt() {
        assert!(is_bearer_only(Some("Bearer eyJhbGciOi..."), false));
        // Header names are case-insensitive and so is the scheme.
        assert!(is_bearer_only(Some("bearer eyJhbGciOi..."), false));
        assert!(is_bearer_only(Some("  Bearer eyJhbGciOi..."), false));
    }

    #[test]
    fn bearer_alongside_a_session_cookie_is_not_exempt() {
        // The load-bearing case. A cross-site page cannot set the header on a
        // victim's behalf, but it can cause a request that carries the victim's
        // cookie — so a request with both must still prove it has the token.
        assert!(!is_bearer_only(Some("Bearer eyJhbGciOi..."), true));
    }

    #[test]
    fn a_request_with_no_bearer_is_never_exempt() {
        assert!(!is_bearer_only(None, false));
        assert!(!is_bearer_only(None, true));
        // Neither is some other scheme: only bearer tokens are non-ambient.
        assert!(!is_bearer_only(Some("Basic dXNlcjpwYXNz"), false));
    }

    // The exempt list and `permissions::PUBLIC_PATHS` are separate registries
    // and a route needs both. These pin the half that was missing, and the one
    // neighbouring route that must stay protected.
    #[test]
    fn webauthn_authentication_ceremonies_are_csrf_exempt() {
        for path in [
            "/api/v1/auth/webauthn/authenticate/start",
            "/api/v1/auth/webauthn/authenticate/finish",
            "/api/v1/auth/webauthn/authenticate/discoverable/start",
            "/api/v1/auth/webauthn/authenticate/discoverable/finish",
        ] {
            assert!(
                is_csrf_exempt(path),
                "{path} must be CSRF-exempt: the caller is signing in and has no csrf cookie yet"
            );
        }
    }

    #[test]
    fn webauthn_registration_is_not_csrf_exempt() {
        for path in [
            "/api/v1/auth/webauthn/register/start",
            "/api/v1/auth/webauthn/register/finish",
        ] {
            assert!(
                !is_csrf_exempt(path),
                "{path} must stay CSRF-protected: enrolling a passkey is done from an \
                 authenticated session, and an exemption would allow silent enrolment \
                 onto a signed-in victim's account"
            );
        }
    }

    #[test]
    fn every_csrf_exempt_auth_path_is_also_publicly_routable() {
        // A path exempted here but absent from PUBLIC_PATHS is 401'd by
        // AuthzMiddleware instead — the same drift in the other direction.
        for path in CSRF_EXEMPT_SUFFIXES {
            if !path.starts_with("/api/v1/auth/") {
                continue;
            }
            assert!(
                crate::permissions::PUBLIC_PATHS.contains(path),
                "{path} is CSRF-exempt but not in PUBLIC_PATHS"
            );
        }
    }

    #[test]
    fn cookie_secure_true_sets_secure_attribute() {
        let c = access_cookie("tok", 900, true);
        assert!(c.secure().unwrap_or(false), "expected Secure=true");

        let c = refresh_cookie("tok", 86400, true);
        assert!(c.secure().unwrap_or(false), "expected Secure=true");

        let c = csrf_cookie("tok", 900, true);
        assert!(c.secure().unwrap_or(false), "expected Secure=true");
    }

    #[test]
    fn cookie_secure_false_omits_secure_attribute() {
        let c = access_cookie("tok", 900, false);
        assert!(
            !c.secure().unwrap_or(true),
            "expected Secure=false for HTTP dev"
        );

        let c = refresh_cookie("tok", 86400, false);
        assert!(
            !c.secure().unwrap_or(true),
            "expected Secure=false for HTTP dev"
        );

        let c = csrf_cookie("tok", 900, false);
        assert!(
            !c.secure().unwrap_or(true),
            "expected Secure=false for HTTP dev"
        );
    }

    /// A removal cookie is a `Set-Cookie` in its own right: the browser stores
    /// what it says until it expires. If it does not carry the same flags as
    /// the cookie it clears, the empty-valued replacement is weaker than the
    /// value it replaced — and a non-`Secure` removal cannot overwrite a
    /// `Secure` cookie from an insecure origin at all.
    #[test]
    fn removal_cookies_mirror_the_attributes_of_the_cookies_they_clear() {
        for secure in [true, false] {
            let pairs = [
                (
                    access_cookie("tok", 900, secure),
                    clear_access_cookie(secure),
                ),
                (
                    refresh_cookie("tok", 86400, secure),
                    clear_refresh_cookie(secure),
                ),
                (csrf_cookie("tok", 900, secure), clear_csrf_cookie(secure)),
            ];

            for (set, clear) in pairs {
                let name = set.name().to_owned();
                assert_eq!(clear.name(), name, "removal must target the same cookie");
                assert_eq!(
                    clear.path(),
                    set.path(),
                    "{name}: a removal on a different path does not match the cookie"
                );
                assert_eq!(
                    clear.secure(),
                    set.secure(),
                    "{name}: removal Secure must match the setter's (secure={secure})"
                );
                assert_eq!(
                    clear.http_only(),
                    set.http_only(),
                    "{name}: removal HttpOnly must match the setter's"
                );
                assert_eq!(
                    clear.same_site(),
                    set.same_site(),
                    "{name}: removal SameSite must match the setter's"
                );
            }
        }
    }

    /// `make_removal` is what actually expires the cookie; the attribute
    /// mirroring above must not have displaced it.
    #[test]
    fn removal_cookies_are_still_expiring_removals() {
        for c in [
            clear_access_cookie(true),
            clear_refresh_cookie(true),
            clear_csrf_cookie(true),
        ] {
            let name = c.name().to_owned();
            assert_eq!(c.value(), "", "{name}: removal must carry an empty value");
            assert_eq!(
                c.max_age(),
                Some(Duration::seconds(0)),
                "{name}: removal must set Max-Age=0"
            );
        }
    }
}

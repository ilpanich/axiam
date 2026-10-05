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
use axiam_auth::config::AuthConfig;
use axiam_core::error::AxiamError;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::error::AxiamApiError;

// ---------------------------------------------------------------------------
// Cookie names and header
// ---------------------------------------------------------------------------

pub const COOKIE_ACCESS: &str = "axiam_access";
pub const COOKIE_REFRESH: &str = "axiam_refresh";
pub const COOKIE_CSRF: &str = "axiam_csrf";
/// W3 — the OP browser-session cookie read by `/oauth2/authorize` (plan §4.0).
pub const COOKIE_OP_SESSION: &str = "axiam_op_session";
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
    //
    // The **setup-token** registration pair (M-3) is the opposite case, and is
    // exempt on the same grounds as `/mfa/setup/enroll` and `/setup/confirm`
    // above. Its caller is mid-forced-enrolment: they have no session, no
    // `axiam_csrf` cookie to echo, and the only credential the endpoint accepts
    // is a setup token carried **in the request body**. That is precisely the
    // condition this middleware's own exemption test names — there is no
    // ambient credential for a cross-site request to ride. A site that could
    // forge one of these would already have to hold the token, and a caller
    // holding the token needs no forgery.
    "/api/v1/auth/webauthn/setup/register/start",
    "/api/v1/auth/webauthn/setup/register/finish",
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
    // The login-provider surface added with "Sign in with X", exempt for the
    // same reason as the four above: none of these callers has a prior session,
    // so none has an `axiam_csrf` cookie to echo.
    //
    // The two `…/form` entries additionally *cannot* carry one even in
    // principle — the request is a cross-site form POST performed by the
    // identity provider. What stands in for CSRF protection there is the
    // provider's own signed assertion plus the single-use server-side state
    // row, both of which an attacker would have to forge.
    "/api/v1/auth/federation/oauth2/start",
    "/api/v1/auth/federation/oauth2/callback",
    "/api/v1/auth/federation/oidc/callback/form",
    "/api/v1/auth/federation/saml/acs/form",
    // Redeeming a handoff code is same-origin but pre-session: the response
    // being requested is the one that *sets* the CSRF cookie.
    "/api/v1/auth/federation/handoff",
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

/// Build the `axiam_op_session` cookie — the OP browser session (W3, plan §4.0).
///
/// - `httpOnly(true)` — script must never read it; it buys authorization codes
/// - `Secure` — **unconditionally `true`**, unlike the other three; see below
/// - `SameSite::Lax` — **the load-bearing attribute**, see below
/// - `path("/oauth2/authorize")` — the only endpoint that consults it, and
///   the only one under the deployment-wide issuer. A deployment serving T21.6
///   per-tenant issuers also mints a copy at `/t/{tenant_id}/oauth2/authorize`
///   for the session's own tenant, identical but for `Path` (T23.1.8, D-11) —
///   see [`op_session_cookie_paths`], which every sign-in and every logout goes
///   through, and which is the only place a path is chosen. The one route under
///   either path besides the endpoint itself is its `/logout` sub-path, which
///   reads the cookie only to revoke the session it names (P23W1-10).
/// - `Max-Age` = the session's, i.e. `AuthConfig::refresh_token_lifetime_secs`
///
/// # Why `Lax`, and why it must stay `Lax`
///
/// A browser sends a `Lax` cookie on **top-level GET navigations and nothing
/// else**. That is precisely an OpenID Connect redirect from a relying party,
/// and precisely *not* an `<iframe>`, an `<img>`, or a cross-site `fetch` —
/// so the one thing this cookie exists to enable works, and the probing
/// technique it would otherwise enable does not. An attacker's page cannot
/// frame `/oauth2/authorize` and watch whether a session exists, because the
/// cookie is not sent inside a frame at all.
///
/// The cost is stated rather than hidden, and it is recorded in plan §9: the
/// cross-site hidden-iframe silent-renew pattern (`prompt=none` in an invisible
/// frame) **is not supported and fails closed**. Relying parties renew with a
/// top-level `prompt=none` navigation or with a refresh token. Changing this to
/// `SameSite=None` would make that pattern work and would hand every site on
/// the internet the same probe; it is not a fix and must not be made as one.
///
/// # Why a second cookie rather than relaxing `axiam_access`
///
/// `axiam_access` is `SameSite=Strict; Path=/` and opens the entire API. This
/// one is scoped to a single endpoint, so a browser that sends it cross-site can
/// obtain exactly one thing: an authorization code, for a client that is
/// registered, at a `redirect_uri` that matched exactly, bound to the relying
/// party's own PKCE and `state`. The API surface keeps its Strict cookies and
/// its double-submit CSRF token untouched, and SEC-046's threat model for the
/// API cookie is unchanged rather than re-argued.
///
/// # Why `Secure` is not `cookie_secure` here
///
/// The other three cookies take `AuthConfig::cookie_secure` (D-18), whose
/// documented purpose is local HTTP development *"e.g. http://localhost"*. This
/// one does not, for two reasons that only apply to it:
///
/// 1. It is the only `SameSite=Lax` cookie in the codebase, i.e. the only one a
///    browser sends on a **cross-site** top-level navigation. That is the whole
///    point of it — and it means a plaintext hop exposes it on a request the
///    user never typed, in a context the three `Strict` cookies never reach.
/// 2. The endpoint it is scoped to must be TLS-protected regardless: RFC 6749
///    §3.1 requires TLS on the authorization endpoint, and this project's own
///    standard is TLS 1.3 minimum for external communication. A cookie that
///    refuses to exist over plaintext is enforcing a rule the endpoint already
///    has, not adding one.
///
/// It costs nothing in the case D-18 exists for: browsers treat
/// `http://localhost` and `http://127.0.0.1` as trustworthy origins and store
/// `Secure` cookies set from them. What it does refuse is a browser login hop
/// over plaintext to a *non-loopback* host — which is a deployment that should
/// not be completing OpenID Connect authorization requests at all.
pub fn op_session_cookie(token: &str, max_age_secs: u64) -> Cookie<'static> {
    op_session_cookie_at(token, max_age_secs, AUTHORIZE_PATH.to_owned())
}

/// [`op_session_cookie`], at one of the paths [`op_session_cookie_paths`]
/// names (T23.1.8, D-11).
///
/// Every attribute but `Path` is fixed here, so the bare-path cookie and each
/// per-tenant one differ in `Path` and in nothing else — the property the
/// acceptance tests assert attribute by attribute. Private to this module on
/// purpose: a caller that could choose the path could mint the cookie
/// somewhere the list does not say, and a removal built from the list would
/// then never reach it.
fn op_session_cookie_at(token: &str, max_age_secs: u64, path: String) -> Cookie<'static> {
    Cookie::build(COOKIE_OP_SESSION, token.to_owned())
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path(path)
        .max_age(Duration::seconds(max_age_secs as i64))
        .finish()
}

/// The authorization endpoint at the deployment root — the bare cookie's path.
const AUTHORIZE_PATH: &str = axiam_oauth2::login_hop::AUTHORIZE_PATH;

/// **Every path a sign-in into `tenant_id` mints the OP-session cookie at**
/// (T23.1.8, D-11). The one list: every setter and every remover is built from
/// it, so a path cannot be minted without also being cleared.
///
/// - `/oauth2/authorize` — the deployment-wide issuer's authorization endpoint,
///   always. Unchanged by D-11.
/// - `/t/{tenant_id}/oauth2/authorize` — the T21.6 per-tenant issuer's, only
///   where the deployment serves per-tenant paths
///   (`AuthConfig::tenant_issuer_paths`), and only for **the session's own
///   tenant**. A browser signed in to tenant A holds no cookie scoped to any
///   other tenant, so a request to `/t/B/oauth2/authorize` carries nothing it
///   could be resolved from.
///
/// - `/saml/v2/{tenant_id}/sso` — the tenant's SAML 2.0 IdP SSO endpoint (G-2,
///   T23.2.3), for the session's own tenant, **always**: it is not gated on
///   `tenant_issuer_paths` (the SAML routes are per-tenant paths by design), on
///   the `saml` build feature, or on the tenant's `saml_idp_enabled` setting.
///   A sign-in cannot know cheaply whether the tenant serves SAML, and a cookie
///   scoped to a path that answers `404` is read by nothing; minting it the same
///   way in every build is also what keeps a build without SAML
///   indistinguishable from a tenant with SAML off (D-20). The path covers the
///   endpoint's three sub-paths, `/continue` (the login hop's return leg),
///   `/idp-initiated` and `/logout` (the IdP-initiated logout trigger, T23.2.4,
///   D-39 — it sits **under** this path precisely so the cookie reaches it, as
///   `/oauth2/authorize/logout` sits under the authorization endpoint), and
///   nothing else. **No new path was minted for logout**: `/slo`, the endpoint
///   that receives a service provider's `LogoutRequest`, is deliberately *not*
///   under it (a cross-site POST would not carry a `Lax` cookie there anyway, and
///   a fourth path would widen this layout), so it never sees the cookie and
///   never decides anything by it.
///
/// # Why one name for every path
///
/// A browser keys cookies by name, domain **and path** (RFC 6265 §5.3 step 11),
/// so several `axiam_op_session` cookies with different paths coexist, and a
/// request carries the ones whose path is a prefix of its own (§5.1.4). The
/// paths here are pairwise disjoint in that sense — `/oauth2/authorize` is not
/// a prefix of `/t/{uuid}/oauth2/authorize`, nor the reverse, nor one tenant's
/// of another's — so **no request ever carries two of them**, and the one
/// resolution path that reads `COOKIE_OP_SESSION` serves the bare endpoint and
/// every tenant endpoint unchanged. A distinct name per path would buy nothing
/// a path does not already give, and would make the resolver choose a name by
/// route — a second place the route-to-cookie mapping could drift.
///
/// # Why one value
///
/// Every path carries the **same** value, so every cookie names the same
/// session row through the one `browser_token_hash` it already stores — no
/// schema change, and revoking the row ends every copy at once. What keeps a
/// copy from being used in the wrong tenant is not its path (a path is a
/// browser courtesy, and a cookie value can be replayed anywhere) but the
/// resolver's tenant-keyed lookup: a digest is looked up in the tenant the
/// request names, and a session in tenant A is not there when the request
/// names tenant B.
///
/// # The path is the canonical one
///
/// The tenant segment is written as `Uuid`'s hyphenated lower-case form, which
/// is what [`axiam_oauth2::login_hop::tenant_authorize_path`] builds and so
/// what every `return_to` and every discovery document names. The `/t/` scope
/// also routes the other spellings `Uuid::parse_str` accepts (upper case,
/// unhyphenated); a browser that requests one of those carries no cookie,
/// because cookie paths match case-sensitively and byte for byte, and fails
/// closed as `login_required`. Nothing a server builds sends it there.
#[must_use]
pub fn op_session_cookie_paths(tenant_id: Uuid, config: &AuthConfig) -> Vec<String> {
    let mut paths = vec![AUTHORIZE_PATH.to_owned()];
    if config.tenant_issuer_paths {
        paths.push(axiam_oauth2::login_hop::tenant_authorize_path(tenant_id));
    }
    paths.push(axiam_oauth2::login_hop::saml_sso_path(tenant_id));
    paths
}

/// The OP-session cookies a completed sign-in into `tenant_id` sets: one per
/// path in [`op_session_cookie_paths`], every one carrying `token` and
/// `max_age_secs` (T23.1.8, D-11).
///
/// The bare-path cookie comes first, so a reader that takes the first
/// `axiam_op_session` it finds sees exactly the cookie it saw before D-11.
#[must_use]
pub fn op_session_cookies(
    token: &str,
    max_age_secs: u64,
    tenant_id: Uuid,
    config: &AuthConfig,
) -> Vec<Cookie<'static>> {
    op_session_cookie_paths(tenant_id, config)
        .into_iter()
        .map(|path| op_session_cookie_at(token, max_age_secs, path))
        .collect()
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

/// Clear the `axiam_op_session` cookie (W3).
///
/// Built from [`op_session_cookie`], so it mirrors its attributes — including
/// the `/oauth2/authorize` path scope, without which the removal would not
/// match the cookie and a logged-out browser would keep presenting an OP
/// session at the authorization endpoint — and including its unconditional
/// `Secure`, without which the removal could not overwrite it at all
/// ("Leave Secure Cookies Alone").
pub fn clear_op_session_cookie() -> Cookie<'static> {
    clear_op_session_cookie_at(AUTHORIZE_PATH.to_owned())
}

/// Clear the OP-session cookie at one path, built from
/// [`op_session_cookie_at`] so it mirrors the setter's attributes at that path.
fn clear_op_session_cookie_at(path: String) -> Cookie<'static> {
    let mut c = op_session_cookie_at("", 0, path);
    c.make_removal();
    c
}

/// Clear **every** OP-session cookie a sign-in into `tenant_id` set
/// (T23.1.8, D-11): one removal per path in [`op_session_cookie_paths`], each
/// built from the setter at that path, so the list that minted them is the list
/// that clears them.
///
/// With `AuthConfig::tenant_issuer_paths` off this is exactly
/// `[clear_op_session_cookie()]`. A per-tenant cookie minted while the flag was
/// on and left behind after an operator turned it off is not cleared — it is
/// scoped to a path that is then not mounted, so no request reaches anything
/// that reads it, and the session it names is revoked by the same logout
/// regardless.
#[must_use]
pub fn clear_op_session_cookies(tenant_id: Uuid, config: &AuthConfig) -> Vec<Cookie<'static>> {
    op_session_cookie_paths(tenant_id, config)
        .into_iter()
        .map(clear_op_session_cookie_at)
        .collect()
}

/// The removal for the one OP-session cookie the request in hand could have
/// carried: the per-tenant one on a `/t/{tenant_id}/…` request, the bare one
/// otherwise (T23.1.8).
///
/// For a handler that has just found the presented cookie stale. It clears the
/// copy that proved stale and nothing else: the other paths may carry a value
/// minted by a later sign-in into another tenant, which is still good there.
#[must_use]
pub fn clear_presented_op_session_cookie(tenant_path: Option<Uuid>) -> Cookie<'static> {
    match tenant_path {
        None => clear_op_session_cookie(),
        Some(tenant_id) => {
            clear_op_session_cookie_at(axiam_oauth2::login_hop::tenant_authorize_path(tenant_id))
        }
    }
}

/// The removal for the OP-session copy a request under the tenant's SAML SSO
/// path carried (T23.2.3): the `/saml/v2/{tenant_id}/sso` copy and nothing else,
/// for the reason [`clear_presented_op_session_cookie`] gives.
#[must_use]
pub fn clear_presented_saml_op_session_cookie(tenant_id: Uuid) -> Cookie<'static> {
    clear_op_session_cookie_at(axiam_oauth2::login_hop::saml_sso_path(tenant_id))
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

        let c = op_session_cookie("tok", 86400);
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

        // `axiam_op_session` is deliberately absent from this list: it does
        // not take `cookie_secure` at all. See the next test.
    }

    /// The OP browser-session cookie does **not** follow `cookie_secure` down.
    /// It is the one `SameSite=Lax` cookie here — the one a browser sends on a
    /// cross-site top-level navigation — and the endpoint it is scoped to is
    /// required to be TLS-protected anyway (RFC 6749 §3.1). Loopback dev is
    /// unaffected: browsers store `Secure` cookies set from `http://localhost`.
    #[test]
    fn the_op_session_cookie_is_secure_whatever_the_deployment_flag_says() {
        assert!(
            op_session_cookie("tok", 86400).secure().unwrap_or(false),
            "the OP session cookie must be Secure unconditionally"
        );
        assert!(
            clear_op_session_cookie().secure().unwrap_or(false),
            "and so must its removal, or it cannot overwrite the cookie"
        );
    }

    /// **T0.6** — the OP browser-session cookie's attributes, pinned one by
    /// one, because every one of them is doing a job:
    ///
    /// - `SameSite=Lax` is what defeats iframe probing and what makes the
    ///   cross-site RP redirect work at all. Plan §9 records that the price is
    ///   hidden-iframe silent renew, which fails closed. A future change to
    ///   `None` would buy that pattern back and sell the probe with it.
    /// - `Path=/oauth2/authorize` is what bounds a stolen cookie to producing
    ///   authorization codes for registered clients rather than API calls.
    /// - `HttpOnly` keeps it out of script.
    /// - `Max-Age` is the session's, not the access token's: it names the same
    ///   thing the session row does.
    #[test]
    fn t0_6_the_op_session_cookie_attributes_are_pinned() {
        let c = op_session_cookie("browser-token", 86_400);
        assert_eq!(c.name(), "axiam_op_session");
        assert_eq!(
            c.same_site(),
            Some(SameSite::Lax),
            "Lax is deliberate: it is sent on a top-level navigation and not \
             inside a frame. Do not 'fix' this to None — see plan §9."
        );
        assert_eq!(
            c.path(),
            Some("/oauth2/authorize"),
            "the cookie must reach exactly one endpoint"
        );
        assert!(
            c.http_only().unwrap_or(false),
            "must not be script-readable"
        );
        assert!(c.secure().unwrap_or(false));
        assert_eq!(c.max_age(), Some(Duration::seconds(86_400)));
    }

    /// The other three cookies are unchanged by W3. Pinned here because the
    /// argument for a *second* cookie is that the first three keep the threat
    /// model SEC-046 gave them — and an edit that relaxed `axiam_access` to
    /// `Lax` would make this wave's cookie pointless and its predecessor
    /// weaker.
    #[test]
    fn the_api_cookies_are_still_strict_and_unscoped_by_the_op_session_cookie() {
        assert_eq!(
            access_cookie("tok", 900, true).same_site(),
            Some(SameSite::Strict)
        );
        assert_eq!(
            refresh_cookie("tok", 86_400, true).same_site(),
            Some(SameSite::Strict)
        );
        assert_eq!(
            csrf_cookie("tok", 900, true).same_site(),
            Some(SameSite::Strict)
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
                (op_session_cookie("tok", 86400), clear_op_session_cookie()),
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

    // -----------------------------------------------------------------------
    // T23.1.8 / D-11 — the per-tenant copies of the OP-session cookie
    // -----------------------------------------------------------------------

    const TENANT_A: &str = "11111111-2222-3333-4444-555555555555";
    const TENANT_B: &str = "66666666-7777-8888-9999-aaaaaaaaaaaa";

    fn tenant(id: &str) -> Uuid {
        Uuid::parse_str(id).unwrap()
    }

    fn deployment(tenant_issuer_paths: bool) -> AuthConfig {
        AuthConfig {
            tenant_issuer_paths,
            ..AuthConfig::default()
        }
    }

    /// **The list, pinned.** Every setter and every remover is built from
    /// `op_session_cookie_paths`, so this is the whole of where the cookie can
    /// exist. T23.2.3 added the SAML SSO path here and nowhere else — and
    /// changed this test in the same commit, which is the point of it.
    #[test]
    fn d11_the_op_session_cookie_paths_are_pinned() {
        assert_eq!(
            op_session_cookie_paths(tenant(TENANT_A), &deployment(true)),
            vec![
                "/oauth2/authorize".to_owned(),
                format!("/t/{TENANT_A}/oauth2/authorize"),
                format!("/saml/v2/{TENANT_A}/sso"),
            ],
        );
        // A deployment that does not serve per-tenant OAuth2 paths mints no
        // `/t/` copy; the SAML SSO copy (T23.2.3) is not gated on that flag.
        assert_eq!(
            op_session_cookie_paths(tenant(TENANT_A), &deployment(false)),
            vec![
                "/oauth2/authorize".to_owned(),
                format!("/saml/v2/{TENANT_A}/sso"),
            ],
        );
    }

    /// A sign-in into tenant A is given no cookie scoped to any other tenant.
    #[test]
    fn d11_a_sign_in_into_one_tenant_mints_no_cookie_for_another() {
        for c in op_session_cookies("tok", 86_400, tenant(TENANT_A), &deployment(true)) {
            let path = c.path().unwrap_or_default();
            assert!(
                !path.contains(TENANT_B),
                "a tenant-A sign-in must not be scoped to tenant B: {path}"
            );
            assert!(
                path == "/oauth2/authorize"
                    || path.starts_with(&format!("/t/{TENANT_A}/"))
                    || path.starts_with(&format!("/saml/v2/{TENANT_A}/")),
                "every path is the bare one or tenant A's own: {path}"
            );
        }
    }

    /// The per-tenant copy is the bare cookie with another `Path` — the same
    /// name, value, `HttpOnly`, `Secure`, `SameSite=Lax` and `Max-Age` — and
    /// the bare copy comes first and is byte-identical to `op_session_cookie`.
    #[test]
    fn d11_every_copy_differs_from_the_bare_cookie_in_path_alone() {
        let set = op_session_cookies("tok", 86_400, tenant(TENANT_A), &deployment(true));
        assert_eq!(set.len(), 3);
        let bare = op_session_cookie("tok", 86_400);
        assert_eq!(
            set[0].to_string(),
            bare.to_string(),
            "the bare copy comes first and is unchanged by D-11"
        );
        for c in &set {
            assert_eq!(c.name(), bare.name());
            assert!(
                c.value() == bare.value(),
                "every copy names the same session"
            );
            assert_eq!(c.http_only(), bare.http_only());
            assert_eq!(c.secure(), bare.secure());
            assert_eq!(c.same_site(), bare.same_site());
            assert_eq!(c.max_age(), bare.max_age());
            assert_eq!(c.domain(), bare.domain(), "host-only, as the bare cookie");
        }
        assert_eq!(
            set[1].path(),
            Some(format!("/t/{TENANT_A}/oauth2/authorize").as_str())
        );
        assert_eq!(
            set[2].path(),
            Some(format!("/saml/v2/{TENANT_A}/sso").as_str())
        );
    }

    /// No request carries two copies: the paths are pairwise disjoint under
    /// RFC 6265 §5.1.4 path-match, which is what lets one resolver read one
    /// cookie name on every route.
    #[test]
    fn d11_no_request_path_matches_two_copies() {
        // §5.1.4: the cookie path is a prefix of the request path, and either
        // they are equal, the cookie path ends in `/`, or the next request
        // character is `/`.
        fn path_matches(request: &str, cookie: &str) -> bool {
            request == cookie
                || (request.starts_with(cookie)
                    && (cookie.ends_with('/') || request[cookie.len()..].starts_with('/')))
        }
        let mut paths = op_session_cookie_paths(tenant(TENANT_A), &deployment(true));
        paths.extend(op_session_cookie_paths(tenant(TENANT_B), &deployment(true)));
        paths.sort();
        paths.dedup();
        for request in [
            "/oauth2/authorize".to_owned(),
            "/oauth2/authorize/logout".to_owned(),
            format!("/t/{TENANT_A}/oauth2/authorize"),
            format!("/t/{TENANT_A}/oauth2/authorize/logout"),
            format!("/t/{TENANT_B}/oauth2/authorize"),
            format!("/saml/v2/{TENANT_A}/sso"),
            format!("/saml/v2/{TENANT_A}/sso/continue"),
            format!("/saml/v2/{TENANT_A}/sso/idp-initiated"),
            // T23.2.4: the IdP-initiated logout trigger is under the SSO path, so
            // the same one copy reaches it and no path was added.
            format!("/saml/v2/{TENANT_A}/sso/logout"),
            format!("/saml/v2/{TENANT_B}/sso/continue"),
        ] {
            let carried = paths.iter().filter(|p| path_matches(&request, p)).count();
            assert_eq!(carried, 1, "{request} must carry exactly one copy");
        }
        for request in [
            "/oauth2/end_session".to_owned(),
            format!("/t/{TENANT_A}/oauth2/end_session"),
            format!("/t/{TENANT_A}/oauth2/token"),
            "/api/v1/auth/me".to_owned(),
            // T23.2.3: the SAML copy reaches the SSO endpoint and its
            // sub-paths only — not the metadata or SLO endpoints (the SLO endpoint
            // never reads the cookie, T23.2.4), not a path that merely starts the
            // same way.
            format!("/saml/v2/{TENANT_A}/metadata"),
            format!("/saml/v2/{TENANT_A}/slo"),
            format!("/saml/v2/{TENANT_A}/ssox"),
            format!("/saml/v2/{TENANT_A}"),
        ] {
            assert!(
                paths.iter().all(|p| !path_matches(&request, p)),
                "{request} must carry no copy at all"
            );
        }
    }

    /// Every removal is built from its own setter: one per minted path, the
    /// same attributes at the same path, and still an expiring removal.
    #[test]
    fn d11_the_removals_mirror_every_copy_the_sign_in_minted() {
        for flag in [true, false] {
            let config = deployment(flag);
            let set = op_session_cookies("tok", 86_400, tenant(TENANT_A), &config);
            let clear = clear_op_session_cookies(tenant(TENANT_A), &config);
            assert_eq!(clear.len(), set.len(), "one removal per minted copy");
            for (s, c) in set.iter().zip(&clear) {
                assert_eq!(c.name(), s.name());
                assert_eq!(c.path(), s.path());
                assert_eq!(c.http_only(), s.http_only());
                assert_eq!(c.secure(), s.secure());
                assert_eq!(c.same_site(), s.same_site());
                assert_eq!(c.value(), "");
                assert_eq!(c.max_age(), Some(Duration::seconds(0)));
            }
        }
        assert_eq!(
            clear_op_session_cookies(tenant(TENANT_A), &deployment(false))[0].to_string(),
            clear_op_session_cookie().to_string(),
            "with per-tenant paths off, the removal is exactly the pre-D-11 one"
        );
    }

    /// The stale-cookie removal targets the copy the request could carry.
    #[test]
    fn d11_the_presented_copy_removal_follows_the_request_path() {
        assert_eq!(
            clear_presented_op_session_cookie(None).to_string(),
            clear_op_session_cookie().to_string()
        );
        let on_tenant = clear_presented_op_session_cookie(Some(tenant(TENANT_A)));
        assert_eq!(
            on_tenant.path(),
            Some(format!("/t/{TENANT_A}/oauth2/authorize").as_str())
        );
        assert_eq!(on_tenant.same_site(), Some(SameSite::Lax));
        assert!(on_tenant.secure().unwrap_or(false));
        assert!(on_tenant.http_only().unwrap_or(false));
        assert_eq!(on_tenant.max_age(), Some(Duration::seconds(0)));

        // T23.2.3 — the SAML copy's removal, built from the same setter.
        let on_saml = clear_presented_saml_op_session_cookie(tenant(TENANT_A));
        assert_eq!(
            on_saml.path(),
            Some(format!("/saml/v2/{TENANT_A}/sso").as_str())
        );
        assert_eq!(on_saml.same_site(), Some(SameSite::Lax));
        assert!(on_saml.secure().unwrap_or(false));
        assert!(on_saml.http_only().unwrap_or(false));
        assert_eq!(on_saml.max_age(), Some(Duration::seconds(0)));
    }

    /// `make_removal` is what actually expires the cookie; the attribute
    /// mirroring above must not have displaced it.
    #[test]
    fn removal_cookies_are_still_expiring_removals() {
        for c in [
            clear_access_cookie(true),
            clear_refresh_cookie(true),
            clear_csrf_cookie(true),
            clear_op_session_cookie(),
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

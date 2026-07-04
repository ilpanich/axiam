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

/// Normalizes `path` for the public-path allowlist check (SECHRD-11 / T-24-11).
///
/// - Collapses repeated `/` into a single `/`.
/// - Rejects (returns `None`) any path with a literal `..` path segment.
///
/// This function performs **no** rewriting/canonicalization for routing
/// purposes — it exists solely to produce a fail-closed input to
/// [`is_public_path`]. A `None` result must always translate to "not
/// public" (deny → falls through to the normal credential check), never an
/// implicit allow.
fn normalize_for_public_check(path: &str) -> Option<String> {
    // Reject any `..` segment outright (path-traversal attempt). A plain
    // per-segment comparison is sufficient here because the only decision
    // this function feeds is a boolean allow/deny, not a rewritten path
    // used for filesystem or routing access.
    if path.split('/').any(|segment| segment == "..") {
        return None;
    }

    // Collapse repeated slashes (`//` -> `/`) without altering leading or
    // trailing slash semantics.
    let mut normalized = String::with_capacity(path.len());
    let mut prev_was_slash = false;
    for c in path.chars() {
        if c == '/' {
            if prev_was_slash {
                continue;
            }
            prev_was_slash = true;
        } else {
            prev_was_slash = false;
        }
        normalized.push(c);
    }
    Some(normalized)
}

/// Returns `true` if `path` matches one of `entries` under the
/// segment-boundary-aware allowlist rule.
///
/// Matching rules:
/// - `path` is first normalized (see [`normalize_for_public_check`]); a
///   normalization failure (a `..` segment present) fails closed — this
///   function returns `false`, never an implicit allow.
/// - Entries ending with `*` are **segment-boundary prefix-matched**: the
///   trailing `*` (and any single `/` immediately before it) is stripped to
///   form the prefix, and a match requires the remainder of `path` after
///   that prefix to be either empty or to begin with `/`. This prevents
///   prefix confusion (e.g. an `/api/v1/auth/*` entry must NOT match
///   `/api/v1/authz/...`).
/// - All other entries are compared with `==` (exact match, against the
///   normalized path).
///
/// Extracted from [`is_public_path`] so tests can prove the matching
/// property against a synthetic allowlist (Pitfall 6: the live
/// [`PUBLIC_PATHS`] registry has no adjacent-prefix wildcard pair to
/// exploit today) while exercising the exact same code path production
/// traffic runs through.
fn matches_public_allowlist(path: &str, entries: &[&str]) -> bool {
    let Some(path) = normalize_for_public_check(path) else {
        // Ambiguous/non-canonical path — fail closed, never public.
        return false;
    };
    let path = path.as_str();

    for &entry in entries {
        if let Some(prefix) = entry.strip_suffix('*') {
            let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
            if let Some(remainder) = path.strip_prefix(prefix)
                && (remainder.is_empty() || remainder.starts_with('/'))
            {
                return true;
            }
        } else if path == entry {
            return true;
        }
    }
    false
}

/// Returns `true` if `path` is in the public-path allowlist and should be
/// allowed through without credential validation.
///
/// See [`matches_public_allowlist`] for the matching rules.
pub fn is_public_path(path: &str) -> bool {
    matches_public_allowlist(path, PUBLIC_PATHS)
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
    use super::{is_public_path, matches_public_allowlist};

    #[test]
    fn public_paths_are_recognized() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/api/v1/auth/login"));
        // Refresh authenticates via its own opaque cookie and must bypass the
        // access-token credential check (the access cookie is gone post-expiry).
        assert!(is_public_path("/api/v1/auth/refresh"));
        assert!(is_public_path("/.well-known/openid-configuration"));
        assert!(is_public_path("/oauth2/token"));
        assert!(is_public_path("/api/docs/openapi.json")); // prefix match via /api/docs/*
        assert!(is_public_path("/api/v1/admin/bootstrap"));
    }

    #[test]
    fn first_time_sso_paths_are_public() {
        // Phase 4 D-22 — unauthenticated first-time SSO endpoints must be
        // reachable without a JWT.
        assert!(is_public_path("/api/v1/auth/federation/oidc/start"));
        assert!(is_public_path("/api/v1/auth/federation/oidc/callback"));
        assert!(is_public_path("/api/v1/auth/federation/saml/login"));
        assert!(is_public_path("/api/v1/auth/federation/saml/acs"));
    }

    #[test]
    fn protected_paths_are_not_public() {
        assert!(!is_public_path("/api/v1/users"));
        assert!(!is_public_path("/api/v1/roles"));
        assert!(!is_public_path("/api/v1/permissions"));
        assert!(!is_public_path("/api/v1/settings"));
    }

    // -----------------------------------------------------------------
    // SECHRD-11 / T-24-11 / T-24-12 — segment-boundary + normalization
    // -----------------------------------------------------------------
    //
    // These tests assert properties of `is_public_path` / `normalize_for_
    // public_check` directly, using a synthetic wildcard entry, per
    // RESEARCH.md Pitfall 6: today's real `PUBLIC_PATHS` has only one
    // wildcard entry (`/api/docs/*`) with no adjacent-prefix collision to
    // exploit, so the property must be proven against the matching
    // function itself, not the live registry.

    #[test]
    fn wildcard_prefix_confusion_is_rejected() {
        // A `/api/v1/auth/*`-style entry must require a segment boundary:
        // `/api/v1/authz/...` shares the literal character prefix
        // "/api/v1/auth" but is a DIFFERENT path segment ("authz", not
        // "auth"), and must never be classified public by that entry.
        //
        // Calls `matches_public_allowlist` (the exact code `is_public_path`
        // delegates to) against a synthetic allowlist, per Pitfall 6: the
        // live PUBLIC_PATHS registry has no adjacent-prefix wildcard pair
        // to exploit today, so this proves the property of the matching
        // function itself, not of the current registry contents.
        const SYNTHETIC_PUBLIC_PATHS: &[&str] = &["/api/v1/auth/*"];
        assert!(!matches_public_allowlist(
            "/api/v1/authz/check",
            SYNTHETIC_PUBLIC_PATHS
        ));
        assert!(!matches_public_allowlist(
            "/api/v1/authzzz",
            SYNTHETIC_PUBLIC_PATHS
        ));
        // But the legitimate child path under the wildcard must still match.
        assert!(matches_public_allowlist(
            "/api/v1/auth/login",
            SYNTHETIC_PUBLIC_PATHS
        ));
        // And the bare prefix itself (no trailing segment) must match too.
        assert!(matches_public_allowlist(
            "/api/v1/auth",
            SYNTHETIC_PUBLIC_PATHS
        ));
    }

    #[test]
    fn real_wildcard_entry_still_matches_legitimate_paths() {
        // /api/docs/* is the one real wildcard entry today (Pitfall 6) —
        // confirm the hardened matcher doesn't regress it.
        assert!(is_public_path("/api/docs/openapi.json"));
        assert!(is_public_path("/api/docs/"));
        assert!(is_public_path("/api/docs"));
        // A sibling path that merely shares the "/api/doc" character
        // prefix must NOT match.
        assert!(!is_public_path("/api/documents/secret"));
    }

    #[test]
    fn double_slash_is_collapsed_before_matching() {
        // "//" must be collapsed to "/" before the allowlist check so an
        // attacker cannot dodge an exact-match entry with a non-canonical
        // path, nor smuggle a false negative/positive via slash-doubling.
        assert!(is_public_path("/api/v1/auth//login"));
        assert!(is_public_path("//health"));
        assert!(!is_public_path("//api//v1//users"));
    }

    #[test]
    fn dot_dot_segment_is_rejected_fail_closed() {
        // Any path containing a literal `..` segment must be denied
        // outright (fail-closed), never resolved/canonicalized into an
        // implicit allow.
        assert!(!is_public_path("/api/docs/../v1/users"));
        assert!(!is_public_path("/api/v1/auth/../../v1/users"));
        assert!(!is_public_path("/.."));
        // A segment that merely CONTAINS ".." as a substring (not an exact
        // ".." segment) is not path traversal and must not be penalized.
        assert!(is_public_path("/api/v1/auth/login"));
    }

    #[test]
    fn exact_match_entry_still_matches_canonical_path() {
        assert!(is_public_path("/health"));
        assert!(is_public_path("/api/v1/auth/login"));
        assert!(!is_public_path("/health/"));
    }
}

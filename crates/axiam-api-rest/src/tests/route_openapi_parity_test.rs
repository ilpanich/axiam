//! Route ↔ OpenAPI parity test (D-15).
//!
//! Guarantees bi-directional consistency between the live route surface
//! (expressed as `ROUTE_PERMISSION_MAP` + `PUBLIC_PATHS`) and the OpenAPI
//! specification returned by `api_doc()`.
//!
//! **Test A** — every protected route in `ROUTE_PERMISSION_MAP` has a matching
//! path in the OpenAPI spec.  Failure means a route is implemented but not
//! documented — clients will miss it.
//!
//! **Test B** — every path in the OpenAPI spec is either:
//!   a) a protected route in `ROUTE_PERMISSION_MAP`,
//!   b) an explicit public path in `PUBLIC_PATHS`, or
//!   c) a "JWT-authenticated, no discrete permission" path (self-service
//!      endpoints like `/api/v1/auth/me` that are guarded by the session
//!      extractor rather than the permission authz layer).
//!
//! Failure means a documented path has no access-control annotation —
//! a potential phantom or undocumented endpoint.

use crate::openapi::api_doc;
use crate::permissions::{PUBLIC_PATHS, ROUTE_PERMISSION_MAP};
use std::collections::HashSet;

/// Paths that appear in the OpenAPI spec and ARE authenticated (JWT-required)
/// but do NOT require a specific named permission.  These are self-service
/// endpoints enforced by the `AuthenticatedUser` extractor rather than by
/// `ROUTE_PERMISSION_MAP`.  They are neither public nor permission-gated, so
/// they form a third category in the bi-directional parity check (Test B).
///
/// When adding a new authenticated, no-permission endpoint to the OpenAPI spec
/// (`openapi.rs` `paths()`), also add its path here if it is not already
/// covered by `ROUTE_PERMISSION_MAP` or `PUBLIC_PATHS`.
const AUTHENTICATED_SELF_SERVICE_PATHS: &[&str] = &[
    // Auth — session-guarded but no discrete permission needed
    "/api/v1/auth/logout",
    "/api/v1/auth/me",
    "/api/v1/auth/mfa/enroll",
    "/api/v1/auth/mfa/confirm",
    "/api/v1/auth/password/change",
    // Federation OIDC account-linking (authenticated user, no role permission)
    "/api/v1/federation/oidc/authorize",
    // Federation SAML SP-initiated AuthnRequest (authenticated user, no role
    // permission). Only present in the OpenAPI spec when the `saml` feature is
    // compiled; listing it unconditionally is harmless (no reverse openapi
    // membership check) and mirrors the SAML entries in PUBLIC_PATHS.
    "/api/v1/federation/saml/authn-request",
    // Authz check — JWT-authenticated; authz:check_as check is conditional
    // inside the handler (not a route-level gate), so these paths are not
    // in ROUTE_PERMISSION_MAP (see PATTERNS.md Pitfall 4).
    "/api/v1/authz/check",
    "/api/v1/authz/check/batch",
];

/// Returns true if `openapi_path` is covered by any `PUBLIC_PATHS` entry.
///
/// Entries ending with `*` are prefix-matched after stripping the `*`.
/// All other entries are compared by exact equality.
fn is_public(openapi_path: &str) -> bool {
    for &p in PUBLIC_PATHS {
        if let Some(prefix) = p.strip_suffix('*') {
            if openapi_path.starts_with(prefix) {
                return true;
            }
        } else if openapi_path == p {
            return true;
        }
    }
    false
}

/// **Test A:** Every path in `ROUTE_PERMISSION_MAP` must have a matching key
/// in the OpenAPI spec.
///
/// Path templates use `{param}` placeholders in both sources, so comparison
/// is exact.  If this test fails, a route was added to `permissions.rs` but
/// its `#[utoipa::path]` annotation is missing or uses a different template.
#[test]
fn every_authed_route_is_in_openapi() {
    let spec = api_doc();
    let openapi_paths: HashSet<String> = spec.paths.paths.keys().cloned().collect();

    let missing: Vec<_> = ROUTE_PERMISSION_MAP
        .iter()
        .filter(|(_, path, _)| !openapi_paths.contains(*path))
        .collect();

    assert!(
        missing.is_empty(),
        "Routes in ROUTE_PERMISSION_MAP are missing from the OpenAPI spec.\n\
         Add a `#[utoipa::path]` annotation (or fix the path template) for:\n\
         {missing:#?}"
    );
}

/// **Test B:** Every path in the OpenAPI spec must be accounted for — either
/// as a protected route, a public path, or a known self-service endpoint.
///
/// If this test fails, a path was added to the OpenAPI `paths()` list without
/// a corresponding entry in `ROUTE_PERMISSION_MAP`, `PUBLIC_PATHS`, or
/// `AUTHENTICATED_SELF_SERVICE_PATHS`.  Add the missing entry to whichever
/// constant is appropriate for the endpoint's access-control model.
#[test]
fn every_openapi_path_is_registered() {
    let spec = api_doc();

    let authed: HashSet<&str> = ROUTE_PERMISSION_MAP.iter().map(|(_, p, _)| *p).collect();
    let self_service: HashSet<&str> = AUTHENTICATED_SELF_SERVICE_PATHS.iter().copied().collect();

    let missing: Vec<_> = spec
        .paths
        .paths
        .keys()
        .filter(|p| {
            !authed.contains(p.as_str()) && !is_public(p) && !self_service.contains(p.as_str())
        })
        .collect();

    assert!(
        missing.is_empty(),
        "OpenAPI paths are not in ROUTE_PERMISSION_MAP, PUBLIC_PATHS, or \
         AUTHENTICATED_SELF_SERVICE_PATHS.\n\
         Register each path in the appropriate constant in `permissions.rs` \
         (or add to AUTHENTICATED_SELF_SERVICE_PATHS if it is JWT-authenticated \
         but requires no named permission):\n\
         {missing:#?}"
    );
}

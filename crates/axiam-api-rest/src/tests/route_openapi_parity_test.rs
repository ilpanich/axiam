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
    // Federation SAML SP metadata (authenticated user, no role permission).
    // Kept JWT-gated by the D-15 scope decision (Phase 28 FUNC-01): it was
    // removed from PUBLIC_PATHS because its handler requires AuthenticatedUser,
    // so it belongs here (JWT-authenticated, no named permission), same
    // saml-feature-conditional OpenAPI presence as authn-request above.
    "/api/v1/federation/saml/metadata",
    // Authz check — JWT-authenticated; authz:check_as check is conditional
    // inside the handler (not a route-level gate), so these paths are not
    // in ROUTE_PERMISSION_MAP (see PATTERNS.md Pitfall 4).
    "/api/v1/authz/check",
    "/api/v1/authz/check/batch",
    // Device Authorization Grant verification page (B2, RFC 8628 §3.3).
    // JWT-authenticated and deliberately *not* permission-gated: the endpoint
    // exists so a user can approve a device for themselves, and approval
    // records the authenticated caller as the subject the token is minted for.
    // A named permission would be the wrong gate — it would let an operator
    // grant "may approve devices" as a capability, when the only thing being
    // authorised here is the caller acting on their own behalf.
    "/api/v1/device/verify",
    "/api/v1/device/decide",
    // GDPR data-subject endpoints (D-12/D-13/D-07). Session-guarded by the
    // `AuthenticatedUser` extractor and deliberately not route-gated: acting on
    // your OWN account needs no permission, and the `gdpr:export` / `users:erase`
    // check fires inside the handler only when `user_id` names somebody else.
    // A route-level gate would be the wrong shape — it would make exporting your
    // own data a capability an operator has to grant. Same reasoning, and the
    // same category, as the authz-check entries above.
    //
    // The fourth GDPR path, `/api/v1/auth/account/delete/cancel`, is in
    // PUBLIC_PATHS instead: it is reached from an emailed single-use token by
    // someone whose account is already disabled.
    "/api/v1/account/export",
    "/api/v1/account/export/{token}",
    "/api/v1/account/delete",
    // UMA 2.0 Protection API (X2). Authenticated by the `ProtectionApiToken`
    // extractor — a client-credentials token carrying `uma_protection` — and
    // deliberately not permission-gated. The scope IS the gate: it is what an
    // operator grants to make a client a resource server, and a second named
    // permission on top would be a different answer to the same question.
    "/uma2/perm",
    // UMA 2.0 resource registration (FedAuthz §2.2), same PAT gate as
    // `/uma2/perm`. Not in ROUTE_PERMISSION_MAP for the same reason: the
    // `uma_protection` scope is the gate.
    "/uma2/rreg/resource_set",
    "/uma2/rreg/resource_set/{id}",
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

//! SCIM authorization: the dedicated `scim:provision` permission (B4).
//!
//! # Tenant scoping — the code path
//!
//! SCIM reuses `axiam-api-rest`'s [`AuthenticatedUser`] extractor unchanged:
//! every `/scim/v2/*` handler takes `user: AuthenticatedUser` exactly like a
//! native `/api/v1/users` handler does, and the middleware chain in front of
//! it (`AuthzMiddleware`, wired in `crate::routes`) is the same one every
//! other authenticated scope uses. `AuthenticatedUser::tenant_id` comes
//! **only** from the validated JWT's `tenant_id` claim — never from anything
//! in the SCIM request path or body. Every repository call this crate makes
//! (`UserRepository`/`GroupRepository`) takes that same `tenant_id` as an
//! explicit, mandatory parameter and every generated SurrealDB query filters
//! on it (see `axiam-db`'s `user.rs`/`group.rs`). A caller cannot name
//! another tenant's resources into existence in the query, and a token
//! minted for tenant A therefore cannot read or mutate tenant B's data
//! through this crate — not because SCIM adds a check, but because it never
//! introduces a second source of tenant identity for the check to miss.
//!
//! This is call-time enforcement (checked on every request), not a
//! provisioning-time assumption: even a handler bug that forgot to call
//! [`require_scim_provision`] would still be unable to cross tenants, because
//! the cross-tenant channel does not exist in the repository calls it would
//! make. `tests/contract_test.rs`'s tenant-isolation tests exercise exactly
//! this property adversarially (cross-tenant GET/PUT/PATCH/DELETE/list by
//! UUID, not merely "no token").
//!
//! # Principal — a note for operators (see `docs/api/scim-provisioning.md`)
//!
//! The bearer principal is deliberately whichever tenant-scoped AXIAM
//! identity holds `scim:provision` — in practice a dedicated tenant user
//! (e.g. `scim-provisioner`) created and role-granted through the existing
//! `/api/v1/users` + `/api/v1/roles` APIs, **not** a `service_account` row:
//! AXIAM's RBAC role-assignment edge (`has_role`) is hard-scoped to the
//! `user` table today (`axiam-db`'s `RoleRepository::assign_to_user`/
//! `get_user_role_assignments` both query `type::record('user', $id)`), so a
//! `service_account` subject cannot currently hold ANY RBAC permission,
//! `scim:provision` included. That gap predates this crate and is out of
//! R3.1's file scope (`axiam-db`, `axiam-authz`) to close; it is flagged
//! here, in the provisioning guide, and in this task's final report so a
//! follow-on (the planned SCIM token-management UI, or a dedicated fix) has
//! a precise pointer.
use axiam_api_rest::authz::{AuthzChecker, RequirePermission};
use axiam_api_rest::extractors::auth::AuthenticatedUser;
use uuid::Uuid;

use crate::error::ScimError;

/// The permission every `/scim/v2/*` route requires (B4: "a DEDICATED
/// `scim:provision` permission"). Declared here, and separately registered
/// in `axiam_api_rest::permissions::PERMISSION_REGISTRY` (the same array
/// every other AXIAM permission is declared in) so it is seeded per-tenant
/// exactly like `users:create`, `groups:list`, etc.
pub const SCIM_PROVISION_PERMISSION: &str = "scim:provision";

/// Enforce `scim:provision` for the calling principal, using the SAME
/// [`RequirePermission`] guard every native `/api/v1/*` handler uses. Not
/// resource-scoped (SCIM has no notion of an AXIAM `resource` hierarchy), so
/// the check runs against the global sentinel (`Uuid::nil()`), exactly like
/// `users:create`/`groups:create` do today.
pub async fn require_scim_provision(
    user: &AuthenticatedUser,
    authz: &dyn AuthzChecker,
) -> Result<(), ScimError> {
    RequirePermission::new(SCIM_PROVISION_PERMISSION, Uuid::nil())
        .check(user, authz)
        .await
        .map_err(ScimError::from)
}

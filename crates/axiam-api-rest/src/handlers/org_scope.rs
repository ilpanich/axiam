//! The scope guard for organization-level endpoints.
//!
//! # What this exists to stop
//!
//! Organization-level handlers used to authorize on two things: the caller
//! holds the permission, and the `org_id` in the path equals the caller's own
//! `org_id`. Both are necessary; together they are not sufficient, because
//! `user.org_id` is the organization the caller's *tenant* belongs to. It is
//! therefore satisfied by **every principal in the organization**, including a
//! tenant-level administrator.
//!
//! The seeded `super-admin` role of an ordinary tenant is granted the entire
//! permission registry — organization-level actions included
//! (`ca_certificates:generate`, `ca_certificates:manage`, `tenants:create`,
//! `organizations:create`, …). So the two guards, each reasonable on its own,
//! left a tenant administrator able to:
//!
//!   * mint an organization root CA,
//!   * flag it as an **mTLS trust anchor**, which is organization-wide,
//!   * create and delete tenants,
//!   * create organizations.
//!
//! The second is the serious one. An mTLS trust anchor decides what client
//! certificates authenticate against the whole deployment, and the tenant
//! administrator holds that CA's private key — so it could mint certificates
//! authenticating as principals in **sibling tenants**. That is the isolation
//! boundary the product is built on, crossed from inside.
//!
//! Meanwhile `scripts/e2e-bootstrap.sh` describes the intended reach in its own
//! words: a tenant administrator "administers all of `default` and nothing
//! outside it."
//!
//! # Why a scope check and not a new permission
//!
//! A permission can be granted to a tenant role by exactly the route that
//! created this gap — it is a value in a registry that tenant roles are seeded
//! from. Where a principal *lives* is not: it is the tenant its own record is
//! in, and a caller cannot move itself. Gating on the scope closes the hole
//! whatever a role happens to carry.
//!
//! The permission check stays. This is an additional condition, not a
//! replacement: an organization-level principal without
//! `ca_certificates:generate` still cannot mint a CA.

use surrealdb::Connection;

use crate::AuthenticatedUser;
use crate::error::AxiamApiError;
use crate::state::AppState;
use axiam_core::error::AxiamError;
use axiam_core::models::role::{TenantReach, tenant_reach_of};
use axiam_core::repository::{RoleRepository as _, TenantRepository as _};

/// Refuses a caller whose own record does not live in the organization's
/// reserved scope.
///
/// Resolved from the caller's `principal_tenant_id` — the tenant its record is
/// in, which is fixed by the token and never by request input. Deliberately not
/// `AuthenticatedUser::organization_level`: that flag is set only when a request
/// names *another* tenant via `X-Axiam-Tenant`, and an organization-level
/// principal acting on its own organization names none, so the flag is `false`
/// for exactly the calls this guards.
///
/// A tenant that cannot be resolved is refused rather than assumed ordinary:
/// failing closed is the only safe direction for an authorization guard, and a
/// principal whose own tenant has vanished has bigger problems.
pub async fn require_organization_principal<C: Connection + Clone>(
    user: &AuthenticatedUser,
    state: &AppState<C>,
) -> Result<(), AxiamApiError> {
    let deny = |reason: &str| -> AxiamApiError {
        AxiamApiError(AxiamError::AuthorizationDenied {
            reason: reason.to_string(),
            action: None,
            resource_id: None,
        })
    };

    let home = state
        .tenant_repo
        .get_by_id(user.principal_tenant_id)
        .await
        .map_err(|_| deny("the caller's own tenant could not be resolved"))?;

    if !home.is_organization_scope() {
        return Err(deny(
            "this action is organization-level; only a principal whose own record \
             lives in the organization scope may perform it",
        ));
    }

    // Living in the organization scope is necessary and, since tenant-scoped
    // assignments exist, no longer sufficient.
    //
    // An organization-level account whose roles name particular tenants was
    // created precisely so it would administer those and not the organization.
    // It lives in the organization tenant like every other organization-level
    // principal, so the residence test alone would still let it create tenants,
    // mint the organization's CA and flag mTLS trust anchors — each an act on
    // the organization as a whole, each reaching the tenants it was deliberately
    // kept out of.
    //
    // `axiam_authz` cannot close this: it refuses such a principal every
    // *tenant-scoped* action outside its reach by comparing the scope against
    // the tenant being acted on, and an organization-level action names no
    // tenant to compare against. This is the only place the comparison can be
    // made, so it is made here rather than at sixteen call sites that would
    // have to remember it.
    //
    // A handler that names a tenant of the organization — a tenant's signing CA,
    // say — wants [`require_organization_principal_for_tenant`] instead, which
    // asks whether the reach covers *that* tenant.
    if principal_tenant_reach(user, state).await?.is_restricted() {
        return Err(deny(
            "this action applies to the whole organization, and this account's \
             roles are restricted to particular tenants of it",
        ));
    }

    Ok(())
}

/// How far across the organization's tenants this caller's grants reach.
///
/// Read from the assignments in the tenant the caller *lives in* — the same
/// tenant `axiam_authz` reads them from, and never the one being acted on, so
/// that this answer and the engine's cannot disagree about what a principal may
/// do.
///
/// An ordinary tenant principal comes back as whatever its own assignments say,
/// which is almost always [`TenantReach::Unrestricted`]. That is correct and
/// uninteresting: it has exactly one tenant it can act on and `resolve_active_tenant`
/// is what enforces that. The answer carries information only for an
/// organization-level principal.
pub async fn principal_tenant_reach<C: Connection + Clone>(
    user: &AuthenticatedUser,
    state: &AppState<C>,
) -> Result<TenantReach, AxiamApiError> {
    let assignments = state
        .role_repo
        .get_user_role_assignments(user.principal_tenant_id, user.user_id)
        .await?;
    Ok(tenant_reach_of(&assignments))
}

/// The per-tenant form of [`require_organization_principal`], for an
/// organization-level endpoint that acts on **one named tenant** rather than on
/// the organization as a whole.
///
/// The tenant's signing CAs are the case: minting one is an organization-level
/// operation — the organization's CA signs it — but what it produces belongs to
/// a single tenant. An account restricted to that tenant is exactly who should
/// be doing it, and refusing them would make a tenant-scoped organization
/// administrator unable to administer the tenant it was created for.
///
/// So the reach must *cover the named tenant*, rather than be unrestricted.
pub async fn require_organization_principal_for_tenant<C: Connection + Clone>(
    user: &AuthenticatedUser,
    state: &AppState<C>,
    tenant_id: uuid::Uuid,
) -> Result<(), AxiamApiError> {
    let deny = |reason: &str| -> AxiamApiError {
        AxiamApiError(AxiamError::AuthorizationDenied {
            reason: reason.to_string(),
            action: None,
            resource_id: None,
        })
    };

    let home = state
        .tenant_repo
        .get_by_id(user.principal_tenant_id)
        .await
        .map_err(|_| deny("the caller's own tenant could not be resolved"))?;

    if !home.is_organization_scope() {
        return Err(deny(
            "this action is organization-level; only a principal whose own record \
             lives in the organization scope may perform it",
        ));
    }

    if !principal_tenant_reach(user, state)
        .await?
        .includes(tenant_id)
    {
        return Err(deny(
            "this account's roles do not reach the tenant this action names",
        ));
    }

    Ok(())
}

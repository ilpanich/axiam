//! Which permission actions act on the **organization** rather than on a
//! tenant.
//!
//! # Why this list exists
//!
//! AXIAM's tenants are isolation boundaries; an organization contains them.
//! A handful of actions operate on the organization itself — minting the CA
//! material every tenant's certificates chain to, deciding what may
//! authenticate against the whole deployment, creating and destroying the
//! tenants themselves. Those are not a tenant administrator's to perform, and
//! [`Tenant::is_organization_scope`](crate::models::tenant::Tenant::is_organization_scope)
//! is the property that says who may.
//!
//! Two independent layers enforce that, and this list is what keeps them
//! talking about the same set of actions:
//!
//! 1. **The scope guard** (`axiam-api-rest`'s `require_organization_principal`)
//!    refuses a caller whose own record does not live in the organization
//!    scope. It is the load-bearing half: it holds whatever permissions a role
//!    happens to carry, because where a principal lives is a row it cannot
//!    edit.
//! 2. **The seeder** (`axiam-db`'s `seed_default_roles` /
//!    `reconcile_default_role_grants`) withholds these actions from an ordinary
//!    tenant's seeded roles, so the grant is not there to be relied on in the
//!    first place.
//!
//! Layer 2 alone would be insufficient — a permission is a value in a registry,
//! and the very route that seeds roles could grant it again. Layer 1 alone was
//! what shipped, and it works; this list adds the second so the two agree
//! rather than one quietly contradicting the other.
//!
//! # Adding an action here
//!
//! Adding an action to this list **withholds it from every ordinary tenant's
//! seeded roles**, and `reconcile_default_role_grants` will revoke it from
//! tenants that already hold it. Add one only together with the
//! `require_organization_principal` guard on the handler it names — the two are
//! asserted to agree by `organization_level_actions_match_the_guarded_handlers`
//! in `axiam-api-rest`, which reads the handler sources rather than trusting
//! this comment.
//!
//! # What is deliberately *not* here
//!
//! `email_config:write` guards both `/organizations/{id}/email-config` and
//! `/tenants/{id}/email-config`. A tenant administrator configuring its own
//! tenant's mail is exactly the thing a tenant administrator should do, so the
//! action stays grantable and the organization half is protected by the scope
//! guard alone. An action shared between the two levels cannot be withheld
//! without taking the tenant-level capability with it.
//!
//! Read actions (`organizations:list`, `organizations:get`, `tenants:list`,
//! `ca_certificates:list`, …) are absent for the same reason they are absent
//! from the scope guard: the tenant switcher needs them and they leak nothing
//! across the boundary.

/// Every permission action that may only be exercised by an organization-level
/// principal.
///
/// Withheld from the seeded `super-admin` and `admin` roles of an ordinary
/// (`TenantKind::Standard`) tenant. The organization's own scope keeps them.
///
/// The `viewer` role is unaffected by construction: it is seeded only with
/// actions ending in `:list` or `:get`, and every action here is a mutation.
pub const ORGANIZATION_LEVEL_ACTIONS: &[&str] = &[
    // The organization itself. `POST /api/v1/organizations` has no
    // organization in its path to bind against at all, which is why the scope
    // of the *caller* is the only thing that can gate it.
    "organizations:create",
    "organizations:update",
    "organizations:delete",
    // The tenants an organization contains. A tenant administrator creating
    // sibling tenants — or deleting one — is acting outside its own boundary
    // by definition.
    "tenants:create",
    "tenants:update",
    "tenants:delete",
    // Organization CA material. `ca_certificates:manage` covers the mTLS
    // trust-anchor flag, which decides what client certificates authenticate
    // against the entire deployment; a tenant administrator holding both that
    // flag and the CA's private key could mint certificates authenticating as
    // principals in sibling tenants. This is the row that made B-04 a
    // high-severity finding rather than an untidiness.
    "ca_certificates:generate",
    "ca_certificates:revoke",
    "ca_certificates:manage",
];

/// Whether `action` may only be exercised by an organization-level principal.
///
/// A linear scan over a list this short is cheaper than any structure that
/// would need building first, and the seeder calls it once per permission per
/// tenant at startup.
pub fn is_organization_level_action(action: &str) -> bool {
    ORGANIZATION_LEVEL_ACTIONS.contains(&action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_holds_no_read_action() {
        // The `viewer` role is seeded with `:list`/`:get` actions and is
        // deliberately not filtered against this list. If a read action ever
        // lands here, viewer would silently keep a grant the other two roles
        // lost — so the assumption is pinned rather than commented.
        for action in ORGANIZATION_LEVEL_ACTIONS {
            assert!(
                !action.ends_with(":list") && !action.ends_with(":get"),
                "{action} is a read action; the viewer role is not filtered \
                 against this list, so adding one here would make the roles \
                 disagree"
            );
        }
    }

    #[test]
    fn the_list_has_no_duplicates() {
        let mut sorted = ORGANIZATION_LEVEL_ACTIONS.to_vec();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "duplicate action in the list");
    }

    #[test]
    fn membership_is_exact_not_prefixed() {
        assert!(is_organization_level_action("tenants:create"));
        // A near miss must not match: the seeder withholds on this answer.
        assert!(!is_organization_level_action("tenants:list"));
        assert!(!is_organization_level_action("tenants"));
        assert!(!is_organization_level_action("email_config:write"));
    }
}

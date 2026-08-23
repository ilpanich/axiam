//! X4 — the two adapters that connect the external token-exchange path to the
//! running system.
//!
//! Same seam, and the same reasoning, as [`crate::uma`]: `axiam-oauth2` defines
//! the grant against narrow traits rather than against `axiam-federation` and
//! `axiam-authz` directly, so its own tests can drive every branch without a
//! datastore or a network. This is where those traits get production
//! implementations, because `axiam-api-rest` is the first crate holding both.
//!
//! Both adapters are deliberately thin — logic that lands here is logic the
//! exchange's unit tests cannot see. The one exception is
//! [`RbacScopeAuthority`], whose deny-override reading is genuinely a decision
//! and is argued in full on the type.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_core::models::permission::PermissionEffect;
use axiam_core::repository::{PermissionRepository, RoleRepository};
use axiam_federation::oidc::OidcFederationService;
use axiam_federation::token_exchange::ExternalSubjectError;
use axiam_oauth2::token_exchange::{
    ExternalSubjectRejection, ExternalSubjectResolver, ResolvedExternalSubject,
    SubjectScopeAuthority,
};
use uuid::Uuid;

/// Resolves an external IdP's subject token through `axiam-federation`.
///
/// Pure translation: every decision — which providers are trusted, how the
/// signature is checked, which user an `(issuer, sub)` pair means — belongs to
/// [`OidcFederationService::verify_external_subject_token`], where it sits
/// beside the login path that answers the same questions.
pub struct FederationSubjectResolver<FC, FL, UR> {
    federation: OidcFederationService<FC, FL, UR>,
}

impl<FC, FL, UR> FederationSubjectResolver<FC, FL, UR> {
    pub fn new(federation: OidcFederationService<FC, FL, UR>) -> Self {
        Self { federation }
    }
}

impl<FC, FL, UR> ExternalSubjectResolver for FederationSubjectResolver<FC, FL, UR>
where
    FC: axiam_core::repository::FederationConfigRepository,
    FL: axiam_core::repository::FederationLinkRepository,
    UR: axiam_core::repository::UserRepository,
{
    fn resolve<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_token: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ResolvedExternalSubject, ExternalSubjectRejection>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let now = chrono::Utc::now().timestamp();
            match self
                .federation
                .verify_external_subject_token(tenant_id, subject_token, now)
                .await
            {
                Ok(s) => Ok(ResolvedExternalSubject {
                    issuer: s.issuer,
                    provider_id: s.provider_id,
                    provider_name: s.provider_name,
                    external_subject: s.external_subject,
                    user_id: s.user_id,
                    newly_provisioned: s.newly_provisioned,
                    candidate_scopes: s.candidate_scopes,
                    subject_exp: s.subject_exp,
                    max_lifetime_secs: s.max_lifetime_secs,
                }),
                Err(ExternalSubjectError::IssuerNotTrusted) => {
                    Err(ExternalSubjectRejection::IssuerNotTrusted)
                }
                Err(ExternalSubjectError::Server(m)) => Err(ExternalSubjectRejection::Server(m)),
                // "Not linked", "not active" and every token-level failure
                // collapse to one wire answer on purpose: they are all facts
                // about the *presented token's subject*, and distinguishing
                // them for the caller would turn the grant into a probe for
                // which partner identities exist in this tenant and what state
                // they are in. The distinction survives where it is useful —
                // the reason code below goes to the audit record.
                Err(other) => Err(ExternalSubjectRejection::Rejected(
                    other.reason_code().to_string(),
                )),
            }
        })
    }
}

/// Answers "which of these AXIAM scope names does this user actually hold",
/// from the RBAC engine's own data.
///
/// # The mapping
///
/// An AXIAM scope name is checked as an **`action`**, the same mapping X2
/// pinned for UMA resource scopes (`claude_dev/uma-mapping-design.md`). Using
/// one vocabulary across both features means an operator writes `read:orders`
/// once and it means the same thing in a permission grant, a UMA ticket and a
/// `scope_map` entry.
///
/// # Why it is not a `check_access` call
///
/// [`AccessRequest`](axiam_authz::types::AccessRequest) is *resource-scoped*,
/// and an OAuth2 scope is not: `read:orders` in a token is a claim about the
/// bearer, not about one row. There is no resource id to put in the request,
/// and inventing one — a tenant root, a per-provider configured resource —
/// would be inventing a policy surface X4 was not asked to add.
///
/// So this reads the same two tables the engine reads and answers the question
/// the engine is never asked: **does this user hold this action anywhere in
/// this tenant?**
///
/// # Deny-override, at its broadest reading
///
/// A scope survives only if the user has an `allow` grant for the action **and
/// no `deny` grant for it anywhere in their applicable roles**. A deny scoped
/// to one resource therefore withholds the *scope* entirely, even though the
/// same deny would only veto that one resource in a live `check_access`.
///
/// That asymmetry is deliberate, and it is the conservative direction. A
/// bearer scope cannot express "except on resource X" — it travels in a token
/// with no resource attached — so the only two honest answers are "grant it
/// everywhere" or "do not grant it". On a cross-domain path, taking the
/// narrower answer costs an operator one extra grant and buys the property
/// that **adding a deny rule can never widen what a partner token can reach**,
/// which is exactly the property B1 chose deny-override to get.
///
/// The live check still governs every actual request: a token carrying
/// `read:orders` does not thereby read anything, it merely presents a scope
/// the engine then evaluates per resource.
pub struct RbacScopeAuthority<RR, PR> {
    role_repo: RR,
    permission_repo: PR,
}

impl<RR, PR> RbacScopeAuthority<RR, PR> {
    pub fn new(role_repo: RR, permission_repo: PR) -> Self {
        Self {
            role_repo,
            permission_repo,
        }
    }
}

impl<RR, PR> SubjectScopeAuthority for RbacScopeAuthority<RR, PR>
where
    RR: RoleRepository + Send + Sync,
    PR: PermissionRepository + Send + Sync,
{
    fn held_scopes<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        candidates: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
        Box::pin(async move {
            if candidates.is_empty() {
                return Ok(Vec::new());
            }

            let assignments = self
                .role_repo
                .get_user_role_assignments(tenant_id, subject_id)
                .await
                .map_err(|e| e.to_string())?;
            if assignments.is_empty() {
                return Ok(Vec::new());
            }

            // Deduplicated: a user assigned the same role globally and on a
            // resource yields two assignments and one role's grants.
            let mut role_ids: Vec<Uuid> = Vec::with_capacity(assignments.len());
            for a in &assignments {
                if !role_ids.contains(&a.role.id) {
                    role_ids.push(a.role.id);
                }
            }

            let grants_by_role = self
                .permission_repo
                .get_role_permission_grants_for_roles(tenant_id, &role_ids)
                .await
                .map_err(|e| e.to_string())?;

            let wanted: HashSet<&str> = candidates.iter().map(String::as_str).collect();
            let mut allowed: HashSet<String> = HashSet::new();
            let mut denied: HashSet<String> = HashSet::new();
            for grants in grants_by_role.values() {
                for grant in grants {
                    if !wanted.contains(grant.permission.action.as_str()) {
                        continue;
                    }
                    match grant.effect {
                        PermissionEffect::Allow => {
                            allowed.insert(grant.permission.action.clone());
                        }
                        PermissionEffect::Deny => {
                            denied.insert(grant.permission.action.clone());
                        }
                    }
                }
            }

            // Order follows `candidates`, not the datastore's, so the result
            // is deterministic and the issued token's `scope` string is stable
            // across calls.
            Ok(candidates
                .iter()
                .filter(|c| allowed.contains(*c) && !denied.contains(*c))
                .cloned()
                .collect())
        })
    }
}

/// Boxed pair, as the exchange service takes them.
pub fn external_collaborators<FC, FL, UR, RR, PR>(
    federation: OidcFederationService<FC, FL, UR>,
    role_repo: RR,
    permission_repo: PR,
) -> (
    Arc<dyn ExternalSubjectResolver>,
    Arc<dyn SubjectScopeAuthority>,
)
where
    FC: axiam_core::repository::FederationConfigRepository + 'static,
    FL: axiam_core::repository::FederationLinkRepository + 'static,
    UR: axiam_core::repository::UserRepository + 'static,
    RR: RoleRepository + Send + Sync + 'static,
    PR: PermissionRepository + Send + Sync + 'static,
{
    (
        Arc::new(FederationSubjectResolver::new(federation)),
        Arc::new(RbacScopeAuthority::new(role_repo, permission_repo)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::permission::{Permission, PermissionGrant};
    use axiam_core::models::role::{Role, RoleAssignment, RoleSubjectAssignment};
    use chrono::Utc;
    use std::collections::HashMap;

    // ---- minimal stubs over just the two methods the authority uses ----

    #[derive(Clone, Default)]
    struct StubRoles(Vec<RoleAssignment>);

    fn role(name: &str) -> Role {
        Role {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: name.into(),
            description: String::new(),
            is_global: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn grant(action: &str, effect: PermissionEffect) -> PermissionGrant {
        PermissionGrant {
            permission: Permission {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                action: action.into(),
                description: String::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            scope_ids: Vec::new(),
            effect,
        }
    }

    /// Only `get_user_role_assignments` and
    /// `get_role_permission_grants_for_roles` are reachable from the adapter;
    /// the rest of both traits is `unimplemented!()` so a future refactor that
    /// starts calling something else fails loudly instead of silently reading
    /// a stub's default.
    macro_rules! unreachable_method {
        ($name:ident ( $($arg:ty),* ) -> $ret:ty) => {
            async fn $name(&self, $(_: $arg),*) -> AxiamResult<$ret> { unimplemented!() }
        };
    }

    impl RoleRepository for StubRoles {
        async fn get_user_role_assignments(
            &self,
            _tenant_id: Uuid,
            _user_id: Uuid,
        ) -> AxiamResult<Vec<RoleAssignment>> {
            Ok(self.0.clone())
        }
        unreachable_method!(create(axiam_core::models::role::CreateRole) -> Role);
        unreachable_method!(get_by_id(Uuid, Uuid) -> Role);
        unreachable_method!(update(Uuid, Uuid, axiam_core::models::role::UpdateRole) -> Role);
        unreachable_method!(delete(Uuid, Uuid) -> ());
        async fn list(
            &self,
            _t: Uuid,
            _p: axiam_core::repository::Pagination,
        ) -> AxiamResult<axiam_core::repository::PaginatedResult<Role>> {
            unimplemented!()
        }
        unreachable_method!(assign_to_user(Uuid, Uuid, Uuid, Option<Uuid>) -> ());
        unreachable_method!(unassign_from_user(Uuid, Uuid, Uuid, Option<Uuid>) -> ());
        unreachable_method!(get_user_roles(Uuid, Uuid) -> Vec<Role>);
        unreachable_method!(assign_to_group(Uuid, Uuid, Uuid, Option<Uuid>) -> ());
        unreachable_method!(unassign_from_group(Uuid, Uuid, Uuid, Option<Uuid>) -> ());
        unreachable_method!(get_group_roles(Uuid, Uuid) -> Vec<Role>);
        unreachable_method!(get_role_user_ids(Uuid, Uuid) -> Vec<Uuid>);
        unreachable_method!(get_role_group_ids(Uuid, Uuid) -> Vec<Uuid>);
        unreachable_method!(get_group_role_assignments(Uuid, Uuid) -> Vec<RoleAssignment>);
        unreachable_method!(
            get_role_user_assignments(Uuid, Uuid) -> Vec<RoleSubjectAssignment>
        );
        unreachable_method!(
            get_role_group_assignments(Uuid, Uuid) -> Vec<RoleSubjectAssignment>
        );
    }

    #[derive(Clone, Default)]
    struct StubPermissions(HashMap<Uuid, Vec<PermissionGrant>>);

    impl PermissionRepository for StubPermissions {
        async fn get_role_permission_grants_for_roles(
            &self,
            _tenant_id: Uuid,
            role_ids: &[Uuid],
        ) -> AxiamResult<HashMap<Uuid, Vec<PermissionGrant>>> {
            Ok(role_ids
                .iter()
                .filter_map(|id| self.0.get(id).map(|g| (*id, g.clone())))
                .collect())
        }
        unreachable_method!(create(axiam_core::models::permission::CreatePermission) -> Permission);
        unreachable_method!(get_by_id(Uuid, Uuid) -> Permission);
        unreachable_method!(
            update(Uuid, Uuid, axiam_core::models::permission::UpdatePermission) -> Permission
        );
        unreachable_method!(delete(Uuid, Uuid) -> ());
        async fn list(
            &self,
            _t: Uuid,
            _p: axiam_core::repository::Pagination,
        ) -> AxiamResult<axiam_core::repository::PaginatedResult<Permission>> {
            unimplemented!()
        }
        unreachable_method!(grant_to_role(Uuid, Uuid, Uuid) -> ());
        unreachable_method!(revoke_from_role(Uuid, Uuid, Uuid) -> ());
        unreachable_method!(get_role_permissions(Uuid, Uuid) -> Vec<Permission>);
        unreachable_method!(grant_to_role_with_scopes(Uuid, Uuid, Uuid, Vec<Uuid>) -> ());
        unreachable_method!(
            grant_to_role_with_effect(Uuid, Uuid, Uuid, Vec<Uuid>, PermissionEffect) -> ()
        );
        unreachable_method!(get_role_permission_grants(Uuid, Uuid) -> Vec<PermissionGrant>);
    }

    fn authority(
        assignments: Vec<RoleAssignment>,
        grants: HashMap<Uuid, Vec<PermissionGrant>>,
    ) -> RbacScopeAuthority<StubRoles, StubPermissions> {
        RbacScopeAuthority::new(StubRoles(assignments), StubPermissions(grants))
    }

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[tokio::test]
    async fn a_user_with_no_roles_holds_nothing() {
        let a = authority(vec![], HashMap::new());
        assert!(
            a.held_scopes(Uuid::new_v4(), Uuid::new_v4(), &v(&["read:orders"]))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_allow_grant_for_the_action_holds_the_scope() {
        let r = role("reader");
        let mut grants = HashMap::new();
        grants.insert(r.id, vec![grant("read:orders", PermissionEffect::Allow)]);
        let a = authority(
            vec![RoleAssignment {
                role: r,
                resource_id: None,
            }],
            grants,
        );

        assert_eq!(
            a.held_scopes(Uuid::new_v4(), Uuid::new_v4(), &v(&["read:orders"]))
                .await
                .unwrap(),
            v(&["read:orders"])
        );
    }

    /// The decision this type exists to make explicit: a deny anywhere in the
    /// user's applicable roles withholds the scope, even alongside an allow.
    /// A bearer scope cannot say "except on resource X", so the only honest
    /// answers are "everywhere" and "not at all".
    #[tokio::test]
    async fn a_deny_anywhere_withholds_the_scope_even_against_an_allow() {
        let allower = role("reader");
        let denier = role("embargoed");
        let mut grants = HashMap::new();
        grants.insert(
            allower.id,
            vec![grant("read:orders", PermissionEffect::Allow)],
        );
        grants.insert(
            denier.id,
            vec![grant("read:orders", PermissionEffect::Deny)],
        );

        let a = authority(
            vec![
                RoleAssignment {
                    role: allower,
                    resource_id: None,
                },
                RoleAssignment {
                    role: denier,
                    // Scoped to one resource — and it still withholds the
                    // whole scope. That is the conservative reading, argued on
                    // `RbacScopeAuthority`.
                    resource_id: Some(Uuid::new_v4()),
                },
            ],
            grants,
        );

        assert!(
            a.held_scopes(Uuid::new_v4(), Uuid::new_v4(), &v(&["read:orders"]))
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// The port's contract: a filter, never a source. Whatever comes back was
    /// in `candidates`.
    #[tokio::test]
    async fn the_result_is_always_a_subset_of_the_candidates() {
        let r = role("wide");
        let mut grants = HashMap::new();
        grants.insert(
            r.id,
            vec![
                grant("read:orders", PermissionEffect::Allow),
                grant("admin", PermissionEffect::Allow),
                grant("write:invoices", PermissionEffect::Allow),
            ],
        );
        let a = authority(
            vec![RoleAssignment {
                role: r,
                resource_id: None,
            }],
            grants,
        );

        let held = a
            .held_scopes(Uuid::new_v4(), Uuid::new_v4(), &v(&["read:orders"]))
            .await
            .unwrap();
        assert_eq!(
            held,
            v(&["read:orders"]),
            "an action the user holds but nobody asked about must not appear"
        );
    }

    #[tokio::test]
    async fn the_result_preserves_candidate_order_so_the_scope_string_is_stable() {
        let r = role("wide");
        let mut grants = HashMap::new();
        grants.insert(
            r.id,
            vec![
                grant("b", PermissionEffect::Allow),
                grant("a", PermissionEffect::Allow),
            ],
        );
        let a = authority(
            vec![RoleAssignment {
                role: r,
                resource_id: None,
            }],
            grants,
        );

        assert_eq!(
            a.held_scopes(Uuid::new_v4(), Uuid::new_v4(), &v(&["a", "b"]))
                .await
                .unwrap(),
            v(&["a", "b"])
        );
    }

    #[tokio::test]
    async fn an_empty_candidate_set_short_circuits_without_touching_the_datastore() {
        // The stubs would panic on any other method; reaching the repositories
        // at all with nothing to ask about would be wasted round-trips on a
        // path that already failed.
        let a = authority(vec![], HashMap::new());
        assert!(
            a.held_scopes(Uuid::new_v4(), Uuid::new_v4(), &[])
                .await
                .unwrap()
                .is_empty()
        );
    }
}

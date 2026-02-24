//! Core authorization engine implementing RBAC with resource hierarchy.

use std::collections::HashSet;

use axiam_core::error::AxiamResult;
use axiam_core::repository::{
    GroupRepository, PermissionRepository, ResourceRepository, RoleRepository, ScopeRepository,
};
use uuid::Uuid;

use crate::types::{AccessDecision, AccessRequest};

/// Permission evaluation engine.
///
/// Implements the design-doc algorithm:
/// 1. Fetch subject's role assignments (direct + group, with resource scope)
/// 2. Filter applicable roles (global, scoped to target resource, or ancestor)
/// 3. Collect permissions from applicable roles
/// 4. Check if requested action matches any permission
/// 5. Validate scope if specified
/// 6. Default deny
pub struct AuthorizationEngine<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    role_repo: R,
    permission_repo: P,
    resource_repo: Res,
    scope_repo: S,
    #[allow(dead_code)]
    group_repo: G,
}

impl<R, P, Res, S, G> AuthorizationEngine<R, P, Res, S, G>
where
    R: RoleRepository,
    P: PermissionRepository,
    Res: ResourceRepository,
    S: ScopeRepository,
    G: GroupRepository,
{
    pub fn new(
        role_repo: R,
        permission_repo: P,
        resource_repo: Res,
        scope_repo: S,
        group_repo: G,
    ) -> Self {
        Self {
            role_repo,
            permission_repo,
            resource_repo,
            scope_repo,
            group_repo,
        }
    }

    /// Evaluate whether the subject can perform the requested action.
    pub async fn check_access(&self, request: &AccessRequest) -> AxiamResult<AccessDecision> {
        // 1. Fetch all role assignments (direct + group) with resource scope.
        let assignments = self
            .role_repo
            .get_user_role_assignments(request.tenant_id, request.subject_id)
            .await?;

        if assignments.is_empty() {
            return Ok(AccessDecision::Deny("no roles assigned".into()));
        }

        // 2. Build the set of ancestor resource IDs for hierarchy inheritance.
        let ancestors = self
            .resource_repo
            .get_ancestors(request.tenant_id, request.resource_id)
            .await?;
        let ancestor_ids: HashSet<Uuid> = ancestors.iter().map(|r| r.id).collect();

        // 3. Filter applicable roles:
        //    - Global roles always apply
        //    - Roles scoped to the target resource
        //    - Roles scoped to any ancestor of the target resource
        let applicable_role_ids: Vec<Uuid> = assignments
            .iter()
            .filter(|a| {
                a.role.is_global
                    || a.resource_id == Some(request.resource_id)
                    || a.resource_id
                        .map(|rid| ancestor_ids.contains(&rid))
                        .unwrap_or(false)
            })
            .map(|a| a.role.id)
            .collect();

        if applicable_role_ids.is_empty() {
            return Ok(AccessDecision::Deny(
                "no applicable roles for this resource".into(),
            ));
        }

        // 4. Collect permissions from all applicable roles.
        let mut has_matching_permission = false;
        let mut seen_roles = HashSet::new();

        for role_id in &applicable_role_ids {
            if !seen_roles.insert(*role_id) {
                continue; // skip duplicates
            }
            let permissions = self
                .permission_repo
                .get_role_permissions(request.tenant_id, *role_id)
                .await?;

            if permissions.iter().any(|p| p.action == request.action) {
                has_matching_permission = true;
                break;
            }
        }

        if !has_matching_permission {
            return Ok(AccessDecision::Deny(format!(
                "no permission grants action '{}'",
                request.action
            )));
        }

        // 5. Validate scope if specified.
        if let Some(ref scope_name) = request.scope {
            let scopes = self
                .scope_repo
                .list_by_resource(request.tenant_id, request.resource_id)
                .await?;

            if !scopes.iter().any(|s| s.name == *scope_name) {
                return Ok(AccessDecision::Deny(format!(
                    "scope '{}' not found on resource",
                    scope_name
                )));
            }
        }

        Ok(AccessDecision::Allow)
    }
}

//! Fixtures the organization-scope tests share (SA-02, review Q-17).
//!
//! Since SA-02 the organization-level routes (the organization baseline, the
//! system audit partition, a tenant's audit export, …) refuse a caller whose
//! own record lives in an ordinary tenant, whatever it holds. Every test of
//! such a route therefore needs the same thing: a user of the organization's
//! reserved scope tenant and a token for it. These are those fixtures, and the
//! real authorization engine and seeded-role users the scope tests decide
//! `RequirePermission` with.
//!
//! Included with `mod org_scope_support;` by each test binary that uses it; a
//! binary uses only some of it, hence the `dead_code` allowance. Nothing here
//! is a literal credential: passwords come from `axiam_test_support`.

#![allow(dead_code)]

use std::sync::Arc;

use axiam_api_rest::authz::AuthzChecker;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    Pagination, PermissionRepository, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealPermissionRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use uuid::Uuid;

/// A user access token for `user_id` acting in `tenant_id` of `org_id`.
pub fn user_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// Create `org_id`'s reserved organization-scope tenant and return its id.
pub async fn organization_scope(db: &Surreal<Db>, org_id: Uuid) -> Uuid {
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org_id))
        .await
        .unwrap()
        .id
}

/// An organization-level operator: the organization's scope tenant, created
/// on the call, a user `username` living in it, and a token for that user.
///
/// Returns `(scope_tenant_id, operator_id, token)`.
pub async fn org_operator(
    db: &Surreal<Db>,
    auth: &AuthConfig,
    org_id: Uuid,
    username: &str,
) -> (Uuid, Uuid, String) {
    let scope = organization_scope(db, org_id).await;
    let operator = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: scope,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    let token = user_token(auth, operator.id, scope, org_id);
    (scope, operator.id, token)
}

/// The token of [`org_operator`], for a test that needs nothing else.
pub async fn org_operator_token(
    db: &Surreal<Db>,
    auth: &AuthConfig,
    org_id: Uuid,
    username: &str,
) -> String {
    org_operator(db, auth, org_id, username).await.2
}

/// The real engine, so the seeded roles' grants decide `RequirePermission`
/// rather than `AllowAllAuthzChecker`.
pub fn real_authz(db: &Surreal<Db>) -> Arc<dyn AuthzChecker> {
    Arc::new(axiam_authz::AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

/// Seed the permission registry and default roles into `tenant_id`, as the
/// tenant-create path does for every new tenant.
pub async fn seed_tenant(db: &Surreal<Db>, tenant_id: Uuid) {
    use axiam_api_rest::permissions::PERMISSION_REGISTRY;
    axiam_db::seed_permissions(db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    axiam_db::seed_default_roles(db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
}

/// A user of `tenant_id` holding the seeded role `role_name`, or — with
/// `action` — a fresh global role granting only that action.
pub async fn tenant_user(
    db: &Surreal<Db>,
    tenant_id: Uuid,
    username: &str,
    role_name: Option<&str>,
    action: Option<&str>,
) -> Uuid {
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    let role_repo = SurrealRoleRepository::new(db.clone());
    let page = Pagination {
        offset: 0,
        limit: 1000,
        search: None,
    };
    let role_id = if let Some(name) = role_name {
        role_repo
            .list(tenant_id, page)
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("default role `{name}` not seeded"))
            .id
    } else {
        let action = action.expect("a role name or an action");
        let role = role_repo
            .create(CreateRole {
                tenant_id,
                name: format!("role-{username}"),
                description: format!("grants only {action}"),
                is_global: true,
            })
            .await
            .unwrap();
        let perm_repo = SurrealPermissionRepository::new(db.clone());
        let perm = perm_repo
            .list(tenant_id, page)
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|p| p.action == action)
            .unwrap_or_else(|| panic!("permission `{action}` not seeded"));
        perm_repo
            .grant_to_role(tenant_id, role.id, perm.id)
            .await
            .unwrap();
        role.id
    };
    role_repo
        .assign_to_user(tenant_id, user.id, role_id, AssignmentScope::global())
        .await
        .unwrap();
    user.id
}

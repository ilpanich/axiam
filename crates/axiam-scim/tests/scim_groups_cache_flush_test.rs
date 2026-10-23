//! R112-05 (#798) — SCIM `/Groups` membership writes and group delete flush
//! the authorization decision cache (D7).
//!
//! The native group routes, SCIM `/Users` and the directory mapper all flush;
//! SCIM `/Groups` did not, so an IdP's usual revocation (remove the user from
//! the group that carries the role) was served from the cache until
//! `decision_cache_ttl_secs`. Each test caches a decision through the same
//! engine the SCIM handlers flush, drives the SCIM write, and asserts the next
//! check is evaluated against the store, not served.

use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::types::{AccessDecision, AccessRequest, SubjectScope};
use axiam_authz::{AuthorizationEngine, DecisionCache, DecisionCacheConfig};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::{CreatePermission, PermissionEffect};
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, Pagination, PermissionRepository, RoleRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use serde_json::json;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;
type Engine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

/// The action the fixture role grants (or denies), on the global sentinel.
const ACTION: &str = "reports:read";

fn generated_secret(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    engine: Arc<Engine>,
    cache: Arc<DecisionCache>,
    auth: AuthConfig,
}

impl Fixture {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "R112-05 Org".into(),
                slug: format!("org-{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "R112-05 Tenant".into(),
                slug: format!("tenant-{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap();
        seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
            .await
            .unwrap();
        seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
            .await
            .unwrap();

        let cache = Arc::new(DecisionCache::new(DecisionCacheConfig {
            ttl: Duration::from_secs(300),
            max_entries_per_tenant: 1000,
        }));
        let engine = Arc::new(
            AuthorizationEngine::new(
                SurrealRoleRepository::new(db.clone()),
                SurrealPermissionRepository::new(db.clone()),
                SurrealResourceRepository::new(db.clone()),
                SurrealScopeRepository::new(db.clone()),
                SurrealGroupRepository::new(db.clone()),
            )
            .with_decision_cache(Arc::clone(&cache)),
        );
        Self {
            db,
            org_id: org.id,
            tenant_id: tenant.id,
            engine,
            cache,
            auth: test_auth_config(),
        }
    }

    async fn active_user(&self) -> Uuid {
        let repo = SurrealUserRepository::new(self.db.clone());
        let user = repo
            .create(CreateUser {
                tenant_id: self.tenant_id,
                username: format!("u-{}", Uuid::new_v4().simple()),
                email: format!("u-{}@example.com", Uuid::new_v4().simple()),
                password: generated_secret("pw"),
                metadata: None,
            })
            .await
            .unwrap();
        repo.update(
            self.tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        user.id
    }

    /// A user holding the seeded `admin` role (which carries
    /// `scim:provision`), and a bearer token for it.
    async fn provisioner_token(&self) -> String {
        let user = self.active_user().await;
        let roles = SurrealRoleRepository::new(self.db.clone());
        let admin = roles
            .list(
                self.tenant_id,
                Pagination {
                    offset: 0,
                    limit: 1000,
                    search: None,
                },
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|r| r.name == "admin")
            .expect("the admin role is seeded");
        roles
            .assign_to_user(self.tenant_id, user, admin.id, AssignmentScope::global())
            .await
            .unwrap();
        issue_access_token(
            user,
            self.tenant_id,
            self.org_id,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap()
    }

    /// A role granting (or denying) [`ACTION`] globally.
    async fn role(&self, effect: PermissionEffect) -> Uuid {
        let roles = SurrealRoleRepository::new(self.db.clone());
        let permissions = SurrealPermissionRepository::new(self.db.clone());
        let role = roles
            .create(CreateRole {
                tenant_id: self.tenant_id,
                name: format!("role-{}", Uuid::new_v4().simple()),
                description: String::new(),
                is_global: true,
            })
            .await
            .unwrap();
        let existing = permissions
            .list(
                self.tenant_id,
                Pagination {
                    offset: 0,
                    limit: 1000,
                    search: None,
                },
            )
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|p| p.action == ACTION);
        let permission = match existing {
            Some(p) => p,
            None => permissions
                .create(CreatePermission {
                    tenant_id: self.tenant_id,
                    action: ACTION.into(),
                    description: String::new(),
                })
                .await
                .unwrap(),
        };
        permissions
            .grant_to_role_with_effect(self.tenant_id, role.id, permission.id, vec![], effect)
            .await
            .unwrap();
        role.id
    }

    /// A group holding `role`, with `members`.
    async fn group(&self, role: Uuid, members: &[Uuid]) -> Uuid {
        let groups = SurrealGroupRepository::new(self.db.clone());
        let group = groups
            .create(CreateGroup {
                tenant_id: self.tenant_id,
                name: format!("g-{}", Uuid::new_v4().simple()),
                description: String::new(),
                metadata: None,
            })
            .await
            .unwrap();
        SurrealRoleRepository::new(self.db.clone())
            .assign_to_group(self.tenant_id, group.id, role, AssignmentScope::global())
            .await
            .unwrap();
        for member in members {
            groups
                .add_member(self.tenant_id, *member, group.id)
                .await
                .unwrap();
        }
        group.id
    }

    fn request(&self, subject: Uuid) -> AccessRequest {
        AccessRequest {
            tenant_id: self.tenant_id,
            subject_scope: SubjectScope::Tenant,
            subject_id: subject,
            action: ACTION.into(),
            resource_id: Uuid::nil(),
            scope: None,
        }
    }

    async fn check(&self, subject: Uuid) -> AccessDecision {
        self.engine
            .check_access(&self.request(subject))
            .await
            .unwrap()
    }

    /// Run one SCIM request through the routes with this fixture's engine as
    /// the `AuthzChecker` the handlers flush.
    async fn scim(&self, req: test::TestRequest) -> u16 {
        let authz: Arc<dyn AuthzChecker> = self.engine.clone();
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(self.auth.clone()))
                .app_data(web::Data::new(authz))
                .app_data(web::Data::new(AppState::for_test(
                    self.db.clone(),
                    self.auth.clone(),
                )))
                .configure(axiam_scim::scim_routes::<TestDb>),
        )
        .await;
        let token = self.provisioner_token().await;
        let req = req
            .peer_addr("203.0.113.9:5000".parse().unwrap())
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        test::call_service(&app, req).await.status().as_u16()
    }
}

fn patch_op(op: serde_json::Value) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [op]
    })
}

/// The issue's case: an allow cached through the group's role, then the IdP
/// removes the member with the Okta/Entra filter shape; the next check is
/// evaluated and denied.
#[actix_rt::test]
async fn a_scim_member_removal_is_not_served_from_the_cache() {
    let f = Fixture::new().await;
    let user = f.active_user().await;
    let role = f.role(PermissionEffect::Allow).await;
    let group = f.group(role, &[user]).await;

    assert_eq!(f.check(user).await, AccessDecision::Allow);
    assert_eq!(f.cache.get(&f.request(user)), Some(AccessDecision::Allow));

    let status = f
        .scim(
            test::TestRequest::patch()
                .uri(&format!("/scim/v2/Groups/{group}"))
                .set_json(patch_op(json!({
                    "op": "remove",
                    "path": format!("members[value eq \"{user}\"]")
                }))),
        )
        .await;
    assert_eq!(status, 200);

    assert_eq!(
        f.cache.get(&f.request(user)),
        None,
        "the removed member's cached allow survived the SCIM PATCH"
    );
    assert!(matches!(f.check(user).await, AccessDecision::Deny(_)));
}

/// Under deny-override an add narrows access: a member added to a group that
/// holds a deny role must lose its cached allow.
#[actix_rt::test]
async fn a_scim_add_to_a_deny_role_group_is_not_served_from_the_cache() {
    let f = Fixture::new().await;
    let user = f.active_user().await;
    let allow = f.role(PermissionEffect::Allow).await;
    let _allowing = f.group(allow, &[user]).await;
    let deny = f.role(PermissionEffect::Deny).await;
    let denying = f.group(deny, &[]).await;

    assert_eq!(f.check(user).await, AccessDecision::Allow);

    let status = f
        .scim(
            test::TestRequest::patch()
                .uri(&format!("/scim/v2/Groups/{denying}"))
                .set_json(patch_op(json!({
                    "op": "add",
                    "path": "members",
                    "value": [{ "value": user }]
                }))),
        )
        .await;
    assert_eq!(status, 200);

    assert_eq!(f.cache.get(&f.request(user)), None);
    assert!(
        matches!(f.check(user).await, AccessDecision::DeniedByRule(_)),
        "the deny role the member now inherits overrides its allow"
    );
}

/// A `PUT` that drops a member from the full membership flushes it too.
#[actix_rt::test]
async fn a_scim_put_that_drops_a_member_is_not_served_from_the_cache() {
    let f = Fixture::new().await;
    let (user, kept) = (f.active_user().await, f.active_user().await);
    let role = f.role(PermissionEffect::Allow).await;
    let group = f.group(role, &[user, kept]).await;

    assert_eq!(f.check(user).await, AccessDecision::Allow);
    assert_eq!(f.check(kept).await, AccessDecision::Allow);

    let status = f
        .scim(
            test::TestRequest::put()
                .uri(&format!("/scim/v2/Groups/{group}"))
                .set_json(json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                    "displayName": "renamed",
                    "members": [{ "value": kept }]
                })),
        )
        .await;
    assert_eq!(status, 200);

    assert!(matches!(f.check(user).await, AccessDecision::Deny(_)));
    assert_eq!(f.check(kept).await, AccessDecision::Allow);
}

/// Deleting the group drops every member's inherited roles; the tenant is
/// flushed, as the native delete does.
#[actix_rt::test]
async fn a_scim_group_delete_is_not_served_from_the_cache() {
    let f = Fixture::new().await;
    let user = f.active_user().await;
    let role = f.role(PermissionEffect::Allow).await;
    let group = f.group(role, &[user]).await;

    assert_eq!(f.check(user).await, AccessDecision::Allow);

    let status = f
        .scim(test::TestRequest::delete().uri(&format!("/scim/v2/Groups/{group}")))
        .await;
    assert_eq!(status, 204);

    assert_eq!(f.cache.tenant_len(f.tenant_id), 0);
    assert!(matches!(f.check(user).await, AccessDecision::Deny(_)));
}

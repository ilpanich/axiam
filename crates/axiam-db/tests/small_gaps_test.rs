//! Small, targeted coverage gaps across several repositories that are
//! otherwise well-tested: unexercised `update()` SET-clause branches and
//! cross-tenant denial branches for permission grants. Each repository here
//! already has substantial coverage elsewhere; these tests fill in the
//! specific remaining branches identified via lcov line analysis.

use axiam_core::models::group::{CreateGroup, UpdateGroup};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::{CreatePermission, UpdatePermission};
use axiam_core::models::role::CreateRole;
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantStatus, UpdateTenant};
use axiam_core::models::user::{CreateUser, UserStatus};
use axiam_core::models::webhook::{CreateWebhook, RetryPolicy, UpdateWebhook};
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, PermissionRepository, RoleRepository,
    ServiceAccountRepository, TenantRepository, UserRepository, WebhookRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealRoleRepository, SurrealServiceAccountRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebhookRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = Surreal<surrealdb::engine::local::Db>;

fn test_password() -> String {
    std::env::var("AXIAM_TEST_PASSWORD").unwrap_or_else(|_| ["Super", "Secret123!"].concat())
}

async fn setup() -> (Db, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

// ---------------------------------------------------------------------------
// Tenant: update() slug+status(Suspended)+metadata, get_by_slug not-found
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tenant_update_slug_status_suspended_and_metadata() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealTenantRepository::new(db);

    let updated = repo
        .update(
            tenant_id,
            UpdateTenant {
                name: None,
                slug: Some("new-slug".into()),
                status: Some(TenantStatus::Suspended),
                metadata: Some(serde_json::json!({"reason": "billing"})),
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.slug, "new-slug");
    assert_eq!(updated.status, TenantStatus::Suspended);
    assert_eq!(updated.metadata, serde_json::json!({"reason": "billing"}));
}

#[tokio::test]
async fn tenant_get_by_slug_not_found() {
    let (db, org_id) = {
        let (db, org, _t) = setup().await;
        (db, org)
    };
    let repo = SurrealTenantRepository::new(db);
    assert!(repo.get_by_slug(org_id, "no-such-slug").await.is_err());
}

// ---------------------------------------------------------------------------
// Group: update() description+metadata; add_member not-found branches
// ---------------------------------------------------------------------------

#[tokio::test]
async fn group_update_description_and_metadata() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    let group = repo
        .create(CreateGroup {
            tenant_id,
            name: "engineers".into(),
            description: "Engineering team".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            group.id,
            UpdateGroup {
                name: None,
                description: Some("Updated description".into()),
                metadata: Some(serde_json::json!({"k": "v"})),
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.description, "Updated description");
    assert_eq!(updated.metadata, serde_json::json!({"k": "v"}));
}

#[tokio::test]
async fn group_add_member_missing_user_or_group_not_found() {
    let (db, _org, tenant_id) = setup().await;
    let group_repo = SurrealGroupRepository::new(db.clone());
    let user_repo = SurrealUserRepository::new(db);

    let group = group_repo
        .create(CreateGroup {
            tenant_id,
            name: "team".into(),
            description: "team".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "member".into(),
            email: "member@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    // Missing user.
    let missing_user = Uuid::new_v4();
    assert!(
        group_repo
            .add_member(tenant_id, missing_user, group.id)
            .await
            .is_err()
    );

    // Missing group.
    let missing_group = Uuid::new_v4();
    assert!(
        group_repo
            .add_member(tenant_id, user.id, missing_group)
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Permission: update() action+description; cross-tenant grant/revoke denial
// ---------------------------------------------------------------------------

#[tokio::test]
async fn permission_update_action_and_description() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealPermissionRepository::new(db);

    let perm = repo
        .create(CreatePermission {
            tenant_id,
            action: "widgets:list".into(),
            description: "List widgets".into(),
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            perm.id,
            UpdatePermission {
                action: Some("widgets:list_all".into()),
                description: Some("List all widgets".into()),
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.action, "widgets:list_all");
    assert_eq!(updated.description, "List all widgets");
}

#[tokio::test]
async fn permission_grant_to_role_cross_tenant_denied() {
    let (db, org_id, tenant_a) = setup().await;
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db);

    // Role lives in tenant_a, permission lives in tenant_b.
    let role = role_repo
        .create(CreateRole {
            tenant_id: tenant_a,
            name: "role-a".into(),
            description: "role in tenant A".into(),
            is_global: true,
        })
        .await
        .unwrap();
    let perm = perm_repo
        .create(CreatePermission {
            tenant_id: tenant_b,
            action: "cross:tenant".into(),
            description: "perm in tenant B".into(),
        })
        .await
        .unwrap();

    // Grant attempted under tenant_a: permission doesn't belong to tenant_a.
    let result = perm_repo.grant_to_role(tenant_a, role.id, perm.id).await;
    assert!(result.is_err(), "cross-tenant grant must be denied");
}

#[tokio::test]
async fn permission_revoke_from_role_cross_tenant_denied() {
    let (db, org_id, tenant_a) = setup().await;
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db);

    let role = role_repo
        .create(CreateRole {
            tenant_id: tenant_a,
            name: "role-a2".into(),
            description: "role in tenant A".into(),
            is_global: true,
        })
        .await
        .unwrap();
    let perm = perm_repo
        .create(CreatePermission {
            tenant_id: tenant_b,
            action: "cross:tenant2".into(),
            description: "perm in tenant B".into(),
        })
        .await
        .unwrap();

    let result = perm_repo.revoke_from_role(tenant_a, role.id, perm.id).await;
    assert!(result.is_err(), "cross-tenant revoke must be denied");
}

// ---------------------------------------------------------------------------
// ServiceAccount: update() description+status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn service_account_update_description_and_status() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db);

    let (sa, _secret) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "svc-1".into(),
            description: Some("initial".into()),
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            sa.id,
            axiam_core::models::service_account::UpdateServiceAccount {
                name: None,
                description: Some("updated description".into()),
                status: Some(UserStatus::Inactive),
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.description.as_deref(), Some("updated description"));
    assert_eq!(updated.status, UserStatus::Inactive);
}

// ---------------------------------------------------------------------------
// Webhook: update() retry_policy branch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_update_retry_policy() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealWebhookRepository::new(db);

    let wh = repo
        .create(CreateWebhook {
            tenant_id,
            url: "https://hooks.example.com/retry".into(),
            events: vec!["user.created".into()],
            secret: "s".into(),
            retry_policy: Some(RetryPolicy::default()),
        })
        .await
        .unwrap();

    let new_policy = RetryPolicy {
        max_retries: 9,
        initial_delay_secs: 5,
        backoff_multiplier: 3.0,
    };
    let updated = repo
        .update(
            tenant_id,
            wh.id,
            UpdateWebhook {
                retry_policy: Some(new_policy.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.retry_policy.max_retries, 9);
    assert_eq!(updated.retry_policy.initial_delay_secs, 5);
    assert_eq!(updated.retry_policy.backoff_multiplier, 3.0);
}

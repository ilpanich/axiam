//! Coverage for `seeder.rs`'s default-data routines not exercised by
//! `seeder_skip_test.rs` (which only covers `seed_permissions`' hash-skip
//! branch): `mint_bootstrap_setup_token_if_needed`, `seed_default_roles`
//! (incl. idempotency), and `reconcile_default_role_grants`.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, Pagination, PermissionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_db::seeder::{
    ReconcileOutcome, SeederStateRow, mint_bootstrap_setup_token_if_needed,
    reconcile_default_role_grants, seed_default_roles, seed_permissions,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

use axiam_test_support::test_password;

type Db = Surreal<surrealdb::engine::local::Db>;

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
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

const REGISTRY: &[(&str, &str)] = &[
    ("users:list", "List users"),
    ("users:get", "Get a user"),
    ("users:create", "Create a user"),
    ("admin:bootstrap", "Bootstrap the tenant"),
];

// ---------------------------------------------------------------------------
// mint_bootstrap_setup_token_if_needed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_bootstrap_token_on_fresh_db_returns_token_once() {
    let (db, _org, _tenant) = setup().await;

    let token = mint_bootstrap_setup_token_if_needed(&db)
        .await
        .expect("mint should succeed on fresh db");
    assert!(token.is_some(), "fresh db should mint a token");
    let token = token.unwrap();
    assert!(!token.is_empty());

    // Second call is a no-op: a bootstrap_setup_token row already exists.
    let second = mint_bootstrap_setup_token_if_needed(&db)
        .await
        .expect("second mint call should succeed");
    assert!(
        second.is_none(),
        "token should only be minted once (existing token row)"
    );
}

#[tokio::test]
async fn mint_bootstrap_token_noop_when_user_already_exists() {
    let (db, _org, tenant_id) = setup().await;

    // Create a user WITHOUT going through the bootstrap token flow — this
    // simulates a DB that was seeded some other way (migration, restore).
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "preexisting".into(),
            email: "preexisting@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_bootstrap_setup_token_if_needed(&db)
        .await
        .expect("mint call should succeed");
    assert!(
        token.is_none(),
        "no token should be minted when a user already exists"
    );
}

// ---------------------------------------------------------------------------
// seed_default_roles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn seed_default_roles_grants_expected_permission_sets() {
    let (db, _org, tenant_id) = setup().await;

    seed_permissions(&db, tenant_id, REGISTRY)
        .await
        .expect("seed_permissions failed");

    let result = seed_default_roles(&db, tenant_id, REGISTRY)
        .await
        .expect("seed_default_roles failed");

    let perm_repo = SurrealPermissionRepository::new(db.clone());

    let super_admin_perms = perm_repo
        .get_role_permissions(tenant_id, result.super_admin_role_id)
        .await
        .unwrap();
    assert_eq!(
        super_admin_perms.len(),
        REGISTRY.len(),
        "super-admin should have every permission"
    );

    let admin_perms = perm_repo
        .get_role_permissions(tenant_id, result.admin_role_id)
        .await
        .unwrap();
    assert_eq!(
        admin_perms.len(),
        REGISTRY.len() - 1,
        "admin should have every permission except admin:bootstrap"
    );
    assert!(admin_perms.iter().all(|p| p.action != "admin:bootstrap"));

    let viewer_perms = perm_repo
        .get_role_permissions(tenant_id, result.viewer_role_id)
        .await
        .unwrap();
    // Only users:list and users:get end with :list/:get in REGISTRY.
    assert_eq!(viewer_perms.len(), 2);
    assert!(
        viewer_perms
            .iter()
            .all(|p| p.action.ends_with(":list") || p.action.ends_with(":get"))
    );
}

#[tokio::test]
async fn seed_default_roles_is_idempotent() {
    let (db, _org, tenant_id) = setup().await;

    seed_permissions(&db, tenant_id, REGISTRY)
        .await
        .expect("seed_permissions failed");

    let first = seed_default_roles(&db, tenant_id, REGISTRY)
        .await
        .expect("first seed_default_roles failed");

    // Second call must reuse the same role IDs and not error on duplicate
    // grants (grant_to_role_idempotent / find_or_create_role branches).
    let second = seed_default_roles(&db, tenant_id, REGISTRY)
        .await
        .expect("second seed_default_roles failed");

    assert_eq!(first.super_admin_role_id, second.super_admin_role_id);
    assert_eq!(first.admin_role_id, second.admin_role_id);
    assert_eq!(first.viewer_role_id, second.viewer_role_id);

    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let super_admin_perms = perm_repo
        .get_role_permissions(tenant_id, second.super_admin_role_id)
        .await
        .unwrap();
    assert_eq!(
        super_admin_perms.len(),
        REGISTRY.len(),
        "no duplicate grants after idempotent re-seed"
    );
}

// ---------------------------------------------------------------------------
// reconcile_default_role_grants
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reconcile_returns_zero_for_never_bootstrapped_tenant() {
    let (db, _org, tenant_id) = setup().await;

    // No default roles exist yet for this tenant.
    let created = reconcile_default_role_grants(&db, tenant_id)
        .await
        .expect("reconcile should not error for an unbootstrapped tenant");
    assert_eq!(created, ReconcileOutcome::default());
}

#[tokio::test]
async fn reconcile_backfills_grants_for_new_permission_and_is_idempotent() {
    let (db, _org, tenant_id) = setup().await;

    // Bootstrap with an initial, smaller registry.
    let initial_registry: &[(&str, &str)] =
        &[("users:list", "List users"), ("users:get", "Get a user")];
    seed_permissions(&db, tenant_id, initial_registry)
        .await
        .unwrap();
    let roles = seed_default_roles(&db, tenant_id, initial_registry)
        .await
        .unwrap();

    // A new permission is added directly (simulating a permission-registry
    // change picked up by `seed_permissions` on a later boot without going
    // through `seed_default_roles`, which only runs at first bootstrap).
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "webhooks:create".into(),
            description: "Create a webhook".into(),
        })
        .await
        .unwrap();

    let created = reconcile_default_role_grants(&db, tenant_id)
        .await
        .expect("reconcile failed");
    // super-admin + admin both need the new grant; viewer does not
    // (`webhooks:create` doesn't end with :list/:get).
    assert_eq!(
        created,
        ReconcileOutcome {
            granted: 2,
            revoked: 0
        },
        "expected 2 new grants (super-admin + admin) and no revocations"
    );

    let super_admin_perms = perm_repo
        .get_role_permissions(tenant_id, roles.super_admin_role_id)
        .await
        .unwrap();
    assert!(
        super_admin_perms
            .iter()
            .any(|p| p.action == "webhooks:create")
    );

    // Second reconcile call: nothing left to backfill.
    let second = reconcile_default_role_grants(&db, tenant_id)
        .await
        .expect("second reconcile failed");
    assert_eq!(
        second,
        ReconcileOutcome::default(),
        "reconcile must be idempotent"
    );
}

// ---------------------------------------------------------------------------
// SeederStateRow is a public re-export used by callers reading seeder_state
// directly; smoke-test its Deserialize wiring via seed_permissions' output.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn seeder_state_row_is_readable_after_seed() {
    let (db, _org, tenant_id) = setup().await;
    seed_permissions(&db, tenant_id, REGISTRY).await.unwrap();

    let state_id = Uuid::new_v5(&tenant_id, b"seeder_state").to_string();
    let mut result = db
        .query("SELECT hash FROM type::record('seeder_state', $id)")
        .bind(("id", state_id))
        .await
        .unwrap();
    let rows: Vec<SeederStateRow> = result.take(0).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].hash.is_empty());
}

// ---------------------------------------------------------------------------
// B-04 follow-up — organization-level actions are withheld from an ordinary
// tenant's seeded roles, and revoked from tenants an older version granted
// them to.
//
// The scope guard in `axiam-api-rest` (`require_organization_principal`) is
// what actually refuses the request; these assertions pin the second layer, so
// that the grant is not merely unusable but absent.
// ---------------------------------------------------------------------------

/// A registry mixing the two kinds, so every assertion below shows both that
/// the organization-level action was withheld AND that an ordinary one next to
/// it survived — a filter that dropped everything would pass the first half
/// alone.
const SCOPED_REGISTRY: &[(&str, &str)] = &[
    ("users:list", "List users"),
    ("users:create", "Create a user"),
    ("ca_certificates:manage", "Manage organization CA material"),
    ("tenants:create", "Create a tenant"),
    ("organizations:create", "Create an organization"),
    // Shares a permission with tenant-level handlers, so it is deliberately
    // NOT organization-level and must survive.
    ("email_config:write", "Write the email configuration"),
];

async fn org_scope_tenant(db: &Db, organization_id: Uuid) -> Uuid {
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id,
            kind: TenantKind::Organization,
            name: "Organization scope".into(),
            slug: "org-scope".into(),
            metadata: None,
        })
        .await
        .expect("organization-scope tenant create failed")
        .id
}

async fn actions_of(db: &Db, tenant_id: Uuid, role_id: Uuid) -> Vec<String> {
    SurrealPermissionRepository::new(db.clone())
        .get_role_permissions(tenant_id, role_id)
        .await
        .unwrap()
        .into_iter()
        .map(|p| p.action)
        .collect()
}

#[tokio::test]
async fn ordinary_tenant_roles_are_not_seeded_with_organization_level_actions() {
    let (db, _org, tenant_id) = setup().await;
    seed_permissions(&db, tenant_id, SCOPED_REGISTRY)
        .await
        .unwrap();
    let roles = seed_default_roles(&db, tenant_id, SCOPED_REGISTRY)
        .await
        .unwrap();

    for (role, role_id) in [
        ("super-admin", roles.super_admin_role_id),
        ("admin", roles.admin_role_id),
    ] {
        let held = actions_of(&db, tenant_id, role_id).await;
        for withheld in [
            "ca_certificates:manage",
            "tenants:create",
            "organizations:create",
        ] {
            assert!(
                !held.contains(&withheld.to_string()),
                "{role} in an ordinary tenant must not be seeded with {withheld}; holds {held:?}"
            );
        }
        // The filter must be selective, not a blanket refusal.
        assert!(
            held.contains(&"users:create".to_string()),
            "{role} lost an ordinary tenant action; holds {held:?}"
        );
        assert!(
            held.contains(&"email_config:write".to_string()),
            "{role} lost email_config:write, which is shared with the \
             tenant-level handlers and must stay grantable; holds {held:?}"
        );
    }
}

#[tokio::test]
async fn the_organization_scope_is_seeded_with_the_organization_level_actions() {
    let (db, org_id, _tenant_id) = setup().await;
    let scope_id = org_scope_tenant(&db, org_id).await;
    seed_permissions(&db, scope_id, SCOPED_REGISTRY)
        .await
        .unwrap();
    let roles = seed_default_roles(&db, scope_id, SCOPED_REGISTRY)
        .await
        .unwrap();

    let held = actions_of(&db, scope_id, roles.super_admin_role_id).await;
    for action in [
        "ca_certificates:manage",
        "tenants:create",
        "organizations:create",
    ] {
        assert!(
            held.contains(&action.to_string()),
            "the organization scope's super-admin must keep {action}; holds {held:?}"
        );
    }
}

#[tokio::test]
async fn reconcile_revokes_an_organization_level_grant_an_older_version_made() {
    let (db, _org, tenant_id) = setup().await;
    seed_permissions(&db, tenant_id, SCOPED_REGISTRY)
        .await
        .unwrap();
    let roles = seed_default_roles(&db, tenant_id, SCOPED_REGISTRY)
        .await
        .unwrap();

    // Reproduce the pre-fix state: grant the organization-level actions to
    // super-admin and admin by hand, exactly as the old seeder did.
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let all = perm_repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
                search: None,
            },
        )
        .await
        .unwrap();
    let org_level: Vec<_> = all
        .items
        .iter()
        .filter(|p| {
            matches!(
                p.action.as_str(),
                "ca_certificates:manage" | "tenants:create" | "organizations:create"
            )
        })
        .collect();
    assert_eq!(
        org_level.len(),
        3,
        "fixture should carry three org-level permissions"
    );
    for perm in &org_level {
        for role_id in [roles.super_admin_role_id, roles.admin_role_id] {
            perm_repo
                .grant_to_role(tenant_id, role_id, perm.id)
                .await
                .unwrap();
        }
    }

    let outcome = reconcile_default_role_grants(&db, tenant_id)
        .await
        .expect("reconcile failed");
    assert_eq!(
        outcome,
        ReconcileOutcome {
            granted: 0,
            revoked: 6
        },
        "three organization-level actions across two roles must be revoked, \
         and nothing granted"
    );

    for role_id in [roles.super_admin_role_id, roles.admin_role_id] {
        let held = actions_of(&db, tenant_id, role_id).await;
        for action in [
            "ca_certificates:manage",
            "tenants:create",
            "organizations:create",
        ] {
            assert!(
                !held.contains(&action.to_string()),
                "{action} survived the revoke"
            );
        }
        assert!(
            held.contains(&"users:create".to_string()),
            "the revoke took an unrelated grant with it; holds {held:?}"
        );
    }

    // Steady state: with the grants gone there is nothing left to revoke.
    let second = reconcile_default_role_grants(&db, tenant_id)
        .await
        .expect("second reconcile failed");
    assert_eq!(
        second,
        ReconcileOutcome::default(),
        "the revoking reconcile must still be idempotent"
    );
}

#[tokio::test]
async fn reconcile_leaves_the_organization_scopes_grants_alone() {
    let (db, org_id, _tenant_id) = setup().await;
    let scope_id = org_scope_tenant(&db, org_id).await;
    seed_permissions(&db, scope_id, SCOPED_REGISTRY)
        .await
        .unwrap();
    let roles = seed_default_roles(&db, scope_id, SCOPED_REGISTRY)
        .await
        .unwrap();

    let outcome = reconcile_default_role_grants(&db, scope_id)
        .await
        .expect("reconcile failed");
    assert_eq!(
        outcome,
        ReconcileOutcome::default(),
        "the organization scope is already correct — reconcile must not touch it"
    );

    let held = actions_of(&db, scope_id, roles.super_admin_role_id).await;
    assert!(held.contains(&"ca_certificates:manage".to_string()));
}

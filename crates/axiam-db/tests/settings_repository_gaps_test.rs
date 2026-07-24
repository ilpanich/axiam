//! Coverage for `SurrealSettingsRepository` branches not exercised by
//! `req14_settings_migration_test.rs` (which only covers baseline
//! propagation and idempotent migrations): the never-configured org
//! defaults branch, `get_tenant_override`'s "no row yet" branch,
//! `delete_tenant_override`, and `get_effective_settings` falling back to
//! the org baseline when no tenant row exists.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::{SetOrgSettings, SetTenantOverride, system_defaults};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{OrganizationRepository, SettingsRepository, TenantRepository};
use axiam_db::{SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // org_id
    uuid::Uuid, // tenant_id
) {
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

/// `get_org_settings` for an org that never had settings persisted must
/// return system defaults with the sentinel epoch timestamps, not an error.
#[tokio::test]
async fn get_org_settings_returns_system_defaults_when_unset() {
    let (db, org_id, _tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    let settings = repo.get_org_settings(org_id).await.unwrap();
    let defaults = system_defaults();

    assert_eq!(settings.password.min_length, defaults.min_length);
    assert_eq!(settings.mfa.mfa_enforced, defaults.mfa_enforced);
    assert_eq!(
        settings.created_at,
        chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        "never-configured org settings use the epoch sentinel timestamp"
    );
}

/// `get_tenant_override` for a tenant with no stored override row returns
/// `Ok(None)` rather than an error.
#[tokio::test]
async fn get_tenant_override_none_when_unset() {
    let (db, _org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    let result = repo.get_tenant_override(tenant_id).await.unwrap();
    assert!(result.is_none());
}

/// After `set_tenant_override`, `get_tenant_override` returns the stored
/// sparse mask (the V16+ overrides_json path).
#[tokio::test]
async fn get_tenant_override_returns_stored_sparse_mask() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    repo.set_org_settings(org_id, system_defaults())
        .await
        .unwrap();

    repo.set_tenant_override(
        tenant_id,
        SetTenantOverride {
            mfa_enforced: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let overrides = repo
        .get_tenant_override(tenant_id)
        .await
        .unwrap()
        .expect("override row must exist after set_tenant_override");
    assert_eq!(overrides.mfa_enforced, Some(true));
}

/// `delete_tenant_override` removes the tenant row so subsequent reads fall
/// back to the org baseline (get_effective_settings' "no tenant row" arm).
#[tokio::test]
async fn delete_tenant_override_falls_back_to_org_baseline() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    let d = system_defaults();
    repo.set_org_settings(
        org_id,
        SetOrgSettings {
            min_length: 16,
            ..d
        },
    )
    .await
    .unwrap();

    repo.set_tenant_override(
        tenant_id,
        SetTenantOverride {
            mfa_enforced: Some(true),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    // Tenant override exists and is reflected in effective settings.
    let before = repo
        .get_effective_settings(org_id, tenant_id)
        .await
        .unwrap();
    assert!(before.mfa.mfa_enforced);

    repo.delete_tenant_override(tenant_id).await.unwrap();

    // No override row anymore.
    assert!(repo.get_tenant_override(tenant_id).await.unwrap().is_none());

    // Effective settings now equal the org baseline exactly (fallback arm).
    let after = repo
        .get_effective_settings(org_id, tenant_id)
        .await
        .unwrap();
    assert_eq!(after.password.min_length, 16);
    assert!(
        !after.mfa.mfa_enforced,
        "override cleared — effective settings must revert to org baseline"
    );
    assert_eq!(
        after.created_at,
        chrono::DateTime::<chrono::Utc>::UNIX_EPOCH,
        "tenant re-scope after deletion uses the epoch sentinel"
    );
}

/// `get_effective_settings` for a tenant that never had an override row
/// (never called `set_tenant_override`/`store_effective_tenant_settings`)
/// returns the org baseline re-scoped as a tenant.
#[tokio::test]
async fn get_effective_settings_no_tenant_row_uses_org_baseline() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    let d = system_defaults();
    repo.set_org_settings(
        org_id,
        SetOrgSettings {
            min_length: 20,
            ..d
        },
    )
    .await
    .unwrap();

    let effective = repo
        .get_effective_settings(org_id, tenant_id)
        .await
        .unwrap();
    assert_eq!(effective.password.min_length, 20);
    assert_eq!(effective.scope_id, tenant_id);
}

/// `set_org_settings` called twice for the same org UPSERTs the same
/// deterministic row rather than creating a duplicate.
#[tokio::test]
async fn set_org_settings_twice_upserts_same_row() {
    let (db, org_id, _tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    let first = repo
        .set_org_settings(
            org_id,
            SetOrgSettings {
                min_length: 8,
                ..system_defaults()
            },
        )
        .await
        .unwrap();

    let second = repo
        .set_org_settings(
            org_id,
            SetOrgSettings {
                min_length: 9,
                ..system_defaults()
            },
        )
        .await
        .unwrap();

    assert_eq!(first.id, second.id, "same deterministic row must be reused");
    assert_eq!(second.password.min_length, 9);
}

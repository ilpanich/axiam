//! REQ-14 AC-3/AC-5 — sparse tenant settings propagation and idempotent migrations.

use axiam_core::models::settings::{SetOrgSettings, SetTenantOverride, system_defaults};
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::repository::{OrganizationRepository, SettingsRepository, TenantRepository};
use axiam_db::{
    SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup_db() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// CQ-B03/SEC-033: Tenant settings store only sparse overrides; org baseline
/// change propagates to tenants that did NOT explicitly override that field.
#[tokio::test]
async fn settings_baseline_propagates() {
    let db = setup_db().await;
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let settings_repo = SurrealSettingsRepository::new(db.clone());

    // Create org + tenant.
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Set org baseline: pw_min_length = 10, mfa_enforced = false.
    let defaults = system_defaults();
    settings_repo
        .set_org_settings(org.id, SetOrgSettings {
            min_length: 10,
            mfa_enforced: false,
            ..defaults
        })
        .await
        .unwrap();

    // Tenant overrides only field X (mfa_enforced = true), NOT field Y (pw_min_length).
    // min_length is None => inherits from org.
    let tenant_override = SetTenantOverride {
        mfa_enforced: Some(true), // explicit override (X)
        min_length: None,         // NOT overridden — inherits from org (Y)
        ..SetTenantOverride::default()
    };
    settings_repo
        .set_tenant_override(tenant.id, tenant_override)
        .await
        .unwrap();

    // Change org baseline for field Y (pw_min_length) from 10 → 12.
    let defaults2 = system_defaults();
    settings_repo
        .set_org_settings(org.id, SetOrgSettings {
            min_length: 12, // changed baseline
            mfa_enforced: false,
            ..defaults2
        })
        .await
        .unwrap();

    // Read tenant effective settings.
    let effective = settings_repo
        .get_effective_settings(org.id, tenant.id)
        .await
        .unwrap();

    // Field Y (pw_min_length) MUST reflect the new org baseline (12).
    assert_eq!(
        effective.password.min_length, 12,
        "org baseline change must propagate to tenant (CQ-B03)"
    );
    // Field X (mfa_enforced) MUST keep the tenant override (true).
    assert!(
        effective.mfa.mfa_enforced,
        "tenant override must be preserved (mfa_enforced = true)"
    );
}

/// store_effective_tenant_settings must also store sparse overrides so that
/// a later org baseline change propagates to non-overridden fields.
#[tokio::test]
async fn store_effective_propagates_baseline() {
    let db = setup_db().await;
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let settings_repo = SurrealSettingsRepository::new(db.clone());

    let org = org_repo
        .create(CreateOrganization {
            name: "Org2".into(),
            slug: "org2".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant2".into(),
            slug: "tenant2".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Set org baseline: pw_min_length = 10.
    let d1 = system_defaults();
    settings_repo
        .set_org_settings(org.id, SetOrgSettings { min_length: 10, ..d1 })
        .await
        .unwrap();

    // Call store_effective_tenant_settings with a fully merged settings object
    // that has mfa_enforced=true as the only real override (min_length matches org).
    let org_settings = settings_repo.get_org_settings(org.id).await.unwrap();
    let merged = axiam_core::models::settings::effective_settings(
        &org_settings,
        &SetTenantOverride {
            mfa_enforced: Some(true),
            ..Default::default()
        },
        tenant.id,
        Uuid::nil(),
    );
    settings_repo
        .store_effective_tenant_settings(tenant.id, merged)
        .await
        .unwrap();

    // Now change org baseline: pw_min_length = 14.
    let d2 = system_defaults();
    settings_repo
        .set_org_settings(org.id, SetOrgSettings { min_length: 14, ..d2 })
        .await
        .unwrap();

    // Tenant effective settings must pick up the new pw_min_length (14).
    let effective = settings_repo
        .get_effective_settings(org.id, tenant.id)
        .await
        .unwrap();
    assert_eq!(
        effective.password.min_length, 14,
        "store_effective_tenant_settings must not snapshot stale org fields (CQ-B03)"
    );
    // Override still preserved.
    assert!(effective.mfa.mfa_enforced, "mfa_enforced override must persist");
}

/// CQ-B06: Migrations run twice without error (idempotent + transactional).
#[tokio::test]
async fn migration_runs_twice() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();

    // First run.
    axiam_db::run_migrations(&db)
        .await
        .expect("first migration run must succeed");

    // Second run must also succeed (idempotent).
    axiam_db::run_migrations(&db)
        .await
        .expect("second migration run must succeed (idempotent)");
}

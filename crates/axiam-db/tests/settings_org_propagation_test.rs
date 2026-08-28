//! An organization baseline change must reach the tenants that already exist.
//!
//! Tenant settings are stored as a **sparse override mask**, so a tenant that
//! never touched a field has always tracked the organization's value for it.
//! The gap was the other half: a tenant that *had* written an override kept it
//! forever, even once the organization's baseline moved past it. Raise
//! `min_length` to 16, or switch `opaque_mode` from `disabled` to `required`,
//! and every such tenant silently stayed below the new floor — while the
//! organization settings page showed the control as on, and tenants without an
//! override genuinely did inherit it. Which tenants were which was visible
//! nowhere.
//!
//! `validate_tenant_override` enforces "a tenant may only tighten" when an
//! override is written. These tests are about the same rule holding when the
//! **baseline** changes, which is what `clamp_overrides_to_org` adds — applied
//! on every read, so the guarantee does not depend on a repair pass having run,
//! on the row's schema version, or on how the row got there.

use axiam_core::models::opaque::{OpaqueKsf, OpaqueMode, OpaqueSuite};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::{
    SetOrgSettings, SetTenantOverride, clamp_overrides_to_org, system_defaults,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OrganizationRepository, SettingsRepository, TenantRepository};
use axiam_db::{SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Propagation Org".into(),
            slug: "propagation-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Propagation Tenant".into(),
            slug: "propagation-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

fn org_settings_with(min_length: u32, opaque_mode: OpaqueMode) -> SetOrgSettings {
    SetOrgSettings {
        min_length,
        opaque_mode,
        opaque_suite: OpaqueSuite::Ristretto255Sha512,
        opaque_ksf: OpaqueKsf::Argon2id,
        ..system_defaults()
    }
}

/// The reported behaviour: an organization tightens, and a tenant that had
/// chosen an intermediate value is brought up to the new floor.
#[tokio::test]
async fn raising_the_org_baseline_overtakes_a_weaker_tenant_override() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Disabled))
        .await
        .unwrap();

    // Legal when written: 12 is stricter than the organization's 8.
    repo.set_tenant_override(
        tenant_id,
        SetTenantOverride {
            min_length: Some(12),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let effective = repo.get_effective_settings(org_id, tenant_id).await.unwrap();
    assert_eq!(effective.password.min_length, 12, "the tenant's own choice");

    // The organization now requires 16. The tenant's 12 is below that floor.
    repo.set_org_settings(org_id, org_settings_with(16, OpaqueMode::Disabled))
        .await
        .unwrap();

    let effective = repo.get_effective_settings(org_id, tenant_id).await.unwrap();
    assert_eq!(
        effective.password.min_length, 16,
        "an org baseline the tenant override no longer satisfies must win — this \
         is the whole point of the tighten-only rule, and it used to apply only \
         at the moment the override was written"
    );
}

/// The other half of the same rule: tightening the organization must not undo
/// a tenant that had gone further.
#[tokio::test]
async fn a_stricter_tenant_override_survives_the_org_baseline_moving() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Disabled))
        .await
        .unwrap();
    repo.set_tenant_override(
        tenant_id,
        SetTenantOverride {
            min_length: Some(24),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    repo.set_org_settings(org_id, org_settings_with(16, OpaqueMode::Disabled))
        .await
        .unwrap();

    let effective = repo.get_effective_settings(org_id, tenant_id).await.unwrap();
    assert_eq!(
        effective.password.min_length, 24,
        "a tenant that chose to go further keeps its choice; the baseline is a \
         floor, not an assignment"
    );
}

/// Switching OPAQUE on at the organization switches it on for a tenant that had
/// explicitly recorded `disabled`.
///
/// This is the case the report named: enabling OPAQUE for an organization has to
/// reach every tenant under it, not only the ones that never opened their own
/// settings page.
#[tokio::test]
async fn enabling_opaque_at_the_org_reaches_a_tenant_that_recorded_disabled() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Disabled))
        .await
        .unwrap();
    repo.set_tenant_override(
        tenant_id,
        SetTenantOverride {
            opaque_mode: Some(OpaqueMode::Disabled),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Optional))
        .await
        .unwrap();
    let effective = repo.get_effective_settings(org_id, tenant_id).await.unwrap();
    assert_eq!(effective.opaque.opaque_mode, OpaqueMode::Optional);

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Required))
        .await
        .unwrap();
    let effective = repo.get_effective_settings(org_id, tenant_id).await.unwrap();
    assert_eq!(
        effective.opaque.opaque_mode,
        OpaqueMode::Required,
        "a tenant cannot hold itself below the organization's OPAQUE mode"
    );
}

/// A tenant that went *past* the organization on OPAQUE keeps its position.
#[tokio::test]
async fn a_tenant_ahead_of_the_org_on_opaque_keeps_its_mode() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Disabled))
        .await
        .unwrap();
    repo.set_tenant_override(
        tenant_id,
        SetTenantOverride {
            opaque_mode: Some(OpaqueMode::Required),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Optional))
        .await
        .unwrap();

    let effective = repo.get_effective_settings(org_id, tenant_id).await.unwrap();
    assert_eq!(effective.opaque.opaque_mode, OpaqueMode::Required);
}

/// A tenant with no override of its own tracks the baseline, as it always did.
///
/// Kept alongside the clamping cases so a future change to `clamp_overrides_to_org`
/// cannot quietly turn inheritance into something that only works for tenants
/// which once wrote an override.
#[tokio::test]
async fn a_tenant_with_no_override_still_tracks_the_baseline() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    repo.set_org_settings(org_id, org_settings_with(20, OpaqueMode::Optional))
        .await
        .unwrap();

    let effective = repo.get_effective_settings(org_id, tenant_id).await.unwrap();
    assert_eq!(effective.password.min_length, 20);
    assert_eq!(effective.opaque.opaque_mode, OpaqueMode::Optional);
}

/// `clamp_overrides_to_org` clears the offending field rather than rewriting it
/// to the baseline value.
///
/// The distinction matters for the *next* baseline change: an absent override
/// keeps tracking, while a value written in would freeze at today's level and
/// need the same repair all over again one change later.
#[tokio::test]
async fn clamping_clears_the_field_rather_than_pinning_it() {
    let (db, org_id, tenant_id) = setup().await;
    let repo = SurrealSettingsRepository::new(db);

    repo.set_org_settings(org_id, org_settings_with(8, OpaqueMode::Disabled))
        .await
        .unwrap();
    repo.set_tenant_override(
        tenant_id,
        SetTenantOverride {
            min_length: Some(12),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let org = repo
        .get_org_settings(org_id)
        .await
        .map(|mut o| {
            o.password.min_length = 16;
            o
        })
        .unwrap();

    let mut overrides = repo.get_tenant_override(tenant_id).await.unwrap().unwrap();
    let cleared = clamp_overrides_to_org(&org, &mut overrides);

    assert_eq!(cleared, vec!["min_length"]);
    assert_eq!(overrides.min_length, None, "cleared, not pinned to 16");
}

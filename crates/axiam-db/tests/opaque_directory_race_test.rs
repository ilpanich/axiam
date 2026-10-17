//! Item 10 of the 1.1.0 atomicity audit: enabling a directory and making
//! `opaque_mode` `required` never both land.
//!
//! Under `required` a tenant refuses password sign-in before reading a
//! password, so directory accounts (which have no OPAQUE record) cannot sign in
//! at all; each side refuses the other (G-3). The refusals were reads made
//! before the write, and the two writes touch different rows, so an enable and
//! a `required` sent together each passed on the other's "before" state and
//! both landed. Both writes now compare and move `tenant.opaque_directory_epoch`
//! (schema v106), read before the read their rule decides on.
//!
//! The race runs on `surrealkv` (`tests/common`), the engine production runs.
//! Each round, both writers read the claim and then their rule's read (each
//! sees the other side as it was), wait at a barrier, then write at once.

mod common;

use std::sync::OnceLock;

use axiam_core::error::AxiamError;
use axiam_core::models::directory::{DirectoryKind, NewDirectoryConfig};
use axiam_core::models::opaque::OpaqueMode;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::{TenantSettingsOverride, system_defaults};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    DirectoryConfigRepository, OrganizationRepository, SettingsRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealDirectoryConfigRepository, SurrealOrganizationRepository, SurrealSettingsRepository,
    SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Db;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Rounds per run; the test was also run 20 times in a row.
const ROUNDS: usize = 8;

fn key() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        key
    })
}

async fn org_and_tenant(db: &Surreal<Db>, n: usize) -> (Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {n}"),
            slug: format!("org-{n}"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = new_tenant(db, org.id, &format!("tenant-{n}")).await;
    (org.id, tenant)
}

async fn new_tenant(db: &Surreal<Db>, org_id: Uuid, slug: &str) -> Uuid {
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: slug.to_owned(),
            slug: slug.to_owned(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

fn directory(tenant_id: Uuid, enabled: bool, secret: bool) -> NewDirectoryConfig {
    NewDirectoryConfig {
        tenant_id,
        enabled,
        kind: DirectoryKind::ActiveDirectory,
        url: "ldaps://dc01.corp.example.com:636".into(),
        start_tls: false,
        bind_dn: "CN=svc-axiam,OU=Service,DC=corp,DC=example,DC=com".into(),
        bind_secret: secret.then(|| Zeroizing::new(format!("Fx1!{}", Uuid::new_v4().simple()))),
        base_dn: "OU=People,DC=corp,DC=example,DC=com".into(),
        user_filter: "(&(objectClass=user)(sAMAccountName={username}))".into(),
        user_attribute_map: DirectoryKind::ActiveDirectory.default_user_attribute_map(),
        group_base_dn: None,
        group_filter: None,
        group_member_attribute: "memberOf".into(),
        group_nesting_depth: 4,
        group_mappings: vec![],
        sync_interval_secs: 900,
        jit_provisioning: true,
        trust_anchors_pem: vec![],
    }
}

fn required() -> TenantSettingsOverride {
    TenantSettingsOverride {
        opaque_mode: Some(OpaqueMode::Required),
        ..Default::default()
    }
}

fn is_changed_since_read(e: &AxiamError) -> bool {
    matches!(e, AxiamError::Conflict { reason } if reason.contains("changed since"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enable_and_a_required_sent_together_never_both_land() {
    let db = common::serialising_db().await;
    for round in 0..ROUNDS {
        let (org_id, tenant_id) = org_and_tenant(&db, round).await;
        let dirs = SurrealDirectoryConfigRepository::new(db.handle(), Some(key()));
        dirs.create(directory(tenant_id, false, true))
            .await
            .unwrap();
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

        // The directory save: claim, then the settings its refusal reads.
        let enable = {
            let (barrier, settings, dirs) = (
                barrier.clone(),
                SurrealSettingsRepository::new(db.handle()),
                SurrealDirectoryConfigRepository::new(db.handle(), Some(key())),
            );
            tokio::spawn(async move {
                let claim = settings.opaque_directory_claim(tenant_id).await.unwrap();
                let effective = settings
                    .get_effective_settings(org_id, tenant_id)
                    .await
                    .unwrap();
                assert_ne!(effective.opaque.opaque_mode, OpaqueMode::Required);
                barrier.wait().await;
                dirs.update_claimed(directory(tenant_id, true, false), claim)
                    .await
                    .map(|_| ())
            })
        };
        // The settings write: claim, then the directory its refusal reads.
        let require = {
            let (barrier, settings, dirs) = (
                barrier.clone(),
                SurrealSettingsRepository::new(db.handle()),
                SurrealDirectoryConfigRepository::new(db.handle(), Some(key())),
            );
            tokio::spawn(async move {
                let claim = settings.opaque_directory_claim(tenant_id).await.unwrap();
                let stored = dirs.get_by_tenant(tenant_id).await.unwrap().unwrap();
                assert!(!stored.enabled);
                barrier.wait().await;
                settings
                    .set_tenant_override_claimed(tenant_id, required(), claim)
                    .await
                    .map(|_| ())
            })
        };
        let mut landed = 0;
        for outcome in [enable.await.unwrap(), require.await.unwrap()] {
            match outcome {
                Ok(()) => landed += 1,
                Err(e) => assert!(is_changed_since_read(&e), "round {round}: {e:?}"),
            }
        }
        assert_eq!(landed, 1, "round {round}: exactly one write lands");

        let settings = SurrealSettingsRepository::new(db.handle());
        let mode = settings
            .get_effective_settings(org_id, tenant_id)
            .await
            .unwrap()
            .opaque
            .opaque_mode;
        let enabled = dirs
            .get_by_tenant(tenant_id)
            .await
            .unwrap()
            .unwrap()
            .enabled;
        assert!(
            !(enabled && mode == OpaqueMode::Required),
            "round {round}: an enabled directory under `required`"
        );
    }
}

/// Sequentially: a claim read before the other side's write is stale, for a
/// directory create too, and a stale write changes nothing.
#[tokio::test]
async fn a_claim_read_before_the_other_side_wrote_is_conflict() {
    let db = common::serialising_db().await;
    let (_, tenant_id) = org_and_tenant(&db, 0).await;
    let settings = SurrealSettingsRepository::new(db.handle());
    let dirs = SurrealDirectoryConfigRepository::new(db.handle(), Some(key()));

    let before = settings.opaque_directory_claim(tenant_id).await.unwrap();
    settings
        .set_tenant_override_claimed(tenant_id, required(), before)
        .await
        .unwrap();
    let stale = dirs
        .create_claimed(directory(tenant_id, true, true), before)
        .await;
    assert!(
        matches!(&stale, Err(e) if is_changed_since_read(e)),
        "{stale:?}"
    );
    assert!(dirs.get_by_tenant(tenant_id).await.unwrap().is_none());

    // A fresh claim is accepted by the repository (the handler's rule, not the
    // claim, is what refuses an enable under `required`).
    let fresh = settings.opaque_directory_claim(tenant_id).await.unwrap();
    assert_eq!(fresh.epoch, before.epoch + 1);
}

/// An organization baseline of `required` claims every live tenant, and is
/// refused when a tenant appeared since its claims were read.
#[tokio::test]
async fn an_organization_baseline_is_refused_when_a_tenant_appeared_since_the_read() {
    let db = common::serialising_db().await;
    let (org_id, first) = org_and_tenant(&db, 0).await;
    let settings = SurrealSettingsRepository::new(db.handle());

    let claims = settings.opaque_directory_claims(org_id).await.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].tenant_id, first);
    let _second = new_tenant(&db, org_id, "tenant-second").await;

    let mut baseline = system_defaults();
    baseline.opaque_mode = OpaqueMode::Required;
    let refused = settings
        .set_org_settings_claimed(org_id, baseline.clone(), &claims)
        .await;
    assert!(
        matches!(&refused, Err(e) if is_changed_since_read(e)),
        "{refused:?}"
    );
    assert_ne!(
        settings
            .get_org_settings(org_id)
            .await
            .unwrap()
            .opaque
            .opaque_mode,
        OpaqueMode::Required,
        "a refused baseline writes nothing"
    );

    let claims = settings.opaque_directory_claims(org_id).await.unwrap();
    assert_eq!(claims.len(), 2);
    let written = settings
        .set_org_settings_claimed(org_id, baseline, &claims)
        .await
        .unwrap();
    assert_eq!(written.opaque.opaque_mode, OpaqueMode::Required);
    for claim in settings.opaque_directory_claims(org_id).await.unwrap() {
        assert_eq!(claim.epoch, 1, "every tenant's epoch moved once");
    }
}

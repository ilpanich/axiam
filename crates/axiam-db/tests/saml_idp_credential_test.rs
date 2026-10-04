//! The SAML IdP signing-credential repository against the real datastore
//! (T23.2.1, G-2, D-21, schema v72).
//!
//! What lives in the datastore rather than in plain Rust: the one-active /
//! one-next-per-tenant rule (a unique index over a computed slot), tenant
//! isolation on every verb, ciphertext as the only form of the key, and the row
//! going with its tenant inside the tenant-delete transaction. The repository
//! stores opaque certificate text and opaque ciphertext; sealing and issuance
//! are `axiam_pki`'s and are tested there.
//!
//! No assertion message in this file formats a certificate, a key or an id.

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredentialStatus, SealedSamlIdpKey, StoreSamlIdpCredential,
};
use axiam_core::models::saml_sp::{
    AcsEndpoint, NameIdFormat, SamlBinding, SamlServiceProviderInput,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    OrganizationRepository, SamlIdpCredentialRepository, SamlServiceProviderRepository,
    TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSamlIdpCredentialRepository,
    SurrealSamlServiceProviderRepository, SurrealTenantRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

mod common;

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn repo(db: &Surreal<Db>) -> SurrealSamlIdpCredentialRepository<Db> {
    SurrealSamlIdpCredentialRepository::new(db.clone())
}

/// Opaque stand-in for ciphertext: not a PEM, distinctive enough that its
/// absence from a debug string or a list result means something.
fn ciphertext() -> Vec<u8> {
    format!("ct-{}", Uuid::new_v4().simple()).into_bytes()
}

fn store(
    tenant_id: Uuid,
    status: SamlIdpCredentialStatus,
    ciphertext: Vec<u8>,
) -> StoreSamlIdpCredential {
    let now = Utc::now();
    StoreSamlIdpCredential {
        id: Uuid::now_v7(),
        tenant_id,
        issuer_ca_id: Uuid::new_v4(),
        certificate_pem: format!("opaque-cert-{}", Uuid::new_v4().simple()),
        serial: Uuid::new_v4().simple().to_string(),
        fingerprint: Uuid::new_v4().simple().to_string(),
        not_before: now,
        not_after: now + Duration::days(365),
        status,
        key: SealedSamlIdpKey {
            custody: CaKeyCustody::Database,
            locator: None,
            ciphertext: Some(ciphertext),
        },
    }
}

#[tokio::test]
async fn create_round_trips_the_public_facts_and_the_key_comes_back_only_sealed() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let sealed = ciphertext();
    let input = store(tenant, SamlIdpCredentialStatus::Active, sealed.clone());
    let created = repo.create(input.clone()).await.unwrap();

    assert_eq!(created.id, input.id);
    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.issuer_ca_id, input.issuer_ca_id);
    assert_eq!(created.certificate_pem, input.certificate_pem);
    assert_eq!(created.serial, input.serial);
    assert_eq!(created.fingerprint, input.fingerprint);
    assert_eq!(created.status, SamlIdpCredentialStatus::Active);
    assert_eq!(created.key_custody, CaKeyCustody::Database);
    assert!(created.retired_at.is_none());

    // get / get_active / list return the same credential and have no key field.
    assert_eq!(repo.get(tenant, created.id).await.unwrap(), created);
    assert_eq!(
        repo.get_active(tenant).await.unwrap(),
        Some(created.clone())
    );
    assert_eq!(repo.list(tenant).await.unwrap(), vec![created.clone()]);

    // The one path that returns a key returns it sealed, byte for byte.
    let with_key = repo.get_active_sealed(tenant).await.unwrap().unwrap();
    assert_eq!(with_key.credential, created);
    assert_eq!(with_key.key.custody, CaKeyCustody::Database);
    assert_eq!(with_key.key.ciphertext.as_deref(), Some(sealed.as_slice()));
    assert!(with_key.key.locator.is_none());

    // Its Debug prints no ciphertext.
    let shown = format!("{with_key:?}");
    assert!(shown.contains("[REDACTED]"));
    assert!(!shown.contains(&String::from_utf8(sealed).unwrap()));
}

/// What the datastore holds is exactly the bytes the repository was given: the
/// column is `bytes`, so there is no text form a plaintext key could take.
#[tokio::test]
async fn the_key_column_holds_only_the_bytes_it_was_given() {
    #[derive(Debug, SurrealValue)]
    struct Raw {
        encrypted_private_key: Option<surrealdb_types::Bytes>,
        certificate_pem: String,
    }
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let sealed = ciphertext();
    let created = repo
        .create(store(
            tenant,
            SamlIdpCredentialStatus::Active,
            sealed.clone(),
        ))
        .await
        .unwrap();

    let mut result = db
        .query(
            "SELECT encrypted_private_key, certificate_pem FROM saml_idp_credential \
             WHERE tenant_id = $t",
        )
        .bind(("t", tenant.to_string()))
        .await
        .unwrap();
    let rows: Vec<Raw> = result.take(0).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]
            .encrypted_private_key
            .as_ref()
            .map(|b| b.clone().into_inner().to_vec()),
        Some(sealed)
    );
    assert_eq!(rows[0].certificate_pem, created.certificate_pem);
}

#[tokio::test]
async fn a_second_active_credential_for_a_tenant_is_refused_by_the_database() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    repo.create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();

    let second = repo
        .create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
        .await;
    assert!(
        matches!(second, Err(AxiamError::AlreadyExists { .. })),
        "a second active credential must be AlreadyExists"
    );
    assert_eq!(repo.list(tenant).await.unwrap().len(), 1);

    // Not the repository's check: the same refusal comes from the datastore
    // when the row is written around it.
    let around = db
        .query(
            "CREATE saml_idp_credential SET tenant_id = $t, issuer_ca_id = 'x', \
             certificate_pem = 'x', serial = 'x', fingerprint = 'x', \
             not_before = time::now(), not_after = time::now(), status = 'active', \
             key_custody = 'database', created_at = time::now(), updated_at = time::now()",
        )
        .bind(("t", tenant.to_string()))
        .await
        .unwrap()
        .check();
    assert!(around.is_err(), "the unique slot index must refuse it");
}

#[tokio::test]
async fn a_second_next_credential_for_a_tenant_is_refused_and_active_and_next_coexist() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    repo.create(store(tenant, SamlIdpCredentialStatus::Next, ciphertext()))
        .await
        .unwrap();
    assert!(matches!(
        repo.create(store(tenant, SamlIdpCredentialStatus::Next, ciphertext()))
            .await,
        Err(AxiamError::AlreadyExists { .. })
    ));
    // The other slot is free.
    repo.create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();
    assert_eq!(repo.list(tenant).await.unwrap().len(), 2);
}

#[tokio::test]
async fn two_tenants_each_hold_their_own_active_credential() {
    let db = setup().await;
    let repo = repo(&db);
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let ca = repo
        .create(store(a, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();
    let cb = repo
        .create(store(b, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();
    assert_eq!(repo.get_active(a).await.unwrap().unwrap().id, ca.id);
    assert_eq!(repo.get_active(b).await.unwrap().unwrap().id, cb.id);
    assert_eq!(repo.get_active(Uuid::new_v4()).await.unwrap(), None);
    assert!(
        repo.get_active_sealed(Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn a_credential_cannot_be_created_retired() {
    let db = setup().await;
    let repo = repo(&db);
    assert!(matches!(
        repo.create(store(
            Uuid::new_v4(),
            SamlIdpCredentialStatus::Retired,
            ciphertext()
        ))
        .await,
        Err(AxiamError::Validation { .. })
    ));
}

#[tokio::test]
async fn retire_frees_the_slot_destroys_the_key_and_is_idempotent() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let first = repo
        .create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();

    let retired = repo.retire(tenant, first.id).await.unwrap();
    assert_eq!(retired.status, SamlIdpCredentialStatus::Retired);
    let retired_at = retired.retired_at.expect("stamped");
    assert_eq!(repo.get_active(tenant).await.unwrap(), None);
    assert!(repo.get_active_sealed(tenant).await.unwrap().is_none());

    // The key is gone from the row, not merely hidden from the lookup.
    #[derive(Debug, SurrealValue)]
    struct Raw {
        encrypted_private_key: Option<surrealdb_types::Bytes>,
    }
    let mut result = db
        .query("SELECT encrypted_private_key FROM saml_idp_credential WHERE tenant_id = $t")
        .bind(("t", tenant.to_string()))
        .await
        .unwrap();
    let rows: Vec<Raw> = result.take(0).unwrap();
    assert!(rows.iter().all(|r| r.encrypted_private_key.is_none()));

    // Retiring again changes nothing, including the timestamp.
    let again = repo.retire(tenant, first.id).await.unwrap();
    assert_eq!(again.retired_at, Some(retired_at));

    // The slot is free: a new active credential is allowed, and retired rows are
    // unbounded, each in a slot of its own.
    for _ in 0..3 {
        let next_active = repo
            .create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
            .await
            .unwrap();
        repo.retire(tenant, next_active.id).await.unwrap();
    }
    let all = repo.list(tenant).await.unwrap();
    assert_eq!(all.len(), 4);
    assert!(
        all.iter()
            .all(|c| c.status == SamlIdpCredentialStatus::Retired)
    );
}

#[tokio::test]
async fn a_next_credential_is_not_the_active_one() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    repo.create(store(tenant, SamlIdpCredentialStatus::Next, ciphertext()))
        .await
        .unwrap();
    assert_eq!(repo.get_active(tenant).await.unwrap(), None);
    assert!(repo.get_active_sealed(tenant).await.unwrap().is_none());
}

#[tokio::test]
async fn tenants_cannot_see_or_retire_each_others_credentials() {
    let db = setup().await;
    let repo = repo(&db);
    let owner = Uuid::new_v4();
    let intruder = Uuid::new_v4();
    let created = repo
        .create(store(owner, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();

    assert!(matches!(
        repo.get(intruder, created.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.retire(intruder, created.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(repo.list(intruder).await.unwrap().is_empty());
    assert_eq!(repo.get_active(intruder).await.unwrap(), None);
    assert!(repo.get_active_sealed(intruder).await.unwrap().is_none());

    // Nothing the intruder tried changed the owner's credential or its key.
    assert_eq!(repo.get(owner, created.id).await.unwrap(), created);
    assert!(
        repo.get_active_sealed(owner)
            .await
            .unwrap()
            .is_some_and(|c| c.key.ciphertext.is_some())
    );
}

#[tokio::test]
async fn the_schema_refuses_an_unknown_status_spelling() {
    let db = setup().await;
    let result = db
        .query(
            "CREATE saml_idp_credential SET tenant_id = 't', issuer_ca_id = 'x', \
             certificate_pem = 'x', serial = 'x', fingerprint = 'x', \
             not_before = time::now(), not_after = time::now(), status = 'pending', \
             key_custody = 'database', created_at = time::now(), updated_at = time::now()",
        )
        .await
        .unwrap()
        .check();
    assert!(result.is_err());
}

#[tokio::test]
async fn credentials_are_deleted_with_their_tenant() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let repo = repo(&db);

    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "saml-idp-cascade".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let make_tenant = |slug: &str| CreateTenant {
        organization_id: org,
        kind: TenantKind::Standard,
        name: slug.into(),
        slug: slug.into(),
        metadata: None,
    };
    let doomed = tenants.create(make_tenant("doomed")).await.unwrap().id;
    let kept = tenants.create(make_tenant("kept")).await.unwrap().id;
    for status in [
        SamlIdpCredentialStatus::Active,
        SamlIdpCredentialStatus::Next,
    ] {
        repo.create(store(doomed, status, ciphertext()))
            .await
            .unwrap();
    }
    let retired = repo
        .create(store(doomed, SamlIdpCredentialStatus::Active, ciphertext()))
        .await;
    assert!(
        retired.is_err(),
        "slot occupied; the retired row comes next"
    );
    let first = repo.get_active(doomed).await.unwrap().unwrap();
    repo.retire(doomed, first.id).await.unwrap();
    repo.create(store(kept, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();

    tenants.delete(doomed).await.unwrap();

    assert!(
        repo.list(doomed).await.unwrap().is_empty(),
        "deleting a tenant must delete its SAML signing credentials, retired ones included"
    );
    assert_eq!(
        repo.list(kept).await.unwrap().len(),
        1,
        "deleting one tenant must not touch another tenant's credential"
    );
}

/// The cascade is one transaction: a credential delete that fails takes the
/// service providers' delete back with it, and the failure is reported.
#[tokio::test]
async fn a_tenant_delete_that_fails_on_the_credentials_is_reported_and_removes_nothing() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let repo = repo(&db);
    let registry = SurrealSamlServiceProviderRepository::new(db.clone());

    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "saml-idp-cascade-failure".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let tenant = tenants
        .create(CreateTenant {
            organization_id: org,
            kind: TenantKind::Standard,
            name: "stuck".into(),
            slug: "stuck".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    repo.create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();
    registry
        .create(
            tenant,
            SamlServiceProviderInput {
                enabled: true,
                display_name: "Payroll".into(),
                entity_id: "https://payroll.example.com/metadata".into(),
                acs_urls: vec![AcsEndpoint {
                    url: "https://payroll.example.com/saml/acs".into(),
                    binding: SamlBinding::HttpPost,
                    index: 0,
                    is_default: true,
                }],
                slo_url: None,
                slo_binding: None,
                name_id_format: NameIdFormat::Persistent,
                sign_responses: true,
                encrypt_assertions: false,
                sp_signing_cert_pem: None,
                sp_encryption_cert_pem: None,
                want_authn_requests_signed: false,
                allow_idp_initiated: false,
                attribute_mappings: vec![],
                allowed_groups: vec![],
            },
        )
        .await
        .unwrap();
    db.query(
        "DEFINE EVENT refuse_credential_delete ON TABLE saml_idp_credential \
         WHEN $event = 'DELETE' THEN { THROW 'refused by the test' };",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    assert!(tenants.delete(tenant).await.is_err());
    assert!(tenants.get_by_id(tenant).await.is_ok());
    assert_eq!(repo.list(tenant).await.unwrap().len(), 1);
    assert_eq!(registry.list(tenant).await.unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// promote (T23.2.5, D-42)
// ---------------------------------------------------------------------------

/// A credential whose validity window is `[from, to]` around now.
fn windowed(
    tenant_id: Uuid,
    status: SamlIdpCredentialStatus,
    not_before: chrono::DateTime<Utc>,
    not_after: chrono::DateTime<Utc>,
) -> StoreSamlIdpCredential {
    StoreSamlIdpCredential {
        not_before,
        not_after,
        ..store(tenant_id, status, ciphertext())
    }
}

/// The key columns of every row of the tenant, straight from the datastore.
async fn key_columns(db: &Surreal<Db>, tenant: Uuid) -> Vec<(String, bool, bool)> {
    #[derive(Debug, SurrealValue)]
    struct Raw {
        status: String,
        encrypted_private_key: Option<surrealdb_types::Bytes>,
        key_locator: Option<String>,
    }
    let mut result = db
        .query(
            "SELECT status, encrypted_private_key, key_locator FROM saml_idp_credential \
             WHERE tenant_id = $t ORDER BY created_at ASC",
        )
        .bind(("t", tenant.to_string()))
        .await
        .unwrap();
    let rows: Vec<Raw> = result.take(0).unwrap();
    rows.into_iter()
        .map(|r| {
            (
                r.status,
                r.encrypted_private_key.is_some(),
                r.key_locator.is_some(),
            )
        })
        .collect()
}

#[tokio::test]
async fn promote_makes_next_active_retires_the_old_active_and_destroys_its_key() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let old = repo
        .create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();
    let next_cipher = ciphertext();
    let next = repo
        .create(store(
            tenant,
            SamlIdpCredentialStatus::Next,
            next_cipher.clone(),
        ))
        .await
        .unwrap();

    let promotion = repo.promote(tenant, next.id, Utc::now()).await.unwrap();
    assert_eq!(promotion.active.id, next.id);
    assert_eq!(promotion.active.status, SamlIdpCredentialStatus::Active);
    let retired = promotion.retired.expect("the old active is returned");
    assert_eq!(retired.id, old.id);
    assert_eq!(retired.status, SamlIdpCredentialStatus::Retired);
    assert!(retired.retired_at.is_some());
    assert!(promotion.active.retired_at.is_none());

    // The signer now finds the promoted credential, with its own key intact.
    let signer = repo.get_active_sealed(tenant).await.unwrap().unwrap();
    assert_eq!(signer.credential.id, next.id);
    assert_eq!(
        signer.key.ciphertext.as_deref(),
        Some(next_cipher.as_slice())
    );
    // The `next` slot is free again, and the old key is gone from its row.
    repo.create(store(tenant, SamlIdpCredentialStatus::Next, ciphertext()))
        .await
        .expect("the next slot is empty after a promotion");
    let columns = key_columns(&db, tenant).await;
    let retired_row = columns
        .iter()
        .find(|c| c.0 == "retired")
        .expect("one retired");
    assert!(
        !retired_row.1 && !retired_row.2,
        "the retired row holds no key material"
    );
    assert_eq!(columns.iter().filter(|c| c.0 == "active").count(), 1);
}

#[tokio::test]
async fn promote_with_no_active_credential_returns_none_for_retired() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let next = repo
        .create(store(tenant, SamlIdpCredentialStatus::Next, ciphertext()))
        .await
        .unwrap();
    let promotion = repo.promote(tenant, next.id, Utc::now()).await.unwrap();
    assert_eq!(promotion.active.id, next.id);
    assert!(promotion.retired.is_none());
    assert_eq!(repo.get_active(tenant).await.unwrap().unwrap().id, next.id);
}

#[tokio::test]
async fn a_promotion_that_cannot_happen_changes_nothing() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let now = Utc::now();
    let active = repo
        .create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
        .await
        .unwrap();
    let retired = {
        let created = repo
            .create(windowed(
                tenant,
                SamlIdpCredentialStatus::Next,
                now - Duration::days(1),
                now + Duration::days(30),
            ))
            .await
            .unwrap();
        repo.retire(tenant, created.id).await.unwrap()
    };
    let expired_next = repo
        .create(windowed(
            tenant,
            SamlIdpCredentialStatus::Next,
            now - Duration::days(40),
            now - Duration::days(10),
        ))
        .await
        .unwrap();
    let before = repo.list(tenant).await.unwrap();
    let keys_before = key_columns(&db, tenant).await;

    // Not the `next` credential: the active one, a retired one.
    for id in [active.id, retired.id] {
        assert!(
            matches!(
                repo.promote(tenant, id, now).await,
                Err(AxiamError::Conflict { .. })
            ),
            "only the current next may be promoted"
        );
    }
    // The `next` credential, but outside its window: expired, and not yet valid.
    assert!(matches!(
        repo.promote(tenant, expired_next.id, now).await,
        Err(AxiamError::Conflict { .. })
    ));
    assert!(matches!(
        repo.promote(tenant, expired_next.id, now - Duration::days(60))
            .await,
        Err(AxiamError::Conflict { .. })
    ));
    // Not this tenant's, and not anyone's.
    assert!(matches!(
        repo.promote(Uuid::new_v4(), expired_next.id, now).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.promote(tenant, Uuid::new_v4(), now).await,
        Err(AxiamError::NotFound { .. })
    ));

    assert_eq!(repo.list(tenant).await.unwrap(), before, "no row changed");
    assert_eq!(
        key_columns(&db, tenant).await,
        keys_before,
        "no key was touched"
    );
    assert_eq!(
        repo.get_active(tenant).await.unwrap().unwrap().id,
        active.id
    );
}

#[tokio::test]
async fn the_window_is_closed_at_not_before_and_open_at_not_after() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let now = Utc::now();
    let next = repo
        .create(windowed(
            tenant,
            SamlIdpCredentialStatus::Next,
            now,
            now + Duration::days(1),
        ))
        .await
        .unwrap();
    // `not_before <= now`: the instant itself is inside; a moment earlier is not.
    assert!(matches!(
        repo.promote(tenant, next.id, next.not_before - Duration::seconds(1))
            .await,
        Err(AxiamError::Conflict { .. })
    ));
    // `now < not_after`: the last instant is outside.
    assert!(matches!(
        repo.promote(tenant, next.id, next.not_after).await,
        Err(AxiamError::Conflict { .. })
    ));
    repo.promote(tenant, next.id, next.not_before)
        .await
        .unwrap();
}

/// Of concurrent promotions of one `next` credential exactly one wins and the
/// others are told `Conflict` — never two winners, never a state with two
/// signers or none. On the engine production runs: `kv-mem` aborts contended
/// attempts and occasionally misses the conflict (`tests/common`).
#[tokio::test]
async fn of_concurrent_promotions_exactly_one_wins() {
    let db = common::serialising_db().await;
    for round in 0..25 {
        let tenant = Uuid::new_v4();
        let repo = SurrealSamlIdpCredentialRepository::new(db.handle());
        repo.create(store(tenant, SamlIdpCredentialStatus::Active, ciphertext()))
            .await
            .unwrap();
        let next = repo
            .create(store(tenant, SamlIdpCredentialStatus::Next, ciphertext()))
            .await
            .unwrap();

        let racers = (0..4).map(|_| {
            let repo = SurrealSamlIdpCredentialRepository::new(db.handle());
            let id = next.id;
            tokio::spawn(async move { repo.promote(tenant, id, Utc::now()).await })
        });
        let outcomes: Vec<_> = futures_join_all(racers).await;
        let winners = outcomes.iter().filter(|o| o.is_ok()).count();
        let conflicts = outcomes
            .iter()
            .filter(|o| matches!(o, Err(AxiamError::Conflict { .. })))
            .count();
        assert_eq!(winners, 1, "round {round}: exactly one promotion wins");
        assert_eq!(
            conflicts,
            3,
            "round {round}: the rest are told Conflict, got {:?}",
            outcomes
                .iter()
                .filter_map(|o| o.as_ref().err())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );

        let all = repo.list(tenant).await.unwrap();
        let active: Vec<_> = all
            .iter()
            .filter(|c| c.status == SamlIdpCredentialStatus::Active)
            .collect();
        assert_eq!(active.len(), 1, "round {round}: exactly one signer");
        assert_eq!(active[0].id, next.id);
        assert_eq!(
            all.iter()
                .filter(|c| c.status == SamlIdpCredentialStatus::Retired)
                .count(),
            1
        );
    }
}

/// `futures::future::join_all` without the dependency: await the handles in turn.
async fn futures_join_all<T>(handles: impl Iterator<Item = tokio::task::JoinHandle<T>>) -> Vec<T> {
    let handles: Vec<_> = handles.collect();
    let mut out = Vec::new();
    for handle in handles {
        out.push(handle.await.expect("racer panicked"));
    }
    out
}

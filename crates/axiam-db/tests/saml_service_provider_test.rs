//! The SAML service-provider registry against the real datastore (T23.2.1,
//! G-2, schema v72).
//!
//! What lives in the datastore rather than in plain Rust: the round trip of
//! every field (including the two JSON-text lists), the unique
//! `(tenant_id, entity_id)` index, tenant isolation on every verb, the schema's
//! enumeration assertions, and the row going with its tenant. The repository
//! does not validate (the rules are `axiam_federation::saml_sp`'s), so these
//! cases store opaque certificate text and assert only on storage.
//!
//! No assertion message in this file formats a certificate or an identifier.

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::saml_sp::{
    AcsEndpoint, AttributeMapping, AttributeSource, NameIdFormat, SamlBinding,
    SamlServiceProviderInput,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{
    OrganizationRepository, SamlServiceProviderRepository, TenantRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSamlServiceProviderRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn repo(db: &Surreal<Db>) -> SurrealSamlServiceProviderRepository<Db> {
    SurrealSamlServiceProviderRepository::new(db.clone())
}

fn input(entity_id: &str) -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        enabled: true,
        display_name: "Payroll".into(),
        entity_id: entity_id.into(),
        acs_urls: vec![
            AcsEndpoint {
                url: "https://payroll.example.com/saml/acs".into(),
                binding: SamlBinding::HttpPost,
                index: 0,
                is_default: true,
            },
            AcsEndpoint {
                url: "https://payroll.example.com/saml/acs-b".into(),
                binding: SamlBinding::HttpPost,
                index: 1,
                is_default: false,
            },
        ],
        slo_url: Some("https://payroll.example.com/saml/slo".into()),
        slo_binding: Some(SamlBinding::HttpRedirect),
        name_id_format: NameIdFormat::EmailAddress,
        sign_responses: false,
        encrypt_assertions: true,
        sp_signing_cert_pem: Some(format!("opaque-{}", Uuid::new_v4())),
        sp_encryption_cert_pem: Some(format!("opaque-{}", Uuid::new_v4())),
        want_authn_requests_signed: true,
        allow_idp_initiated: true,
        attribute_mappings: vec![
            AttributeMapping {
                saml_name: "mail".into(),
                name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into()),
                source: AttributeSource::Email,
            },
            AttributeMapping {
                saml_name: "groups".into(),
                name_format: None,
                source: AttributeSource::Groups,
            },
        ],
        allowed_groups: vec![Uuid::new_v4(), Uuid::new_v4()],
    }
}

fn minimal(entity_id: &str) -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        enabled: true,
        display_name: "Minimal".into(),
        entity_id: entity_id.into(),
        acs_urls: vec![AcsEndpoint {
            url: "https://min.example.com/acs".into(),
            binding: SamlBinding::HttpPost,
            index: 0,
            is_default: false,
        }],
        slo_url: None,
        slo_binding: None,
        name_id_format: NameIdFormat::default(),
        sign_responses: true,
        encrypt_assertions: false,
        sp_signing_cert_pem: None,
        sp_encryption_cert_pem: None,
        want_authn_requests_signed: false,
        allow_idp_initiated: false,
        attribute_mappings: Vec::new(),
        allowed_groups: Vec::new(),
    }
}

#[tokio::test]
async fn create_round_trips_every_field() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let want = input("https://payroll.example.com/metadata");

    let created = repo.create(tenant, want.clone()).await.unwrap();
    assert_eq!(created.tenant_id, tenant);
    assert_eq!(created.enabled, want.enabled);
    assert_eq!(created.display_name, want.display_name);
    assert_eq!(created.entity_id, want.entity_id);
    assert_eq!(created.acs_urls, want.acs_urls);
    assert_eq!(created.slo_url, want.slo_url);
    assert_eq!(created.slo_binding, want.slo_binding);
    assert_eq!(created.name_id_format, want.name_id_format);
    assert_eq!(created.sign_responses, want.sign_responses);
    assert_eq!(created.encrypt_assertions, want.encrypt_assertions);
    assert_eq!(created.sp_signing_cert_pem, want.sp_signing_cert_pem);
    assert_eq!(created.sp_encryption_cert_pem, want.sp_encryption_cert_pem);
    assert_eq!(
        created.want_authn_requests_signed,
        want.want_authn_requests_signed
    );
    assert_eq!(created.allow_idp_initiated, want.allow_idp_initiated);
    assert_eq!(created.attribute_mappings, want.attribute_mappings);
    assert_eq!(created.allowed_groups, want.allowed_groups);
    assert!(created.updated_at >= created.created_at);

    let read = repo.get(tenant, created.id).await.unwrap();
    assert_eq!(read, created, "get returns exactly what create returned");
}

#[tokio::test]
async fn absent_optional_fields_round_trip_as_absent() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let created = repo
        .create(tenant, minimal("https://min.example.com/metadata"))
        .await
        .unwrap();
    assert_eq!(created.slo_url, None);
    assert_eq!(created.slo_binding, None);
    assert_eq!(created.sp_signing_cert_pem, None);
    assert_eq!(created.sp_encryption_cert_pem, None);
    assert!(created.attribute_mappings.is_empty());
    assert!(created.allowed_groups.is_empty());
    assert_eq!(created.name_id_format, NameIdFormat::Persistent);
    assert!(created.sign_responses);
    assert!(!created.encrypt_assertions);
    assert!(!created.allow_idp_initiated);
}

#[tokio::test]
async fn get_by_entity_id_finds_the_registration_and_only_in_its_tenant() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();
    let entity = "https://payroll.example.com/metadata";
    let created = repo.create(tenant, minimal(entity)).await.unwrap();

    let found = repo.get_by_entity_id(tenant, entity).await.unwrap();
    assert_eq!(found.map(|sp| sp.id), Some(created.id));
    assert!(
        repo.get_by_entity_id(other, entity)
            .await
            .unwrap()
            .is_none(),
        "another tenant cannot look an SP up by entity id"
    );
    assert!(
        repo.get_by_entity_id(tenant, "https://payroll.example.com/Metadata")
            .await
            .unwrap()
            .is_none(),
        "the entity id is matched exactly"
    );
}

#[tokio::test]
async fn the_entity_id_is_unique_per_tenant() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let entity = "https://payroll.example.com/metadata";
    repo.create(tenant, minimal(entity)).await.unwrap();

    let again = repo.create(tenant, minimal(entity)).await;
    assert!(
        matches!(again, Err(AxiamError::AlreadyExists { .. })),
        "a second registration of the same entity id must be AlreadyExists"
    );
    assert_eq!(repo.list(tenant).await.unwrap().len(), 1);

    // The same entity id in another tenant is a different registration.
    repo.create(Uuid::new_v4(), minimal(entity)).await.unwrap();
}

#[tokio::test]
async fn update_replaces_the_configuration_and_keeps_identity() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let created = repo
        .create(tenant, input("https://payroll.example.com/metadata"))
        .await
        .unwrap();

    let mut replacement = minimal("https://payroll.example.com/metadata-v2");
    replacement.display_name = "Payroll v2".into();
    let updated = repo.update(tenant, created.id, replacement).await.unwrap();

    assert_eq!(updated.id, created.id);
    assert_eq!(updated.tenant_id, tenant);
    assert_eq!(updated.created_at, created.created_at);
    assert!(updated.updated_at >= created.updated_at);
    assert_eq!(updated.display_name, "Payroll v2");
    assert_eq!(updated.entity_id, "https://payroll.example.com/metadata-v2");
    assert_eq!(updated.slo_url, None, "an update is a full replacement");
    assert!(updated.attribute_mappings.is_empty());
    assert!(updated.allowed_groups.is_empty());
    assert!(!updated.allow_idp_initiated);
}

#[tokio::test]
async fn update_to_another_sps_entity_id_is_already_exists_and_changes_nothing() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let first = repo
        .create(tenant, minimal("https://a.example.com/metadata"))
        .await
        .unwrap();
    repo.create(tenant, minimal("https://b.example.com/metadata"))
        .await
        .unwrap();

    let result = repo
        .update(tenant, first.id, minimal("https://b.example.com/metadata"))
        .await;
    assert!(matches!(result, Err(AxiamError::AlreadyExists { .. })));
    assert_eq!(
        repo.get(tenant, first.id).await.unwrap().entity_id,
        "https://a.example.com/metadata"
    );
}

#[tokio::test]
async fn list_is_oldest_first_and_tenant_scoped() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();
    let one = repo
        .create(tenant, minimal("https://one.example.com/m"))
        .await
        .unwrap();
    let two = repo
        .create(tenant, minimal("https://two.example.com/m"))
        .await
        .unwrap();
    repo.create(other, minimal("https://three.example.com/m"))
        .await
        .unwrap();

    let listed: Vec<Uuid> = repo
        .list(tenant)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.id)
        .collect();
    assert_eq!(listed, vec![one.id, two.id]);
    assert_eq!(repo.list(other).await.unwrap().len(), 1);
    assert!(repo.list(Uuid::new_v4()).await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_removes_the_registration_and_a_second_delete_is_not_found() {
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let created = repo
        .create(tenant, minimal("https://payroll.example.com/metadata"))
        .await
        .unwrap();

    repo.delete(tenant, created.id).await.unwrap();
    assert!(matches!(
        repo.get(tenant, created.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.delete(tenant, created.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    // The entity id is free again.
    repo.create(tenant, minimal("https://payroll.example.com/metadata"))
        .await
        .unwrap();
}

#[tokio::test]
async fn tenants_cannot_read_update_or_delete_each_others_registrations() {
    let db = setup().await;
    let repo = repo(&db);
    let owner = Uuid::new_v4();
    let intruder = Uuid::new_v4();
    let created = repo
        .create(owner, input("https://payroll.example.com/metadata"))
        .await
        .unwrap();

    assert!(matches!(
        repo.get(intruder, created.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.update(intruder, created.id, minimal("https://evil.example.com/m"))
            .await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        repo.delete(intruder, created.id).await,
        Err(AxiamError::NotFound { .. })
    ));

    // Nothing the intruder tried changed the owner's row.
    let intact = repo.get(owner, created.id).await.unwrap();
    assert_eq!(intact, created);
}

#[tokio::test]
async fn the_schema_refuses_an_unknown_enumeration_spelling() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    for (column, value) in [
        ("name_id_format", "transient"),
        ("slo_binding", "http_artifact"),
    ] {
        let sql = format!(
            "CREATE saml_service_provider SET tenant_id = $t, enabled = true, \
             display_name = 'x', entity_id = $e, acs_urls_json = '[]', \
             name_id_format = 'persistent', sign_responses = true, \
             encrypt_assertions = false, want_authn_requests_signed = false, \
             allow_idp_initiated = false, attribute_mappings_json = '[]', \
             created_at = time::now(), updated_at = time::now(), {column} = $v"
        );
        let result = db
            .query(sql)
            .bind(("t", tenant.to_string()))
            .bind(("e", Uuid::new_v4().to_string()))
            .bind(("v", value.to_string()))
            .await
            .unwrap();
        assert!(
            result.check().is_err(),
            "the schema must refuse a bad {column}"
        );
    }
}

#[tokio::test]
async fn registrations_are_deleted_with_their_tenant() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let registry = repo(&db);

    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "saml-cascade".into(),
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
    registry
        .create(doomed, minimal("https://one.example.com/m"))
        .await
        .unwrap();
    registry
        .create(doomed, minimal("https://two.example.com/m"))
        .await
        .unwrap();
    registry
        .create(kept, minimal("https://one.example.com/m"))
        .await
        .unwrap();

    tenants.delete(doomed).await.unwrap();

    assert!(
        registry.list(doomed).await.unwrap().is_empty(),
        "deleting a tenant must delete its service providers"
    );
    assert_eq!(
        registry.list(kept).await.unwrap().len(),
        1,
        "deleting one tenant must not touch another tenant's registrations"
    );
}

/// The tenant delete is one transaction: a cascade step that fails removes
/// nothing, and the failure is reported (P23W2-02, extended to this table).
#[tokio::test]
async fn a_tenant_delete_that_fails_on_the_registry_is_reported_and_removes_nothing() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let registry = repo(&db);

    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "saml-cascade-failure".into(),
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
    registry
        .create(tenant, minimal("https://one.example.com/m"))
        .await
        .unwrap();
    db.query(
        "DEFINE EVENT refuse_sp_delete ON TABLE saml_service_provider \
         WHEN $event = 'DELETE' THEN { THROW 'refused by the test' };",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    assert!(tenants.delete(tenant).await.is_err());
    assert!(tenants.get_by_id(tenant).await.is_ok());
    assert_eq!(registry.list(tenant).await.unwrap().len(), 1);
}

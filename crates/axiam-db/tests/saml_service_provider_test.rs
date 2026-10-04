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

// ---------------------------------------------------------------------------
// T23.2.5: paging with search, the group fence, the delete cascade
// ---------------------------------------------------------------------------

fn named(entity_id: &str, display_name: &str) -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        display_name: display_name.into(),
        ..minimal(entity_id)
    }
}

#[tokio::test]
async fn list_page_pages_oldest_first_and_counts_matches_not_rows() {
    use axiam_core::repository::Pagination;
    let db = setup().await;
    let repo = repo(&db);
    let tenant = Uuid::new_v4();
    let mut ids = Vec::new();
    for n in 0..5 {
        ids.push(
            repo.create(
                tenant,
                named(
                    &format!("https://sp{n}.example.com/m"),
                    &format!("Alpha {n}"),
                ),
            )
            .await
            .unwrap()
            .id,
        );
    }
    let beta = repo
        .create(tenant, named("https://beta.example.com/m", "Beta Billing"))
        .await
        .unwrap();
    repo.create(
        Uuid::new_v4(),
        named("https://other.example.com/m", "Alpha Other"),
    )
    .await
    .unwrap();

    let page = |offset, limit, search: Option<&str>| Pagination {
        offset,
        limit,
        search: search.map(str::to_owned),
    };
    let first = repo.list_page(tenant, page(0, 2, None)).await.unwrap();
    assert_eq!(first.total, 6);
    assert_eq!((first.offset, first.limit), (0, 2));
    assert_eq!(
        first.items.iter().map(|s| s.id).collect::<Vec<_>>(),
        ids[..2]
    );
    let last = repo.list_page(tenant, page(4, 10, None)).await.unwrap();
    assert_eq!(last.items.len(), 2, "rows 4 and 5 of 6");
    assert_eq!(last.items[1].id, beta.id);

    // The term narrows BEFORE paging, so `total` counts matches: display name
    // (case-insensitive), entity id, and the record id.
    let alpha = repo
        .list_page(tenant, page(0, 2, Some("  ALPHA ")))
        .await
        .unwrap();
    assert_eq!(alpha.total, 5);
    assert_eq!(alpha.items.len(), 2);
    let by_entity = repo
        .list_page(tenant, page(0, 10, Some("beta.example")))
        .await
        .unwrap();
    assert_eq!(by_entity.total, 1);
    let by_id = repo
        .list_page(tenant, page(0, 10, Some(&beta.id.to_string())))
        .await
        .unwrap();
    assert_eq!(
        by_id.items.iter().map(|s| s.id).collect::<Vec<_>>(),
        vec![beta.id]
    );
    let none = repo
        .list_page(tenant, page(0, 10, Some("nothing-matches")))
        .await
        .unwrap();
    assert_eq!((none.total, none.items.len()), (0, 0));
    // Tenant scope: the other tenant's "Alpha Other" is in neither answer.
    assert!(
        repo.list_page(Uuid::new_v4(), page(0, 10, None))
            .await
            .unwrap()
            .items
            .is_empty()
    );
}

#[tokio::test]
async fn groups_outside_tenant_names_exactly_the_ones_that_are_not_the_tenants() {
    use axiam_core::models::group::CreateGroup;
    use axiam_core::repository::GroupRepository;
    use axiam_db::repository::SurrealGroupRepository;
    let db = setup().await;
    let repo = repo(&db);
    let groups = SurrealGroupRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();
    let mine = groups
        .create(CreateGroup {
            tenant_id: tenant,
            name: "mine".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let theirs = groups
        .create(CreateGroup {
            tenant_id: other,
            name: "theirs".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let missing = Uuid::new_v4();

    assert!(
        repo.groups_outside_tenant(tenant, &[])
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        repo.groups_outside_tenant(tenant, &[mine, mine])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.groups_outside_tenant(tenant, &[mine, theirs, missing, theirs])
            .await
            .unwrap(),
        vec![theirs, missing],
        "another tenant's group is outside, like one that does not exist; order kept, no repeats"
    );
}

#[tokio::test]
async fn deleting_an_sp_removes_what_the_datastore_holds_for_it() {
    use axiam_core::models::saml_authn_request::NewPendingSamlRequest;
    use axiam_core::repository::PendingSamlRequestRepository;
    use axiam_db::repository::SurrealPendingSamlRequestRepository;
    let db = setup().await;
    let sps = repo(&db);
    let pending = SurrealPendingSamlRequestRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let doomed = sps
        .create(tenant, minimal("https://doomed.example.com/m"))
        .await
        .unwrap();
    let kept = sps
        .create(tenant, minimal("https://kept.example.com/m"))
        .await
        .unwrap();

    let now = chrono::Utc::now();
    let request = |sp_id: Uuid, request_id: &str| NewPendingSamlRequest {
        tenant_id: tenant,
        sp_id,
        request_id: Some(request_id.into()),
        acs_url: "https://doomed.example.com/acs".into(),
        relay_state: None,
        force_authn: false,
        is_passive: false,
        handle_hash: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        binding_hash: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        created_at: now,
        expires_at: now + chrono::Duration::minutes(10),
    };
    let doomed_hash = request(doomed.id, "_a");
    pending.create(doomed_hash.clone()).await.unwrap();
    pending.create(request(doomed.id, "_b")).await.unwrap();
    let kept_request = request(kept.id, "_a");
    pending.create(kept_request.clone()).await.unwrap();

    async fn rows(db: &Surreal<Db>, sp: Uuid) -> usize {
        let mut result = db
            .query("SELECT count() AS n FROM saml_authn_request WHERE sp_id = $sp GROUP ALL")
            .bind(("sp", sp.to_string()))
            .await
            .unwrap();
        use surrealdb_types::SurrealValue;
        #[derive(Debug, SurrealValue)]
        struct Count {
            n: usize,
        }
        let counted: Vec<Count> = result.take(0).unwrap();
        counted.first().map_or(0, |c| c.n)
    }
    assert_eq!(rows(&db, doomed.id).await, 2);

    // Another tenant's delete of the id removes nothing at all.
    assert!(matches!(
        sps.delete(Uuid::new_v4(), doomed.id).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert_eq!(
        rows(&db, doomed.id).await,
        2,
        "a refused delete cascades nothing"
    );
    assert!(sps.get(tenant, doomed.id).await.is_ok());

    sps.delete(tenant, doomed.id).await.unwrap();
    assert_eq!(
        rows(&db, doomed.id).await,
        0,
        "its pending requests went with it"
    );
    assert_eq!(rows(&db, kept.id).await, 1, "another SP's requests did not");
    assert!(
        pending
            .get_pending(tenant, &kept_request.handle_hash)
            .await
            .unwrap()
            .is_some()
    );
    // T23.2.4 extends `SP_DELETE_CASCADE` with `saml_sp_session` and this test
    // with the rows of that table.
}

//! Integration tests for Organization and Tenant repository
//! implementations using in-memory SurrealDB.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::repository::{OrganizationRepository, Pagination, TenantRepository};
use axiam_db::repository::{SurrealOrganizationRepository, SurrealTenantRepository};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Helper: spin up in-memory DB and run migrations.
async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

// -----------------------------------------------------------------------
// Organization tests
// -----------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_organization() {
    let db = setup().await;
    let repo = SurrealOrganizationRepository::new(db);

    let org = repo
        .create(CreateOrganization {
            name: "ACME Corp".into(),
            slug: "acme".into(),
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(org.name, "ACME Corp");
    assert_eq!(org.slug, "acme");

    // Get by ID should return the same organization.
    let fetched = repo.get_by_id(org.id).await.unwrap();
    assert_eq!(fetched.id, org.id);
    assert_eq!(fetched.name, org.name);
    assert_eq!(fetched.slug, org.slug);
}

#[tokio::test]
async fn get_organization_by_slug() {
    let db = setup().await;
    let repo = SurrealOrganizationRepository::new(db);

    let org = repo
        .create(CreateOrganization {
            name: "Slug Test".into(),
            slug: "slug-test".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let fetched = repo.get_by_slug("slug-test").await.unwrap();
    assert_eq!(fetched.id, org.id);
    assert_eq!(fetched.slug, "slug-test");
}

#[tokio::test]
async fn update_organization() {
    let db = setup().await;
    let repo = SurrealOrganizationRepository::new(db);

    let org = repo
        .create(CreateOrganization {
            name: "Before".into(),
            slug: "update-test".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            org.id,
            axiam_core::models::organization::UpdateOrganization {
                name: Some("After".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.id, org.id);
    assert_eq!(updated.name, "After");
    assert_eq!(updated.slug, "update-test"); // unchanged
    assert!(updated.updated_at >= org.updated_at);
}

#[tokio::test]
async fn delete_organization() {
    let db = setup().await;
    let repo = SurrealOrganizationRepository::new(db);

    let org = repo
        .create(CreateOrganization {
            name: "To Delete".into(),
            slug: "delete-test".into(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.delete(org.id).await.unwrap();

    let result = repo.get_by_id(org.id).await;
    assert!(result.is_err(), "should not find deleted organization");
}

#[tokio::test]
async fn list_organizations_with_pagination() {
    let db = setup().await;
    let repo = SurrealOrganizationRepository::new(db);

    for i in 0..5 {
        repo.create(CreateOrganization {
            name: format!("Org {i}"),
            slug: format!("org-{i}"),
            metadata: None,
        })
        .await
        .unwrap();
    }

    let page1 = repo
        .list(Pagination {
            offset: 0,
            limit: 3,
        })
        .await
        .unwrap();

    assert_eq!(page1.items.len(), 3);
    assert_eq!(page1.total, 5);
    assert_eq!(page1.offset, 0);
    assert_eq!(page1.limit, 3);

    let page2 = repo
        .list(Pagination {
            offset: 3,
            limit: 3,
        })
        .await
        .unwrap();

    assert_eq!(page2.items.len(), 2);
    assert_eq!(page2.total, 5);
}

#[tokio::test]
async fn duplicate_organization_slug_rejected() {
    let db = setup().await;
    let repo = SurrealOrganizationRepository::new(db);

    repo.create(CreateOrganization {
        name: "First".into(),
        slug: "unique-slug".into(),
        metadata: None,
    })
    .await
    .unwrap();

    let result = repo
        .create(CreateOrganization {
            name: "Second".into(),
            slug: "unique-slug".into(),
            metadata: None,
        })
        .await;

    assert!(result.is_err(), "duplicate slug should be rejected");
}

// -----------------------------------------------------------------------
// Tenant tests
// -----------------------------------------------------------------------

/// Helper: create an organization and return its ID.
async fn create_org(
    repo: &SurrealOrganizationRepository<surrealdb::engine::local::Db>,
    slug: &str,
) -> uuid::Uuid {
    repo.create(CreateOrganization {
        name: format!("Org {slug}"),
        slug: slug.into(),
        metadata: None,
    })
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn create_and_get_tenant() {
    let db = setup().await;
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db);

    let org_id = create_org(&org_repo, "tenant-test-org").await;

    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            name: "Dev Tenant".into(),
            slug: "dev".into(),
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(tenant.organization_id, org_id);
    assert_eq!(tenant.name, "Dev Tenant");
    assert_eq!(tenant.slug, "dev");

    let fetched = tenant_repo.get_by_id(tenant.id).await.unwrap();
    assert_eq!(fetched.id, tenant.id);
    assert_eq!(fetched.organization_id, org_id);
}

#[tokio::test]
async fn get_tenant_by_slug() {
    let db = setup().await;
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db);

    let org_id = create_org(&org_repo, "slug-tenant-org").await;

    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            name: "Staging".into(),
            slug: "staging".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let fetched = tenant_repo.get_by_slug(org_id, "staging").await.unwrap();
    assert_eq!(fetched.id, tenant.id);
}

#[tokio::test]
async fn list_tenants_by_organization() {
    let db = setup().await;
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db);

    let org1 = create_org(&org_repo, "list-org-1").await;
    let org2 = create_org(&org_repo, "list-org-2").await;

    // Create 3 tenants under org1 and 1 under org2.
    for i in 0..3 {
        tenant_repo
            .create(CreateTenant {
                organization_id: org1,
                name: format!("Tenant {i}"),
                slug: format!("t-{i}"),
                metadata: None,
            })
            .await
            .unwrap();
    }
    tenant_repo
        .create(CreateTenant {
            organization_id: org2,
            name: "Other Tenant".into(),
            slug: "other".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let list = tenant_repo
        .list_by_organization(org1, Pagination::default())
        .await
        .unwrap();
    assert_eq!(list.total, 3);
    assert_eq!(list.items.len(), 3);

    let list2 = tenant_repo
        .list_by_organization(org2, Pagination::default())
        .await
        .unwrap();
    assert_eq!(list2.total, 1);
}

#[tokio::test]
async fn delete_tenant() {
    let db = setup().await;
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db);

    let org_id = create_org(&org_repo, "del-tenant-org").await;

    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            name: "Ephemeral".into(),
            slug: "ephemeral".into(),
            metadata: None,
        })
        .await
        .unwrap();

    tenant_repo.delete(tenant.id).await.unwrap();

    let result = tenant_repo.get_by_id(tenant.id).await;
    assert!(result.is_err(), "should not find deleted tenant");
}

#[tokio::test]
async fn update_tenant() {
    let db = setup().await;
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let tenant_repo = SurrealTenantRepository::new(db);

    let org_id = create_org(&org_repo, "upd-tenant-org").await;

    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            name: "Before".into(),
            slug: "upd-test".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let updated = tenant_repo
        .update(
            tenant.id,
            axiam_core::models::tenant::UpdateTenant {
                name: Some("After".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.name, "After");
    assert_eq!(updated.slug, "upd-test"); // unchanged
    assert!(updated.updated_at >= tenant.updated_at);
}

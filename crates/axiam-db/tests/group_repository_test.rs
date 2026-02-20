//! Integration tests for Group repository using in-memory SurrealDB.

use axiam_core::models::group::{CreateGroup, UpdateGroup};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, Pagination, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// Helper: spin up in-memory DB, run migrations, create org + tenant + 2 users.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // tenant_id
    uuid::Uuid, // user_a_id
    uuid::Uuid, // user_b_id
) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user_a = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_b = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: "pass123".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id, user_a.id, user_b.id)
}

#[tokio::test]
async fn create_and_get_group() {
    let (db, tenant_id, _, _) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    let group = repo
        .create(CreateGroup {
            tenant_id,
            name: "Developers".into(),
            description: "Software developers".into(),
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(group.tenant_id, tenant_id);
    assert_eq!(group.name, "Developers");
    assert_eq!(group.description, "Software developers");

    let fetched = repo.get_by_id(tenant_id, group.id).await.unwrap();
    assert_eq!(fetched.id, group.id);
    assert_eq!(fetched.name, "Developers");
}

#[tokio::test]
async fn update_group() {
    let (db, tenant_id, _, _) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    let group = repo
        .create(CreateGroup {
            tenant_id,
            name: "Original".into(),
            description: "Original desc".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            group.id,
            UpdateGroup {
                name: Some("Renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.name, "Renamed");
    assert_eq!(updated.description, "Original desc"); // unchanged
}

#[tokio::test]
async fn delete_group() {
    let (db, tenant_id, _, _) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    let group = repo
        .create(CreateGroup {
            tenant_id,
            name: "ToDelete".into(),
            description: "Will be deleted".into(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.delete(tenant_id, group.id).await.unwrap();

    let result = repo.get_by_id(tenant_id, group.id).await;
    assert!(result.is_err(), "deleted group should not be found");
}

#[tokio::test]
async fn list_groups_with_pagination() {
    let (db, tenant_id, _, _) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    for i in 0..5 {
        repo.create(CreateGroup {
            tenant_id,
            name: format!("group-{i}"),
            description: format!("Group {i}"),
            metadata: None,
        })
        .await
        .unwrap();
    }

    let page1 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 3,
            },
        )
        .await
        .unwrap();

    assert_eq!(page1.items.len(), 3);
    assert_eq!(page1.total, 5);

    let page2 = repo
        .list(
            tenant_id,
            Pagination {
                offset: 3,
                limit: 3,
            },
        )
        .await
        .unwrap();

    assert_eq!(page2.items.len(), 2);
}

#[tokio::test]
async fn duplicate_name_rejected() {
    let (db, tenant_id, _, _) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    repo.create(CreateGroup {
        tenant_id,
        name: "unique-group".into(),
        description: "first".into(),
        metadata: None,
    })
    .await
    .unwrap();

    let result = repo
        .create(CreateGroup {
            tenant_id,
            name: "unique-group".into(),
            description: "second".into(),
            metadata: None,
        })
        .await;

    assert!(result.is_err(), "duplicate group name should be rejected");
}

#[tokio::test]
async fn add_and_get_members() {
    let (db, tenant_id, user_a, user_b) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    let group = repo
        .create(CreateGroup {
            tenant_id,
            name: "Team".into(),
            description: "A team".into(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.add_member(tenant_id, user_a, group.id).await.unwrap();
    repo.add_member(tenant_id, user_b, group.id).await.unwrap();

    let members = repo
        .get_members(
            tenant_id,
            group.id,
            Pagination {
                offset: 0,
                limit: 10,
            },
        )
        .await
        .unwrap();

    assert_eq!(members.total, 2);
    assert_eq!(members.items.len(), 2);

    let usernames: Vec<&str> = members.items.iter().map(|u| u.username.as_str()).collect();
    assert!(usernames.contains(&"alice"));
    assert!(usernames.contains(&"bob"));
}

#[tokio::test]
async fn remove_member() {
    let (db, tenant_id, user_a, user_b) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    let group = repo
        .create(CreateGroup {
            tenant_id,
            name: "Team2".into(),
            description: "Another team".into(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.add_member(tenant_id, user_a, group.id).await.unwrap();
    repo.add_member(tenant_id, user_b, group.id).await.unwrap();

    repo.remove_member(tenant_id, user_a, group.id)
        .await
        .unwrap();

    let members = repo
        .get_members(
            tenant_id,
            group.id,
            Pagination {
                offset: 0,
                limit: 10,
            },
        )
        .await
        .unwrap();

    assert_eq!(members.total, 1);
    assert_eq!(members.items[0].username, "bob");
}

#[tokio::test]
async fn get_user_groups() {
    let (db, tenant_id, user_a, _) = setup().await;
    let repo = SurrealGroupRepository::new(db);

    let g1 = repo
        .create(CreateGroup {
            tenant_id,
            name: "GroupA".into(),
            description: "A".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let g2 = repo
        .create(CreateGroup {
            tenant_id,
            name: "GroupB".into(),
            description: "B".into(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.add_member(tenant_id, user_a, g1.id).await.unwrap();
    repo.add_member(tenant_id, user_a, g2.id).await.unwrap();

    let groups = repo.get_user_groups(tenant_id, user_a).await.unwrap();

    assert_eq!(groups.len(), 2);
    let names: Vec<&str> = groups.iter().map(|g| g.name.as_str()).collect();
    assert!(names.contains(&"GroupA"));
    assert!(names.contains(&"GroupB"));
}

#[tokio::test]
async fn tenant_isolation() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Iso Org".into(),
            slug: "iso-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant_a = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant A".into(),
            slug: "tenant-a".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_b = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let group_repo = SurrealGroupRepository::new(db);

    let group = group_repo
        .create(CreateGroup {
            tenant_id: tenant_a.id,
            name: "Isolated".into(),
            description: "Tenant A only".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Group should be findable under tenant_a.
    let found = group_repo.get_by_id(tenant_a.id, group.id).await;
    assert!(found.is_ok());

    // Group should NOT be findable under tenant_b.
    let not_found = group_repo.get_by_id(tenant_b.id, group.id).await;
    assert!(
        not_found.is_err(),
        "group should not be visible in other tenant"
    );
}

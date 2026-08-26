//! Free-text search on list endpoints.
//!
//! Every repository splices `Pagination::search` into the SAME query it runs
//! unfiltered, which is what makes an unsearched list byte-identical to what it
//! was before search existed — and also what makes it easy to get wrong in a
//! way the compiler cannot see. The fragment is spliced with `format!`, and a
//! literal that is *not* wrapped in `format!` compiles perfectly and ships
//! `{search}` to the database as five characters of SurrealQL. That is exactly
//! what happened once here; these tests are what found it.
//!
//! So the assertions below are not only about behaviour. Any of them failing on
//! a plain unfiltered list means the placeholder reached the query engine.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, Pagination, PermissionRepository, RoleRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealRoleRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type Db = surrealdb::engine::local::Db;

async fn setup() -> (Surreal<Db>, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Acme".into(),
            slug: "acme".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Prod".into(),
            slug: "prod".into(),
            kind: Default::default(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id)
}

fn page(search: Option<&str>) -> Pagination {
    Pagination {
        offset: 0,
        limit: 50,
        search: search.map(str::to_string),
    }
}

// ---------------------------------------------------------------------------

/// The regression test.
///
/// An unfiltered list must return every row. If `{search}` were reaching the
/// database as a literal, this would fail — either with a parse error or with
/// zero rows — and it is the cheapest possible check that the splice is real.
#[tokio::test]
async fn an_unfiltered_list_returns_everything() {
    let (db, tenant) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    for name in ["alice", "bob", "carol"] {
        users
            .create(CreateUser {
                tenant_id: tenant,
                username: name.into(),
                email: format!("{name}@acme.test"),
                password: "correct horse battery staple".into(),
                metadata: None,
            })
            .await
            .unwrap();
    }

    let all = users.list(tenant, page(None)).await.unwrap();
    assert_eq!(all.total, 3, "an unfiltered list must count every row");
    assert_eq!(all.items.len(), 3);
}

#[tokio::test]
async fn search_narrows_users_by_username_and_email() {
    let (db, tenant) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    for (name, mail) in [
        ("alice", "alice@acme.test"),
        ("bob", "bob@example.org"),
        ("carol", "carol@acme.test"),
    ] {
        users
            .create(CreateUser {
                tenant_id: tenant,
                username: name.into(),
                email: mail.into(),
                password: "correct horse battery staple".into(),
                metadata: None,
            })
            .await
            .unwrap();
    }

    let by_name = users.list(tenant, page(Some("ali"))).await.unwrap();
    assert_eq!(by_name.total, 1);
    assert_eq!(by_name.items[0].username, "alice");

    // A field other than the primary one still matches — the box says "name or
    // ID" but an operator who pastes a domain expects it to work.
    let by_domain = users.list(tenant, page(Some("example.org"))).await.unwrap();
    assert_eq!(by_domain.total, 1);
    assert_eq!(by_domain.items[0].username, "bob");
}

/// `total` must count matches, not rows.
///
/// The pager divides `total` by the page size to decide how many pages there
/// are. A `total` that counted the unfiltered collection would promise pages
/// the filtered result set cannot fill, so the last few render empty — which is
/// how a filtered list ends up looking broken rather than filtered.
#[tokio::test]
async fn the_total_counts_matches_not_rows() {
    let (db, tenant) = setup().await;
    let roles = SurrealRoleRepository::new(db.clone());
    for name in ["admin", "auditor", "viewer"] {
        roles
            .create(CreateRole {
                tenant_id: tenant,
                name: name.into(),
                description: String::new(),
                is_global: true,
            })
            .await
            .unwrap();
    }

    let filtered = roles.list(tenant, page(Some("aud"))).await.unwrap();
    assert_eq!(filtered.items.len(), 1);
    assert_eq!(
        filtered.total, 1,
        "total must describe the filtered set the page came from"
    );
}

#[tokio::test]
async fn search_is_case_insensitive() {
    let (db, tenant) = setup().await;
    let roles = SurrealRoleRepository::new(db.clone());
    roles
        .create(CreateRole {
            tenant_id: tenant,
            name: "Platform-Admin".into(),
            description: String::new(),
            is_global: true,
        })
        .await
        .unwrap();

    for term in ["platform", "PLATFORM", "Platform-Ad"] {
        let hit = roles.list(tenant, page(Some(term))).await.unwrap();
        assert_eq!(hit.total, 1, "term {term:?} should match");
    }
}

/// An operator with an id from a log line pastes it into the same box.
#[tokio::test]
async fn the_record_id_is_searchable() {
    let (db, tenant) = setup().await;
    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
        .create(CreateRole {
            tenant_id: tenant,
            name: "auditor".into(),
            description: String::new(),
            is_global: true,
        })
        .await
        .unwrap();

    let by_id = roles
        .list(tenant, page(Some(&role.id.to_string())))
        .await
        .unwrap();
    assert_eq!(by_id.total, 1);
    assert_eq!(by_id.items[0].id, role.id);
}

/// Search must not become a way to read another tenant's rows.
///
/// The fragment is spliced onto an existing `WHERE tenant_id = $tenant_id`, so
/// it has to bracket its own disjunction. Without the brackets one `OR` escapes
/// the tenant predicate and the filter matches everywhere.
#[tokio::test]
async fn search_never_crosses_a_tenant_boundary() {
    let (db, tenant_a) = setup().await;
    let tenants = SurrealTenantRepository::new(db.clone());
    let org_id = tenants.get_by_id(tenant_a).await.unwrap().organization_id;
    let tenant_b = tenants
        .create(CreateTenant {
            organization_id: org_id,
            name: "Staging".into(),
            slug: "staging".into(),
            kind: Default::default(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let roles = SurrealRoleRepository::new(db.clone());
    for t in [tenant_a, tenant_b] {
        roles
            .create(CreateRole {
                tenant_id: t,
                name: "shared-name".into(),
                description: String::new(),
                is_global: true,
            })
            .await
            .unwrap();
    }

    let from_a = roles.list(tenant_a, page(Some("shared"))).await.unwrap();
    assert_eq!(
        from_a.total, 1,
        "a search must see only the caller's own tenant"
    );
    assert_eq!(from_a.items[0].tenant_id, tenant_a);
}

#[tokio::test]
async fn a_blank_term_is_the_same_as_no_term() {
    let (db, tenant) = setup().await;
    let perms = SurrealPermissionRepository::new(db.clone());
    for action in ["users:list", "users:create"] {
        perms
            .create(CreatePermission {
                tenant_id: tenant,
                action: action.into(),
                description: String::new(),
            })
            .await
            .unwrap();
    }

    let none = perms.list(tenant, page(None)).await.unwrap();
    // `normalize_search` maps blank to `None` on the serde path; a directly
    // constructed `Some("   ")` is the one case that bypasses it, so the
    // repository has to treat a whitespace term as matching everything rather
    // than nothing.
    let blank = perms.list(tenant, page(Some("   "))).await.unwrap();
    assert_eq!(none.total, blank.total);
}

#[tokio::test]
async fn search_composes_with_paging() {
    let (db, tenant) = setup().await;
    let perms = SurrealPermissionRepository::new(db.clone());
    for i in 0..5 {
        perms
            .create(CreatePermission {
                tenant_id: tenant,
                action: format!("reports:action{i}"),
                description: String::new(),
            })
            .await
            .unwrap();
    }
    perms
        .create(CreatePermission {
            tenant_id: tenant,
            action: "users:list".into(),
            description: String::new(),
        })
        .await
        .unwrap();

    let first = perms
        .list(
            tenant,
            Pagination {
                offset: 0,
                limit: 2,
                search: Some("reports".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(first.items.len(), 2, "the page honours the limit");
    assert_eq!(
        first.total, 5,
        "the total describes every match, not just this page"
    );
}

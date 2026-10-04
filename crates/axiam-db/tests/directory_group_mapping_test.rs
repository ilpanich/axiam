//! The storage half of directory group mapping (T23.3.4, G-3, D-30, schema
//! v74), against the real datastore.
//!
//! What lives in the datastore rather than in plain Rust, so a mock would agree
//! with whatever the code happened to do:
//!
//! - the **mapping table** round-trips through `directory_config` and a row
//!   written before v74 reads as *no mapping*;
//! - **a group of another tenant** (or none) cannot be named in the table, on
//!   create and on update, and a refused write changes nothing;
//! - the **owner marker** on `member_of`: the directory writes
//!   `source = directory`, an edge without the field is manual, the mapping's
//!   remove never touches a manual edge, and a manual edge for the same pair is
//!   neither rewritten nor duplicated;
//! - the datastore admits no owner other than `directory`.
//!
//! No assertion message formats a secret, a key or an identifier.

use std::sync::OnceLock;

use axiam_core::error::AxiamError;
use axiam_core::models::directory::{
    DirectoryKind, GROUP_MAPPINGS_MAX, GroupMapping, NewDirectoryConfig,
};
use axiam_core::models::group::{CreateGroup, DirectoryMembershipWrite};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{DirectoryConfigRepository, GroupRepository, UserRepository};
use axiam_db::repository::{
    SurrealDirectoryConfigRepository, SurrealGroupRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

fn key() -> [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    *KEY.get_or_init(|| {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        bytes
    })
}

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn config_repo(db: &Surreal<Db>) -> SurrealDirectoryConfigRepository<Db> {
    SurrealDirectoryConfigRepository::new(db.clone(), Some(key()))
}

fn input(tenant_id: Uuid, mappings: Vec<GroupMapping>) -> NewDirectoryConfig {
    NewDirectoryConfig {
        tenant_id,
        enabled: true,
        kind: DirectoryKind::OpenLdap,
        url: "ldaps://ldap.example.com:636".into(),
        start_tls: false,
        bind_dn: "cn=svc,dc=example,dc=com".into(),
        bind_secret: Some(Zeroizing::new(axiam_test_support::other_password())),
        base_dn: "ou=people,dc=example,dc=com".into(),
        user_filter: "(uid={username})".into(),
        user_attribute_map: DirectoryKind::OpenLdap.default_user_attribute_map(),
        group_base_dn: Some("ou=groups,dc=example,dc=com".into()),
        group_filter: Some("(objectClass=groupOfNames)".into()),
        group_member_attribute: "member".into(),
        group_nesting_depth: 3,
        group_mappings: mappings,
        sync_interval_secs: 900,
        jit_provisioning: true,
        trust_anchors_pem: vec![],
    }
}

async fn group(db: &Surreal<Db>, tenant_id: Uuid, name: &str) -> Uuid {
    SurrealGroupRepository::new(db.clone())
        .create(CreateGroup {
            tenant_id,
            name: name.into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

async fn user(db: &Surreal<Db>, tenant_id: Uuid, name: &str) -> Uuid {
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

fn mapping(dn: &str, group_id: Uuid) -> GroupMapping {
    GroupMapping {
        directory_group_dn: dn.into(),
        group_id,
    }
}

// ---------------------------------------------------------------------------
// The mapping table
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_mapping_table_round_trips_in_order() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let (a, b) = (group(&db, tenant, "a").await, group(&db, tenant, "b").await);
    let want = vec![
        mapping("cn=staff,ou=groups,dc=example,dc=com", a),
        mapping("cn=staff,ou=groups,dc=example,dc=com", b),
        mapping("CN=Ops, OU=Groups, DC=example, DC=com", a),
    ];
    let repo = config_repo(&db);
    let created = repo.create(input(tenant, want.clone())).await.unwrap();
    assert!(created.group_mappings == want);
    let fetched = repo.get_by_tenant(tenant).await.unwrap().unwrap();
    assert!(fetched.group_mappings == want, "stored as typed, in order");
    let listed = repo.list_enabled().await.unwrap();
    assert!(listed[0].group_mappings == want);

    // An update replaces the whole table.
    let updated = repo
        .update(NewDirectoryConfig {
            bind_secret: None,
            ..input(tenant, vec![mapping("cn=only,dc=example,dc=com", b)])
        })
        .await
        .unwrap();
    assert_eq!(updated.group_mappings.len(), 1);
    assert_eq!(updated.group_mappings[0].group_id, b);
}

/// A row written before v74 has no `group_mappings` field; it must read as an
/// empty table, so no mapping applies and nothing is granted.
#[tokio::test]
async fn a_row_without_the_column_reads_as_no_mapping() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let g = group(&db, tenant, "g").await;
    let repo = config_repo(&db);
    repo.create(input(tenant, vec![mapping("cn=x,dc=example,dc=com", g)]))
        .await
        .unwrap();
    db.query("UPDATE directory_config SET group_mappings = NONE")
        .await
        .unwrap()
        .check()
        .unwrap();
    let fetched = repo.get_by_tenant(tenant).await.unwrap().unwrap();
    assert!(fetched.group_mappings.is_empty());
}

#[tokio::test]
async fn a_mapping_naming_another_tenants_group_is_refused_and_writes_nothing() {
    let db = setup().await;
    let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());
    let own_group = group(&db, mine, "own").await;
    let foreign_group = group(&db, theirs, "foreign").await;
    let repo = config_repo(&db);

    // Create is refused.
    let refused = repo
        .create(input(
            mine,
            vec![
                mapping("cn=a,dc=example,dc=com", own_group),
                mapping("cn=b,dc=example,dc=com", foreign_group),
            ],
        ))
        .await
        .unwrap_err();
    assert!(matches!(refused, AxiamError::Validation { .. }));
    assert!(repo.get_by_tenant(mine).await.unwrap().is_none());

    // So is an update, and the stored table is untouched.
    repo.create(input(
        mine,
        vec![mapping("cn=a,dc=example,dc=com", own_group)],
    ))
    .await
    .unwrap();
    let refused = repo
        .update(NewDirectoryConfig {
            bind_secret: None,
            ..input(mine, vec![mapping("cn=b,dc=example,dc=com", foreign_group)])
        })
        .await
        .unwrap_err();
    assert!(matches!(refused, AxiamError::Validation { .. }));
    let stored = repo.get_by_tenant(mine).await.unwrap().unwrap();
    assert_eq!(stored.group_mappings.len(), 1);
    assert_eq!(stored.group_mappings[0].group_id, own_group);
}

#[tokio::test]
async fn a_mapping_naming_no_group_at_all_is_refused() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let repo = config_repo(&db);
    let refused = repo
        .create(input(
            tenant,
            vec![mapping("cn=a,dc=example,dc=com", Uuid::new_v4())],
        ))
        .await
        .unwrap_err();
    assert!(matches!(refused, AxiamError::Validation { .. }));
}

#[tokio::test]
async fn the_table_holds_at_most_five_hundred_rows() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let g = group(&db, tenant, "g").await;
    let repo = config_repo(&db);

    let at_limit: Vec<GroupMapping> = (0..GROUP_MAPPINGS_MAX)
        .map(|i| mapping(&format!("cn=g{i},dc=example,dc=com"), g))
        .collect();
    repo.create(input(tenant, at_limit.clone())).await.unwrap();
    assert_eq!(
        repo.get_by_tenant(tenant)
            .await
            .unwrap()
            .unwrap()
            .group_mappings
            .len(),
        GROUP_MAPPINGS_MAX
    );

    let mut over = at_limit;
    over.push(mapping("cn=one-too-many,dc=example,dc=com", g));
    let refused = repo
        .update(NewDirectoryConfig {
            bind_secret: None,
            ..input(tenant, over)
        })
        .await
        .unwrap_err();
    assert!(matches!(refused, AxiamError::Validation { .. }));
    assert_eq!(
        repo.get_by_tenant(tenant)
            .await
            .unwrap()
            .unwrap()
            .group_mappings
            .len(),
        GROUP_MAPPINGS_MAX
    );
}

/// The datastore restates the cap, so a writer that skips the repository still
/// cannot store a 501st row.
#[tokio::test]
async fn the_datastore_itself_refuses_a_five_hundred_and_first_row() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let g = group(&db, tenant, "g").await;
    let repo = config_repo(&db);
    repo.create(input(tenant, vec![])).await.unwrap();
    let rows: Vec<serde_json::Value> = (0..=GROUP_MAPPINGS_MAX)
        .map(|i| {
            serde_json::json!({
                "directory_group_dn": format!("cn=g{i},dc=example,dc=com"),
                "group_id": g.to_string(),
            })
        })
        .collect();
    let outcome = db
        .query("UPDATE directory_config SET group_mappings = $rows")
        .bind(("rows", rows))
        .await
        .unwrap()
        .check();
    assert!(outcome.is_err(), "501 rows must be refused by the ASSERT");
}

// ---------------------------------------------------------------------------
// The membership owner
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_directory_membership_is_written_marked_and_listed() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let (u, g) = (
        user(&db, tenant, "alice").await,
        group(&db, tenant, "staff").await,
    );
    let repo = SurrealGroupRepository::new(db.clone());

    assert_eq!(
        repo.add_directory_member(tenant, u, g).await.unwrap(),
        DirectoryMembershipWrite::Created
    );
    // The edge is a real membership: the engine reads it like any other.
    let groups = repo.get_user_groups(tenant, u).await.unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].id, g);
    assert_eq!(
        repo.get_user_directory_group_ids(tenant, u).await.unwrap(),
        vec![g]
    );
    // Again: nothing new, and still one edge.
    assert_eq!(
        repo.add_directory_member(tenant, u, g).await.unwrap(),
        DirectoryMembershipWrite::AlreadyDirectory
    );
    assert_eq!(repo.get_user_groups(tenant, u).await.unwrap().len(), 1);
}

/// D-30: a manual membership of the same pair is left as it is, no second edge
/// is written, and the directory can never remove it.
#[tokio::test]
async fn a_manual_membership_of_the_same_pair_is_left_alone_and_never_removed() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let (u, g) = (
        user(&db, tenant, "alice").await,
        group(&db, tenant, "staff").await,
    );
    let repo = SurrealGroupRepository::new(db.clone());
    repo.add_member(tenant, u, g).await.unwrap();

    assert_eq!(
        repo.add_directory_member(tenant, u, g).await.unwrap(),
        DirectoryMembershipWrite::AlreadyManual
    );
    // Not re-marked: the mapping does not own it and does not list it.
    assert!(
        repo.get_user_directory_group_ids(tenant, u)
            .await
            .unwrap()
            .is_empty()
    );
    // Not removable by the directory's method.
    assert!(!repo.remove_directory_member(tenant, u, g).await.unwrap());
    assert_eq!(repo.get_user_groups(tenant, u).await.unwrap().len(), 1);
    // One edge, not two.
    let mut edges = db
        .query("SELECT count() AS total FROM member_of GROUP ALL")
        .await
        .unwrap();
    let rows: Vec<serde_json::Value> = edges.take(0).unwrap();
    assert_eq!(rows[0]["total"], 1);
    // The administrator's own removal still works.
    repo.remove_member(tenant, u, g).await.unwrap();
    assert!(repo.get_user_groups(tenant, u).await.unwrap().is_empty());
}

#[tokio::test]
async fn removing_a_directory_membership_removes_only_that_edge() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let u = user(&db, tenant, "alice").await;
    let (by_directory, by_hand) = (
        group(&db, tenant, "mapped").await,
        group(&db, tenant, "manual").await,
    );
    let repo = SurrealGroupRepository::new(db.clone());
    repo.add_directory_member(tenant, u, by_directory)
        .await
        .unwrap();
    repo.add_member(tenant, u, by_hand).await.unwrap();

    assert!(
        repo.remove_directory_member(tenant, u, by_directory)
            .await
            .unwrap()
    );
    // Gone, so a second call reports nothing removed.
    assert!(
        !repo
            .remove_directory_member(tenant, u, by_directory)
            .await
            .unwrap()
    );
    let left = repo.get_user_groups(tenant, u).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, by_hand);
}

/// An edge written before v74 has no `source`: it reads as manual.
#[tokio::test]
async fn an_edge_without_the_field_reads_as_manual() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let (u, g) = (
        user(&db, tenant, "alice").await,
        group(&db, tenant, "legacy").await,
    );
    db.query(format!("RELATE user:`{u}` -> member_of -> group:`{g}`;"))
        .await
        .unwrap()
        .check()
        .unwrap();
    let repo = SurrealGroupRepository::new(db.clone());
    assert!(
        repo.get_user_directory_group_ids(tenant, u)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(!repo.remove_directory_member(tenant, u, g).await.unwrap());
    assert_eq!(repo.get_user_groups(tenant, u).await.unwrap().len(), 1);
}

#[tokio::test]
async fn the_datastore_admits_no_owner_but_directory() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let (u, g) = (
        user(&db, tenant, "alice").await,
        group(&db, tenant, "g").await,
    );
    let refused = db
        .query(format!(
            "RELATE user:`{u}` -> member_of -> group:`{g}` SET source = 'somebody';"
        ))
        .await
        .unwrap()
        .check();
    assert!(refused.is_err());
}

#[tokio::test]
async fn directory_memberships_are_tenant_scoped() {
    let db = setup().await;
    let (mine, theirs) = (Uuid::new_v4(), Uuid::new_v4());
    let u = user(&db, mine, "alice").await;
    let foreign_group = group(&db, theirs, "foreign").await;
    let own_group = group(&db, mine, "own").await;
    let repo = SurrealGroupRepository::new(db.clone());

    // A foreign group cannot be joined, and no edge is written.
    assert!(matches!(
        repo.add_directory_member(mine, u, foreign_group)
            .await
            .unwrap_err(),
        AxiamError::NotFound { .. }
    ));
    // Nor can another tenant's id reach this tenant's edge.
    repo.add_directory_member(mine, u, own_group).await.unwrap();
    assert!(
        !repo
            .remove_directory_member(theirs, u, own_group)
            .await
            .unwrap()
    );
    assert!(
        repo.get_user_directory_group_ids(theirs, u)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        repo.get_user_directory_group_ids(mine, u).await.unwrap(),
        vec![own_group]
    );
}

/// The manual path is as it was: a second `add_member` of a directory-sourced
/// pair is still the duplicate-membership conflict (recorded as a residual: it
/// does not promote the edge to manual).
#[tokio::test]
async fn add_member_on_a_directory_edge_is_still_a_conflict() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let (u, g) = (
        user(&db, tenant, "alice").await,
        group(&db, tenant, "g").await,
    );
    let repo = SurrealGroupRepository::new(db.clone());
    repo.add_directory_member(tenant, u, g).await.unwrap();
    assert!(matches!(
        repo.add_member(tenant, u, g).await.unwrap_err(),
        AxiamError::AlreadyExists { .. }
    ));
}

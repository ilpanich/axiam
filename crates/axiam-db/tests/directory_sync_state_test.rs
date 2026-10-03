//! The directory sync job's storage (T23.3.5, G-3, D-31, schema v75) against the
//! real datastore:
//!
//! - the per-tenant state row round-trips, is one row per tenant, is replaced by
//!   a second save and is trimmed to its cap;
//! - the row goes **with the tenant**, in the tenant-delete transaction, and a
//!   neighbouring tenant's row stays;
//! - the user repository's sync methods: `list_directory_accounts` (keyset
//!   pages of marked accounts only), `deactivate_directory_account` (one
//!   compare-and-set, `Inactive` and nothing else) and the collision probe that
//!   leaves one account out.
//!
//! No assertion message formats a credential, a name or an identifier.

use axiam_core::models::directory_sync::{
    DirectorySyncResult, DirectorySyncState, REPORTED_USER_IDS_MAX,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{
    CollisionAttribute, CreateDirectoryAccount, CreateUser, UpdateUser, UserStatus,
};
use axiam_core::repository::{
    DirectorySyncStateRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealDirectorySyncStateRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use chrono::{TimeZone, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use surrealdb_types::SurrealValue;
use uuid::Uuid;

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn full_state(tenant_id: Uuid) -> DirectorySyncState {
    DirectorySyncState {
        tenant_id,
        watermark: Some("20261003120000Z".into()),
        server_identity: Some("CN=NTDS Settings,CN=DC1,CN=Servers".into()),
        full_required: true,
        last_attempt_at: Some(Utc.with_ymd_and_hms(2026, 10, 3, 12, 0, 0).unwrap()),
        last_full_run_at: Some(Utc.with_ymd_and_hms(2026, 10, 3, 3, 0, 0).unwrap()),
        last_result: Some(DirectorySyncResult::Partial),
        reported_user_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        updated_at: Utc::now(),
    }
}

// ---------------------------------------------------------------------------
// The state row
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_tenant_that_was_never_synced_has_no_state() {
    let db = setup().await;
    let repo = SurrealDirectorySyncStateRepository::new(db);
    assert!(repo.get(Uuid::new_v4()).await.unwrap().is_none());
}

#[tokio::test]
async fn the_state_round_trips_every_field() {
    let db = setup().await;
    let repo = SurrealDirectorySyncStateRepository::new(db);
    let tenant = Uuid::new_v4();
    let want = full_state(tenant);
    repo.save(&want).await.unwrap();

    let got = repo.get(tenant).await.unwrap().expect("a state row");
    assert_eq!(got.tenant_id, want.tenant_id);
    assert_eq!(got.watermark, want.watermark);
    assert_eq!(got.server_identity, want.server_identity);
    assert_eq!(got.full_required, want.full_required);
    assert_eq!(got.last_attempt_at, want.last_attempt_at);
    assert_eq!(got.last_full_run_at, want.last_full_run_at);
    assert_eq!(got.last_result, want.last_result);
    assert_eq!(got.reported_user_ids, want.reported_user_ids);
}

#[tokio::test]
async fn absent_values_read_back_absent() {
    let db = setup().await;
    let repo = SurrealDirectorySyncStateRepository::new(db);
    let tenant = Uuid::new_v4();
    repo.save(&DirectorySyncState::new(tenant)).await.unwrap();
    let got = repo.get(tenant).await.unwrap().unwrap();
    assert!(got.watermark.is_none() && got.server_identity.is_none());
    assert!(got.last_attempt_at.is_none() && got.last_full_run_at.is_none());
    assert!(got.last_result.is_none() && got.reported_user_ids.is_empty());
    assert!(!got.full_required);
}

#[tokio::test]
async fn a_second_save_replaces_the_row_rather_than_adding_one() {
    let db = setup().await;
    let repo = SurrealDirectorySyncStateRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    repo.save(&full_state(tenant)).await.unwrap();

    let mut next = DirectorySyncState::new(tenant);
    next.watermark = Some("42".into());
    next.last_result = Some(DirectorySyncResult::Ok);
    repo.save(&next).await.unwrap();

    let got = repo.get(tenant).await.unwrap().unwrap();
    assert_eq!(got.watermark.as_deref(), Some("42"));
    assert!(
        got.server_identity.is_none(),
        "the old row is gone, not merged"
    );
    assert_eq!(got.last_result, Some(DirectorySyncResult::Ok));

    let mut count = db
        .query("SELECT count() AS total FROM directory_sync_state GROUP ALL")
        .await
        .unwrap();
    #[derive(SurrealValue)]
    struct Count {
        total: i64,
    }
    let rows: Vec<Count> = count.take(0).unwrap();
    assert_eq!(rows[0].total, 1);
}

#[tokio::test]
async fn tenants_cannot_read_each_others_state() {
    let db = setup().await;
    let repo = SurrealDirectorySyncStateRepository::new(db);
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let mut state = DirectorySyncState::new(a);
    state.watermark = Some("a-mark".into());
    repo.save(&state).await.unwrap();
    assert!(repo.get(b).await.unwrap().is_none());
    assert_eq!(
        repo.get(a).await.unwrap().unwrap().watermark.as_deref(),
        Some("a-mark")
    );
}

#[tokio::test]
async fn the_reported_list_is_trimmed_to_its_cap_keeping_the_newest() {
    let db = setup().await;
    let repo = SurrealDirectorySyncStateRepository::new(db);
    let tenant = Uuid::new_v4();
    let mut state = DirectorySyncState::new(tenant);
    state.reported_user_ids = (0..REPORTED_USER_IDS_MAX + 3)
        .map(|_| Uuid::new_v4())
        .collect();
    let newest = *state.reported_user_ids.last().unwrap();
    let oldest = state.reported_user_ids[0];
    repo.save(&state).await.unwrap();

    let got = repo.get(tenant).await.unwrap().unwrap();
    assert_eq!(got.reported_user_ids.len(), REPORTED_USER_IDS_MAX);
    assert!(got.reported_user_ids.contains(&newest));
    assert!(!got.reported_user_ids.contains(&oldest));
}

#[tokio::test]
async fn the_datastore_refuses_an_unknown_result_spelling() {
    let db = setup().await;
    let response = db
        .query(
            "CREATE directory_sync_state SET tenant_id = 't', full_required = false, \
             last_result = 'bogus', reported_user_ids = [], updated_at = time::now()",
        )
        .await
        .unwrap();
    assert!(response.check().is_err());
}

#[tokio::test]
async fn delete_removes_the_row_and_is_ok_when_there_is_none() {
    let db = setup().await;
    let repo = SurrealDirectorySyncStateRepository::new(db);
    let tenant = Uuid::new_v4();
    repo.save(&DirectorySyncState::new(tenant)).await.unwrap();
    repo.delete(tenant).await.unwrap();
    assert!(repo.get(tenant).await.unwrap().is_none());
    repo.delete(tenant).await.unwrap();
}

/// The row is deleted in the tenant's own transaction, and a neighbour's stays.
#[tokio::test]
async fn a_tenants_state_goes_with_the_tenant() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let states = SurrealDirectorySyncStateRepository::new(db.clone());

    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "sync-cascade".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let make = |slug: &str| CreateTenant {
        organization_id: org,
        kind: TenantKind::Standard,
        name: slug.into(),
        slug: slug.into(),
        metadata: None,
    };
    let doomed = tenants.create(make("doomed")).await.unwrap().id;
    let kept = tenants.create(make("kept")).await.unwrap().id;
    states.save(&full_state(doomed)).await.unwrap();
    states.save(&full_state(kept)).await.unwrap();

    tenants.delete(doomed).await.unwrap();

    assert!(states.get(doomed).await.unwrap().is_none());
    assert!(states.get(kept).await.unwrap().is_some());
}

// ---------------------------------------------------------------------------
// The user repository's sync methods
// ---------------------------------------------------------------------------

fn local_password() -> String {
    format!("Lp1!{}", Uuid::new_v4().simple())
}

async fn local(repo: &SurrealUserRepository<Db>, tenant: Uuid, name: &str) -> Uuid {
    repo.create(CreateUser {
        tenant_id: tenant,
        username: name.into(),
        email: format!("{name}@example.com"),
        password: local_password(),
        metadata: None,
    })
    .await
    .unwrap()
    .id
}

async fn directory(repo: &SurrealUserRepository<Db>, tenant: Uuid, name: &str) -> Uuid {
    repo.create_directory_account(CreateDirectoryAccount {
        tenant_id: tenant,
        username: name.into(),
        email: format!("{name}@example.com"),
        external_id: Uuid::new_v4().to_string(),
        metadata: serde_json::json!({}),
    })
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn the_listing_holds_marked_accounts_only_and_pages_by_id() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let other = Uuid::new_v4();
    local(&repo, tenant, "local-one").await;
    let mut marked = Vec::new();
    for i in 0..5 {
        marked.push(directory(&repo, tenant, &format!("dir-{i}")).await);
    }
    directory(&repo, other, "elsewhere").await;

    let mut seen = Vec::new();
    let mut after = None;
    loop {
        let page = repo
            .list_directory_accounts(tenant, after, 2)
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 2);
        after = Some(page.last().unwrap().id);
        for user in page {
            assert!(user.is_directory_account());
            assert_eq!(user.tenant_id, tenant);
            seen.push(user.id);
        }
    }
    marked.sort();
    let mut sorted_seen = seen.clone();
    sorted_seen.sort();
    assert_eq!(
        sorted_seen, marked,
        "every marked account once, no local one"
    );
    assert_eq!(seen, sorted_seen, "pages come in id order");
}

#[tokio::test]
async fn deactivating_sets_inactive_and_only_inactive() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let id = directory(&repo, tenant, "alice").await;

    let after = repo
        .deactivate_directory_account(tenant, id)
        .await
        .unwrap()
        .expect("the account was active");
    assert_eq!(after.status, UserStatus::Inactive);
    assert!(after.is_directory_account(), "the marker is kept");
    assert_eq!(
        repo.get_by_id(tenant, id).await.unwrap().status,
        UserStatus::Inactive
    );

    // A second call is a compare-and-set that matches nothing: not an error.
    assert!(
        repo.deactivate_directory_account(tenant, id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn deactivating_takes_pending_and_locked_accounts_too() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    for status in [UserStatus::PendingVerification, UserStatus::Locked] {
        let id = directory(&repo, tenant, &format!("u-{}", Uuid::new_v4().simple())).await;
        repo.update(
            tenant,
            id,
            UpdateUser {
                status: Some(status),
                ..UpdateUser::default()
            },
        )
        .await
        .unwrap();
        assert!(
            repo.deactivate_directory_account(tenant, id)
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn deactivating_never_touches_a_local_account_or_another_tenants() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let local_id = local(&repo, tenant, "local").await;
    assert!(
        repo.deactivate_directory_account(tenant, local_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_by_id(tenant, local_id).await.unwrap().status,
        UserStatus::PendingVerification
    );

    let marked = directory(&repo, tenant, "marked").await;
    assert!(
        repo.deactivate_directory_account(Uuid::new_v4(), marked)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_by_id(tenant, marked).await.unwrap().status,
        UserStatus::Active
    );
}

#[tokio::test]
async fn deactivating_does_not_overwrite_a_deleted_account() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let id = directory(&repo, tenant, "gone").await;
    repo.update(
        tenant,
        id,
        UpdateUser {
            status: Some(UserStatus::Deleted),
            ..UpdateUser::default()
        },
    )
    .await
    .unwrap();
    assert!(
        repo.deactivate_directory_account(tenant, id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        repo.get_by_id(tenant, id).await.unwrap().status,
        UserStatus::Deleted
    );
}

#[tokio::test]
async fn the_collision_probe_can_leave_one_account_out() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let alice = directory(&repo, tenant, "alice").await;
    let bob = local(&repo, tenant, "bob").await;

    // Alice's own name, in another case, is not a collision with anyone else...
    let own = vec!["ALICE".to_string(), "Alice@Example.com".to_string()];
    assert!(
        repo.find_identity_collision_excluding(tenant, &own, alice)
            .await
            .unwrap()
            .is_none()
    );
    // ...but the unqualified probe still sees her.
    assert!(
        repo.find_identity_collision(tenant, &own)
            .await
            .unwrap()
            .is_some()
    );

    // Bob's name and bob's address do collide, with Bob, in the right column.
    let hit = repo
        .find_identity_collision_excluding(tenant, &["BOB".to_string()], alice)
        .await
        .unwrap()
        .expect("a collision");
    assert_eq!(
        (hit.user_id, hit.attribute),
        (bob, CollisionAttribute::Username)
    );
    let hit = repo
        .find_identity_collision_excluding(tenant, &["bob@example.com".to_string()], alice)
        .await
        .unwrap()
        .expect("a collision");
    assert_eq!(
        (hit.user_id, hit.attribute),
        (bob, CollisionAttribute::Email)
    );

    // Another tenant's names are nobody's business.
    assert!(
        repo.find_identity_collision_excluding(Uuid::new_v4(), &["bob".to_string()], alice)
            .await
            .unwrap()
            .is_none()
    );
}

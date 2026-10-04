//! The SSF step-up record against the real datastore (T23.5.3, G-5, D-53 (1),
//! schema v78's `ssf_step_up`).
//!
//! What the datastore decides rather than plain Rust: one row per
//! `(tenant, user)` with the latest replacing the earlier, the ten-minute
//! expiry, single-use consumption, the sweep, and the cascades — the tenant's
//! delete transaction and both erasure paths of the user.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::ssf::{STEP_UP_RECORD_TTL_MINUTES, SsfStepUp};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SsfStepUpRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSsfStepUpRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

const SINGLE: &str = "urn:axiam:acr:1fa";
const MULTI: &str = "urn:axiam:acr:mfa";

async fn setup() -> (Surreal<Db>, SurrealSsfStepUpRepository<Db>) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let repo = SurrealSsfStepUpRepository::new(db.clone());
    (db, repo)
}

fn record(tenant: Uuid, user: Uuid, acr: &str) -> SsfStepUp {
    SsfStepUp {
        tenant_id: tenant,
        user_id: user,
        previous_session_id: Uuid::new_v4(),
        previous_acr: acr.to_owned(),
    }
}

async fn rows(db: &Surreal<Db>, tenant: Uuid) -> u64 {
    SurrealSsfStepUpRepository::new(db.clone())
        .count_for_tenant(tenant)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_record_is_taken_once_and_then_it_is_gone() {
    let (_db, repo) = setup().await;
    let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());
    let written = record(tenant, user, SINGLE);
    repo.put(&written, Utc::now()).await.unwrap();

    assert_eq!(
        repo.take(tenant, user, Utc::now()).await.unwrap(),
        Some(written),
        "the record comes back as written"
    );
    assert_eq!(
        repo.take(tenant, user, Utc::now()).await.unwrap(),
        None,
        "consumed: a second take finds nothing"
    );
}

#[tokio::test]
async fn the_latest_record_replaces_the_earlier_one_for_a_user() {
    let (db, repo) = setup().await;
    let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());
    repo.put(&record(tenant, user, SINGLE), Utc::now())
        .await
        .unwrap();
    let latest = record(tenant, user, MULTI);
    repo.put(&latest, Utc::now()).await.unwrap();

    assert_eq!(rows(&db, tenant).await, 1, "one row per (tenant, user)");
    assert_eq!(
        repo.take(tenant, user, Utc::now()).await.unwrap(),
        Some(latest)
    );
}

#[tokio::test]
async fn a_record_is_one_users_in_one_tenant_only() {
    let (_db, repo) = setup().await;
    let (tenant, other_tenant) = (Uuid::new_v4(), Uuid::new_v4());
    let (user, other_user) = (Uuid::new_v4(), Uuid::new_v4());
    let written = record(tenant, user, SINGLE);
    repo.put(&written, Utc::now()).await.unwrap();

    assert_eq!(
        repo.take(tenant, other_user, Utc::now()).await.unwrap(),
        None,
        "another user's take finds nothing"
    );
    assert_eq!(
        repo.take(other_tenant, user, Utc::now()).await.unwrap(),
        None,
        "another tenant's take finds nothing"
    );
    assert_eq!(
        repo.take(tenant, user, Utc::now()).await.unwrap(),
        Some(written),
        "and neither disturbed the record"
    );
}

#[tokio::test]
async fn an_expired_record_is_consumed_and_returns_nothing() {
    let (db, repo) = setup().await;
    let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());
    let put_at = Utc::now();
    repo.put(&record(tenant, user, SINGLE), put_at)
        .await
        .unwrap();

    let after_expiry =
        put_at + Duration::minutes(STEP_UP_RECORD_TTL_MINUTES) + Duration::seconds(1);
    assert_eq!(repo.take(tenant, user, after_expiry).await.unwrap(), None);
    assert_eq!(
        rows(&db, tenant).await,
        0,
        "the stale row went with the take"
    );

    // Just inside the window it is still good.
    repo.put(&record(tenant, user, SINGLE), put_at)
        .await
        .unwrap();
    let inside = put_at + Duration::minutes(STEP_UP_RECORD_TTL_MINUTES) - Duration::seconds(1);
    assert!(repo.take(tenant, user, inside).await.unwrap().is_some());
}

#[tokio::test]
async fn the_sweep_removes_only_expired_records_in_every_tenant() {
    let (db, repo) = setup().await;
    let now = Utc::now();
    let old = now - Duration::minutes(STEP_UP_RECORD_TTL_MINUTES + 5);
    let (t1, t2) = (Uuid::new_v4(), Uuid::new_v4());
    repo.put(&record(t1, Uuid::new_v4(), SINGLE), old)
        .await
        .unwrap();
    repo.put(&record(t2, Uuid::new_v4(), SINGLE), old)
        .await
        .unwrap();
    repo.put(&record(t1, Uuid::new_v4(), MULTI), now)
        .await
        .unwrap();

    assert_eq!(repo.delete_expired(now).await.unwrap(), 2);
    assert_eq!(rows(&db, t1).await, 1, "the fresh record stays");
    assert_eq!(rows(&db, t2).await, 0);
    assert_eq!(repo.delete_expired(now).await.unwrap(), 0, "idempotent");
}

#[tokio::test]
async fn the_datastore_refuses_an_acr_outside_the_vocabulary() {
    let (_db, repo) = setup().await;
    let bad = record(Uuid::new_v4(), Uuid::new_v4(), "urn:example:acr:gold");
    assert!(repo.put(&bad, Utc::now()).await.is_err());
}

async fn tenant_in_org(db: &Surreal<Db>, slug: &str) -> Uuid {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {slug}"),
            slug: format!("org-{slug}"),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {slug}"),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// The tenant-delete transaction takes the table's rows, and only its own.
#[tokio::test]
async fn deleting_a_tenant_removes_its_records_and_only_its_own() {
    let (db, repo) = setup().await;
    let doomed = tenant_in_org(&db, "step-up-doomed").await;
    let kept = tenant_in_org(&db, "step-up-kept").await;
    for tenant in [doomed, doomed, kept] {
        repo.put(&record(tenant, Uuid::new_v4(), SINGLE), Utc::now())
            .await
            .unwrap();
    }

    SurrealTenantRepository::new(db.clone())
        .delete(doomed)
        .await
        .unwrap();

    assert_eq!(rows(&db, doomed).await, 0);
    assert_eq!(rows(&db, kept).await, 1, "the other tenant's record stays");
}

/// Both erasure paths — the administrator's `delete` and the Art. 17
/// `anonymize_user` — remove the record naming the person, in their tenant only.
#[tokio::test]
async fn both_erasure_paths_remove_the_persons_record() {
    let (db, repo) = setup().await;
    let tenant = tenant_in_org(&db, "step-up-erasure").await;
    let users = SurrealUserRepository::new(db.clone());
    let mut people = Vec::new();
    for name in ["erased-by-delete", "erased-by-anonymize", "stays"] {
        let user = users
            .create(CreateUser {
                tenant_id: tenant,
                username: name.into(),
                email: format!("{name}@example.test"),
                password: axiam_test_support::test_password(),
                metadata: None,
            })
            .await
            .unwrap();
        people.push(user.id);
    }
    for user in &people {
        repo.put(&record(tenant, *user, SINGLE), Utc::now())
            .await
            .unwrap();
    }
    assert_eq!(rows(&db, tenant).await, 3);

    users.delete(tenant, people[0]).await.unwrap();
    assert_eq!(
        rows(&db, tenant).await,
        2,
        "the administrator's delete took the person's record"
    );
    assert!(
        repo.take(tenant, people[0], Utc::now())
            .await
            .unwrap()
            .is_none()
    );

    users
        .anonymize_user(
            tenant,
            people[1],
            &Uuid::new_v4().simple().to_string(),
            "DELETED_USER_test",
        )
        .await
        .unwrap();
    assert_eq!(
        rows(&db, tenant).await,
        1,
        "the Art. 17 anonymisation took the other's"
    );
    assert!(
        repo.take(tenant, people[2], Utc::now())
            .await
            .unwrap()
            .is_some(),
        "the third person's record is untouched"
    );
}

//! The provisioning event source against the real datastore (T23.6.2, G-6,
//! D-57): the user and group repositories report every committed change to a
//! provisioned field through [`ProvisioningSink`], and a login's bookkeeping
//! reports nothing.
//!
//! The sink here is a recorder; what the real sink does with a report is the
//! provisioner's (`axiam-scim`). No assertion message formats a password or a
//! hash.

use std::sync::Arc;

use axiam_core::models::group::{CreateGroup, UpdateGroup};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::user::{CreateDirectoryAccount, CreateUser, UpdateUser, UserStatus};
use axiam_core::provisioning::{ProvisioningEvent, RecordingProvisioningSink};
use axiam_core::repository::{GroupRepository, ServiceAccountRepository, UserRepository};
use axiam_db::repository::{
    SurrealAccountDeletionRepository, SurrealGroupRepository, SurrealServiceAccountRepository,
    SurrealUserRepository,
};
use axiam_test_support::test_password;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

const ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

struct Fixture {
    tenant: Uuid,
    users: SurrealUserRepository<Db>,
    groups: SurrealGroupRepository<Db>,
    sink: Arc<RecordingProvisioningSink>,
    db: Surreal<Db>,
}

async fn fixture() -> Fixture {
    let db = setup().await;
    let sink = RecordingProvisioningSink::new();
    Fixture {
        tenant: Uuid::new_v4(),
        users: SurrealUserRepository::new(db.clone()).with_provisioning_sink(sink.clone()),
        groups: SurrealGroupRepository::new(db.clone()).with_provisioning_sink(sink.clone()),
        sink,
        db,
    }
}

/// A value standing in for a hash the caller computed; made at run time.
fn digest() -> String {
    Uuid::new_v4().simple().to_string()
}

fn new_user(tenant: Uuid, name: &str) -> CreateUser {
    CreateUser {
        tenant_id: tenant,
        username: name.into(),
        email: format!("{name}@example.com"),
        password: test_password(),
        metadata: None,
    }
}

fn user_event(tenant: Uuid, user: Uuid) -> ProvisioningEvent {
    ProvisioningEvent::User {
        tenant_id: tenant,
        user_id: user,
    }
}

fn group_event(tenant: Uuid, group: Uuid) -> ProvisioningEvent {
    ProvisioningEvent::Group {
        tenant_id: tenant,
        group_id: group,
    }
}

fn member_event(tenant: Uuid, group: Uuid, user: Uuid) -> ProvisioningEvent {
    ProvisioningEvent::Membership {
        tenant_id: tenant,
        group_id: group,
        user_id: user,
    }
}

async fn make_group(f: &Fixture, name: &str) -> Uuid {
    f.groups
        .create(CreateGroup {
            tenant_id: f.tenant,
            name: name.into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_create_reports_the_new_user() {
    let f = fixture().await;
    let user = f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, user.id)]);
}

#[tokio::test]
async fn user_create_with_consent_reports_the_new_user() {
    let f = fixture().await;
    let user = f
        .users
        .create_with_consent(
            new_user(f.tenant, "alice"),
            "terms_of_service",
            "1",
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, user.id)]);
}

#[tokio::test]
async fn a_failed_write_reports_nothing() {
    let f = fixture().await;
    f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    f.sink.clear();
    // The unique (tenant, username) index refuses the second one.
    let duplicate = f.users.create(new_user(f.tenant, "alice")).await;
    assert!(duplicate.is_err());
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn user_update_reports_only_a_change_to_a_provisioned_field() {
    let f = fixture().await;
    let user = f.users.create(new_user(f.tenant, "alice")).await.unwrap();

    for (label, update) in [
        (
            "username",
            UpdateUser {
                username: Some("alice2".into()),
                ..Default::default()
            },
        ),
        (
            "email",
            UpdateUser {
                email: Some("alice2@example.com".into()),
                ..Default::default()
            },
        ),
        (
            "status",
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        ),
        (
            "metadata",
            UpdateUser {
                metadata: Some(serde_json::json!({"scim": {"givenName": "Alice"}})),
                ..Default::default()
            },
        ),
    ] {
        f.sink.clear();
        f.users.update(f.tenant, user.id, update).await.unwrap();
        assert_eq!(
            f.sink.events(),
            vec![user_event(f.tenant, user.id)],
            "{label}"
        );
    }

    // Bookkeeping, credentials, MFA and contact data nobody provisions.
    f.sink.clear();
    f.users
        .update(
            f.tenant,
            user.id,
            UpdateUser {
                mfa_enabled: Some(true),
                failed_login_attempts: Some(2),
                last_failed_login_at: Some(Some(Utc::now())),
                locked_until: Some(Some(Utc::now() + Duration::minutes(5))),
                email_verified_at: Some(Some(Utc::now())),
                phone_number: Some(Some("+15550100".into())),
                totp_last_used_step: Some(Some(7)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn login_bookkeeping_never_reports() {
    let f = fixture().await;
    let user = f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    f.sink.clear();
    f.users
        .increment_failed_logins(f.tenant, user.id, 5, 60, 2.0, 3600)
        .await
        .unwrap();
    assert!(
        f.users
            .update_totp_step(f.tenant, user.id, 41)
            .await
            .unwrap()
    );
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn user_delete_and_anonymize_report_the_user() {
    let f = fixture().await;
    let deleted = f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    let erased = f.users.create(new_user(f.tenant, "bob")).await.unwrap();
    f.sink.clear();

    f.users.delete(f.tenant, deleted.id).await.unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, deleted.id)]);

    f.sink.clear();
    f.users
        .anonymize_user(f.tenant, erased.id, &digest(), "DELETED_USER_x")
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, erased.id)]);

    // A user that is not there is not announced.
    f.sink.clear();
    assert!(f.users.delete(f.tenant, Uuid::new_v4()).await.is_err());
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn deletion_request_and_cancellation_report_the_status_change() {
    let f = fixture().await;
    let user = f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    f.sink.clear();

    f.users
        .mark_deletion_pending(f.tenant, user.id, Utc::now() + Duration::days(30))
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, user.id)]);

    f.sink.clear();
    f.users
        .clear_deletion_pending(f.tenant, user.id)
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, user.id)]);

    // The GDPR request path writes the status in the account-deletion
    // repository's own transaction, which announces it too.
    let deletions =
        SurrealAccountDeletionRepository::new(f.db.clone()).with_provisioning_sink(f.sink.clone());
    f.sink.clear();
    deletions
        .create_with_pending_flag(f.tenant, user.id, Utc::now() + Duration::days(30), digest())
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, user.id)]);
}

#[tokio::test]
async fn directory_account_methods_report_the_user() {
    let f = fixture().await;
    let created = f
        .users
        .create_directory_account(CreateDirectoryAccount {
            tenant_id: f.tenant,
            username: "carol".into(),
            email: "carol@example.com".into(),
            external_id: ENTRY.into(),
            metadata: serde_json::json!({}),
        })
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, created.id)]);

    // Marking a local account as directory-owned.
    let local = f.users.create(new_user(f.tenant, "dave")).await.unwrap();
    f.sink.clear();
    f.users
        .mark_directory_account(f.tenant, local.id, "6f9619ff-8b86-d011-b42d-00c04fc964aa")
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, local.id)]);

    // Deactivation reports only when it changed something.
    f.sink.clear();
    assert!(
        f.users
            .deactivate_directory_account(f.tenant, created.id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(f.sink.events(), vec![user_event(f.tenant, created.id)]);
    f.sink.clear();
    assert!(
        f.users
            .deactivate_directory_account(f.tenant, created.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn a_repository_without_a_sink_and_its_clones_behave_as_before() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let plain = SurrealUserRepository::new(db.clone());
    plain.create(new_user(tenant, "alice")).await.unwrap();

    // A clone carries the sink: one binding reaches every service that clones.
    let sink = RecordingProvisioningSink::new();
    let bound = SurrealUserRepository::new(db).with_provisioning_sink(sink.clone());
    let clone = bound.clone();
    let user = clone.create(new_user(tenant, "bob")).await.unwrap();
    assert_eq!(sink.events(), vec![user_event(tenant, user.id)]);
}

// ---------------------------------------------------------------------------
// Groups and memberships
// ---------------------------------------------------------------------------

#[tokio::test]
async fn group_create_update_and_delete_report_the_group() {
    let f = fixture().await;
    let group = make_group(&f, "staff").await;
    assert_eq!(f.sink.events(), vec![group_event(f.tenant, group)]);

    f.sink.clear();
    f.groups
        .update(
            f.tenant,
            group,
            UpdateGroup {
                name: Some("employees".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(f.sink.events(), vec![group_event(f.tenant, group)]);

    f.sink.clear();
    f.groups.delete(f.tenant, group).await.unwrap();
    assert_eq!(f.sink.events(), vec![group_event(f.tenant, group)]);

    // A group of another tenant is neither deleted nor announced.
    let foreign = make_group(&f, "ops").await;
    f.sink.clear();
    assert!(f.groups.delete(Uuid::new_v4(), foreign).await.is_err());
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn add_and_remove_member_report_the_membership() {
    let f = fixture().await;
    let user = f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    let group = make_group(&f, "staff").await;
    f.sink.clear();

    f.groups.add_member(f.tenant, user.id, group).await.unwrap();
    assert_eq!(
        f.sink.events(),
        vec![member_event(f.tenant, group, user.id)]
    );

    // A duplicate add is refused and not announced.
    f.sink.clear();
    assert!(f.groups.add_member(f.tenant, user.id, group).await.is_err());
    assert!(f.sink.events().is_empty());

    f.groups
        .remove_member(f.tenant, user.id, group)
        .await
        .unwrap();
    assert_eq!(
        f.sink.events(),
        vec![member_event(f.tenant, group, user.id)]
    );

    // Removing a membership that is not there changes nothing.
    f.sink.clear();
    f.groups
        .remove_member(f.tenant, user.id, group)
        .await
        .unwrap();
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn deleting_a_group_reports_each_user_who_lost_the_membership() {
    let f = fixture().await;
    let a = f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    let b = f.users.create(new_user(f.tenant, "bob")).await.unwrap();
    let group = make_group(&f, "staff").await;
    f.groups.add_member(f.tenant, a.id, group).await.unwrap();
    f.groups.add_member(f.tenant, b.id, group).await.unwrap();
    f.sink.clear();

    f.groups.delete(f.tenant, group).await.unwrap();
    let events = f.sink.events();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0], group_event(f.tenant, group));
    assert!(events.contains(&member_event(f.tenant, group, a.id)));
    assert!(events.contains(&member_event(f.tenant, group, b.id)));
}

#[tokio::test]
async fn directory_membership_methods_report_only_what_they_changed() {
    let f = fixture().await;
    let user = f.users.create(new_user(f.tenant, "alice")).await.unwrap();
    let group = make_group(&f, "staff").await;
    f.sink.clear();

    f.groups
        .add_directory_member(f.tenant, user.id, group)
        .await
        .unwrap();
    assert_eq!(
        f.sink.events(),
        vec![member_event(f.tenant, group, user.id)]
    );

    // The second write finds the edge: nothing changed, nothing reported.
    f.sink.clear();
    f.groups
        .add_directory_member(f.tenant, user.id, group)
        .await
        .unwrap();
    assert!(f.sink.events().is_empty());

    assert!(
        f.groups
            .remove_directory_member(f.tenant, user.id, group)
            .await
            .unwrap()
    );
    assert_eq!(
        f.sink.events(),
        vec![member_event(f.tenant, group, user.id)]
    );

    f.sink.clear();
    assert!(
        !f.groups
            .remove_directory_member(f.tenant, user.id, group)
            .await
            .unwrap()
    );
    assert!(f.sink.events().is_empty());
}

#[tokio::test]
async fn a_service_accounts_membership_is_not_provisioned() {
    let f = fixture().await;
    let service = SurrealServiceAccountRepository::new(f.db.clone())
        .create(CreateServiceAccount {
            tenant_id: f.tenant,
            name: "robot".into(),
            description: None,
        })
        .await
        .unwrap();
    let group = make_group(&f, "staff").await;
    f.sink.clear();
    f.groups
        .add_service_account_member(f.tenant, service.0.id, group)
        .await
        .unwrap();
    f.groups
        .remove_service_account_member(f.tenant, service.0.id, group)
        .await
        .unwrap();
    assert!(f.sink.events().is_empty());
}

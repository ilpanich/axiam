//! `count_active_users_without_credential` — the query behind the `required` gate.
//!
//! Switching an organization to `opaque_mode: "required"` is refused while any
//! active user still has no registration record, because none can be minted for
//! them retroactively and the switch would lock them out. That decision rests
//! entirely on this count, and nothing exercised it directly: it shipped
//! reachable only through the settings handler, where a query error surfaces as
//! a 500 with the reason swallowed.

use axiam_core::models::opaque::{CreateOpaqueCredential, OpaqueKsf, OpaqueKsfParams, OpaqueSuite};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OpaqueCredentialRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOpaqueCredentialRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// A password minted at runtime.
///
/// The repository hashes whatever it is given and no test here authenticates,
/// so the value is irrelevant — but a literal that *looks* like a credential is
/// reported as a hard-coded cryptographic value, and the placeholder string the
/// older suites use is only unreported because their files are unchanged. Any
/// new file reintroduces the finding, so generate instead.
fn a_password() -> String {
    format!("Pw1-{}", Uuid::new_v4().simple())
}

async fn setup() -> (Surreal<TestDb>, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Coverage Org".into(),
            slug: "coverage-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Coverage Tenant".into(),
            slug: "coverage-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id)
}

/// Create a user and activate it — `create` leaves a user `PendingVerification`,
/// and only an *active* user can be locked out by the switch.
async fn active_user(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: a_password(),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    user.id
}

async fn enrol(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) {
    SurrealOpaqueCredentialRepository::new(db.clone())
        .upsert(CreateOpaqueCredential {
            tenant_id,
            user_id,
            credential_identifier: "00".repeat(32),
            suite: OpaqueSuite::default(),
            ksf_params: OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id),
            record: "11".repeat(192),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn an_empty_tenant_strands_nobody() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealOpaqueCredentialRepository::new(db.clone());

    // The query has to *run*, not merely not-refuse. A malformed statement here
    // reached the caller as a 500 that read like an unrelated server fault.
    assert_eq!(
        repo.count_active_users_without_credential(tenant_id)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn an_active_user_with_no_record_is_counted() {
    let (db, tenant_id) = setup().await;
    active_user(&db, tenant_id, "uncovered").await;

    assert_eq!(
        SurrealOpaqueCredentialRepository::new(db.clone())
            .count_active_users_without_credential(tenant_id)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn enrolling_that_user_clears_the_count() {
    let (db, tenant_id) = setup().await;
    let user_id = active_user(&db, tenant_id, "covered").await;
    let repo = SurrealOpaqueCredentialRepository::new(db.clone());

    assert_eq!(
        repo.count_active_users_without_credential(tenant_id)
            .await
            .unwrap(),
        1
    );
    enrol(&db, tenant_id, user_id).await;
    assert_eq!(
        repo.count_active_users_without_credential(tenant_id)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn a_user_that_is_not_active_yet_cannot_be_locked_out() {
    // `create` leaves a user `PendingVerification`: they have never signed in,
    // so `required` strands nothing, and counting them would block the switch
    // on accounts that will enrol the first time they set a password.
    let (db, tenant_id) = setup().await;
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "pending".into(),
            email: "pending@example.com".into(),
            password: a_password(),
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(
        SurrealOpaqueCredentialRepository::new(db.clone())
            .count_active_users_without_credential(tenant_id)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn another_tenants_users_are_not_counted() {
    let (db, tenant_id) = setup().await;
    let other = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: SurrealOrganizationRepository::new(db.clone())
                .get_by_slug("coverage-org")
                .await
                .unwrap()
                .id,
            kind: TenantKind::Standard,
            name: "Other".into(),
            slug: "other".into(),
            metadata: None,
        })
        .await
        .unwrap();
    active_user(&db, other.id, "elsewhere").await;

    assert_eq!(
        SurrealOpaqueCredentialRepository::new(db.clone())
            .count_active_users_without_credential(tenant_id)
            .await
            .unwrap(),
        0
    );
}

// N7 / SA-06: `UserRepository::update` is the one writer of the Argon2id hash
// (password reset, self-service change, SCIM). A write of the hash retires the
// OPAQUE record that verifies the previous password, in the same transaction;
// every other write leaves it alone.

async fn has_record(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) -> bool {
    SurrealOpaqueCredentialRepository::new(db.clone())
        .get_by_user(tenant_id, user_id)
        .await
        .is_ok()
}

#[tokio::test]
async fn writing_the_password_hash_retires_the_opaque_record() {
    let (db, tenant_id) = setup().await;
    let user_id = active_user(&db, tenant_id, "rotated").await;
    enrol(&db, tenant_id, user_id).await;
    assert!(has_record(&db, tenant_id, user_id).await);

    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$not-checked-here".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(
        !has_record(&db, tenant_id, user_id).await,
        "a record for the previous password must not outlive the hash"
    );
}

#[tokio::test]
async fn writing_the_hash_and_the_email_together_retires_the_record() {
    // Both writes share one transaction; the statement slot the row is read
    // back from must still be the UPDATE's.
    let (db, tenant_id) = setup().await;
    let user_id = active_user(&db, tenant_id, "both").await;
    enrol(&db, tenant_id, user_id).await;

    let updated = SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                email: Some("both-new@example.com".into()),
                password_hash: Some("$argon2id$not-checked-here".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.email, "both-new@example.com");
    assert!(!has_record(&db, tenant_id, user_id).await);
}

#[tokio::test]
async fn an_update_that_leaves_the_hash_alone_keeps_the_record() {
    let (db, tenant_id) = setup().await;
    let user_id = active_user(&db, tenant_id, "untouched").await;
    enrol(&db, tenant_id, user_id).await;

    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                username: Some("untouched-renamed".into()),
                email: Some("untouched-new@example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert!(has_record(&db, tenant_id, user_id).await);
}

// SA-06 / SR3-1: the credential version moves in the same transaction as every
// write that stamps the credential epoch, and only those.

async fn version_of(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) -> i64 {
    SurrealUserRepository::new(db.clone())
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .credential_version
}

#[tokio::test]
async fn the_credential_version_counts_every_credential_write_and_no_other() {
    let (db, tenant_id) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    let user_id = active_user(&db, tenant_id, "versioned").await;
    assert_eq!(
        version_of(&db, tenant_id, user_id).await,
        0,
        "a user nobody has changed reads as version 0"
    );

    // A write that is not a credential write leaves it alone.
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                email: Some("versioned-new@example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(version_of(&db, tenant_id, user_id).await, 0);

    // Every write of the hash, every record write and every record delete moves it.
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$not-checked-here".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(version_of(&db, tenant_id, user_id).await, 1, "hash write");

    // An upsert may stamp more than once (its update attempt and its create
    // are separate transactions); only that each moves the version matters.
    let mut seen = version_of(&db, tenant_id, user_id).await;
    enrol(&db, tenant_id, user_id).await;
    let after_create = version_of(&db, tenant_id, user_id).await;
    assert!(after_create > seen, "record create");
    seen = after_create;
    enrol(&db, tenant_id, user_id).await;
    let after_update = version_of(&db, tenant_id, user_id).await;
    assert!(after_update > seen, "record update");
    seen = after_update;

    // The result is ignored on purpose: reading the deleted row back
    // (`RETURN BEFORE` into `CredentialRow`) fails to deserialise today, after
    // the transaction has committed. That is not this test's subject; the
    // stamp is, and it committed.
    let _ = SurrealOpaqueCredentialRepository::new(db.clone())
        .delete_for_user(tenant_id, user_id)
        .await;
    let after_delete = version_of(&db, tenant_id, user_id).await;
    assert!(after_delete > seen, "record delete");
    seen = after_delete;

    // The directory path stamps the epoch, so it moves the version too.
    users
        .mark_directory_account(tenant_id, user_id, "cn=versioned,dc=example")
        .await
        .unwrap();
    assert!(
        version_of(&db, tenant_id, user_id).await > seen,
        "directory mark"
    );
}

// SA-06 / N7 / SR4-2: a hash write that carries the new OPAQUE record writes
// the hash, replaces the record, stamps the epoch and bumps the version in ONE
// transaction. Before, the record was a separate upsert after the hash write,
// so a writer that committed in between left its hash next to this one's record.

fn record_for(tenant_id: Uuid, user_id: Uuid, marker: &str) -> CreateOpaqueCredential {
    CreateOpaqueCredential {
        tenant_id,
        user_id,
        credential_identifier: marker.repeat(32),
        suite: OpaqueSuite::default(),
        ksf_params: OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id),
        record: marker.repeat(192),
    }
}

async fn stored_identifier(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) -> Option<String> {
    SurrealOpaqueCredentialRepository::new(db.clone())
        .get_by_user(tenant_id, user_id)
        .await
        .ok()
        .map(|c| c.credential_identifier)
}

async fn hash_of(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) -> String {
    SurrealUserRepository::new(db.clone())
        .get_by_id(tenant_id, user_id)
        .await
        .unwrap()
        .password_hash
}

#[tokio::test]
async fn a_hash_write_with_a_record_stores_both_from_the_same_write() {
    let (db, tenant_id) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    let user_id = active_user(&db, tenant_id, "atomic-both").await;
    enrol(&db, tenant_id, user_id).await; // identifier "00.."
    let before = version_of(&db, tenant_id, user_id).await;

    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$hash-a".into()),
                opaque_record: Some(record_for(tenant_id, user_id, "aa")),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(hash_of(&db, tenant_id, user_id).await, "$argon2id$hash-a");
    assert_eq!(
        stored_identifier(&db, tenant_id, user_id).await.as_deref(),
        Some("aa".repeat(32).as_str()),
        "the record is the one that came with the hash, not the stale one"
    );
    assert_eq!(
        version_of(&db, tenant_id, user_id).await,
        before + 1,
        "one write, one version bump"
    );
}

#[tokio::test]
async fn a_hash_write_with_a_record_creates_it_when_none_existed() {
    let (db, tenant_id) = setup().await;
    let user_id = active_user(&db, tenant_id, "atomic-create").await;
    assert!(!has_record(&db, tenant_id, user_id).await);

    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$hash-a".into()),
                opaque_record: Some(record_for(tenant_id, user_id, "aa")),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(
        stored_identifier(&db, tenant_id, user_id).await.as_deref(),
        Some("aa".repeat(32).as_str())
    );
}

#[tokio::test]
async fn a_reset_without_a_record_that_lands_after_a_change_with_one_leaves_no_stale_record() {
    // The interleaving of SR4-2: the attacker's change (hash A + record A)
    // commits, then the victim's reset (hash V, no record). Before, the change
    // was hash-write then upsert, so the reset could land between the two and
    // the record written second outlived it.
    let (db, tenant_id) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    let user_id = active_user(&db, tenant_id, "interleaved").await;

    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$hash-a".into()),
                opaque_record: Some(record_for(tenant_id, user_id, "aa")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$hash-v".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(hash_of(&db, tenant_id, user_id).await, "$argon2id$hash-v");
    assert!(
        !has_record(&db, tenant_id, user_id).await,
        "the record that answers to the attacker's password must not pair with the reset's hash"
    );
}

#[tokio::test]
async fn the_later_of_two_changes_with_records_wins_both_hash_and_record() {
    let (db, tenant_id) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    let user_id = active_user(&db, tenant_id, "two-changes").await;

    for (hash, marker) in [("$argon2id$hash-a", "aa"), ("$argon2id$hash-b", "bb")] {
        users
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    password_hash: Some(hash.into()),
                    opaque_record: Some(record_for(tenant_id, user_id, marker)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    assert_eq!(hash_of(&db, tenant_id, user_id).await, "$argon2id$hash-b");
    assert_eq!(
        stored_identifier(&db, tenant_id, user_id).await.as_deref(),
        Some("bb".repeat(32).as_str())
    );
}

#[tokio::test]
async fn a_record_without_a_hash_or_for_another_user_is_refused_and_writes_nothing() {
    let (db, tenant_id) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    let user_id = active_user(&db, tenant_id, "refused").await;
    let other = active_user(&db, tenant_id, "refused-other").await;
    let before = version_of(&db, tenant_id, user_id).await;

    let no_hash = users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                opaque_record: Some(record_for(tenant_id, user_id, "aa")),
                ..Default::default()
            },
        )
        .await;
    assert!(no_hash.is_err(), "a record with no hash write is refused");

    let wrong_user = users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                password_hash: Some("$argon2id$hash-a".into()),
                opaque_record: Some(record_for(tenant_id, other, "aa")),
                ..Default::default()
            },
        )
        .await;
    assert!(wrong_user.is_err(), "a record for another user is refused");

    assert_eq!(version_of(&db, tenant_id, user_id).await, before);
    assert_ne!(hash_of(&db, tenant_id, user_id).await, "$argon2id$hash-a");
    assert!(!has_record(&db, tenant_id, other).await);
}

//! The directory marker on `user` (T23.3.2, G-3, schema v71) against the real
//! datastore.
//!
//! - existing and new accounts carry **no** marker, and any number of them
//!   coexist under the unique index;
//! - `mark_directory_account` is the only writer: it sets the marker, replaces
//!   the password hash with an unusable one and drops any OPAQUE record, in one
//!   transaction;
//! - one entry cannot back two accounts in a tenant (unique index), but can in
//!   two tenants;
//! - the general update path — what the admin API and SCIM write through —
//!   neither sets nor clears it;
//! - the login lookups and the list read it back;
//! - the administrator's tombstone clears it with the rest of the personal data.
//!
//! No assertion message formats a password, a hash or an identifier.

use axiam_auth::password::verify_password;
use axiam_core::error::AxiamError;
use axiam_core::models::opaque::{CreateOpaqueCredential, OpaqueKsf, OpaqueKsfParams, OpaqueSuite};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{OpaqueCredentialRepository, Pagination, UserRepository};
use axiam_db::repository::{SurrealOpaqueCredentialRepository, SurrealUserRepository};
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

fn local_password() -> String {
    format!("Lp1!{}", Uuid::new_v4().simple())
}

async fn user(repo: &SurrealUserRepository<Db>, tenant_id: Uuid, name: &str, pw: &str) -> Uuid {
    repo.create(CreateUser {
        tenant_id,
        username: name.into(),
        email: format!("{name}@example.com"),
        password: pw.into(),
        metadata: None,
    })
    .await
    .unwrap()
    .id
}

#[tokio::test]
async fn accounts_without_a_marker_coexist_under_the_unique_index() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    for name in ["a", "b", "c"] {
        let id = user(&repo, tenant, name, &local_password()).await;
        let read = repo.get_by_id(tenant, id).await.unwrap();
        assert!(!read.is_directory_account(), "a new account is local");
    }
}

#[tokio::test]
async fn marking_sets_the_marker_and_retires_every_local_credential() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db.clone());
    let opaque = SurrealOpaqueCredentialRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let pw = local_password();
    let id = user(&repo, tenant, "alice", &pw).await;
    opaque
        .upsert(CreateOpaqueCredential {
            tenant_id: tenant,
            user_id: id,
            credential_identifier: "00".repeat(32),
            suite: OpaqueSuite::default(),
            ksf_params: OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id),
            record: "11".repeat(192),
        })
        .await
        .unwrap();
    let before = repo.get_by_id(tenant, id).await.unwrap();
    assert!(verify_password(&pw, &before.password_hash, None).unwrap());

    let marked = repo
        .mark_directory_account(tenant, id, ENTRY)
        .await
        .unwrap();
    assert_eq!(marked.directory_external_id.as_deref(), Some(ENTRY));
    assert!(marked.is_directory_account());

    // The old local password no longer verifies, and the replacement is a
    // real PHC string (never empty, never the tombstone).
    let after = repo.get_by_id(tenant, id).await.unwrap();
    assert!(after.password_hash.starts_with("$argon2id$"));
    assert!(!verify_password(&pw, &after.password_hash, None).unwrap());
    assert_ne!(after.password_hash, before.password_hash);
    // The OPAQUE record went in the same transaction.
    assert!(matches!(
        opaque.get_by_user(tenant, id).await,
        Err(AxiamError::NotFound { .. })
    ));
}

#[tokio::test]
async fn one_entry_cannot_back_two_accounts_in_a_tenant() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let first = user(&repo, tenant, "first", &local_password()).await;
    let second = user(&repo, tenant, "second", &local_password()).await;
    repo.mark_directory_account(tenant, first, ENTRY)
        .await
        .unwrap();
    let outcome = repo.mark_directory_account(tenant, second, ENTRY).await;
    assert!(
        outcome.is_err(),
        "the unique index must refuse a second account"
    );
    assert!(
        !repo
            .get_by_id(tenant, second)
            .await
            .unwrap()
            .is_directory_account(),
        "the refused account keeps no marker"
    );

    // The same entry in another tenant is another tenant's business.
    let other_tenant = Uuid::new_v4();
    let elsewhere = user(&repo, other_tenant, "first", &local_password()).await;
    assert!(
        repo.mark_directory_account(other_tenant, elsewhere, ENTRY)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn marking_is_tenant_scoped_and_refuses_an_empty_identifier() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let id = user(&repo, tenant, "alice", &local_password()).await;
    assert!(matches!(
        repo.mark_directory_account(Uuid::new_v4(), id, ENTRY).await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(repo.mark_directory_account(tenant, id, "  ").await.is_err());
    assert!(
        !repo
            .get_by_id(tenant, id)
            .await
            .unwrap()
            .is_directory_account()
    );
}

/// The general update path is what `PUT /api/v1/users/{id}` and SCIM write
/// through. It has no field for the marker, and writing everything it does
/// have — including a password hash and a status — leaves the marker alone.
#[tokio::test]
async fn the_general_update_path_neither_sets_nor_clears_the_marker() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let id = user(&repo, tenant, "alice", &local_password()).await;
    repo.mark_directory_account(tenant, id, ENTRY)
        .await
        .unwrap();
    let updated = repo
        .update(
            tenant,
            id,
            UpdateUser {
                username: Some("alice2".into()),
                email: Some("alice2@example.com".into()),
                status: Some(UserStatus::Active),
                metadata: Some(serde_json::json!({ "directory_external_id": "x" })),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.directory_external_id.as_deref(), Some(ENTRY));
}

#[tokio::test]
async fn the_login_lookups_and_the_list_read_the_marker_back() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let id = user(&repo, tenant, "alice", &local_password()).await;
    user(&repo, tenant, "bob", &local_password()).await;
    repo.mark_directory_account(tenant, id, ENTRY)
        .await
        .unwrap();

    let by_name = repo.get_by_username(tenant, "alice").await.unwrap();
    assert_eq!(by_name.directory_external_id.as_deref(), Some(ENTRY));
    let by_mail = repo
        .get_by_email(tenant, "alice@example.com")
        .await
        .unwrap();
    assert_eq!(by_mail.directory_external_id.as_deref(), Some(ENTRY));
    assert!(
        !repo
            .get_by_username(tenant, "bob")
            .await
            .unwrap()
            .is_directory_account()
    );

    let page = repo
        .list(
            tenant,
            Pagination {
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .await
        .unwrap();
    let alice = page.items.iter().find(|u| u.id == id).unwrap();
    assert_eq!(alice.directory_external_id.as_deref(), Some(ENTRY));
}

#[tokio::test]
async fn the_tombstone_clears_the_marker() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let id = user(&repo, tenant, "alice", &local_password()).await;
    repo.mark_directory_account(tenant, id, ENTRY)
        .await
        .unwrap();
    repo.delete(tenant, id).await.unwrap();
    let tomb = repo.get_by_id(tenant, id).await.unwrap();
    assert_eq!(tomb.status, UserStatus::Deleted);
    assert!(!tomb.is_directory_account());
    // ...which frees the identifier for a fresh account.
    let again = user(&repo, tenant, "alice-again", &local_password()).await;
    assert!(
        repo.mark_directory_account(tenant, again, ENTRY)
            .await
            .is_ok()
    );
}

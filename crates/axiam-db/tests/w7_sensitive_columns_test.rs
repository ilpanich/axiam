//! W7 / X7 G8 — the two GDPR-sensitive user columns, end to end against a real
//! database.
//!
//! # Why this file exists
//!
//! The plan's §4.8 says the new fields are "covered by the existing erasure and
//! export paths because they are user-row fields". They are not. Both erasure
//! statements in `axiam_db::repository::user` write an **explicit column
//! list** — `anonymize_user` and the administrator tombstone behind
//! `UserRepository::delete` — and a column that is not named in one of those
//! lists survives it. An erased subject would have kept their telephone number
//! and postal address indefinitely, with the account hidden from the UI, which
//! is what that tombstone's own doc comment calls "retention with the UI
//! hidden, not erasure".
//!
//! So the columns were added to both statements, and the assertions below are
//! the reason to believe it: each one writes an address and a telephone
//! number, runs the erasure, and reads the row back.
//!
//! The tests deliberately read the row *after* erasure rather than trusting the
//! statement text. A test that greps the SQL would pass the day somebody adds a
//! third erasure path.

use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{Address, CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_test_support::test_password;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup() -> (Surreal<surrealdb::engine::local::Db>, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, tenant.id)
}

fn an_address() -> Address {
    Address {
        formatted: Some("Via Roma 1\n20121 Milano\nItalia".into()),
        street_address: Some("Via Roma 1".into()),
        locality: Some("Milano".into()),
        region: Some("MI".into()),
        postal_code: Some("20121".into()),
        country: Some("Italia".into()),
    }
}

const A_NUMBER: &str = "+390212345678";

async fn a_user_with_sensitive_data(
    repo: &SurrealUserRepository<surrealdb::engine::local::Db>,
    tenant_id: Uuid,
    name: &str,
) -> Uuid {
    let user = repo
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.test"),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    repo.update(
        tenant_id,
        user.id,
        UpdateUser {
            phone_number: Some(Some(A_NUMBER.into())),
            phone_number_verified_at: Some(Some(chrono::Utc::now())),
            address: Some(Some(an_address())),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    user.id
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

/// The columns store and read back every OIDC Core §5.1.1 member. A migration
/// that defined five sub-fields instead of six would lose one silently, which
/// is exactly the failure a `FLEXIBLE` object would have hidden.
#[tokio::test]
async fn the_sensitive_columns_round_trip_every_member() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    let id = a_user_with_sensitive_data(&repo, tenant_id, "roundtrip").await;

    let read = repo.get_by_id(tenant_id, id).await.unwrap();
    assert_eq!(read.phone_number.as_deref(), Some(A_NUMBER));
    assert!(read.phone_number_verified_at.is_some());
    assert_eq!(read.address.as_ref(), Some(&an_address()));
}

/// A user created before this wave — which is every user in every existing
/// deployment — reads back with all three columns absent rather than failing
/// to decode. Invariant I4 at the storage layer.
#[tokio::test]
async fn a_user_that_never_had_these_columns_still_decodes() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "legacy".into(),
            email: "legacy@example.test".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let read = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(read.phone_number, None);
    assert_eq!(read.phone_number_verified_at, None);
    assert_eq!(read.address, None);
}

/// Clearing is a real operation, not a no-op: `Some(None)` removes the value.
/// This is the path a data subject exercising Art. 16 rectification reaches,
/// and it has to work without erasing the whole account.
#[tokio::test]
async fn a_subject_can_have_the_values_cleared_without_being_erased() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    let id = a_user_with_sensitive_data(&repo, tenant_id, "rectify").await;

    repo.update(
        tenant_id,
        id,
        UpdateUser {
            phone_number: Some(None),
            phone_number_verified_at: Some(None),
            address: Some(None),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let read = repo.get_by_id(tenant_id, id).await.unwrap();
    assert_eq!(read.phone_number, None);
    assert_eq!(read.phone_number_verified_at, None);
    assert_eq!(read.address, None);
    assert_eq!(
        read.status,
        UserStatus::PendingVerification,
        "clearing two claims must not touch the account's status"
    );
}

/// An address whose every member is absent is stored as no address at all, so
/// "the subject has an address" and "the address says something" cannot
/// disagree — and UserInfo never emits `"address": {}`.
#[tokio::test]
async fn an_empty_address_is_stored_as_no_address() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    let id = a_user_with_sensitive_data(&repo, tenant_id, "hollow").await;

    repo.update(
        tenant_id,
        id,
        UpdateUser {
            address: Some(Some(Address::default())),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert_eq!(repo.get_by_id(tenant_id, id).await.unwrap().address, None);
}

// ---------------------------------------------------------------------------
// Erasure — the plan's §4.8 claim, checked
// ---------------------------------------------------------------------------

/// GDPR Art. 17, the scheduled pipeline. `anonymize_user` must leave neither
/// value behind.
#[tokio::test]
async fn anonymisation_erases_the_telephone_number_and_the_postal_address() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    let id = a_user_with_sensitive_data(&repo, tenant_id, "anonymised").await;

    repo.anonymize_user(tenant_id, id, "sha256:deadbeef", "anon-1")
        .await
        .unwrap();

    let read = repo.get_by_id(tenant_id, id).await.unwrap();
    assert_eq!(read.status, UserStatus::Anonymized);
    assert_eq!(
        read.phone_number, None,
        "an anonymised subject keeping their telephone number is retention, not erasure"
    );
    assert_eq!(read.phone_number_verified_at, None);
    assert_eq!(
        read.address, None,
        "an anonymised subject keeping their postal address is retention, not erasure"
    );
}

/// The administrator's immediate removal. The tombstone's own documentation
/// says it "holds no personal data"; these two columns are what would have
/// made that untrue.
#[tokio::test]
async fn the_admin_delete_tombstone_erases_them_too() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    let id = a_user_with_sensitive_data(&repo, tenant_id, "tombstoned").await;

    repo.delete(tenant_id, id).await.unwrap();

    let read = repo.get_by_id(tenant_id, id).await.unwrap();
    assert_eq!(read.status, UserStatus::Deleted);
    assert_eq!(read.phone_number, None);
    assert_eq!(read.phone_number_verified_at, None);
    assert_eq!(read.address, None);
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

/// The list projection carries both columns, so a resource's representation
/// does not depend on how it was reached. `GET /scim/v2/Users` reads this
/// path; `GET /scim/v2/Users/{id}` reads `get_by_id`; a `phoneNumbers` that
/// appeared in one and not the other would be a SCIM conformance bug.
///
/// This is where the projection argument *stops*: `mfa_secret` is still
/// excluded here (SEC-043) because it is a credential, and this is not.
#[tokio::test]
async fn the_list_projection_carries_the_sensitive_columns_but_still_no_credential() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    a_user_with_sensitive_data(&repo, tenant_id, "listed").await;

    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    let listed = page
        .items
        .iter()
        .find(|u| u.username == "listed")
        .expect("the user we just created must be in the page");
    assert_eq!(listed.phone_number.as_deref(), Some(A_NUMBER));
    assert_eq!(listed.address.as_ref(), Some(&an_address()));
    assert_eq!(
        listed.mfa_secret, None,
        "SEC-043's exclusion must be untouched by W7 widening the projection"
    );
}

/// Neither value reaches a log line from the list path either, even though the
/// row now carries them. Being in the projection and being in `Debug` are
/// different decisions.
#[tokio::test]
async fn the_listed_user_still_redacts_both_values_when_printed() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);
    a_user_with_sensitive_data(&repo, tenant_id, "printed").await;

    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    let printed = format!("{:?}", page.items);
    assert!(!printed.contains(A_NUMBER), "{printed}");
    assert!(!printed.contains("Via Roma"), "{printed}");
}

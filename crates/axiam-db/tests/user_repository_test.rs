//! Integration tests for User repository using in-memory SurrealDB.

use axiam_auth::password::verify_password;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

/// A throwaway password for a fixture user nothing verifies.
///
/// Generated rather than written as a literal. A constant here is a hard-coded
/// credential to any scanner reading the file — CodeQL's "Hard-coded
/// cryptographic value" rule flags exactly this, at critical severity — and the
/// rule is not wrong about the shape even in a test: a password sitting in
/// source is how one ends up copied into a seeder or a fixture that outlives
/// the test.
///
/// Each call returns a distinct value, so a test also cannot pass by
/// accidentally matching another fixture's password.
///
/// The three tests that assert on their password — `create_and_get_user`,
/// `password_verification`, `password_with_pepper` — keep their literals on
/// purpose: the value is what they are about.
fn fixture_password() -> String {
    format!("fixture-{}", uuid::Uuid::new_v4())
}

/// Helper: spin up in-memory DB, run migrations, create org + tenant.
async fn setup() -> (
    Surreal<surrealdb::engine::local::Db>,
    uuid::Uuid, // tenant_id
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
            kind: TenantKind::Standard,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, tenant.id)
}

#[tokio::test]
async fn create_and_get_user() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "SuperSecret123!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    assert_eq!(user.tenant_id, tenant_id);
    assert_eq!(user.username, "alice");
    assert_eq!(user.email, "alice@example.com");
    assert_eq!(user.status, UserStatus::PendingVerification);
    assert!(!user.mfa_enabled);

    // Password should be hashed, not stored in plaintext.
    assert_ne!(user.password_hash, "SuperSecret123!");
    assert!(user.password_hash.starts_with("$argon2id$"));

    // Get by ID should return the same user.
    let fetched = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(fetched.id, user.id);
    assert_eq!(fetched.username, "alice");
}

#[tokio::test]
async fn password_verification() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "bob".into(),
            email: "bob@example.com".into(),
            password: "MyPassword42!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Correct password should verify.
    assert!(verify_password("MyPassword42!", &user.password_hash, None).unwrap());

    // Wrong password should not verify.
    assert!(!verify_password("WrongPassword", &user.password_hash, None).unwrap());
}

#[tokio::test]
async fn password_with_pepper() {
    let (db, tenant_id) = setup().await;
    let pepper = "server-secret-pepper".to_string();
    let repo = SurrealUserRepository::with_pepper(db, pepper.clone());

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "carol".into(),
            email: "carol@example.com".into(),
            password: "PepperedPass!".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Verify with pepper should succeed.
    assert!(verify_password("PepperedPass!", &user.password_hash, Some(&pepper)).unwrap());

    // Verify without pepper should fail.
    assert!(!verify_password("PepperedPass!", &user.password_hash, None).unwrap());
}

#[tokio::test]
async fn get_user_by_username() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "dave".into(),
            email: "dave@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let fetched = repo.get_by_username(tenant_id, "dave").await.unwrap();
    assert_eq!(fetched.id, user.id);
}

#[tokio::test]
async fn get_user_by_email() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "eve".into(),
            email: "eve@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let fetched = repo
        .get_by_email(tenant_id, "eve@example.com")
        .await
        .unwrap();
    assert_eq!(fetched.id, user.id);
}

#[tokio::test]
async fn update_user() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "frank".into(),
            email: "frank@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            user.id,
            axiam_core::models::user::UpdateUser {
                username: Some("franklin".into()),
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(updated.username, "franklin");
    assert_eq!(updated.status, UserStatus::Active);
    assert_eq!(updated.email, "frank@example.com"); // unchanged
}

/// Delete anonymises the row, strips its credentials, and marks it `Deleted`.
///
/// Two regressions in one. It used to set `status = 'Inactive'` — exactly what
/// the admin UI's Active/Inactive toggle does — so a deleted user stayed in the
/// list, kept their password hash and MFA secret, and was indistinguishable from
/// a suspended one.
///
/// And the first fix for that kept `username` and `email` on the tombstone,
/// which is not erasure: a row holding someone's address indefinitely is
/// retention with the UI hidden.
#[tokio::test]
async fn delete_anonymises_the_user_and_strips_its_credentials() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "grace".into(),
            email: "grace@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();
    assert!(!user.password_hash.is_empty());

    repo.delete(tenant_id, user.id).await.unwrap();

    // The row survives, so audit entries naming this actor still resolve.
    let fetched = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(fetched.status, UserStatus::Deleted);
    assert_ne!(
        fetched.status,
        UserStatus::Inactive,
        "Deleted must be distinguishable from the reversible suspended state"
    );

    // No personal data left on it.
    assert!(
        !fetched.username.contains("grace"),
        "the username must not survive erasure, got `{}`",
        fetched.username
    );
    assert!(
        !fetched.email.contains("grace"),
        "the email must not survive erasure, got `{}`",
        fetched.email
    );
    // Derived from the row's own id, which is an internal identifier.
    assert_eq!(fetched.username, format!("deleted-{}", user.id));

    // Nothing left to authenticate with. Argon2 output is never empty, so an
    // empty hash cannot be satisfied by any password even if some future path
    // skipped the status check.
    assert!(fetched.password_hash.is_empty());
    assert!(fetched.mfa_secret.is_none());
    assert!(!fetched.mfa_enabled);
}

/// The erased person can sign up again with the same username and email.
///
/// GDPR erasure has to leave someone able to register afresh. The unique indexes
/// `idx_user_tenant_username` and `idx_user_tenant_email` are enforced by the
/// database, so *hiding* a tombstone's identifiers is not enough — a re-signup
/// would be refused with a duplicate-account error that itself discloses the
/// deleted account had existed. Overwriting them is what frees the values.
#[tokio::test]
async fn a_deleted_user_can_register_again_with_the_same_identifiers() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let first = repo
        .create(CreateUser {
            tenant_id,
            username: "nina".into(),
            email: "nina@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.delete(tenant_id, first.id).await.unwrap();

    let second = repo
        .create(CreateUser {
            tenant_id,
            username: "nina".into(),
            email: "nina@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .expect("the identifiers must be free again after erasure");

    // A genuinely new account, not the old one revived: the audit trail of the
    // first must not be attributable to the second.
    assert_ne!(second.id, first.id);
    assert_eq!(second.status, UserStatus::PendingVerification);
    assert_eq!(
        repo.get_by_username(tenant_id, "nina").await.unwrap().id,
        second.id
    );
}

/// Two erased accounts do not collide with each other.
#[tokio::test]
async fn erasing_two_users_produces_two_distinct_tombstones() {
    // The replacements are derived per row id rather than being one constant,
    // which is what stops the second erasure failing on the unique index.
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let mut ids = Vec::new();
    for name in ["oscar", "peggy"] {
        let u = repo
            .create(CreateUser {
                tenant_id,
                username: name.into(),
                email: format!("{name}@example.com"),
                password: fixture_password(),
                metadata: None,
            })
            .await
            .unwrap();
        repo.delete(tenant_id, u.id).await.unwrap();
        ids.push(u.id);
    }

    let a = repo.get_by_id(tenant_id, ids[0]).await.unwrap();
    let b = repo.get_by_id(tenant_id, ids[1]).await.unwrap();
    assert_ne!(a.username, b.username);
    assert_ne!(a.email, b.email);
}

/// Erasure is idempotent — the same call twice is not an error.
#[tokio::test]
async fn erasing_an_already_erased_user_is_not_an_error() {
    // The replacements are deterministic, so the second write is a no-op rather
    // than a unique-index violation. A delete that failed on retry would make a
    // transient network error look like a corrupted account.
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "quinn".into(),
            email: "quinn@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.delete(tenant_id, user.id).await.unwrap();
    repo.delete(tenant_id, user.id).await.unwrap();

    let fetched = repo.get_by_id(tenant_id, user.id).await.unwrap();
    assert_eq!(fetched.username, format!("deleted-{}", user.id));
}

/// A deleted user is gone from the list — the actual user-visible symptom.
#[tokio::test]
async fn a_deleted_user_disappears_from_the_listing() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    for name in ["heidi", "ivan", "judy"] {
        repo.create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();
    }

    let before = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert_eq!(before.total, 3);

    let ivan = repo.get_by_username(tenant_id, "ivan").await.unwrap();
    repo.delete(tenant_id, ivan.id).await.unwrap();

    let after = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert_eq!(after.items.len(), 2);
    assert!(after.items.iter().all(|u| u.username != "ivan"));
    // The count must agree with the page. A total that still said 3 would give
    // the admin UI a page it can never fill.
    assert_eq!(
        after.total, 2,
        "the count and the page must exclude the same rows"
    );
}

/// The credential lookups exclude tombstones, so the username and email are
/// free again and no login can resolve to a deleted account.
#[tokio::test]
async fn a_deleted_users_username_and_email_stop_resolving() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    let user = repo
        .create(CreateUser {
            tenant_id,
            username: "mallory".into(),
            email: "mallory@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();

    repo.delete(tenant_id, user.id).await.unwrap();

    assert!(
        repo.get_by_username(tenant_id, "mallory").await.is_err(),
        "login resolves users by username, and the erased row no longer carries it"
    );
    assert!(
        repo.get_by_email(tenant_id, "mallory@example.com")
            .await
            .is_err(),
        "password reset resolves users by email; likewise"
    );
    // But by id it still resolves, which is what keeps the audit trail readable.
    assert!(repo.get_by_id(tenant_id, user.id).await.is_ok());
}

#[tokio::test]
async fn list_users_with_pagination() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    for i in 0..5 {
        repo.create(CreateUser {
            tenant_id,
            username: format!("user-{i}"),
            email: format!("user-{i}@example.com"),
            password: fixture_password(),
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
                search: None,
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
                search: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(page2.items.len(), 2);
}

#[tokio::test]
async fn duplicate_username_rejected() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    repo.create(CreateUser {
        tenant_id,
        username: "unique-user".into(),
        email: "first@example.com".into(),
        password: fixture_password(),
        metadata: None,
    })
    .await
    .unwrap();

    let result = repo
        .create(CreateUser {
            tenant_id,
            username: "unique-user".into(),
            email: "second@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await;

    assert!(result.is_err(), "duplicate username should be rejected");
}

#[tokio::test]
async fn duplicate_email_rejected() {
    let (db, tenant_id) = setup().await;
    let repo = SurrealUserRepository::new(db);

    repo.create(CreateUser {
        tenant_id,
        username: "user-a".into(),
        email: "same@example.com".into(),
        password: fixture_password(),
        metadata: None,
    })
    .await
    .unwrap();

    let result = repo
        .create(CreateUser {
            tenant_id,
            username: "user-b".into(),
            email: "same@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await;

    assert!(result.is_err(), "duplicate email should be rejected");
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
            kind: TenantKind::Standard,
            name: "Tenant A".into(),
            slug: "tenant-a".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_b = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db);

    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant_a.id,
            username: "isolated".into(),
            email: "isolated@example.com".into(),
            password: fixture_password(),
            metadata: None,
        })
        .await
        .unwrap();

    // User should be findable under tenant_a.
    let found = user_repo.get_by_id(tenant_a.id, user.id).await;
    assert!(found.is_ok());

    // User should NOT be findable under tenant_b.
    let not_found = user_repo.get_by_id(tenant_b.id, user.id).await;
    assert!(
        not_found.is_err(),
        "user should not be visible in other tenant"
    );
}

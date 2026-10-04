//! The repository half of just-in-time provisioning and linking
//! (T23.3.3, G-3), against the real datastore.
//!
//! - `create_directory_account` makes the account in one write: `Active`, the
//!   marker set, an unusable hash — and the unique indexes decide a race;
//! - `find_identity_collision` folds case, compares both columns with every
//!   name, and counts every status;
//! - `revoke_user_certificates` revokes active `User` certificates that belong
//!   to the account by the two conventions the model has, and nothing else.
//!
//! No assertion message formats a password, a hash or an identifier.

use axiam_auth::password::verify_password;
use axiam_core::error::AxiamError;
use axiam_core::models::certificate::{
    CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
};
use axiam_core::models::user::{
    CollisionAttribute, CreateDirectoryAccount, CreateUser, UpdateUser, UserStatus,
};
use axiam_core::repository::{CertificateRepository, UserRepository};
use axiam_db::repository::{SurrealCertificateRepository, SurrealUserRepository};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

const ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";
const OTHER_ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964aa";

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn local_password() -> String {
    format!("Lp1!{}", Uuid::new_v4().simple())
}

fn directory_account(tenant_id: Uuid, username: &str, external_id: &str) -> CreateDirectoryAccount {
    CreateDirectoryAccount {
        tenant_id,
        username: username.into(),
        email: format!("{username}@example.com"),
        external_id: external_id.into(),
        metadata: serde_json::json!({ "oidc": { "name": "Alice Example" } }),
    }
}

async fn local_user(repo: &SurrealUserRepository<Db>, tenant_id: Uuid, name: &str) -> Uuid {
    repo.create(CreateUser {
        tenant_id,
        username: name.into(),
        email: format!("{name}@example.com"),
        password: local_password(),
        metadata: None,
    })
    .await
    .unwrap()
    .id
}

// -----------------------------------------------------------------------
// create_directory_account
// -----------------------------------------------------------------------

#[tokio::test]
async fn a_directory_account_is_born_active_marked_and_without_a_usable_password() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let created = repo
        .create_directory_account(directory_account(tenant, "alice", ENTRY))
        .await
        .unwrap();
    assert_eq!(created.status, UserStatus::Active);
    assert_eq!(created.directory_external_id.as_deref(), Some(ENTRY));
    assert_eq!(created.username, "alice");
    assert_eq!(created.email, "alice@example.com");
    assert!(!created.mfa_enabled);
    assert!(created.password_hash.starts_with("$argon2id$"));
    assert!(!verify_password(&local_password(), &created.password_hash, None).unwrap());
    assert_eq!(created.metadata["oidc"]["name"], "Alice Example");

    // Read back by every lookup the login path uses.
    let by_name = repo.get_by_username(tenant, "alice").await.unwrap();
    assert_eq!(by_name.id, created.id);
    assert_eq!(by_name.directory_external_id.as_deref(), Some(ENTRY));
    let by_mail = repo
        .get_by_email(tenant, "alice@example.com")
        .await
        .unwrap();
    assert_eq!(by_mail.id, created.id);
}

#[tokio::test]
async fn a_blank_external_id_is_refused_and_nothing_is_created() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    assert!(
        repo.create_directory_account(directory_account(tenant, "alice", "  "))
            .await
            .is_err()
    );
    assert!(matches!(
        repo.get_by_username(tenant, "alice").await,
        Err(AxiamError::NotFound { .. })
    ));
}

/// The race for one entry, decided by the datastore: of any number of
/// concurrent creations exactly one account exists afterwards, and the others
/// are told `AlreadyExists`.
#[tokio::test]
async fn concurrent_creations_for_one_entry_yield_one_account() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let attempts = (0..6).map(|_| {
        let repo = repo.clone();
        tokio::spawn(async move {
            repo.create_directory_account(directory_account(tenant, "alice", ENTRY))
                .await
        })
    });
    let mut created = 0;
    for attempt in attempts {
        match attempt.await.unwrap() {
            Ok(_) => created += 1,
            Err(AxiamError::AlreadyExists { .. } | AxiamError::WriteContention) => {}
            Err(_) => panic!("a lost race must be AlreadyExists or contention"),
        }
    }
    assert_eq!(created, 1, "exactly one creation may win");
    let page = repo
        .list(
            tenant,
            axiam_core::repository::Pagination {
                offset: 0,
                limit: 50,
                search: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page.total, 1, "exactly one account exists");
}

#[tokio::test]
async fn the_marker_username_and_email_are_each_unique() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    repo.create_directory_account(directory_account(tenant, "alice", ENTRY))
        .await
        .unwrap();
    // Same entry, different name.
    assert!(matches!(
        repo.create_directory_account(directory_account(tenant, "alice2", ENTRY))
            .await,
        Err(AxiamError::AlreadyExists { .. })
    ));
    // Same name, different entry.
    assert!(matches!(
        repo.create_directory_account(directory_account(tenant, "alice", OTHER_ENTRY))
            .await,
        Err(AxiamError::AlreadyExists { .. })
    ));
    // Same email, different name and entry.
    let mut same_email = directory_account(tenant, "other", OTHER_ENTRY);
    same_email.email = "alice@example.com".into();
    assert!(matches!(
        repo.create_directory_account(same_email).await,
        Err(AxiamError::AlreadyExists { .. })
    ));
    // The same entry in another tenant is a different account.
    repo.create_directory_account(directory_account(Uuid::new_v4(), "alice", ENTRY))
        .await
        .unwrap();
}

// -----------------------------------------------------------------------
// find_identity_collision
// -----------------------------------------------------------------------

fn names(of: &[&str]) -> Vec<String> {
    of.iter().map(|n| (*n).to_string()).collect()
}

#[tokio::test]
async fn a_collision_ignores_case_on_both_columns() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let existing = local_user(&repo, tenant, "admin").await;

    for probe in ["admin", "ADMIN", "Admin", "  aDmIn  "] {
        let hit = repo
            .find_identity_collision(tenant, &names(&[probe]))
            .await
            .unwrap()
            .expect("a case variant of a username collides");
        assert_eq!(hit.user_id, existing);
        assert_eq!(hit.attribute, CollisionAttribute::Username);
    }
    let hit = repo
        .find_identity_collision(tenant, &names(&["ADMIN@Example.COM"]))
        .await
        .unwrap()
        .expect("a case variant of an email collides");
    assert_eq!(hit.user_id, existing);
    assert_eq!(hit.attribute, CollisionAttribute::Email);

    // Any one of several names is enough.
    assert!(
        repo.find_identity_collision(tenant, &names(&["nobody", "x@y.test", "Admin"]))
            .await
            .unwrap()
            .is_some()
    );
}

/// A new username equal to somebody's *email* collides: the login lookup tries
/// usernames first, so it would capture that person's address.
#[tokio::test]
async fn a_username_equal_to_an_email_collides() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let existing = local_user(&repo, tenant, "bob").await;
    let hit = repo
        .find_identity_collision(tenant, &names(&["Bob@example.com"]))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(hit.user_id, existing);
}

#[tokio::test]
async fn no_collision_across_tenants_or_for_unrelated_names() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    local_user(&repo, tenant, "admin").await;
    assert!(
        repo.find_identity_collision(Uuid::new_v4(), &names(&["admin"]))
            .await
            .unwrap()
            .is_none(),
        "another tenant's names are not this tenant's"
    );
    assert!(
        repo.find_identity_collision(tenant, &names(&["administrator", "adm", ""]))
            .await
            .unwrap()
            .is_none(),
        "a different name is not a collision"
    );
    assert!(
        repo.find_identity_collision(tenant, &[])
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repo.find_identity_collision(tenant, &names(&["", "   "]))
            .await
            .unwrap()
            .is_none(),
        "blank names match nothing"
    );
}

#[tokio::test]
async fn an_inactive_account_still_holds_its_name() {
    let db = setup().await;
    let repo = SurrealUserRepository::new(db);
    let tenant = Uuid::new_v4();
    let existing = local_user(&repo, tenant, "carol").await;
    repo.update(
        tenant,
        existing,
        UpdateUser {
            status: Some(UserStatus::Inactive),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        repo.find_identity_collision(tenant, &names(&["CAROL"]))
            .await
            .unwrap()
            .is_some()
    );
}

// -----------------------------------------------------------------------
// revoke_user_certificates
// -----------------------------------------------------------------------

fn certificate(
    tenant_id: Uuid,
    fingerprint: &str,
    subject: &str,
    cert_type: CertificateType,
    metadata: serde_json::Value,
) -> StoreCertificate {
    StoreCertificate {
        tenant_id,
        issuer_ca_id: Uuid::new_v4(),
        subject: subject.into(),
        public_cert_pem: "not-a-parsed-certificate".into(),
        fingerprint: fingerprint.into(),
        cert_type,
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: Utc::now() - Duration::minutes(1),
        not_after: Utc::now() + Duration::days(30),
        metadata,
    }
}

#[tokio::test]
async fn only_the_accounts_active_user_certificates_are_revoked() {
    let db = setup().await;
    let certs = SurrealCertificateRepository::new(db);
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let none = serde_json::json!({});

    let by_metadata = certs
        .create(certificate(
            tenant,
            "fp-meta",
            "device-17",
            CertificateType::User,
            serde_json::json!({ "user_id": user.to_string() }),
        ))
        .await
        .unwrap();
    let by_username = certs
        .create(certificate(
            tenant,
            "fp-name",
            "Alice",
            CertificateType::User,
            none.clone(),
        ))
        .await
        .unwrap();
    let by_email = certs
        .create(certificate(
            tenant,
            "fp-mail",
            "alice@example.com",
            CertificateType::User,
            none.clone(),
        ))
        .await
        .unwrap();
    // Not the account's: another user's, another type, another tenant, and one
    // that is already revoked.
    let someone_else = certs
        .create(certificate(
            tenant,
            "fp-else",
            "bob",
            CertificateType::User,
            serde_json::json!({ "user_id": Uuid::new_v4().to_string() }),
        ))
        .await
        .unwrap();
    let service_cert = certs
        .create(certificate(
            tenant,
            "fp-service",
            "alice",
            CertificateType::Service,
            serde_json::json!({ "user_id": user.to_string() }),
        ))
        .await
        .unwrap();
    let other_tenant = certs
        .create(certificate(
            Uuid::new_v4(),
            "fp-tenant",
            "alice",
            CertificateType::User,
            none.clone(),
        ))
        .await
        .unwrap();
    let already = certs
        .create(certificate(
            tenant,
            "fp-already",
            "alice",
            CertificateType::User,
            none,
        ))
        .await
        .unwrap();
    certs.revoke(tenant, already.id).await.unwrap();

    let revoked = certs
        .revoke_user_certificates(tenant, user, "alice", "alice@example.com")
        .await
        .unwrap();
    assert_eq!(
        revoked, 3,
        "the three active matches, not the already revoked"
    );

    for (cert, expected) in [
        (&by_metadata, CertificateStatus::Revoked),
        (&by_username, CertificateStatus::Revoked),
        (&by_email, CertificateStatus::Revoked),
        (&someone_else, CertificateStatus::Active),
        (&service_cert, CertificateStatus::Active),
    ] {
        let read = certs.get_by_id(tenant, cert.id).await.unwrap();
        assert_eq!(read.status, expected);
    }
    let foreign = certs
        .get_by_id(other_tenant.tenant_id, other_tenant.id)
        .await
        .unwrap();
    assert_eq!(foreign.status, CertificateStatus::Active);

    // Idempotent: a second run has nothing left to revoke.
    assert_eq!(
        certs
            .revoke_user_certificates(tenant, user, "alice", "alice@example.com")
            .await
            .unwrap(),
        0
    );
}

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

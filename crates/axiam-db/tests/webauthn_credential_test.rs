//! Integration tests for the WebAuthn credential repository
//! implementation using in-memory SurrealDB.

use axiam_core::models::webauthn_credential::{
    CreateWebauthnCredential, WebauthnCredentialType,
};
use axiam_core::repository::WebauthnCredentialRepository;
use axiam_db::repository::SurrealWebauthnCredentialRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// Helper: spin up in-memory DB and run migrations.
async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

/// Build a [`CreateWebauthnCredential`] with sensible defaults.
fn make_input(
    tenant_id: Uuid,
    user_id: Uuid,
    name: &str,
    cred_type: WebauthnCredentialType,
) -> CreateWebauthnCredential {
    CreateWebauthnCredential {
        tenant_id,
        user_id,
        credential_id: format!("cred-{}", Uuid::new_v4()),
        name: name.to_owned(),
        credential_type: cred_type,
        passkey_json: r#"{"encrypted":"placeholder"}"#.to_owned(),
    }
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[tokio::test]
async fn create_and_get_credential() {
    let db = setup().await;
    let repo = SurrealWebauthnCredentialRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let cred = repo
        .create(make_input(
            tenant_id,
            user_id,
            "My YubiKey",
            WebauthnCredentialType::SecurityKey,
        ))
        .await
        .unwrap();

    assert_eq!(cred.tenant_id, tenant_id);
    assert_eq!(cred.user_id, user_id);
    assert_eq!(cred.name, "My YubiKey");
    assert_eq!(cred.credential_type, WebauthnCredentialType::SecurityKey);
    assert!(cred.last_used_at.is_none());

    // Round-trip through get_by_id.
    let fetched = repo.get_by_id(tenant_id, cred.id).await.unwrap();
    assert_eq!(fetched.id, cred.id);
    assert_eq!(fetched.tenant_id, tenant_id);
    assert_eq!(fetched.name, "My YubiKey");
    assert_eq!(
        fetched.credential_type,
        WebauthnCredentialType::SecurityKey
    );
}

#[tokio::test]
async fn list_by_user_returns_only_matching() {
    let db = setup().await;
    let repo = SurrealWebauthnCredentialRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();

    // Two credentials for user_a, one for user_b.
    repo.create(make_input(
        tenant_id,
        user_a,
        "Passkey A1",
        WebauthnCredentialType::Passkey,
    ))
    .await
    .unwrap();

    repo.create(make_input(
        tenant_id,
        user_a,
        "Passkey A2",
        WebauthnCredentialType::Passkey,
    ))
    .await
    .unwrap();

    repo.create(make_input(
        tenant_id,
        user_b,
        "Key B1",
        WebauthnCredentialType::SecurityKey,
    ))
    .await
    .unwrap();

    let list_a = repo.list_by_user(tenant_id, user_a).await.unwrap();
    assert_eq!(list_a.len(), 2);
    assert!(list_a.iter().all(|c| c.user_id == user_a));

    let list_b = repo.list_by_user(tenant_id, user_b).await.unwrap();
    assert_eq!(list_b.len(), 1);
    assert_eq!(list_b[0].user_id, user_b);
}

#[tokio::test]
async fn count_by_user() {
    let db = setup().await;
    let repo = SurrealWebauthnCredentialRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    // Zero before any creation.
    let count = repo.count_by_user(tenant_id, user_id).await.unwrap();
    assert_eq!(count, 0);

    repo.create(make_input(
        tenant_id,
        user_id,
        "Key 1",
        WebauthnCredentialType::Passkey,
    ))
    .await
    .unwrap();

    repo.create(make_input(
        tenant_id,
        user_id,
        "Key 2",
        WebauthnCredentialType::SecurityKey,
    ))
    .await
    .unwrap();

    let count = repo.count_by_user(tenant_id, user_id).await.unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn update_last_used_sets_timestamp() {
    let db = setup().await;
    let repo = SurrealWebauthnCredentialRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let cred = repo
        .create(make_input(
            tenant_id,
            user_id,
            "Passkey",
            WebauthnCredentialType::Passkey,
        ))
        .await
        .unwrap();

    assert!(cred.last_used_at.is_none());

    repo.update_last_used(tenant_id, cred.id).await.unwrap();

    let updated = repo.get_by_id(tenant_id, cred.id).await.unwrap();
    assert!(
        updated.last_used_at.is_some(),
        "last_used_at should be set after update_last_used"
    );
}

#[tokio::test]
async fn delete_removes_credential() {
    let db = setup().await;
    let repo = SurrealWebauthnCredentialRepository::new(db);

    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let cred = repo
        .create(make_input(
            tenant_id,
            user_id,
            "Disposable",
            WebauthnCredentialType::SecurityKey,
        ))
        .await
        .unwrap();

    // Confirm it exists.
    repo.get_by_id(tenant_id, cred.id).await.unwrap();

    // Delete it.
    repo.delete(tenant_id, cred.id).await.unwrap();

    // Should no longer be retrievable.
    let result = repo.get_by_id(tenant_id, cred.id).await;
    assert!(result.is_err(), "deleted credential should not be found");

    // Count should be zero.
    let count = repo.count_by_user(tenant_id, user_id).await.unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn get_by_id_wrong_tenant_returns_not_found() {
    let db = setup().await;
    let repo = SurrealWebauthnCredentialRepository::new(db);

    let tenant_a = Uuid::new_v4();
    let tenant_b = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let cred = repo
        .create(make_input(
            tenant_a,
            user_id,
            "Tenant A key",
            WebauthnCredentialType::Passkey,
        ))
        .await
        .unwrap();

    // Fetching with the correct tenant succeeds.
    repo.get_by_id(tenant_a, cred.id).await.unwrap();

    // Fetching with a different tenant must fail — tenant isolation.
    let result = repo.get_by_id(tenant_b, cred.id).await;
    assert!(
        result.is_err(),
        "credential from tenant_a must not be visible to tenant_b"
    );
}

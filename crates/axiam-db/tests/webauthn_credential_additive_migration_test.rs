//! D6 (X3 wave 2) regression: a `webauthn_credential` row written **before**
//! the four attestation-metadata columns existed must still read back
//! correctly, with those columns defaulting to `None`/`false` — additive,
//! no migration, no backfill.
//!
//! This deliberately bypasses `WebauthnCredentialRepository::create` (which
//! always sets the new columns, even to `None`/`false`) and instead inserts a
//! row with a raw `CREATE` that never mentions `aaguid`, `attestation_format`,
//! `attested`, or `authenticator_name` at all — the genuine shape of a row
//! written by the pre-X3 code path, not merely a post-X3 row with those
//! fields explicitly set to their zero values.

use axiam_core::repository::WebauthnCredentialRepository;
use axiam_db::repository::SurrealWebauthnCredentialRepository;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

#[tokio::test]
async fn pre_x3_row_reads_back_with_default_attestation_metadata() {
    let db = setup().await;
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    // A raw INSERT that only ever sets the columns that existed before
    // schema v35 (D6) — no aaguid/attestation_format/attested/authenticator_name.
    db.query(
        "CREATE type::record('webauthn_credential', $id) SET \
         tenant_id = $tenant_id, \
         user_id = $user_id, \
         credential_id = $credential_id, \
         name = $name, \
         credential_type = $credential_type, \
         passkey_json = $passkey_json",
    )
    .bind(("id", id.to_string()))
    .bind(("tenant_id", tenant_id.to_string()))
    .bind(("user_id", user_id.to_string()))
    .bind(("credential_id", "pre-x3-cred-id".to_string()))
    .bind(("name", "Pre-X3 Key".to_string()))
    .bind(("credential_type", "SecurityKey".to_string()))
    .bind(("passkey_json", r#"{"encrypted":"placeholder"}"#.to_string()))
    .await
    .unwrap()
    .check()
    .expect("raw pre-X3-shaped insert must succeed against the additive schema");

    let repo = SurrealWebauthnCredentialRepository::new(db);
    let fetched = repo.get_by_id(tenant_id, id).await.unwrap();

    assert_eq!(fetched.name, "Pre-X3 Key");
    assert_eq!(fetched.credential_id, "pre-x3-cred-id");
    assert_eq!(fetched.aaguid, None, "pre-X3 row must read aaguid as None");
    assert_eq!(
        fetched.attestation_format, None,
        "pre-X3 row must read attestation_format as None"
    );
    assert!(
        !fetched.attested,
        "pre-X3 row must read attested as false (D6 default)"
    );
    assert_eq!(
        fetched.authenticator_name, None,
        "pre-X3 row must read authenticator_name as None"
    );
}

#[tokio::test]
async fn pre_x3_row_also_reads_back_correctly_via_list_by_user() {
    // Same regression through the `SELECT meta::id(id) AS record_id, *`
    // listing path (`WebauthnCredentialRowWithId`), which has its own
    // separate deserialization from `get_by_id`'s `WebauthnCredentialRow`.
    let db = setup().await;
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let id = Uuid::new_v4();

    db.query(
        "CREATE type::record('webauthn_credential', $id) SET \
         tenant_id = $tenant_id, \
         user_id = $user_id, \
         credential_id = $credential_id, \
         name = $name, \
         credential_type = $credential_type, \
         passkey_json = $passkey_json",
    )
    .bind(("id", id.to_string()))
    .bind(("tenant_id", tenant_id.to_string()))
    .bind(("user_id", user_id.to_string()))
    .bind(("credential_id", "pre-x3-cred-id-2".to_string()))
    .bind(("name", "Pre-X3 Key 2".to_string()))
    .bind(("credential_type", "Passkey".to_string()))
    .bind(("passkey_json", r#"{"encrypted":"placeholder"}"#.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();

    let repo = SurrealWebauthnCredentialRepository::new(db);
    let list = repo.list_by_user(tenant_id, user_id).await.unwrap();
    assert_eq!(list.len(), 1);
    let fetched = &list[0];
    assert_eq!(fetched.aaguid, None);
    assert_eq!(fetched.attestation_format, None);
    assert!(!fetched.attested);
    assert_eq!(fetched.authenticator_name, None);
}

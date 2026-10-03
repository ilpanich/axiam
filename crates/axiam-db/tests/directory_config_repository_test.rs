//! The directory (LDAP / Active Directory) configuration against the real
//! datastore (T23.3.1, G-3, D-15).
//!
//! What lives in the datastore and the crypto rather than in plain Rust, so a
//! mock would agree with whatever the code happened to do:
//!
//! - the bind secret is **encrypted at rest** (the stored ciphertext is not the
//!   plaintext and decrypts back), under a fresh nonce on every write;
//! - an update without a secret **keeps** the stored one, and one with a secret
//!   rotates it;
//! - **one row per tenant** is the unique index's doing, and tenants cannot read
//!   each other's configuration or secret;
//! - without the optional `directory_encryption_key` the feature **fails closed**
//!   with an error that names the key;
//! - a tenant's row goes **with the tenant**.
//!
//! No assertion message in this file formats the secret, the ciphertext, a key
//! or an identifier: a failing case is named, never printed.

use axiam_core::error::AxiamError;
use axiam_core::models::directory::{DirectoryConfig, DirectoryKind, NewDirectoryConfig};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{DirectoryConfigRepository, OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealDirectoryConfigRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use surrealdb_types::SurrealValue;
use uuid::Uuid;
use zeroize::Zeroizing;

const KEY: [u8; 32] = [0xAB; 32];
const OTHER_KEY: [u8; 32] = [0xCD; 32];

async fn setup() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn repo(db: &Surreal<Db>, key: Option<[u8; 32]>) -> SurrealDirectoryConfigRepository<Db> {
    SurrealDirectoryConfigRepository::new(db.clone(), key)
}

/// A throwaway secret generated at run time, so no credential literal sits in
/// the source for a scanner to flag.
fn fresh_secret() -> String {
    format!("Fx1!{}", Uuid::new_v4().simple())
}

fn input(tenant_id: Uuid, secret: Option<&str>) -> NewDirectoryConfig {
    NewDirectoryConfig {
        tenant_id,
        enabled: true,
        kind: DirectoryKind::ActiveDirectory,
        url: "ldaps://dc01.corp.example.com:636".into(),
        start_tls: false,
        bind_dn: "CN=svc-axiam,OU=Service,DC=corp,DC=example,DC=com".into(),
        bind_secret: secret.map(|s| Zeroizing::new(s.to_string())),
        base_dn: "OU=People,DC=corp,DC=example,DC=com".into(),
        user_filter: "(&(objectClass=user)(sAMAccountName={username}))".into(),
        user_attribute_map: DirectoryKind::ActiveDirectory.default_user_attribute_map(),
        group_base_dn: Some("OU=Groups,DC=corp,DC=example,DC=com".into()),
        group_filter: Some("(objectClass=group)".into()),
        group_member_attribute: "memberOf".into(),
        group_nesting_depth: 4,
        sync_interval_secs: 900,
        jit_provisioning: true,
        trust_anchors_pem: vec![
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(),
        ],
    }
}

#[derive(SurrealValue)]
struct RawSecret {
    bind_secret_ciphertext: String,
    bind_secret_nonce: String,
}

/// The stored `(ciphertext, nonce)`, read behind the repository's back.
async fn raw_secret(db: &Surreal<Db>, tenant_id: Uuid) -> (String, String) {
    let mut result = db
        .query(
            "SELECT bind_secret_ciphertext, bind_secret_nonce \
             FROM directory_config WHERE tenant_id = $t",
        )
        .bind(("t", tenant_id.to_string()))
        .await
        .unwrap();
    let rows: Vec<RawSecret> = result.take(0).unwrap();
    let row = rows.into_iter().next().expect("a stored directory row");
    (row.bind_secret_ciphertext, row.bind_secret_nonce)
}

async fn row_count(db: &Surreal<Db>) -> usize {
    let mut result = db.query("SELECT id FROM directory_config").await.unwrap();
    let rows: Vec<surrealdb_types::Value> = result.take(0).unwrap();
    rows.len()
}

#[tokio::test]
async fn create_round_trips_every_non_secret_field() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let want = input(tenant, Some(&fresh_secret()));

    let created = repo.create(want.clone()).await.unwrap();
    let fetched = repo.get_by_tenant(tenant).await.unwrap().expect("a config");

    assert!(created == fetched, "create must return what a read returns");
    assert_eq!(fetched.tenant_id, tenant);
    assert!(fetched.enabled);
    assert_eq!(fetched.kind, want.kind);
    assert_eq!(fetched.url, want.url);
    assert_eq!(fetched.start_tls, want.start_tls);
    assert_eq!(fetched.bind_dn, want.bind_dn);
    assert_eq!(fetched.base_dn, want.base_dn);
    assert_eq!(fetched.user_filter, want.user_filter);
    assert_eq!(fetched.user_attribute_map, want.user_attribute_map);
    assert_eq!(fetched.group_base_dn, want.group_base_dn);
    assert_eq!(fetched.group_filter, want.group_filter);
    assert_eq!(fetched.group_member_attribute, want.group_member_attribute);
    assert_eq!(fetched.group_nesting_depth, 4);
    assert_eq!(fetched.sync_interval_secs, 900);
    assert!(fetched.jit_provisioning);
    assert_eq!(fetched.trust_anchors_pem, want.trust_anchors_pem);
    assert!(fetched.updated_at >= fetched.created_at);
}

#[tokio::test]
async fn optional_group_fields_and_an_empty_anchor_list_round_trip_as_absent() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let mut want = input(tenant, Some(&fresh_secret()));
    want.kind = DirectoryKind::OpenLdap;
    want.group_base_dn = None;
    want.group_filter = None;
    want.trust_anchors_pem = vec![];

    repo.create(want).await.unwrap();
    let fetched = repo.get_by_tenant(tenant).await.unwrap().unwrap();

    assert_eq!(fetched.kind, DirectoryKind::OpenLdap);
    assert_eq!(fetched.group_base_dn, None);
    assert_eq!(fetched.group_filter, None);
    assert!(fetched.trust_anchors_pem.is_empty());
}

#[tokio::test]
async fn the_bind_secret_is_encrypted_at_rest_and_decrypts_back() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let secret = fresh_secret();

    repo.create(input(tenant, Some(&secret))).await.unwrap();

    let (ciphertext, nonce) = raw_secret(&db, tenant).await;
    assert!(
        ciphertext != secret,
        "the stored ciphertext must not be the plaintext"
    );
    assert!(
        !ciphertext.contains(&secret) && !nonce.contains(&secret),
        "the plaintext must appear in neither stored column"
    );
    assert!(!nonce.is_empty());

    let opened = repo.decrypt_bind_secret(tenant).await.unwrap();
    assert!(
        opened.as_str() == secret,
        "decrypt_bind_secret must return the secret that was written"
    );
}

#[tokio::test]
async fn the_stored_row_has_no_plaintext_secret_column() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let secret = fresh_secret();
    repo.create(input(tenant, Some(&secret))).await.unwrap();

    // The whole row, as the datastore holds it, rendered as text.
    let mut result = db
        .query("SELECT * FROM directory_config WHERE tenant_id = $t")
        .bind(("t", tenant.to_string()))
        .await
        .unwrap();
    let rows: Vec<surrealdb_types::Value> = result.take(0).unwrap();
    let rendered = format!("{rows:?}");
    assert!(
        !rendered.contains(&secret),
        "no column of the stored row may hold the plaintext secret"
    );
}

#[tokio::test]
async fn an_update_without_a_secret_keeps_the_stored_one() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let secret = fresh_secret();
    repo.create(input(tenant, Some(&secret))).await.unwrap();
    let before = raw_secret(&db, tenant).await;

    let mut change = input(tenant, None);
    change.url = "ldaps://dc02.corp.example.com".into();
    change.enabled = false;
    change.group_nesting_depth = 2;
    let updated = repo.update(change).await.unwrap();

    assert_eq!(updated.url, "ldaps://dc02.corp.example.com");
    assert!(!updated.enabled);
    assert_eq!(updated.group_nesting_depth, 2);
    assert!(
        raw_secret(&db, tenant).await == before,
        "an update without a secret must leave the ciphertext and nonce untouched"
    );
    let opened = repo.decrypt_bind_secret(tenant).await.unwrap();
    assert!(
        opened.as_str() == secret,
        "the kept secret must still decrypt to the original"
    );
}

#[tokio::test]
async fn an_update_keeps_the_row_identity_and_creation_time() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let created = repo
        .create(input(tenant, Some(&fresh_secret())))
        .await
        .unwrap();

    let updated = repo.update(input(tenant, None)).await.unwrap();

    assert_eq!(updated.id, created.id);
    assert_eq!(updated.created_at, created.created_at);
    assert!(updated.updated_at >= created.updated_at);
}

#[tokio::test]
async fn an_update_with_a_secret_rotates_the_ciphertext_and_the_nonce() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    repo.create(input(tenant, Some(&fresh_secret())))
        .await
        .unwrap();
    let (old_ciphertext, old_nonce) = raw_secret(&db, tenant).await;

    let replacement = fresh_secret();
    repo.update(input(tenant, Some(&replacement)))
        .await
        .unwrap();

    let (new_ciphertext, new_nonce) = raw_secret(&db, tenant).await;
    assert!(
        new_nonce != old_nonce,
        "a new secret must use a fresh nonce"
    );
    assert!(
        new_ciphertext != old_ciphertext,
        "a new secret must change the stored ciphertext"
    );
    let opened = repo.decrypt_bind_secret(tenant).await.unwrap();
    assert!(
        opened.as_str() == replacement,
        "the stored secret must now be the replacement"
    );
}

#[tokio::test]
async fn writing_the_same_secret_twice_still_uses_a_fresh_nonce() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let secret = fresh_secret();
    repo.create(input(tenant, Some(&secret))).await.unwrap();
    let (first_ciphertext, first_nonce) = raw_secret(&db, tenant).await;

    repo.update(input(tenant, Some(&secret))).await.unwrap();
    let (second_ciphertext, second_nonce) = raw_secret(&db, tenant).await;

    assert!(first_nonce != second_nonce, "the nonce must never repeat");
    assert!(
        first_ciphertext != second_ciphertext,
        "the same plaintext must not produce the same ciphertext twice"
    );
}

#[tokio::test]
async fn a_second_create_for_the_same_tenant_is_refused() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let secret = fresh_secret();
    repo.create(input(tenant, Some(&secret))).await.unwrap();
    let before = raw_secret(&db, tenant).await;

    let err = repo
        .create(input(tenant, Some(&fresh_secret())))
        .await
        .unwrap_err();

    assert!(
        matches!(err, AxiamError::AlreadyExists { .. }),
        "the second create must be AlreadyExists, not another variant"
    );
    assert_eq!(row_count(&db).await, 1);
    assert!(
        raw_secret(&db, tenant).await == before,
        "a refused create must not touch the stored secret"
    );
}

#[tokio::test]
async fn create_requires_a_secret() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));

    let err = repo.create(input(Uuid::new_v4(), None)).await.unwrap_err();

    assert!(matches!(err, AxiamError::Validation { .. }));
    assert_eq!(row_count(&db).await, 0);
}

#[tokio::test]
async fn updating_a_tenant_with_no_configuration_is_not_found() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));

    let err = repo
        .update(input(Uuid::new_v4(), Some(&fresh_secret())))
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::NotFound { .. }));
    assert_eq!(row_count(&db).await, 0, "an update must never create a row");
}

#[tokio::test]
async fn tenants_cannot_read_each_others_configuration_or_secret() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    let secret_a = fresh_secret();
    repo.create(input(a, Some(&secret_a))).await.unwrap();

    assert!(repo.get_by_tenant(b).await.unwrap().is_none());
    assert!(matches!(
        repo.decrypt_bind_secret(b).await.unwrap_err(),
        AxiamError::NotFound { .. }
    ));
    assert!(matches!(
        repo.update(input(b, None)).await.unwrap_err(),
        AxiamError::NotFound { .. }
    ));

    // B's own, separate configuration does not disturb A's.
    let secret_b = fresh_secret();
    repo.create(input(b, Some(&secret_b))).await.unwrap();
    let opened_a = repo.decrypt_bind_secret(a).await.unwrap();
    let opened_b = repo.decrypt_bind_secret(b).await.unwrap();
    assert!(opened_a.as_str() == secret_a);
    assert!(opened_b.as_str() == secret_b);

    // Deleting B leaves A.
    repo.delete(b).await.unwrap();
    assert!(repo.get_by_tenant(a).await.unwrap().is_some());
    assert!(repo.get_by_tenant(b).await.unwrap().is_none());
}

#[tokio::test]
async fn without_the_key_the_feature_fails_closed_and_names_the_key() {
    let db = setup().await;
    let keyless = repo(&db, None);
    let tenant = Uuid::new_v4();

    let named = |err: &AxiamError| {
        let text = err.to_string();
        text.contains("directory_encryption_key")
            && text.contains("AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY")
    };

    let create_err = keyless
        .create(input(tenant, Some(&fresh_secret())))
        .await
        .unwrap_err();
    assert!(matches!(create_err, AxiamError::Validation { .. }));
    assert!(named(&create_err), "create must name the missing key");

    let update_err = keyless.update(input(tenant, None)).await.unwrap_err();
    assert!(matches!(update_err, AxiamError::Validation { .. }));
    assert!(named(&update_err), "update must name the missing key");

    let decrypt_err = keyless.decrypt_bind_secret(tenant).await.unwrap_err();
    assert!(matches!(decrypt_err, AxiamError::ServiceUnavailable(_)));
    assert!(named(&decrypt_err), "decrypt must name the missing key");

    assert_eq!(
        row_count(&db).await,
        0,
        "a refused write must store nothing"
    );
}

#[tokio::test]
async fn a_keyless_repository_still_reads_lists_and_deletes() {
    let db = setup().await;
    let keyed = repo(&db, Some(KEY));
    let keyless = repo(&db, None);
    let tenant = Uuid::new_v4();
    keyed
        .create(input(tenant, Some(&fresh_secret())))
        .await
        .unwrap();

    assert!(keyless.get_by_tenant(tenant).await.unwrap().is_some());
    assert_eq!(keyless.list_enabled().await.unwrap().len(), 1);
    keyless.delete(tenant).await.unwrap();
    assert!(keyless.get_by_tenant(tenant).await.unwrap().is_none());
}

#[tokio::test]
async fn the_wrong_key_does_not_decrypt_and_says_nothing_about_the_secret() {
    let db = setup().await;
    let tenant = Uuid::new_v4();
    let secret = fresh_secret();
    repo(&db, Some(KEY))
        .create(input(tenant, Some(&secret)))
        .await
        .unwrap();

    let err = repo(&db, Some(OTHER_KEY))
        .decrypt_bind_secret(tenant)
        .await
        .unwrap_err();

    assert!(matches!(err, AxiamError::Crypto(_)));
    assert!(
        !err.to_string().contains(&secret),
        "a decryption failure must not repeat the secret"
    );
}

#[tokio::test]
async fn the_datastore_refuses_a_row_with_no_secret_columns() {
    let db = setup().await;

    let response = db
        .query(
            "CREATE type::record('directory_config', $id) SET \
             tenant_id = $t, enabled = true, kind = 'open_ldap', \
             url = 'ldaps://x', start_tls = false, bind_dn = 'cn=a', \
             secret_key_version = 1, base_dn = 'dc=x', user_filter = '(uid={username})', \
             attr_username = 'uid', attr_email = 'mail', attr_display_name = 'cn', \
             attr_external_id = 'entryUUID', group_member_attribute = 'member', \
             group_nesting_depth = 1, sync_interval_secs = 300, \
             jit_provisioning = false, trust_anchors_pem = [], \
             created_at = time::now(), updated_at = time::now()",
        )
        .bind(("id", Uuid::new_v4().to_string()))
        .bind(("t", Uuid::new_v4().to_string()))
        .await
        .unwrap();

    assert!(
        response.check().is_err(),
        "a row without ciphertext and nonce must not be storable"
    );
}

#[tokio::test]
async fn list_enabled_returns_only_enabled_configurations() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let (on, off) = (Uuid::new_v4(), Uuid::new_v4());
    repo.create(input(on, Some(&fresh_secret()))).await.unwrap();
    let mut disabled = input(off, Some(&fresh_secret()));
    disabled.enabled = false;
    repo.create(disabled).await.unwrap();

    let listed = repo.list_enabled().await.unwrap();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].tenant_id, on);
}

#[tokio::test]
async fn delete_removes_the_row_and_is_ok_when_there_is_none() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    repo.create(input(tenant, Some(&fresh_secret())))
        .await
        .unwrap();

    repo.delete(tenant).await.unwrap();
    assert_eq!(row_count(&db).await, 0);
    repo.delete(tenant).await.unwrap();
    repo.delete(Uuid::new_v4()).await.unwrap();
}

#[tokio::test]
async fn the_configuration_is_deleted_with_its_tenant() {
    let db = setup().await;
    let orgs = SurrealOrganizationRepository::new(db.clone());
    let tenants = SurrealTenantRepository::new(db.clone());
    let directories = repo(&db, Some(KEY));

    let org = orgs
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "directory-cascade".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let make_tenant = |slug: &str| CreateTenant {
        organization_id: org,
        kind: TenantKind::Standard,
        name: slug.into(),
        slug: slug.into(),
        metadata: None,
    };
    let doomed = tenants.create(make_tenant("doomed")).await.unwrap().id;
    let kept = tenants.create(make_tenant("kept")).await.unwrap().id;
    directories
        .create(input(doomed, Some(&fresh_secret())))
        .await
        .unwrap();
    directories
        .create(input(kept, Some(&fresh_secret())))
        .await
        .unwrap();

    tenants.delete(doomed).await.unwrap();

    assert!(
        directories.get_by_tenant(doomed).await.unwrap().is_none(),
        "deleting a tenant must delete its directory configuration"
    );
    assert!(
        directories.get_by_tenant(kept).await.unwrap().is_some(),
        "deleting one tenant must not touch another tenant's configuration"
    );
    assert_eq!(
        row_count(&db).await,
        1,
        "no ciphertext may outlive its tenant"
    );
}

#[tokio::test]
async fn debug_and_serialisation_carry_no_secret_material() {
    let db = setup().await;
    let repo = repo(&db, Some(KEY));
    let tenant = Uuid::new_v4();
    let secret = fresh_secret();
    let write = input(tenant, Some(&secret));

    let write_debug = format!("{write:?}");
    let created: DirectoryConfig = repo.create(write).await.unwrap();
    let (ciphertext, nonce) = raw_secret(&db, tenant).await;

    let surfaces = [
        ("write input Debug", write_debug),
        ("config Debug", format!("{created:?}")),
        ("config JSON", serde_json::to_string(&created).unwrap()),
        ("repository Debug", format!("{repo:?}")),
    ];
    for (name, text) in surfaces {
        assert!(!text.contains(&secret), "{name} must not hold the secret");
        assert!(
            !text.contains(&ciphertext),
            "{name} must not hold the ciphertext"
        );
        assert!(!text.contains(&nonce), "{name} must not hold the nonce");
    }
    // And the model has no field that could: nothing named for the secret.
    let json = serde_json::to_string(&created).unwrap();
    assert!(
        !json.contains("secret") && !json.contains("ciphertext") && !json.contains("nonce"),
        "the serialised configuration must have no secret-bearing field"
    );
}

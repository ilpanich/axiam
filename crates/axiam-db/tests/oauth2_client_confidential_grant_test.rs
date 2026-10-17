//! `count_confidential_with_grant` against the real datastore (R110W3-02,
//! #675): the numbers behind the boot-time device-grant warning.
//!
//! Counted: a confidential client holding the grant, whether its method is
//! stored or absent. Not counted: a public client, a confidential client
//! without the grant, a tombstoned tenant's client, an orphaned row.

use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OAuth2ClientRepository, OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

const URN: &str = "urn:ietf:params:oauth:grant-type:device_code";
const SPELLINGS: [&str; 2] = [URN, "device_code"];

async fn setup() -> (Surreal<Db>, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "confidential-grant".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    (db, org)
}

async fn tenant(db: &Surreal<Db>, org: Uuid, slug: &str) -> Uuid {
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org,
            kind: TenantKind::Standard,
            name: slug.into(),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

/// `method` of `None` omits `token_endpoint_auth_method`, as the 1.0.x
/// quickstart did.
async fn client(
    db: &Surreal<Db>,
    tenant_id: Uuid,
    grants: &[&str],
    method: Option<&str>,
) -> String {
    let mut body = serde_json::json!({
        "tenant_id": tenant_id,
        "name": "device",
        "redirect_uris": [],
        "grant_types": grants,
        "scopes": ["openid"],
    });
    if let Some(m) = method {
        body["token_endpoint_auth_method"] = m.into();
    }
    let input: CreateOAuth2Client = serde_json::from_value(body).unwrap();
    SurrealOAuth2ClientRepository::new(db.clone())
        .create(input)
        .await
        .unwrap()
        .0
        .client_id
}

#[tokio::test]
async fn it_counts_confidential_device_clients_and_nothing_else() {
    let (db, org) = setup().await;
    let repo = SurrealOAuth2ClientRepository::new(db.clone());

    let empty = repo
        .count_confidential_with_grant(&SPELLINGS)
        .await
        .unwrap();
    assert_eq!((empty.clients, empty.tenants), (0, 0));

    let a = tenant(&db, org, "tenant-a").await;
    let b = tenant(&db, org, "tenant-b").await;
    let gone = tenant(&db, org, "tenant-gone").await;

    // Excluded: a public device client.
    client(&db, a, &[URN], Some("none")).await;
    // Excluded: a confidential client without the device grant.
    client(&db, a, &["client_credentials"], None).await;
    client(&db, a, &["authorization_code"], Some("client_secret_basic")).await;
    let none_yet = repo
        .count_confidential_with_grant(&SPELLINGS)
        .await
        .unwrap();
    assert_eq!((none_yet.clients, none_yet.tenants), (0, 0));

    // Counted: the default method (absent), an explicit one, and the bare
    // spelling of the grant.
    client(&db, a, &[URN, "refresh_token"], None).await;
    client(&db, a, &[URN], Some("client_secret_basic")).await;
    client(&db, b, &["device_code"], Some("client_secret_post")).await;

    // Excluded: a tombstoned tenant's client (the row survives until the purge).
    client(&db, gone, &[URN], None).await;
    let with_gone = repo
        .count_confidential_with_grant(&SPELLINGS)
        .await
        .unwrap();
    assert_eq!((with_gone.clients, with_gone.tenants), (4, 3));
    SurrealTenantRepository::new(db.clone())
        .delete(gone)
        .await
        .unwrap();

    let count = repo
        .count_confidential_with_grant(&SPELLINGS)
        .await
        .unwrap();
    assert_eq!(
        (count.clients, count.tenants),
        (3, 2),
        "three confidential device clients in two live tenants"
    );

    // Excluded: an orphaned row whose tenant never existed.
    client(&db, Uuid::new_v4(), &[URN], None).await;
    let count = repo
        .count_confidential_with_grant(&SPELLINGS)
        .await
        .unwrap();
    assert_eq!((count.clients, count.tenants), (3, 2));

    // The spelling asked for decides: only the URN leaves the bare one out.
    let urn_only = repo.count_confidential_with_grant(&[URN]).await.unwrap();
    assert_eq!((urn_only.clients, urn_only.tenants), (2, 1));
}

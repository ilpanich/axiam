//! The record caches (`axiam_db::record_cache`): a hot, read-only lookup is
//! served from the cache for at most the TTL; a write through the owning
//! repository drops the entry at once; a change made anywhere else is seen
//! within the TTL; a cached account never carries credential material.

use std::sync::Arc;
use std::time::Duration;

use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
    UpdateOAuth2Client,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind, TenantStatus, UpdateTenant};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OAuth2ClientRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::RecordCaches;
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_test_support::test_password;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

struct Repos {
    db: Surreal<Db>,
    tenants: SurrealTenantRepository<Db>,
    users: SurrealUserRepository<Db>,
    clients: SurrealOAuth2ClientRepository<Db>,
    tenant: Uuid,
}

async fn repos(ttl: Duration) -> Repos {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let caches = Arc::new(RecordCaches::new(ttl, 1_000));
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let tenants = SurrealTenantRepository::new(db.clone()).with_record_caches(caches.clone());
    let tenant = tenants
        .create(CreateTenant {
            organization_id: org,
            kind: TenantKind::Standard,
            name: "t".into(),
            slug: "t".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    Repos {
        users: SurrealUserRepository::new(db.clone()).with_record_caches(caches.clone()),
        clients: SurrealOAuth2ClientRepository::new(db.clone()).with_record_caches(caches),
        tenants,
        db,
        tenant,
    }
}

async fn out_of_band(db: &Surreal<Db>, sql: &str, id: Uuid) {
    db.query(sql)
        .bind(("id", id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
}

#[tokio::test]
async fn a_tenant_suspended_through_the_repository_is_refused_at_once() {
    let r = repos(Duration::from_secs(60)).await;
    assert!(r.tenants.get_by_id_cached(r.tenant).await.is_ok());
    r.tenants
        .update(
            r.tenant,
            UpdateTenant {
                status: Some(TenantStatus::Suspended),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        r.tenants.get_by_id_cached(r.tenant).await.unwrap().status,
        TenantStatus::Suspended,
        "the write dropped the cached live tenant"
    );
    r.tenants.delete(r.tenant).await.unwrap();
    assert!(matches!(
        r.tenants.get_by_id_cached(r.tenant).await,
        Err(AxiamError::NotFound { .. })
    ));
}

#[tokio::test]
async fn a_change_made_elsewhere_is_seen_within_the_ttl() {
    let r = repos(Duration::from_millis(200)).await;
    assert!(r.tenants.get_by_id_cached(r.tenant).await.is_ok());
    // Tombstoned behind the repository's back (another replica, a restore).
    out_of_band(
        &r.db,
        "UPDATE type::record('tenant', $id) SET deleted_at = time::now()",
        r.tenant,
    )
    .await;
    assert!(
        r.tenants.get_by_id_cached(r.tenant).await.is_ok(),
        "within the TTL the cached answer stands — the documented bound"
    );
    assert!(matches!(
        r.tenants.get_by_id(r.tenant).await,
        Err(AxiamError::NotFound { .. })
    ));
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(matches!(
        r.tenants.get_by_id_cached(r.tenant).await,
        Err(AxiamError::NotFound { .. })
    ));
}

#[tokio::test]
async fn a_cached_account_carries_no_credentials_and_follows_status_changes() {
    let r = repos(Duration::from_secs(60)).await;
    let user = r
        .users
        .create(CreateUser {
            tenant_id: r.tenant,
            username: "u".into(),
            email: "u@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    for _ in 0..2 {
        let cached = r.users.get_by_id_cached(r.tenant, user.id).await.unwrap();
        assert!(cached.password_hash.is_empty(), "no hash, miss or hit");
        assert!(cached.mfa_secret.is_none());
        assert_eq!(cached.status, user.status, "the account as created");
    }
    // The uncached read is untouched.
    assert!(
        !r.users
            .get_by_id(r.tenant, user.id)
            .await
            .unwrap()
            .password_hash
            .is_empty()
    );

    r.users
        .update(
            r.tenant,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Locked),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        r.users
            .get_by_id_cached(r.tenant, user.id)
            .await
            .unwrap()
            .status,
        UserStatus::Locked
    );
    // Deletion anonymises the row in place and marks it `Deleted`; the cached
    // `Locked` copy must not outlive it.
    r.users.delete(r.tenant, user.id).await.unwrap();
    assert_eq!(
        r.users
            .get_by_id_cached(r.tenant, user.id)
            .await
            .unwrap()
            .status,
        UserStatus::Deleted
    );
}

#[tokio::test]
async fn the_client_lookup_is_served_from_the_caches_and_dropped_by_a_client_write() {
    let r = repos(Duration::from_secs(60)).await;
    let (client, _) = r
        .clients
        .create(CreateOAuth2Client {
            tenant_id: r.tenant,
            name: "c".into(),
            redirect_uris: vec!["http://127.0.0.1/callback".into()],
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: Vec::new(),
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            allowed_resources: Vec::new(),
            managed_by: ManagedBy::Admin,
            ciba: Default::default(),
            default_idp: None,
        })
        .await
        .unwrap();

    let first = r
        .clients
        .get_by_client_id_with_context(r.tenant, &client.client_id, None)
        .await
        .unwrap();
    assert_eq!(first.client.id, client.id);

    // Removed behind the repository's back: the cached lookup still answers
    // (≤ TTL), which shows it no longer reads the datastore.
    out_of_band(
        &r.db,
        "DELETE type::record('oauth2_client', $id)",
        client.id,
    )
    .await;
    let cached = r
        .clients
        .get_by_client_id_with_context(r.tenant, &client.client_id, None)
        .await
        .unwrap();
    assert_eq!(cached.client.id, client.id);
    assert!(cached.tenant.unwrap().is_ok());

    // A write through the repository drops it, whatever the write's outcome.
    let _ = r
        .clients
        .update(
            r.tenant,
            client.id,
            UpdateOAuth2Client {
                name: Some("renamed".into()),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(
        r.clients
            .get_by_client_id_with_context(r.tenant, &client.client_id, None)
            .await,
        Err(AxiamError::NotFound { .. })
    ));
}

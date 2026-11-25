//! The single-record reads on every authenticated request —
//! `SessionRepository::get_by_id` (the revocation check) and
//! `UserRepository::get_by_id` — check the row's tenant in the repository
//! instead of in a `WHERE` on the fetch (see
//! `claude_dev/db-query-optimization.md`). The answer must be what the
//! predicate gave: the row in its own tenant, and `NotFound` — never the row —
//! when asked from any other tenant.

use axiam_core::error::AxiamError;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, SessionRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_test_support::test_password;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

async fn setup() -> (Surreal<Db>, Uuid, Uuid) {
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
        .unwrap()
        .id;
    let tenants = SurrealTenantRepository::new(db.clone());
    let mut ids = Vec::new();
    for slug in ["a", "b"] {
        ids.push(
            tenants
                .create(CreateTenant {
                    organization_id: org,
                    kind: TenantKind::Standard,
                    name: slug.into(),
                    slug: slug.into(),
                    metadata: None,
                })
                .await
                .unwrap()
                .id,
        );
    }
    (db, ids[0], ids[1])
}

#[tokio::test]
async fn a_user_is_read_in_its_own_tenant_only() {
    let (db, a, b) = setup().await;
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id: a,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let read = users.get_by_id(a, user.id).await.unwrap();
    assert_eq!((read.id, read.tenant_id), (user.id, a));

    for wrong in [b, Uuid::new_v4(), Uuid::nil()] {
        assert!(
            matches!(
                users.get_by_id(wrong, user.id).await,
                Err(AxiamError::NotFound { .. })
            ),
            "tenant {wrong} must not read tenant {a}'s user"
        );
    }
    assert!(matches!(
        users.get_by_id(a, Uuid::new_v4()).await,
        Err(AxiamError::NotFound { .. })
    ));
}

#[tokio::test]
async fn a_session_is_read_and_validated_in_its_own_tenant_only() {
    let (db, a, b) = setup().await;
    let sessions = SurrealSessionRepository::new(db.clone());
    let session = sessions
        .create(CreateSession {
            tenant_id: a,
            user_id: Uuid::new_v4(),
            token_hash: "h".into(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            amr: vec![Amr::Pwd],
            browser_token_hash: None,
            lineage_id: None,
        })
        .await
        .unwrap();

    assert_eq!(
        sessions.get_by_id(a, session.id).await.unwrap().id,
        session.id
    );
    assert!(sessions.is_session_active_checked(a, session.id).await);

    for wrong in [b, Uuid::new_v4(), Uuid::nil()] {
        assert!(matches!(
            sessions.get_by_id(wrong, session.id).await,
            Err(AxiamError::NotFound { .. })
        ));
        assert!(
            !sessions.is_session_active_checked(wrong, session.id).await,
            "a session is never active for another tenant"
        );
    }
}

// ---------------------------------------------------------------------------
// The merged reads: session check + account, client + tenant + account
// ---------------------------------------------------------------------------

async fn user_in(db: &Surreal<Db>, tenant_id: Uuid, name: &str) -> Uuid {
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

async fn session_for(db: &Surreal<Db>, tenant_id: Uuid, user_id: Uuid, ttl: Duration) -> Uuid {
    SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: Uuid::new_v4().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + ttl,
            authenticated_at: Utc::now(),
            amr: vec![Amr::Pwd],
            browser_token_hash: None,
            lineage_id: None,
        })
        .await
        .unwrap()
        .id
}

/// The client lookup with its tenant and an account: the client as
/// `get_by_client_id` answers, the tenant as `TenantRepository::get_by_id`
/// (a tombstoned one is NotFound), the account as `UserRepository::get_by_id`.
#[tokio::test]
async fn the_client_lookup_with_context_answers_as_the_three_reads() {
    use axiam_core::models::oauth2_client::{
        AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
    };
    use axiam_core::repository::OAuth2ClientRepository;
    use axiam_db::repository::SurrealOAuth2ClientRepository;

    let (db, a, b) = setup().await;
    let clients = SurrealOAuth2ClientRepository::new(db.clone());
    let (client, _secret) = clients
        .create(CreateOAuth2Client {
            tenant_id: a,
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
    let alice = user_in(&db, a, "alice").await;
    let bob = user_in(&db, b, "bob").await;

    let lookup = clients
        .get_by_client_id_with_context(a, &client.client_id, Some(alice))
        .await
        .unwrap();
    assert_eq!(lookup.client.id, client.id);
    assert_eq!(lookup.tenant.unwrap().unwrap().id, a);
    assert_eq!(lookup.user.unwrap().unwrap().id, alice);

    // No account asked for, none read; another tenant's account is NotFound.
    let lookup = clients
        .get_by_client_id_with_context(a, &client.client_id, None)
        .await
        .unwrap();
    assert!(lookup.user.is_none());
    let lookup = clients
        .get_by_client_id_with_context(a, &client.client_id, Some(bob))
        .await
        .unwrap();
    assert!(matches!(
        lookup.user,
        Some(Err(AxiamError::NotFound { .. }))
    ));

    // The client's own outcome is the method's.
    assert!(matches!(
        clients
            .get_by_client_id_with_context(a, "oa_unknown", Some(alice))
            .await,
        Err(AxiamError::NotFound { .. })
    ));
    assert!(matches!(
        clients
            .get_by_client_id_with_context(b, &client.client_id, None)
            .await,
        Err(AxiamError::NotFound { .. })
    ));

    // A tombstoned tenant reads as the liveness read says: NotFound.
    db.query("UPDATE type::record('tenant', $t) SET deleted_at = time::now()")
        .bind(("t", a.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let lookup = clients
        .get_by_client_id_with_context(a, &client.client_id, None)
        .await
        .unwrap();
    assert!(matches!(
        lookup.tenant,
        Some(Err(AxiamError::NotFound { .. }))
    ));
    assert!(matches!(
        SurrealTenantRepository::new(db.clone()).get_by_id(a).await,
        Err(AxiamError::NotFound { .. })
    ));
}

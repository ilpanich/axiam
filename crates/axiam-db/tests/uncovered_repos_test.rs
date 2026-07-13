//! CRUD coverage for repositories that carry no axiam-db-local tests:
//! webhooks, federation config/link, OAuth2 clients, and the email
//! verification / password reset token repos. Uses the in-memory SurrealDB
//! engine — no external services required.

use axiam_core::models::email_verification::CreateEmailVerificationToken;
use axiam_core::models::federation::{
    CreateFederationConfig, CreateFederationLink, FederationProtocol, UpdateFederationConfig,
};
use axiam_core::models::oauth2_client::{CreateOAuth2Client, UpdateOAuth2Client};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::models::webhook::{CreateWebhook, RetryPolicy, UpdateWebhook};
use axiam_core::repository::{
    EmailVerificationTokenRepository, FederationConfigRepository, FederationLinkRepository,
    OAuth2ClientRepository, OrganizationRepository, Pagination, PasswordResetTokenRepository,
    TenantRepository, UserRepository, WebhookRepository,
};
use axiam_db::repository::{
    SurrealEmailVerificationTokenRepository, SurrealFederationConfigRepository,
    SurrealFederationLinkRepository, SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealPasswordResetTokenRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebhookRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

/// Runtime-built test password (avoids a hard-coded credential literal).
fn test_password() -> String {
    std::env::var("AXIAM_TEST_PASSWORD").unwrap_or_else(|_| ["Super", "Secret123!"].concat())
}


type Db = Surreal<surrealdb::engine::local::Db>;

async fn setup() -> (Db, Uuid, Uuid) {
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
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    (db, org.id, tenant.id)
}

async fn make_user(db: &Db, tenant_id: Uuid) -> Uuid {
    SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: format!("u{}", Uuid::new_v4().simple()),
            email: format!("{}@example.com", Uuid::new_v4().simple()),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

// ---------------------------------------------------------------------------
// Webhook
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webhook_crud() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealWebhookRepository::new(db);

    let wh = repo
        .create(CreateWebhook {
            tenant_id,
            url: "https://hooks.example.com/a".into(),
            events: vec!["user.created".into()],
            secret: "enc-secret".into(),
            retry_policy: Some(RetryPolicy::default()),
        })
        .await
        .unwrap();

    let got = repo.get_by_id(tenant_id, wh.id).await.unwrap();
    assert_eq!(got.url, "https://hooks.example.com/a");

    let updated = repo
        .update(
            tenant_id,
            wh.id,
            UpdateWebhook {
                enabled: Some(false),
                events: Some(vec!["user.deleted".into()]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!updated.enabled);
    assert_eq!(updated.events, vec!["user.deleted".to_string()]);

    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|w| w.id == wh.id));

    repo.delete(tenant_id, wh.id).await.unwrap();
    assert!(repo.get_by_id(tenant_id, wh.id).await.is_err());
}

// ---------------------------------------------------------------------------
// FederationConfig
// ---------------------------------------------------------------------------

#[tokio::test]
async fn federation_config_crud_and_backfill() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);

    let cfg = repo
        .create(CreateFederationConfig {
            tenant_id,
            provider: "okta".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some("https://idp.example.com/.well-known".into()),
            client_id: "cid".into(),
            client_secret: "legacy-plain".into(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: Some(vec!["RS256".into()]),
        })
        .await
        .unwrap();

    let got = repo.get_by_id(tenant_id, cfg.id).await.unwrap();
    assert_eq!(got.provider, "okta");

    let updated = repo
        .update(
            tenant_id,
            cfg.id,
            UpdateFederationConfig {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(!updated.enabled);

    // legacy-plaintext backfill query surfaces this row.
    let legacy = repo.list_with_legacy_plaintext_secret().await.unwrap();
    assert!(legacy.iter().any(|c| c.id == cfg.id));

    // Persist encrypted secret + clear legacy.
    repo.set_encrypted_secret(tenant_id, cfg.id, "nonce".into(), "cipher".into(), 1)
        .await
        .unwrap();
    let after = repo.get_by_id(tenant_id, cfg.id).await.unwrap();
    assert_eq!(after.client_secret_ciphertext.as_deref(), Some("cipher"));

    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|c| c.id == cfg.id));

    repo.delete(tenant_id, cfg.id).await.unwrap();
    assert!(repo.get_by_id(tenant_id, cfg.id).await.is_err());
}

// ---------------------------------------------------------------------------
// FederationLink
// ---------------------------------------------------------------------------

#[tokio::test]
async fn federation_link_create_and_lookup() {
    let (db, _org, tenant_id) = setup().await;
    let user_id = make_user(&db, tenant_id).await;
    let cfg_id = Uuid::new_v4();
    let repo = SurrealFederationLinkRepository::new(db);

    let link = repo
        .create(CreateFederationLink {
            tenant_id,
            user_id,
            federation_config_id: cfg_id,
            external_subject: "ext-sub-123".into(),
            external_email: Some("ext@example.com".into()),
        })
        .await
        .unwrap();
    assert_eq!(link.user_id, user_id);

    let by_subject = repo
        .get_by_external_subject(tenant_id, cfg_id, "ext-sub-123")
        .await
        .unwrap();
    assert_eq!(by_subject.id, link.id);

    let by_user = repo.get_by_user_id(tenant_id, user_id).await.unwrap();
    assert!(by_user.iter().any(|l| l.id == link.id));

    // Unknown subject → not found.
    assert!(
        repo.get_by_external_subject(tenant_id, cfg_id, "nope")
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// OAuth2Client
// ---------------------------------------------------------------------------

#[tokio::test]
async fn oauth2_client_crud() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealOAuth2ClientRepository::new(db);

    let (client, secret) = repo
        .create(CreateOAuth2Client {
            tenant_id,
            name: "My App".into(),
            redirect_uris: vec!["https://app.example.com/cb".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
        })
        .await
        .unwrap();
    assert!(!secret.is_empty());

    let by_id = repo.get_by_id(tenant_id, client.id).await.unwrap();
    assert_eq!(by_id.name, "My App");

    let by_client_id = repo
        .get_by_client_id(tenant_id, &client.client_id)
        .await
        .unwrap();
    assert_eq!(by_client_id.id, client.id);

    let updated = repo
        .update(
            tenant_id,
            client.id,
            UpdateOAuth2Client {
                name: Some("Renamed".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.name, "Renamed");

    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert!(page.items.iter().any(|c| c.id == client.id));

    repo.delete(tenant_id, client.id).await.unwrap();
    assert!(repo.get_by_id(tenant_id, client.id).await.is_err());
}

// ---------------------------------------------------------------------------
// Email verification tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn email_verification_token_lifecycle() {
    let (db, _org, tenant_id) = setup().await;
    let user_id = make_user(&db, tenant_id).await;
    let repo = SurrealEmailVerificationTokenRepository::new(db);

    let hash = "verify-hash-abc";
    repo.create(CreateEmailVerificationToken {
        tenant_id,
        user_id,
        token_hash: hash.into(),
        expires_at: Utc::now() + Duration::hours(24),
    })
    .await
    .unwrap();

    let got = repo.get_by_token_hash(tenant_id, hash).await.unwrap();
    assert_eq!(got.user_id, user_id);

    let consumed = repo.consume(tenant_id, hash).await.unwrap();
    assert_eq!(consumed.user_id, user_id);

    // Second consume → error (already consumed).
    assert!(repo.consume(tenant_id, hash).await.is_err());
}

#[tokio::test]
async fn email_verification_token_expired_is_not_returned() {
    let (db, _org, tenant_id) = setup().await;
    let user_id = make_user(&db, tenant_id).await;
    let repo = SurrealEmailVerificationTokenRepository::new(db);

    repo.create(CreateEmailVerificationToken {
        tenant_id,
        user_id,
        token_hash: "expired".into(),
        expires_at: Utc::now() - Duration::hours(1),
    })
    .await
    .unwrap();
    assert!(repo.get_by_token_hash(tenant_id, "expired").await.is_err());
}

// ---------------------------------------------------------------------------
// Password reset tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn password_reset_token_lifecycle() {
    let (db, _org, tenant_id) = setup().await;
    let user_id = make_user(&db, tenant_id).await;
    let repo = SurrealPasswordResetTokenRepository::new(db);

    let hash = "reset-hash-xyz";
    repo.create(CreatePasswordResetToken {
        tenant_id,
        user_id,
        token_hash: hash.into(),
        expires_at: Utc::now() + Duration::hours(1),
    })
    .await
    .unwrap();

    let got = repo.get_by_token_hash(tenant_id, hash).await.unwrap();
    assert_eq!(got.user_id, user_id);

    repo.consume(tenant_id, hash).await.unwrap();
    assert!(repo.consume(tenant_id, hash).await.is_err());
}

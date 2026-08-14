//! CRUD coverage for repositories that carry no axiam-db-local tests:
//! webhooks, federation config/link, OAuth2 clients, and the email
//! verification / password reset token repos. Uses the in-memory SurrealDB
//! engine — no external services required.

use axiam_core::models::email_verification::CreateEmailVerificationToken;
use axiam_core::models::federation::{
    CreateFederationConfig, CreateFederationLink, FederationProtocol, SubjectMapping,
    TokenExchangeTrust, UpdateFederationConfig,
};
use axiam_core::models::oauth2_client::{CreateOAuth2Client, UpdateOAuth2Client};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::models::webhook::{CreateWebhook, RetryPolicy, UpdateWebhook};
use axiam_core::repository::{
    EmailVerificationTokenRepository, FederationConfigRepository, FederationLinkRepository,
    OAuth2ClientRepository, OrganizationRepository, Pagination, PasswordResetTokenRepository,
    ServiceAccountRepository, TenantRepository, UserRepository, WebhookRepository,
};
use axiam_db::repository::{
    SurrealEmailVerificationTokenRepository, SurrealFederationConfigRepository,
    SurrealFederationLinkRepository, SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealPasswordResetTokenRepository, SurrealServiceAccountRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebhookRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

use axiam_test_support::test_password;

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

#[tokio::test]
async fn webhook_not_found_branches() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealWebhookRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.get_by_id(tenant_id, missing).await.is_err());
    assert!(
        repo.update(
            tenant_id,
            missing,
            UpdateWebhook {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .is_err()
    );
    assert!(repo.delete(tenant_id, missing).await.is_err());
}

#[tokio::test]
async fn webhook_get_by_event_filters_enabled_and_event_type() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealWebhookRepository::new(db);

    let matching = repo
        .create(CreateWebhook {
            tenant_id,
            url: "https://hooks.example.com/matching".into(),
            events: vec!["user.created".into(), "user.deleted".into()],
            secret: "s1".into(),
            retry_policy: None,
        })
        .await
        .unwrap();

    let wrong_event = repo
        .create(CreateWebhook {
            tenant_id,
            url: "https://hooks.example.com/wrong-event".into(),
            events: vec!["user.deleted".into()],
            secret: "s2".into(),
            retry_policy: None,
        })
        .await
        .unwrap();
    let _ = wrong_event;

    let disabled = repo
        .create(CreateWebhook {
            tenant_id,
            url: "https://hooks.example.com/disabled".into(),
            events: vec!["user.created".into()],
            secret: "s3".into(),
            retry_policy: None,
        })
        .await
        .unwrap();
    repo.update(
        tenant_id,
        disabled.id,
        UpdateWebhook {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    let results = repo.get_by_event(tenant_id, "user.created").await.unwrap();
    assert_eq!(
        results.len(),
        1,
        "only the enabled, matching webhook: {results:?}"
    );
    assert_eq!(results[0].id, matching.id);
}

#[tokio::test]
async fn webhook_update_rotates_secret() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealWebhookRepository::new(db);

    let wh = repo
        .create(CreateWebhook {
            tenant_id,
            url: "https://hooks.example.com/rotate".into(),
            events: vec!["user.created".into()],
            secret: "old-secret".into(),
            retry_policy: None,
        })
        .await
        .unwrap();

    let updated = repo
        .update(
            tenant_id,
            wh.id,
            UpdateWebhook {
                secret: Some("new-secret".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.secret, "new-secret");
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
            token_exchange: None,
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
// X4 — external token-exchange trust
// ---------------------------------------------------------------------------

/// A provider created without a trust block reads back as
/// `TokenExchangeTrust::default()` — disabled, trusting nothing.
///
/// This is the "no backfill" claim of schema v36 stated as a test: the
/// migration adds columns and nothing rewrites existing rows, so a pre-X4 row
/// must hydrate to today's behaviour rather than to a partially-populated
/// struct. `list_token_exchange_enabled` must also not see it.
#[tokio::test]
async fn a_provider_without_a_trust_block_reads_back_disabled() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);

    let cfg = repo
        .create(CreateFederationConfig {
            tenant_id,
            provider: "legacy-idp".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some("https://idp.example.com/.well-known".into()),
            client_id: "cid".into(),
            client_secret: String::new(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: None,
            token_exchange: None,
        })
        .await
        .unwrap();

    let got = repo.get_by_id(tenant_id, cfg.id).await.unwrap();
    assert_eq!(got.token_exchange, TokenExchangeTrust::default());
    assert!(!got.token_exchange.enabled);

    assert!(
        repo.list_token_exchange_enabled(tenant_id)
            .await
            .unwrap()
            .is_empty(),
        "a provider with no trust block must not be a candidate issuer"
    );
}

/// Every field survives a write/read round trip, including the nested scope
/// map — which is stored as a JSON string, so it is the one field a naive
/// column mapping would quietly lose.
#[tokio::test]
async fn a_trust_block_round_trips_through_the_datastore() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);

    let mut scope_map = std::collections::BTreeMap::new();
    scope_map.insert(
        "partner.orders.read".to_string(),
        vec!["read:orders".to_string(), "list:orders".to_string()],
    );
    let trust = TokenExchangeTrust {
        enabled: true,
        accepted_audiences: vec!["https://api.example.com".into()],
        subject_mapping: SubjectMapping::JitProvision,
        scope_map,
        max_token_age_secs: 120,
        max_lifetime_secs: Some(600),
    };

    let cfg = repo
        .create(CreateFederationConfig {
            tenant_id,
            provider: "partner".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some("https://partner.example/.well-known".into()),
            client_id: "cid".into(),
            client_secret: String::new(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: Some(vec!["RS256".into()]),
            token_exchange: Some(trust.clone()),
        })
        .await
        .unwrap();

    assert_eq!(
        repo.get_by_id(tenant_id, cfg.id)
            .await
            .unwrap()
            .token_exchange,
        trust
    );

    // The exchange path's own query must find it, and hydrate it fully —
    // that query uses the narrowed list projection, which is a second place
    // the columns have to be named.
    let candidates = repo.list_token_exchange_enabled(tenant_id).await.unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].token_exchange, trust);

    // Disabling removes it from the candidate set. Wholesale replacement, so
    // the rest of the block travels with the flag.
    repo.update(
        tenant_id,
        cfg.id,
        UpdateFederationConfig {
            token_exchange: Some(TokenExchangeTrust {
                enabled: false,
                ..trust.clone()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        repo.list_token_exchange_enabled(tenant_id)
            .await
            .unwrap()
            .is_empty()
    );
    let after = repo.get_by_id(tenant_id, cfg.id).await.unwrap();
    assert_eq!(
        after.token_exchange.accepted_audiences,
        trust.accepted_audiences
    );
    assert_eq!(after.token_exchange.scope_map, trust.scope_map);
}

/// A SAML row is never a candidate, whatever its columns say. It has no issuer
/// to match and no JWKS to verify against, so the predicate lives in the query
/// rather than in every caller.
#[tokio::test]
async fn a_saml_provider_is_never_a_token_exchange_candidate() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);

    repo.create(CreateFederationConfig {
        tenant_id,
        provider: "saml-idp".into(),
        protocol: FederationProtocol::Saml,
        metadata_url: Some("https://saml.example/metadata".into()),
        client_id: "cid".into(),
        client_secret: String::new(),
        attribute_map: None,
        idp_signing_cert_pem: None,
        allowed_algorithms: None,
        token_exchange: Some(TokenExchangeTrust {
            enabled: true,
            accepted_audiences: vec!["https://api.example.com".into()],
            ..TokenExchangeTrust::default()
        }),
    })
    .await
    .unwrap();

    assert!(
        repo.list_token_exchange_enabled(tenant_id)
            .await
            .unwrap()
            .is_empty()
    );
}

/// A provider that is globally disabled is not a candidate either. `enabled`
/// and `token_exchange.enabled` are different statements — "this provider is
/// live at all" and "…and its tokens may be exchanged" — and both must hold.
#[tokio::test]
async fn a_globally_disabled_provider_is_not_a_candidate() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);

    let cfg = repo
        .create(CreateFederationConfig {
            tenant_id,
            provider: "paused".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some("https://paused.example/.well-known".into()),
            client_id: "cid".into(),
            client_secret: String::new(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: None,
            token_exchange: Some(TokenExchangeTrust {
                enabled: true,
                accepted_audiences: vec!["https://api.example.com".into()],
                ..TokenExchangeTrust::default()
            }),
        })
        .await
        .unwrap();
    assert_eq!(
        repo.list_token_exchange_enabled(tenant_id)
            .await
            .unwrap()
            .len(),
        1
    );

    repo.update(
        tenant_id,
        cfg.id,
        UpdateFederationConfig {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();

    assert!(
        repo.list_token_exchange_enabled(tenant_id)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn federation_config_not_found_branches() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);
    let missing = Uuid::new_v4();

    assert!(repo.get_by_id(tenant_id, missing).await.is_err());
    assert!(
        repo.update(
            tenant_id,
            missing,
            UpdateFederationConfig {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .is_err()
    );
    assert!(repo.delete(tenant_id, missing).await.is_err());
}

#[tokio::test]
async fn federation_config_list_excludes_secret_columns() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);

    repo.create(CreateFederationConfig {
        tenant_id,
        provider: "generic".into(),
        protocol: FederationProtocol::OidcConnect,
        metadata_url: None,
        client_id: "cid".into(),
        client_secret: "super-secret-plaintext".into(),
        attribute_map: None,
        idp_signing_cert_pem: None,
        allowed_algorithms: None,
        token_exchange: None,
    })
    .await
    .unwrap();

    let page = repo.list(tenant_id, Pagination::default()).await.unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].client_secret, "",
        "list() must never hydrate the plaintext secret (SECHRD-09/D-06)"
    );
    assert!(page.items[0].client_secret_ciphertext.is_none());
}

#[tokio::test]
async fn federation_config_legacy_plaintext_excludes_encrypted_rows() {
    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealFederationConfigRepository::new(db);

    let legacy = repo
        .create(CreateFederationConfig {
            tenant_id,
            provider: "legacy".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: None,
            client_id: "cid-legacy".into(),
            client_secret: "plain".into(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: None,
            token_exchange: None,
        })
        .await
        .unwrap();

    let encrypted = repo
        .create(CreateFederationConfig {
            tenant_id,
            provider: "encrypted".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: None,
            client_id: "cid-encrypted".into(),
            client_secret: "plain2".into(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: None,
            token_exchange: None,
        })
        .await
        .unwrap();
    repo.set_encrypted_secret(tenant_id, encrypted.id, "nonce".into(), "cipher".into(), 1)
        .await
        .unwrap();

    let pending = repo.list_with_legacy_plaintext_secret().await.unwrap();
    assert!(pending.iter().any(|c| c.id == legacy.id));
    assert!(
        !pending.iter().any(|c| c.id == encrypted.id),
        "an already-encrypted row must not be reported as legacy plaintext"
    );
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
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
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

/// OBS-1 — the lazy migration of a legacy `client_secret_hash`, exercised
/// against a real SurrealDB instance rather than a mock.
///
/// A pre-OBS-1 row is planted by writing the unsalted SHA-256 digest directly,
/// because the repository can no longer produce one.
#[tokio::test]
async fn oauth2_client_secret_hash_is_upgraded_with_a_compare_and_swap() {
    use axiam_db::client_secret::{self, ClientSecretVerdict, V2_PREFIX};

    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealOAuth2ClientRepository::new(db.clone());
    let hasher = client_secret::global().unwrap();

    let (client, secret) = repo
        .create(CreateOAuth2Client {
            tenant_id,
            name: "Legacy App".into(),
            redirect_uris: vec!["https://app.example.com/cb".into()],
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
        })
        .await
        .unwrap();

    // A newly created client is already in the current scheme.
    assert!(client.client_secret_hash.starts_with(V2_PREFIX));

    // Plant the pre-OBS-1 representation of the same secret.
    let legacy = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(secret.as_bytes()))
    };
    db.query("UPDATE oauth2_client SET client_secret_hash = $h WHERE client_id = $c")
        .bind(("h", legacy.clone()))
        .bind(("c", client.client_id.clone()))
        .await
        .unwrap();

    let stored = repo
        .get_by_client_id(tenant_id, &client.client_id)
        .await
        .unwrap();
    assert_eq!(stored.client_secret_hash, legacy);

    // The legacy row still verifies, and asks to be upgraded.
    let upgraded_hash = match hasher.verify(&secret, &stored.client_secret_hash) {
        ClientSecretVerdict::MatchNeedsUpgrade { upgraded_hash } => upgraded_hash,
        other => panic!("expected MatchNeedsUpgrade, got {other:?}"),
    };

    assert!(
        repo.upgrade_client_secret_hash(tenant_id, &client.client_id, &legacy, &upgraded_hash,)
            .await
            .unwrap(),
        "the compare-and-swap must match the row it read"
    );

    let migrated = repo
        .get_by_client_id(tenant_id, &client.client_id)
        .await
        .unwrap();
    assert_eq!(migrated.client_secret_hash, upgraded_hash);
    assert!(migrated.client_secret_hash.starts_with(V2_PREFIX));
    assert_eq!(
        hasher.verify(&secret, &migrated.client_secret_hash),
        ClientSecretVerdict::Match,
        "the migrated row verifies with no further upgrade"
    );

    // Replaying the same upgrade (as a racing request would) is a no-op: the
    // CAS no longer matches, so nothing is written and `false` is returned.
    assert!(
        !repo
            .upgrade_client_secret_hash(tenant_id, &client.client_id, &legacy, &upgraded_hash)
            .await
            .unwrap(),
        "a stale compare-and-swap must not clobber the row"
    );

    // A rotation racing the upgrade must win: with a different current hash,
    // the CAS fails and the rotated secret survives.
    let rotated = hasher.hash("some-rotated-secret");
    db.query("UPDATE oauth2_client SET client_secret_hash = $h WHERE client_id = $c")
        .bind(("h", rotated.clone()))
        .bind(("c", client.client_id.clone()))
        .await
        .unwrap();
    assert!(
        !repo
            .upgrade_client_secret_hash(tenant_id, &client.client_id, &legacy, &upgraded_hash)
            .await
            .unwrap()
    );
    let after = repo
        .get_by_client_id(tenant_id, &client.client_id)
        .await
        .unwrap();
    assert_eq!(
        after.client_secret_hash, rotated,
        "a concurrent rotation must never be clobbered by a late migration"
    );

    // Tenant scoping: another tenant cannot drive the migration.
    assert!(
        !repo
            .upgrade_client_secret_hash(
                Uuid::new_v4(),
                &client.client_id,
                &rotated,
                &hasher.hash("attacker"),
            )
            .await
            .unwrap()
    );
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

// ---------------------------------------------------------------------------
// Service-account client-secret migration (§13.4 observation 4)
// ---------------------------------------------------------------------------

/// Service accounts write the current hash scheme on create/rotate, but had no
/// `upgrade_client_secret_hash`, so an existing row never migrated no matter how
/// often it authenticated. The consequence was structural: the v1 arm of the
/// verifier could not be retired on the strength of "no v1 `oauth2_client` rows
/// remain", because the `service_account` table was silently accumulating rows
/// the migration never reached.
#[tokio::test]
async fn service_account_client_secret_hash_migrates_with_a_compare_and_swap() {
    use axiam_db::client_secret::{self, ClientSecretVerdict, V2_PREFIX};

    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db.clone());
    let hasher = client_secret::global().unwrap();

    let (sa, secret) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "svc-migrating".into(),
            description: None,
        })
        .await
        .unwrap();

    // Force the row back to a legacy (v1) hash, as a pre-OBS-1 deployment holds.
    let legacy = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(secret.as_bytes()))
    };
    db.query("UPDATE service_account SET client_secret_hash = $h WHERE client_id = $c")
        .bind(("h", legacy.clone()))
        .bind(("c", sa.client_id.clone()))
        .await
        .unwrap();

    let stored = repo
        .get_by_client_id(tenant_id, &sa.client_id)
        .await
        .unwrap();
    assert_eq!(stored.client_secret_hash, legacy);

    let upgraded_hash = match hasher.verify(&secret, &stored.client_secret_hash) {
        ClientSecretVerdict::MatchNeedsUpgrade { upgraded_hash } => upgraded_hash,
        other => panic!("expected MatchNeedsUpgrade, got {other:?}"),
    };

    assert!(
        repo.upgrade_client_secret_hash(tenant_id, &sa.client_id, &legacy, &upgraded_hash)
            .await
            .unwrap(),
        "the compare-and-swap must match the row it read"
    );

    let migrated = repo
        .get_by_client_id(tenant_id, &sa.client_id)
        .await
        .unwrap();
    assert!(migrated.client_secret_hash.starts_with(V2_PREFIX));
    assert_eq!(
        hasher.verify(&secret, &migrated.client_secret_hash),
        ClientSecretVerdict::Match,
        "the migrated row verifies with no further upgrade"
    );

    // A replayed upgrade (as a racing request would issue) is a no-op.
    assert!(
        !repo
            .upgrade_client_secret_hash(tenant_id, &sa.client_id, &legacy, &upgraded_hash)
            .await
            .unwrap(),
        "a stale compare-and-swap must not clobber the row"
    );

    // A rotation racing the upgrade must win — otherwise a late migration would
    // silently resurrect the previous secret.
    let rotated_secret = repo.rotate_secret(tenant_id, sa.id).await.unwrap();
    assert!(
        !repo
            .upgrade_client_secret_hash(tenant_id, &sa.client_id, &legacy, &upgraded_hash)
            .await
            .unwrap()
    );
    let after = repo
        .get_by_client_id(tenant_id, &sa.client_id)
        .await
        .unwrap();
    assert_eq!(
        hasher.verify(&rotated_secret, &after.client_secret_hash),
        ClientSecretVerdict::Match,
        "a concurrent rotation must never be clobbered by a late migration"
    );

    // Tenant scoping: `client_id` alone must not be enough. Another tenant
    // cannot drive a rewrite of this row's stored hash.
    assert!(
        !repo
            .upgrade_client_secret_hash(
                Uuid::new_v4(),
                &sa.client_id,
                &after.client_secret_hash,
                &hasher.hash("attacker"),
            )
            .await
            .unwrap()
    );
}

/// §15.2 — service-account legacy hashes must be *countable*.
///
/// They cannot migrate on their own: `upgrade_client_secret_hash` only fires on
/// a successful verification, and nothing in the running server verifies a
/// service-account secret. So the only honest answers are (a) make the backlog
/// visible, and (b) name rotation as the migration route. This pins both.
#[tokio::test]
async fn legacy_service_account_hashes_are_countable_and_clear_on_rotation() {
    use axiam_db::client_secret::V2_PREFIX;

    let (db, _org, tenant_id) = setup().await;
    let repo = SurrealServiceAccountRepository::new(db.clone());

    let (a, _) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "legacy-a".into(),
            description: None,
        })
        .await
        .unwrap();
    let (b, secret_b) = repo
        .create(CreateServiceAccount {
            tenant_id,
            name: "current-b".into(),
            description: None,
        })
        .await
        .unwrap();

    // Freshly created rows are already current.
    assert_eq!(repo.count_legacy_secret_hashes(None).await.unwrap(), 0);
    assert!(b.client_secret_hash.starts_with(V2_PREFIX));

    // Plant a pre-OBS-1 row, as a deployment upgraded from an older release has.
    let legacy = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(b"whatever"))
    };
    db.query("UPDATE service_account SET client_secret_hash = $h WHERE client_id = $c")
        .bind(("h", legacy))
        .bind(("c", a.client_id.clone()))
        .await
        .unwrap();

    assert_eq!(
        repo.count_legacy_secret_hashes(None).await.unwrap(),
        1,
        "the backlog must be visible — otherwise 'can the v1 arm be retired?' is unanswerable"
    );
    assert_eq!(
        repo.count_legacy_secret_hashes(Some(tenant_id))
            .await
            .unwrap(),
        1,
        "tenant scoping must narrow, not miss"
    );
    assert_eq!(
        repo.count_legacy_secret_hashes(Some(Uuid::new_v4()))
            .await
            .unwrap(),
        0,
        "another tenant's backlog must not be reported as this tenant's"
    );

    // Rotation is the migration route, since lazy upgrade can never fire here.
    let rotated = repo.rotate_secret(tenant_id, a.id).await.unwrap();
    assert_ne!(rotated, secret_b);
    assert_eq!(
        repo.count_legacy_secret_hashes(None).await.unwrap(),
        0,
        "rotating a legacy service account must clear it from the backlog"
    );
}

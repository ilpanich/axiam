//! X4 — external-IdP token exchange, end to end through the real token
//! endpoint.
//!
//! What only exists once the grant is mounted: that a partner's token, signed
//! by a *different* key than ours and verified against that IdP's JWKS, buys an
//! AXIAM token — and that each invariant, violated in isolation, produces its
//! own refusal. The scope arithmetic itself is proved exhaustively by
//! `axiam-oauth2`'s unit tests; the claim/signature checks by
//! `axiam-federation`'s. This file is about the seam.
//!
//! # The mock IdP
//!
//! RSA-2048, RS256, real JWKS served over loopback by wiremock — the same
//! harness `federation_first_time_sso_test.rs` uses, for the same reason: the
//! SSRF guard's `allow_private_networks` test seam (28-05) is what lets
//! `discover()` and the JWKS fetch reach a loopback server. Production
//! constructs `JwksCache::new()` and the guard stays fully enforced.
//!
//! # What this file deliberately does NOT prove
//!
//! X4's plan asks for fixtures minted by a **real Keycloak container** as
//! cross-vendor proof. That belongs to the e2e compose suite, not here — a
//! container is not available to a unit-test harness, and a hand-rolled
//! "Keycloak-shaped" token would prove only that this file and this file's
//! author agree. What *is* covered here is every claim shape those vendors
//! emit (`scope`, `scp` as string and array, `roles`, `groups`), each with its
//! own test.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::federation::{
    CreateFederationConfig, FederationProtocol, SubjectMapping, TokenExchangeTrust,
};
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, OAuth2ClientRepository,
    OrganizationRepository, PermissionRepository, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealRoleRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
use axiam_oauth2::token_exchange::{
    ISSUER_NOT_TRUSTED, TOKEN_EXCHANGE_GRANT_TYPE, TOKEN_TYPE_ACCESS_TOKEN, TOKEN_TYPE_ID_TOKEN,
    TOKEN_TYPE_JWT, TOKEN_TYPE_REFRESH_TOKEN,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:34599";
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
/// Test-only AES-256-GCM key (32 bytes of 0x2a) — not a secret. gitleaks:allow
const TEST_FED_ENC_KEY: [u8; 32] = [0x2a; 32];
const KID: &str = "partner-key-1";
const AXIAM_AUDIENCE: &str = "https://api.axiam.test";
const EXTERNAL_SUBJECT: &str = "partner-user-42";

// ---------------------------------------------------------------------------
// Mock IdP
// ---------------------------------------------------------------------------

struct IdpKeys {
    private_key_pem: String,
    jwk: Value,
}

impl IdpKeys {
    fn generate() -> Self {
        let mut rng = rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA key");
        let private_key_pem = key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("PEM")
            .to_string();
        Self {
            jwk: json!({
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
            }),
            private_key_pem,
        }
    }

    fn encoding_key(&self) -> EncodingKey {
        EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes()).expect("encoding key")
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn test_auth_config() -> AuthConfig {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.axiam.test".into(),
        federation_encryption_key: Some(TEST_FED_ENC_KEY),
        ..AuthConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    user_id: Uuid,
    client_id: String,
    client_secret: String,
    keys: IdpKeys,
    issuer: String,
    /// Kept alive for the duration of the test — dropping it stops the server.
    _idp: MockServer,
}

/// How the provider's trust block should be configured for a given test.
struct TrustSpec {
    enabled: bool,
    accepted_audiences: Vec<String>,
    subject_mapping: SubjectMapping,
    scope_map: BTreeMap<String, Vec<String>>,
    max_token_age_secs: i64,
    max_lifetime_secs: Option<i64>,
    /// Whether to write a `federation_link` for [`EXTERNAL_SUBJECT`].
    link_subject: bool,
    /// AXIAM actions granted to the seeded user, as `(action, deny)`.
    grants: Vec<(&'static str, bool)>,
}

impl Default for TrustSpec {
    fn default() -> Self {
        let mut scope_map = BTreeMap::new();
        scope_map.insert(
            "partner.orders.read".to_string(),
            vec!["read:orders".to_string()],
        );
        Self {
            enabled: true,
            accepted_audiences: vec![AXIAM_AUDIENCE.to_string()],
            subject_mapping: SubjectMapping::LinkedOnly,
            scope_map,
            max_token_age_secs: 300,
            max_lifetime_secs: None,
            link_subject: true,
            grants: vec![("read:orders", false)],
        }
    }
}

async fn setup(spec: TrustSpec) -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    // --- the mock IdP ---------------------------------------------------
    let keys = IdpKeys::generate();
    let idp = MockServer::start().await;
    let issuer = idp.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        })))
        .mount(&idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "keys": [keys.jwk.clone()] })),
        )
        .mount(&idp)
        .await;

    // --- tenant, user, client -------------------------------------------
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "X4 Org".into(),
            slug: "org-x4".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "X4 Tenant".into(),
            slug: "tenant-x4".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "partner-linked-user".into(),
            email: "partner@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let (client, secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "edge-gateway".into(),
            redirect_uris: vec!["https://orders.internal".into()],
            grant_types: vec![TOKEN_EXCHANGE_GRANT_TYPE.into()],
            scopes: vec!["read:orders".into(), "write:orders".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
        })
        .await
        .unwrap();

    // --- RBAC: what the user actually holds ------------------------------
    if !spec.grants.is_empty() {
        let role_repo = SurrealRoleRepository::new(db.clone());
        let perm_repo = SurrealPermissionRepository::new(db.clone());
        let role = role_repo
            .create(CreateRole {
                tenant_id: tenant.id,
                name: "partner-role".into(),
                description: String::new(),
                is_global: true,
            })
            .await
            .unwrap();
        role_repo
            .assign_to_user(tenant.id, user.id, role.id, None)
            .await
            .unwrap();
        for (action, deny) in &spec.grants {
            let perm = perm_repo
                .create(CreatePermission {
                    tenant_id: tenant.id,
                    action: (*action).into(),
                    description: String::new(),
                })
                .await
                .unwrap();
            perm_repo
                .grant_to_role_with_effect(
                    tenant.id,
                    role.id,
                    perm.id,
                    Vec::new(),
                    if *deny {
                        axiam_core::models::permission::PermissionEffect::Deny
                    } else {
                        axiam_core::models::permission::PermissionEffect::Allow
                    },
                )
                .await
                .unwrap();
        }
    }

    // --- the federation provider, with its X4 trust block ----------------
    let fed_repo = SurrealFederationConfigRepository::new(db.clone());
    let config = fed_repo
        .create(CreateFederationConfig {
            tenant_id: tenant.id,
            provider: "PartnerIdP".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some(format!("{issuer}/.well-known/openid-configuration")),
            client_id: "axiam-at-partner".into(),
            client_secret: "unused-for-exchange".into(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: Some(vec!["RS256".into()]),
            token_exchange: Some(TokenExchangeTrust {
                enabled: spec.enabled,
                accepted_audiences: spec.accepted_audiences,
                subject_mapping: spec.subject_mapping,
                scope_map: spec.scope_map,
                max_token_age_secs: spec.max_token_age_secs,
                max_lifetime_secs: spec.max_lifetime_secs,
            }),
        })
        .await
        .unwrap();

    if spec.link_subject {
        SurrealFederationLinkRepository::new(db.clone())
            .create(axiam_core::models::federation::CreateFederationLink {
                tenant_id: tenant.id,
                user_id: user.id,
                federation_config_id: config.id,
                external_subject: EXTERNAL_SUBJECT.into(),
                external_email: Some("partner@example.com".into()),
            })
            .await
            .unwrap();
    }

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        user_id: user.id,
        client_id: client.client_id,
        client_secret: secret,
        keys,
        issuer,
        _idp: idp,
    }
}

use axiam_db::repository::SurrealFederationLinkRepository;

/// Build the app with X4 switched on, exactly as production does.
macro_rules! test_app {
    ($f:expr) => {{
        let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new({
                    let mut state = AppState::for_test($f.db.clone(), $f.auth.clone());
                    // The loopback seam: without it the SSRF guard refuses the
                    // wiremock IdP and every test here fails identically for
                    // the wrong reason.
                    state.http_client = reqwest::Client::builder()
                        .redirect(reqwest::redirect::Policy::none())
                        .timeout(std::time::Duration::from_secs(10))
                        .build()
                        .unwrap();
                    state.jwks_cache = Arc::clone(&jwks_cache);
                    state.oidc_federation_service = Some(OidcFederationService::new(
                        state.federation_config_repo.clone(),
                        state.federation_link_repo.clone(),
                        state.user_repo.clone(),
                        state.http_client.clone(),
                        Arc::clone(&state.jwks_cache),
                        TEST_FED_ENC_KEY,
                    ));
                    assert!(
                        state.enable_external_token_exchange(),
                        "the federation service is installed, so X4 must switch on"
                    );
                    state
                }))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    }};
}

fn enc(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

macro_rules! exchange {
    ($app:expr, $f:expr, $extra:expr) => {{
        let body = format!(
            "grant_type={}&client_id={}&client_secret={}{}",
            enc(TOKEN_EXCHANGE_GRANT_TYPE),
            $f.client_id,
            $f.client_secret,
            $extra
        );
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/token?tenant_id={}", $f.tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let json: Value = test::read_body_json(resp).await;
        (status, json)
    }};
}

/// A partner token, with per-test overrides applied to the claims.
fn partner_token(f: &Fixture, mutate: impl FnOnce(&mut serde_json::Map<String, Value>)) -> String {
    let mut claims = serde_json::Map::new();
    claims.insert("iss".into(), json!(f.issuer));
    claims.insert("sub".into(), json!(EXTERNAL_SUBJECT));
    claims.insert("aud".into(), json!(AXIAM_AUDIENCE));
    claims.insert("iat".into(), json!(now()));
    claims.insert("exp".into(), json!(now() + 600));
    claims.insert("scope".into(), json!("partner.orders.read"));
    mutate(&mut claims);

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    header.typ = Some("at+jwt".into());
    encode(&header, &Value::Object(claims), &f.keys.encoding_key()).expect("sign")
}

fn subject_param(token: &str, ty: &str) -> String {
    format!("&subject_token={token}&subject_token_type={}", enc(ty))
}

fn claims_of(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("three parts");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("b64")).expect("json")
}

// ===========================================================================
// The happy path
// ===========================================================================

#[actix_web::test]
async fn a_trusted_partners_token_buys_a_scoped_axiam_token() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);

    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));

    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["issued_token_type"], TOKEN_TYPE_ACCESS_TOKEN);
    assert_eq!(body["scope"], "read:orders");
    assert!(
        body.get("refresh_token").is_none(),
        "an exchange never issues a refresh token"
    );

    let claims = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(
        claims["sub"],
        f.user_id.to_string(),
        "the subject is the LINKED AXIAM user, not the partner's identifier"
    );
    assert_eq!(
        claims["ext_exchange"]["iss"], f.issuer,
        "provenance must be stamped into the token"
    );
    assert_eq!(claims["aud"], "axiam:user");
    assert!(claims.get("act").is_none());
}

/// Every claim shape the target IdPs actually emit reaches the scope map.
#[actix_web::test]
async fn each_vendor_claim_shape_feeds_the_scope_map() {
    for (name, apply) in [
        (
            "scope (Okta/Keycloak/RFC 9068)",
            json!({ "scope": "partner.orders.read other" }),
        ),
        (
            "scp string (Entra)",
            json!({ "scp": "partner.orders.read" }),
        ),
        (
            "scp array (Okta)",
            json!({ "scp": ["partner.orders.read"] }),
        ),
        (
            "roles (Entra app roles)",
            json!({ "roles": ["partner.orders.read"] }),
        ),
        ("groups", json!({ "groups": ["partner.orders.read"] })),
    ] {
        let f = setup(TrustSpec::default()).await;
        let app = test_app!(f);
        let token = partner_token(&f, |c| {
            c.remove("scope");
            for (k, v) in apply.as_object().unwrap() {
                c.insert(k.clone(), v.clone());
            }
        });
        let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
        assert_eq!(status, 200, "{name}: {body:?}");
        assert_eq!(body["scope"], "read:orders", "{name}");
    }
}

#[actix_web::test]
async fn an_access_token_type_is_accepted_for_an_external_issuer_too() {
    // A caller who knows the partner calls it an access token should not have
    // to learn RFC 8693's generic `…:jwt` type to be understood.
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_ACCESS_TOKEN));
    assert_eq!(status, 200, "{body:?}");
}

// ===========================================================================
// The validation matrix — each invariant violated in isolation
// ===========================================================================

#[actix_web::test]
async fn a_provider_with_token_exchange_disabled_does_not_trust_its_own_issuer() {
    let f = setup(TrustSpec {
        enabled: false,
        ..Default::default()
    })
    .await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));

    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"], ISSUER_NOT_TRUSTED,
        "configuring a provider for LOGIN is not agreement to accept its \
         tokens as API credentials"
    );
}

#[actix_web::test]
async fn an_issuer_nobody_configured_is_named_as_such() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        c.insert("iss".into(), json!("https://stranger.example"));
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));

    assert_eq!(status, 400);
    assert_eq!(body["error_description"], ISSUER_NOT_TRUSTED);
}

#[actix_web::test]
async fn a_token_signed_by_the_wrong_key_is_refused_generically() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);

    // Correct issuer, correct claims, a key the IdP's JWKS does not publish.
    let impostor = IdpKeys::generate();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.into());
    let token = encode(
        &header,
        &json!({
            "iss": f.issuer, "sub": EXTERNAL_SUBJECT, "aud": AXIAM_AUDIENCE,
            "iat": now(), "exp": now() + 600, "scope": "partner.orders.read",
        }),
        &impostor.encoding_key(),
    )
    .unwrap();

    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(
        body["error_description"], "subject token is not valid",
        "which check refused is a map of our validation order; it stays off the wire"
    );
}

#[actix_web::test]
async fn a_token_addressed_to_someone_else_is_refused() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        c.insert("aud".into(), json!("https://someone-elses-api.example"));
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_web::test]
async fn a_multi_valued_audience_needs_only_one_match() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        c.insert(
            "aud".into(),
            json!(["https://elsewhere.example", AXIAM_AUDIENCE]),
        );
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 200, "{body:?}");
}

#[actix_web::test]
async fn a_token_older_than_the_provider_allows_is_refused() {
    let f = setup(TrustSpec {
        max_token_age_secs: 60,
        ..Default::default()
    })
    .await;
    let app = test_app!(f);
    // Still valid by `exp` — 10 minutes of life left — but issued 5 minutes
    // ago, which this provider does not accept. The two bounds are separate
    // policies and this proves the age one bites on its own.
    let token = partner_token(&f, |c| {
        c.insert("iat".into(), json!(now() - 300));
        c.insert("exp".into(), json!(now() + 600));
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_web::test]
async fn an_expired_partner_token_is_refused() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        c.insert("iat".into(), json!(now() - 1000));
        c.insert("exp".into(), json!(now() - 500));
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_grant");
}

/// An ID token is an assertion to a client about a login, not a credential for
/// an API — and OIDC gives it a longer, more widely distributed life for
/// exactly that reason. Correctly signed, correctly addressed, still refused.
#[actix_web::test]
async fn a_correctly_signed_id_token_is_still_refused() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        c.insert("nonce".into(), json!("n-0S6_WzA2Mj"));
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_web::test]
async fn refresh_and_id_token_types_are_refused_by_name() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});

    for ty in [TOKEN_TYPE_REFRESH_TOKEN, TOKEN_TYPE_ID_TOKEN] {
        let (status, body) = exchange!(app, f, subject_param(&token, ty));
        assert_eq!(status, 400, "{ty}");
        assert_eq!(body["error"], "invalid_request", "{ty}");
        assert_ne!(
            body["error_description"], "subject token is not valid",
            "{ty} deserves an actionable message, not a generic refusal"
        );
    }
}

#[actix_web::test]
async fn an_unlinked_subject_is_refused_under_linked_only() {
    let f = setup(TrustSpec {
        link_subject: false,
        ..Default::default()
    })
    .await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_grant");
}

#[actix_web::test]
async fn jit_provisioning_creates_the_user_when_the_provider_says_so() {
    let f = setup(TrustSpec {
        link_subject: false,
        subject_mapping: SubjectMapping::JitProvision,
        ..Default::default()
    })
    .await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));

    // The JIT-provisioned user is brand new and therefore holds no roles, so
    // the engine gate refuses it — which is itself the point worth pinning:
    // provisioning an identity is not granting it anything.
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(
        body["error"], "invalid_scope",
        "a freshly provisioned user holds no permissions, so there is nothing \
         to put in a token — but the failure is about SCOPES, not about the \
         subject being unknown"
    );
}

#[actix_web::test]
async fn a_suspended_user_is_not_resurrected_by_a_partner_token() {
    let f = setup(TrustSpec::default()).await;
    SurrealUserRepository::new(f.db.clone())
        .update(
            f.tenant_id,
            f.user_id,
            UpdateUser {
                status: Some(UserStatus::Inactive),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_grant");
}

// ===========================================================================
// Scopes
// ===========================================================================

#[actix_web::test]
async fn an_unmapped_partner_scope_contributes_nothing() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        // The partner says "admin". Nobody mapped it. It buys nothing, and
        // there is no passthrough mode that would let it.
        c.insert("scope".into(), json!("partner.admin"));
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_scope");
}

/// The engine is the authority, not the admin's map. Same map, same token —
/// the user simply does not hold the action.
#[actix_web::test]
async fn a_mapped_scope_the_user_does_not_hold_is_not_issued() {
    let f = setup(TrustSpec {
        grants: vec![],
        ..Default::default()
    })
    .await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_scope");
}

/// B1 deny-override, on the cross-domain path.
#[actix_web::test]
async fn a_deny_rule_vetoes_a_scope_a_partner_token_would_otherwise_get() {
    let f = setup(TrustSpec {
        grants: vec![("read:orders", true)],
        ..Default::default()
    })
    .await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_scope");
}

#[actix_web::test]
async fn an_explicitly_requested_unmapped_scope_is_refused_by_name() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(
        app,
        f,
        format!(
            "{}&scope=write%3Aorders",
            subject_param(&token, TOKEN_TYPE_JWT)
        )
    );
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_scope");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("write:orders"),
        "a refusal must name the scope: {body:?}"
    );
}

// ===========================================================================
// Transitivity
// ===========================================================================

/// The invariant that stops trust composing silently: A trusts B, B trusts C,
/// therefore A trusts C — which nobody configured and nobody can see.
#[actix_web::test]
async fn a_token_minted_from_a_partner_token_cannot_be_exchanged_again() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);

    let partner = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&partner, TOKEN_TYPE_JWT));
    assert_eq!(status, 200, "{body:?}");
    let minted = body["access_token"].as_str().unwrap().to_string();

    // The minted token is ours, cryptographically valid, and carries the
    // scope. It still cannot buy another one.
    let (status, body) = exchange!(app, f, subject_param(&minted, TOKEN_TYPE_ACCESS_TOKEN));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("do not compose"),
        "{body:?}"
    );
}

/// …and the other direction: a *foreign* token that carries the claim, because
/// the partner also runs AXIAM or copied the convention.
#[actix_web::test]
async fn a_partner_token_that_is_itself_an_exchange_product_is_refused() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        c.insert(
            "ext_exchange".into(),
            json!({ "iss": "https://someone-upstream.example" }),
        );
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_grant");
}

// ===========================================================================
// Lifetime and actor
// ===========================================================================

#[actix_web::test]
async fn the_issued_token_never_outlives_the_partners_token() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |c| {
        c.insert("exp".into(), json!(now() + 45));
    });
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 200, "{body:?}");
    assert!(
        body["expires_in"].as_u64().unwrap() <= 45,
        "expires_in was {}",
        body["expires_in"]
    );
}

#[actix_web::test]
async fn a_per_provider_lifetime_ceiling_is_honoured() {
    let f = setup(TrustSpec {
        max_lifetime_secs: Some(30),
        ..Default::default()
    })
    .await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 200, "{body:?}");
    assert!(body["expires_in"].as_u64().unwrap() <= 30);
}

#[actix_web::test]
async fn an_actor_token_is_refused_across_the_trust_boundary() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let token = partner_token(&f, |_| {});
    let (status, body) = exchange!(
        app,
        f,
        format!(
            "{}&actor_token=anything&actor_token_type={}",
            subject_param(&token, TOKEN_TYPE_JWT),
            enc(TOKEN_TYPE_ACCESS_TOKEN)
        )
    );
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(body["error"], "invalid_request");
}

// ===========================================================================
// JWKS rollover
// ===========================================================================

/// The partner rotates its signing key between two exchanges. The first call
/// warms the cache with the old JWKS; the second presents a token signed by a
/// key that is only in the new one, and must succeed via the forced refetch.
#[actix_web::test]
async fn a_key_rotation_mid_flight_is_recovered_by_the_forced_refetch() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);

    // Warm the JWKS cache with the original key.
    let first = partner_token(&f, |_| {});
    let (status, _) = exchange!(app, f, subject_param(&first, TOKEN_TYPE_JWT));
    assert_eq!(status, 200);

    // The IdP rotates: a new key under a new kid, served from the same URI.
    //
    // `reset()` rather than mounting a second `/jwks` mock — wiremock picks
    // the *first* matching mock, so a shadowing registration would silently
    // keep serving the old key and this test would prove nothing. Discovery is
    // re-mounted alongside it; the discovery cache is already warm, so it is
    // belt-and-braces rather than load-bearing.
    let rotated = IdpKeys::generate();
    let mut rotated_jwk = rotated.jwk.clone();
    rotated_jwk["kid"] = json!("partner-key-2");
    f._idp.reset().await;
    let issuer = f.issuer.clone();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        })))
        .mount(&f._idp)
        .await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "keys": [rotated_jwk] })))
        .mount(&f._idp)
        .await;

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("partner-key-2".into());
    header.typ = Some("at+jwt".into());
    let token = encode(
        &header,
        &json!({
            "iss": f.issuer, "sub": EXTERNAL_SUBJECT, "aud": AXIAM_AUDIENCE,
            "iat": now(), "exp": now() + 600, "scope": "partner.orders.read",
        }),
        &rotated.encoding_key(),
    )
    .unwrap();

    let (status, body) = exchange!(app, f, subject_param(&token, TOKEN_TYPE_JWT));
    assert_eq!(status, 200, "rollover must recover: {body:?}");
}

// ===========================================================================
// Regression: the internal path is untouched
// ===========================================================================

/// X4 widens which subject tokens are admissible and nothing else. An ordinary
/// AXIAM-issued token still exchanges exactly as B3 says it does.
#[actix_web::test]
async fn an_ordinary_axiam_subject_token_still_exchanges_unchanged() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);

    let subject = axiam_auth::token::issue_access_token(
        f.user_id,
        f.tenant_id,
        Uuid::new_v4(),
        &["read:orders".to_string()],
        &f.auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();

    // No actor token and no `may_impersonate` grant ⇒ B3 refuses, as it always
    // has. The value of the assertion is the error CODE: the token reached the
    // internal path rather than being sent to the external resolver.
    let (status, body) = exchange!(app, f, subject_param(&subject, TOKEN_TYPE_ACCESS_TOKEN));
    assert_eq!(status, 400, "{body:?}");
    assert_eq!(
        body["error"], "unauthorized_client",
        "an AXIAM-issued token must take the B3 path: {body:?}"
    );
}

#[actix_web::test]
async fn an_axiam_token_presented_as_the_generic_jwt_type_is_told_so() {
    let f = setup(TrustSpec::default()).await;
    let app = test_app!(f);
    let subject = axiam_auth::token::issue_access_token(
        f.user_id,
        f.tenant_id,
        Uuid::new_v4(),
        &["read:orders".to_string()],
        &f.auth,
        Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap();

    let (status, body) = exchange!(app, f, subject_param(&subject, TOKEN_TYPE_JWT));
    assert_eq!(status, 400);
    assert_eq!(body["error"], "invalid_request");
    assert!(
        body["error_description"]
            .as_str()
            .unwrap()
            .contains("external issuers"),
        "{body:?}"
    );
}

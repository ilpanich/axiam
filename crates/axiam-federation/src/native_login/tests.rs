//! G-A (#816) — native sign-in: every refusal its own named test, plus the
//! success paths and the resolution parity with the browser login.
//!
//! The fixture is a real in-memory datastore (migrated, so the replay store's
//! UNIQUE index is the real one) and a loopback stub IdP serving discovery and
//! a JWKS. Signing keys are generated per fixture at run time. No assertion
//! message interpolates a token: failures print the error variant only.

use super::*;
use axiam_core::models::federation::{
    CreateFederationConfig, FederationProtocol, NativeLoginTrust, ProviderKind,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{UpdateUser, UserStatus};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, OrganizationRepository, TenantRepository,
    UserRepository,
};
use axiam_db::{
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealOrganizationRepository, SurrealProviderIdTokenReplayRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::signature::KeyPair;
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::jwks_cache::JwksCache;

type Svc = OidcFederationService<
    SurrealFederationConfigRepository<Db>,
    SurrealFederationLinkRepository<Db>,
    SurrealUserRepository<Db>,
>;

const IOS: &str = "com.example.ios";
const ANDROID: &str = "android-client.apps.example";
const WEB: &str = "web-client";
const SLUG: &str = "acme-idp";

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

// ---------------------------------------------------------------------------
// Keys and tokens, generated at run time
// ---------------------------------------------------------------------------

/// An Ed25519 signing key generated for this run, and its JWK.
struct TestKey {
    kid: String,
    pkcs8: Vec<u8>,
    x: String,
}

impl TestKey {
    fn generate(kid: &str) -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("keygen");
        let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
        Self {
            kid: kid.to_owned(),
            x: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pair.public_key().as_ref()),
            pkcs8: pkcs8.as_ref().to_vec(),
        }
    }

    fn jwk(&self) -> Value {
        json!({ "kty": "OKP", "crv": "Ed25519", "kid": self.kid, "use": "sig", "x": self.x })
    }

    fn header(&self) -> Header {
        let mut h = Header::new(Algorithm::EdDSA);
        h.kid = Some(self.kid.clone());
        h
    }

    fn sign_with(&self, header: &Header, claims: &Value) -> String {
        encode(header, claims, &EncodingKey::from_ed_der(&self.pkcs8)).expect("sign")
    }

    fn sign(&self, claims: &Value) -> String {
        self.sign_with(&self.header(), claims)
    }
}

/// A loopback stub IdP: discovery and a JWKS, from a mock server.
struct Idp {
    server: MockServer,
    key: TestKey,
}

impl Idp {
    async fn start() -> Self {
        let idp = Self {
            server: MockServer::start().await,
            key: TestKey::generate("k1"),
        };
        idp.mount_discovery().await;
        idp
    }

    async fn mount_discovery(&self) {
        let base = self.server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "issuer": base,
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "jwks_uri": format!("{base}/jwks"),
            })))
            .mount(&self.server)
            .await;
    }

    /// Serve this JWKS from now on.
    async fn serve_jwks(&self, keys: &[&TestKey]) {
        let body = json!({ "keys": keys.iter().map(|k| k.jwk()).collect::<Vec<_>>() });
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.server)
            .await;
    }

    fn issuer(&self) -> String {
        self.server.uri()
    }

    fn metadata_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.server.uri())
    }

    async fn jwks_hits(&self) -> usize {
        self.server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path() == "/jwks")
            .count()
    }
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fx {
    db: Surreal<Db>,
    svc: Svc,
    tenants: SurrealTenantRepository<Db>,
    replay: SurrealProviderIdTokenReplayRepository<Db>,
    org_id: Uuid,
    org_tenant_id: Uuid,
    tenant_id: Uuid,
    idp: Idp,
    /// A generic OIDC provider in `tenant_id`, slug `acme-idp`, native sign-in
    /// on for the iOS and Android client IDs, EdDSA only.
    provider_id: Uuid,
    nonce: String,
}

fn native(client_ids: &[&str]) -> NativeLoginTrust {
    NativeLoginTrust {
        enabled: true,
        client_ids: client_ids.iter().map(|s| (*s).to_owned()).collect(),
        max_token_age_secs: 300,
    }
}

impl Fx {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();

        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Org".into(),
                slug: format!("org-{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap();
        let tenants = SurrealTenantRepository::new(db.clone());
        let org_tenant = tenants
            .create(CreateTenant::organization_scope(org.id))
            .await
            .unwrap();
        let tenant = tenants
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "Tenant".into(),
                slug: "tenant-a".into(),
                metadata: None,
            })
            .await
            .unwrap();

        let idp = Idp::start().await;
        idp.serve_jwks(&[&idp.key]).await;

        let svc = OidcFederationService::new(
            SurrealFederationConfigRepository::new(db.clone()),
            SurrealFederationLinkRepository::new(db.clone()),
            SurrealUserRepository::new(db.clone()),
            reqwest::Client::new(),
            Arc::new(JwksCache::new_allow_private_networks()),
            [0u8; 32], // gitleaks:allow
        );

        let mut fx = Self {
            db: db.clone(),
            svc,
            tenants,
            replay: SurrealProviderIdTokenReplayRepository::new(db),
            org_id: org.id,
            org_tenant_id: org_tenant.id,
            tenant_id: tenant.id,
            idp,
            provider_id: Uuid::nil(),
            nonce: Uuid::new_v4().to_string(),
        };
        fx.provider_id = fx
            .provider(fx.tenant_id, |c| {
                c.provider_slug = Some(SLUG.into());
            })
            .await;
        fx
    }

    /// Create an OIDC provider pointing at the stub IdP, native sign-in on;
    /// `tweak` adjusts it before the write.
    async fn provider(
        &self,
        tenant_id: Uuid,
        tweak: impl FnOnce(&mut CreateFederationConfig),
    ) -> Uuid {
        let mut c = CreateFederationConfig {
            tenant_id,
            provider: "Acme".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some(self.idp.metadata_url()),
            client_id: WEB.into(),
            client_secret: "web-secret".into(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: Some(vec!["EdDSA".into()]),
            native_login: Some(native(&[IOS, ANDROID])),
            token_exchange: None,
            provider_kind: Some(ProviderKind::GenericOidc),
            provider_slug: None,
            allow_tenant_inheritance: None,
            scopes: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            allowed_issuer_tenants: None,
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: None,
            button_icon: None,
            allow_sha1_signatures: None,
            idp_metadata_signing_cert_pem: None,
        };
        tweak(&mut c);
        SurrealFederationConfigRepository::new(self.db.clone())
            .create(c)
            .await
            .unwrap()
            .id
    }

    /// A well-formed native ID token's claims: issued to the iOS app, now,
    /// bound to the fixture's nonce the way D-N16 requires — the claim is the
    /// SHA-256 hex of the raw nonce the request carries.
    fn claims(&self) -> Value {
        json!({
            "iss": self.idp.issuer(),
            "aud": IOS,
            "sub": "user-1",
            "iat": now(),
            "exp": now() + 600,
            "nonce": sha256_hex(&self.nonce),
            "email": "ada@example.com",
            "email_verified": true,
            "name": "Ada",
        })
    }

    /// The fixture's claims with `patch` applied (`null` removes a claim).
    fn claims_with(&self, patch: Value) -> Value {
        let mut c = self.claims();
        for (k, v) in patch.as_object().unwrap() {
            if v.is_null() {
                c.as_object_mut().unwrap().remove(k);
            } else {
                c[k] = v.clone();
            }
        }
        c
    }

    fn token(&self, patch: Value) -> String {
        self.idp.key.sign(&self.claims_with(patch))
    }

    async fn sign_in_as(
        &self,
        tenant_id: Uuid,
        provider: &str,
        token: &str,
        nonce: &str,
    ) -> Result<NativeSubject, NativeLoginError> {
        let request = NativeIdTokenRequest {
            provider,
            id_token: token,
            nonce,
        };
        self.svc
            .verify_native_id_token(&self.tenants, &self.replay, tenant_id, &request, now())
            .await
    }

    async fn sign_in(&self, token: &str) -> Result<NativeSubject, NativeLoginError> {
        self.sign_in_as(
            self.tenant_id,
            &self.provider_id.to_string(),
            token,
            &self.nonce,
        )
        .await
    }

    async fn update_provider(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        update: axiam_core::models::federation::UpdateFederationConfig,
    ) {
        SurrealFederationConfigRepository::new(self.db.clone())
            .update(tenant_id, id, update)
            .await
            .unwrap();
    }
}

/// Assert a refusal, printing the variant — never the token.
#[track_caller]
fn refused(result: Result<NativeSubject, NativeLoginError>, want: NativeLoginError) {
    match result {
        Ok(_) => panic!("expected refusal {}, got a sign-in", want.reason_code()),
        Err(got) => assert_eq!(got, want, "wrong refusal"),
    }
}

/// Assert a refusal by reason code, for variants carrying a detail string.
#[track_caller]
fn refused_as(result: Result<NativeSubject, NativeLoginError>, code: &str) {
    match result {
        Ok(_) => panic!("expected refusal {code}, got a sign-in"),
        Err(got) => assert_eq!(got.reason_code(), code, "wrong refusal: {got}"),
    }
}

// ---------------------------------------------------------------------------
// Success
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_valid_native_id_token_signs_in_and_provisions_on_first_sight() {
    let fx = Fx::new().await;
    let subject = fx.sign_in(&fx.token(json!({}))).await.expect("sign-in");

    assert!(subject.newly_provisioned);
    assert_eq!(subject.tenant_id, fx.tenant_id);
    assert_eq!(subject.provider_id, fx.provider_id);
    assert_eq!(subject.provider_tenant_id, fx.tenant_id);
    assert!(!subject.inherited);
    assert_eq!(subject.audience, IOS);
    assert_eq!(subject.external_subject, "user-1");
    assert_eq!(subject.issuer, fx.idp.issuer());

    let user = SurrealUserRepository::new(fx.db.clone())
        .get_by_id(fx.tenant_id, subject.user_id)
        .await
        .unwrap();
    assert_eq!(user.email, "ada@example.com");
}

#[tokio::test]
async fn the_provider_may_be_named_by_its_slug() {
    let fx = Fx::new().await;
    let token = fx.token(json!({}));
    let subject = fx
        .sign_in_as(fx.tenant_id, SLUG, &token, &fx.nonce)
        .await
        .expect("sign-in by slug");
    assert_eq!(subject.provider_id, fx.provider_id);
}

/// D-N16: the app hands the SDK the SHA-256 hex of its nonce, the ID token
/// carries that, and the request carries the raw value.
#[tokio::test]
async fn nonce_matching_the_sha256_hex_of_the_request_nonce_is_accepted() {
    let fx = Fx::new().await;
    let token = fx.token(json!({ "nonce": sha256_hex(&fx.nonce) }));
    fx.sign_in(&token).await.expect("hashed nonce");
}

/// F4-W2-02 — the raw form is refused: a claim equal to the request's nonce
/// is what a token's holder could always send, by reading the claim. The
/// refusal spends nothing.
#[tokio::test]
async fn a_raw_nonce_equal_to_the_claim_is_refused() {
    let fx = Fx::new().await;
    let token = fx.token(json!({ "nonce": fx.nonce }));
    refused(fx.sign_in(&token).await, NativeLoginError::NonceMismatch);
}

/// F4-W2-02, the review's probe kept as a test: a presenter who holds only a
/// leaked token reads its `nonce` claim from the payload and sends it as the
/// nonce. Refused, and the genuine app's presentation still signs in — the
/// token was not spent by the attempt.
#[tokio::test]
async fn a_presenter_who_copies_the_nonce_claim_is_refused() {
    let fx = Fx::new().await;
    let token = fx.token(json!({}));
    let payload = token.split('.').nth(1).expect("a JWS");
    let claims: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("base64url"),
    )
    .expect("json");
    let copied = claims["nonce"].as_str().expect("a nonce claim").to_owned();
    assert_ne!(
        copied, fx.nonce,
        "the token carries the hash, not the raw nonce"
    );

    refused(
        fx.sign_in_as(fx.tenant_id, &fx.provider_id.to_string(), &token, &copied)
            .await,
        NativeLoginError::NonceMismatch,
    );
    fx.sign_in(&token)
        .await
        .expect("the genuine presentation still signs in");
}

/// D-N17 — Google's Android shape: `aud` is the provider's web (server)
/// client, `azp` the listed Android client. Issued to the `azp`.
#[tokio::test]
async fn the_android_shape_signs_in_as_its_azp() {
    let fx = Fx::new().await;
    let token = fx.token(json!({ "aud": WEB, "azp": ANDROID }));
    let subject = fx.sign_in(&token).await.expect("android shape");
    assert_eq!(subject.audience, ANDROID);
}

/// D-N17 — the iOS shape without a server client: one listed `aud`, no `azp`
/// (and the same with an `azp` naming the same client).
#[tokio::test]
async fn the_ios_shape_signs_in_as_its_aud() {
    let fx = Fx::new().await;
    let subject = fx
        .sign_in(&fx.token(json!({ "aud": IOS })))
        .await
        .expect("ios shape");
    assert_eq!(subject.audience, IOS);
    let subject = fx
        .sign_in(&fx.token(
            json!({ "aud": IOS, "azp": IOS, "sub": "user-2", "email": "user-2@example.com" }),
        ))
        .await
        .expect("ios shape with azp");
    assert_eq!(subject.audience, IOS);
}

/// D-N17 — a token from the provider's browser flow is issued to the web
/// client (`azp` the web client, or absent), which is not listed: refused,
/// although the web client is the provider's own.
#[tokio::test]
async fn a_browser_flow_token_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "aud": WEB, "azp": WEB })))
            .await,
        NativeLoginError::AuthorizedPartyRefused,
    );
    refused(
        fx.sign_in(&fx.token(json!({ "aud": WEB }))).await,
        NativeLoginError::WrongAudience,
    );
}

/// D-N17 — a listed `azp` does not carry a token addressed elsewhere: `aud`
/// must name a listed ID or the provider's web client.
#[tokio::test]
async fn a_listed_azp_with_a_foreign_aud_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "aud": "another-web-client", "azp": ANDROID })))
            .await,
        NativeLoginError::WrongAudience,
    );
    // A listed `azp` with a third party's `azp`-less shape is not rescued
    // either: a foreign `azp` beside a listed `aud` is refused.
    refused(
        fx.sign_in(&fx.token(json!({ "aud": IOS, "azp": "third-party" })))
            .await,
        NativeLoginError::AuthorizedPartyRefused,
    );
}

#[tokio::test]
async fn multi_aud_with_a_listed_azp_signs_in_as_the_azp() {
    let fx = Fx::new().await;
    let token = fx.token(json!({ "aud": [WEB, ANDROID], "azp": ANDROID }));
    let subject = fx.sign_in(&token).await.expect("listed azp");
    assert_eq!(subject.audience, ANDROID);
}

/// The rollover refetch finds a key the provider rotated in since the cache
/// was filled.
#[tokio::test]
async fn a_rotated_key_is_found_by_the_rollover_refetch() {
    let fx = Fx::new().await;
    // Fill the cache with the old key.
    fx.sign_in(&fx.token(json!({ "sub": "warm-up", "email": "warm-up@example.com" })))
        .await
        .expect("old key");

    // The provider rotates: its JWKS now also publishes `k2`.
    let rotated = TestKey::generate("k2");
    fx.idp.server.reset().await;
    fx.idp.mount_discovery().await;
    fx.idp.serve_jwks(&[&fx.idp.key, &rotated]).await;

    let token = rotated.sign(&fx.claims());
    fx.sign_in(&token).await.expect("rotated key after refetch");
}

// ---------------------------------------------------------------------------
// Step 2 — provider
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_provider_of_another_tenant_is_not_found() {
    let fx = Fx::new().await;
    let other = fx
        .tenants
        .create(CreateTenant {
            organization_id: fx.org_id,
            kind: TenantKind::Standard,
            name: "Other".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let theirs = fx
        .provider(other.id, |c| c.provider_slug = Some("theirs".into()))
        .await;
    let token = fx.token(json!({}));

    refused(
        fx.sign_in_as(fx.tenant_id, &theirs.to_string(), &token, &fx.nonce)
            .await,
        NativeLoginError::ProviderNotFound,
    );
    refused(
        fx.sign_in_as(fx.tenant_id, "theirs", &token, &fx.nonce)
            .await,
        NativeLoginError::ProviderNotFound,
    );
}

#[tokio::test]
async fn a_disabled_provider_is_not_found() {
    let fx = Fx::new().await;
    fx.update_provider(
        fx.tenant_id,
        fx.provider_id,
        axiam_core::models::federation::UpdateFederationConfig {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await;
    refused(
        fx.sign_in(&fx.token(json!({}))).await,
        NativeLoginError::ProviderNotFound,
    );
}

#[tokio::test]
async fn a_provider_with_native_login_disabled_is_not_found() {
    let fx = Fx::new().await;
    let off = fx
        .provider(fx.tenant_id, |c| {
            c.provider_slug = Some("off".into());
            c.native_login = None;
        })
        .await;
    let token = fx.token(json!({}));
    refused(
        fx.sign_in_as(fx.tenant_id, &off.to_string(), &token, &fx.nonce)
            .await,
        NativeLoginError::ProviderNotFound,
    );
}

/// The write path refuses an enabled block on SAML; a row that has one anyway
/// (written past that path) is still not a native sign-in provider.
#[tokio::test]
async fn a_saml_provider_is_not_found() {
    let fx = Fx::new().await;
    let saml = fx
        .provider(fx.tenant_id, |c| {
            c.protocol = FederationProtocol::Saml;
            c.provider_kind = Some(ProviderKind::GenericSaml);
            c.provider_slug = Some("saml".into());
        })
        .await;
    let token = fx.token(json!({}));
    refused(
        fx.sign_in_as(fx.tenant_id, &saml.to_string(), &token, &fx.nonce)
            .await,
        NativeLoginError::ProviderNotFound,
    );
}

#[tokio::test]
async fn an_oauth2_protocol_provider_is_not_found() {
    let fx = Fx::new().await;
    let oauth2 = fx
        .provider(fx.tenant_id, |c| {
            c.protocol = FederationProtocol::OAuth2;
            c.provider_kind = Some(ProviderKind::GenericOauth2);
            c.provider_slug = Some("oauth2".into());
        })
        .await;
    let token = fx.token(json!({}));
    refused(
        fx.sign_in_as(fx.tenant_id, &oauth2.to_string(), &token, &fx.nonce)
            .await,
        NativeLoginError::ProviderNotFound,
    );
}

#[tokio::test]
async fn an_unknown_provider_is_not_found() {
    let fx = Fx::new().await;
    let token = fx.token(json!({}));
    for name in [Uuid::new_v4().to_string(), "nobody".into(), "  ".into()] {
        refused(
            fx.sign_in_as(fx.tenant_id, &name, &token, &fx.nonce).await,
            NativeLoginError::ProviderNotFound,
        );
    }
}

/// An organization provider a tenant inherits signs in to that tenant, and its
/// token is spent once across the organization, not once per tenant.
#[tokio::test]
async fn an_inherited_provider_signs_in_and_its_token_is_single_use_across_tenants() {
    let fx = Fx::new().await;
    let org_provider = fx
        .provider(fx.org_tenant_id, |c| {
            c.provider_kind = Some(ProviderKind::Google);
            c.allow_tenant_inheritance = Some(true);
        })
        .await;
    let sibling = fx
        .tenants
        .create(CreateTenant {
            organization_id: fx.org_id,
            kind: TenantKind::Standard,
            name: "Sibling".into(),
            slug: "tenant-c".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let token = fx.token(json!({}));
    let id = org_provider.to_string();

    let subject = fx
        .sign_in_as(fx.tenant_id, &id, &token, &fx.nonce)
        .await
        .expect("inherited provider");
    assert!(subject.inherited);
    assert_eq!(subject.provider_tenant_id, fx.org_tenant_id);
    assert_eq!(subject.tenant_id, fx.tenant_id);

    refused(
        fx.sign_in_as(sibling.id, &id, &token, &fx.nonce).await,
        NativeLoginError::Replayed,
    );
}

// ---------------------------------------------------------------------------
// Step 3 — header
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alg_none_is_refused() {
    let fx = Fx::new().await;
    let b64 = |v: &Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    let token = format!(
        "{}.{}.",
        b64(&json!({ "alg": "none", "kid": "k1" })),
        b64(&fx.claims())
    );
    refused(fx.sign_in(&token).await, NativeLoginError::AlgorithmRefused);
}

#[tokio::test]
async fn an_alg_outside_the_allowed_list_is_refused() {
    let fx = Fx::new().await;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("k1".into());
    let token = encode(
        &header,
        &fx.claims(),
        &EncodingKey::from_secret(Uuid::new_v4().as_bytes()),
    )
    .unwrap();
    refused(fx.sign_in(&token).await, NativeLoginError::AlgorithmRefused);
}

/// An unknown `kid` costs exactly one refetch of the JWKS (the rollover rule),
/// then refuses; a second try inside the refetch window costs none.
#[tokio::test]
async fn an_unknown_kid_after_jwks_rollover_is_refused_after_one_refetch() {
    let fx = Fx::new().await;
    let stranger = TestKey::generate("k-unknown");
    let token = stranger.sign(&fx.claims());

    refused(fx.sign_in(&token).await, NativeLoginError::UnknownKey);
    assert_eq!(
        fx.idp.jwks_hits().await,
        2,
        "one fetch, one rollover refetch"
    );

    refused(fx.sign_in(&token).await, NativeLoginError::UnknownKey);
    assert_eq!(fx.idp.jwks_hits().await, 2, "the refetch is rate-limited");
}

// ---------------------------------------------------------------------------
// Step 4 — signature and claims
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_bad_signature_is_refused() {
    let fx = Fx::new().await;
    // Another key under the same `kid`.
    let impostor = TestKey::generate("k1");
    refused(
        fx.sign_in(&impostor.sign(&fx.claims())).await,
        NativeLoginError::BadSignature,
    );
}

#[tokio::test]
async fn a_wrong_iss_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "iss": "https://other.example" })))
            .await,
        NativeLoginError::WrongIssuer,
    );
}

#[tokio::test]
async fn a_wrong_aud_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "aud": "com.someone.else" })))
            .await,
        NativeLoginError::WrongAudience,
    );
}

/// Deny by default: the provider's web `client_id` is never the party a token
/// was issued to unless it is listed. Listing it — which the docs advise
/// against — admits the browser flow's tokens (`aud` the web client, `azp`
/// the web client or absent), exactly as configured; this pins that
/// behaviour so a change to it is a decision, not an accident.
#[tokio::test]
async fn the_web_client_id_is_refused_unless_listed() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "aud": WEB }))).await,
        NativeLoginError::WrongAudience,
    );
    refused(
        fx.sign_in(&fx.token(json!({ "aud": WEB, "azp": WEB })))
            .await,
        NativeLoginError::AuthorizedPartyRefused,
    );

    fx.update_provider(
        fx.tenant_id,
        fx.provider_id,
        axiam_core::models::federation::UpdateFederationConfig {
            native_login: Some(native(&[IOS, WEB])),
            ..Default::default()
        },
    )
    .await;
    fx.sign_in(&fx.token(json!({ "aud": WEB })))
        .await
        .expect("listed web client id");
    fx.sign_in(
        &fx.token(
            json!({ "aud": WEB, "azp": WEB, "sub": "user-2", "email": "user-2@example.com" }),
        ),
    )
    .await
    .expect("listed web client id, browser-flow shape");
}

#[tokio::test]
async fn multi_aud_without_azp_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "aud": [IOS, "third-party"] })))
            .await,
        NativeLoginError::AuthorizedPartyRefused,
    );
}

#[tokio::test]
async fn multi_aud_with_an_unlisted_azp_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "aud": [IOS, "third-party"], "azp": "third-party" })))
            .await,
        NativeLoginError::AuthorizedPartyRefused,
    );
}

#[tokio::test]
async fn a_stale_iat_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "iat": now() - 301 }))).await,
        NativeLoginError::TooOld,
    );
}

#[tokio::test]
async fn a_future_iat_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "iat": now() + 120 }))).await,
        NativeLoginError::IssuedInFuture,
    );
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "iat": now() - 200, "exp": now() - 120 })))
            .await,
        NativeLoginError::Expired,
    );
}

// ---------------------------------------------------------------------------
// Step 5 — shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_nonce_is_refused() {
    let fx = Fx::new().await;
    refused(
        fx.sign_in(&fx.token(json!({ "nonce": null }))).await,
        NativeLoginError::NonceMissing,
    );
}

#[tokio::test]
async fn a_mismatched_nonce_is_refused() {
    let fx = Fx::new().await;
    let token = fx.token(json!({ "nonce": Uuid::new_v4().to_string() }));
    refused(fx.sign_in(&token).await, NativeLoginError::NonceMismatch);
    // The SHA-256 form of some other nonce is a mismatch too.
    let token = fx.token(json!({ "nonce": sha256_hex("another") }));
    refused(fx.sign_in(&token).await, NativeLoginError::NonceMismatch);
    // And a request that carries no nonce matches nothing.
    let token = fx.token(json!({}));
    refused(
        fx.sign_in_as(fx.tenant_id, &fx.provider_id.to_string(), &token, "")
            .await,
        NativeLoginError::NonceMismatch,
    );
}

/// An RFC 9068 access token — `typ: at+jwt`, no nonce — is not an ID token,
/// however well signed and addressed.
#[tokio::test]
async fn an_access_token_shape_is_refused() {
    let fx = Fx::new().await;
    let mut header = fx.idp.key.header();
    header.typ = Some("at+jwt".into());
    let token = fx
        .idp
        .key
        .sign_with(&header, &fx.claims_with(json!({ "nonce": null })));
    refused_as(fx.sign_in(&token).await, "wrong_token_shape");

    // The type in a claim is read too, even with a nonce present.
    let token = fx.token(json!({ "typ": "application/at+jwt" }));
    refused_as(fx.sign_in(&token).await, "wrong_token_shape");

    // And an access-token-shaped JWT with no `typ` at all fails on the nonce.
    let token = fx.token(json!({ "nonce": null, "scope": "openid" }));
    refused(fx.sign_in(&token).await, NativeLoginError::NonceMissing);
}

// ---------------------------------------------------------------------------
// Step 6 — replay
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_replayed_token_is_refused() {
    let fx = Fx::new().await;
    let token = fx.token(json!({}));
    fx.sign_in(&token).await.expect("first presentation");
    refused(fx.sign_in(&token).await, NativeLoginError::Replayed);
}

/// A token that failed the nonce check spends nothing: whoever presented it
/// without the nonce cannot burn it for the app that holds both.
#[tokio::test]
async fn a_refused_presentation_does_not_spend_the_token() {
    let fx = Fx::new().await;
    let token = fx.token(json!({}));
    refused(
        fx.sign_in_as(fx.tenant_id, &fx.provider_id.to_string(), &token, "guess")
            .await,
        NativeLoginError::NonceMismatch,
    );
    fx.sign_in(&token)
        .await
        .expect("the genuine presentation still signs in");
}

/// A replay store that cannot record refuses — and refuses before any user is
/// resolved.
struct BrokenReplayStore;
impl ProviderIdTokenReplayRepository for BrokenReplayStore {
    async fn insert_id_token(
        &self,
        _: Uuid,
        _: Uuid,
        _: &str,
        _: chrono::DateTime<chrono::Utc>,
    ) -> axiam_core::error::AxiamResult<()> {
        Err(AxiamError::Database("replay store down".into()))
    }
    async fn cleanup_expired(&self) -> axiam_core::error::AxiamResult<u64> {
        Ok(0)
    }
}

#[tokio::test]
async fn an_unavailable_replay_guard_refuses() {
    let fx = Fx::new().await;
    let token = fx.token(json!({}));
    let request = NativeIdTokenRequest {
        provider: SLUG,
        id_token: &token,
        nonce: &fx.nonce,
    };
    let err = fx
        .svc
        .verify_native_id_token(
            &fx.tenants,
            &BrokenReplayStore,
            fx.tenant_id,
            &request,
            now(),
        )
        .await
        .expect_err("a guard that cannot record must not accept");
    assert_eq!(err.reason_code(), "replay_guard_unavailable");
    assert_eq!(err.refusal(), NativeLoginRefusal::ServerError);

    let link = SurrealFederationLinkRepository::new(fx.db.clone())
        .get_by_external_subject(fx.tenant_id, fx.provider_id, "user-1")
        .await;
    assert!(
        matches!(link, Err(AxiamError::NotFound { .. })),
        "no user was provisioned"
    );
}

// ---------------------------------------------------------------------------
// Step 7 — subject resolution (D-N11: exactly the browser login's)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_existing_link_resolves_to_the_same_user() {
    let fx = Fx::new().await;
    let first = fx.sign_in(&fx.token(json!({}))).await.expect("first");
    // A fresh token for the same subject (different `iat`, so different bytes).
    let second = fx
        .sign_in(&fx.token(json!({ "iat": now() - 1, "name": "Ada L." })))
        .await
        .expect("second");
    assert!(first.newly_provisioned);
    assert!(!second.newly_provisioned);
    assert_eq!(first.user_id, second.user_id);
}

/// As in the browser OIDC login: an unverified email does not refuse the
/// sign-in, and it is never recorded as verified.
#[tokio::test]
async fn an_unverified_email_provisions_as_the_browser_does_and_stays_unverified() {
    let fx = Fx::new().await;
    let subject = fx
        .sign_in(&fx.token(json!({ "email_verified": false })))
        .await
        .expect("JIT under the browser's rule");
    assert!(subject.newly_provisioned);
    let user = SurrealUserRepository::new(fx.db.clone())
        .get_by_id(fx.tenant_id, subject.user_id)
        .await
        .unwrap();
    assert!(user.email_verified_at.is_none(), "never marked verified");
}

#[tokio::test]
async fn a_token_the_attribute_map_finds_no_subject_in_is_refused() {
    let fx = Fx::new().await;
    fx.update_provider(
        fx.tenant_id,
        fx.provider_id,
        axiam_core::models::federation::UpdateFederationConfig {
            attribute_map: Some(json!({ "external_subject": "employee_id" })),
            ..Default::default()
        },
    )
    .await;
    refused(
        fx.sign_in(&fx.token(json!({}))).await,
        NativeLoginError::SubjectUnmapped,
    );
}

#[tokio::test]
async fn an_account_that_may_not_act_is_refused() {
    let fx = Fx::new().await;
    let first = fx.sign_in(&fx.token(json!({}))).await.expect("first");
    SurrealUserRepository::new(fx.db.clone())
        .update(
            fx.tenant_id,
            first.user_id,
            UpdateUser {
                status: Some(UserStatus::Locked),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    refused_as(
        fx.sign_in(&fx.token(json!({ "iat": now() - 1 }))).await,
        "account_refused",
    );
}

/// D-N11: a native sign-in and a browser login with the same claims are the
/// same AXIAM user — on a provider whose `attribute_map` keys the subject on a
/// claim other than `sub`, which `provision_or_link_user` (standard mapping)
/// would not honour.
#[tokio::test]
async fn a_native_sign_in_and_a_browser_login_resolve_the_same_user() {
    let fx = Fx::new().await;
    fx.update_provider(
        fx.tenant_id,
        fx.provider_id,
        axiam_core::models::federation::UpdateFederationConfig {
            attribute_map: Some(json!({ "external_subject": "employee_id" })),
            ..Default::default()
        },
    )
    .await;

    // The browser login: code exchange at the stub IdP, ID token for the web
    // client, bound to the server-side nonce.
    let browser_nonce = Uuid::new_v4().to_string();
    let browser_token = fx.idp.key.sign(&fx.claims_with(json!({
        "aud": WEB,
        "sub": "rotating-1",
        "employee_id": "E-42",
        "nonce": browser_nonce,
    })));
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "opaque",
            "id_token": browser_token,
            "token_type": "Bearer",
        })))
        .mount(&fx.idp.server)
        .await;
    let config = SurrealFederationConfigRepository::new(fx.db.clone())
        .get_by_id(fx.tenant_id, fx.provider_id)
        .await
        .unwrap();
    let browser = fx
        .svc
        .handle_callback_for(
            &config,
            fx.tenant_id,
            "code",
            "https://rp.example/cb",
            &browser_nonce,
            None,
            None,
        )
        .await
        .expect("browser login");

    // The native sign-in: another `sub`, the same mapped subject.
    let native_subject = fx
        .sign_in(&fx.token(json!({ "sub": "rotating-2", "employee_id": "E-42" })))
        .await
        .expect("native sign-in");

    assert_eq!(native_subject.user_id, browser.user.id);
    assert!(!native_subject.newly_provisioned);
    assert_eq!(native_subject.external_subject, "E-42");
}

// ---------------------------------------------------------------------------
// The shared marker list (X4 and native sign-in)
// ---------------------------------------------------------------------------

/// One list, read in opposite directions: X4 refuses every ID-token marker
/// and type; native sign-in requires the nonce marker and refuses the
/// access-token type X4 accepts.
#[test]
fn native_requires_a_marker_x4_refuses() {
    assert!(token_shape::ID_TOKEN_ONLY_CLAIMS.contains(&REQUIRED_MARKER));

    let base = json!({ "sub": "s", "iss": "i", "aud": "a", "exp": 0, "iat": 0 });
    assert!(
        !crate::token_exchange::kind_check_refuses(base.clone(), Some("at+jwt")),
        "X4 accepts the access-token shape"
    );
    for marker in token_shape::ID_TOKEN_ONLY_CLAIMS {
        let mut c = base.clone();
        c[marker] = json!("v");
        assert!(
            crate::token_exchange::kind_check_refuses(c, None),
            "X4 refuses {marker}"
        );
    }
    for typ in token_shape::ID_TOKEN_TYPES {
        assert!(crate::token_exchange::kind_check_refuses(
            base.clone(),
            Some(typ)
        ));
        let with_nonce = json!({ "nonce": sha256_hex("n") });
        assert!(
            check_shape(Some(typ), &with_nonce, "n").is_ok(),
            "native accepts the ID-token type {typ}"
        );
    }

    assert_eq!(
        check_shape(None, &json!({}), "n"),
        Err(NativeLoginError::NonceMissing),
        "native requires the marker"
    );
    for typ in token_shape::ACCESS_TOKEN_TYPES
        .iter()
        .chain(&token_shape::NEITHER_ACCESS_NOR_ID_TYPES)
    {
        assert!(matches!(
            check_shape(Some(typ), &json!({ "nonce": "n" }), "n"),
            Err(NativeLoginError::WrongTokenShape(_))
        ));
    }
}

// ---------------------------------------------------------------------------
// Pure rules and the error surface
// ---------------------------------------------------------------------------

#[test]
fn the_iat_bounds_are_inclusive_and_the_future_has_the_leeway() {
    assert_eq!(check_iat(Some(1_000), 1_300, 300), Ok(()));
    assert_eq!(
        check_iat(Some(1_000), 1_301, 300),
        Err(NativeLoginError::TooOld)
    );
    assert_eq!(check_iat(Some(1_060), 1_000, 300), Ok(()));
    assert_eq!(
        check_iat(Some(1_061), 1_000, 300),
        Err(NativeLoginError::IssuedInFuture)
    );
    assert!(matches!(
        check_iat(None, 1_000, 300),
        Err(NativeLoginError::ClaimRejected(_))
    ));
}

/// D-N17, the pure rule: the issued-to party is the `azp` when present,
/// otherwise the single `aud`, and it must be listed.
#[test]
fn the_audience_rule_is_azp_first() {
    let ids = vec![IOS.to_owned(), ANDROID.to_owned()];
    let rule = |aud: Value, azp: Option<Value>| issued_to(&ids, WEB, Some(&aud), azp.as_ref());
    // No azp: one listed audience.
    assert_eq!(rule(json!(IOS), None), Ok(IOS.to_owned()));
    assert_eq!(rule(json!([IOS]), None), Ok(IOS.to_owned()));
    assert_eq!(rule(json!(WEB), None), Err(NativeLoginError::WrongAudience));
    assert_eq!(
        rule(json!([IOS, ANDROID]), None),
        Err(NativeLoginError::AuthorizedPartyRefused),
        "several audiences need an azp, even when all are listed"
    );
    // An azp: it must be listed, and is the answer.
    assert_eq!(
        rule(json!(WEB), Some(json!(ANDROID))),
        Ok(ANDROID.to_owned())
    );
    assert_eq!(rule(json!(IOS), Some(json!(IOS))), Ok(IOS.to_owned()));
    assert_eq!(
        rule(json!([WEB, "x"]), Some(json!(ANDROID))),
        Ok(ANDROID.to_owned())
    );
    assert_eq!(
        rule(json!(IOS), Some(json!("anything"))),
        Err(NativeLoginError::AuthorizedPartyRefused),
        "an unlisted azp is refused even beside a listed aud"
    );
    assert_eq!(
        rule(json!(WEB), Some(json!(WEB))),
        Err(NativeLoginError::AuthorizedPartyRefused),
        "a browser-flow token"
    );
    assert_eq!(
        rule(json!([IOS, "x"]), Some(json!(42))),
        Err(NativeLoginError::AuthorizedPartyRefused)
    );
    // A listed azp does not carry an audience that is neither listed nor the
    // provider's web client.
    assert_eq!(
        rule(json!(["x", "y"]), Some(json!(IOS))),
        Err(NativeLoginError::WrongAudience),
        "azp cannot stand in for an audience"
    );
    // No configured web client: nothing matches it.
    assert_eq!(
        issued_to(&ids, "", Some(&json!("")), Some(&json!(ANDROID))),
        Err(NativeLoginError::WrongAudience)
    );
    assert_eq!(
        issued_to(&ids, WEB, None, None),
        Err(NativeLoginError::WrongAudience)
    );
}

/// Every refusal is `invalid_grant` on the wire except a datastore failure;
/// the reason codes are stable, distinct and carry no detail.
#[test]
fn every_refusal_is_generic_on_the_wire_and_distinct_in_the_log() {
    let all = [
        NativeLoginError::ProviderNotFound,
        NativeLoginError::ProviderUnavailable("datastore down".into()),
        NativeLoginError::AlgorithmRefused,
        NativeLoginError::UnknownKey,
        NativeLoginError::KeysUnavailable("datastore down".into()),
        NativeLoginError::BadSignature,
        NativeLoginError::WrongIssuer,
        NativeLoginError::WrongAudience,
        NativeLoginError::AuthorizedPartyRefused,
        NativeLoginError::Expired,
        NativeLoginError::TooOld,
        NativeLoginError::IssuedInFuture,
        NativeLoginError::ClaimRejected("datastore down".into()),
        NativeLoginError::WrongTokenShape("datastore down".into()),
        NativeLoginError::NonceMissing,
        NativeLoginError::NonceMismatch,
        NativeLoginError::Replayed,
        NativeLoginError::ReplayGuardUnavailable("datastore down".into()),
        NativeLoginError::SubjectUnmapped,
        NativeLoginError::AccountRefused("datastore down".into()),
        NativeLoginError::Server("datastore down".into()),
    ];
    let mut codes = std::collections::BTreeSet::new();
    for e in &all {
        assert!(codes.insert(e.reason_code()), "duplicate reason code");
        assert!(!e.reason_code().contains(' '));
        let server = matches!(
            e,
            NativeLoginError::ReplayGuardUnavailable(_) | NativeLoginError::Server(_)
        );
        assert_eq!(
            e.refusal(),
            if server {
                NativeLoginRefusal::ServerError
            } else {
                NativeLoginRefusal::InvalidGrant
            }
        );
        assert!(e.to_string().len() > 10, "a diagnosable message");
    }
    assert!(!PUBLIC_REFUSAL_DESCRIPTION.contains("nonce"));
}

/// The request's `Debug` never prints the token or the nonce.
#[test]
fn a_request_debug_prints_neither_token_nor_nonce() {
    let token = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let shown = format!(
        "{:?}",
        NativeIdTokenRequest {
            provider: SLUG,
            id_token: &token,
            nonce: &nonce,
        }
    );
    assert!(shown.contains(SLUG));
    assert!(!shown.contains(&token) && !shown.contains(&nonce));
}

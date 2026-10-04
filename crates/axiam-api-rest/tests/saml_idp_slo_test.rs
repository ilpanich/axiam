//! **T23.2.4** — the SAML 2.0 IdP's single-logout endpoint over HTTP (G-2).
//!
//! Every acceptance row of the task, driven through the real routes, the real
//! login endpoint, the real SSO endpoint (which writes the participant rows) and
//! the real repositories:
//!
//! * an SP-initiated logout on both bindings revokes the AXIAM session — the
//!   session and OP cookie are refused afterwards, and `GET /oauth2/revocations`
//!   shows it — and back-channel logout reaches the OIDC RPs bound to it;
//! * only the sessions the SP participates in, only when the `NameID` matches;
//!   no match answers `Success`;
//! * unsigned, wrong-key, tampered and SHA-1-signed messages on both bindings, a
//!   signature in a misplaced position, a replayed request `ID`, a wrong
//!   `Destination`, a stale `IssueInstant`, an `EncryptedID`, more than 32
//!   `SessionIndex` values and an SP with no certificate are all refused, with a
//!   page that posts nowhere and nothing signed;
//! * propagation: the other SPs receive signed `LogoutRequest`s in sequence on
//!   their registered bindings (the Redirect signature detached, the POST one
//!   enveloped), a replayed or foreign `InResponseTo` is refused, the partial
//!   cases end in `PartialLogout`, the full run ends in `Success`;
//! * the IdP-initiated trigger, with its cross-site refusal;
//! * D-20's indistinguishable `404`, each rate-limit bucket pinned by a test of
//!   its own, and the request tracer redacting every message parameter.
//!
//! Keys and certificates are generated at runtime. No assertion message formats a
//! `NameID`, a `SessionIndex`, a cookie, a request id or a document.

#![cfg(feature = "saml")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::middleware::security_headers::SecurityHeadersMiddleware;
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
use axiam_auth::config::AuthConfig;
use axiam_core::ca_keys::{CaKeyCustody, StoredCaKey};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredentialStatus, SealedSamlIdpKey, StoreSamlIdpCredential,
};
use axiam_core::models::saml_sp::{
    AcsEndpoint, NameIdFormat, SamlBinding, SamlServiceProviderInput,
};
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SamlIdpCredentialRepository, SamlServiceProviderRepository,
    SessionRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealRefreshTokenRepository,
    SurrealSamlIdpCredentialRepository, SurrealSamlServiceProviderRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_federation::saml_idp::request::{RedirectQuery, decode_redirect, verify_post_signature};
use axiam_federation::saml_idp::test_support::{
    Material, deflate_base64, rsa_material, sign_document, sign_octets, sign_octets_sha1,
    signature_template,
};
use axiam_federation::saml_idp::{PairwiseKey, SamlIdpIssuer};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{SecondsFormat, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const ROOT_ISSUER: &str = "https://iam.example.com";
const SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA1: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SESSION_SECS: u64 = 2_592_000;
const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
const EMAIL: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
const PARTIAL: &str = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
const RESPONDER: &str = "urn:oasis:names:tc:SAML:2.0:status:Responder";

// ---------------------------------------------------------------------------
// Material, generated once per binary
// ---------------------------------------------------------------------------

/// The tenant's IdP signing credential: RSA-4096, as D-21 issues.
fn idp_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(4096, "AXIAM SAML IdP test", 365))
}

fn sp_a_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(2048, "SP A signing", 365))
}

fn sp_b_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(2048, "SP B signing", 365))
}

fn sp_e_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(2048, "SP E signing", 365))
}

/// Somebody else's key.
fn stranger_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(2048, "Not an SP", 365))
}

/// The registered certificate of the named test SP, if it has one.
fn material_of(sp: &str) -> Option<&'static Material> {
    match sp {
        "a" => Some(sp_a_material()),
        "b" => Some(sp_b_material()),
        "e" => Some(sp_e_material()),
        _ => None,
    }
}

/// 32 bytes minted at runtime, for the PKI sealing key and the pairwise key.
fn runtime_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

fn test_password() -> String {
    axiam_test_support::test_password()
}

/// The deployment's Ed25519 pair, generated once per test binary: no key is
/// written down in this file (F4 W4, CodeQL hygiene).
fn jwt_pair() -> &'static (String, String) {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

fn auth_config() -> AuthConfig {
    let (private_pem, public_pem) = jwt_pair().clone();
    AuthConfig {
        jwt_private_key_pem: private_pem,
        jwt_public_key_pem: public_pem,
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: SESSION_SECS,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ROOT_ISSUER.into(),
        ..AuthConfig::default()
    }
}

// ---------------------------------------------------------------------------
// The world: an organization with SAML on, two tenants, users, SPs
// ---------------------------------------------------------------------------

struct World {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    other_tenant_id: Uuid,
    state: AppState<TestDb>,
}

async fn create_tenant(db: &Surreal<TestDb>, org_id: Uuid, slug: &str) -> Uuid {
    SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: format!("SAML {slug}"),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

async fn create_user(db: &Surreal<TestDb>, tenant_id: Uuid, username: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant_id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    user.id
}

/// The tenant's active signing credential, sealed exactly as D-21 seals it.
async fn install_credential(
    db: &Surreal<TestDb>,
    custodians: &axiam_pki::CaKeyCustodians,
    org_id: Uuid,
    tenant_id: Uuid,
) {
    let id = Uuid::new_v4();
    let sealed = custodians
        .store_for(CaKeyCustody::Database)
        .unwrap()
        .store(org_id, id, &idp_material().pkcs8_pem)
        .await
        .unwrap();
    let StoredCaKey::Inline(ciphertext) = sealed else {
        panic!("the database custodian seals inline");
    };
    let now = Utc::now();
    SurrealSamlIdpCredentialRepository::new(db.clone())
        .create(StoreSamlIdpCredential {
            id,
            tenant_id,
            issuer_ca_id: Uuid::new_v4(),
            certificate_pem: idp_material().cert_pem.clone(),
            serial: "01".into(),
            fingerprint: "test".into(),
            not_before: now - chrono::Duration::hours(1),
            not_after: now + chrono::Duration::days(300),
            status: SamlIdpCredentialStatus::Active,
            key: SealedSamlIdpKey {
                custody: CaKeyCustody::Database,
                locator: None,
                ciphertext: Some(ciphertext),
            },
        })
        .await
        .unwrap();
}

/// The app state: a pairwise key, a credential service whose sealing key is
/// minted at runtime, and **the revocation feed on** — the session repository
/// the sign-in and the logout both use publishes to it.
fn world_state(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
) -> (AppState<TestDb>, Arc<axiam_pki::CaKeyCustodians>) {
    let mut state = AppState::for_test(db.clone(), auth.clone());
    let custodians = Arc::new(
        axiam_pki::ca_key_store::custodians_from(Some(runtime_bytes()), &|_| None).unwrap(),
    );
    state.saml_idp.credential_service = axiam_pki::saml_signing::SamlIdpCredentialService::new(
        axiam_pki::CertService::new(
            axiam_db::SurrealCaCertificateRepository::new(db.clone()),
            axiam_db::SurrealCertificateRepository::new(db.clone()),
            axiam_pki::PkiConfig::default(),
            Arc::clone(&state.crypto_semaphore),
            Arc::clone(&custodians),
        ),
        Arc::clone(&custodians),
        SurrealSamlIdpCredentialRepository::new(db.clone()),
    );
    state.saml_idp.issuer = Arc::new(SamlIdpIssuer::new(
        auth.root_issuer(),
        Some(PairwiseKey::new(runtime_bytes())),
    ));
    let session_repo = SurrealSessionRepository::new(db.clone())
        .with_revocation_feed(chrono::Duration::seconds(900));
    state.auth_service = axiam_auth::service::AuthService::new(
        SurrealUserRepository::new(db.clone()),
        session_repo.clone(),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        auth.clone(),
        Arc::clone(&state.crypto_semaphore),
    );
    state.session_repo = session_repo;
    (state, custodians)
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SAML IdP".into(),
            slug: "saml-idp".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let mut settings = system_defaults();
    settings.saml_idp_enabled = true;
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, settings)
        .await
        .unwrap();
    let tenant_id = create_tenant(&db, org.id, "saml-a").await;
    let other_tenant_id = create_tenant(&db, org.id, "saml-b").await;
    for name in ["alice", "carol"] {
        create_user(&db, tenant_id, name).await;
    }
    create_user(&db, other_tenant_id, "bob").await;
    let auth = auth_config();
    let (state, custodians) = world_state(&db, &auth);
    install_credential(&db, &custodians, org.id, tenant_id).await;
    install_credential(&db, &custodians, org.id, other_tenant_id).await;
    World {
        db,
        org_id: org.id,
        tenant_id,
        other_tenant_id,
        state,
    }
}

// ---------------------------------------------------------------------------
// Service providers
// ---------------------------------------------------------------------------

fn entity(sp: &str) -> String {
    format!("https://sp-{sp}.example.test/metadata")
}

fn sp_acs(sp: &str) -> String {
    format!("https://sp-{sp}.example.test/saml/acs")
}

fn sp_slo(sp: &str) -> String {
    format!("https://sp-{sp}.example.test/saml/slo")
}

/// What an SP registers: a single-logout binding (or none) and whether it has a
/// signing certificate (`a`, `b` and `e` do).
struct Sp {
    name: String,
    slo: Option<SamlBinding>,
    format: NameIdFormat,
}

impl Sp {
    fn new(name: impl Into<String>, slo: Option<SamlBinding>) -> Self {
        Self {
            name: name.into(),
            slo,
            format: NameIdFormat::Persistent,
        }
    }

    fn input(&self) -> SamlServiceProviderInput {
        SamlServiceProviderInput {
            enabled: true,
            display_name: format!("SP {}", self.name),
            entity_id: entity(&self.name),
            acs_urls: vec![AcsEndpoint {
                url: sp_acs(&self.name),
                binding: SamlBinding::HttpPost,
                index: 0,
                is_default: true,
            }],
            slo_url: self.slo.map(|_| sp_slo(&self.name)),
            slo_binding: self.slo,
            name_id_format: self.format,
            sign_responses: false,
            encrypt_assertions: false,
            sp_signing_cert_pem: material_of(&self.name).map(|m| m.cert_pem.clone()),
            sp_encryption_cert_pem: None,
            want_authn_requests_signed: false,
            allow_idp_initiated: false,
            attribute_mappings: Vec::new(),
            allowed_groups: Vec::new(),
        }
    }
}

async fn register(w: &World, sp: Sp) -> Uuid {
    SurrealSamlServiceProviderRepository::new(w.db.clone())
        .create(w.tenant_id, sp.input())
        .await
        .unwrap()
        .id
}

/// The limits every test but the rate-limit ones runs under (the shared
/// counter's cold-start back-fill makes a test that sends many requests from one
/// address flaky otherwise; each bucket is pinned by a test of its own).
fn permissive_limits() -> RateLimitConfig {
    RateLimitConfig {
        end_session_per_min: 100_000,
        login_per_min: 100_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! app {
    ($w:expr) => {
        app!($w, permissive_limits())
    };
    ($w:expr, $limits:expr) => {{
        let auth = auth_config();
        test::init_service(
            App::new()
                .wrap(SecurityHeadersMiddleware)
                .app_data(web::Data::new(auth.clone()))
                .app_data(web::Data::new($w.state.clone()))
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($w.db.clone()))
                        as Arc<dyn axiam_api_rest::TenantScopeResolver>,
                ))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                // What refuses an access token whose session was revoked.
                .app_data(web::Data::new(
                    Arc::new(SurrealSessionRepository::new($w.db.clone()))
                        as Arc<dyn axiam_api_rest::SessionValidator>,
                ))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(
                        cfg,
                        &$limits,
                        RouteOptions {
                            revocation_feed_enabled: true,
                            ..RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    }};
}

/// The in-process app under test.
trait TestApp:
    actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >
{
}

impl<S> TestApp for S where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
        >
{
}

// ---------------------------------------------------------------------------
// A browser: a cookie jar and the access cookie, nothing more
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Browser {
    jar: BTreeMap<String, String>,
    access: Option<String>,
}

impl Browser {
    fn keep(&mut self, resp: &actix_web::dev::ServiceResponse) {
        for c in resp.response().cookies() {
            if c.value().is_empty() || c.max_age() == Some(actix_web::cookie::time::Duration::ZERO)
            {
                self.jar.remove(c.name());
            } else {
                self.jar.insert(c.name().to_owned(), c.value().to_owned());
            }
        }
    }

    fn header(&self) -> Option<String> {
        (!self.jar.is_empty()).then(|| {
            self.jar
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; ")
        })
    }

    fn op_cookie(&self) -> Option<String> {
        self.jar.get("axiam_op_session").cloned()
    }

    async fn get(&mut self, app: &impl TestApp, uri: &str) -> actix_web::dev::ServiceResponse {
        self.get_with(app, uri, &[]).await
    }

    async fn get_with(
        &mut self,
        app: &impl TestApp,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> actix_web::dev::ServiceResponse {
        let mut req = test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(uri);
        if let Some(cookies) = self.header() {
            req = req.insert_header(("Cookie", cookies));
        }
        for (name, value) in headers {
            req = req.insert_header((*name, *value));
        }
        let resp = test::call_service(app, req.to_request()).await;
        self.keep(&resp);
        resp
    }

    async fn post_form(
        &mut self,
        app: &impl TestApp,
        uri: &str,
        body: String,
    ) -> actix_web::dev::ServiceResponse {
        // A cross-site form post: a SameSite=Lax cookie is not sent on it.
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(uri)
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(body);
        let resp = test::call_service(app, req.to_request()).await;
        self.keep(&resp);
        resp
    }

    /// Sign in over HTTP, keeping the OP cookie and the access cookie.
    async fn sign_in_to(&mut self, app: &impl TestApp, w: &World, tenant_id: Uuid, username: &str) {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/login")
            .set_json(serde_json::json!({
                "tenant_id": tenant_id,
                "org_id": w.org_id,
                "username_or_email": username,
                "password": test_password(),
            }))
            .to_request();
        let resp = test::call_service(app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "the sign-in must succeed");
        let saml_path = format!("/saml/v2/{tenant_id}/sso");
        for c in resp.response().cookies() {
            if c.name() == "axiam_op_session" && c.path() == Some(saml_path.as_str()) {
                self.jar.insert(c.name().to_owned(), c.value().to_owned());
            }
            if c.name() == "axiam_access" {
                self.access = Some(c.value().to_owned());
            }
        }
        assert!(self.op_cookie().is_some(), "an OP cookie at the SSO path");
    }

    async fn sign_in(&mut self, app: &impl TestApp, w: &World, username: &str) {
        self.sign_in_to(app, w, w.tenant_id, username).await;
    }

    /// `GET /api/v1/auth/me` with the access cookie from the sign-in: the status.
    async fn me(&self, app: &impl TestApp) -> u16 {
        let access = self.access.clone().expect("signed in");
        let resp = test::call_service(
            app,
            test::TestRequest::get()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri("/api/v1/auth/me")
                .insert_header(("Cookie", format!("axiam_access={access}")))
                .to_request(),
        )
        .await;
        resp.status().as_u16()
    }
}

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn location(resp: &actix_web::dev::ServiceResponse) -> String {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn header(resp: &actix_web::dev::ServiceResponse, name: &str) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

async fn body_of(resp: actix_web::dev::ServiceResponse) -> String {
    String::from_utf8(test::read_body(resp).await.to_vec()).unwrap()
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn attr(xml: &str, name: &str) -> Option<String> {
    let marker = format!(" {name}=\"");
    let start = xml.find(&marker)? + marker.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_owned())
}

/// The `NameID` text of an assertion.
fn name_id_of(xml: &str) -> String {
    let open = xml.find("<saml:NameID").expect("a NameID");
    let start = xml[open..].find('>').expect("a tag") + open + 1;
    let end = xml[start..].find("</saml:NameID>").expect("an end tag") + start;
    xml[start..end].to_owned()
}

fn status_codes(xml: &str) -> Vec<String> {
    xml.match_indices("StatusCode Value=\"")
        .map(|(i, m)| {
            let start = i + m.len();
            let end = xml[start..].find('"').unwrap() + start;
            xml[start..end].to_owned()
        })
        .collect()
}

fn at(offset_secs: i64) -> String {
    (Utc::now() + chrono::Duration::seconds(offset_secs)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn slo_url(tenant_id: Uuid) -> String {
    format!("{ROOT_ISSUER}/saml/v2/{tenant_id}/slo")
}

fn slo_path(tenant_id: Uuid) -> String {
    format!("/saml/v2/{tenant_id}/slo")
}

fn sso_path(tenant_id: Uuid) -> String {
    format!("/saml/v2/{tenant_id}/sso")
}

fn sso_url(tenant_id: Uuid) -> String {
    format!("{ROOT_ISSUER}/saml/v2/{tenant_id}/sso")
}

// ---------------------------------------------------------------------------
// Signing in to SPs: what writes the participant rows
// ---------------------------------------------------------------------------

struct SignedOn {
    index: String,
    name_id: String,
}

/// One SP-initiated sign-on for an already signed-in browser.
async fn sign_on(app: &impl TestApp, browser: &mut Browser, w: &World, sp: &str) -> SignedOn {
    let id = format!("_{}", Uuid::new_v4().simple());
    let document = format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{}" Destination="{}"><saml:Issuer>{}</saml:Issuer></samlp:AuthnRequest>"#,
        at(0),
        sso_url(w.tenant_id),
        entity(sp)
    );
    let query = format!("SAMLRequest={}", enc(&deflate_base64(document.as_bytes())));
    let started = browser
        .get(app, &format!("{}?{query}", sso_path(w.tenant_id)))
        .await;
    assert_eq!(started.status().as_u16(), 303, "the first leg answers 303");
    let issued = browser.get(app, &location(&started)).await;
    assert_eq!(
        issued.status().as_u16(),
        200,
        "a signed-in browser is issued"
    );
    let (_, xml, _) = posted(&body_of(issued).await, "SAMLResponse");
    SignedOn {
        index: attr(&xml, "SessionIndex").expect("a SessionIndex"),
        name_id: name_id_of(&xml),
    }
}

/// `(action, document, RelayState)` from an auto-post page carrying `field`.
fn posted(page: &str, field: &str) -> (String, String, Option<String>) {
    let read = |marker: &str| -> Option<String> {
        let start = page.find(marker)? + marker.len();
        let end = page[start..].find('"')? + start;
        Some(html_unescape(&page[start..end]))
    };
    let action = read("action=\"").expect("a form action");
    let value = read(&format!("name=\"{field}\" value=\"")).expect("the message field");
    let xml = String::from_utf8(STANDARD.decode(value).unwrap()).unwrap();
    (action, xml, read("name=\"RelayState\" value=\""))
}

#[derive(Debug)]
struct ParticipantRow {
    session_id: Uuid,
}

async fn participants(w: &World) -> Vec<ParticipantRow> {
    let mut result =
        w.db.query("SELECT session_id FROM saml_sp_session ORDER BY created_at ASC")
            .await
            .unwrap();
    let rows: Vec<serde_json::Value> = result.take(0).unwrap();
    rows.iter()
        .map(|r| ParticipantRow {
            session_id: Uuid::parse_str(r["session_id"].as_str().unwrap()).unwrap(),
        })
        .collect()
}

async fn runs(w: &World) -> Vec<serde_json::Value> {
    let mut result = w.db.query("SELECT * FROM saml_logout_run").await.unwrap();
    result.take(0).unwrap()
}

/// The one session the participant rows name.
async fn the_session(w: &World) -> Uuid {
    let rows = participants(w).await;
    assert!(!rows.is_empty(), "a participant row exists");
    let session = rows[0].session_id;
    assert!(rows.iter().all(|r| r.session_id == session));
    session
}

async fn session_alive(w: &World, tenant_id: Uuid, session_id: Uuid) -> bool {
    w.state
        .session_repo
        .get_by_id(tenant_id, session_id)
        .await
        .is_ok()
}

/// Whether the OP cookie of this browser still names a session.
async fn op_cookie_resolves(w: &World, tenant_id: Uuid, browser: &Browser) -> bool {
    let cookie = browser.op_cookie().expect("an OP cookie");
    let digest = axiam_auth::token::hash_browser_session_token(&cookie);
    w.state
        .session_repo
        .get_by_browser_token_hash(tenant_id, &digest)
        .await
        .unwrap()
        .is_some()
}

async fn feed(app: &impl TestApp) -> Vec<String> {
    let resp = test::call_service(
        app,
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/oauth2/revocations")
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    body["revoked"]
        .as_array()
        .expect("an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect()
}

// ---------------------------------------------------------------------------
// What an SP sends
// ---------------------------------------------------------------------------

fn fresh_id() -> String {
    format!("_{}", Uuid::new_v4().simple())
}

/// How a message is signed.
#[derive(Clone, Copy)]
enum Sig<'a> {
    /// Not at all.
    Unsigned,
    /// RSA-SHA256, the algorithm every SP uses.
    Sha256(&'a Material),
    /// RSA-SHA1, which AXIAM never accepts.
    Sha1(&'a Material),
}

/// A message document: its root `ID`, and a renderer that takes the signature
/// template (placed where the message wants it) when the binding signs enveloped.
struct Doc {
    id: String,
    render: Renderer,
}

/// Renders a document, with the signature template when it is to be signed
/// enveloped.
type Renderer = Box<dyn Fn(Option<&str>) -> String>;

/// Where the enveloped signature template goes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// The root's child after `Issuer`: the one admissible place.
    AfterIssuer,
    /// Inside an `Extensions` wrapper.
    InExtensions,
    /// Inside the `NameID` element.
    InsideNameId,
    /// In place, plus a second, unsigned `ds:Signature` in an `Extensions`.
    WithDummy,
}

#[derive(Clone)]
struct LogoutReq {
    id: String,
    issuer: String,
    destination: Option<String>,
    issued_offset: i64,
    name_id: String,
    name_id_format: Option<String>,
    indexes: Vec<String>,
    not_on_or_after: Option<String>,
    /// Replaces the `NameID` element altogether.
    principal_xml: Option<String>,
    /// An `Extensions` element, between the signature and the principal.
    extensions: Option<String>,
    place: Place,
}

impl LogoutReq {
    /// The request SP `sp` sends for what it was given at sign-on.
    fn new(w: &World, sp: &str, on: &SignedOn) -> Self {
        Self {
            id: fresh_id(),
            issuer: entity(sp),
            destination: Some(slo_url(w.tenant_id)),
            issued_offset: 0,
            name_id: on.name_id.clone(),
            name_id_format: Some(PERSISTENT.into()),
            indexes: vec![on.index.clone()],
            not_on_or_after: None,
            principal_xml: None,
            extensions: None,
            place: Place::AfterIssuer,
        }
    }

    fn doc(&self) -> Doc {
        let this = self.clone();
        Doc {
            id: self.id.clone(),
            render: Box::new(move |template| {
                let mut attrs = String::new();
                if let Some(d) = &this.destination {
                    attrs.push_str(&format!(r#" Destination="{d}""#));
                }
                if let Some(n) = &this.not_on_or_after {
                    attrs.push_str(&format!(r#" NotOnOrAfter="{n}""#));
                }
                let format = this
                    .name_id_format
                    .as_deref()
                    .map(|f| format!(r#" Format="{f}""#))
                    .unwrap_or_default();
                let inner = if this.place == Place::InsideNameId {
                    template.unwrap_or_default()
                } else {
                    ""
                };
                let principal = this.principal_xml.clone().unwrap_or_else(|| {
                    format!("<saml:NameID{format}>{}{inner}</saml:NameID>", this.name_id)
                });
                let indexes: String = this
                    .indexes
                    .iter()
                    .map(|i| format!("<samlp:SessionIndex>{i}</samlp:SessionIndex>"))
                    .collect();
                let after_issuer = if this.place == Place::AfterIssuer {
                    template.unwrap_or_default().to_owned()
                } else if this.place == Place::WithDummy {
                    // The real template first (xmlsec signs the first), then a
                    // second one nobody signs, in a wrapper.
                    let dummy = signature_template("_dummy", &sp_a_material().cert_der);
                    format!(
                        "{}<samlp:Extensions>{dummy}</samlp:Extensions>",
                        template.unwrap_or_default()
                    )
                } else if this.place == Place::InExtensions {
                    format!(
                        "<samlp:Extensions>{}</samlp:Extensions>",
                        template.unwrap_or_default()
                    )
                } else {
                    String::new()
                };
                format!(
                    r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}"{attrs}><saml:Issuer>{}</saml:Issuer>{after_issuer}{}{principal}{indexes}</samlp:LogoutRequest>"#,
                    this.id,
                    at(this.issued_offset),
                    this.issuer,
                    this.extensions.clone().unwrap_or_default(),
                )
            }),
        }
    }
}

/// A `LogoutResponse` from an SP, answering AXIAM's request `in_response_to`.
fn response_doc(
    in_response_to: &str,
    issuer: &str,
    destination: Option<String>,
    status: &str,
    nested: Option<&str>,
) -> Doc {
    let id = fresh_id();
    let (in_response_to, issuer) = (in_response_to.to_owned(), issuer.to_owned());
    let (status, nested) = (status.to_owned(), nested.map(str::to_owned));
    Doc {
        id: id.clone(),
        render: Box::new(move |template| {
            let destination = destination
                .as_deref()
                .map(|d| format!(r#" Destination="{d}""#))
                .unwrap_or_default();
            let inner = match &nested {
                Some(n) => format!(r#"<samlp:StatusCode Value="{n}"/>"#),
                None => String::new(),
            };
            format!(
                r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{id}" Version="2.0" IssueInstant="{}"{destination} InResponseTo="{in_response_to}"><saml:Issuer>{issuer}</saml:Issuer>{}<samlp:Status><samlp:StatusCode Value="{status}">{inner}</samlp:StatusCode></samlp:Status></samlp:LogoutResponse>"#,
                at(0),
                template.unwrap_or_default(),
            )
        }),
    }
}

fn template_for(id: &str, material: &Material, sha1: bool) -> String {
    let template = signature_template(id, &material.cert_der);
    if sha1 {
        template.replace(SHA256, SHA1).replace(
            "http://www.w3.org/2001/04/xmlenc#sha256",
            "http://www.w3.org/2000/09/xmldsig#sha1",
        )
    } else {
        template
    }
}

/// The document as the POST binding carries it.
fn signed_xml(doc: &Doc, sig: Sig<'_>) -> String {
    match sig {
        Sig::Unsigned => (doc.render)(None),
        Sig::Sha256(m) | Sig::Sha1(m) => {
            let template = template_for(&doc.id, m, matches!(sig, Sig::Sha1(_)));
            sign_document(&(doc.render)(Some(&template)), &m.pkcs8_der)
        }
    }
}

fn post_body(param: &str, xml: &str, relay: Option<&str>) -> String {
    let mut body = format!("{param}={}", enc(&STANDARD.encode(xml)));
    if let Some(r) = relay {
        body.push_str(&format!("&RelayState={}", enc(r)));
    }
    body
}

/// An HTTP-Redirect query, signed over exactly the octets sent.
fn redirect_query(param: &str, doc: &Doc, sig: Sig<'_>, relay: Option<&str>) -> String {
    let xml = (doc.render)(None);
    let mut query = format!("{param}={}", enc(&deflate_base64(xml.as_bytes())));
    if let Some(r) = relay {
        query.push_str(&format!("&RelayState={}", enc(r)));
    }
    match sig {
        Sig::Unsigned => {}
        Sig::Sha256(m) => {
            query.push_str(&format!("&SigAlg={}", enc(SHA256)));
            let signature = sign_octets(&query, &m.pkcs8_der);
            query.push_str(&format!("&Signature={}", enc(&signature)));
        }
        Sig::Sha1(m) => {
            query.push_str(&format!("&SigAlg={}", enc(SHA1)));
            let signature = sign_octets_sha1(&query, &m.pkcs8_der);
            query.push_str(&format!("&Signature={}", enc(&signature)));
        }
    }
    query
}

/// What goes on the wire: a query string (Redirect) or a form body (POST).
fn payload(via: SamlBinding, param: &str, doc: &Doc, sig: Sig<'_>, relay: Option<&str>) -> String {
    match via {
        SamlBinding::HttpRedirect => redirect_query(param, doc, sig, relay),
        SamlBinding::HttpPost => post_body(param, &signed_xml(doc, sig), relay),
    }
}

/// Deliver a payload to `/slo` the way a browser carrying an SP's redirect or form
/// post does: no cookies (the OP cookie's path is the SSO path).
async fn deliver(
    app: &impl TestApp,
    tenant_id: Uuid,
    via: SamlBinding,
    payload: String,
) -> actix_web::dev::ServiceResponse {
    let mut anonymous = Browser::default();
    match via {
        SamlBinding::HttpRedirect => {
            anonymous
                .get(app, &format!("{}?{payload}", slo_path(tenant_id)))
                .await
        }
        SamlBinding::HttpPost => {
            anonymous
                .post_form(app, &slo_path(tenant_id), payload)
                .await
        }
    }
}

async fn send(
    app: &impl TestApp,
    tenant_id: Uuid,
    via: SamlBinding,
    param: &str,
    doc: &Doc,
    sig: Sig<'_>,
    relay: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    deliver(app, tenant_id, via, payload(via, param, doc, sig, relay)).await
}

/// The SP's request, signed by `sp`'s own certificate.
async fn request_from(
    app: &impl TestApp,
    w: &World,
    sp: &str,
    via: SamlBinding,
    req: &LogoutReq,
    relay: Option<&str>,
) -> actix_web::dev::ServiceResponse {
    let material = material_of(sp).expect("this SP has a certificate");
    send(
        app,
        w.tenant_id,
        via,
        "SAMLRequest",
        &req.doc(),
        Sig::Sha256(material),
        relay,
    )
    .await
}

// ---------------------------------------------------------------------------
// What AXIAM sends
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Outbound {
    binding: SamlBinding,
    destination: String,
    field: &'static str,
    xml: String,
    relay: Option<String>,
    /// The raw query of a Redirect-bound message.
    query: Option<String>,
    /// The page's own policy header (POST binding).
    policy: String,
    /// Whether every OP copy and the API cookies were cleared by this answer.
    cleared: bool,
}

/// Whether the answer removes the three API cookies and both OP-session copies
/// the tenant's sign-in mints.
fn clears_every_cookie(resp: &actix_web::dev::ServiceResponse, tenant_id: Uuid) -> bool {
    let removed = |name: &str, path: Option<&str>| {
        resp.response().cookies().any(|c| {
            c.name() == name
                && (c.value().is_empty()
                    || c.max_age() == Some(actix_web::cookie::time::Duration::ZERO))
                && path.is_none_or(|p| c.path() == Some(p))
        })
    };
    let sso = sso_path(tenant_id);
    removed("axiam_access", None)
        && removed("axiam_refresh", None)
        && removed("axiam_csrf", None)
        && removed("axiam_op_session", Some("/oauth2/authorize"))
        && removed("axiam_op_session", Some(sso.as_str()))
}

/// Read what AXIAM answered with: a redirect carrying a Redirect-bound message,
/// or an auto-post page carrying a POST-bound one.
async fn outbound(resp: actix_web::dev::ServiceResponse, tenant_id: Uuid) -> Outbound {
    let cleared = clears_every_cookie(&resp, tenant_id);
    match resp.status().as_u16() {
        302 => {
            let target = location(&resp);
            let (base, query) = target.split_once('?').expect("a message in the query");
            let parsed = RedirectQuery::parse_logout(query).expect("a well-formed query");
            Outbound {
                binding: SamlBinding::HttpRedirect,
                destination: base.to_owned(),
                field: match parsed.param {
                    axiam_federation::saml_idp::request::MessageParam::Request => "SAMLRequest",
                    axiam_federation::saml_idp::request::MessageParam::Response => "SAMLResponse",
                },
                xml: decode_redirect(&parsed.message()).expect("a document"),
                relay: parsed.relay_state(),
                query: Some(query.to_owned()),
                policy: String::new(),
                cleared,
            }
        }
        200 => {
            let policy = header(&resp, "content-security-policy");
            let page = body_of(resp).await;
            assert!(page.contains("<form"), "an auto-post page");
            let field = if page.contains("name=\"SAMLRequest\"") {
                "SAMLRequest"
            } else {
                "SAMLResponse"
            };
            let (action, xml, relay) = posted(&page, field);
            Outbound {
                binding: SamlBinding::HttpPost,
                destination: action,
                field,
                xml,
                relay,
                query: None,
                policy,
                cleared,
            }
        }
        other => panic!("expected a logout message, the status was {other}"),
    }
}

/// The message is signed by the tenant's credential and nobody else's, the way
/// its binding signs: detached over the query for Redirect (no `ds:Signature`
/// exists in the document), enveloped on the root for POST.
fn assert_signed_by_idp(out: &Outbound) {
    match out.binding {
        SamlBinding::HttpRedirect => {
            let query = RedirectQuery::parse_logout(out.query.as_deref().unwrap()).unwrap();
            query
                .verify_signature(&idp_material().cert_der)
                .expect("the detached signature verifies against the tenant credential");
            assert!(
                query
                    .verify_signature(&stranger_material().cert_der)
                    .is_err(),
                "and against no other certificate"
            );
            assert!(
                !out.xml.contains("Signature"),
                "a Redirect-bound message carries no XML signature to harvest"
            );
        }
        SamlBinding::HttpPost => {
            verify_post_signature(&out.xml, &idp_material().cert_der)
                .expect("the enveloped signature verifies against the tenant credential");
            assert_eq!(out.xml.matches("<ds:Signature ").count(), 1, "exactly one");
        }
    }
}

fn message_id(out: &Outbound) -> String {
    attr(&out.xml, "ID").expect("a message ID")
}

fn is_logout_request(out: &Outbound) -> bool {
    out.field == "SAMLRequest" && out.xml.contains("<samlp:LogoutRequest")
}

/// The SP answers AXIAM's request in `out` with `status`, through the browser.
async fn answer(
    app: &impl TestApp,
    w: &World,
    out: &Outbound,
    sp: &str,
    status: &str,
    nested: Option<&str>,
    sig: Sig<'_>,
    via: SamlBinding,
) -> actix_web::dev::ServiceResponse {
    assert!(is_logout_request(out), "AXIAM sent a request to answer");
    let doc = response_doc(
        &message_id(out),
        &entity(sp),
        Some(slo_url(w.tenant_id)),
        status,
        nested,
    );
    send(app, w.tenant_id, via, "SAMLResponse", &doc, sig, None).await
}

/// A refusal: an error page that posts nowhere, sets no cookie and signs
/// nothing.
async fn assert_refused(resp: actix_web::dev::ServiceResponse, label: &str) {
    let status = resp.status().as_u16();
    assert!(
        matches!(status, 400 | 403 | 413),
        "{label}: refused with a client error (status {status})"
    );
    assert!(
        resp.headers().get("location").is_none(),
        "{label}: no redirect anywhere"
    );
    assert_eq!(
        resp.response().cookies().count(),
        0,
        "{label}: an unverified message changes nothing in the browser"
    );
    let page = body_of(resp).await;
    assert!(
        !page.contains("<form") && !page.contains("SAMLRe"),
        "{label}: nothing is posted and nothing is signed"
    );
}

// ---------------------------------------------------------------------------
// 1. Revocation
// ---------------------------------------------------------------------------

/// One SP-initiated logout on `binding`, end to end: the AXIAM session is gone —
/// the access cookie and the OP cookie are refused afterwards — the revocation
/// feed shows it, and the SP is answered with a signed `Success` at its
/// registered endpoint, with the browser's cookies cleared.
async fn revocation_case(binding: SamlBinding) {
    use axiam_core::revocation_feed::revocation_hash;

    let w = world().await;
    register(&w, Sp::new("a", Some(binding))).await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;
    let on = sign_on(&app, &mut browser, &w, "a").await;
    let session = the_session(&w).await;
    assert_eq!(browser.me(&app).await, 200, "the session works before");
    assert!(op_cookie_resolves(&w, w.tenant_id, &browser).await);
    assert!(!feed(&app).await.contains(&revocation_hash(session)));

    let req = LogoutReq::new(&w, "a", &on);
    let resp = request_from(&app, &w, "a", binding, &req, Some("sp-relay")).await;
    let out = outbound(resp, w.tenant_id).await;

    assert_eq!(out.binding, binding, "the SP's registered binding");
    assert_eq!(out.field, "SAMLResponse");
    assert_eq!(out.destination, sp_slo("a"), "its registered endpoint");
    assert_eq!(attr(&out.xml, "InResponseTo"), Some(req.id.clone()));
    assert_eq!(attr(&out.xml, "Destination"), Some(sp_slo("a")));
    assert_eq!(out.relay.as_deref(), Some("sp-relay"), "echoed to that SP");
    assert_eq!(status_codes(&out.xml), vec![SUCCESS.to_string()]);
    assert_signed_by_idp(&out);
    assert!(out.cleared, "every OP copy and the API cookies are cleared");
    if binding == SamlBinding::HttpPost {
        assert!(
            out.policy
                .contains("form-action https://sp-a.example.test;"),
            "the shared auto-post page: form-action is the slo_url's origin"
        );
    }

    assert!(
        !session_alive(&w, w.tenant_id, session).await,
        "the session is gone"
    );
    assert_eq!(browser.me(&app).await, 401, "the session is refused");
    assert!(
        !op_cookie_resolves(&w, w.tenant_id, &browser).await,
        "the OP cookie names nothing"
    );
    assert!(
        feed(&app).await.contains(&revocation_hash(session)),
        "the revocation feed shows the revocation"
    );
    assert!(
        participants(&w).await.is_empty(),
        "the chain ended: no row left"
    );
    let recorded = runs(&w).await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0]["status"], "finished");
    assert_eq!(recorded[0]["partial"], false);
}

/// **Acceptance: revocation, HTTP-Redirect.**
#[actix_rt::test]
async fn an_sp_initiated_logout_on_the_redirect_binding_revokes_the_session_and_the_feed_shows_it()
{
    revocation_case(SamlBinding::HttpRedirect).await;
}

/// **Acceptance: revocation, HTTP-POST.**
#[actix_rt::test]
async fn an_sp_initiated_logout_on_the_post_binding_revokes_the_session_and_the_feed_shows_it() {
    revocation_case(SamlBinding::HttpPost).await;
}

/// **Acceptance: back-channel logout** is dispatched to the OIDC RPs bound to
/// the session — the signed token names the session and the RP.
#[actix_rt::test]
async fn back_channel_logout_is_dispatched_to_oidc_rps_bound_to_the_session() {
    use axiam_core::models::oauth2_client::{
        AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client,
        CreateSessionClient, ManagedBy,
    };
    use axiam_core::repository::{OAuth2ClientRepository, SessionClientRepository};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (client, _) = axiam_db::repository::SurrealOAuth2ClientRepository::new(w.db.clone())
        .create(CreateOAuth2Client {
            tenant_id: w.tenant_id,
            name: "rp".into(),
            redirect_uris: vec!["https://rp.test.example/callback".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: Some(format!("http://127.0.0.1:{port}/backchannel")),
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            allowed_resources: Vec::new(),
            managed_by: ManagedBy::Admin,
        })
        .await
        .unwrap();
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;
    let on = sign_on(&app, &mut browser, &w, "a").await;
    let session = the_session(&w).await;
    let user_id = w
        .state
        .session_repo
        .get_by_id(w.tenant_id, session)
        .await
        .unwrap()
        .user_id;
    axiam_db::repository::SurrealSessionClientRepository::new(w.db.clone())
        .record(CreateSessionClient {
            tenant_id: w.tenant_id,
            session_id: session,
            client_id: client.client_id.clone(),
            user_id,
        })
        .await
        .unwrap();

    let req = LogoutReq::new(&w, "a", &on);
    let resp = request_from(&app, &w, "a", SamlBinding::HttpRedirect, &req, None).await;
    assert_eq!(resp.status().as_u16(), 302, "the SP is answered");

    // The RP is told: a form post of one `logout_token`.
    let (mut stream, _) =
        tokio::time::timeout(std::time::Duration::from_secs(20), listener.accept())
            .await
            .expect("the RP is told within the timeout")
            .unwrap();
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    let body = loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut chunk))
            .await
            .expect("the request arrives")
            .unwrap();
        received.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&received).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let length = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if body.len() >= length {
                break body.to_owned();
            }
        }
        assert!(n > 0, "the connection closed before a body arrived");
    };
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let token = url::form_urlencoded::parse(body.as_bytes())
        .find(|(k, _)| k == "logout_token")
        .map(|(_, v)| v.into_owned())
        .expect("a logout_token parameter");
    let payload = token.split('.').nth(1).expect("a JWT");
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["sid"], session.to_string(), "it names the session");
    assert_eq!(claims["aud"], client.client_id, "and the RP it is for");
    assert!(!session_alive(&w, w.tenant_id, session).await);
}

// ---------------------------------------------------------------------------
// 2. Which sessions a request reaches
// ---------------------------------------------------------------------------

/// **Acceptance: session selection.** A session the SP does not participate in is
/// untouched; the `NameID` — value and format — must match; no match answers
/// `Success` and ends nothing; and only then, with the right index and principal,
/// the SP's own session ends.
#[actix_rt::test]
async fn only_the_sessions_the_sp_participates_in_end_and_only_for_the_right_name_id() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    register(&w, Sp::new("b", Some(SamlBinding::HttpRedirect))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;
    let mut carol = Browser::default();
    carol.sign_in(&app, &w, "carol").await;
    let on_b = sign_on(&app, &mut carol, &w, "b").await;

    async fn answered_success(app: &impl TestApp, w: &World, label: &str, req: LogoutReq) {
        let resp = request_from(app, w, "a", SamlBinding::HttpRedirect, &req, None).await;
        let out = outbound(resp, w.tenant_id).await;
        assert_eq!(
            status_codes(&out.xml),
            vec![SUCCESS.to_string()],
            "{label}: no match answers Success"
        );
        assert_signed_by_idp(&out);
    }

    // Another SP's index, with the principal that SP gave: not this SP's row.
    let mut foreign_index = LogoutReq::new(&w, "a", &on_a);
    foreign_index.indexes = vec![on_b.index.clone()];
    foreign_index.name_id = on_b.name_id.clone();
    answered_success(&app, &w, "another SP's index", foreign_index).await;

    // This SP's index, naming somebody else's NameID.
    let mut wrong_name = LogoutReq::new(&w, "a", &on_a);
    wrong_name.name_id = on_b.name_id.clone();
    answered_success(&app, &w, "a mismatched NameID", wrong_name).await;

    // Right value, wrong format.
    let mut wrong_format = LogoutReq::new(&w, "a", &on_a);
    wrong_format.name_id_format = Some(EMAIL.into());
    answered_success(&app, &w, "a mismatched format", wrong_format).await;

    // Right value, no format at all: the row's format is persistent.
    let mut no_format = LogoutReq::new(&w, "a", &on_a);
    no_format.name_id_format = None;
    answered_success(&app, &w, "no format", no_format).await;

    // No index, a principal this SP never named.
    let mut unknown = LogoutReq::new(&w, "a", &on_a);
    unknown.indexes.clear();
    unknown.name_id = "nobody-gave-this-out".into();
    answered_success(&app, &w, "an unknown principal", unknown).await;

    assert_eq!(alice.me(&app).await, 200, "alice's session is untouched");
    assert_eq!(carol.me(&app).await, 200, "carol's session is untouched");
    assert_eq!(participants(&w).await.len(), 2);

    // The right index and principal: alice's session ends, carol's does not.
    let ok = LogoutReq::new(&w, "a", &on_a);
    answered_success(&app, &w, "the right index and principal", ok).await;
    assert_eq!(alice.me(&app).await, 401, "alice's session ended");
    assert_eq!(
        carol.me(&app).await,
        200,
        "a session SP A is not in is untouched"
    );
}

/// With no `SessionIndex`: everything that SP holds for that `NameID` — whole
/// sessions, every one.
#[actix_rt::test]
async fn a_request_without_an_index_ends_every_session_the_sp_holds_for_that_name_id() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpPost))).await;
    let app = app!(w);
    let (mut one, mut two) = (Browser::default(), Browser::default());
    one.sign_in(&app, &w, "alice").await;
    two.sign_in(&app, &w, "alice").await;
    let on_one = sign_on(&app, &mut one, &w, "a").await;
    let on_two = sign_on(&app, &mut two, &w, "a").await;
    assert_eq!(
        on_one.name_id, on_two.name_id,
        "one person, one pairwise NameID"
    );
    assert_ne!(on_one.index, on_two.index, "two sessions, two indexes");

    let mut req = LogoutReq::new(&w, "a", &on_one);
    req.indexes.clear();
    let resp = request_from(&app, &w, "a", SamlBinding::HttpPost, &req, None).await;
    let out = outbound(resp, w.tenant_id).await;
    assert_eq!(status_codes(&out.xml), vec![SUCCESS.to_string()]);
    assert_eq!(one.me(&app).await, 401);
    assert_eq!(two.me(&app).await, 401);
    assert!(participants(&w).await.is_empty());
}

/// `/slo` never reads the OP cookie and decides nothing by it: a browser that
/// carries another person's cookie along with the SP's request ends the session
/// the *message* names, and leaves the one the cookie names alone (the cookie is
/// cleared in the browser, but its session is not revoked).
#[actix_rt::test]
async fn slo_never_reads_the_op_cookie() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;
    let mut carol = Browser::default();
    carol.sign_in(&app, &w, "carol").await;
    let carols_cookie = carol.clone();

    let req = LogoutReq::new(&w, "a", &on_a);
    let query = redirect_query(
        "SAMLRequest",
        &req.doc(),
        Sig::Sha256(sp_a_material()),
        None,
    );
    let resp = carol
        .get(&app, &format!("{}?{query}", slo_path(w.tenant_id)))
        .await;
    let out = outbound(resp, w.tenant_id).await;
    assert_eq!(status_codes(&out.xml), vec![SUCCESS.to_string()]);
    assert!(
        out.cleared,
        "the browser's copies are cleared by the answer"
    );
    assert_eq!(alice.me(&app).await, 401, "the message's session ended");
    assert_eq!(
        carols_cookie.me(&app).await,
        200,
        "the cookie's session did not"
    );
    assert!(
        op_cookie_resolves(&w, w.tenant_id, &carols_cookie).await,
        "its OP cookie still names a live session"
    );
}

/// Another tenant's path ends nothing: an SP registered in this tenant is not an
/// SP of the other, and even one that registered the same entity id and
/// certificate there resolves its index only among its own tenant's rows.
#[actix_rt::test]
async fn another_tenants_path_ends_nothing() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;

    let mut req = LogoutReq::new(&w, "a", &on_a);
    req.destination = Some(slo_url(w.other_tenant_id));

    // The other tenant has no such SP: refused.
    let resp = send(
        &app,
        w.other_tenant_id,
        SamlBinding::HttpRedirect,
        "SAMLRequest",
        &req.doc(),
        Sig::Sha256(sp_a_material()),
        None,
    )
    .await;
    assert_refused(resp, "an SP unknown to the other tenant").await;

    // It registers the same entity id and certificate there: the message is
    // verified, finds no row under that tenant, and ends nothing here.
    SurrealSamlServiceProviderRepository::new(w.db.clone())
        .create(
            w.other_tenant_id,
            Sp::new("a", Some(SamlBinding::HttpRedirect)).input(),
        )
        .await
        .unwrap();
    let mut again = req.clone();
    again.id = fresh_id();
    let resp = send(
        &app,
        w.other_tenant_id,
        SamlBinding::HttpRedirect,
        "SAMLRequest",
        &again.doc(),
        Sig::Sha256(sp_a_material()),
        None,
    )
    .await;
    let out = outbound(resp, w.other_tenant_id).await;
    assert_eq!(status_codes(&out.xml), vec![SUCCESS.to_string()]);
    assert_eq!(
        alice.me(&app).await,
        200,
        "this tenant's session is untouched"
    );
    assert_eq!(participants(&w).await.len(), 1);
}

// ---------------------------------------------------------------------------
// 3. Refusals
// ---------------------------------------------------------------------------

/// Alice signed on to SP `a`, and what a refusal must leave as it was.
struct Standing {
    on: SignedOn,
    alice: Browser,
}

impl Standing {
    async fn assert_untouched(&self, app: &impl TestApp, w: &World, label: &str) {
        assert_eq!(
            self.alice.me(app).await,
            200,
            "{label}: the session is untouched"
        );
        assert_eq!(
            participants(w).await.len(),
            1,
            "{label}: the participant row stays"
        );
        assert!(runs(w).await.is_empty(), "{label}: no run was claimed");
    }
}

async fn standing(app: &impl TestApp, w: &World) -> Standing {
    let mut alice = Browser::default();
    alice.sign_in(app, w, "alice").await;
    let on = sign_on(app, &mut alice, w, "a").await;
    Standing { on, alice }
}

/// **Acceptance: refusals, signatures.** Unsigned, wrong-key, tampered and
/// SHA-1-signed messages are refused on both bindings — with an error page that
/// posts nowhere — and end nothing.
#[actix_rt::test]
async fn unsigned_wrong_key_tampered_and_sha1_requests_are_refused_on_both_bindings() {
    for binding in [SamlBinding::HttpRedirect, SamlBinding::HttpPost] {
        let w = world().await;
        register(&w, Sp::new("a", Some(binding))).await;
        let app = app!(w);
        let st = standing(&app, &w).await;
        let req = LogoutReq::new(&w, "a", &st.on);
        let doc = req.doc();
        let tag = |label: &str| format!("{label} ({})", binding.as_str());

        for (label, sig) in [
            ("unsigned", Sig::Unsigned),
            ("a stranger's key", Sig::Sha256(stranger_material())),
            ("SHA-1", Sig::Sha1(sp_a_material())),
        ] {
            let resp = send(&app, w.tenant_id, binding, "SAMLRequest", &doc, sig, None).await;
            assert_refused(resp, &tag(label)).await;
            st.assert_untouched(&app, &w, &tag(label)).await;
        }

        // Tampered after signing: the principal changed (POST), the RelayState
        // changed (Redirect: the octets signed are no longer the octets sent).
        let tampered = match binding {
            SamlBinding::HttpPost => {
                let signed = signed_xml(&doc, Sig::Sha256(sp_a_material()));
                assert!(signed.contains(&st.on.name_id));
                post_body(
                    "SAMLRequest",
                    &signed.replace(&st.on.name_id, "somebody-else"),
                    None,
                )
            }
            SamlBinding::HttpRedirect => {
                let query = redirect_query(
                    "SAMLRequest",
                    &doc,
                    Sig::Sha256(sp_a_material()),
                    Some("original"),
                );
                query.replace("RelayState=original", "RelayState=changed")
            }
        };
        let resp = deliver(&app, w.tenant_id, binding, tampered).await;
        assert_refused(resp, &tag("tampered")).await;
        st.assert_untouched(&app, &w, &tag("tampered")).await;
    }
}

/// **Acceptance: refusals, a half signature and a signature in the wrong
/// place.** A Redirect query with `SigAlg` and no `Signature`, a Redirect
/// document carrying an enveloped signature, and a POST message whose signature
/// sits in a misplaced position — inside an `Extensions` wrapper, inside the
/// `NameID`, beside a second one — are refused, though each is signed by the
/// SP's own key.
#[actix_rt::test]
async fn a_misplaced_or_wrong_binding_signature_is_refused() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpPost))).await;
    let app = app!(w);
    let st = standing(&app, &w).await;
    let req = LogoutReq::new(&w, "a", &st.on);

    for (label, place) in [
        ("inside Extensions", Place::InExtensions),
        ("inside the NameID", Place::InsideNameId),
        ("beside a second signature", Place::WithDummy),
    ] {
        let mut misplaced = req.clone();
        misplaced.id = fresh_id();
        misplaced.place = place;
        let resp = send(
            &app,
            w.tenant_id,
            SamlBinding::HttpPost,
            "SAMLRequest",
            &misplaced.doc(),
            Sig::Sha256(sp_a_material()),
            None,
        )
        .await;
        assert_refused(resp, label).await;
        st.assert_untouched(&app, &w, label).await;
    }

    // A half signature: `SigAlg` and no `Signature`.
    let query = redirect_query(
        "SAMLRequest",
        &req.doc(),
        Sig::Sha256(sp_a_material()),
        None,
    );
    let half = query.split("&Signature=").next().unwrap().to_owned();
    let resp = deliver(&app, w.tenant_id, SamlBinding::HttpRedirect, half).await;
    assert_refused(resp, "a half signature").await;

    // An enveloped signature inside a Redirect-bound document.
    let enveloped = signed_xml(&req.doc(), Sig::Sha256(sp_a_material()));
    let query = format!("SAMLRequest={}", enc(&deflate_base64(enveloped.as_bytes())));
    let resp = deliver(&app, w.tenant_id, SamlBinding::HttpRedirect, query).await;
    assert_refused(resp, "an enveloped signature on the Redirect binding").await;

    // Both messages at once, and the wrong parameter for the kind.
    let resp = deliver(
        &app,
        w.tenant_id,
        SamlBinding::HttpRedirect,
        "SAMLRequest=x&SAMLResponse=y".to_owned(),
    )
    .await;
    assert_refused(resp, "both parameters").await;
    let resp = deliver(
        &app,
        w.tenant_id,
        SamlBinding::HttpRedirect,
        redirect_query(
            "SAMLResponse",
            &req.doc(),
            Sig::Sha256(sp_a_material()),
            None,
        ),
    )
    .await;
    assert_refused(resp, "a request in the response parameter").await;
    st.assert_untouched(&app, &w, "the wrong-place cases").await;
}

/// **T-371, acceptance: a replayed request `ID` is refused**, on both bindings —
/// and a replay never ends a session created after it, even when the replayed
/// message names no index.
#[actix_rt::test]
async fn a_replayed_request_id_is_refused_and_ends_no_later_session() {
    for binding in [SamlBinding::HttpRedirect, SamlBinding::HttpPost] {
        let w = world().await;
        register(&w, Sp::new("a", Some(binding))).await;
        let app = app!(w);
        let mut first = Browser::default();
        first.sign_in(&app, &w, "alice").await;
        let on = sign_on(&app, &mut first, &w, "a").await;

        let mut req = LogoutReq::new(&w, "a", &on);
        req.indexes.clear();
        let message = payload(
            binding,
            "SAMLRequest",
            &req.doc(),
            Sig::Sha256(sp_a_material()),
            None,
        );
        let resp = deliver(&app, w.tenant_id, binding, message.clone()).await;
        let out = outbound(resp, w.tenant_id).await;
        assert_eq!(status_codes(&out.xml), vec![SUCCESS.to_string()]);
        assert_eq!(first.me(&app).await, 401);

        // A new session, a new sign-on: the same pairwise NameID.
        let mut second = Browser::default();
        second.sign_in(&app, &w, "alice").await;
        let again = sign_on(&app, &mut second, &w, "a").await;
        assert_eq!(again.name_id, on.name_id);

        let replay = deliver(&app, w.tenant_id, binding, message).await;
        assert_refused(replay, "a replayed request ID").await;
        assert_eq!(
            second.me(&app).await,
            200,
            "the replay did not end the later session ({})",
            binding.as_str()
        );
    }
}

/// **Acceptance: refusals, fields.** A wrong `Destination`, none, a stale or
/// future `IssueInstant`, an expired `NotOnOrAfter`, an `EncryptedID` and a
/// `BaseID`, more than 32 `SessionIndex` values and an empty principal — each
/// refused, each properly signed, on both bindings.
#[actix_rt::test]
async fn field_level_refusals_hold_on_both_bindings() {
    for binding in [SamlBinding::HttpRedirect, SamlBinding::HttpPost] {
        let w = world().await;
        register(&w, Sp::new("a", Some(binding))).await;
        let app = app!(w);
        let st = standing(&app, &w).await;
        let base = LogoutReq::new(&w, "a", &st.on);

        let mut cases: Vec<(&str, LogoutReq)> = Vec::new();
        let mut wrong_destination = base.clone();
        wrong_destination.destination = Some(slo_url(w.other_tenant_id));
        cases.push(("a wrong Destination", wrong_destination));
        let mut no_destination = base.clone();
        no_destination.destination = None;
        cases.push(("no Destination", no_destination));
        let mut stale = base.clone();
        stale.issued_offset = -3600;
        cases.push(("a stale IssueInstant", stale));
        let mut future = base.clone();
        future.issued_offset = 3600;
        cases.push(("a future IssueInstant", future));
        let mut expired = base.clone();
        expired.not_on_or_after = Some("2001-01-01T00:00:00Z".into());
        cases.push(("an expired NotOnOrAfter", expired));
        let mut encrypted = base.clone();
        encrypted.principal_xml = Some(
            "<saml:EncryptedID><x:EncryptedData xmlns:x=\"http://www.w3.org/2001/04/xmlenc#\"/></saml:EncryptedID>"
                .into(),
        );
        cases.push(("an EncryptedID", encrypted));
        let mut base_id = base.clone();
        base_id.principal_xml = Some("<saml:BaseID>opaque</saml:BaseID>".into());
        cases.push(("a BaseID", base_id));
        let mut many = base.clone();
        many.indexes = (0..33).map(|i| format!("index-{i}")).collect();
        cases.push(("33 SessionIndex values", many));
        let mut empty = base.clone();
        empty.name_id = String::new();
        cases.push(("an empty NameID", empty));

        for (label, mut case) in cases {
            case.id = fresh_id();
            let resp = request_from(&app, &w, "a", binding, &case, None).await;
            let label = format!("{label} ({})", binding.as_str());
            assert_refused(resp, &label).await;
            st.assert_untouched(&app, &w, &label).await;
        }
        // The control: 32 indexes, the right destination, are accepted.
        let mut thirty_two = base.clone();
        thirty_two.id = fresh_id();
        thirty_two.indexes = (0..31)
            .map(|i| format!("index-{i}"))
            .chain([st.on.index.clone()])
            .collect();
        let resp = request_from(&app, &w, "a", binding, &thirty_two, None).await;
        let out = outbound(resp, w.tenant_id).await;
        assert_eq!(status_codes(&out.xml), vec![SUCCESS.to_string()]);
        assert_eq!(st.alice.me(&app).await, 401, "32 indexes are served");
    }
}

/// **Acceptance: an SP without a certificate cannot initiate** — signed with
/// somebody's key or not at all — and neither can a disabled one or an unknown
/// issuer.
#[actix_rt::test]
async fn an_sp_without_a_certificate_a_disabled_sp_and_an_unknown_issuer_cannot_initiate() {
    let w = world().await;
    register(&w, Sp::new("c", Some(SamlBinding::HttpPost))).await;
    let a = register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_c = sign_on(&app, &mut alice, &w, "c").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;

    let from_c = LogoutReq::new(&w, "c", &on_c);
    for (label, sig) in [
        ("unsigned", Sig::Unsigned),
        (
            "signed with a stranger's key",
            Sig::Sha256(stranger_material()),
        ),
    ] {
        for binding in [SamlBinding::HttpRedirect, SamlBinding::HttpPost] {
            let mut req = from_c.clone();
            req.id = fresh_id();
            let resp = send(
                &app,
                w.tenant_id,
                binding,
                "SAMLRequest",
                &req.doc(),
                sig,
                None,
            )
            .await;
            assert_refused(resp, &format!("{label}, no certificate registered")).await;
        }
    }

    // Disabled: its own valid signature ends nothing.
    let mut input = Sp::new("a", Some(SamlBinding::HttpRedirect)).input();
    input.enabled = false;
    SurrealSamlServiceProviderRepository::new(w.db.clone())
        .update(w.tenant_id, a, input)
        .await
        .unwrap();
    let resp = request_from(
        &app,
        &w,
        "a",
        SamlBinding::HttpRedirect,
        &LogoutReq::new(&w, "a", &on_a),
        None,
    )
    .await;
    assert_refused(resp, "a disabled SP").await;

    // An issuer nobody registered.
    let mut unknown = LogoutReq::new(&w, "a", &on_a);
    unknown.issuer = entity("zzz");
    let resp = send(
        &app,
        w.tenant_id,
        SamlBinding::HttpRedirect,
        "SAMLRequest",
        &unknown.doc(),
        Sig::Sha256(sp_a_material()),
        None,
    )
    .await;
    assert_refused(resp, "an unknown issuer").await;

    assert_eq!(alice.me(&app).await, 200, "nothing ended");
    assert_eq!(participants(&w).await.len(), 2);
    assert!(runs(&w).await.is_empty());
}

/// **T-375, acceptance.** A message that names another location — in its
/// extensions, in its `RelayState`, in a query parameter of the trigger — is
/// answered at the SP's registered `slo_url` on its registered binding, and the
/// trigger ends on AXIAM's own page with no redirect to anywhere: the destination
/// is never read from a message.
#[actix_rt::test]
async fn a_message_naming_another_location_is_answered_at_the_registered_one() {
    let evil = "https://evil.example.test";
    for binding in [SamlBinding::HttpRedirect, SamlBinding::HttpPost] {
        let w = world().await;
        register(&w, Sp::new("a", Some(binding))).await;
        let app = app!(w);
        let mut alice = Browser::default();
        alice.sign_in(&app, &w, "alice").await;
        let on = sign_on(&app, &mut alice, &w, "a").await;
        let mut req = LogoutReq::new(&w, "a", &on);
        req.extensions = Some(format!(
            r#"<samlp:Extensions><x:ReplyTo xmlns:x="urn:evil">{evil}/steal</x:ReplyTo></samlp:Extensions>"#
        ));
        let relay = format!("{evil}/redirect");
        let resp = request_from(&app, &w, "a", binding, &req, Some(&relay)).await;
        let out = outbound(resp, w.tenant_id).await;
        assert_eq!(out.destination, sp_slo("a"), "the registered endpoint");
        assert_eq!(out.binding, binding, "the registered binding");
        assert!(!out.xml.contains("evil.example.test"));
        if binding == SamlBinding::HttpPost {
            assert!(
                out.policy
                    .contains("form-action https://sp-a.example.test;")
                    && !out.policy.contains("evil.example.test"),
                "the form can post to the registered origin only"
            );
        }
    }
}

/// **T-375, the trigger.** Query parameters that name a place to go are not read:
/// the first hop goes to the registered endpoint and the chain ends on AXIAM's own
/// page, with no redirect anywhere.
#[actix_rt::test]
async fn the_trigger_reads_no_destination_from_its_query() {
    let evil = "https://evil.example.test";
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let _on = sign_on(&app, &mut alice, &w, "a").await;
    let uri = format!(
        "{}?post_logout_redirect_uri={}&RelayState={}&redirect_uri={}",
        trigger_uri(&w),
        enc(&format!("{evil}/x")),
        enc(&format!("{evil}/y")),
        enc(&format!("{evil}/z"))
    );
    let resp = alice.get(&app, &uri).await;
    let to_a = outbound(resp, w.tenant_id).await;
    assert_eq!(
        to_a.destination,
        sp_slo("a"),
        "only the registered endpoint"
    );
    assert!(
        to_a.relay.is_none(),
        "no RelayState is made up from a parameter"
    );
    let answered = answer(
        &app,
        &w,
        &to_a,
        "a",
        SUCCESS,
        None,
        Sig::Sha256(sp_a_material()),
        SamlBinding::HttpRedirect,
    )
    .await;
    assert_eq!(answered.status().as_u16(), 200, "AXIAM's own page");
    assert!(answered.headers().get("location").is_none());
    let page = body_of(answered).await;
    assert!(page.contains("You are signed out") && !page.contains("evil.example.test"));
}

/// **T-372.** A DTD, an entity and a decompression bomb are refused before any
/// lookup, on both bindings.
#[actix_rt::test]
async fn xxe_and_a_decompression_bomb_are_refused_before_any_lookup() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpPost))).await;
    let app = app!(w);
    let st = standing(&app, &w).await;

    let xxe = format!(
        r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x" Version="2.0" IssueInstant="{}">&x;</samlp:LogoutRequest>"#,
        at(0)
    );
    let resp = deliver(
        &app,
        w.tenant_id,
        SamlBinding::HttpPost,
        post_body("SAMLRequest", &xxe, None),
    )
    .await;
    assert_refused(resp, "an external entity (POST)").await;
    let resp = deliver(
        &app,
        w.tenant_id,
        SamlBinding::HttpRedirect,
        format!("SAMLRequest={}", enc(&deflate_base64(xxe.as_bytes()))),
    )
    .await;
    assert_refused(resp, "an external entity (Redirect)").await;

    let bomb = deflate_base64(&vec![0u8; 16 * 1024 * 1024]);
    let resp = deliver(
        &app,
        w.tenant_id,
        SamlBinding::HttpRedirect,
        format!("SAMLRequest={}", enc(&bomb)),
    )
    .await;
    assert_refused(resp, "a decompression bomb").await;
    st.assert_untouched(&app, &w, "the XML attacks").await;
}

// ---------------------------------------------------------------------------
// 4. Propagation
// ---------------------------------------------------------------------------

async fn audit_rows(w: &World) -> Vec<serde_json::Value> {
    let mut result =
        w.db.query("SELECT * FROM audit_log WHERE action = 'saml_idp.logout'")
            .await
            .unwrap();
    result.take(0).unwrap()
}

fn sha256_hex(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// **Acceptance: propagation.** Session revoked first; then the other SPs
/// receive signed `LogoutRequest`s in sequence, each on its registered binding
/// (a detached query signature on Redirect, an enveloped one on POST, through the
/// shared auto-post page), carrying its own `NameID` and `SessionIndex`; the
/// chain advances on each answer; an SP with no certificate may answer unsigned
/// and an SP with no endpoint is skipped, both making the run partial; and the
/// run ends with a signed `PartialLogout` to the initiator.
#[actix_rt::test]
async fn the_other_sps_receive_signed_logout_requests_in_sequence_and_a_partial_run_ends_in_partial_logout()
 {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    register(&w, Sp::new("b", Some(SamlBinding::HttpRedirect))).await;
    register(&w, Sp::new("c", Some(SamlBinding::HttpPost))).await;
    register(&w, Sp::new("d", None)).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;
    let on_b = sign_on(&app, &mut alice, &w, "b").await;
    let on_c = sign_on(&app, &mut alice, &w, "c").await;
    let on_d = sign_on(&app, &mut alice, &w, "d").await;
    let session = the_session(&w).await;

    let req = LogoutReq::new(&w, "a", &on_a);
    let first = request_from(
        &app,
        &w,
        "a",
        SamlBinding::HttpRedirect,
        &req,
        Some("relay-a"),
    )
    .await;
    let to_b = outbound(first, w.tenant_id).await;

    // Revoked first: the AXIAM session is gone before any other SP is told.
    assert!(!session_alive(&w, w.tenant_id, session).await);
    assert_eq!(alice.me(&app).await, 401);

    // Hop one: SP B, on its registered Redirect binding, with its own principal.
    assert!(is_logout_request(&to_b));
    assert_eq!(to_b.binding, SamlBinding::HttpRedirect);
    assert_eq!(to_b.destination, sp_slo("b"));
    assert_eq!(attr(&to_b.xml, "Destination"), Some(sp_slo("b")));
    let id_b = message_id(&to_b);
    assert!(id_b.starts_with('_') && id_b.len() == 65, "256 random bits");
    assert!(
        to_b.xml
            .contains(&format!(">{}</saml:NameID>", on_b.name_id))
    );
    assert!(
        to_b.xml
            .contains(&format!(">{}</samlp:SessionIndex>", on_b.index))
    );
    assert!(
        !to_b.xml.contains(&on_a.index) && !to_b.xml.contains(&on_c.index),
        "it carries its own SessionIndex and nobody else's"
    );
    assert!(
        to_b.relay.is_none(),
        "the initiator's RelayState goes to the initiator only"
    );
    assert_signed_by_idp(&to_b);
    assert!(
        to_b.cleared,
        "every answer to a verified message clears the cookies"
    );
    let state = runs(&w).await;
    assert_eq!(
        state[0]["queue"].as_array().unwrap().len(),
        2,
        "C and D remain"
    );
    assert_eq!(state[0]["sps_told"], 1);
    assert_eq!(
        state[0]["current_request_hash"],
        sha256_hex(&id_b),
        "the run holds the digest of the outbound ID"
    );
    assert!(
        !serde_json::to_string(&state).unwrap().contains(&id_b),
        "and never the ID itself (T-383)"
    );
    assert_eq!(
        participants(&w).await.len(),
        4,
        "the rows stay while the chain runs"
    );

    // Hop two: SP C, on POST, enveloped, through the shared auto-post page.
    let answered_b = answer(
        &app,
        &w,
        &to_b,
        "b",
        SUCCESS,
        None,
        Sig::Sha256(sp_b_material()),
        SamlBinding::HttpRedirect,
    )
    .await;
    let to_c = outbound(answered_b, w.tenant_id).await;
    assert!(is_logout_request(&to_c));
    assert_eq!(to_c.binding, SamlBinding::HttpPost);
    assert_eq!(to_c.destination, sp_slo("c"));
    assert_signed_by_idp(&to_c);
    assert!(
        to_c.policy
            .contains("form-action https://sp-c.example.test;")
            && to_c.policy.contains("script-src 'nonce-")
            && to_c.policy.contains("default-src 'none'"),
        "the one auto-post policy, form-action the slo_url's origin"
    );
    assert!(
        to_c.xml
            .contains(&format!(">{}</samlp:SessionIndex>", on_c.index))
    );

    // SP C registered no certificate: its answer advances the chain unsigned.
    // SP D has no endpoint: skipped. The run is partial, and ends.
    let answered_c = answer(
        &app,
        &w,
        &to_c,
        "c",
        SUCCESS,
        None,
        Sig::Unsigned,
        SamlBinding::HttpPost,
    )
    .await;
    let last = outbound(answered_c, w.tenant_id).await;
    assert_eq!(last.field, "SAMLResponse");
    assert_eq!(
        last.binding,
        SamlBinding::HttpRedirect,
        "A's registered binding"
    );
    assert_eq!(
        last.destination,
        sp_slo("a"),
        "only ever A's registered endpoint"
    );
    assert_eq!(attr(&last.xml, "InResponseTo"), Some(req.id.clone()));
    assert_eq!(last.relay.as_deref(), Some("relay-a"), "echoed to A");
    assert_eq!(
        status_codes(&last.xml),
        vec![SUCCESS.to_string(), PARTIAL.to_string()],
        "PartialLogout: C answered unsigned, D has no endpoint"
    );
    assert_signed_by_idp(&last);
    assert!(last.cleared);

    assert!(
        participants(&w).await.is_empty(),
        "the chain ended: the rows are deleted"
    );
    let state = runs(&w).await;
    assert_eq!(state[0]["status"], "finished");
    assert_eq!(state[0]["partial"], true);
    assert_eq!(state[0]["sps_told"], 2);

    // One audit row when the sessions ended and one when the chain did, and no
    // NameID, SessionIndex or session id in either (T-376).
    let rows = audit_rows(&w).await;
    assert_eq!(rows.len(), 2);
    let phases: Vec<&str> = rows
        .iter()
        .map(|r| r["metadata"]["phase"].as_str().unwrap())
        .collect();
    assert!(phases.contains(&"sessions_ended") && phases.contains(&"completed"));
    let text = serde_json::to_string(&rows).unwrap();
    for needle in [
        on_a.name_id.as_str(),
        on_a.index.as_str(),
        on_b.index.as_str(),
        on_c.index.as_str(),
        on_d.index.as_str(),
    ] {
        assert!(
            !text.contains(needle),
            "the audit rows carry no NameID or index"
        );
    }
    let completed = rows
        .iter()
        .find(|r| r["metadata"]["phase"] == "completed")
        .unwrap();
    assert_eq!(completed["metadata"]["outcome"], "partial_logout");
    assert_eq!(completed["metadata"]["sessions_ended"], 1);
    assert_eq!(completed["metadata"]["sps_told"], 2);
}

/// **Acceptance: the full run ends in `Success`** to the initiator, on POST at
/// both ends.
#[actix_rt::test]
async fn a_full_run_ends_in_success_to_the_initiator() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpPost))).await;
    register(&w, Sp::new("e", Some(SamlBinding::HttpPost))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;
    let _on_e = sign_on(&app, &mut alice, &w, "e").await;

    let req = LogoutReq::new(&w, "a", &on_a);
    let first = request_from(&app, &w, "a", SamlBinding::HttpPost, &req, Some("rs")).await;
    let to_e = outbound(first, w.tenant_id).await;
    assert_eq!(to_e.binding, SamlBinding::HttpPost);
    assert_eq!(to_e.destination, sp_slo("e"));
    assert_signed_by_idp(&to_e);

    let answered = answer(
        &app,
        &w,
        &to_e,
        "e",
        SUCCESS,
        None,
        Sig::Sha256(sp_e_material()),
        SamlBinding::HttpPost,
    )
    .await;
    let last = outbound(answered, w.tenant_id).await;
    assert_eq!(last.destination, sp_slo("a"));
    assert_eq!(
        status_codes(&last.xml),
        vec![SUCCESS.to_string()],
        "no PartialLogout"
    );
    assert_eq!(attr(&last.xml, "InResponseTo"), Some(req.id));
    assert_eq!(last.relay.as_deref(), Some("rs"));
    assert_signed_by_idp(&last);
    let state = runs(&w).await;
    assert_eq!(state[0]["partial"], false);
    assert_eq!(state[0]["sps_told"], 1);
    let completed = audit_rows(&w)
        .await
        .into_iter()
        .find(|r| r["metadata"]["phase"] == "completed")
        .unwrap();
    assert_eq!(completed["metadata"]["outcome"], "success");
}

/// **Acceptance: the partial cases.** A signed non-`Success` answer and a signed
/// `PartialLogout` end the run `PartialLogout`; an unsigned answer from an SP
/// that registered a certificate, and a wrong-key one, are refused without
/// consuming the request — the SP can still answer properly, and the run then
/// ends in `Success`.
#[actix_rt::test]
async fn non_success_answers_make_the_run_partial_and_unverified_ones_are_refused_unconsumed() {
    // (label, signature, status, nested, refused first)
    /// (label, signature material, status, nested status, refused first)
    type Case<'a> = (
        &'a str,
        Option<&'a Material>,
        &'a str,
        Option<&'a str>,
        bool,
    );
    let cases: [Case<'_>; 4] = [
        (
            "a signed Responder status",
            Some(sp_b_material()),
            RESPONDER,
            None,
            false,
        ),
        (
            "a signed PartialLogout",
            Some(sp_b_material()),
            SUCCESS,
            Some(PARTIAL),
            false,
        ),
        (
            "an unsigned answer from an SP with a certificate",
            None,
            SUCCESS,
            None,
            true,
        ),
        (
            "an answer signed with the wrong key",
            Some(stranger_material()),
            SUCCESS,
            None,
            true,
        ),
    ];
    for (label, material, status, nested, refused_first) in cases {
        let w = world().await;
        register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
        register(&w, Sp::new("b", Some(SamlBinding::HttpRedirect))).await;
        let app = app!(w);
        let mut alice = Browser::default();
        alice.sign_in(&app, &w, "alice").await;
        let on_a = sign_on(&app, &mut alice, &w, "a").await;
        let _on_b = sign_on(&app, &mut alice, &w, "b").await;
        let req = LogoutReq::new(&w, "a", &on_a);
        let first = request_from(&app, &w, "a", SamlBinding::HttpRedirect, &req, None).await;
        let to_b = outbound(first, w.tenant_id).await;

        let sig = material.map_or(Sig::Unsigned, Sig::Sha256);
        let resp = answer(
            &app,
            &w,
            &to_b,
            "b",
            status,
            nested,
            sig,
            SamlBinding::HttpRedirect,
        )
        .await;
        let last = if refused_first {
            assert_refused(resp, label).await;
            let state = runs(&w).await;
            assert_eq!(state[0]["status"], "active", "{label}: the chain waits");
            assert_eq!(
                state[0]["current_request_hash"],
                sha256_hex(&message_id(&to_b)),
                "{label}: the request was not consumed"
            );
            // The SP can still answer properly.
            let proper = answer(
                &app,
                &w,
                &to_b,
                "b",
                SUCCESS,
                None,
                Sig::Sha256(sp_b_material()),
                SamlBinding::HttpRedirect,
            )
            .await;
            let last = outbound(proper, w.tenant_id).await;
            assert_eq!(
                status_codes(&last.xml),
                vec![SUCCESS.to_string()],
                "{label}: a proper answer completes the run"
            );
            last
        } else {
            let last = outbound(resp, w.tenant_id).await;
            assert_eq!(
                status_codes(&last.xml),
                vec![SUCCESS.to_string(), PARTIAL.to_string()],
                "{label}: the run is partial"
            );
            last
        };
        assert_signed_by_idp(&last);
        assert_eq!(last.destination, sp_slo("a"), "{label}");
    }
}

/// **Acceptance: a replayed or foreign `InResponseTo` is refused.** Another SP —
/// with a valid signature of its own — cannot answer a request that went to
/// someone else; an unknown id matches nothing; and an answer is consumed once,
/// so a replay of it is refused after the chain has moved on and after it has
/// ended.
#[actix_rt::test]
async fn a_replayed_or_foreign_in_response_to_is_refused() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    register(&w, Sp::new("b", Some(SamlBinding::HttpRedirect))).await;
    register(&w, Sp::new("e", Some(SamlBinding::HttpPost))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;
    let _on_b = sign_on(&app, &mut alice, &w, "b").await;
    let _on_e = sign_on(&app, &mut alice, &w, "e").await;

    let req = LogoutReq::new(&w, "a", &on_a);
    let first = request_from(&app, &w, "a", SamlBinding::HttpRedirect, &req, None).await;
    let to_b = outbound(first, w.tenant_id).await;
    let waiting = sha256_hex(&message_id(&to_b));

    // Foreign: SP E, validly signed, names the request that went to B.
    let foreign = answer(
        &app,
        &w,
        &to_b,
        "e",
        SUCCESS,
        None,
        Sig::Sha256(sp_e_material()),
        SamlBinding::HttpPost,
    )
    .await;
    assert_refused(foreign, "an answer from the wrong SP").await;
    // Unknown: B, validly signed, names an id AXIAM never sent.
    let unknown = send(
        &app,
        w.tenant_id,
        SamlBinding::HttpRedirect,
        "SAMLResponse",
        &response_doc(
            "_never-sent-by-axiam",
            &entity("b"),
            Some(slo_url(w.tenant_id)),
            SUCCESS,
            None,
        ),
        Sig::Sha256(sp_b_material()),
        None,
    )
    .await;
    assert_refused(unknown, "an unknown InResponseTo").await;
    assert_eq!(
        runs(&w).await[0]["current_request_hash"],
        waiting,
        "neither refusal consumed the request"
    );

    // B answers: the chain moves to E.
    let proper = answer(
        &app,
        &w,
        &to_b,
        "b",
        SUCCESS,
        None,
        Sig::Sha256(sp_b_material()),
        SamlBinding::HttpRedirect,
    )
    .await;
    let to_e = outbound(proper, w.tenant_id).await;
    assert_eq!(to_e.destination, sp_slo("e"));

    // A replay of B's answer: consumed already.
    let replay = answer(
        &app,
        &w,
        &to_b,
        "b",
        SUCCESS,
        None,
        Sig::Sha256(sp_b_material()),
        SamlBinding::HttpRedirect,
    )
    .await;
    assert_refused(replay, "a replayed InResponseTo").await;
    assert_eq!(
        runs(&w).await[0]["current_request_hash"],
        sha256_hex(&message_id(&to_e)),
        "the chain still waits for E"
    );

    // E answers and the run ends; a replay of E's answer is refused too.
    let done = answer(
        &app,
        &w,
        &to_e,
        "e",
        SUCCESS,
        None,
        Sig::Sha256(sp_e_material()),
        SamlBinding::HttpPost,
    )
    .await;
    let last = outbound(done, w.tenant_id).await;
    assert_eq!(status_codes(&last.xml), vec![SUCCESS.to_string()]);
    let again = answer(
        &app,
        &w,
        &to_e,
        "e",
        SUCCESS,
        None,
        Sig::Sha256(sp_e_material()),
        SamlBinding::HttpPost,
    )
    .await;
    assert_refused(again, "a replay after the run ended").await;
}

/// **T-374.** A run tells at most 32 SPs: a session that took part in more is
/// told 32 and the run is partial from the start.
#[actix_rt::test]
async fn a_run_is_capped_at_32_service_providers_and_is_partial_past_it() {
    use axiam_core::models::saml_slo::NewSamlSpSession;
    use axiam_core::repository::SamlSpSessionRepository;

    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let on_a = sign_on(&app, &mut alice, &w, "a").await;
    let session = the_session(&w).await;
    let user_id = w
        .state
        .session_repo
        .get_by_id(w.tenant_id, session)
        .await
        .unwrap()
        .user_id;
    for n in 0..33 {
        let sp = register(
            &w,
            Sp::new(format!("s{n}"), Some(SamlBinding::HttpRedirect)),
        )
        .await;
        w.state
            .saml_idp
            .participant_repo
            .record(NewSamlSpSession {
                tenant_id: w.tenant_id,
                session_id: session,
                user_id,
                sp_id: sp,
                sp_entity_id: entity(&format!("s{n}")),
                name_id: format!("name-{n}"),
                name_id_format: PERSISTENT.into(),
                session_index: format!("index-{n}-{}", Uuid::new_v4().simple()),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            })
            .await
            .unwrap();
    }

    let req = LogoutReq::new(&w, "a", &on_a);
    let resp = request_from(&app, &w, "a", SamlBinding::HttpRedirect, &req, None).await;
    let out = outbound(resp, w.tenant_id).await;
    assert!(is_logout_request(&out), "the first of the 32 is on its way");
    let state = runs(&w).await;
    assert_eq!(
        state[0]["queue"].as_array().unwrap().len(),
        31,
        "32 are taken, one is in flight"
    );
    assert_eq!(state[0]["partial"], true, "past the cap the run is partial");
    assert_eq!(state[0]["sps_told"], 1);
}

// ---------------------------------------------------------------------------
// 5. The IdP-initiated trigger
// ---------------------------------------------------------------------------

fn trigger_uri(w: &World) -> String {
    format!("{}/logout", sso_path(w.tenant_id))
}

/// **Acceptance: the IdP-initiated trigger** revokes the browser's session,
/// clears its cookies, propagates to the SPs that hold it on their registered
/// bindings, and ends on AXIAM's own logged-out page — signing nothing for
/// anyone at the end.
#[actix_rt::test]
async fn the_idp_initiated_trigger_revokes_clears_the_cookies_and_propagates() {
    use axiam_core::revocation_feed::revocation_hash;

    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    register(&w, Sp::new("c", Some(SamlBinding::HttpPost))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let _on_a = sign_on(&app, &mut alice, &w, "a").await;
    let _on_c = sign_on(&app, &mut alice, &w, "c").await;
    let session = the_session(&w).await;
    assert_eq!(alice.me(&app).await, 200);

    let resp = alice
        .get_with(&app, &trigger_uri(&w), &[("Sec-Fetch-Site", "same-origin")])
        .await;
    let to_a = outbound(resp, w.tenant_id).await;
    assert!(is_logout_request(&to_a));
    assert_eq!(to_a.destination, sp_slo("a"));
    assert_eq!(to_a.binding, SamlBinding::HttpRedirect);
    assert_signed_by_idp(&to_a);
    assert!(to_a.cleared, "the trigger clears every cookie");
    assert!(
        alice.op_cookie().is_none(),
        "the browser's own jar lost its OP cookie"
    );
    assert!(!session_alive(&w, w.tenant_id, session).await);
    assert!(feed(&app).await.contains(&revocation_hash(session)));
    assert_eq!(alice.me(&app).await, 401);

    let answered_a = answer(
        &app,
        &w,
        &to_a,
        "a",
        SUCCESS,
        None,
        Sig::Sha256(sp_a_material()),
        SamlBinding::HttpRedirect,
    )
    .await;
    let to_c = outbound(answered_a, w.tenant_id).await;
    assert_eq!(to_c.destination, sp_slo("c"));
    assert_eq!(to_c.binding, SamlBinding::HttpPost);
    assert_signed_by_idp(&to_c);

    // C (no certificate) answers unsigned: the chain ends, on AXIAM's own page.
    let answered_c = answer(
        &app,
        &w,
        &to_c,
        "c",
        SUCCESS,
        None,
        Sig::Unsigned,
        SamlBinding::HttpPost,
    )
    .await;
    assert_eq!(answered_c.status().as_u16(), 200);
    assert!(clears_every_cookie(&answered_c, w.tenant_id));
    let page = body_of(answered_c).await;
    assert!(
        page.contains("You are signed out"),
        "AXIAM's logged-out page"
    );
    assert!(
        !page.contains("<form") && !page.contains("SAMLRe"),
        "nothing is posted or signed at the end"
    );
    let state = runs(&w).await;
    assert_eq!(state[0]["status"], "finished");
    assert!(participants(&w).await.is_empty());
    let completed = audit_rows(&w)
        .await
        .into_iter()
        .find(|r| r["metadata"]["phase"] == "completed")
        .unwrap();
    assert_eq!(completed["metadata"]["initiator"], "idp");
}

/// **T-378.** A cross-site trigger is `403` and changes nothing; with no cookie
/// the trigger clears and shows the page; another tenant's cookie names nothing
/// here.
#[actix_rt::test]
async fn the_trigger_refuses_cross_site_and_resolves_the_cookie_in_its_own_tenant_only() {
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    let app = app!(w);
    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let _on_a = sign_on(&app, &mut alice, &w, "a").await;

    // Cross-site: refused, nothing ended, nothing cleared.
    let resp = alice
        .get_with(&app, &trigger_uri(&w), &[("Sec-Fetch-Site", "cross-site")])
        .await;
    assert_refused(resp, "a cross-site trigger").await;
    assert_eq!(alice.me(&app).await, 200, "the session is untouched");
    assert!(alice.op_cookie().is_some());
    assert_eq!(participants(&w).await.len(), 1);
    assert!(runs(&w).await.is_empty());

    // No cookie: the cookies are cleared and the page shown; nothing else.
    let mut nobody = Browser::default();
    let resp = nobody.get(&app, &trigger_uri(&w)).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(clears_every_cookie(&resp, w.tenant_id));
    assert!(body_of(resp).await.contains("You are signed out"));
    assert!(runs(&w).await.is_empty(), "no session, no run");

    // Another tenant's OP cookie, presented here: the tenant-keyed lookup finds
    // no session, so nothing in either tenant ends.
    let mut bob = Browser::default();
    bob.sign_in_to(&app, &w, w.other_tenant_id, "bob").await;
    let resp = bob.get(&app, &trigger_uri(&w)).await;
    assert_eq!(resp.status().as_u16(), 200);
    assert!(runs(&w).await.is_empty());
    assert_eq!(bob.me(&app).await, 200, "bob's session is untouched");
    assert_eq!(alice.me(&app).await, 200, "and so is alice's");
}

// ---------------------------------------------------------------------------
// 6. D-20, the buckets, and the request log
// ---------------------------------------------------------------------------

/// **Acceptance: D-20.** The `404`s on `/slo` and `/sso/logout` are
/// indistinguishable — from an unmounted path and from each other — whether the
/// tenant is unknown, malformed, spelled non-canonically or has SAML off, and on
/// every method.
#[actix_rt::test]
async fn slo_and_the_logout_trigger_answer_an_indistinguishable_404_when_saml_is_off() {
    use axiam_core::models::settings::SetTenantOverride;
    let w = world().await;
    register(&w, Sp::new("a", Some(SamlBinding::HttpRedirect))).await;
    SurrealSettingsRepository::new(w.db.clone())
        .set_tenant_override(
            w.tenant_id,
            SetTenantOverride {
                saml_idp_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let app = app!(w);

    let call = |method: actix_web::http::Method, uri: String| {
        test::TestRequest::default()
            .method(method)
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&uri)
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload("SAMLRequest=x")
            .to_request()
    };
    let fingerprint = |resp: &actix_web::dev::ServiceResponse| {
        let mut headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .filter(|(k, _)| k.as_str() != "date")
            .map(|(k, v)| {
                (
                    k.as_str().to_owned(),
                    v.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        headers.sort();
        (resp.status().as_u16(), headers)
    };

    let unmounted = test::call_service(
        &app,
        call(actix_web::http::Method::GET, "/saml/v3/nothing/here".into()),
    )
    .await;
    let expected = fingerprint(&unmounted);
    assert_eq!(expected.0, 404);
    assert!(test::read_body(unmounted).await.is_empty());

    let doc = LogoutReq::new(
        &w,
        "a",
        &SignedOn {
            index: "i".into(),
            name_id: "n".into(),
        },
    )
    .doc();
    let query = redirect_query("SAMLRequest", &doc, Sig::Sha256(sp_a_material()), None);
    let upper = w.tenant_id.to_string().to_uppercase();
    for tenant in [
        w.tenant_id.to_string(),
        Uuid::new_v4().to_string(),
        upper,
        "not-a-uuid".into(),
    ] {
        for (method, uri) in [
            (
                actix_web::http::Method::GET,
                format!("/saml/v2/{tenant}/slo?{query}"),
            ),
            (
                actix_web::http::Method::POST,
                format!("/saml/v2/{tenant}/slo"),
            ),
            (
                actix_web::http::Method::PUT,
                format!("/saml/v2/{tenant}/slo"),
            ),
            (
                actix_web::http::Method::DELETE,
                format!("/saml/v2/{tenant}/slo"),
            ),
            (
                actix_web::http::Method::HEAD,
                format!("/saml/v2/{tenant}/slo"),
            ),
            (
                actix_web::http::Method::GET,
                format!("/saml/v2/{tenant}/sso/logout"),
            ),
            (
                actix_web::http::Method::POST,
                format!("/saml/v2/{tenant}/sso/logout"),
            ),
            (
                actix_web::http::Method::GET,
                format!("/saml/v2/{tenant}/slo/extra"),
            ),
        ] {
            let resp = test::call_service(&app, call(method.clone(), uri.clone())).await;
            assert_eq!(
                fingerprint(&resp),
                expected,
                "{method} on a SAML logout route"
            );
            assert!(test::read_body(resp).await.is_empty());
        }
    }
    assert!(runs(&w).await.is_empty());
}

/// **§7 rule 6, `saml_idp_slo`.** The SLO route is covered by its own bucket of
/// the browser-endpoint preset, on both methods.
#[actix_rt::test]
async fn the_slo_route_is_rate_limited() {
    let w = world().await;
    let limits = RateLimitConfig {
        end_session_per_min: 1,
        ..RateLimitConfig::default()
    };
    let app = app!(w, limits);
    let path = slo_path(w.tenant_id);
    let first = Browser::default()
        .get(&app, &format!("{path}?SAMLRequest=x"))
        .await;
    assert_ne!(first.status().as_u16(), 429, "the first request is served");
    let second = Browser::default()
        .get(&app, &format!("{path}?SAMLRequest=x"))
        .await;
    assert_eq!(second.status().as_u16(), 429, "the second is limited");
}

/// **§7 rule 6, `saml_idp_sso_logout`.** The trigger is covered by a bucket of
/// its own, separate from `/slo`'s.
#[actix_rt::test]
async fn the_logout_trigger_is_rate_limited_in_a_bucket_of_its_own() {
    let w = world().await;
    let limits = RateLimitConfig {
        end_session_per_min: 1,
        ..RateLimitConfig::default()
    };
    let app = app!(w, limits);
    let first = Browser::default().get(&app, &trigger_uri(&w)).await;
    assert_ne!(first.status().as_u16(), 429, "the first request is served");
    let second = Browser::default().get(&app, &trigger_uri(&w)).await;
    assert_eq!(second.status().as_u16(), 429, "the second is limited");
    // The SLO bucket is untouched by the trigger's.
    let slo = Browser::default()
        .get(&app, &format!("{}?SAMLRequest=x", slo_path(w.tenant_id)))
        .await;
    assert_ne!(slo.status().as_u16(), 429, "/slo has its own allowance");
}

/// **T-377.** The request tracer records `/slo`'s target with every message
/// parameter redacted: nothing a message, a relay state or a signature carries
/// reaches the log.
#[actix_rt::test]
async fn the_request_log_records_no_message_parameter_of_slo() {
    use std::sync::Mutex;

    use axiam_api_rest::middleware::request_span::RedactingRootSpanBuilder;
    use tracing_actix_web::TracingLogger;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = world().await;
    let auth = auth_config();
    // An event of this test's own, inside the request span: the fmt layer prints a
    // span's fields on the events recorded under it, and an event whose callsite
    // another test of this binary already hit with no subscriber installed would
    // be cached as disabled.
    use actix_web::dev::Service as _;
    let app = test::init_service(
        App::new()
            .wrap_fn(|req, srv| {
                tracing::info!("inside the request");
                srv.call(req)
            })
            .wrap(TracingLogger::<RedactingRootSpanBuilder>::new())
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(w.state.clone()))
            .app_data(web::Data::new(
                Arc::new(SurrealTenantRepository::new(w.db.clone()))
                    as Arc<dyn axiam_api_rest::TenantScopeResolver>,
            ))
            .configure(|cfg| {
                register_api_v1_routes_with::<TestDb>(
                    cfg,
                    &permissive_limits(),
                    RouteOptions::default(),
                )
            }),
    )
    .await;

    let message = "probe-message-0123456789";
    let relay = "probe-relay-0123456789";
    let signature = "probe-signature-0123456789";
    for param in ["SAMLRequest", "SAMLResponse"] {
        let uri = format!(
            "{}?{param}={message}&RelayState={relay}&SigAlg=alg&Signature={signature}",
            slo_path(w.tenant_id)
        );
        let resp = test::call_service(
            &app,
            test::TestRequest::get()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri(&uri)
                .to_request(),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 400, "refused, and recorded");
    }
    let log = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("inside the request"), "the event was recorded");
    assert!(log.contains("SAMLRequest=[redacted]"));
    assert!(log.contains("SAMLResponse=[redacted]"));
    assert!(log.contains("RelayState=[redacted]"));
    assert!(log.contains("Signature=[redacted]"));
    for probe in [message, relay, signature] {
        assert!(!log.contains(probe), "a message parameter reached the log");
    }
}

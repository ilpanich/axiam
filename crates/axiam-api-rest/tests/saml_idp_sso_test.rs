//! **T23.2.3** — the SAML 2.0 IdP SSO endpoint over HTTP (G-2).
//!
//! Every acceptance row of the task, driven through the real routes, the real
//! login endpoint and the real repositories:
//!
//! * SP-initiated sign-on end to end on both bindings, through the login hop,
//!   the response verified by xmlsec against the tenant's credential and by
//!   AXIAM's own SP verifier;
//! * IdP-initiated for an SP that opted in, refused for one that has not and
//!   for a cross-site trigger;
//! * a replayed `AuthnRequest` ID, a second use of the pending handle, a handle
//!   from another browser; an ACS URL or index outside the registry; a
//!   `Destination` mismatch; missing, bad and wrong-key signatures on both
//!   bindings for an SP that signs;
//! * `IsPassive` with and without a session; `ForceAuthn` bound to the request
//!   (a pre-existing session plus a forged hop marker yields no assertion);
//!   `allowed_groups`; a suspended account and a `PendingVerification` one;
//! * D-20's indistinguishable `404`; the OP cookie read only through the
//!   tenant-keyed lookup, in both directions; XXE and the decompression bomb
//!   over HTTP; the rate-limit bucket.
//!
//! Every pre-hop refusal is asserted with [`assert_no_hop`]: no redirect to
//! the sign-in page and no pending request created. Keys and certificates are
//! generated at runtime; no assertion message formats a cookie, a handle, a
//! `SAMLResponse` or a `RelayState`.

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
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredentialStatus, SealedSamlIdpKey, StoreSamlIdpCredential,
};
use axiam_core::models::saml_sp::{
    AcsEndpoint, AttributeMapping, AttributeSource, NameIdFormat, SamlBinding,
    SamlServiceProviderInput,
};
use axiam_core::models::settings::{SetTenantOverride, system_defaults};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, SamlIdpCredentialRepository,
    SamlServiceProviderRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealSamlIdpCredentialRepository,
    SurrealSamlServiceProviderRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_federation::saml_idp::test_support::{
    Material, deflate_base64, rsa_material, sign_document, sign_octets, signature_template,
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
const SP_ENTITY: &str = "https://sp.example.test/metadata";
const ACS: &str = "https://sp.example.test/saml/acs";
const ACS_2: &str = "https://sp.example.test/saml/acs-2";
const SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SESSION_SECS: u64 = 2_592_000;

// ---------------------------------------------------------------------------
// Material, generated once per binary
// ---------------------------------------------------------------------------

/// The tenant's IdP signing credential: RSA-4096, as D-21 issues.
fn idp_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(4096, "AXIAM SAML IdP test", 365))
}

/// The SP's request-signing key.
fn sp_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(2048, "SP request signing", 365))
}

/// Somebody else's key.
fn stranger_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(2048, "Not the SP", 365))
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
// The world: an organization with SAML on, a tenant, a user, an SP
// ---------------------------------------------------------------------------

struct World {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    state: web::Data<AppState<TestDb>>,
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

async fn create_user(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    username: &str,
    status: UserStatus,
) -> Uuid {
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
                status: Some(status),
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

/// The app state, with a pairwise key and a credential service whose sealing
/// key is minted at runtime (and the same custodians to seal the credential
/// with).
fn world_state(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
) -> (web::Data<AppState<TestDb>>, Arc<axiam_pki::CaKeyCustodians>) {
    let mut state = AppState::for_test(db.clone(), auth.clone());
    let custodians = Arc::new(
        axiam_pki::ca_key_store::custodians_from(Some(runtime_bytes()), &|_| None).unwrap(),
    );
    let pki_config = axiam_pki::PkiConfig::default();
    state.saml_idp.credential_service = axiam_pki::saml_signing::SamlIdpCredentialService::new(
        axiam_pki::CertService::new(
            axiam_db::SurrealCaCertificateRepository::new(db.clone()),
            axiam_db::SurrealCertificateRepository::new(db.clone()),
            pki_config,
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
    (web::Data::new(state), custodians)
}

/// The in-memory database with its schema, and the organization with SAML on.
///
/// The embedded SurrealDB engine recurses deeply in a debug build: the settings
/// upsert below alone reaches about 1.5 MB of the test thread's 2 MiB stack. The
/// steps of [`world`] are therefore separate, boxed futures: whatever a step
/// holds across an `.await` is not also on the stack of the frames above it
/// while that query runs, which keeps the whole test inside the default stack
/// with room to spare.
async fn world_org() -> (Surreal<TestDb>, Uuid) {
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
    (db, org.id)
}

/// The tenant `saml-a`, its user `alice`, the app state and the tenant's signing
/// credential.
async fn world_tenant(
    db: &Surreal<TestDb>,
    org_id: Uuid,
) -> (Uuid, Uuid, web::Data<AppState<TestDb>>) {
    let tenant_id = create_tenant(db, org_id, "saml-a").await;
    let user_id = create_user(db, tenant_id, "alice", UserStatus::Active).await;
    let auth = auth_config();
    let (state, custodians) = world_state(db, &auth);
    install_credential(db, &custodians, org_id, tenant_id).await;
    (tenant_id, user_id, state)
}

async fn world() -> World {
    let (db, org_id) = Box::pin(world_org()).await;
    let (tenant_id, user_id, state) = Box::pin(world_tenant(&db, org_id)).await;
    World {
        db,
        org_id,
        tenant_id,
        user_id,
        state,
    }
}

fn sp_input() -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        enabled: true,
        display_name: "Payroll".into(),
        entity_id: SP_ENTITY.into(),
        acs_urls: vec![
            AcsEndpoint {
                url: ACS.into(),
                binding: SamlBinding::HttpPost,
                index: 0,
                is_default: true,
            },
            AcsEndpoint {
                url: ACS_2.into(),
                binding: SamlBinding::HttpPost,
                index: 1,
                is_default: false,
            },
        ],
        slo_url: None,
        slo_binding: None,
        name_id_format: NameIdFormat::Persistent,
        sign_responses: true,
        encrypt_assertions: false,
        sp_signing_cert_pem: None,
        sp_encryption_cert_pem: None,
        want_authn_requests_signed: false,
        allow_idp_initiated: false,
        attribute_mappings: vec![AttributeMapping {
            saml_name: "mail".into(),
            name_format: None,
            source: AttributeSource::Email,
        }],
        allowed_groups: Vec::new(),
    }
}

async fn register_sp(w: &World, input: SamlServiceProviderInput) -> Uuid {
    SurrealSamlServiceProviderRepository::new(w.db.clone())
        .create(w.tenant_id, input)
        .await
        .unwrap()
        .id
}

fn signing_sp() -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        sp_signing_cert_pem: Some(sp_material().cert_pem.clone()),
        want_authn_requests_signed: true,
        ..sp_input()
    }
}

/// The limits every test but the rate-limit one runs under.
///
/// The shared rate-limit counter back-fills a key it first sees part-way
/// through a window pro rata (the sliding window's cold seed), so a test that
/// sends a dozen requests to the SSO routes or the login route from one address
/// can be refused with `429` depending on the second of the minute it started
/// in — seen as a flaky `an_acs_outside_the_registry_…` in CI. The limiter's own
/// behaviour stays pinned, deterministically, by
/// `the_sso_routes_are_rate_limited`, which sets the preset to 1.
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
                .app_data($w.state.clone())
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($w.db.clone()))
                        as Arc<dyn axiam_api_rest::TenantScopeResolver>,
                ))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(cfg, &$limits, RouteOptions::default())
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
// A browser: a cookie jar, nothing more
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Browser {
    jar: BTreeMap<String, String>,
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

    fn without_binding(&self) -> Self {
        Self {
            jar: self
                .jar
                .iter()
                .filter(|(k, _)| !k.starts_with("axiam_saml_req_"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
    }

    fn op_only(&self) -> Self {
        Self {
            jar: self
                .jar
                .iter()
                .filter(|(k, _)| *k == "axiam_op_session")
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        }
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

    /// Sign in over HTTP, keeping the OP cookie the sign-in set.
    async fn sign_in(&mut self, app: &impl TestApp, w: &World, username: &str) {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/login")
            .set_json(serde_json::json!({
                "tenant_id": w.tenant_id,
                "org_id": w.org_id,
                "username_or_email": username,
                "password": test_password(),
            }))
            .to_request();
        let resp = test::call_service(app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "the sign-in must succeed");
        let saml_path = format!("/saml/v2/{}/sso", w.tenant_id);
        assert!(
            resp.response()
                .cookies()
                .any(|c| c.name() == "axiam_op_session" && c.path() == Some(saml_path.as_str())),
            "a sign-in mints the OP cookie at the tenant's SAML SSO path"
        );
        // Only the OP cookie: the API cookies are no part of a SAML browser.
        for c in resp.response().cookies() {
            if c.name() == "axiam_op_session" {
                self.jar.insert(c.name().to_owned(), c.value().to_owned());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Req {
    id: String,
    destination: Option<String>,
    acs_url: Option<String>,
    acs_index: Option<u16>,
    force: bool,
    passive: bool,
    protocol_binding: Option<String>,
    name_id_format: Option<String>,
    issuer: String,
}

impl Req {
    fn new(tenant_id: Uuid) -> Self {
        Self {
            id: format!("_{}", Uuid::new_v4().simple()),
            destination: Some(sso_url(tenant_id)),
            acs_url: None,
            acs_index: None,
            force: false,
            passive: false,
            protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".into()),
            name_id_format: None,
            issuer: SP_ENTITY.into(),
        }
    }

    fn xml(&self, signature: Option<&Material>) -> String {
        let mut attrs = String::new();
        let mut push = |name: &str, value: &str| {
            attrs.push_str(&format!(r#" {name}="{value}""#));
        };
        if let Some(d) = &self.destination {
            push("Destination", d);
        }
        if let Some(a) = &self.acs_url {
            push("AssertionConsumerServiceURL", a);
        }
        if let Some(i) = self.acs_index {
            push("AssertionConsumerServiceIndex", &i.to_string());
        }
        if self.force {
            push("ForceAuthn", "true");
        }
        if self.passive {
            push("IsPassive", "true");
        }
        if let Some(b) = &self.protocol_binding {
            push("ProtocolBinding", b);
        }
        let policy = self
            .name_id_format
            .as_deref()
            .map(|f| format!(r#"<samlp:NameIDPolicy Format="{f}" AllowCreate="true"/>"#))
            .unwrap_or_default();
        let template = signature
            .map(|m| signature_template(&self.id, &m.cert_der))
            .unwrap_or_default();
        let document = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}"{attrs}><saml:Issuer>{}</saml:Issuer>{template}{policy}</samlp:AuthnRequest>"#,
            self.id,
            Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            self.issuer,
        );
        match signature {
            Some(m) => sign_document(&document, &m.pkcs8_der),
            None => document,
        }
    }
}

fn sso_url(tenant_id: Uuid) -> String {
    format!("{ROOT_ISSUER}/saml/v2/{tenant_id}/sso")
}

fn sso_path(tenant_id: Uuid) -> String {
    format!("/saml/v2/{tenant_id}/sso")
}

fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// An HTTP-Redirect query, signed with `key` when given (over exactly the
/// octets sent).
fn redirect_query(document: &str, relay: Option<&str>, key: Option<&Material>) -> String {
    let mut query = format!("SAMLRequest={}", enc(&deflate_base64(document.as_bytes())));
    if let Some(r) = relay {
        query.push_str(&format!("&RelayState={}", enc(r)));
    }
    if let Some(m) = key {
        query.push_str(&format!("&SigAlg={}", enc(SHA256)));
        let signature = sign_octets(&query, &m.pkcs8_der);
        query.push_str(&format!("&Signature={}", enc(&signature)));
    }
    query
}

fn post_body(document: &str, relay: Option<&str>) -> String {
    let mut body = format!("SAMLRequest={}", enc(&STANDARD.encode(document)));
    if let Some(r) = relay {
        body.push_str(&format!("&RelayState={}", enc(r)));
    }
    body
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

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

fn sets_binding_cookie(resp: &actix_web::dev::ServiceResponse) -> bool {
    resp.response()
        .cookies()
        .any(|c| c.name().starts_with("axiam_saml_req_") && !c.value().is_empty())
}

async fn pending_rows(w: &World) -> usize {
    let mut result =
        w.db.query("SELECT count() AS n FROM saml_authn_request GROUP ALL")
            .await
            .unwrap();
    let rows: Vec<serde_json::Value> = result.take(0).unwrap();
    rows.first().and_then(|r| r["n"].as_u64()).unwrap_or(0) as usize
}

/// **Precondition 4.** Refused before the login hop: no redirect to the
/// sign-in page, no handle, no binding cookie, no pending row.
async fn assert_no_hop(w: &World, resp: &actix_web::dev::ServiceResponse, label: &str) {
    let loc = location(resp);
    assert!(
        !loc.starts_with("/login") && !loc.contains("/sso/continue"),
        "{label}: no redirect towards a sign-in (status {})",
        resp.status()
    );
    assert!(!sets_binding_cookie(resp), "{label}: no binding cookie");
    assert_eq!(
        pending_rows(w).await,
        0,
        "{label}: no pending request stored"
    );
}

/// The body of an auto-post page, or of an error page.
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

/// `(action, SAMLResponse XML, RelayState)` from an auto-post page.
fn posted(page: &str) -> (String, String, Option<String>) {
    let field = |marker: &str| -> Option<String> {
        let start = page.find(marker)? + marker.len();
        let end = page[start..].find('"')? + start;
        Some(html_unescape(&page[start..end]))
    };
    let action = field("action=\"").expect("a form action");
    let response = field("name=\"SAMLResponse\" value=\"").expect("a SAMLResponse");
    let xml = String::from_utf8(STANDARD.decode(response).unwrap()).unwrap();
    (action, xml, field("name=\"RelayState\" value=\""))
}

fn attr(xml: &str, name: &str) -> Option<String> {
    let marker = format!(" {name}=\"");
    let start = xml.find(&marker)? + marker.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_owned())
}

fn is_success(xml: &str) -> bool {
    xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success") && xml.contains("Assertion")
}

fn status_of(xml: &str) -> Vec<String> {
    xml.match_indices("StatusCode Value=\"")
        .map(|(i, m)| {
            let start = i + m.len();
            let end = xml[start..].find('"').unwrap() + start;
            xml[start..end].to_owned()
        })
        .collect()
}

/// The response is signed by the tenant's credential (xmlsec, every
/// signature) and answers this request at this ACS.
fn assert_issued(xml: &str, request_id: Option<&str>, acs: &str) {
    assert!(is_success(xml), "a Success response with an assertion");
    axiam_federation::saml_idp::request::verify_post_signature(xml, &idp_material().cert_der)
        .expect("every signature verifies against the tenant credential");
    assert_eq!(attr(xml, "Destination").as_deref(), Some(acs));
    assert_eq!(attr(xml, "Recipient").as_deref(), Some(acs));
    assert_eq!(attr(xml, "InResponseTo").as_deref(), request_id);
    assert!(xml.contains(&format!("<saml:Audience>{SP_ENTITY}</saml:Audience>")));
}

/// Run one SP-initiated request to the point where the browser is at the
/// continue leg: returns the continue URI.
async fn start(app: &impl TestApp, browser: &mut Browser, tenant_id: Uuid, query: &str) -> String {
    let resp = browser
        .get(app, &format!("{}?{query}", sso_path(tenant_id)))
        .await;
    assert_eq!(resp.status().as_u16(), 303, "the first leg answers 303");
    assert!(
        sets_binding_cookie(&resp),
        "the first leg binds the browser"
    );
    let loc = location(&resp);
    assert!(loc.starts_with(&format!("{}/continue?handle=", sso_path(tenant_id))));
    loc
}

// ---------------------------------------------------------------------------
// 1. SP-initiated, end to end
// ---------------------------------------------------------------------------

/// **Acceptance: HTTP-Redirect, end to end through the login hop.** An
/// anonymous browser is sent to sign in with a `return_to` naming the
/// continue leg, signs in, comes back, and receives a signed response for
/// this request at the registered ACS, with the `RelayState` echoed.
#[actix_rt::test]
async fn redirect_binding_end_to_end_through_the_login_hop() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);
    let mut browser = Browser::default();
    let req = Req::new(w.tenant_id);

    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), Some("rs-1"), None),
    )
    .await;
    let hop = browser.get(&app, &cont).await;
    assert_eq!(hop.status().as_u16(), 302, "anonymous: the login hop");
    let loc = location(&hop);
    assert!(
        loc.starts_with("/login?return_to="),
        "to the SPA sign-in page"
    );
    assert!(
        !loc.contains("reauth=1"),
        "nothing stale to re-authenticate"
    );
    assert_eq!(header(&hop, "cache-control"), "no-store");
    let return_to = url::form_urlencoded::parse(loc.split_once('?').unwrap().1.as_bytes())
        .find(|(k, _)| k == "return_to")
        .map(|(_, v)| v.into_owned())
        .unwrap();
    assert!(return_to.starts_with(&format!("{}/continue?handle=", sso_path(w.tenant_id))));
    assert!(return_to.ends_with("&axiam_login_hop=1"));
    axiam_oauth2::login_hop::validate_return_to_at(
        &return_to,
        &axiam_oauth2::login_hop::saml_sso_continue_path(w.tenant_id),
    )
    .expect("the SAML return_to validates");

    browser.sign_in(&app, &w, "alice").await;
    let issued = browser.get(&app, &return_to).await;
    assert_eq!(issued.status().as_u16(), 200);
    assert_eq!(header(&issued, "cache-control"), "no-store");
    let csp = header(&issued, "content-security-policy");
    assert!(
        csp.contains("form-action https://sp.example.test;"),
        "form-action is the ACS origin alone"
    );
    assert!(
        csp.contains("script-src 'nonce-"),
        "the one inline script runs under a nonce"
    );
    assert!(csp.contains("default-src 'none'"));
    assert!(
        issued
            .response()
            .cookies()
            .any(|c| c.name().starts_with("axiam_saml_req_") && c.value().is_empty()),
        "the binding cookie is cleared"
    );
    let (action, xml, relay) = posted(&body_of(issued).await);
    assert_eq!(action, ACS);
    assert_eq!(relay.as_deref(), Some("rs-1"));
    assert_issued(&xml, Some(&req.id), ACS);
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"));
}

/// **Acceptance: HTTP-POST, signed, for a signed-in browser — and through
/// AXIAM's own SP verifier.** The cross-site form post carries no cookie; the
/// continue leg does, and issues without a hop.
#[actix_rt::test]
async fn post_binding_signed_end_to_end_verified_by_axiam_own_sp() {
    let w = world().await;
    register_sp(
        &w,
        SamlServiceProviderInput {
            name_id_format: NameIdFormat::EmailAddress,
            ..signing_sp()
        },
    )
    .await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;

    let mut req = Req::new(w.tenant_id);
    req.acs_url = Some(ACS_2.into());
    req.protocol_binding = None;
    let resp = browser
        .post_form(
            &app,
            &sso_path(w.tenant_id),
            post_body(&req.xml(Some(sp_material())), Some("relay&<x>")),
        )
        .await;
    assert_eq!(resp.status().as_u16(), 303);
    let cont = location(&resp);
    let issued = browser.get(&app, &cont).await;
    assert_eq!(issued.status().as_u16(), 200, "signed in already: no hop");
    let page = body_of(issued).await;
    assert!(
        !page.contains("relay&<x>"),
        "RelayState is HTML-escaped in the page"
    );
    let (action, xml, relay) = posted(&page);
    assert_eq!(action, ACS_2);
    assert_eq!(relay.as_deref(), Some("relay&<x>"));
    assert_issued(&xml, Some(&req.id), ACS_2);

    // AXIAM's own SP verifier, configured with the tenant's IdP certificate.
    let config = axiam_core::models::federation::FederationConfig {
        id: Uuid::new_v4(),
        tenant_id: w.tenant_id,
        provider: "axiam-self".into(),
        protocol: axiam_core::models::federation::FederationProtocol::Saml,
        metadata_url: None,
        client_id: SP_ENTITY.into(),
        client_secret: String::new(),
        attribute_map: serde_json::json!({}),
        enabled: true,
        allowed_algorithms: vec![],
        idp_signing_cert_pem: Some(idp_material().cert_pem.clone()),
        client_secret_ciphertext: None,
        client_secret_nonce: None,
        client_secret_key_version: None,
        token_exchange: Default::default(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        provider_kind: axiam_core::models::federation::ProviderKind::GenericOidc,
        provider_slug: None,
        allow_tenant_inheritance: false,
        scopes: Vec::new(),
        authorization_endpoint: None,
        token_endpoint: None,
        userinfo_endpoint: None,
        allowed_issuer_tenants: Vec::new(),
        apple_team_id: None,
        apple_key_id: None,
        require_pkce: false,
        button_icon: None,
        allow_sha1_signatures: false,
        idp_metadata_signing_cert_pem: None,
    };
    let other_tenant = create_tenant(&w.db, w.org_id, "saml-sp-side").await;
    w.state
        .federation
        .saml_federation_service
        .handle_saml_response_for(
            &config,
            other_tenant,
            &STANDARD.encode(&xml),
            relay.as_deref(),
            Some(&req.id),
            Some(ACS_2),
            true,
        )
        .await
        .expect("AXIAM's SP verifier accepts the response");
}

/// **Acceptance: HTTP-Redirect, signed.**
#[actix_rt::test]
async fn redirect_binding_signed_request_is_served() {
    let w = world().await;
    register_sp(&w, signing_sp()).await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;
    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), Some("signed-relay"), Some(sp_material())),
    )
    .await;
    let issued = browser.get(&app, &cont).await;
    assert_eq!(issued.status().as_u16(), 200);
    let (_, xml, relay) = posted(&body_of(issued).await);
    assert_eq!(relay.as_deref(), Some("signed-relay"));
    assert_issued(&xml, Some(&req.id), ACS);
}

// ---------------------------------------------------------------------------
// 2. IdP-initiated (D-3)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn idp_initiated_is_served_for_an_sp_that_opted_in_and_refused_otherwise() {
    let w = world().await;
    let sp_id = register_sp(
        &w,
        SamlServiceProviderInput {
            allow_idp_initiated: true,
            ..sp_input()
        },
    )
    .await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;
    let uri = format!(
        "{}/idp-initiated?sp={}&RelayState=dash",
        sso_path(w.tenant_id),
        enc(SP_ENTITY)
    );

    // A cross-site trigger is refused before anything.
    let cross = browser
        .get_with(&app, &uri, &[("Sec-Fetch-Site", "cross-site")])
        .await;
    assert_eq!(cross.status().as_u16(), 403);
    assert_no_hop(&w, &cross, "cross-site IdP-initiated").await;

    let resp = browser
        .get_with(&app, &uri, &[("Sec-Fetch-Site", "same-origin")])
        .await;
    assert_eq!(resp.status().as_u16(), 303);
    let issued = browser.get(&app, &location(&resp)).await;
    assert_eq!(issued.status().as_u16(), 200);
    let (action, xml, relay) = posted(&body_of(issued).await);
    assert_eq!(action, ACS, "the SP's default ACS");
    assert_eq!(relay.as_deref(), Some("dash"));
    assert_issued(&xml, None, ACS);

    // Not opted in: refused before the hop.
    let mut input = sp_input();
    input.allow_idp_initiated = false;
    SurrealSamlServiceProviderRepository::new(w.db.clone())
        .update(w.tenant_id, sp_id, input)
        .await
        .unwrap();
    w.db.query("DELETE saml_authn_request").await.unwrap();
    let refused = Browser::default().get(&app, &uri).await;
    assert_eq!(refused.status().as_u16(), 403);
    assert_no_hop(&w, &refused, "IdP-initiated, not opted in").await;
}

// ---------------------------------------------------------------------------
// 3. Replay, single use, binding
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_replayed_request_id_is_refused_before_the_hop() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);
    let req = Req::new(w.tenant_id);
    let document = req.xml(None);
    let mut first = Browser::default();
    start(
        &app,
        &mut first,
        w.tenant_id,
        &redirect_query(&document, None, None),
    )
    .await;

    let mut second = Browser::default();
    let replay = second
        .get(
            &app,
            &format!(
                "{}?{}",
                sso_path(w.tenant_id),
                redirect_query(&document, None, None)
            ),
        )
        .await;
    assert_eq!(replay.status().as_u16(), 400);
    assert!(!sets_binding_cookie(&replay) && location(&replay).is_empty());
    assert_eq!(
        pending_rows(&w).await,
        1,
        "only the first request was stored"
    );

    // Over the other binding too.
    let replay_post = second
        .post_form(&app, &sso_path(w.tenant_id), post_body(&document, None))
        .await;
    assert_eq!(replay_post.status().as_u16(), 400);
    assert_eq!(pending_rows(&w).await, 1);
}

#[actix_rt::test]
async fn a_handle_is_single_use_and_bound_to_the_browser_that_started_it() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;
    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;

    // Another browser — even one signed in — cannot use the handle.
    let mut thief = Browser::default();
    thief.sign_in(&app, &w, "alice").await;
    let stolen = thief.get(&app, &cont).await;
    assert_eq!(
        stolen.status().as_u16(),
        400,
        "no binding cookie, no assertion"
    );
    let page = body_of(stolen).await;
    assert!(!page.contains("SAMLResponse"));

    // The same browser without its binding cookie: refused, nothing burned.
    let unbound = browser.without_binding().get(&app, &cont).await;
    assert_eq!(unbound.status().as_u16(), 400);

    // A copy of the browser as it is now, binding cookie and all.
    let mut replayer = browser.clone();
    let first = browser.get(&app, &cont).await;
    assert_eq!(first.status().as_u16(), 200, "the first continue issues");
    // A second continue of the same handle, from a browser that still holds
    // the binding cookie, is refused: the handle was consumed.
    let second = replayer.get(&app, &cont).await;
    assert_eq!(second.status().as_u16(), 400, "the handle was consumed");
    assert!(!body_of(second).await.contains("SAMLResponse"));
}

// ---------------------------------------------------------------------------
// 4. ACS allow-list, Destination, signatures — all before the hop
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn an_acs_outside_the_registry_or_a_destination_mismatch_is_refused_before_the_hop() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);

    let mut cases: Vec<(&str, Req)> = Vec::new();
    let mut r = Req::new(w.tenant_id);
    r.acs_url = Some("https://evil.example/acs".into());
    cases.push(("an unregistered ACS URL", r));
    let mut r = Req::new(w.tenant_id);
    r.acs_url = Some(format!("{ACS}/"));
    cases.push(("a near-miss ACS URL", r));
    let mut r = Req::new(w.tenant_id);
    r.acs_index = Some(9);
    cases.push(("an unregistered ACS index", r));
    let mut r = Req::new(w.tenant_id);
    r.acs_url = Some(ACS.into());
    r.acs_index = Some(0);
    cases.push(("an ACS URL and an index", r));
    let mut r = Req::new(w.tenant_id);
    r.destination = Some(format!("{ROOT_ISSUER}/saml/v2/{}/sso", Uuid::new_v4()));
    cases.push(("another tenant's Destination", r));
    let mut r = Req::new(w.tenant_id);
    r.destination = Some("https://evil.example/sso".into());
    cases.push(("a foreign Destination", r));
    let mut r = Req::new(w.tenant_id);
    r.protocol_binding = Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".into());
    cases.push(("a Redirect response binding", r));
    let mut r = Req::new(w.tenant_id);
    r.issuer = "https://unknown.example/sp".into();
    cases.push(("an unknown SP", r));

    for (label, req) in cases {
        let mut browser = Browser::default();
        browser.sign_in(&app, &w, "alice").await;
        let resp = browser
            .get(
                &app,
                &format!(
                    "{}?{}",
                    sso_path(w.tenant_id),
                    redirect_query(&req.xml(None), None, None)
                ),
            )
            .await;
        assert_eq!(resp.status().as_u16(), 400, "{label}");
        assert_no_hop(&w, &resp, label).await;
        assert!(
            !body_of(resp).await.contains("SAMLResponse"),
            "{label}: posts nowhere"
        );
    }

    // A RelayState over 80 bytes, before the hop as well.
    let req = Req::new(w.tenant_id);
    let resp = Browser::default()
        .get(
            &app,
            &format!(
                "{}?{}",
                sso_path(w.tenant_id),
                redirect_query(&req.xml(None), Some(&"r".repeat(81)), None)
            ),
        )
        .await;
    assert_eq!(resp.status().as_u16(), 400);
    assert_no_hop(&w, &resp, "RelayState").await;
}

#[actix_rt::test]
async fn a_signing_sp_s_missing_bad_or_wrong_key_signature_is_refused_on_both_bindings() {
    let w = world().await;
    register_sp(&w, signing_sp()).await;
    let app = app!(w);
    let path = sso_path(w.tenant_id);

    // Redirect.
    let req = Req::new(w.tenant_id);
    let unsigned = redirect_query(&req.xml(None), Some("r"), None);
    let wrong_key = redirect_query(&req.xml(None), Some("r"), Some(stranger_material()));
    let tampered = redirect_query(&req.xml(None), Some("r"), Some(sp_material()))
        .replace("RelayState=r", "RelayState=x");
    for (label, query) in [
        ("unsigned", unsigned),
        ("wrong key", wrong_key),
        ("tampered", tampered),
    ] {
        let resp = Browser::default()
            .get(&app, &format!("{path}?{query}"))
            .await;
        assert_eq!(resp.status().as_u16(), 400, "Redirect, {label}");
        assert_no_hop(&w, &resp, label).await;
    }

    // POST.
    let req = Req::new(w.tenant_id);
    let unsigned = req.xml(None);
    let wrong_key = req.xml(Some(stranger_material()));
    // A changed attribute inside the signed root, after signing: the issuer
    // still names the SP, so this reaches (and fails) the signature check.
    let tampered = req.xml(Some(sp_material())).replacen(
        r#" Version="2.0""#,
        r#" Version="2.0" ForceAuthn="true""#,
        1,
    );
    for (label, document) in [
        ("unsigned", unsigned),
        ("wrong key", wrong_key),
        ("tampered", tampered),
    ] {
        let resp = Browser::default()
            .post_form(&app, &path, post_body(&document, None))
            .await;
        assert!(resp.status().is_client_error(), "POST, {label}");
        assert_no_hop(&w, &resp, label).await;
    }
}

// ---------------------------------------------------------------------------
// 5. Policy refusals the SP is told about — still before the hop
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_disabled_sp_encryption_or_a_conflicting_name_id_policy_is_answered_to_the_acs() {
    for (label, input, policy, expected) in [
        (
            "disabled SP",
            SamlServiceProviderInput {
                enabled: false,
                ..sp_input()
            },
            None,
            "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
        ),
        (
            "encryption requested",
            SamlServiceProviderInput {
                encrypt_assertions: true,
                sp_encryption_cert_pem: Some(sp_material().cert_pem.clone()),
                ..sp_input()
            },
            None,
            "urn:oasis:names:tc:SAML:2.0:status:Responder",
        ),
        (
            "NameIDPolicy conflict",
            sp_input(),
            Some(NameIdFormat::EmailAddress.urn().to_owned()),
            "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
        ),
    ] {
        let w = world().await;
        register_sp(&w, input).await;
        let app = app!(w);
        let mut req = Req::new(w.tenant_id);
        req.name_id_format = policy;
        let resp = Browser::default()
            .get(
                &app,
                &format!(
                    "{}?{}",
                    sso_path(w.tenant_id),
                    redirect_query(&req.xml(None), None, None)
                ),
            )
            .await;
        assert_eq!(
            resp.status().as_u16(),
            200,
            "{label}: a failure posted to the ACS"
        );
        assert_no_hop(&w, &resp, label).await;
        let (action, xml, _) = posted(&body_of(resp).await);
        assert_eq!(action, ACS);
        assert!(status_of(&xml).contains(&expected.to_owned()), "{label}");
        assert!(!xml.contains("Assertion"), "{label}: no assertion");
        assert!(
            !xml.contains("Signature"),
            "{label}: a failure is never signed"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. IsPassive, ForceAuthn
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn is_passive_never_shows_the_sign_in_page() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);

    // No session: NoPassive, posted, no hop.
    let mut anon = Browser::default();
    let mut req = Req::new(w.tenant_id);
    req.passive = true;
    let cont = start(
        &app,
        &mut anon,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let resp = anon.get(&app, &cont).await;
    assert_eq!(resp.status().as_u16(), 200);
    let (_, xml, _) = posted(&body_of(resp).await);
    assert!(status_of(&xml).contains(&"urn:oasis:names:tc:SAML:2.0:status:NoPassive".to_owned()));
    assert_eq!(attr(&xml, "InResponseTo").as_deref(), Some(req.id.as_str()));

    // With a session: issued.
    let mut signed_in = Browser::default();
    signed_in.sign_in(&app, &w, "alice").await;
    let mut req = Req::new(w.tenant_id);
    req.passive = true;
    let cont = start(
        &app,
        &mut signed_in,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let resp = signed_in.get(&app, &cont).await;
    let (_, xml, _) = posted(&body_of(resp).await);
    assert_issued(&xml, Some(&req.id), ACS);
}

/// **Precondition 3: `ForceAuthn` is bound to the request.** A pre-existing
/// session is sent to sign in again (`reauth=1`); a forged hop marker on the
/// continue leg yields a failure and no assertion; a sign-in after the request
/// was accepted is served.
#[actix_rt::test]
async fn force_authn_requires_a_sign_in_after_the_request_and_a_forged_marker_skips_nothing() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;

    let mut req = Req::new(w.tenant_id);
    req.force = true;
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;

    let hop = browser.get(&app, &cont).await;
    assert_eq!(
        hop.status().as_u16(),
        302,
        "a session older than the request: hop"
    );
    assert!(
        location(&hop).contains("reauth=1"),
        "and the SPA must re-authenticate"
    );

    // The forged marker: the same browser, the same old session, the marker
    // appended by hand. No assertion.
    let forged = browser
        .clone()
        .get(&app, &format!("{cont}&axiam_login_hop=1"))
        .await;
    assert_eq!(forged.status().as_u16(), 200);
    let (_, xml, _) = posted(&body_of(forged).await);
    assert!(status_of(&xml).contains(&"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed".to_owned()));
    assert!(
        !xml.contains("Assertion"),
        "no assertion under a forged marker"
    );

    // A fresh request, and a sign-in after it: served.
    let mut req = Req::new(w.tenant_id);
    req.force = true;
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let hop = browser.get(&app, &cont).await;
    assert_eq!(hop.status().as_u16(), 302);
    browser.sign_in(&app, &w, "alice").await;
    let resp = browser
        .get(&app, &format!("{cont}&axiam_login_hop=1"))
        .await;
    assert_eq!(resp.status().as_u16(), 200);
    let (_, xml, _) = posted(&body_of(resp).await);
    assert_issued(&xml, Some(&req.id), ACS);
}

// ---------------------------------------------------------------------------
// 7. Account rules, groups
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn allowed_groups_decide_who_may_use_the_sp() {
    let w = world().await;
    let groups = SurrealGroupRepository::new(w.db.clone());
    let group = groups
        .create(CreateGroup {
            tenant_id: w.tenant_id,
            name: "payroll-users".into(),
            description: "Payroll users".into(),
            metadata: None,
        })
        .await
        .unwrap();
    register_sp(
        &w,
        SamlServiceProviderInput {
            allowed_groups: vec![group.id],
            ..sp_input()
        },
    )
    .await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;

    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let (_, xml, _) = posted(&body_of(browser.get(&app, &cont).await).await);
    assert!(
        status_of(&xml).contains(&"urn:oasis:names:tc:SAML:2.0:status:RequestDenied".to_owned())
    );

    groups
        .add_member(w.tenant_id, w.user_id, group.id)
        .await
        .unwrap();
    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let (_, xml, _) = posted(&body_of(browser.get(&app, &cont).await).await);
    assert_issued(&xml, Some(&req.id), ACS);
}

/// `account_may_act`: a suspended account's session does not count (hop, then
/// `AuthnFailed`), and a `PendingVerification` one is served (T-160).
#[actix_rt::test]
async fn a_suspended_account_is_not_served_and_a_pending_one_is() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);

    let pending_user = create_user(&w.db, w.tenant_id, "pat", UserStatus::Active).await;
    let mut pat = Browser::default();
    pat.sign_in(&app, &w, "pat").await;
    SurrealUserRepository::new(w.db.clone())
        .update(
            w.tenant_id,
            pending_user,
            UpdateUser {
                status: Some(UserStatus::PendingVerification),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut pat,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let (_, xml, _) = posted(&body_of(pat.get(&app, &cont).await).await);
    assert_issued(&xml, Some(&req.id), ACS);

    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    SurrealUserRepository::new(w.db.clone())
        .update(
            w.tenant_id,
            w.user_id,
            UpdateUser {
                status: Some(UserStatus::Locked),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut alice,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let hop = alice.clone().get(&app, &cont).await;
    assert_eq!(
        hop.status().as_u16(),
        302,
        "a locked account's session is stale"
    );
    assert!(location(&hop).contains("reauth=1"));
    let back = alice.get(&app, &format!("{cont}&axiam_login_hop=1")).await;
    let (_, xml, _) = posted(&body_of(back).await);
    assert!(status_of(&xml).contains(&"urn:oasis:names:tc:SAML:2.0:status:AuthnFailed".to_owned()));
    assert!(!xml.contains("Assertion"));
}

#[actix_rt::test]
async fn a_tenant_without_a_signing_credential_answers_responder() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    w.db.query("DELETE saml_idp_credential").await.unwrap();
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;
    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let (_, xml, _) = posted(&body_of(browser.get(&app, &cont).await).await);
    assert_eq!(
        status_of(&xml),
        vec!["urn:oasis:names:tc:SAML:2.0:status:Responder".to_owned()]
    );
}

// ---------------------------------------------------------------------------
// 8. Cookie preconditions: the tenant-keyed lookup, both directions
// ---------------------------------------------------------------------------

/// **Precondition 2.** A cookie whose digest names a live session in tenant B
/// resolves nothing on tenant A's continue leg, and the reverse.
#[actix_rt::test]
async fn the_op_cookie_never_resolves_across_tenants_in_either_direction() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let tenant_b = create_tenant(&w.db, w.org_id, "saml-b").await;
    create_user(&w.db, tenant_b, "bob", UserStatus::Active).await;
    SurrealSamlServiceProviderRepository::new(w.db.clone())
        .create(tenant_b, sp_input())
        .await
        .unwrap();
    let app = app!(w);
    let world_b = World {
        db: w.db.clone(),
        org_id: w.org_id,
        tenant_id: tenant_b,
        user_id: Uuid::nil(),
        state: w.state.clone(),
    };

    let mut alice = Browser::default();
    alice.sign_in(&app, &w, "alice").await;
    let mut bob = Browser::default();
    bob.sign_in(&app, &world_b, "bob").await;

    for (label, cookie_from, request_tenant) in [
        ("B's cookie on A", &bob, w.tenant_id),
        ("A's cookie on B", &alice, tenant_b),
    ] {
        let mut browser = cookie_from.op_only();
        let req = Req::new(request_tenant);
        let cont = start(
            &app,
            &mut browser,
            request_tenant,
            &redirect_query(&req.xml(None), None, None),
        )
        .await;
        let resp = browser.get(&app, &cont).await;
        assert_eq!(
            resp.status().as_u16(),
            302,
            "{label}: anonymous here, so the hop"
        );
        assert!(
            location(&resp).contains("reauth=1"),
            "{label}: the cookie is stale here"
        );
        assert!(
            resp.response()
                .cookies()
                .any(|c| c.name() == "axiam_op_session"
                    && c.value().is_empty()
                    && c.path() == Some(sso_path(request_tenant).as_str())),
            "{label}: only this path's stale copy is cleared"
        );
    }
}

// ---------------------------------------------------------------------------
// 9. XML: XXE and the decompression bomb, over HTTP
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn xxe_billion_laughs_and_a_decompression_bomb_are_refused_before_any_lookup() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);
    let path = sso_path(w.tenant_id);
    let base = Req::new(w.tenant_id).xml(None);

    let xxe = format!(
        r#"<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>{}"#,
        base.replace(SP_ENTITY, "&x;")
    );
    let laughs = format!(
        r#"<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>{}"#,
        base.replace(SP_ENTITY, "&c;")
    );
    for (label, document) in [("XXE", xxe), ("billion laughs", laughs)] {
        let resp = Browser::default()
            .post_form(&app, &path, post_body(&document, None))
            .await;
        assert_eq!(resp.status().as_u16(), 400, "{label}");
        assert_no_hop(&w, &resp, label).await;
        let resp = Browser::default()
            .get(
                &app,
                &format!("{path}?{}", redirect_query(&document, None, None)),
            )
            .await;
        assert_eq!(resp.status().as_u16(), 400, "{label} (Redirect)");
        assert_no_hop(&w, &resp, label).await;
    }

    let bomb = vec![b' '; 8 * 1024 * 1024];
    let query = format!("SAMLRequest={}", enc(&deflate_base64(&bomb)));
    let resp = Browser::default()
        .get(&app, &format!("{path}?{query}"))
        .await;
    assert_eq!(
        resp.status().as_u16(),
        413,
        "the bomb stops at the inflate cap"
    );
    assert_no_hop(&w, &resp, "decompression bomb").await;

    let huge = format!(
        "SAMLRequest={}",
        "A".repeat(axiam_api_rest::handlers::saml_idp::MAX_POST_BODY_BYTES)
    );
    let resp = Browser::default().post_form(&app, &path, huge).await;
    assert_eq!(resp.status().as_u16(), 413, "an over-long POST body");
    assert_no_hop(&w, &resp, "over-long body").await;
}

// ---------------------------------------------------------------------------
// 10. D-20 and the rate limit
// ---------------------------------------------------------------------------

/// **D-20.** A tenant with the setting off, an unknown tenant and a
/// non-canonical spelling all answer exactly what an unmounted path answers,
/// on every route and every method.
#[actix_rt::test]
async fn every_sso_route_answers_an_indistinguishable_404_when_saml_is_off() {
    let w = world().await;
    register_sp(
        &w,
        SamlServiceProviderInput {
            allow_idp_initiated: true,
            ..sp_input()
        },
    )
    .await;
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
    // Generous limits: this test sends dozens of requests from one address,
    // and what it compares is the 404, not the limiter.
    let limits = RateLimitConfig {
        end_session_per_min: 10_000,
        ..RateLimitConfig::default()
    };
    let app = app!(w, limits);

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

    let req = Req::new(w.tenant_id);
    let query = redirect_query(&req.xml(None), None, None);
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
                format!("/saml/v2/{tenant}/sso?{query}"),
            ),
            (
                actix_web::http::Method::POST,
                format!("/saml/v2/{tenant}/sso"),
            ),
            (
                actix_web::http::Method::PUT,
                format!("/saml/v2/{tenant}/sso"),
            ),
            (
                actix_web::http::Method::GET,
                format!("/saml/v2/{tenant}/sso/continue?handle=x"),
            ),
            (
                actix_web::http::Method::DELETE,
                format!("/saml/v2/{tenant}/sso/continue"),
            ),
            (
                actix_web::http::Method::GET,
                format!("/saml/v2/{tenant}/sso/idp-initiated?sp={}", enc(SP_ENTITY)),
            ),
            (
                actix_web::http::Method::GET,
                format!("/saml/v2/{tenant}/anything"),
            ),
        ] {
            let resp = test::call_service(&app, call(method.clone(), uri.clone())).await;
            assert_eq!(fingerprint(&resp), expected, "{method} on a SAML route");
            assert!(test::read_body(resp).await.is_empty());
        }
    }
    assert_eq!(pending_rows(&w).await, 0);
}

/// **§7 rule 6.** The SSO routes are covered by a rate-limit bucket (the
/// browser-endpoint preset, `end_session_per_min`).
#[actix_rt::test]
async fn the_sso_routes_are_rate_limited() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let limits = RateLimitConfig {
        end_session_per_min: 1,
        ..RateLimitConfig::default()
    };
    let app = app!(w, limits);
    let path = sso_path(w.tenant_id);
    for route in [
        format!("{path}?SAMLRequest=x"),
        format!("{path}/continue?handle=x"),
        format!("{path}/idp-initiated?sp=x"),
    ] {
        let first = Browser::default().get(&app, &route).await;
        assert_ne!(first.status().as_u16(), 429, "the first request is served");
        let second = Browser::default().get(&app, &route).await;
        assert_eq!(second.status().as_u16(), 429, "the second is limited");
    }
}

// ---------------------------------------------------------------------------
// T23.2.4 / D-37: the per-SP SessionIndex, recorded before signing
// ---------------------------------------------------------------------------

const SP_B_ENTITY: &str = "https://sp-b.example.test/metadata";
const SP_B_ACS: &str = "https://sp-b.example.test/saml/acs";

fn sp_b_input() -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        display_name: "Wiki".into(),
        entity_id: SP_B_ENTITY.into(),
        acs_urls: vec![AcsEndpoint {
            url: SP_B_ACS.into(),
            binding: SamlBinding::HttpPost,
            index: 0,
            is_default: true,
        }],
        ..sp_input()
    }
}

/// One SP-initiated sign-on for an already signed-in browser: the signed
/// response XML.
async fn sign_on(
    app: &impl TestApp,
    browser: &mut Browser,
    tenant_id: Uuid,
    entity: &str,
) -> String {
    let mut req = Req::new(tenant_id);
    req.issuer = entity.to_owned();
    let cont = start(
        app,
        browser,
        tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let issued = browser.get(app, &cont).await;
    assert_eq!(issued.status().as_u16(), 200);
    posted(&body_of(issued).await).1
}

struct ParticipantRow {
    session_id: String,
    sp_entity_id: String,
    session_index: String,
}

async fn participants(w: &World) -> Vec<ParticipantRow> {
    let mut result =
        w.db.query("SELECT session_id, sp_entity_id, session_index FROM saml_sp_session")
            .await
            .unwrap();
    let rows: Vec<serde_json::Value> = result.take(0).unwrap();
    rows.iter()
        .map(|r| ParticipantRow {
            session_id: r["session_id"].as_str().unwrap().to_owned(),
            sp_entity_id: r["sp_entity_id"].as_str().unwrap().to_owned(),
            session_index: r["session_index"].as_str().unwrap().to_owned(),
        })
        .collect()
}

/// **Acceptance: per-SP index.** One session, two SPs: the `SessionIndex` differs
/// per SP, is not the session id, is the one the participant record holds, and
/// the session id appears nowhere in either assertion. A second sign-on to one SP
/// in the same session reuses its index (SAML Core §2.7.2.1).
#[actix_rt::test]
async fn the_assertion_carries_a_per_sp_index_that_is_not_the_session_id() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    register_sp(&w, sp_b_input()).await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;

    let xml_a = sign_on(&app, &mut browser, w.tenant_id, SP_ENTITY).await;
    let xml_b = sign_on(&app, &mut browser, w.tenant_id, SP_B_ENTITY).await;
    let index_a = attr(&xml_a, "SessionIndex").expect("a SessionIndex");
    let index_b = attr(&xml_b, "SessionIndex").expect("a SessionIndex");
    assert_ne!(index_a, index_b, "one session, two SPs, two indexes");
    assert_eq!(index_a.len(), 43, "32 bytes, base64url, no padding");

    let rows = participants(&w).await;
    assert_eq!(rows.len(), 2, "one participant row per (session, SP)");
    let session_id = rows[0].session_id.clone();
    assert_eq!(rows[1].session_id, session_id);
    for (entity, index) in [(SP_ENTITY, &index_a), (SP_B_ENTITY, &index_b)] {
        let row = rows
            .iter()
            .find(|r| r.sp_entity_id == entity)
            .expect("a row for the SP");
        assert_eq!(
            &row.session_index, index,
            "the assertion carries the recorded index"
        );
    }
    for (label, text) in [("A", &xml_a), ("B", &xml_b)] {
        assert!(
            !text.contains(&session_id),
            "SP {label}: the session id does not reach the XML"
        );
    }
    assert!(!index_a.contains(&session_id) && !index_b.contains(&session_id));

    let again = sign_on(&app, &mut browser, w.tenant_id, SP_ENTITY).await;
    assert_eq!(
        attr(&again, "SessionIndex").as_deref(),
        Some(index_a.as_str()),
        "a second sign-on to one SP in one session reuses its index"
    );
    assert_eq!(participants(&w).await.len(), 2, "and adds no row");

    // The assertion is still signed by the tenant credential and still verifies.
    axiam_federation::saml_idp::request::verify_post_signature(&xml_b, &idp_material().cert_der)
        .expect("signed");
}

/// **T-382.** The participant row is written before the assertion is signed: a
/// failed write answers `Responder` and issues nothing.
#[actix_rt::test]
async fn a_failed_participant_write_yields_no_assertion() {
    let w = world().await;
    register_sp(&w, sp_input()).await;
    let app = app!(w);
    let mut browser = Browser::default();
    browser.sign_in(&app, &w, "alice").await;
    // The datastore refuses every participant write from now on.
    w.db.query("DEFINE FIELD OVERWRITE name_id ON TABLE saml_sp_session TYPE string ASSERT false")
        .await
        .unwrap()
        .check()
        .unwrap();

    let req = Req::new(w.tenant_id);
    let cont = start(
        &app,
        &mut browser,
        w.tenant_id,
        &redirect_query(&req.xml(None), None, None),
    )
    .await;
    let resp = browser.get(&app, &cont).await;
    assert_eq!(resp.status().as_u16(), 200, "a failure response is posted");
    let (action, xml, _) = posted(&body_of(resp).await);
    assert_eq!(action, ACS);
    assert!(!is_success(&xml), "no assertion");
    assert!(!xml.contains("Assertion"), "nothing signed at all");
    assert_eq!(
        status_of(&xml),
        vec!["urn:oasis:names:tc:SAML:2.0:status:Responder".to_string()]
    );
    assert!(participants(&w).await.is_empty(), "and no row");
}

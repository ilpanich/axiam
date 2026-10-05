//! The world the SAML IdP end-to-end tests (T23.2.7, G-2) share: the production
//! route table on an in-memory database, real RBAC, the real PKI services, the
//! revocation feed on, an organization with `saml_idp_enabled`, and a browser
//! that is a cookie jar.
//!
//! The IdP signing credential is issued through the **real administrator route**
//! (`POST …/saml/idp-credentials`) from a tenant signing CA, so the certificate a
//! service provider reads out of the IdP metadata is the one AXIAM produces in
//! production (RSA-4096, `id-kp-documentSigning`, no SAN), not a fixture shaped
//! like it. Service providers are registered through the administrator routes
//! too.
//!
//! Nothing here is a credential literal: the JWT keypair, the sealing key and the
//! pairwise key are generated at runtime, passwords come from
//! `axiam_test_support`, certificates from rcgen or OpenSSL. No helper formats a
//! cookie, a token, a handle, a `SAMLResponse` or a `NameID` into a message.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use actix_web::http::Method;
use actix_web::test;
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_authz::AuthorizationEngine;
use axiam_core::ca_keys::{CaKeyCustody, StoredCaKey};
use axiam_core::models::certificate::{
    CaCertificate, CreateCaCertificate, CreateIntermediateCa, KeyAlgorithm,
};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredentialStatus, SealedSamlIdpKey, StoreSamlIdpCredential,
};
use axiam_core::models::settings::{SetTenantOverride, system_defaults};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    GroupRepository, OrganizationRepository, Pagination, RoleRepository,
    SamlIdpCredentialRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealRefreshTokenRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealSamlIdpCredentialRepository, SurrealScopeRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use axiam_federation::saml_idp::test_support::{Material, rsa_material};
use axiam_federation::saml_idp::{PairwiseKey, SamlIdpIssuer};
use axiam_test_support::test_password;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

pub type TestDb = surrealdb::engine::local::Db;

pub const TEST_PEER: &str = "127.0.0.1:12345";
/// The deployment's public origin. Nothing listens there: the test process
/// carries every message between the parties, so no party ever dials it.
pub const ROOT_ISSUER: &str = "https://iam.example.com";
pub const SESSION_SECS: u64 = 2_592_000;

pub const PERSISTENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
pub const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

// ---------------------------------------------------------------------------
// Runtime-minted material
// ---------------------------------------------------------------------------

/// A fresh Ed25519 JWT keypair, minted once per process.
fn jwt_pair() -> &'static (String, String) {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

/// 32 bytes minted at runtime, for the PKI sealing key and the pairwise key.
pub fn runtime_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

pub fn auth_config() -> AuthConfig {
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
// The world
// ---------------------------------------------------------------------------

pub struct World {
    pub db: Surreal<TestDb>,
    pub org_id: Uuid,
    /// The tenant with `saml_idp_enabled` on (inherited from the organization).
    pub tenant_id: Uuid,
    /// A tenant of the same organization whose switch is off.
    pub off_tenant_id: Uuid,
    pub admin: Uuid,
    pub alice: Uuid,
    pub bob: Uuid,
    pub auth: AuthConfig,
    pub authz: Arc<dyn AuthzChecker>,
    pub state: AppState<TestDb>,
    /// The administrator's access token, from a real sign-in (the app refuses a
    /// token whose session it has never seen).
    admin_access: std::sync::Mutex<Option<String>>,
    /// The sealing custodians the state's PKI services share: a key sealed with
    /// them is one the credential service can open.
    pub custodians: Arc<axiam_pki::CaKeyCustodians>,
}

pub fn alice_email() -> String {
    "alice@example.com".into()
}

async fn tenant_in(db: &Surreal<TestDb>, org_id: Uuid, slug: &str) -> Uuid {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: format!("SAML {slug}"),
            slug: slug.into(),
            metadata: None,
        })
        .await
        .unwrap();
    seed_permissions(db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(db, tenant.id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    tenant.id
}

async fn active_user(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    name: &str,
    metadata: Option<serde_json::Value>,
) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
            password: test_password(),
            metadata,
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

async fn assign_named_role(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid, role: &str) {
    let roles = SurrealRoleRepository::new(db.clone());
    let found = roles
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 1000,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name == role)
        .expect("seeded role");
    roles
        .assign_to_user(tenant_id, user_id, found.id, AssignmentScope::global())
        .await
        .unwrap();
}

/// A world: one organization with SAML on, a serving tenant, a tenant with the
/// switch off, an administrator, and two ordinary users (`alice`, who has a
/// profile and belongs to a group, and `bob`). The revocation feed is on: the
/// session repository the sign-in and the logout both use publishes to it.
pub async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SAML e2e".into(),
            slug: format!("saml-e2e-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let mut settings = system_defaults();
    settings.saml_idp_enabled = true;
    let settings_repo = SurrealSettingsRepository::new(db.clone());
    settings_repo
        .set_org_settings(org.id, settings)
        .await
        .unwrap();
    let tenant_id = tenant_in(&db, org.id, "saml-e2e").await;
    let off_tenant_id = tenant_in(&db, org.id, "saml-e2e-off").await;
    settings_repo
        .set_tenant_override(
            off_tenant_id,
            SetTenantOverride {
                saml_idp_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let admin = active_user(&db, tenant_id, "admin", None).await;
    assign_named_role(&db, tenant_id, admin, "admin").await;
    let alice = active_user(
        &db,
        tenant_id,
        "alice",
        Some(serde_json::json!({
            "oidc": { "given_name": "Alice", "family_name": "Example", "name": "Alice Example" }
        })),
    )
    .await;
    let bob = active_user(&db, tenant_id, "bob", None).await;
    let groups = SurrealGroupRepository::new(db.clone());
    let group = groups
        .create(CreateGroup {
            tenant_id,
            name: "engineering".into(),
            description: "Engineering".into(),
            metadata: None,
        })
        .await
        .unwrap();
    groups.add_member(tenant_id, alice, group.id).await.unwrap();

    let auth = auth_config();
    let authz: Arc<dyn AuthzChecker> = Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ));
    let (state, custodians) = build_state(&db, &auth);
    World {
        db,
        org_id: org.id,
        tenant_id,
        off_tenant_id,
        admin,
        alice,
        bob,
        auth,
        authz,
        state,
        admin_access: std::sync::Mutex::new(None),
        custodians,
    }
}

/// The app state: a pairwise key, PKI services sharing one runtime-minted
/// sealing key (so a CA made through `ca_service` is one the credential service
/// signs under), and the revocation feed on.
fn build_state(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
) -> (AppState<TestDb>, Arc<axiam_pki::CaKeyCustodians>) {
    let mut state = AppState::for_test(db.clone(), auth.clone());
    let custodians = Arc::new(
        axiam_pki::ca_key_store::custodians_from(Some(runtime_bytes()), &|_| None).unwrap(),
    );
    let pki_config = axiam_pki::PkiConfig::default();
    state.saml_idp.credential_service = axiam_pki::saml_signing::SamlIdpCredentialService::new(
        axiam_pki::CertService::new(
            axiam_db::SurrealCaCertificateRepository::new(db.clone()),
            axiam_db::SurrealCertificateRepository::new(db.clone()),
            pki_config.clone(),
            Arc::clone(&state.crypto_semaphore),
            Arc::clone(&custodians),
        ),
        Arc::clone(&custodians),
        SurrealSamlIdpCredentialRepository::new(db.clone()),
    );
    state.pki.ca_service = axiam_pki::CaService::new(
        axiam_db::SurrealCaCertificateRepository::new(db.clone()),
        pki_config,
        Arc::clone(&state.crypto_semaphore),
        Arc::clone(&custodians),
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

/// The limits every test here runs under. The shared rate-limit counter
/// back-fills a key it first sees part-way through a window pro rata, so a test
/// that sends a dozen requests to the SSO routes or the login route from one
/// address can be refused with `429` depending on the second of the minute it
/// started in. The buckets are pinned, deterministically, by the suites that own
/// them (`saml_idp_sso_test`, `saml_idp_slo_test`, `saml_admin_test`).
pub fn permissive_limits() -> RateLimitConfig {
    RateLimitConfig {
        saml_admin_per_min: 100_000,
        end_session_per_min: 100_000,
        login_per_min: 100_000,
        ..RateLimitConfig::default()
    }
}

#[macro_export]
macro_rules! e2e_app {
    ($w:expr) => {{
        let auth = $w.auth.clone();
        actix_web::test::init_service(
            actix_web::App::new()
                .wrap(axiam_api_rest::middleware::security_headers::SecurityHeadersMiddleware)
                .app_data(actix_web::web::Data::new(auth))
                .app_data(actix_web::web::Data::new($w.authz.clone()))
                .app_data(actix_web::web::Data::new($w.state.clone()))
                .app_data(actix_web::web::Data::new(std::sync::Arc::new(
                    axiam_db::repository::SurrealTenantRepository::new($w.db.clone()),
                )
                    as std::sync::Arc<dyn axiam_api_rest::TenantScopeResolver>))
                // What refuses an access token whose session was revoked.
                .app_data(actix_web::web::Data::new(std::sync::Arc::new(
                    axiam_db::repository::SurrealSessionRepository::new($w.db.clone()),
                )
                    as std::sync::Arc<dyn axiam_api_rest::SessionValidator>))
                .configure(|cfg| {
                    axiam_api_rest::register_api_v1_routes_with::<$crate::saml_e2e_support::TestDb>(
                        cfg,
                        &$crate::saml_e2e_support::permissive_limits(),
                        axiam_api_rest::RouteOptions {
                            revocation_feed_enabled: true,
                            ..axiam_api_rest::RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    }};
}

/// The in-process app under test.
pub trait TestApp:
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
// The administrator's routes (§29)
// ---------------------------------------------------------------------------

impl World {
    /// The administrator's access token: a real sign-in at the login endpoint,
    /// once per world.
    pub async fn admin_token(&self, app: &impl TestApp) -> String {
        if let Some(token) = self.admin_access.lock().unwrap().clone() {
            return token;
        }
        let mut browser = Browser::default();
        browser.sign_in(app, self, "admin").await;
        let token = browser.access.clone().expect("an access token");
        *self.admin_access.lock().unwrap() = Some(token.clone());
        token
    }

    /// An organization root CA and a tenant signing CA beneath it.
    pub async fn tenant_ca(&self) -> CaCertificate {
        let root = self
            .state
            .pki
            .ca_service
            .generate(CreateCaCertificate {
                organization_id: self.org_id,
                subject: "SAML e2e Root CA".into(),
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 3650,
                intermediate_subject: None,
                intermediate_validity_days: None,
                issue_from_root: false,
            })
            .await
            .expect("root CA")
            .certificate;
        self.state
            .pki
            .ca_service
            .generate_intermediate(CreateIntermediateCa {
                organization_id: self.org_id,
                tenant_id: self.tenant_id,
                parent_ca_id: root.id,
                subject: "SAML e2e Tenant Signing CA".into(),
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 1825,
            })
            .await
            .expect("tenant signing CA")
            .certificate
    }
}

pub fn saml_admin_uri(tenant_id: Uuid, tail: &str) -> String {
    format!("/api/v1/tenants/{tenant_id}/saml/{tail}")
}

/// One administrator call: `(status, body text)`.
pub async fn admin_call(
    app: &impl TestApp,
    w: &World,
    method: Method,
    tail: &str,
    body: Option<serde_json::Value>,
) -> (u16, String) {
    let mut req = test::TestRequest::default()
        .method(method)
        .uri(&saml_admin_uri(w.tenant_id, tail))
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header((
            "Authorization",
            format!("Bearer {}", w.admin_token(app).await),
        ));
    if let Some(body) = body {
        req = req.set_json(body);
    }
    let resp = test::call_service(app, req.to_request()).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

pub fn json_of(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or(serde_json::Value::Null)
}

/// The IdP signing credential the fast path installs: RSA-4096 like D-21's, from
/// OpenSSL, minted once per binary (the PKI service's own RSA-4096 generation
/// takes about a minute in a debug build, which only the tests that exercise
/// the administrator route pay).
pub fn idp_material() -> &'static Material {
    static M: OnceLock<Material> = OnceLock::new();
    M.get_or_init(|| rsa_material(4096, "AXIAM SAML IdP test", 365))
}

/// Install the tenant's active credential directly, sealed exactly as D-21 seals
/// it — what `saml_idp_sso_test` and `saml_idp_slo_test` do.
pub async fn install_idp_credential(w: &World) {
    let id = Uuid::new_v4();
    let sealed = w
        .custodians
        .store_for(CaKeyCustody::Database)
        .unwrap()
        .store(w.org_id, id, &idp_material().pkcs8_pem)
        .await
        .unwrap();
    let StoredCaKey::Inline(ciphertext) = sealed else {
        panic!("the database custodian seals inline");
    };
    let now = chrono::Utc::now();
    SurrealSamlIdpCredentialRepository::new(w.db.clone())
        .create(StoreSamlIdpCredential {
            id,
            tenant_id: w.tenant_id,
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

/// Issue the tenant's active IdP signing credential through the administrator
/// route (RSA-4096, from a tenant signing CA): the certificate PEM it returns.
pub async fn issue_idp_credential(app: &impl TestApp, w: &World) -> String {
    let ca = w.tenant_ca().await;
    let (status, text) = admin_call(
        app,
        w,
        Method::POST,
        "idp-credentials",
        Some(serde_json::json!({ "issuer_ca_id": ca.id, "slot": "active", "validity_days": 90 })),
    )
    .await;
    assert_eq!(status, 201, "the credential is issued");
    json_of(&text)["certificate_pem"]
        .as_str()
        .expect("the credential's certificate")
        .to_owned()
}

/// Register a service provider through the administrator route, returning its
/// id. `body` is a `SamlServiceProviderInput`.
pub async fn register_sp(app: &impl TestApp, w: &World, body: serde_json::Value) -> Uuid {
    let (status, text) = admin_call(app, w, Method::POST, "service-providers", Some(body)).await;
    assert_eq!(status, 201, "the service provider is registered");
    Uuid::parse_str(json_of(&text)["id"].as_str().expect("an id")).unwrap()
}

/// The IdP metadata document, fetched from the route an SP administrator would
/// fetch it from.
pub async fn fetch_idp_metadata(app: &impl TestApp, tenant_id: Uuid) -> String {
    let resp = test::call_service(
        app,
        test::TestRequest::get()
            .uri(&format!("/saml/v2/{tenant_id}/metadata"))
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "the IdP metadata is served");
    String::from_utf8(test::read_body(resp).await.to_vec()).unwrap()
}

// ---------------------------------------------------------------------------
// A browser: a cookie jar and the access cookie, nothing more
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
pub struct Browser {
    pub jar: BTreeMap<String, String>,
    pub access: Option<String>,
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

    pub fn op_cookie(&self) -> Option<String> {
        self.jar.get("axiam_op_session").cloned()
    }

    pub async fn get(&mut self, app: &impl TestApp, uri: &str) -> actix_web::dev::ServiceResponse {
        self.get_with(app, uri, &[]).await
    }

    pub async fn get_with(
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

    /// A cross-site form post: the browser sends no `SameSite=Lax` cookie on it,
    /// so none is attached, though it keeps what the answer sets.
    pub async fn post_form(
        &mut self,
        app: &impl TestApp,
        uri: &str,
        body: String,
    ) -> actix_web::dev::ServiceResponse {
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(uri)
            .insert_header(("Content-Type", "application/x-www-form-urlencoded"))
            .set_payload(body);
        let resp = test::call_service(app, req.to_request()).await;
        self.keep(&resp);
        resp
    }

    /// Sign in over HTTP at the real login endpoint, keeping the OP cookie the
    /// sign-in mints at the tenant's SAML SSO path and the access cookie.
    pub async fn sign_in(&mut self, app: &impl TestApp, w: &World, username: &str) {
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

    /// `GET /api/v1/auth/me` with the access cookie from the sign-in: the status.
    pub async fn me(&self, app: &impl TestApp) -> u16 {
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

/// The first leg answered `303`; run the second leg, hopping to sign in as
/// `username` when the browser has no session, and return the auto-post page.
pub async fn complete_login(
    app: &impl TestApp,
    w: &World,
    browser: &mut Browser,
    first_leg: &actix_web::dev::ServiceResponse,
    username: &str,
) -> String {
    assert_eq!(
        first_leg.status().as_u16(),
        303,
        "the first leg answers 303"
    );
    let mut resp = browser.get(app, &location(first_leg)).await;
    if resp.status().as_u16() == 302 {
        let target = location(&resp);
        assert!(
            target.starts_with("/login?return_to="),
            "an anonymous browser is sent to the sign-in page"
        );
        let return_to = url::form_urlencoded::parse(target.split_once('?').unwrap().1.as_bytes())
            .find(|(k, _)| k == "return_to")
            .map(|(_, v)| v.into_owned())
            .expect("a return_to");
        browser.sign_in(app, w, username).await;
        resp = browser.get(app, &return_to).await;
    }
    assert_eq!(resp.status().as_u16(), 200, "the second leg issues");
    body_of(resp).await
}

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

pub fn enc(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

pub fn location(resp: &actix_web::dev::ServiceResponse) -> String {
    resp.headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

pub fn header(resp: &actix_web::dev::ServiceResponse, name: &str) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

pub async fn body_of(resp: actix_web::dev::ServiceResponse) -> String {
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

/// `(action, document, RelayState)` from an auto-post page carrying `field`,
/// the document base64-decoded.
pub fn posted(page: &str, field: &str) -> (String, String, Option<String>) {
    let read = |marker: &str| -> Option<String> {
        let start = page.find(marker)? + marker.len();
        let end = page[start..].find('"')? + start;
        Some(html_unescape(&page[start..end]))
    };
    let action = read("action=\"").expect("a form action");
    let value = read(&format!("name=\"{field}\" value=\"")).expect("the message field");
    let xml = String::from_utf8(STANDARD.decode(&value).unwrap()).unwrap();
    (action, xml, read("name=\"RelayState\" value=\""))
}

/// The base64 `SAMLResponse` form value of an auto-post page, as the browser
/// would carry it to the SP.
pub fn posted_response_b64(page: &str) -> (String, String, Option<String>) {
    let read = |marker: &str| -> Option<String> {
        let start = page.find(marker)? + marker.len();
        let end = page[start..].find('"')? + start;
        Some(html_unescape(&page[start..end]))
    };
    (
        read("action=\"").expect("a form action"),
        read("name=\"SAMLResponse\" value=\"").expect("a SAMLResponse"),
        read("name=\"RelayState\" value=\""),
    )
}

pub fn attr(xml: &str, name: &str) -> Option<String> {
    let marker = format!(" {name}=\"");
    let start = xml.find(&marker)? + marker.len();
    let end = xml[start..].find('"')? + start;
    Some(xml[start..end].to_owned())
}

pub fn sso_path(tenant_id: Uuid) -> String {
    format!("/saml/v2/{tenant_id}/sso")
}

pub fn slo_path(tenant_id: Uuid) -> String {
    format!("/saml/v2/{tenant_id}/slo")
}

pub fn metadata_path(tenant_id: Uuid) -> String {
    format!("/saml/v2/{tenant_id}/metadata")
}

/// The path and query of an absolute URL the IdP's metadata advertises: what an
/// in-process app answers, since nothing listens at `ROOT_ISSUER`.
pub fn path_and_query(url: &str) -> String {
    let parsed = url::Url::parse(url).expect("an absolute URL");
    match parsed.query() {
        Some(q) => format!("{}?{q}", parsed.path()),
        None => parsed.path().to_owned(),
    }
}

//! **T23.2.5** — the SAML IdP registry and credential routes over HTTP (G-2,
//! contract §29, D-34, D-40, D-41, D-42).
//!
//! Real RBAC (the engine and the seeded roles), the production route table, the
//! real repositories on an in-memory database and the real PKI services. What is
//! pinned, each as a test over HTTP:
//!
//! * every route's happy path and every answer §29.3 lists: `400` naming the
//!   rule, `403`, `404`, `409`, `429`, `503`;
//! * the validator on every write and each of the four D-42 refusals
//!   (`encrypt_assertions`, an unusable signing certificate, a changed
//!   `entity_id`, an `allowed_groups` entry outside the tenant), on create and on
//!   update;
//! * the credential lifecycle — issue into an empty slot only (an occupied one is
//!   `409` before any key is generated), promote in one transaction with its
//!   `409`s and a race, retire and its idempotence — and that **no response ever
//!   carries a key or its ciphertext**;
//! * SP metadata import as a parse to a draft, never a write: good, DTD/XXE,
//!   aggregate, non-https, private addresses refused through the SSRF guard,
//!   oversize, no `encrypt_assertions`, and the generic messages;
//! * the IdP metadata endpoint: parsed back with `samael`, active before next, no
//!   retired key, `ETag`/`304`, `HEAD`, the D-20 `404`s indistinguishable, the
//!   bucket;
//! * one permission per operation, another tenant's id refused, a service-account
//!   token refused, the write buckets pinned per route, the audit rows with no
//!   certificate in them.
//!
//! Keys and certificates are generated at runtime; no assertion or panic message
//! formats a certificate, a key, a token or a document.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use actix_web::http::Method;
use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::ca_keys::{CaKeyCustody, StoredCaKey};
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::certificate::{
    CaCertificate, CreateCaCertificate, CreateIntermediateCa, KeyAlgorithm, SignIntermediateCsr,
};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::saml_idp_credential::{
    SamlIdpCredentialStatus, SealedSamlIdpKey, StoreSamlIdpCredential,
};
use axiam_core::models::saml_sp::{
    AcsEndpoint, NameIdFormat, SamlBinding, SamlServiceProviderInput,
};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::settings::{SetTenantOverride, system_defaults};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, GroupRepository, OrganizationRepository, Pagination,
    PermissionRepository, RoleRepository, SamlIdpCredentialRepository,
    SamlServiceProviderRepository, ServiceAccountRepository, SettingsRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealCaCertificateRepository, SurrealCertificateRepository,
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealSamlIdpCredentialRepository,
    SurrealSamlServiceProviderRepository, SurrealScopeRepository, SurrealServiceAccountRepository,
    SurrealSettingsRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use axiam_pki::{CaService, CertService, PkiConfig, SamlIdpCredentialService};
use axiam_test_support::test_password;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{Duration, Utc};
use sha2::Digest;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem, SurrealKv};
use uuid::Uuid;

type TestDb = Db;

const TEST_PEER: &str = "127.0.0.1:40000";
const ROOT_ISSUER: &str = "https://iam.example.com";
const SP_ENTITY: &str = "https://payroll.example.test/saml/metadata";
const ACS: &str = "https://payroll.example.test/saml/acs";

// ---------------------------------------------------------------------------
// Fixtures: nothing here is a literal credential
// ---------------------------------------------------------------------------

/// A fresh Ed25519 JWT keypair, minted once per process.
fn jwt_pair() -> &'static (String, String) {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

/// 32 bytes minted at runtime, for the PKI sealing custodian.
fn runtime_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

fn auth_config() -> AuthConfig {
    let (private_pem, public_pem) = jwt_pair().clone();
    AuthConfig {
        jwt_private_key_pem: private_pem,
        jwt_public_key_pem: public_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ROOT_ISSUER.into(),
        ..AuthConfig::default()
    }
}

/// A self-signed certificate generated now, as PEM.
fn cert_pem() -> String {
    let pair = rcgen::KeyPair::generate().expect("key pair");
    rcgen::CertificateParams::new(vec!["sp.example.test".to_string()])
        .expect("params")
        .self_signed(&pair)
        .expect("self-signed")
        .pem()
}

/// A self-signed certificate whose validity ended in 2002.
fn expired_cert_pem() -> String {
    let pair = rcgen::KeyPair::generate().expect("key pair");
    let mut params =
        rcgen::CertificateParams::new(vec!["old.example.test".to_string()]).expect("params");
    params.not_before = rcgen::date_time_ymd(2001, 1, 1);
    params.not_after = rcgen::date_time_ymd(2002, 1, 1);
    params.self_signed(&pair).expect("self-signed").pem()
}

/// An ECDSA P-256 certificate, which an SP may sign requests with.
fn ecdsa_cert_pem() -> String {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key pair");
    rcgen::CertificateParams::new(vec!["ec.example.test".to_string()])
        .expect("params")
        .self_signed(&pair)
        .expect("self-signed")
        .pem()
}

/// An Ed25519 certificate: a key no verifier AXIAM runs for SPs can use.
fn ed25519_cert_pem() -> String {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("key pair");
    rcgen::CertificateParams::new(vec!["ed.example.test".to_string()])
        .expect("params")
        .self_signed(&pair)
        .expect("self-signed")
        .pem()
}

fn der_b64(pem: &str) -> String {
    STANDARD.encode(axiam_federation::cert::pem_cert_to_der(pem).expect("der"))
}

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

struct World {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    other_tenant_id: Uuid,
    admin: Uuid,
    auth: AuthConfig,
    authz: Arc<dyn AuthzChecker>,
    custodians: Arc<axiam_pki::CaKeyCustodians>,
}

async fn tenant_in(db: &Surreal<TestDb>, org_id: Uuid, slug: &str) -> Uuid {
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: format!("Tenant {slug}"),
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

async fn active_user(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@example.com"),
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

/// A user whose only grants are `actions`.
async fn user_holding(db: &Surreal<TestDb>, tenant_id: Uuid, actions: &[&str]) -> Uuid {
    let user_id = active_user(db, tenant_id, &format!("u{}", Uuid::new_v4().simple())).await;
    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
        .create(CreateRole {
            tenant_id,
            name: format!("r{}", Uuid::new_v4().simple()),
            description: "saml test role".into(),
            is_global: true,
        })
        .await
        .unwrap();
    let permissions = SurrealPermissionRepository::new(db.clone());
    let all = permissions
        .list(
            tenant_id,
            Pagination {
                offset: 0,
                limit: 10_000,
                search: None,
            },
        )
        .await
        .unwrap()
        .items;
    for wanted in actions {
        let permission = all
            .iter()
            .find(|p| p.action == *wanted)
            .expect("seeded permission");
        permissions
            .grant_to_role(tenant_id, role.id, permission.id)
            .await
            .unwrap();
    }
    roles
        .assign_to_user(tenant_id, user_id, role.id, AssignmentScope::global())
        .await
        .unwrap();
    user_id
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    world_on(db).await
}

async fn world_on(db: Surreal<TestDb>) -> World {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SAML Admin Org".into(),
            slug: format!("saml-org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    // SAML on for the organization; tests that want it off override the tenant.
    let mut settings = system_defaults();
    settings.saml_idp_enabled = true;
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, settings)
        .await
        .unwrap();
    let tenant_id = tenant_in(&db, org.id, "saml-home").await;
    let other_tenant_id = tenant_in(&db, org.id, "saml-other").await;
    let admin = active_user(&db, tenant_id, "admin").await;
    assign_named_role(&db, tenant_id, admin, "admin").await;
    let authz: Arc<dyn AuthzChecker> = Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ));
    let custodians = Arc::new(
        axiam_pki::ca_key_store::custodians_from(Some(runtime_bytes()), &|_| None).unwrap(),
    );
    World {
        db,
        org_id: org.id,
        tenant_id,
        other_tenant_id,
        admin,
        auth: auth_config(),
        authz,
        custodians,
    }
}

impl World {
    fn token_for(&self, user_id: Uuid) -> String {
        issue_access_token(
            user_id,
            self.tenant_id,
            self.org_id,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap()
    }

    fn admin_token(&self) -> String {
        self.token_for(self.admin)
    }

    /// `AppState` whose PKI services share this world's custodians, so a CA made
    /// by `ca_service` is one the credential service can sign under, and a key
    /// this file seals is one the service can open.
    fn state(&self) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        let pki_config = PkiConfig::default();
        state.saml_idp.credential_service = SamlIdpCredentialService::new(
            CertService::new(
                SurrealCaCertificateRepository::new(self.db.clone()),
                SurrealCertificateRepository::new(self.db.clone()),
                pki_config.clone(),
                Arc::clone(&state.crypto_semaphore),
                Arc::clone(&self.custodians),
            ),
            Arc::clone(&self.custodians),
            SurrealSamlIdpCredentialRepository::new(self.db.clone()),
        );
        state.pki.ca_service = CaService::new(
            SurrealCaCertificateRepository::new(self.db.clone()),
            pki_config,
            Arc::clone(&state.crypto_semaphore),
            Arc::clone(&self.custodians),
        );
        state
    }

    fn credentials(&self) -> SurrealSamlIdpCredentialRepository<TestDb> {
        SurrealSamlIdpCredentialRepository::new(self.db.clone())
    }

    fn sps(&self) -> SurrealSamlServiceProviderRepository<TestDb> {
        SurrealSamlServiceProviderRepository::new(self.db.clone())
    }

    /// A credential row, with its key sealed the way D-21 seals it, in a window
    /// of `[now + from_days, now + to_days]`.
    async fn install(
        &self,
        tenant_id: Uuid,
        status: SamlIdpCredentialStatus,
        from_days: i64,
        to_days: i64,
    ) -> Installed {
        let id = Uuid::new_v4();
        let pair = rcgen::KeyPair::generate().expect("key pair");
        let cert_pem = rcgen::CertificateParams::new(vec!["idp.example.test".to_string()])
            .expect("params")
            .self_signed(&pair)
            .expect("self-signed")
            .pem();
        let sealed = self
            .custodians
            .store_for(CaKeyCustody::Database)
            .unwrap()
            .store(self.org_id, id, &pair.serialize_pem())
            .await
            .unwrap();
        let StoredCaKey::Inline(ciphertext) = sealed else {
            panic!("the database custodian seals inline");
        };
        let now = Utc::now();
        self.credentials()
            .create(StoreSamlIdpCredential {
                id,
                tenant_id,
                issuer_ca_id: Uuid::new_v4(),
                certificate_pem: cert_pem.clone(),
                serial: format!("{:02x}", id.as_bytes()[0]),
                fingerprint: hex::encode(sha2::Sha256::digest(
                    axiam_federation::cert::pem_cert_to_der(&cert_pem).unwrap(),
                )),
                not_before: now + Duration::days(from_days),
                not_after: now + Duration::days(to_days),
                status,
                key: SealedSamlIdpKey {
                    custody: CaKeyCustody::Database,
                    locator: None,
                    ciphertext: Some(ciphertext.clone()),
                },
            })
            .await
            .unwrap();
        Installed {
            id,
            cert_pem,
            ciphertext,
        }
    }

    async fn audit_rows(&self, action: &str) -> Vec<AuditLogEntry> {
        SurrealAuditLogRepository::new(self.db.clone())
            .list(
                self.tenant_id,
                AuditLogFilter {
                    action: Some(action.into()),
                    ..Default::default()
                },
                Pagination {
                    offset: 0,
                    limit: 100,
                    search: None,
                },
            )
            .await
            .unwrap()
            .items
    }

    async fn every_audit_row(&self) -> Vec<AuditLogEntry> {
        SurrealAuditLogRepository::new(self.db.clone())
            .list(
                self.tenant_id,
                AuditLogFilter::default(),
                Pagination {
                    offset: 0,
                    limit: 1000,
                    search: None,
                },
            )
            .await
            .unwrap()
            .items
    }

    /// An organization root CA and a tenant signing CA beneath it.
    async fn tenant_ca(
        &self,
        state: &AppState<TestDb>,
        org_id: Uuid,
        tenant_id: Uuid,
    ) -> (CaCertificate, CaCertificate) {
        let root = state
            .pki
            .ca_service
            .generate(CreateCaCertificate {
                organization_id: org_id,
                subject: "Test Org Root CA".into(),
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 3650,
                intermediate_subject: None,
                intermediate_validity_days: None,
                issue_from_root: false,
            })
            .await
            .expect("root CA")
            .certificate;
        let signing = state
            .pki
            .ca_service
            .generate_intermediate(CreateIntermediateCa {
                organization_id: org_id,
                tenant_id,
                parent_ca_id: root.id,
                subject: "Tenant Signing CA".into(),
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 1825,
            })
            .await
            .expect("tenant signing CA")
            .certificate;
        (root, signing)
    }
}

/// A credential this file installed: its id, certificate and the ciphertext its
/// key was sealed to — what no response may carry.
struct Installed {
    id: Uuid,
    cert_pem: String,
    ciphertext: Vec<u8>,
}

/// The limits every test but the rate-limit ones runs under. The shared counter
/// back-fills a key it first sees part-way through a window pro rata, so a test
/// that sends a dozen writes from one address can be refused with `429`
/// depending on the second of the minute it started in. The buckets are pinned,
/// deterministically, by their own tests.
fn permissive_limits() -> RateLimitConfig {
    RateLimitConfig {
        saml_admin_per_min: 100_000,
        end_session_per_min: 100_000,
        login_per_min: 100_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! app {
    ($state:expr, $w:expr) => {
        app!($state, $w, permissive_limits())
    };
    ($state:expr, $w:expr, $limits:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.authz.clone()))
                .app_data(web::Data::new($state))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &$limits)),
        )
        .await
    };
}

fn request(method: Method, uri: &str, token: &str) -> test::TestRequest {
    test::TestRequest::default()
        .method(method)
        .uri(uri)
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
}

async fn send<S, B>(app: &S, req: test::TestRequest) -> (u16, String)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let resp = test::call_service(app, req.to_request()).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn json_of(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or(serde_json::Value::Null)
}

fn saml_uri(tenant_id: Uuid, tail: &str) -> String {
    format!("/api/v1/tenants/{tenant_id}/saml/{tail}")
}

/// The rule a `400 validation_error` names: its `message`, without the
/// "Validation error: " every such answer carries in front of it.
fn message_of(body: &serde_json::Value) -> String {
    let message = body["message"].as_str().unwrap_or_default();
    message
        .strip_prefix("Validation error: ")
        .unwrap_or(message)
        .to_string()
}

/// No key, no ciphertext, no custody anywhere in `text`.
fn assert_keyless(label: &str, text: &str, installed: &[&Installed]) {
    for marker in [
        "PRIVATE KEY",
        "encrypted_private_key",
        "private_key",
        "key_custody",
        "key_locator",
        "ciphertext",
    ] {
        assert!(
            !text.contains(marker),
            "{label}: the answer carries {marker}"
        );
    }
    for credential in installed {
        assert!(
            !text.contains(&STANDARD.encode(&credential.ciphertext))
                && !text.contains(&hex::encode(&credential.ciphertext))
                && !text.contains(&format!("{:?}", credential.ciphertext)),
            "{label}: the answer carries sealed key bytes"
        );
    }
}

fn acs(url: &str, index: u16, is_default: bool) -> serde_json::Value {
    serde_json::json!({ "url": url, "binding": "http_post", "index": index, "is_default": is_default })
}

/// A complete, valid `SamlServiceProviderInput` body.
fn sp_body(entity_id: &str) -> serde_json::Value {
    serde_json::json!({
        "display_name": "Payroll",
        "entity_id": entity_id,
        "acs_urls": [acs(ACS, 0, true)],
    })
}

fn sp_input(entity_id: &str) -> SamlServiceProviderInput {
    SamlServiceProviderInput {
        enabled: true,
        display_name: "Payroll".into(),
        entity_id: entity_id.into(),
        acs_urls: vec![AcsEndpoint {
            url: ACS.into(),
            binding: SamlBinding::HttpPost,
            index: 0,
            is_default: true,
        }],
        slo_url: None,
        slo_binding: None,
        name_id_format: NameIdFormat::Persistent,
        sign_responses: true,
        encrypt_assertions: false,
        sp_signing_cert_pem: None,
        sp_encryption_cert_pem: None,
        want_authn_requests_signed: false,
        allow_idp_initiated: false,
        attribute_mappings: Vec::new(),
        allowed_groups: Vec::new(),
    }
}

async fn create_sp<S, B>(app: &S, w: &World, body: serde_json::Value) -> (u16, serde_json::Value)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let (status, text) = send(
        app,
        request(
            Method::POST,
            &saml_uri(w.tenant_id, "service-providers"),
            &w.admin_token(),
        )
        .set_json(body),
    )
    .await;
    (status, json_of(&text))
}

async fn put_sp<S, B>(
    app: &S,
    w: &World,
    sp_id: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let (status, text) = send(
        app,
        request(
            Method::PUT,
            &saml_uri(w.tenant_id, &format!("service-providers/{sp_id}")),
            &w.admin_token(),
        )
        .set_json(body),
    )
    .await;
    (status, json_of(&text))
}

async fn get_json<S, B>(app: &S, w: &World, tail: &str) -> (u16, String)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    send(
        app,
        request(Method::GET, &saml_uri(w.tenant_id, tail), &w.admin_token()),
    )
    .await
}

async fn post_json<S, B>(
    app: &S,
    w: &World,
    tail: &str,
    body: serde_json::Value,
) -> (u16, serde_json::Value, String)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let req = request(Method::POST, &saml_uri(w.tenant_id, tail), &w.admin_token());
    let req = if body.is_null() {
        req
    } else {
        req.set_json(body)
    };
    let (status, text) = send(app, req).await;
    (status, json_of(&text), text)
}

// ---------------------------------------------------------------------------
// Service providers: CRUD, §29.3 rules 1–5
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_service_provider_is_created_read_listed_replaced_and_deleted() {
    let w = world().await;
    let app = app!(w.state(), w);

    // Create: 201 with every member of §29.2 and no `sign_assertions`.
    let mut body = sp_body(SP_ENTITY);
    body["acs_urls"] = serde_json::json!([acs(ACS, 0, true), acs(&format!("{ACS}-2"), 1, false)]);
    body["slo_url"] = "https://payroll.example.test/saml/slo".into();
    body["slo_binding"] = "http_redirect".into();
    body["name_id_format"] = "email_address".into();
    body["allow_idp_initiated"] = true.into();
    body["attribute_mappings"] = serde_json::json!([{ "saml_name": "mail", "source": "email" }]);
    let (status, created) = create_sp(&app, &w, body).await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_string();
    assert_eq!(created["tenant_id"], w.tenant_id.to_string());
    assert_eq!(created["entity_id"], SP_ENTITY);
    assert_eq!(created["enabled"], true, "omitted: defaults to true");
    assert_eq!(created["sign_responses"], true);
    assert_eq!(created["encrypt_assertions"], false);
    assert_eq!(created["want_authn_requests_signed"], false);
    assert_eq!(created["name_id_format"], "email_address");
    assert_eq!(created["slo_binding"], "http_redirect");
    assert_eq!(created["acs_urls"].as_array().unwrap().len(), 2);
    assert!(
        created.get("sign_assertions").is_none(),
        "assertions are signed always"
    );
    assert!(created["created_at"].is_string() && created["updated_at"].is_string());

    // Get and list.
    let (status, text) = get_json(&app, &w, &format!("service-providers/{id}")).await;
    assert_eq!(status, 200);
    assert_eq!(json_of(&text), created);
    let (status, text) = get_json(&app, &w, "service-providers").await;
    let page = json_of(&text);
    assert_eq!(status, 200);
    assert_eq!(page["total"], 1);
    assert_eq!(page["offset"], 0);
    assert!(page["limit"].is_u64());
    assert_eq!(page["items"][0]["id"], id);

    // Replace: what the body omits is reset, not kept.
    let (status, replaced) = put_sp(&app, &w, &id, sp_body(SP_ENTITY)).await;
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(replaced["id"], id.as_str());
    assert_eq!(replaced["slo_url"], serde_json::Value::Null);
    assert_eq!(replaced["slo_binding"], serde_json::Value::Null);
    assert_eq!(replaced["name_id_format"], "persistent");
    assert_eq!(replaced["allow_idp_initiated"], false);
    assert_eq!(replaced["acs_urls"].as_array().unwrap().len(), 1);
    assert_eq!(replaced["attribute_mappings"], serde_json::json!([]));
    assert_eq!(replaced["created_at"], created["created_at"]);

    // Delete, and then it is gone: a second delete is 404, not a success.
    let uri = saml_uri(w.tenant_id, &format!("service-providers/{id}"));
    let (status, text) = send(&app, request(Method::DELETE, &uri, &w.admin_token())).await;
    assert_eq!((status, text.as_str()), (204, ""));
    let (status, _) = send(&app, request(Method::DELETE, &uri, &w.admin_token())).await;
    assert_eq!(
        status, 404,
        "a second delete is not made to look like a success"
    );
    let (status, _) = get_json(&app, &w, &format!("service-providers/{id}")).await;
    assert_eq!(status, 404);
}

#[actix_rt::test]
async fn the_list_pages_and_searches_before_it_pages() {
    let w = world().await;
    let app = app!(w.state(), w);
    for n in 0..3 {
        let mut body = sp_body(&format!("https://alpha{n}.example.test/m"));
        body["display_name"] = format!("Alpha {n}").into();
        assert_eq!(create_sp(&app, &w, body).await.0, 201);
    }
    let mut body = sp_body("https://beta.example.test/m");
    body["display_name"] = "Beta Billing".into();
    let (_, beta) = create_sp(&app, &w, body).await;

    let (_, text) = get_json(&app, &w, "service-providers?limit=2&offset=0").await;
    let first = json_of(&text);
    assert_eq!(
        (
            first["total"].as_u64(),
            first["items"].as_array().map(Vec::len)
        ),
        (Some(4), Some(2))
    );
    let (_, text) = get_json(&app, &w, "service-providers?limit=2&offset=2").await;
    assert_eq!(json_of(&text)["items"].as_array().unwrap().len(), 2);

    let (_, text) = get_json(&app, &w, "service-providers?search=ALPHA&limit=2").await;
    let alpha = json_of(&text);
    assert_eq!(alpha["total"], 3, "total counts the matches, not the rows");
    assert_eq!(alpha["items"].as_array().unwrap().len(), 2);
    let (_, text) = get_json(&app, &w, "service-providers?search=beta.example").await;
    assert_eq!(json_of(&text)["total"], 1, "entity id is searched");
    let id = beta["id"].as_str().unwrap();
    let (_, text) = get_json(&app, &w, &format!("service-providers?search={id}")).await;
    assert_eq!(json_of(&text)["items"][0]["id"], id, "so is the record id");
    let (_, text) = get_json(&app, &w, "service-providers?search=%20%20").await;
    assert_eq!(json_of(&text)["total"], 4, "a blank term is no term");
}

#[actix_rt::test]
async fn every_validator_refusal_is_a_400_validation_error_naming_the_rule() {
    let w = world().await;
    let app = app!(w.state(), w);
    let private_key_block = rcgen::KeyPair::generate().unwrap().serialize_pem();
    let cases: Vec<(&str, serde_json::Value, &str)> = vec![
        (
            "empty display_name",
            {
                let mut b = sp_body(SP_ENTITY);
                b["display_name"] = "".into();
                b
            },
            "display_name",
        ),
        (
            "padded display_name",
            {
                let mut b = sp_body(SP_ENTITY);
                b["display_name"] = " Payroll".into();
                b
            },
            "display_name",
        ),
        (
            "control character in entity_id",
            {
                let mut b = sp_body(SP_ENTITY);
                b["entity_id"] = "https://a.test/\u{7}".into();
                b
            },
            "entity_id",
        ),
        (
            "no ACS endpoint",
            {
                let mut b = sp_body(SP_ENTITY);
                b["acs_urls"] = serde_json::json!([]);
                b
            },
            "acs_urls",
        ),
        (
            "a glob in an ACS URL",
            {
                let mut b = sp_body(SP_ENTITY);
                b["acs_urls"] = serde_json::json!([acs("https://*.example.test/acs", 0, false)]);
                b
            },
            "wildcards",
        ),
        (
            "an http ACS URL",
            {
                let mut b = sp_body(SP_ENTITY);
                b["acs_urls"] =
                    serde_json::json!([acs("http://payroll.example.test/acs", 0, false)]);
                b
            },
            "https",
        ),
        (
            "an ACS URL with a fragment",
            {
                let mut b = sp_body(SP_ENTITY);
                b["acs_urls"] =
                    serde_json::json!([acs("https://payroll.example.test/acs#x", 0, false)]);
                b
            },
            "fragment",
        ),
        (
            "a repeated ACS URL",
            {
                let mut b = sp_body(SP_ENTITY);
                b["acs_urls"] = serde_json::json!([acs(ACS, 0, true), acs(ACS, 1, false)]);
                b
            },
            "acs_urls",
        ),
        (
            "a repeated ACS index",
            {
                let mut b = sp_body(SP_ENTITY);
                b["acs_urls"] =
                    serde_json::json!([acs(ACS, 0, true), acs(&format!("{ACS}-2"), 0, false)]);
                b
            },
            "index",
        ),
        (
            "two default endpoints",
            {
                let mut b = sp_body(SP_ENTITY);
                b["acs_urls"] =
                    serde_json::json!([acs(ACS, 0, true), acs(&format!("{ACS}-2"), 1, true)]);
                b
            },
            "default",
        ),
        (
            "an slo_url without a binding",
            {
                let mut b = sp_body(SP_ENTITY);
                b["slo_url"] = "https://payroll.example.test/slo".into();
                b
            },
            "slo",
        ),
        (
            "a private key where a certificate belongs",
            {
                let mut b = sp_body(SP_ENTITY);
                b["sp_signing_cert_pem"] = private_key_block.clone().into();
                b
            },
            "sp_signing_cert_pem",
        ),
        (
            "want_authn_requests_signed without a certificate",
            {
                let mut b = sp_body(SP_ENTITY);
                b["want_authn_requests_signed"] = true.into();
                b
            },
            "want_authn_requests_signed",
        ),
        (
            "a repeated attribute name",
            {
                let mut b = sp_body(SP_ENTITY);
                b["attribute_mappings"] = serde_json::json!([{"duplicate attribute name":"a","source":"email"},{"saml_name":"a","source":"username"}]);
                b
            },
            "saml_name",
        ),
        (
            "an unknown name_format",
            {
                let mut b = sp_body(SP_ENTITY);
                b["attribute_mappings"] =
                    serde_json::json!([{"saml_name":"a","name_format":"urn:x","source":"email"}]);
                b
            },
            "name_format",
        ),
        (
            "more than 256 groups",
            {
                let mut b = sp_body(SP_ENTITY);
                b["allowed_groups"] =
                    serde_json::json!((0..257).map(|_| Uuid::new_v4()).collect::<Vec<_>>());
                b
            },
            "allowed_groups",
        ),
    ];
    for (label, body, names) in &cases {
        let (status, refusal) = create_sp(&app, &w, body.clone()).await;
        assert_eq!(status, 400, "create: {label}");
        assert_eq!(refusal["error"], "validation_error", "create: {label}");
        assert!(
            message_of(&refusal).contains(names),
            "create: {label}: the message names the rule"
        );
        assert!(
            !refusal.to_string().contains("BEGIN"),
            "create: {label}: the message never echoes a certificate or a key"
        );
    }
    // Nothing a refusal did is in the registry.
    assert!(w.sps().list(w.tenant_id).await.unwrap().is_empty());

    // The same rules on update: every case is refused for a stored registration
    // too (each body keeps the stored entity id, so it is the rule that refuses).
    let (status, stored) = create_sp(&app, &w, sp_body(SP_ENTITY)).await;
    assert_eq!(status, 201);
    let id = stored["id"].as_str().unwrap().to_string();
    for (label, body, names) in &cases {
        let (status, refusal) = put_sp(&app, &w, &id, body.clone()).await;
        assert_eq!(status, 400, "update: {label}");
        assert_eq!(refusal["error"], "validation_error", "update: {label}");
        assert!(
            message_of(&refusal).contains(names),
            "update: {label}: the message names the rule"
        );
        assert!(!refusal.to_string().contains("BEGIN"), "update: {label}");
    }
    let intact = w.sps().get(w.tenant_id, id.parse().unwrap()).await.unwrap();
    assert_eq!(
        intact.display_name, "Payroll",
        "no refused update changed the registration"
    );
    assert!(w.audit_rows("saml_sp.updated").await.is_empty());
}

#[actix_rt::test]
async fn each_d42_refusal_is_a_400_on_create_and_on_update() {
    let w = world().await;
    let app = app!(w.state(), w);
    let (status, stored) = create_sp(&app, &w, sp_body(SP_ENTITY)).await;
    assert_eq!(status, 201);
    let id = stored["id"].as_str().unwrap().to_string();

    // An SP of another tenant of the organization, and a group of it.
    let foreign_group = SurrealGroupRepository::new(w.db.clone())
        .create(CreateGroup {
            tenant_id: w.other_tenant_id,
            name: "foreign".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    #[cfg_attr(not(feature = "saml"), allow(unused_mut))]
    let mut refusals: Vec<(&str, serde_json::Value, &str)> = vec![
        (
            "encrypt_assertions",
            {
                let mut b = sp_body(SP_ENTITY);
                b["encrypt_assertions"] = true.into();
                b["sp_encryption_cert_pem"] = cert_pem().into();
                b
            },
            "encrypt_assertions",
        ),
        (
            "an Ed25519 signing certificate",
            {
                let mut b = sp_body(SP_ENTITY);
                b["sp_signing_cert_pem"] = ed25519_cert_pem().into();
                b
            },
            "sp_signing_cert_pem",
        ),
        (
            "a group of another tenant",
            {
                let mut b = sp_body(SP_ENTITY);
                b["allowed_groups"] = serde_json::json!([foreign_group]);
                b
            },
            "allowed_groups",
        ),
        (
            "a group that does not exist",
            {
                let mut b = sp_body(SP_ENTITY);
                b["allowed_groups"] = serde_json::json!([Uuid::new_v4()]);
                b
            },
            "allowed_groups",
        ),
    ];
    // A weak RSA key needs OpenSSL's generator, which is behind `saml`.
    #[cfg(feature = "saml")]
    refusals.push((
        "a 1024-bit RSA signing certificate",
        {
            let mut b = sp_body(SP_ENTITY);
            b["sp_signing_cert_pem"] =
                axiam_federation::saml_idp::test_support::rsa_material(1024, "weak", 30)
                    .cert_pem
                    .into();
            b
        },
        "2048",
    ));
    for (label, body, names) in refusals {
        let mut for_create = body.clone();
        for_create["entity_id"] =
            format!("https://new-{}.example.test/m", Uuid::new_v4().simple()).into();
        let (status, refusal) = create_sp(&app, &w, for_create).await;
        assert_eq!(status, 400, "create: {label}");
        assert_eq!(refusal["error"], "validation_error", "create: {label}");
        assert!(message_of(&refusal).contains(names), "create: {label}");
        assert!(!refusal.to_string().contains("BEGIN"), "create: {label}");

        let (status, refusal) = put_sp(&app, &w, &id, body).await;
        assert_eq!(status, 400, "update: {label}");
        assert!(message_of(&refusal).contains(names), "update: {label}");
    }

    // A changed entity_id is refused on update, whatever else is valid.
    let (status, refusal) = put_sp(&app, &w, &id, sp_body("https://other.example.test/m")).await;
    assert_eq!(status, 400);
    assert_eq!(refusal["error"], "validation_error");
    assert!(message_of(&refusal).contains("register a new service provider"));

    // The stored registration is what it was.
    let intact = w.sps().get(w.tenant_id, id.parse().unwrap()).await.unwrap();
    assert_eq!(intact.entity_id, SP_ENTITY);
    assert!(!intact.encrypt_assertions);
    assert_eq!(w.sps().list(w.tenant_id).await.unwrap().len(), 1);
}

#[actix_rt::test]
async fn the_certificates_the_endpoint_can_use_are_accepted_expired_ones_included() {
    let w = world().await;
    let app = app!(w.state(), w);
    #[cfg_attr(not(feature = "saml"), allow(unused_mut))]
    let mut accepted: Vec<(&str, String)> = vec![
        ("ECDSA P-256", ecdsa_cert_pem()),
        ("an expired certificate", expired_cert_pem()),
    ];
    #[cfg(feature = "saml")]
    accepted.push((
        "RSA-2048",
        axiam_federation::saml_idp::test_support::rsa_material(2048, "sp", 30).cert_pem,
    ));
    for (label, pem) in accepted {
        let mut body = sp_body(&format!(
            "https://c-{}.example.test/m",
            Uuid::new_v4().simple()
        ));
        body["sp_signing_cert_pem"] = pem.clone().into();
        body["want_authn_requests_signed"] = true.into();
        let (status, created) = create_sp(&app, &w, body).await;
        assert_eq!(status, 201, "{label}: {created}");
        assert_eq!(created["sp_signing_cert_pem"], pem.as_str(), "{label}");
    }
}

#[actix_rt::test]
async fn a_duplicate_entity_id_is_409_conflict_and_a_group_of_the_tenant_is_accepted() {
    let w = world().await;
    let app = app!(w.state(), w);
    let group = SurrealGroupRepository::new(w.db.clone())
        .create(CreateGroup {
            tenant_id: w.tenant_id,
            name: "payroll-staff".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    let mut body = sp_body(SP_ENTITY);
    body["allowed_groups"] = serde_json::json!([group, group]);
    let (status, created) = create_sp(&app, &w, body).await;
    assert_eq!(status, 201, "{created}");

    let (status, refusal) = create_sp(&app, &w, sp_body(SP_ENTITY)).await;
    assert_eq!(status, 409);
    assert_eq!(refusal["error"], "conflict");
    assert_eq!(w.sps().list(w.tenant_id).await.unwrap().len(), 1);
}

#[actix_rt::test]
async fn an_unknown_sp_is_404_and_another_tenants_sp_is_not_found_in_this_one() {
    let w = world().await;
    let app = app!(w.state(), w);
    let foreign = w
        .sps()
        .create(
            w.other_tenant_id,
            sp_input("https://foreign.example.test/m"),
        )
        .await
        .unwrap();
    for id in [Uuid::new_v4(), foreign.id] {
        let (status, _) = get_json(&app, &w, &format!("service-providers/{id}")).await;
        assert_eq!(status, 404, "get");
        let (status, _) = put_sp(
            &app,
            &w,
            &id.to_string(),
            sp_body("https://x.example.test/m"),
        )
        .await;
        assert_eq!(status, 404, "update");
        let (status, _) = send(
            &app,
            request(
                Method::DELETE,
                &saml_uri(w.tenant_id, &format!("service-providers/{id}")),
                &w.admin_token(),
            ),
        )
        .await;
        assert_eq!(status, 404, "delete");
    }
    // Nothing the other tenant's id touched changed its registration.
    assert!(w.sps().get(w.other_tenant_id, foreign.id).await.is_ok());
}

#[actix_rt::test]
async fn a_body_that_cannot_be_read_is_a_validation_error_that_echoes_nothing() {
    let w = world().await;
    let app = app!(w.state(), w);
    let marker = format!("marker-{}", Uuid::new_v4().simple());
    let (status, text) = send(
        &app,
        request(
            Method::POST,
            &saml_uri(w.tenant_id, "service-providers"),
            &w.admin_token(),
        )
        .set_json(serde_json::json!({
            "display_name": marker, "entity_id": 7, "acs_urls": "not a list"
        })),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(json_of(&text)["error"], "validation_error");
    assert!(!text.contains(&marker), "serde's quoted value is scrubbed");
    let (status, text) = send(
        &app,
        request(
            Method::POST,
            &saml_uri(w.tenant_id, "service-providers"),
            &w.admin_token(),
        )
        .insert_header(("Content-Type", "application/json"))
        .set_payload("{not json"),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(json_of(&text)["error"], "validation_error");
}

/// T-366: deleting an SP removes what the datastore holds for it, in the same
/// transaction — over HTTP, with a pending `AuthnRequest` and a participant row
/// (`saml_sp_session`, D-37) of its own and one of each of another SP's.
#[actix_rt::test]
async fn deleting_an_sp_over_http_removes_its_pending_requests_and_only_its_own() {
    use axiam_core::models::saml_authn_request::NewPendingSamlRequest;
    use axiam_core::models::saml_slo::NewSamlSpSession;
    use axiam_core::repository::{PendingSamlRequestRepository, SamlSpSessionRepository};
    let w = world().await;
    let state = w.state();
    let pending = state.saml_idp.pending_repo.clone();
    let participants = state.saml_idp.participant_repo.clone();
    let app = app!(state, w);
    let (_, doomed) = create_sp(&app, &w, sp_body("https://doomed.example.test/m")).await;
    let (_, kept) = create_sp(&app, &w, sp_body("https://kept.example.test/m")).await;
    let now = Utc::now();
    let request = |sp_id: &str| NewPendingSamlRequest {
        tenant_id: w.tenant_id,
        sp_id: sp_id.parse().unwrap(),
        request_id: Some("_req".into()),
        acs_url: ACS.into(),
        relay_state: None,
        force_authn: false,
        is_passive: false,
        handle_hash: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        binding_hash: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        created_at: now,
        expires_at: now + Duration::minutes(10),
    };
    let doomed_request = request(doomed["id"].as_str().unwrap());
    let kept_request = request(kept["id"].as_str().unwrap());
    pending.create(doomed_request.clone()).await.unwrap();
    pending.create(kept_request.clone()).await.unwrap();
    let session = Uuid::new_v4();
    let participant = |sp_id: &str| NewSamlSpSession {
        tenant_id: w.tenant_id,
        session_id: session,
        user_id: Uuid::new_v4(),
        sp_id: sp_id.parse().unwrap(),
        sp_entity_id: SP_ENTITY.into(),
        name_id: format!("name-{}", Uuid::new_v4().simple()),
        name_id_format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".into(),
        session_index: format!("idx-{}", Uuid::new_v4().simple()),
        expires_at: now + Duration::hours(1),
    };
    participants
        .record(participant(doomed["id"].as_str().unwrap()))
        .await
        .unwrap();
    participants
        .record(participant(kept["id"].as_str().unwrap()))
        .await
        .unwrap();

    let (status, _) = send(&app, request_to_delete(&w, doomed["id"].as_str().unwrap())).await;
    assert_eq!(status, 204);
    let left = participants
        .list_for_session(w.tenant_id, session)
        .await
        .unwrap();
    assert_eq!(
        left.iter().map(|r| r.sp_id.to_string()).collect::<Vec<_>>(),
        vec![kept["id"].as_str().unwrap().to_owned()],
        "the deleted SP's participant row went with it, and only that one"
    );
    assert!(
        pending
            .get_pending(w.tenant_id, &doomed_request.handle_hash)
            .await
            .unwrap()
            .is_none(),
        "the deleted SP's pending request went with it"
    );
    assert!(
        pending
            .get_pending(w.tenant_id, &kept_request.handle_hash)
            .await
            .unwrap()
            .is_some(),
        "another SP's did not"
    );
}

fn request_to_delete(w: &World, sp_id: &str) -> test::TestRequest {
    request(
        Method::DELETE,
        &saml_uri(w.tenant_id, &format!("service-providers/{sp_id}")),
        &w.admin_token(),
    )
}

#[actix_rt::test]
async fn another_tenants_credential_is_not_found_to_promote_or_retire() {
    let w = world().await;
    let app = app!(w.state(), w);
    let foreign = w
        .install(w.other_tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
        .await;
    for verb in ["promote", "retire"] {
        let (status, refusal, text) = post_json(
            &app,
            &w,
            &format!("idp-credentials/{}/{verb}", foreign.id),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, 404, "{verb}");
        assert_eq!(refusal["error"], "not_found", "{verb}");
        assert_keyless(verb, &text, &[&foreign]);
    }
    let intact = w.credentials().list(w.other_tenant_id).await.unwrap();
    assert_eq!(intact.len(), 1);
    assert_eq!(intact[0].status, SamlIdpCredentialStatus::Next);
}

// ---------------------------------------------------------------------------
// get_idp
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn get_idp_shows_the_urls_the_switch_and_the_slots() {
    let w = world().await;
    let app = app!(w.state(), w);
    let (status, text) = get_json(&app, &w, "idp").await;
    let empty = json_of(&text);
    assert_eq!(status, 200, "{text}");
    let tenant = w.tenant_id;
    assert_eq!(empty["tenant_id"], tenant.to_string());
    assert_eq!(
        empty["entity_id"],
        format!("{ROOT_ISSUER}/saml/v2/{tenant}/metadata")
    );
    assert_eq!(empty["metadata_url"], empty["entity_id"]);
    assert_eq!(
        empty["sso_url"],
        format!("{ROOT_ISSUER}/saml/v2/{tenant}/sso")
    );
    assert_eq!(
        empty["slo_url"],
        format!("{ROOT_ISSUER}/saml/v2/{tenant}/slo")
    );
    assert_eq!(empty["saml_available"], cfg!(feature = "saml"));
    assert_eq!(
        empty["saml_idp_enabled"], true,
        "the organization turned it on"
    );
    assert_eq!(empty["metadata_served"], false, "no credential yet");
    assert_eq!(empty["active_credential_id"], serde_json::Value::Null);
    assert_eq!(empty["next_credential_id"], serde_json::Value::Null);
    assert_eq!(empty.as_object().unwrap().len(), 10);

    let active = w
        .install(tenant, SamlIdpCredentialStatus::Active, -1, 300)
        .await;
    let next = w
        .install(tenant, SamlIdpCredentialStatus::Next, -1, 300)
        .await;
    let (_, text) = get_json(&app, &w, "idp").await;
    let ready = json_of(&text);
    assert_eq!(ready["active_credential_id"], active.id.to_string());
    assert_eq!(ready["next_credential_id"], next.id.to_string());
    assert_eq!(ready["metadata_served"], cfg!(feature = "saml"));

    // The setting is the tenant's effective one: a tenant override turns it off.
    SurrealSettingsRepository::new(w.db.clone())
        .set_tenant_override(
            tenant,
            SetTenantOverride {
                saml_idp_enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (_, text) = get_json(&app, &w, "idp").await;
    let off = json_of(&text);
    assert_eq!(off["saml_idp_enabled"], false);
    assert_eq!(off["metadata_served"], false);
    assert_keyless("get_idp", &text, &[&active, &next]);
}

// ---------------------------------------------------------------------------
// Credentials: list, issue, promote, retire (D-21, D-42)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_credential_list_is_a_bare_array_newest_first_and_carries_no_key() {
    let w = world().await;
    let app = app!(w.state(), w);
    let (status, text) = get_json(&app, &w, "idp-credentials").await;
    assert_eq!((status, json_of(&text)), (200, serde_json::json!([])));

    let retired = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Active, -2, 300)
        .await;
    w.credentials()
        .retire(w.tenant_id, retired.id)
        .await
        .unwrap();
    let active = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Active, -1, 300)
        .await;
    let next = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
        .await;
    let (status, text) = get_json(&app, &w, "idp-credentials").await;
    assert_eq!(status, 200);
    let list = json_of(&text);
    let ids: Vec<&str> = list
        .as_array()
        .expect("a bare array, not a page")
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        [
            next.id.to_string(),
            active.id.to_string(),
            retired.id.to_string()
        ],
        "newest first"
    );
    let first = list[0].as_object().unwrap();
    let mut members: Vec<&str> = first.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "certificate_pem",
            "created_at",
            "fingerprint",
            "id",
            "issuer_ca_id",
            "not_after",
            "not_before",
            "retired_at",
            "serial",
            "status",
            "tenant_id"
        ]
    );
    assert_eq!(list[0]["status"], "next");
    assert_eq!(list[2]["status"], "retired");
    assert!(list[2]["retired_at"].is_string() && list[0]["retired_at"].is_null());
    assert_eq!(list[0]["certificate_pem"], next.cert_pem.as_str());
    assert_keyless("list", &text, &[&retired, &active, &next]);
}

/// Acceptance for issuance: both slots, through the real PKI, one RSA-4096
/// generation each (the expensive step — every other issuance case below is
/// refused before a key is made).
#[actix_rt::test]
async fn issuing_fills_an_empty_slot_with_a_keyless_answer_and_a_sealed_key() {
    let w = world().await;
    let state = w.state();
    let (_root, ca) = w.tenant_ca(&state, w.org_id, w.tenant_id).await;
    let app = app!(state, w);

    let (status, issued, text) = post_json(
        &app,
        &w,
        "idp-credentials",
        serde_json::json!({ "issuer_ca_id": ca.id, "slot": "active", "validity_days": 400 }),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    assert_eq!(issued["status"], "active");
    assert_eq!(issued["tenant_id"], w.tenant_id.to_string());
    assert_eq!(issued["issuer_ca_id"], ca.id.to_string());
    assert!(
        issued["certificate_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert_eq!(issued["fingerprint"].as_str().unwrap().len(), 64);
    assert!(issued["retired_at"].is_null());
    let span = chrono::DateTime::parse_from_rfc3339(issued["not_after"].as_str().unwrap()).unwrap()
        - chrono::DateTime::parse_from_rfc3339(issued["not_before"].as_str().unwrap()).unwrap();
    assert_eq!(span.num_days(), 400, "the requested validity");
    assert_keyless("issue active", &text, &[]);

    // The default validity is a year, and `next` is its own slot.
    let (status, next, text) = post_json(
        &app,
        &w,
        "idp-credentials",
        serde_json::json!({ "issuer_ca_id": ca.id, "slot": "next" }),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    assert_eq!(next["status"], "next");
    let span = chrono::DateTime::parse_from_rfc3339(next["not_after"].as_str().unwrap()).unwrap()
        - chrono::DateTime::parse_from_rfc3339(next["not_before"].as_str().unwrap()).unwrap();
    assert_eq!(span.num_days(), 365);
    assert_keyless("issue next", &text, &[]);

    // The key is in the datastore, sealed, and nowhere else.
    let sealed = w
        .credentials()
        .get_active_sealed(w.tenant_id)
        .await
        .unwrap()
        .expect("an active credential");
    assert_eq!(
        sealed.credential.id.to_string(),
        issued["id"].as_str().unwrap()
    );
    assert!(sealed.key.ciphertext.is_some_and(|c| !c.is_empty()));

    // Both slots are now taken: a third is a 409 before a key is generated.
    for slot in ["active", "next"] {
        let (status, refusal, _) = post_json(
            &app,
            &w,
            "idp-credentials",
            serde_json::json!({ "issuer_ca_id": ca.id, "slot": slot }),
        )
        .await;
        assert_eq!(status, 409, "{slot}");
        assert_eq!(refusal["error"], "conflict");
    }

    // The audit rows: ids, slot, fingerprint — and no certificate.
    let rows = w.audit_rows("saml_idp.credential_issued").await;
    assert_eq!(rows.len(), 2);
    let slots: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.metadata["slot"].as_str())
        .collect();
    assert!(slots.contains(&"active") && slots.contains(&"next"));
    for row in &rows {
        assert_eq!(row.metadata["fingerprint"].as_str().map(str::len), Some(64));
        assert_eq!(row.metadata["issuer_ca_id"], ca.id.to_string());
        assert!(!row.metadata.to_string().contains("BEGIN"));
        assert_eq!(
            row.resource_id.map(|r| r.to_string()).as_deref(),
            row.metadata["credential_id"].as_str()
        );
    }
}

#[actix_rt::test]
async fn an_occupied_slot_is_409_before_any_key_is_generated() {
    // T-363: the answer for an occupied slot does not depend on the CA, so the
    // slot was checked before the CA was looked up and before the RSA-4096 key
    // was generated — a CA that does not exist would otherwise be a 404.
    let w = world().await;
    let app = app!(w.state(), w);
    w.install(w.tenant_id, SamlIdpCredentialStatus::Active, -1, 300)
        .await;
    w.install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
        .await;
    let before = w.credentials().list(w.tenant_id).await.unwrap();
    for slot in ["active", "next"] {
        let started = std::time::Instant::now();
        let (status, refusal, _) = post_json(
            &app,
            &w,
            "idp-credentials",
            serde_json::json!({ "issuer_ca_id": Uuid::new_v4(), "slot": slot }),
        )
        .await;
        assert_eq!(status, 409, "{slot}");
        assert_eq!(refusal["error"], "conflict");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{slot}: an RSA-4096 key was not generated for a refused request"
        );
    }
    assert_eq!(w.credentials().list(w.tenant_id).await.unwrap(), before);
}

#[actix_rt::test]
async fn issuing_refuses_a_bad_validity_and_a_ca_it_may_not_use_without_generating_a_key() {
    let w = world().await;
    let state = w.state();
    let (_root, ca) = w.tenant_ca(&state, w.org_id, w.tenant_id).await;
    // A CA of the sibling tenant, and one of another organization.
    let (_, sibling_ca) = w.tenant_ca(&state, w.org_id, w.other_tenant_id).await;
    let other_org = SurrealOrganizationRepository::new(w.db.clone())
        .create(CreateOrganization {
            name: "Elsewhere".into(),
            slug: format!("else-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let foreign_tenant = tenant_in(&w.db, other_org.id, "foreign").await;
    let (_, foreign_ca) = w.tenant_ca(&state, other_org.id, foreign_tenant).await;
    // A CA AXIAM never held the key of (imported through its CSR), and a revoked one.
    let imported = {
        let csr = {
            let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Offline Tenant CA");
            params.serialize_request(&pair).unwrap().pem().unwrap()
        };
        let (root, _) = w.tenant_ca(&state, w.org_id, Uuid::new_v4()).await;
        state
            .pki
            .ca_service
            .sign_intermediate_csr(SignIntermediateCsr {
                organization_id: w.org_id,
                tenant_id: w.tenant_id,
                parent_ca_id: root.id,
                csr_pem: csr,
                validity_days: 365,
            })
            .await
            .expect("imported intermediate")
    };
    let (_, revoked) = w.tenant_ca(&state, w.org_id, w.tenant_id).await;
    state
        .pki
        .ca_service
        .revoke(w.org_id, revoked.id)
        .await
        .unwrap();
    let app = app!(state, w);

    let started = std::time::Instant::now();
    for days in [0, -1, 731, 100_000, i64::from(u32::MAX) + 1] {
        let (status, refusal, _) = post_json(
            &app,
            &w,
            "idp-credentials",
            serde_json::json!({ "issuer_ca_id": ca.id, "slot": "active", "validity_days": days }),
        )
        .await;
        assert_eq!(status, 400, "validity_days {days}");
        assert_eq!(refusal["error"], "validation_error");
        assert!(message_of(&refusal).contains("validity_days"), "{days}");
    }
    for (label, ca_id) in [
        ("another tenant's CA", sibling_ca.id),
        ("another organization's CA", foreign_ca.id),
        ("no CA at all", Uuid::new_v4()),
    ] {
        let (status, refusal, _) = post_json(
            &app,
            &w,
            "idp-credentials",
            serde_json::json!({ "issuer_ca_id": ca_id, "slot": "active" }),
        )
        .await;
        assert_eq!(status, 404, "{label}");
        assert_eq!(refusal["error"], "not_found", "{label}");
    }
    for (label, ca_id) in [
        ("an imported CA", imported.id),
        ("a revoked CA", revoked.id),
    ] {
        let (status, refusal, _) = post_json(
            &app,
            &w,
            "idp-credentials",
            serde_json::json!({ "issuer_ca_id": ca_id, "slot": "active" }),
        )
        .await;
        assert_eq!(status, 400, "{label}");
        assert_eq!(refusal["error"], "validation_error", "{label}");
    }
    let (status, refusal, _) = post_json(
        &app,
        &w,
        "idp-credentials",
        serde_json::json!({ "issuer_ca_id": ca.id, "slot": "retired" }),
    )
    .await;
    assert_eq!(status, 400, "a slot is active or next");
    assert_eq!(refusal["error"], "validation_error");

    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "every refusal came before a key was generated"
    );
    assert!(w.credentials().list(w.tenant_id).await.unwrap().is_empty());
    assert!(w.audit_rows("saml_idp.credential_issued").await.is_empty());
}

#[actix_rt::test]
async fn promote_swaps_the_slots_in_one_transaction_and_destroys_the_old_key() {
    let w = world().await;
    let app = app!(w.state(), w);
    let old = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
        .await;
    let next = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
        .await;

    let (status, promoted, text) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/promote", next.id),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(promoted["active"]["id"], next.id.to_string());
    assert_eq!(promoted["active"]["status"], "active");
    assert_eq!(promoted["retired"]["id"], old.id.to_string());
    assert_eq!(promoted["retired"]["status"], "retired");
    assert!(promoted["retired"]["retired_at"].is_string());
    assert_eq!(promoted.as_object().unwrap().len(), 2);
    assert_keyless("promote", &text, &[&old, &next]);

    // The signer's lookup finds the promoted key; the old row holds no key.
    let signer = w
        .credentials()
        .get_active_sealed(w.tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(signer.credential.id, next.id);
    assert_eq!(
        signer.key.ciphertext.as_deref(),
        Some(next.ciphertext.as_slice())
    );
    let mut result = w
        .db
        .query("SELECT VALUE (encrypted_private_key IS NONE) FROM saml_idp_credential WHERE meta::id(id) = $id")
        .bind(("id", old.id.to_string()))
        .await
        .unwrap();
    let key_is_gone: Vec<bool> = result.take(0).unwrap();
    assert_eq!(key_is_gone, vec![true], "the old key is destroyed");
    // The `next` slot is free again.
    let (_, text) = get_json(&app, &w, "idp").await;
    let info = json_of(&text);
    assert_eq!(info["active_credential_id"], next.id.to_string());
    assert_eq!(info["next_credential_id"], serde_json::Value::Null);

    // The audit row: both ids and the fingerprint, slots named, no certificate.
    let rows = w.audit_rows("saml_idp.credential_promoted").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["credential_id"], next.id.to_string());
    assert_eq!(
        rows[0].metadata["retired_credential_id"],
        old.id.to_string()
    );
    assert_eq!(rows[0].metadata["slot_from"], "next");
    assert_eq!(rows[0].metadata["slot_to"], "active");
    assert!(rows[0].metadata["fingerprint"].is_string());
    assert!(!rows[0].metadata.to_string().contains("BEGIN"));
}

#[actix_rt::test]
async fn promote_with_no_active_credential_answers_a_null_retired() {
    let w = world().await;
    let app = app!(w.state(), w);
    let next = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
        .await;
    let (status, promoted, _) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/promote", next.id),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(promoted["active"]["id"], next.id.to_string());
    assert!(promoted["retired"].is_null());
}

#[actix_rt::test]
async fn a_promotion_that_cannot_happen_is_a_409_or_404_and_changes_nothing() {
    let w = world().await;
    let app = app!(w.state(), w);
    let active = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
        .await;
    let gone = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, -10, 300)
        .await;
    w.credentials().retire(w.tenant_id, gone.id).await.unwrap();
    // A `next` whose window has closed, and one whose window has not opened.
    let expired = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, -40, -10)
        .await;
    let before = w.credentials().list(w.tenant_id).await.unwrap();

    for (label, id) in [
        ("the active credential", active.id),
        ("a retired credential", gone.id),
        ("a next credential past its window", expired.id),
    ] {
        let (status, refusal, text) = post_json(
            &app,
            &w,
            &format!("idp-credentials/{id}/promote"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, 409, "{label}");
        assert_eq!(refusal["error"], "conflict", "{label}");
        assert_keyless(label, &text, &[&active, &gone, &expired]);
    }
    w.credentials()
        .retire(w.tenant_id, expired.id)
        .await
        .unwrap();
    let not_yet = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, 5, 300)
        .await;
    let (status, refusal, _) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/promote", not_yet.id),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 409, "a next credential before its window");
    assert_eq!(refusal["error"], "conflict");

    let (status, refusal, _) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/promote", Uuid::new_v4()),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(refusal["error"], "not_found");

    let after = w.credentials().list(w.tenant_id).await.unwrap();
    assert_eq!(after.len(), before.len() + 1);
    let still = w
        .credentials()
        .get_active_sealed(w.tenant_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still.credential.id, active.id, "the signer never changed");
    assert_eq!(
        still.key.ciphertext.as_deref(),
        Some(active.ciphertext.as_slice())
    );
    assert!(
        w.audit_rows("saml_idp.credential_promoted")
            .await
            .is_empty()
    );
}

#[actix_rt::test]
async fn a_promotion_repeated_with_a_stale_page_is_a_409() {
    let w = world().await;
    let app = app!(w.state(), w);
    w.install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
        .await;
    let next = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
        .await;
    let uri = format!("idp-credentials/{}/promote", next.id);
    assert_eq!(
        post_json(&app, &w, &uri, serde_json::Value::Null).await.0,
        200
    );
    let (status, refusal, _) = post_json(&app, &w, &uri, serde_json::Value::Null).await;
    assert_eq!(status, 409, "the first call already promoted it");
    assert_eq!(refusal["error"], "conflict");
    assert_eq!(w.audit_rows("saml_idp.credential_promoted").await.len(), 1);
}

/// Of concurrent promotions of one `next` credential exactly one wins, over HTTP,
/// on the engine production runs (`kv-mem` occasionally admits two winners; see
/// `axiam-db/tests/common`). The rest are `409`, never `5xx`, and the tenant ends
/// with exactly one signer.
#[actix_rt::test]
async fn of_two_concurrent_promotions_exactly_one_wins() {
    let dir = tempfile::TempDir::new().expect("temp dir");
    let db = Surreal::new::<SurrealKv>(
        dir.path()
            .join("saml-admin.db")
            .to_string_lossy()
            .into_owned(),
    )
    .await
    .unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let w = world_on(db).await;
    let app = app!(w.state(), w);
    for round in 0..8 {
        let tenant_note = format!("round {round}");
        // Fresh credentials each round: retire what the last one left.
        for c in w.credentials().list(w.tenant_id).await.unwrap() {
            w.credentials().retire(w.tenant_id, c.id).await.unwrap();
        }
        w.install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        let next = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
            .await;
        let uri = format!("idp-credentials/{}/promote", next.id);
        let ((a, _, _), (b, _, _)) = futures::future::join(
            post_json(&app, &w, &uri, serde_json::Value::Null),
            post_json(&app, &w, &uri, serde_json::Value::Null),
        )
        .await;
        let mut statuses = [a, b];
        statuses.sort_unstable();
        assert_eq!(
            statuses,
            [200, 409],
            "{tenant_note}: one wins, one is told 409"
        );
        let active: Vec<_> = w
            .credentials()
            .list(w.tenant_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|c| c.status == SamlIdpCredentialStatus::Active)
            .collect();
        assert_eq!(active.len(), 1, "{tenant_note}: exactly one signer");
        assert_eq!(active[0].id, next.id, "{tenant_note}");
    }
}

#[actix_rt::test]
async fn retire_works_on_next_and_active_and_is_idempotent() {
    let w = world().await;
    let app = app!(w.state(), w);
    let active = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
        .await;
    let next = w
        .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
        .await;

    // `next`: out of its slot, key destroyed; the tenant still signs.
    let (status, retired, text) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/retire", next.id),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(retired["status"], "retired");
    assert!(retired["retired_at"].is_string());
    assert_keyless("retire next", &text, &[&next]);
    assert!(
        w.credentials()
            .get_active(w.tenant_id)
            .await
            .unwrap()
            .is_some()
    );

    // The active one: the incident response. Sign-on stops for the tenant.
    let (status, retired_active, text) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/retire", active.id),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(retired_active["status"], "retired");
    assert_keyless("retire active", &text, &[&active]);
    assert!(
        w.credentials()
            .get_active_sealed(w.tenant_id)
            .await
            .unwrap()
            .is_none()
    );

    // Again: the credential as it was, nothing written, nothing audited.
    let before = w.audit_rows("saml_idp.credential_retired").await.len();
    assert_eq!(before, 2);
    let (status, again, _) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/retire", active.id),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(again, retired_active, "unchanged, retired_at included");
    assert_eq!(
        w.audit_rows("saml_idp.credential_retired").await.len(),
        before
    );

    // Unknown is 404.
    let (status, refusal, _) = post_json(
        &app,
        &w,
        &format!("idp-credentials/{}/retire", Uuid::new_v4()),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(refusal["error"], "not_found");

    // The rows say which slot was retired and whether the tenant can still sign.
    let rows = w.audit_rows("saml_idp.credential_retired").await;
    let slot_of = |id: Uuid| {
        rows.iter()
            .find(|r| r.metadata["credential_id"] == id.to_string())
            .map(|r| {
                (
                    r.metadata["slot"].clone(),
                    r.metadata["tenant_has_active_credential"].clone(),
                )
            })
    };
    assert_eq!(slot_of(next.id), Some(("next".into(), true.into())));
    assert_eq!(slot_of(active.id), Some(("active".into(), false.into())));
}

// ---------------------------------------------------------------------------
// Authorization, tenancy, service accounts, the rate limit
// ---------------------------------------------------------------------------

/// The eleven operations, each with a body well-formed enough to reach its
/// handler, and the permission it needs.
fn operations(
    tenant_id: Uuid,
) -> Vec<(
    &'static str,
    Method,
    String,
    serde_json::Value,
    &'static str,
)> {
    let base = format!("/api/v1/tenants/{tenant_id}/saml");
    let sp = Uuid::new_v4();
    let credential = Uuid::new_v4();
    let null = serde_json::Value::Null;
    vec![
        (
            "get_idp",
            Method::GET,
            format!("{base}/idp"),
            null.clone(),
            "saml_sp:read",
        ),
        (
            "list_service_providers",
            Method::GET,
            format!("{base}/service-providers"),
            null.clone(),
            "saml_sp:read",
        ),
        (
            "create_service_provider",
            Method::POST,
            format!("{base}/service-providers"),
            sp_body("https://perm.example.test/m"),
            "saml_sp:write",
        ),
        (
            "get_service_provider",
            Method::GET,
            format!("{base}/service-providers/{sp}"),
            null.clone(),
            "saml_sp:read",
        ),
        (
            "update_service_provider",
            Method::PUT,
            format!("{base}/service-providers/{sp}"),
            sp_body("https://perm.example.test/m"),
            "saml_sp:write",
        ),
        (
            "delete_service_provider",
            Method::DELETE,
            format!("{base}/service-providers/{sp}"),
            null.clone(),
            "saml_sp:write",
        ),
        (
            "parse_sp_metadata",
            Method::POST,
            format!("{base}/parse-sp-metadata"),
            serde_json::json!({ "metadata_xml": "<x/>" }),
            "saml_sp:write",
        ),
        (
            "list_idp_credentials",
            Method::GET,
            format!("{base}/idp-credentials"),
            null.clone(),
            "saml_sp:read",
        ),
        (
            "issue_idp_credential",
            Method::POST,
            format!("{base}/idp-credentials"),
            serde_json::json!({ "issuer_ca_id": Uuid::new_v4(), "slot": "active", "validity_days": 0 }),
            "saml_idp:credential",
        ),
        (
            "promote_idp_credential",
            Method::POST,
            format!("{base}/idp-credentials/{credential}/promote"),
            null.clone(),
            "saml_idp:credential",
        ),
        (
            "retire_idp_credential",
            Method::POST,
            format!("{base}/idp-credentials/{credential}/retire"),
            null,
            "saml_idp:credential",
        ),
    ]
}

fn with_body(req: test::TestRequest, body: &serde_json::Value) -> test::TestRequest {
    if body.is_null() {
        req
    } else {
        req.set_json(body.clone())
    }
}

#[actix_rt::test]
async fn each_operation_needs_its_own_permission_and_no_other() {
    let w = world().await;
    let app = app!(w.state(), w);
    let holders = [
        (
            "a holder of nothing",
            user_holding(&w.db, w.tenant_id, &[]).await,
            "",
        ),
        (
            "saml_sp:read",
            user_holding(&w.db, w.tenant_id, &["saml_sp:read"]).await,
            "saml_sp:read",
        ),
        (
            "saml_sp:write",
            user_holding(&w.db, w.tenant_id, &["saml_sp:write"]).await,
            "saml_sp:write",
        ),
        (
            "saml_idp:credential",
            user_holding(&w.db, w.tenant_id, &["saml_idp:credential"]).await,
            "saml_idp:credential",
        ),
    ];
    for (who, user_id, held) in holders {
        let token = w.token_for(user_id);
        for (name, method, uri, body, needs) in operations(w.tenant_id) {
            let (status, _) = send(&app, with_body(request(method, &uri, &token), &body)).await;
            if needs == held {
                assert!(
                    status != 403 && status != 401,
                    "{who} must be admitted to {name}, got {status}"
                );
            } else {
                assert_eq!(status, 403, "{who} must be refused {name}");
            }
        }
    }
    // The seeded roles: admin holds all three, the read-only viewer none.
    let viewer = active_user(&w.db, w.tenant_id, "viewer").await;
    assign_named_role(&w.db, w.tenant_id, viewer, "viewer").await;
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &saml_uri(w.tenant_id, "idp"),
            &w.token_for(viewer),
        ),
    )
    .await;
    assert_eq!(
        status, 403,
        "the viewer role does not read the SAML registry"
    );
    for (name, method, uri, body, _) in operations(w.tenant_id) {
        let (status, _) = send(
            &app,
            with_body(request(method, &uri, &w.admin_token()), &body),
        )
        .await;
        assert!(
            status != 403 && status != 401,
            "the admin role holds the permission for {name}"
        );
    }
}

#[actix_rt::test]
async fn another_tenants_id_is_403_on_all_eleven() {
    let w = world().await;
    let app = app!(w.state(), w);
    for (name, method, uri, body, _) in operations(w.other_tenant_id) {
        let (status, text) = send(
            &app,
            with_body(request(method, &uri, &w.admin_token()), &body),
        )
        .await;
        assert_eq!(status, 403, "{name} for a sibling tenant");
        assert_eq!(json_of(&text)["error"], "authorization_denied", "{name}");
    }
}

/// A service-account token is refused on the whole namespace — even one holding
/// the broadest role in the tenant. `saml_sp` and `saml_idp` are human-only
/// permission families, so the refusal is the extractor's audience check, the
/// same `401` every human-only route answers (CONTRACT §27.13 S-9).
#[actix_rt::test]
async fn a_service_account_token_is_refused_on_all_eleven() {
    let w = world().await;
    let (account, _) = SurrealServiceAccountRepository::new(w.db.clone())
        .create(CreateServiceAccount {
            tenant_id: w.tenant_id,
            name: "saml-probe".into(),
            description: None,
        })
        .await
        .unwrap();
    let roles = SurrealRoleRepository::new(w.db.clone());
    let super_admin = roles
        .list(
            w.tenant_id,
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
        .find(|r| r.name == "super-admin")
        .unwrap();
    roles
        .assign_to_service_account(
            w.tenant_id,
            account.id,
            super_admin.id,
            AssignmentScope::global(),
        )
        .await
        .unwrap();
    let token = issue_service_account_token(
        account.id,
        w.tenant_id,
        w.org_id,
        Uuid::new_v4().to_string(),
        None,
        &w.auth,
    )
    .unwrap();
    let app = app!(w.state(), w);
    for (name, method, uri, body, _) in operations(w.tenant_id) {
        let (status, _) = send(&app, with_body(request(method, &uri, &token), &body)).await;
        assert_eq!(status, 401, "a service-account token on {name}");
    }
    assert!(w.sps().list(w.tenant_id).await.unwrap().is_empty());
}

#[actix_rt::test]
async fn the_seven_writes_have_a_bucket_each_pinned_at_30_and_reads_have_none() {
    assert_eq!(RateLimitConfig::default().saml_admin_per_min, 30);

    let w = world().await;
    let limits = RateLimitConfig {
        saml_admin_per_min: 1,
        end_session_per_min: 100_000,
        login_per_min: 100_000,
        ..RateLimitConfig::default()
    };
    let app = app!(w.state(), w, limits);
    // The limiter runs before the handler, so the bodies need not be valid; the
    // first call of each route is served (whatever it answers) and the second is
    // `429`, while the other routes' buckets are untouched.
    let writes: Vec<_> = operations(w.tenant_id)
        .into_iter()
        .filter(|(_, method, _, _, _)| method != Method::GET)
        .collect();
    assert_eq!(writes.len(), 7);
    for (name, method, uri, body, _) in &writes {
        let first = send(
            &app,
            with_body(request(method.clone(), uri, &w.admin_token()), body),
        )
        .await;
        assert_ne!(first.0, 429, "{name}: the first call is served");
    }
    for (name, method, uri, body, _) in &writes {
        let (status, _) = send(
            &app,
            with_body(request(method.clone(), uri, &w.admin_token()), body),
        )
        .await;
        assert_eq!(
            status, 429,
            "{name}: the second call in the minute is limited"
        );
    }
    // Reads are not in any bucket.
    for tail in ["idp", "service-providers", "idp-credentials"] {
        for _ in 0..4 {
            let (status, _) = get_json(&app, &w, tail).await;
            assert_eq!(
                status, 200,
                "a read after every write bucket is empty: {tail}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn every_sp_write_leaves_an_audit_row_with_names_and_no_certificate() {
    let w = world().await;
    let app = app!(w.state(), w);
    let mut body = sp_body(SP_ENTITY);
    let signing = ecdsa_cert_pem();
    body["sp_signing_cert_pem"] = signing.clone().into();
    let (status, created) = create_sp(&app, &w, body).await;
    assert_eq!(status, 201);
    let id = created["id"].as_str().unwrap().to_string();

    // Replace: a new ACS list and a new certificate, and a renamed display name.
    let mut changed = sp_body(SP_ENTITY);
    changed["display_name"] = "Payroll v2".into();
    changed["acs_urls"] = serde_json::json!([acs("https://payroll.example.test/new-acs", 0, true)]);
    changed["sp_signing_cert_pem"] = ecdsa_cert_pem().into();
    assert_eq!(put_sp(&app, &w, &id, changed).await.0, 200);
    // And one that changes neither the ACS nor a certificate.
    let mut quiet = sp_body(SP_ENTITY);
    quiet["display_name"] = "Payroll v3".into();
    quiet["acs_urls"] = serde_json::json!([acs("https://payroll.example.test/new-acs", 0, true)]);
    // The stored certificate is the second one now; resend it.
    let stored = w.sps().get(w.tenant_id, id.parse().unwrap()).await.unwrap();
    quiet["sp_signing_cert_pem"] = stored.sp_signing_cert_pem.clone().into();
    assert_eq!(put_sp(&app, &w, &id, quiet).await.0, 200);
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &saml_uri(w.tenant_id, &format!("service-providers/{id}")),
            &w.admin_token(),
        ),
    )
    .await;
    assert_eq!(status, 204);

    let created_rows = w.audit_rows("saml_sp.created").await;
    assert_eq!(created_rows.len(), 1);
    assert_eq!(created_rows[0].actor_id, w.admin);
    assert_eq!(
        created_rows[0].resource_id.map(|r| r.to_string()),
        Some(id.clone())
    );
    assert_eq!(created_rows[0].metadata["entity_id"], SP_ENTITY);
    assert_eq!(
        created_rows[0].metadata["signing_certificate_fingerprint"]
            .as_str()
            .map(str::len),
        Some(64)
    );

    let updated = w.audit_rows("saml_sp.updated").await;
    assert_eq!(updated.len(), 2);
    let loud = updated
        .iter()
        .find(|r| r.metadata["acs_changed"] == true)
        .expect("the ACS change");
    assert_eq!(loud.metadata["certificate_changed"], true);
    let fields: Vec<&str> = loud.metadata["changed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        fields.contains(&"display_name")
            && fields.contains(&"acs_urls")
            && fields.contains(&"sp_signing_cert_pem")
    );
    let quiet_row = updated
        .iter()
        .find(|r| r.metadata["acs_changed"] == false)
        .expect("the quiet change");
    assert_eq!(quiet_row.metadata["certificate_changed"], false);
    assert_eq!(
        quiet_row.metadata["changed_fields"],
        serde_json::json!(["display_name"])
    );

    let deleted = w.audit_rows("saml_sp.deleted").await;
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].metadata["entity_id"], SP_ENTITY);

    // No row of any kind carries a certificate, in whole or in part.
    for row in w.every_audit_row().await {
        let rendered = format!("{} {}", row.action, row.metadata);
        assert!(
            !rendered.contains("BEGIN"),
            "an audit row carries a PEM: {}",
            row.action
        );
        assert!(
            !rendered.contains(&der_b64(&signing)[..40]),
            "an audit row carries certificate content: {}",
            row.action
        );
    }
}

// ---------------------------------------------------------------------------
// SP metadata import (D-41)
// ---------------------------------------------------------------------------

fn sp_metadata_xml(entity: &str, extra_sp_children: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" \
         xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" entityID=\"{entity}\">\
         <md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" \
         AuthnRequestsSigned=\"true\">{extra_sp_children}\
         <md:AssertionConsumerService \
         Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \
         Location=\"{ACS}\" index=\"0\" isDefault=\"true\"/>\
         </md:SPSSODescriptor></md:EntityDescriptor>"
    )
}

#[cfg_attr(not(feature = "saml"), allow(dead_code))]
fn key_descriptor(usage: &str, pem: &str) -> String {
    format!(
        "<md:KeyDescriptor use=\"{usage}\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}\
         </ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
        der_b64(pem)
    )
}

#[cfg(feature = "saml")]
mod parse {
    use super::*;

    async fn parse_with<S, B>(
        app: &S,
        w: &World,
        body: serde_json::Value,
    ) -> (u16, serde_json::Value, String)
    where
        S: actix_web::dev::Service<
                actix_http::Request,
                Response = actix_web::dev::ServiceResponse<B>,
                Error = actix_web::Error,
            >,
        B: actix_web::body::MessageBody,
    {
        post_json(app, w, "parse-sp-metadata", body).await
    }

    #[actix_rt::test]
    async fn good_metadata_becomes_a_draft_that_create_accepts_unchanged_and_nothing_is_stored() {
        let w = world().await;
        let app = app!(w.state(), w);
        let signing = ecdsa_cert_pem();
        let encryption = cert_pem();
        let xml = sp_metadata_xml(
            SP_ENTITY,
            &format!(
                "{}{}",
                key_descriptor("signing", &signing),
                key_descriptor("encryption", &encryption)
            ),
        );
        let (status, draft, text) =
            parse_with(&app, &w, serde_json::json!({ "metadata_xml": xml })).await;
        assert_eq!(status, 200, "{text}");
        let sp = &draft["service_provider"];
        assert_eq!(sp["entity_id"], SP_ENTITY);
        assert_eq!(sp["acs_urls"][0]["url"], ACS);
        assert_eq!(sp["acs_urls"][0]["binding"], "http_post");
        assert_eq!(sp["acs_urls"][0]["is_default"], true);
        assert_eq!(sp["want_authn_requests_signed"], true);
        assert_eq!(sp["encrypt_assertions"], false, "never set from a document");
        assert!(sp["sp_signing_cert_pem"].is_string() && sp["sp_encryption_cert_pem"].is_string());
        assert_eq!(
            draft["signing_certificate_fingerprint"]
                .as_str()
                .map(str::len),
            Some(64)
        );
        assert_eq!(
            draft["encryption_certificate_fingerprint"]
                .as_str()
                .map(str::len),
            Some(64)
        );
        assert!(draft["warnings"].is_array());
        assert_eq!(draft.as_object().unwrap().len(), 4);

        // A parse is not a registration.
        assert!(w.sps().list(w.tenant_id).await.unwrap().is_empty());

        // The draft is a body `create` takes unchanged.
        let (status, created) = create_sp(&app, &w, sp.clone()).await;
        assert_eq!(status, 201, "{created}");
        assert_eq!(created["encrypt_assertions"], false);

        // The audit row says what, where from and how it went — and no document.
        let rows = w.audit_rows("saml_sp.metadata_parsed").await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].metadata["source"], "upload");
        assert_eq!(rows[0].metadata["outcome"], "parsed");
        assert!(rows[0].metadata["url_host"].is_null());
        assert!(!rows[0].metadata.to_string().contains("BEGIN"));
        assert!(!rows[0].metadata.to_string().contains(SP_ENTITY));
    }

    #[actix_rt::test]
    async fn a_document_signature_is_reported_as_not_verified() {
        let w = world().await;
        let app = app!(w.state(), w);
        let signed = sp_metadata_xml(SP_ENTITY, "").replacen(
            "<md:SPSSODescriptor",
            "<ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod \
             Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod \
             Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference \
             URI=\"\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>\
             <ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo>\
             <ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature><md:SPSSODescriptor",
            1,
        );
        let (status, draft, text) =
            parse_with(&app, &w, serde_json::json!({ "metadata_xml": signed })).await;
        assert_eq!(status, 200, "{text}");
        assert!(
            draft["warnings"].as_array().unwrap().iter().any(|w| w
                .as_str()
                .is_some_and(|s| s.starts_with("metadata signature not verified"))),
            "the signature is reported, not evaluated"
        );
    }

    #[actix_rt::test]
    async fn dtd_xxe_encoding_aggregate_and_oversize_documents_are_refused_with_one_generic_message()
     {
        let w = world().await;
        let app = app!(w.state(), w);
        let good = sp_metadata_xml(SP_ENTITY, "");
        let marker = format!("file-{}", Uuid::new_v4().simple());
        let aggregate = {
            let body = good.split_once("?>").unwrap().1;
            format!(
                "<md:EntitiesDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\">{body}\
                 </md:EntitiesDescriptor>"
            )
        };
        let cases: Vec<(&str, String)> = vec![
            ("a DOCTYPE with an external entity", good.replacen("<md:EntityDescriptor", &format!("<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///{marker}\">]><md:EntityDescriptor"), 1)),
            ("an internal entity bomb", good.replacen("<md:EntityDescriptor", "<!DOCTYPE l [<!ENTITY a \"aaaa\"><!ENTITY b \"&a;&a;&a;&a;\">]><md:EntityDescriptor", 1)),
            ("a bare ENTITY declaration", good.replacen("<md:EntityDescriptor", "<!ENTITY e \"x\"><md:EntityDescriptor", 1)),
            ("a declared UTF-16 encoding", good.replace("UTF-8", "UTF-16")),
            ("an aggregate", aggregate),
            ("not XML", "this is not xml".to_string()),
            ("an IdP's metadata", good.replace("SPSSODescriptor", "IDPSSODescriptor")),
            ("an oversized document", format!("{good}{}", " ".repeat(512 * 1024))),
        ];
        for (label, xml) in cases {
            let (status, refusal, text) =
                parse_with(&app, &w, serde_json::json!({ "metadata_xml": xml })).await;
            assert_eq!(status, 400, "{label}");
            assert_eq!(refusal["error"], "validation_error", "{label}");
            assert_eq!(
                message_of(&refusal),
                "not SAML service-provider metadata",
                "{label}"
            );
            assert!(
                !text.contains(&marker),
                "{label}: the document is not echoed"
            );
        }
        // UTF-16 on the wire, as a JSON string cannot carry it: a NUL smuggled in.
        let (status, refusal, _) = parse_with(
            &app,
            &w,
            serde_json::json!({ "metadata_xml": good.replace("<md:Ent", "\u{0}<md:Ent") }),
        )
        .await;
        assert_eq!(status, 400);
        assert_eq!(message_of(&refusal), "not SAML service-provider metadata");
        assert!(w.sps().list(w.tenant_id).await.unwrap().is_empty());

        let rows = w.audit_rows("saml_sp.metadata_parsed").await;
        assert!(!rows.is_empty());
        assert!(
            rows.iter()
                .all(|r| r.metadata["outcome"] == "not_sp_metadata")
        );
    }

    #[actix_rt::test]
    async fn exactly_one_of_the_two_members_is_required() {
        let w = world().await;
        let app = app!(w.state(), w);
        let xml = sp_metadata_xml(SP_ENTITY, "");
        for (label, body) in [
            (
                "both",
                serde_json::json!({ "metadata_xml": xml, "metadata_url": "https://sp.example.test/m" }),
            ),
            ("neither", serde_json::json!({})),
        ] {
            let (status, refusal, _) = parse_with(&app, &w, body).await;
            assert_eq!(status, 400, "{label}");
            assert_eq!(refusal["error"], "validation_error", "{label}");
            assert!(message_of(&refusal).contains("exactly one"), "{label}");
        }
        assert!(
            w.audit_rows("saml_sp.metadata_parsed").await.is_empty(),
            "a malformed request is not an import"
        );
    }

    #[actix_rt::test]
    async fn a_url_is_refused_by_the_guard_with_a_message_that_names_no_address() {
        let w = world().await;
        let app = app!(w.state(), w);
        let urls = [
            "http://sp.example.test/metadata",
            "ftp://sp.example.test/metadata",
            "https://127.0.0.1/metadata",
            "https://localhost/metadata",
            "https://10.0.0.5/metadata",
            "https://192.168.0.7/metadata",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/metadata",
            "https://user:pw@sp.example.test/metadata",
            "not a url",
        ];
        for url in urls {
            let (status, refusal, text) =
                parse_with(&app, &w, serde_json::json!({ "metadata_url": url })).await;
            assert_eq!(status, 400, "{url}");
            assert_eq!(refusal["error"], "validation_error", "{url}");
            assert_eq!(message_of(&refusal), "metadata_url refused", "{url}");
            for fragment in [
                "127.0.0.1",
                "169.254",
                "10.0.0.5",
                "192.168",
                "::1",
                "localhost",
                "pw@",
            ] {
                assert!(
                    !text.contains(fragment),
                    "{url}: the answer names {fragment}"
                );
            }
        }
        // The audit rows carry the host the administrator typed and the category.
        let rows = w.audit_rows("saml_sp.metadata_parsed").await;
        assert_eq!(rows.len(), urls.len());
        assert!(
            rows.iter()
                .all(|r| r.metadata["source"] == "url" && r.metadata["outcome"] == "url_refused")
        );
        let hosts: Vec<&str> = rows
            .iter()
            .filter_map(|r| r.metadata["url_host"].as_str())
            .collect();
        assert!(hosts.contains(&"169.254.169.254") && hosts.contains(&"sp.example.test"));
        assert!(
            rows.iter()
                .all(|r| !r.metadata.to_string().contains("/latest")),
            "the host only, never a path"
        );
    }
}

/// In a build without `saml` the route is compiled in and answers `503`, and
/// every other §29 operation works.
#[cfg(not(feature = "saml"))]
#[actix_rt::test]
async fn without_saml_parse_sp_metadata_is_503_and_the_rest_work() {
    let w = world().await;
    let app = app!(w.state(), w);
    let (status, refusal, _) = post_json(
        &app,
        &w,
        "parse-sp-metadata",
        serde_json::json!({ "metadata_xml": sp_metadata_xml(SP_ENTITY, "") }),
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(refusal["error"], "service_unavailable");
    let (status, _, _) = post_json(&app, &w, "parse-sp-metadata", serde_json::json!({})).await;
    assert_eq!(status, 400, "the request shape is checked on every build");
    assert_eq!(create_sp(&app, &w, sp_body(SP_ENTITY)).await.0, 201);
    let (status, text) = get_json(&app, &w, "idp").await;
    assert_eq!(status, 200);
    assert_eq!(json_of(&text)["saml_available"], false);
    assert_eq!(json_of(&text)["metadata_served"], false);
}

// ---------------------------------------------------------------------------
// The IdP metadata endpoint (D-40)
// ---------------------------------------------------------------------------

#[cfg(feature = "saml")]
mod metadata {
    use super::*;
    use axiam_federation::saml_idp::test_support::parse_idp_metadata;

    fn metadata_uri(tenant: impl std::fmt::Display) -> String {
        format!("/saml/v2/{tenant}/metadata")
    }

    fn anonymous(method: Method, uri: &str) -> test::TestRequest {
        test::TestRequest::default()
            .method(method)
            .uri(uri)
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
    }

    fn fingerprint(resp: &actix_web::dev::ServiceResponse) -> (u16, Vec<(String, String)>) {
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
    }

    #[actix_rt::test]
    async fn the_document_parses_back_with_samael_active_before_next_and_never_a_retired_key() {
        let w = world().await;
        let app = app!(w.state(), w);
        let retired = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Active, -20, 300)
            .await;
        w.credentials()
            .retire(w.tenant_id, retired.id)
            .await
            .unwrap();
        let active = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        let next = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
            .await;

        let resp = test::call_service(
            &app,
            anonymous(Method::GET, &metadata_uri(w.tenant_id)).to_request(),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/samlmetadata+xml"
        );
        assert_eq!(
            resp.headers().get("cache-control").unwrap(),
            "public, max-age=3600"
        );
        let etag = resp
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            etag.starts_with('"') && !etag.starts_with("W/"),
            "a strong tag"
        );
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();

        let summary = parse_idp_metadata(&body).expect("an SP's library reads it");
        let tenant = w.tenant_id;
        assert_eq!(
            summary.entity_id,
            format!("{ROOT_ISSUER}/saml/v2/{tenant}/metadata")
        );
        assert_eq!(
            summary.keys,
            vec![
                (Some("signing".to_string()), der_b64(&active.cert_pem)),
                (Some("signing".to_string()), der_b64(&next.cert_pem)),
            ],
            "the active credential, then the next; no retired one; no encryption key"
        );
        let sso = format!("{ROOT_ISSUER}/saml/v2/{tenant}/sso");
        assert_eq!(
            summary.single_sign_on,
            vec![
                (
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".to_string(),
                    sso.clone()
                ),
                (
                    "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string(),
                    sso
                ),
            ]
        );
        assert_eq!(
            summary.name_id_formats,
            [
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            ]
        );
        assert!(
            summary.single_logout.is_empty(),
            "no SLO until the route exists"
        );
        assert!(
            !summary.has_validity_or_signature,
            "unsigned, no validUntil, no cacheDuration"
        );
        assert!(!body.contains(&der_b64(&retired.cert_pem)));
        for absent in [
            "use=\"encryption\"",
            "Organization",
            "ContactPerson",
            "ds:Signature",
        ] {
            assert!(!body.contains(absent), "{absent}");
        }
        assert_keyless("metadata", &body, &[&retired, &active, &next]);
    }

    #[actix_rt::test]
    async fn the_etag_revalidates_with_304_and_head_answers_like_get() {
        let w = world().await;
        let app = app!(w.state(), w);
        let active = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        let uri = metadata_uri(w.tenant_id);

        let first = test::call_service(&app, anonymous(Method::GET, &uri).to_request()).await;
        let etag = first
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body = test::read_body(first).await;
        assert!(!body.is_empty());

        for header in [
            etag.clone(),
            format!("W/{etag}"),
            format!("\"other\", {etag}"),
            "*".to_string(),
        ] {
            let resp = test::call_service(
                &app,
                anonymous(Method::GET, &uri)
                    .insert_header(("If-None-Match", header))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status().as_u16(), 304);
            assert_eq!(resp.headers().get("etag").unwrap().to_str().unwrap(), etag);
            assert_eq!(
                resp.headers().get("cache-control").unwrap(),
                "public, max-age=3600"
            );
            assert!(test::read_body(resp).await.is_empty());
        }
        let stale = test::call_service(
            &app,
            anonymous(Method::GET, &uri)
                .insert_header(("If-None-Match", "\"stale\""))
                .to_request(),
        )
        .await;
        assert_eq!(stale.status().as_u16(), 200);

        let head = test::call_service(&app, anonymous(Method::HEAD, &uri).to_request()).await;
        assert_eq!(head.status().as_u16(), 200);
        assert_eq!(head.headers().get("etag").unwrap().to_str().unwrap(), etag);
        assert_eq!(
            head.headers().get("content-type").unwrap(),
            "application/samlmetadata+xml"
        );

        // A new credential in `next` changes the document and so the tag.
        w.install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
            .await;
        let changed = test::call_service(
            &app,
            anonymous(Method::GET, &uri)
                .insert_header(("If-None-Match", etag.clone()))
                .to_request(),
        )
        .await;
        assert_eq!(
            changed.status().as_u16(),
            200,
            "the old tag no longer matches"
        );
        assert_ne!(
            changed.headers().get("etag").unwrap().to_str().unwrap(),
            etag
        );
        let _ = active;
    }

    #[actix_rt::test]
    async fn a_promotion_changes_what_is_published() {
        let w = world().await;
        let app = app!(w.state(), w);
        let old = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        let next = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Next, -1, 300)
            .await;
        let (status, _, _) = post_json(
            &app,
            &w,
            &format!("idp-credentials/{}/promote", next.id),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, 200);
        let resp = test::call_service(
            &app,
            anonymous(Method::GET, &metadata_uri(w.tenant_id)).to_request(),
        )
        .await;
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        let summary = parse_idp_metadata(&body).unwrap();
        assert_eq!(
            summary.keys,
            vec![(Some("signing".to_string()), der_b64(&next.cert_pem))]
        );
        assert!(
            !body.contains(&der_b64(&old.cert_pem)),
            "the retired key stops being trusted"
        );
    }

    /// D-20 / T-368: every way of having nothing to say is the same empty `404`,
    /// indistinguishable from a path nothing is mounted at — an unknown tenant, a
    /// non-canonical id, the setting off, a tenant with no publishable credential,
    /// and every other method.
    #[actix_rt::test]
    async fn the_three_d20_404s_are_indistinguishable_from_each_other_and_from_an_unmounted_path() {
        let w = world().await;
        // The tenant with a credential, and SAML on, is the control: it serves.
        let serving = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        // A tenant whose setting is off, with a credential.
        let off_tenant = tenant_in(&w.db, w.org_id, "saml-off").await;
        w.install(off_tenant, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        SurrealSettingsRepository::new(w.db.clone())
            .set_tenant_override(
                off_tenant,
                SetTenantOverride {
                    saml_idp_enabled: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        // A tenant with SAML on and only a retired credential: nothing publishable.
        let bare_tenant = tenant_in(&w.db, w.org_id, "saml-bare").await;
        let gone = w
            .install(bare_tenant, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        w.credentials().retire(bare_tenant, gone.id).await.unwrap();
        // And one with SAML on and no credential at all.
        let empty_tenant = tenant_in(&w.db, w.org_id, "saml-empty").await;
        let app = app!(w.state(), w);

        let served = test::call_service(
            &app,
            anonymous(Method::GET, &metadata_uri(w.tenant_id)).to_request(),
        )
        .await;
        assert_eq!(served.status().as_u16(), 200, "the control serves");
        drop(serving);

        let unmounted = test::call_service(
            &app,
            anonymous(Method::GET, "/saml/v3/nothing/here").to_request(),
        )
        .await;
        let expected = fingerprint(&unmounted);
        assert_eq!(expected.0, 404);
        assert!(test::read_body(unmounted).await.is_empty());

        for (label, tenant) in [
            ("an unknown tenant", Uuid::new_v4().to_string()),
            ("a non-canonical id", w.tenant_id.to_string().to_uppercase()),
            ("not a UUID", "not-a-uuid".to_string()),
            ("the setting off", off_tenant.to_string()),
            ("only a retired credential", bare_tenant.to_string()),
            ("no credential", empty_tenant.to_string()),
        ] {
            for method in [Method::GET, Method::HEAD] {
                let resp = test::call_service(
                    &app,
                    anonymous(method.clone(), &metadata_uri(&tenant)).to_request(),
                )
                .await;
                assert_eq!(fingerprint(&resp), expected, "{label} ({method})");
                assert!(test::read_body(resp).await.is_empty(), "{label} ({method})");
            }
        }
        // Sub-paths of the metadata route are that same 404 too.
        for tail in ["/extra", "/", "/sso"] {
            let uri = format!("{}{tail}", metadata_uri(w.tenant_id));
            let resp = test::call_service(&app, anonymous(Method::GET, &uri).to_request()).await;
            assert_eq!(
                fingerprint(&resp),
                expected,
                "GET {tail} under the metadata route"
            );
        }
        // Every other method, for a tenant that does serve, is that same 404.
        for method in [Method::POST, Method::PUT, Method::DELETE, Method::PATCH] {
            let resp = test::call_service(
                &app,
                anonymous(method.clone(), &metadata_uri(w.tenant_id)).to_request(),
            )
            .await;
            assert_eq!(
                fingerprint(&resp),
                expected,
                "{method} on the metadata route"
            );
        }
    }

    /// T-367: a document is the path tenant's own — its entity id and SSO
    /// locations are built from that tenant's id, and its keys are that
    /// tenant's credentials, never another's.
    #[actix_rt::test]
    async fn each_tenant_publishes_its_own_urls_and_keys() {
        let w = world().await;
        let app = app!(w.state(), w);
        let mine = w
            .install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        let theirs = w
            .install(w.other_tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        for (tenant, own, other) in [
            (w.tenant_id, &mine, &theirs),
            (w.other_tenant_id, &theirs, &mine),
        ] {
            let resp = test::call_service(
                &app,
                anonymous(Method::GET, &metadata_uri(tenant)).to_request(),
            )
            .await;
            assert_eq!(resp.status().as_u16(), 200);
            let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
            let summary = parse_idp_metadata(&body).unwrap();
            assert_eq!(
                summary.entity_id,
                format!("{ROOT_ISSUER}/saml/v2/{tenant}/metadata")
            );
            assert!(summary.single_sign_on.iter().all(|(_, location)| *location == format!("{ROOT_ISSUER}/saml/v2/{tenant}/sso")));
            assert_eq!(
                summary.keys,
                vec![(Some("signing".to_string()), der_b64(&own.cert_pem))]
            );
            assert!(
                !body.contains(&der_b64(&other.cert_pem)),
                "another tenant's certificate"
            );
        }
    }

    /// §7 rule 6: the metadata route has a limiter — the browser-endpoint preset,
    /// a bucket of its own.
    #[actix_rt::test]
    async fn the_metadata_route_is_rate_limited_with_a_bucket_of_its_own() {
        let w = world().await;
        w.install(w.tenant_id, SamlIdpCredentialStatus::Active, -10, 300)
            .await;
        let limits = RateLimitConfig {
            end_session_per_min: 1,
            saml_admin_per_min: 100_000,
            login_per_min: 100_000,
            ..RateLimitConfig::default()
        };
        let app = app!(w.state(), w, limits);
        let uri = metadata_uri(w.tenant_id);
        let first = test::call_service(&app, anonymous(Method::GET, &uri).to_request()).await;
        assert_eq!(first.status().as_u16(), 200, "the first request is served");
        let second = test::call_service(&app, anonymous(Method::GET, &uri).to_request()).await;
        assert_eq!(second.status().as_u16(), 429, "the second is limited");
        // The SSO route's bucket is its own: it has not been spent.
        let sso = test::call_service(
            &app,
            anonymous(
                Method::GET,
                &format!("/saml/v2/{}/sso?SAMLRequest=x", w.tenant_id),
            )
            .to_request(),
        )
        .await;
        assert_ne!(sso.status().as_u16(), 429);
    }
}

// ---------------------------------------------------------------------------
// The contract surface
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_spec_has_the_eleven_operations_and_a_credential_with_no_key_member() {
    let spec = serde_json::to_value(axiam_api_rest::openapi::api_doc()).unwrap();
    let base = "/api/v1/tenants/{tenant_id}/saml";
    for (path, method, operation) in [
        (format!("{base}/idp"), "get", "get_idp"),
        (
            format!("{base}/service-providers"),
            "get",
            "list_service_providers",
        ),
        (
            format!("{base}/service-providers"),
            "post",
            "create_service_provider",
        ),
        (
            format!("{base}/service-providers/{{sp_id}}"),
            "get",
            "get_service_provider",
        ),
        (
            format!("{base}/service-providers/{{sp_id}}"),
            "put",
            "update_service_provider",
        ),
        (
            format!("{base}/service-providers/{{sp_id}}"),
            "delete",
            "delete_service_provider",
        ),
        (
            format!("{base}/parse-sp-metadata"),
            "post",
            "parse_sp_metadata",
        ),
        (
            format!("{base}/idp-credentials"),
            "get",
            "list_idp_credentials",
        ),
        (
            format!("{base}/idp-credentials"),
            "post",
            "issue_idp_credential",
        ),
        (
            format!("{base}/idp-credentials/{{credential_id}}/promote"),
            "post",
            "promote_idp_credential",
        ),
        (
            format!("{base}/idp-credentials/{{credential_id}}/retire"),
            "post",
            "retire_idp_credential",
        ),
    ] {
        let op = &spec["paths"][&path][method];
        assert!(op.is_object(), "{method} {path} is in the spec");
        assert_eq!(op["tags"], serde_json::json!(["saml"]), "{method} {path}");
        assert_eq!(op["operationId"], operation);
    }
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    for name in [
        "SamlIdpInfo",
        "SamlServiceProvider",
        "SamlServiceProviderInput",
        "ParseSamlSpMetadata",
        "SamlSpMetadataDraft",
        "SamlIdpCredential",
        "IssueSamlIdpCredential",
        "SamlIdpCredentialPromotion",
    ] {
        assert!(schemas.contains_key(name), "{name} is a component");
    }
    // No key, no ciphertext, no custody and no `sign_assertions` on any SAML schema.
    for (name, schema) in schemas {
        if !(name.starts_with("Saml")
            || name.starts_with("IssueSaml")
            || name.starts_with("ParseSaml"))
        {
            continue;
        }
        let properties = schema["properties"].as_object();
        for forbidden in [
            "private_key_pem",
            "encrypted_private_key",
            "key_custody",
            "key_locator",
            "sign_assertions",
        ] {
            assert!(
                properties.is_none_or(|p| !p.contains_key(forbidden)),
                "{name} has a {forbidden} member"
            );
        }
    }
    let mut members: Vec<&str> = schemas["SamlIdpCredential"]["properties"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "certificate_pem",
            "created_at",
            "fingerprint",
            "id",
            "issuer_ca_id",
            "not_after",
            "not_before",
            "retired_at",
            "serial",
            "status",
            "tenant_id"
        ]
    );
    // The seven writes are in the limiter's reach: the permissions are in the registry.
    let actions: Vec<&str> = PERMISSION_REGISTRY.iter().map(|(a, _)| *a).collect();
    for permission in ["saml_sp:read", "saml_sp:write", "saml_idp:credential"] {
        assert!(actions.contains(&permission), "{permission}");
    }
}

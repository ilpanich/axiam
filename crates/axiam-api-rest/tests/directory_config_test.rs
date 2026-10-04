//! The directory management routes over HTTP (G-3, T23.3.8, CONTRACT §30).
//!
//! Real RBAC (the engine and the seeded roles), the production route table and
//! an in-memory database. The connector is never reached: the address guard is
//! given a scripted resolver, so no test needs DNS, and the link route is given
//! a stub `DirectoryAuthenticator` (the LDAP client has its own live-server
//! tests in `axiam-directory`).
//!
//! What is pinned, each as a test over HTTP:
//!
//! * every route's happy path and its §30 answers (`400`, `403`, `404`, `409`,
//!   `503`), and that no response ever carries the bind secret;
//! * `config::validate` and the address guard on every write — loopback, the
//!   metadata address, an IPv6 literal, a private address without an allow-list,
//!   an unresolvable name — each a `400` naming the rule, and the guard re-run on
//!   a write that did not change `url`;
//! * P23W2-01: moving `url`, `start_tls`, `bind_dn` or the trust anchors without
//!   a secret is a `400` on `PUT` and on `PATCH`, and an ordinary write with one;
//! * `opaque_mode = required` and an enabled directory never coexist, in both
//!   directions, including the organization-level write for an inheriting tenant;
//! * `503` without the encryption key for a write that carries a secret, while
//!   reads, `DELETE` and the sync status still answer;
//! * the secret in no response, no log line and no audit row, and the audit rows
//!   that record the changed field names and that the connection moved;
//! * one permission per operation, another tenant's id refused, a service-account
//!   token refused, the rate-limit bucket pinned;
//! * `DELETE` removing the sync state, and the link route wrapping the D-28
//!   function and mapping its outcomes.
//!
//! Assertion messages name the case; none formats the bind value, a token or a
//! body that carries one.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};

use actix_web::http::Method;
use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_api_rest::state::bundles::DirectoryState;
use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::directory::{
    DirectoryAuthError, DirectoryAuthenticator, DirectoryFuture, DirectoryIdentity,
};
use axiam_core::models::directory_sync::{DirectorySyncResult, DirectorySyncState};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::opaque::OpaqueMode;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, DirectoryConfigRepository, DirectorySyncStateRepository,
    GroupRepository, OrganizationRepository, Pagination, PermissionRepository, RoleRepository,
    ServiceAccountRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealDirectoryConfigRepository,
    SurrealDirectorySyncStateRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealServiceAccountRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use axiam_directory::DirectoryClient;
use axiam_directory::address::{ResolveFuture, Resolver};
use axiam_test_support::test_password;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tracing_subscriber::fmt::MakeWriter;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:40000";
const ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";
const OTHER_ENTRY: &str = "0b9f1a52-1d5e-4a64-9b33-5a1f9f3d2c10";

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

/// The deployment's directory encryption key, minted once per process.
fn sealing_bytes() -> [u8; 32] {
    static BYTES: OnceLock<[u8; 32]> = OnceLock::new();
    *BYTES.get_or_init(|| {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        out
    })
}

/// A bind value no one could have typed: fresh per call.
fn bind_value() -> String {
    format!("Bv{}7", Uuid::new_v4().simple())
}

fn opaque_bytes() -> ([u8; 32], [u8; 32]) {
    static BYTES: OnceLock<([u8; 32], [u8; 32])> = OnceLock::new();
    *BYTES.get_or_init(|| {
        let mut session = [0u8; 32];
        let mut setup = [0u8; 32];
        session[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        session[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        setup[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        setup[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        (session, setup)
    })
}

fn auth_config(with_opaque_keys: bool) -> AuthConfig {
    let (private_pem, public_pem) = jwt_pair().clone();
    let mut config = AuthConfig {
        jwt_private_key_pem: private_pem,
        jwt_public_key_pem: public_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    };
    if with_opaque_keys {
        let (session, setup) = opaque_bytes();
        config.opaque_session_key = Some(session);
        config.opaque_setup_key = Some(setup);
    }
    config
}

/// A CA certificate generated now.
fn ca_pem() -> String {
    let pair = rcgen::KeyPair::generate().expect("key pair");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.self_signed(&pair).expect("self-signed CA").pem()
}

/// What the address guard's resolver answers, by name. Shared so a test can
/// re-point a name between two writes (the rebinding case).
#[derive(Clone, Default)]
struct Names(Arc<Mutex<HashMap<String, Vec<IpAddr>>>>);

impl Names {
    fn standard() -> Self {
        let names = Self::default();
        names.point("ldap.example.com", "93.184.216.34");
        names.point("other.example.com", "93.184.216.35");
        names.point("loopback.example.com", "127.0.0.1");
        names.point("private.example.com", "10.20.30.40");
        names.point("metadata.example.com", "169.254.169.254");
        names
    }

    fn point(&self, name: &str, address: &str) {
        self.0
            .lock()
            .unwrap()
            .insert(name.to_string(), vec![address.parse().unwrap()]);
    }
}

impl Resolver for Names {
    fn resolve<'a>(&'a self, host: &'a str, port: u16) -> ResolveFuture<'a> {
        let found = self
            .0
            .lock()
            .unwrap()
            .get(host)
            .map(|ips| ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect());
        Box::pin(async move {
            found.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such name"))
        })
    }
}

/// The directory behind `link_account`: what each login name resolves to.
#[derive(Clone, Default)]
struct Entries(Arc<Mutex<HashMap<String, Result<DirectoryIdentity, DirectoryAuthError>>>>);

impl Entries {
    fn answer(&self, login_name: &str, outcome: Result<DirectoryIdentity, DirectoryAuthError>) {
        self.0
            .lock()
            .unwrap()
            .insert(login_name.to_string(), outcome);
    }
}

fn identity(external_id: &str, login_name: &str) -> DirectoryIdentity {
    DirectoryIdentity {
        external_id: external_id.into(),
        dn: format!("uid={login_name},ou=people,dc=example,dc=com"),
        username: Some(login_name.into()),
        email: Some(format!("{login_name}@example.com")),
        display_name: None,
    }
}

impl DirectoryAuthenticator for Entries {
    fn authenticate<'a>(
        &'a self,
        _tenant_id: Uuid,
        _login_name: &'a str,
        _password: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<DirectoryIdentity, DirectoryAuthError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(DirectoryAuthError::NotConfigured) })
    }

    fn lookup_entry<'a>(
        &'a self,
        _tenant_id: Uuid,
        login_name: &'a str,
    ) -> DirectoryFuture<'a, Result<DirectoryIdentity, DirectoryAuthError>> {
        let outcome = self
            .0
            .lock()
            .unwrap()
            .get(login_name)
            .cloned()
            .unwrap_or(Err(DirectoryAuthError::InvalidCredentials));
        Box::pin(async move { outcome })
    }
}

/// Log lines, captured at the most verbose level, for the "secret in no log
/// line" assertion.
#[derive(Clone, Default)]
struct LogSink(Arc<Mutex<Vec<u8>>>);

impl io::Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogSink {
    type Writer = LogSink;
    fn make_writer(&'a self) -> LogSink {
        self.clone()
    }
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
    names: Names,
    entries: Entries,
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
            description: "directory test role".into(),
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
    world_with(false).await
}

async fn world_with(opaque_keys: bool) -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Directory Org".into(),
            slug: format!("dir-org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_id = tenant_in(&db, org.id, "dir-home").await;
    let other_tenant_id = tenant_in(&db, org.id, "dir-other").await;
    let admin = active_user(&db, tenant_id, "admin").await;
    assign_named_role(&db, tenant_id, admin, "admin").await;
    let authz: Arc<dyn AuthzChecker> = Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ));
    World {
        db,
        org_id: org.id,
        tenant_id,
        other_tenant_id,
        admin,
        auth: auth_config(opaque_keys),
        authz,
        names: Names::standard(),
        entries: Entries::default(),
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

    /// `AppState` with the directory bundle the production composition builds:
    /// the encryption key when `keyed`, and the scripted resolver in the guard.
    fn state(&self, keyed: bool) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state.directory = DirectoryState {
            config_repo: SurrealDirectoryConfigRepository::new(
                self.db.clone(),
                keyed.then(sealing_bytes),
            ),
            sync_state_repo: SurrealDirectorySyncStateRepository::new(self.db.clone()),
            client: Arc::new(
                DirectoryClient::default().with_resolver(Arc::new(self.names.clone())),
            ),
        };
        state
    }

    /// The state, with the stub directory behind the link route.
    fn state_with_directory(&self) -> AppState<TestDb> {
        let mut state = self.state(true);
        state.auth_service = state
            .auth_service
            .clone()
            .with_directory_authenticator(Arc::new(self.entries.clone()))
            .with_directory_audit(Arc::new(axiam_auth::service::RepositoryDirectoryAuditSink(
                SurrealAuditLogRepository::new(self.db.clone()),
            )));
        state
    }

    fn config_repo(&self, keyed: bool) -> SurrealDirectoryConfigRepository<TestDb> {
        SurrealDirectoryConfigRepository::new(self.db.clone(), keyed.then(sealing_bytes))
    }

    async fn audit_rows(&self, action: &str) -> Vec<axiam_core::models::audit::AuditLogEntry> {
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

    async fn every_audit_row(&self) -> Vec<axiam_core::models::audit::AuditLogEntry> {
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
}

/// The limits every test but the rate-limit one runs under.
///
/// The shipped 30 a minute is not what these tests are about, and a shared
/// counter that first sees a key part-way through a window back-fills it
/// pro rata (`axiam_db::rate_limit_counter`, the sliding window's cold seed), so
/// a test that sends a dozen writes can be refused with `429` depending on the
/// second of the minute it started in. The bucket's own behaviour is pinned,
/// deterministically, by `the_write_bucket_is_pinned_at_30_and_fires_per_route`.
fn permissive_limits() -> RateLimitConfig {
    RateLimitConfig {
        directory_admin_per_min: 100_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! app {
    ($state:expr, $auth:expr, $authz:expr) => {
        app!($state, $auth, $authz, permissive_limits())
    };
    ($state:expr, $auth:expr, $authz:expr, $limits:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
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

fn directory_uri(tenant_id: Uuid) -> String {
    format!("/api/v1/tenants/{tenant_id}/directory")
}

/// A complete `SetDirectoryConfig`, with the secret when one is given.
fn config_body(bind: Option<&str>) -> serde_json::Value {
    let mut body = serde_json::json!({
        "enabled": true,
        "kind": "open_ldap",
        "url": "ldaps://ldap.example.com",
        "start_tls": false,
        "bind_dn": "cn=svc,dc=example,dc=com",
        "base_dn": "dc=example,dc=com",
        "user_filter": "(uid={username})",
    });
    if let Some(value) = bind {
        body["bind_secret"] = value.into();
    }
    body
}

async fn put_config<S, B>(
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
    let (status, text) = send(
        app,
        request(Method::PUT, &directory_uri(w.tenant_id), &w.admin_token()).set_json(body),
    )
    .await;
    (status, json_of(&text), text)
}

async fn patch_config<S, B>(
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
    let (status, text) = send(
        app,
        request(Method::PATCH, &directory_uri(w.tenant_id), &w.admin_token()).set_json(body),
    )
    .await;
    (status, json_of(&text), text)
}

async fn get_json<S, B>(app: &S, w: &World, suffix: &str) -> (u16, serde_json::Value)
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
            Method::GET,
            &format!("{}{suffix}", directory_uri(w.tenant_id)),
            &w.admin_token(),
        ),
    )
    .await;
    (status, json_of(&text))
}

fn message_of(body: &serde_json::Value) -> String {
    body["message"].as_str().unwrap_or_default().to_string()
}

// ---------------------------------------------------------------------------
// Happy paths and the shape of what comes back
// ---------------------------------------------------------------------------

/// The members `DirectoryConfig` has, and no other: in particular no secret, no
/// flag that says one is set, and no hash or prefix of it.
const CONFIG_MEMBERS: [&str; 20] = [
    "id",
    "tenant_id",
    "enabled",
    "kind",
    "url",
    "start_tls",
    "bind_dn",
    "base_dn",
    "user_filter",
    "user_attribute_map",
    "group_base_dn",
    "group_filter",
    "group_member_attribute",
    "group_nesting_depth",
    "group_mappings",
    "sync_interval_secs",
    "jit_provisioning",
    "trust_anchors_pem",
    "created_at",
    "updated_at",
];

#[actix_rt::test]
async fn a_tenant_without_a_configuration_reads_404_and_put_creates_it_with_201() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);

    let (status, _) = get_json(&app, &w, "").await;
    assert_eq!(status, 404, "GET before any PUT");

    let bind = bind_value();
    let (status, created, text) = put_config(&app, &w, config_body(Some(&bind))).await;
    assert_eq!(status, 201, "the first PUT creates");
    assert!(
        !text.contains(&bind),
        "the PUT response echoed the bind value"
    );
    let mut members: Vec<&str> = created
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    let mut expected = CONFIG_MEMBERS.to_vec();
    expected.sort_unstable();
    assert_eq!(members, expected, "the response's members");
    assert_eq!(created["tenant_id"], w.tenant_id.to_string());
    assert_eq!(created["kind"], "open_ldap");

    // The defaults of an omitted member, by kind.
    assert_eq!(created["group_nesting_depth"], 5);
    assert_eq!(created["sync_interval_secs"], 3600);
    assert_eq!(created["jit_provisioning"], false);
    assert_eq!(created["group_member_attribute"], "member");
    assert_eq!(created["user_attribute_map"]["username"], "uid");
    assert_eq!(created["user_attribute_map"]["external_id"], "entryUUID");
    assert_eq!(created["group_mappings"], serde_json::json!([]));
    assert_eq!(created["trust_anchors_pem"], serde_json::json!([]));

    let (status, fetched) = get_json(&app, &w, "").await;
    assert_eq!(status, 200, "GET after PUT");
    assert_eq!(fetched, created, "GET returns what PUT returned");

    // The stored secret is what was entered: only the repository can say so.
    let opened = w
        .config_repo(true)
        .decrypt_bind_secret(w.tenant_id)
        .await
        .unwrap();
    assert!(
        opened.as_str() == bind,
        "the stored value is the entered one"
    );
}

#[actix_rt::test]
async fn an_active_directory_configuration_takes_the_active_directory_defaults() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let mut body = config_body(Some(&bind_value()));
    body["kind"] = "active_directory".into();
    body["user_filter"] = "(sAMAccountName={username})".into();
    let (status, created, _) = put_config(&app, &w, body).await;
    assert_eq!(status, 201);
    assert_eq!(created["group_member_attribute"], "memberOf");
    assert_eq!(created["user_attribute_map"]["username"], "sAMAccountName");
    assert_eq!(created["user_attribute_map"]["external_id"], "objectGUID");
}

#[actix_rt::test]
async fn put_replaces_and_resets_what_it_omits_and_keeps_the_stored_secret() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let group = SurrealGroupRepository::new(w.db.clone())
        .create(CreateGroup {
            tenant_id: w.tenant_id,
            name: "staff".into(),
            description: "mapped".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let bind = bind_value();
    let mut first = config_body(Some(&bind));
    first["jit_provisioning"] = true.into();
    first["group_nesting_depth"] = 3.into();
    first["sync_interval_secs"] = 600.into();
    first["group_base_dn"] = "ou=groups,dc=example,dc=com".into();
    first["group_filter"] = "(objectClass=groupOfNames)".into();
    first["group_mappings"] = serde_json::json!([
        { "directory_group_dn": "cn=staff,ou=groups,dc=example,dc=com", "group_id": group.id }
    ]);
    let (status, created, _) = put_config(&app, &w, first).await;
    assert_eq!(status, 201);
    assert_eq!(created["jit_provisioning"], true);
    assert_eq!(created["group_mappings"].as_array().unwrap().len(), 1);

    // A replacement that names only the required members, and no secret: every
    // optional member is back at its default, the secret is kept.
    let (status, replaced, _) = put_config(&app, &w, config_body(None)).await;
    assert_eq!(status, 200, "a replacement answers 200");
    assert_eq!(replaced["id"], created["id"], "the same row");
    assert_eq!(replaced["jit_provisioning"], false);
    assert_eq!(replaced["group_nesting_depth"], 5);
    assert_eq!(replaced["sync_interval_secs"], 3600);
    assert_eq!(replaced["group_base_dn"], serde_json::Value::Null);
    assert_eq!(replaced["group_filter"], serde_json::Value::Null);
    assert_eq!(replaced["group_mappings"], serde_json::json!([]));
    let opened = w
        .config_repo(true)
        .decrypt_bind_secret(w.tenant_id)
        .await
        .unwrap();
    assert!(opened.as_str() == bind, "the stored value was kept");
}

#[actix_rt::test]
async fn patch_is_sparse_and_an_explicit_null_clears_a_nullable_member() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let mut body = config_body(Some(&bind_value()));
    body["group_base_dn"] = "ou=groups,dc=example,dc=com".into();
    body["group_filter"] = "(objectClass=groupOfNames)".into();
    body["sync_interval_secs"] = 900.into();
    let (status, before, _) = put_config(&app, &w, body).await;
    assert_eq!(status, 201);

    // One member: only it changes.
    let (status, after, _) = patch_config(&app, &w, serde_json::json!({ "enabled": false })).await;
    assert_eq!(status, 200);
    assert_eq!(after["enabled"], false);
    for member in CONFIG_MEMBERS {
        if member == "enabled" || member == "updated_at" {
            continue;
        }
        assert_eq!(after[member], before[member], "PATCH moved {member}");
    }

    // Absent leaves, null clears.
    let (status, cleared, _) =
        patch_config(&app, &w, serde_json::json!({ "group_filter": null })).await;
    assert_eq!(status, 200);
    assert_eq!(cleared["group_filter"], serde_json::Value::Null);
    assert_eq!(cleared["group_base_dn"], "ou=groups,dc=example,dc=com");
    assert_eq!(cleared["sync_interval_secs"], 900);

    // A PATCH with no configuration to edit is a 404.
    let (status, _) = send(
        &app,
        request(
            Method::PATCH,
            &directory_uri(w.other_tenant_id),
            &w.admin_token(),
        )
        .set_json(serde_json::json!({ "enabled": true })),
    )
    .await;
    assert_eq!(
        status, 403,
        "another tenant's id is refused before any read"
    );
    let lonely = world().await;
    let lonely_app = app!(lonely.state(true), lonely.auth, lonely.authz);
    let (status, _, _) = patch_config(&lonely_app, &lonely, serde_json::json!({})).await;
    assert_eq!(status, 404, "PATCH with nothing stored");
}

#[actix_rt::test]
async fn delete_removes_the_configuration_and_the_sync_state_and_says_what_it_leaves() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 201);

    // A sync state, and one live directory account.
    let mut state_row = DirectorySyncState::new(w.tenant_id);
    state_row.last_result = Some(DirectorySyncResult::Ok);
    state_row.watermark = Some("20260101000000Z".into());
    let sync_repo = SurrealDirectorySyncStateRepository::new(w.db.clone());
    sync_repo.save(&state_row).await.unwrap();
    let alice = active_user(&w.db, w.tenant_id, "alice").await;
    SurrealUserRepository::new(w.db.clone())
        .mark_directory_account(w.tenant_id, alice, ENTRY)
        .await
        .unwrap();

    let (status, text) = send(
        &app,
        request(
            Method::DELETE,
            &directory_uri(w.tenant_id),
            &w.admin_token(),
        ),
    )
    .await;
    assert_eq!(status, 204, "DELETE answers 204");
    assert!(text.is_empty());
    let (status, _) = get_json(&app, &w, "").await;
    assert_eq!(status, 404, "the configuration is gone");
    assert!(
        sync_repo.get(w.tenant_id).await.unwrap().is_none(),
        "the sync state row is gone with it"
    );

    let rows = w.audit_rows("directory.config_deleted").await;
    assert_eq!(rows.len(), 1, "one delete row");
    assert_eq!(rows[0].metadata["live_directory_accounts"], 1);
    assert_eq!(rows[0].actor_id, w.admin);

    // Idempotent, and a second delete writes no second row.
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &directory_uri(w.tenant_id),
            &w.admin_token(),
        ),
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(w.audit_rows("directory.config_deleted").await.len(), 1);

    // The account is still a directory account, still live: there is no unlink.
    let alice_row = SurrealUserRepository::new(w.db.clone())
        .get_by_id(w.tenant_id, alice)
        .await
        .unwrap();
    assert_eq!(alice_row.directory_external_id.as_deref(), Some(ENTRY));
}

#[actix_rt::test]
async fn the_sync_status_is_null_before_the_first_run_and_404_without_a_configuration() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let (status, _) = get_json(&app, &w, "/sync-status").await;
    assert_eq!(status, 404, "no configuration, no status");

    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 201);
    let (status, fresh) = get_json(&app, &w, "/sync-status").await;
    assert_eq!(status, 200);
    assert_eq!(fresh["last_result"], serde_json::Value::Null);
    assert_eq!(fresh["last_attempt_at"], serde_json::Value::Null);
    assert_eq!(fresh["last_full_run_at"], serde_json::Value::Null);
    assert_eq!(fresh["has_watermark"], false);
    assert!(fresh["full_required"].is_boolean());
    assert_eq!(
        fresh.as_object().unwrap().len(),
        5,
        "the five members of §30.2, and no account id"
    );

    let mut row = DirectorySyncState::new(w.tenant_id);
    row.last_result = Some(DirectorySyncResult::SafetyValve);
    row.last_attempt_at = Some(chrono::Utc::now());
    row.watermark = Some("42".into());
    row.full_required = true;
    row.reported_user_ids = vec![Uuid::new_v4()];
    SurrealDirectorySyncStateRepository::new(w.db.clone())
        .save(&row)
        .await
        .unwrap();
    let (status, ran) = get_json(&app, &w, "/sync-status").await;
    assert_eq!(status, 200);
    assert_eq!(ran["last_result"], "safety_valve");
    assert_eq!(ran["has_watermark"], true);
    assert_eq!(ran["full_required"], true);
    assert!(ran["last_attempt_at"].is_string());
    assert_eq!(ran.as_object().unwrap().len(), 5);
}

// ---------------------------------------------------------------------------
// validate and the address guard, on every write
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn validate_runs_on_put_and_on_patch_and_names_the_rule_without_echoing_a_value() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let mut cases: Vec<(&str, serde_json::Value, &str)> = Vec::new();
    for (label, member, value, expect) in [
        (
            "plaintext ldap without start_tls",
            "url",
            serde_json::json!("ldap://ldap.example.com"),
            "plaintext",
        ),
        (
            "userinfo in the url",
            "url",
            serde_json::json!("ldaps://user@ldap.example.com"),
            "user information",
        ),
        (
            "a path in the url",
            "url",
            serde_json::json!("ldaps://ldap.example.com/dc=x"),
            "path",
        ),
        (
            "a filter without the placeholder",
            "user_filter",
            serde_json::json!("(uid=bob)"),
            "{username}",
        ),
        (
            "a nesting depth over 10",
            "group_nesting_depth",
            serde_json::json!(11),
            "group_nesting_depth",
        ),
        (
            "a sync interval under 300",
            "sync_interval_secs",
            serde_json::json!(60),
            "sync_interval_secs",
        ),
        (
            "an anchor that is not PEM",
            "trust_anchors_pem",
            serde_json::json!(["not a certificate"]),
            "trust anchor",
        ),
        (
            "an empty bind secret",
            "bind_secret",
            serde_json::json!(""),
            "bind secret",
        ),
    ] {
        let mut body = config_body(Some(&bind_value()));
        body[member] = value;
        cases.push((label, body, expect));
    }
    for (label, body, expect) in cases {
        let (status, refusal, text) = put_config(&app, &w, body).await;
        assert_eq!(status, 400, "PUT: {label}");
        assert_eq!(refusal["error"], "validation_error", "PUT: {label}");
        assert!(
            message_of(&refusal).contains(expect),
            "PUT: {label}: the message names the rule"
        );
        assert!(!text.contains("user@"), "PUT: {label}: a value was echoed");
    }
    let (status, _) = get_json(&app, &w, "").await;
    assert_eq!(status, 404, "no refused write stored anything");

    // PATCH runs it too, on the merged result.
    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 201);
    let (status, refusal, _) =
        patch_config(&app, &w, serde_json::json!({ "user_filter": "(uid=bob)" })).await;
    assert_eq!(status, 400, "PATCH: a filter without the placeholder");
    assert!(message_of(&refusal).contains("{username}"));
}

#[actix_rt::test]
async fn a_mapping_naming_a_group_of_another_tenant_is_a_400() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let foreign = SurrealGroupRepository::new(w.db.clone())
        .create(CreateGroup {
            tenant_id: w.other_tenant_id,
            name: "foreign".into(),
            description: "another tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let mut body = config_body(Some(&bind_value()));
    body["group_base_dn"] = "ou=groups,dc=example,dc=com".into();
    body["group_mappings"] = serde_json::json!([
        { "directory_group_dn": "cn=staff,ou=groups,dc=example,dc=com", "group_id": foreign.id }
    ]);
    let (status, refusal, _) = put_config(&app, &w, body).await;
    assert_eq!(status, 400);
    assert!(message_of(&refusal).contains("not a group of this tenant"));
}

#[actix_rt::test]
async fn the_address_guard_refuses_each_class_as_a_400_naming_the_rule() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    for (label, url, expect, rule) in [
        (
            "a name that resolves to loopback",
            "ldaps://loopback.example.com",
            "loopback",
            "address_guard.loopback",
        ),
        (
            "the loopback address itself",
            "ldaps://127.0.0.1:636",
            "loopback",
            "address_guard.loopback",
        ),
        (
            "the cloud metadata address",
            "ldaps://169.254.169.254",
            "link-local",
            "address_guard.link_local",
        ),
        (
            "a name that resolves to the metadata address",
            "ldaps://metadata.example.com",
            "link-local",
            "address_guard.link_local",
        ),
        (
            "an IPv6 literal",
            "ldaps://[2001:db8::1]:636",
            "IPv6",
            "address_guard.ipv6_literal",
        ),
        (
            "the IPv6 loopback literal",
            "ldaps://[::1]",
            "IPv6",
            "address_guard.ipv6_literal",
        ),
        (
            "a private address with no allow-list",
            "ldaps://private.example.com",
            "private address",
            "address_guard.private_not_allowed",
        ),
        (
            "a private literal with no allow-list",
            "ldaps://10.1.2.3",
            "private address",
            "address_guard.private_not_allowed",
        ),
        (
            "a name that does not resolve",
            "ldaps://nowhere.example.com",
            "could not be resolved",
            "address_guard.unresolvable",
        ),
    ] {
        let mut body = config_body(Some(&bind_value()));
        body["url"] = url.into();
        let (status, refusal, text) = put_config(&app, &w, body).await;
        assert_eq!(status, 400, "{label}: {text}");
        assert_eq!(refusal["error"], "validation_error", "{label}");
        assert!(
            message_of(&refusal).contains(expect),
            "{label}: the message names the rule"
        );
        let rows = w.audit_rows("directory.config_created").await;
        let newest = rows.first().expect("the refusal is audited");
        assert_eq!(
            newest.metadata["rule"], rule,
            "{label}: audited with the rule"
        );
    }
    let (status, _) = get_json(&app, &w, "").await;
    assert_eq!(status, 404, "no refused write stored anything");

    // The same on PATCH, against a stored configuration.
    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 201, "a globally routable host is accepted");
    let (status, refusal, _) = patch_config(
        &app,
        &w,
        serde_json::json!({ "url": "ldaps://loopback.example.com", "bind_secret": bind_value() }),
    )
    .await;
    assert_eq!(status, 400, "PATCH to a loopback name");
    assert!(message_of(&refusal).contains("loopback"));
}

#[actix_rt::test]
async fn a_write_that_does_not_change_the_url_still_re_checks_it() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 201);

    // The name is re-pointed after the save, as a rebinding would.
    w.names.point("ldap.example.com", "127.0.0.1");
    let (status, refusal, _) =
        patch_config(&app, &w, serde_json::json!({ "enabled": false })).await;
    assert_eq!(status, 400, "an unrelated PATCH is caught by the guard");
    assert!(message_of(&refusal).contains("loopback"));
    let (status, _, _) = put_config(&app, &w, config_body(None)).await;
    assert_eq!(status, 400, "and so is an unrelated PUT");

    // DELETE does not resolve anything, so an administrator can always remove it.
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &directory_uri(w.tenant_id),
            &w.admin_token(),
        ),
    )
    .await;
    assert_eq!(status, 204);
}

// ---------------------------------------------------------------------------
// P23W2-01
// ---------------------------------------------------------------------------

/// The four connection members, each moved on its own where that is a valid
/// configuration (StartTLS is tied to the URL's scheme, so it moves with it).
fn moves() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        (
            "url",
            serde_json::json!({ "url": "ldaps://other.example.com" }),
        ),
        (
            "bind_dn",
            serde_json::json!({ "bind_dn": "cn=other,dc=example,dc=com" }),
        ),
        (
            "trust_anchors_pem",
            serde_json::json!({ "trust_anchors_pem": [ca_pem()] }),
        ),
        (
            "start_tls",
            serde_json::json!({ "url": "ldap://ldap.example.com", "start_tls": true }),
        ),
    ]
}

#[actix_rt::test]
async fn moving_the_connection_without_the_secret_is_a_400_on_put_and_on_patch() {
    for use_patch in [false, true] {
        for (field, change) in moves() {
            let w = world().await;
            let app = app!(w.state(true), w.auth, w.authz);
            let bind = bind_value();
            let (status, stored, _) = put_config(&app, &w, config_body(Some(&bind))).await;
            assert_eq!(status, 201);

            let (status, refusal, text) = if use_patch {
                patch_config(&app, &w, change.clone()).await
            } else {
                let mut body = config_body(None);
                for (member, value) in change.as_object().unwrap() {
                    body[member] = value.clone();
                }
                put_config(&app, &w, body).await
            };
            let verb = if use_patch { "PATCH" } else { "PUT" };
            assert_eq!(status, 400, "{verb} moving {field} without the secret");
            assert_eq!(refusal["error"], "validation_error");
            assert!(
                message_of(&refusal).contains("bind secret again"),
                "{verb} {field}: the message names the rule"
            );
            assert!(!text.contains(&bind));
            let (_, unchanged) = get_json(&app, &w, "").await;
            assert_eq!(unchanged, stored, "{verb} {field}: nothing changed");

            // The refusal is audited with the rule, and the row carries neither
            // the secret nor any anchor.
            let rows = w.audit_rows("directory.config_updated").await;
            let refused = rows
                .iter()
                .find(|r| r.metadata["rule"] == "connection_moved_without_secret")
                .unwrap_or_else(|| panic!("{verb} {field}: the refusal was not audited"));
            assert_eq!(refused.metadata["connection_moved"], true);
            assert_eq!(refused.metadata["secret_replaced"], false);
            assert!(!refused.metadata.to_string().contains("BEGIN CERTIFICATE"));
            assert!(!refused.metadata.to_string().contains(&bind));
        }
    }
}

#[actix_rt::test]
async fn moving_the_connection_with_the_secret_is_an_ordinary_write() {
    for use_patch in [false, true] {
        for (field, change) in moves() {
            let w = world().await;
            let app = app!(w.state(true), w.auth, w.authz);
            let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
            assert_eq!(status, 201);

            let replacement = bind_value();
            let (status, moved, text) = if use_patch {
                let mut body = change.clone();
                body["bind_secret"] = replacement.clone().into();
                patch_config(&app, &w, body).await
            } else {
                let mut body = config_body(Some(&replacement));
                for (member, value) in change.as_object().unwrap() {
                    body[member] = value.clone();
                }
                put_config(&app, &w, body).await
            };
            let verb = if use_patch { "PATCH" } else { "PUT" };
            assert_eq!(status, 200, "{verb} moving {field} with the secret");
            assert!(!text.contains(&replacement));
            for (member, value) in change.as_object().unwrap() {
                assert_eq!(moved[member], *value, "{verb} {field}: {member} stored");
            }
            let opened = w
                .config_repo(true)
                .decrypt_bind_secret(w.tenant_id)
                .await
                .unwrap();
            assert!(opened.as_str() == replacement, "{verb} {field}: re-sealed");

            let rows = w.audit_rows("directory.config_updated").await;
            let written = rows
                .iter()
                .find(|r| r.outcome == axiam_core::models::audit::AuditOutcome::Success)
                .expect("the change is audited");
            assert_eq!(written.metadata["connection_moved"], true, "{verb} {field}");
            assert_eq!(written.metadata["secret_replaced"], true, "{verb} {field}");
            let names = written.metadata["changed_fields"].to_string();
            assert!(names.contains(&format!(
                "\"{}\"",
                change.as_object().unwrap().keys().next().unwrap()
            )));
            assert!(!written.metadata.to_string().contains(&replacement));
            assert!(!written.metadata.to_string().contains("BEGIN CERTIFICATE"));
        }
    }
}

#[actix_rt::test]
async fn a_write_that_leaves_the_connection_alone_needs_no_secret_and_records_that() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 201);
    let created = w.audit_rows("directory.config_created").await;
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].metadata["connection_moved"], true);
    assert_eq!(created[0].metadata["secret_replaced"], true);

    let (status, _, _) = patch_config(
        &app,
        &w,
        serde_json::json!({ "jit_provisioning": true, "sync_interval_secs": 600 }),
    )
    .await;
    assert_eq!(status, 200);
    let rows = w.audit_rows("directory.config_updated").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].metadata["connection_moved"], false);
    assert_eq!(rows[0].metadata["secret_replaced"], false);
    let mut names: Vec<String> = rows[0].metadata["changed_fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["jit_provisioning", "sync_interval_secs"]);
}

#[actix_rt::test]
async fn creating_without_a_secret_is_a_400() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let (status, refusal, _) = put_config(&app, &w, config_body(None)).await;
    assert_eq!(status, 400);
    assert!(message_of(&refusal).contains("bind_secret"));
}

// ---------------------------------------------------------------------------
// A directory and opaque_mode = required
// ---------------------------------------------------------------------------

async fn require_opaque_for_the_org(w: &World) {
    let mut settings = system_defaults();
    settings.opaque_mode = OpaqueMode::Required;
    SurrealSettingsRepository::new(w.db.clone())
        .set_org_settings(w.org_id, settings)
        .await
        .unwrap();
}

#[actix_rt::test]
async fn an_enabled_directory_is_refused_under_required_and_a_disabled_one_may_coexist() {
    let w = world_with(true).await;
    require_opaque_for_the_org(&w).await;
    let app = app!(w.state(true), w.auth, w.authz);

    let (status, refusal, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 409, "an enabled directory under `required`");
    assert_eq!(refusal["error"], "conflict");
    assert!(message_of(&refusal).contains("opaque_mode"));
    let (status, _) = get_json(&app, &w, "").await;
    assert_eq!(status, 404, "nothing was stored");

    let mut disabled = config_body(Some(&bind_value()));
    disabled["enabled"] = false.into();
    let (status, _, _) = put_config(&app, &w, disabled).await;
    assert_eq!(status, 201, "a disabled configuration may coexist");

    let (status, refusal, _) = patch_config(&app, &w, serde_json::json!({ "enabled": true })).await;
    assert_eq!(status, 409, "enabling it is the refused write");
    assert_eq!(refusal["error"], "conflict");
    let (_, stored) = get_json(&app, &w, "").await;
    assert_eq!(stored["enabled"], false, "and it changed nothing");
}

#[actix_rt::test]
async fn required_is_refused_for_a_tenant_with_an_enabled_directory_on_every_settings_write() {
    let w = world_with(true).await;
    // The settings routes need no real RBAC here: what is under test is the
    // directory exclusion, which runs after validation and before the write.
    let allow_all: Arc<dyn AuthzChecker> = Arc::new(AllowAllAuthzChecker);
    let app = app!(w.state(true), w.auth, allow_all);
    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 201, "an enabled directory under `disabled` opaque");
    let token = w.admin_token();

    // set_effective: `PUT /api/v1/settings`.
    let (status, text) = send(
        &app,
        request(Method::PUT, "/api/v1/settings", &token)
            .set_json(serde_json::json!({ "opaque_mode": "required" })),
    )
    .await;
    assert_eq!(status, 409, "set_effective");
    assert_eq!(json_of(&text)["error"], "conflict");

    // set_tenant_override.
    let (status, text) = send(
        &app,
        request(
            Method::PUT,
            &format!("/api/v1/tenants/{}/settings", w.tenant_id),
            &token,
        )
        .set_json(serde_json::json!({ "opaque_mode": "required" })),
    )
    .await;
    assert_eq!(status, 409, "set_tenant_override");
    assert_eq!(json_of(&text)["error"], "conflict");

    // set_org, for the tenant that inherits the organization's baseline.
    let mut org_body = serde_json::json!({
        "min_length": 12, "require_uppercase": true, "require_lowercase": true,
        "require_digits": true, "require_symbols": false, "password_history_count": 5,
        "hibp_check_enabled": true, "mfa_enforced": false,
        "mfa_challenge_lifetime_secs": 300, "max_failed_login_attempts": 5,
        "lockout_duration_secs": 300, "lockout_backoff_multiplier": 2.0,
        "max_lockout_duration_secs": 3600, "access_token_lifetime_secs": 900,
        "refresh_token_lifetime_secs": 2592000, "email_verification_required": true,
        "email_verification_grace_period_hours": 24, "default_cert_validity_days": 365,
        "max_cert_validity_days": 730, "admin_notifications_enabled": true
    });
    org_body["opaque_mode"] = "required".into();
    let (status, text) = send(
        &app,
        request(
            Method::PUT,
            &format!("/api/v1/organizations/{}/settings", w.org_id),
            &token,
        )
        .set_json(org_body.clone()),
    )
    .await;
    assert_eq!(status, 409, "set_org for an inheriting tenant");
    assert_eq!(json_of(&text)["error"], "conflict");

    // Nothing changed: `optional` is still fine, and the directory still saves.
    org_body["opaque_mode"] = "optional".into();
    let (status, _) = send(
        &app,
        request(
            Method::PUT,
            &format!("/api/v1/organizations/{}/settings", w.org_id),
            &token,
        )
        .set_json(org_body),
    )
    .await;
    assert_eq!(status, 200, "optional coexists with an enabled directory");
    let (status, _) = get_json(&app, &w, "").await;
    assert_eq!(status, 200);

    // With the directory disabled, the org write that makes `required` true is
    // no longer refused by the exclusion (it meets the coverage gate instead,
    // which is the other rule's 400 and not a 409).
    let (status, _, _) = patch_config(&app, &w, serde_json::json!({ "enabled": false })).await;
    assert_eq!(status, 200);
    let (status, text) = send(
        &app,
        request(Method::PUT, "/api/v1/settings", &token)
            .set_json(serde_json::json!({ "opaque_mode": "optional" })),
    )
    .await;
    assert_eq!(status, 200, "{text}");
}

// ---------------------------------------------------------------------------
// 503 without the encryption key
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn without_the_key_a_write_with_a_secret_is_503_and_everything_else_still_answers() {
    let w = world().await;
    // The configuration was saved while the deployment had its key.
    let keyed = w.config_repo(true);
    let created = keyed
        .create(axiam_core::models::directory::NewDirectoryConfig {
            tenant_id: w.tenant_id,
            enabled: true,
            kind: axiam_core::models::directory::DirectoryKind::OpenLdap,
            url: "ldaps://ldap.example.com".into(),
            start_tls: false,
            bind_dn: "cn=svc,dc=example,dc=com".into(),
            bind_secret: Some(zeroize::Zeroizing::new(bind_value())),
            base_dn: "dc=example,dc=com".into(),
            user_filter: "(uid={username})".into(),
            user_attribute_map: axiam_core::models::directory::DirectoryKind::OpenLdap
                .default_user_attribute_map(),
            group_base_dn: None,
            group_filter: None,
            group_member_attribute: "member".into(),
            group_nesting_depth: 5,
            group_mappings: vec![],
            sync_interval_secs: 3600,
            jit_provisioning: false,
            trust_anchors_pem: vec![],
        })
        .await
        .unwrap();
    let app = app!(w.state(false), w.auth, w.authz);

    // A write carrying a secret: 503, a generic message, no key named.
    let bind = bind_value();
    let (status, refusal, text) = put_config(&app, &w, config_body(Some(&bind))).await;
    assert_eq!(status, 503);
    assert_eq!(refusal["error"], "service_unavailable");
    assert!(
        !text.contains("directory_encryption_key"),
        "the key is named in the log only"
    );
    assert!(!text.contains("ENCRYPTION_KEY"));
    assert!(!text.contains(&bind));
    let (status, _, _) = patch_config(
        &app,
        &w,
        serde_json::json!({ "bind_dn": "cn=other,dc=example,dc=com", "bind_secret": bind }),
    )
    .await;
    assert_eq!(status, 503, "a connection move carries a secret");

    // Reads, the sync status, a write with no secret, and DELETE all answer.
    let (status, read) = get_json(&app, &w, "").await;
    assert_eq!(status, 200, "GET");
    assert_eq!(read["id"], created.id.to_string());
    let (status, _) = get_json(&app, &w, "/sync-status").await;
    assert_eq!(status, 200, "sync status");
    let (status, patched, _) =
        patch_config(&app, &w, serde_json::json!({ "enabled": false })).await;
    assert_eq!(status, 200, "a write that carries no secret needs no key");
    assert_eq!(patched["enabled"], false);
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &directory_uri(w.tenant_id),
            &w.admin_token(),
        ),
    )
    .await;
    assert_eq!(status, 204, "DELETE");

    // And creating one on a keyless deployment is the same 503.
    let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
    assert_eq!(status, 503, "create");
}

// ---------------------------------------------------------------------------
// The secret: in no response, no log line, no audit row
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_secret_appears_in_no_response_no_log_line_and_no_audit_row() {
    let sink = LogSink::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(sink.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let first = bind_value();
    let second = bind_value();
    let anchor = ca_pem();
    let mut seen = Vec::new();

    let (status, _, text) = put_config(&app, &w, config_body(Some(&first))).await;
    assert_eq!(status, 201);
    seen.push(text);
    let (_, text) = send(
        &app,
        request(Method::GET, &directory_uri(w.tenant_id), &w.admin_token()),
    )
    .await;
    seen.push(text);
    let (status, _, text) = patch_config(
        &app,
        &w,
        serde_json::json!({ "bind_secret": second, "trust_anchors_pem": [anchor] }),
    )
    .await;
    assert_eq!(status, 200);
    seen.push(text);
    // Refusals that carry a secret: validation, the guard, the key rule.
    let mut bad = config_body(Some(&first));
    bad["user_filter"] = "(uid=x)".into();
    seen.push(put_config(&app, &w, bad).await.2);
    let mut loopback = config_body(Some(&second));
    loopback["url"] = "ldaps://loopback.example.com".into();
    seen.push(put_config(&app, &w, loopback).await.2);
    // A body in which the secret has the wrong type is not echoed back.
    let (status, text) = send(
        &app,
        request(Method::PUT, &directory_uri(w.tenant_id), &w.admin_token())
            .insert_header(("Content-Type", "application/json"))
            .set_payload(
                r#"{"enabled":true,"kind":"open_ldap","url":"ldaps://ldap.example.com","start_tls":false,
                    "bind_dn":"cn=svc,dc=example,dc=com","base_dn":"dc=example,dc=com",
                    "user_filter":"(uid={username})","bind_secret":987654321012345}"#,
            ),
    )
    .await;
    assert_eq!(status, 400, "a numeric secret is a malformed body");
    assert!(
        !text.contains("987654321012345"),
        "the wrong-typed value was echoed"
    );
    seen.push(text);

    for (index, text) in seen.iter().enumerate() {
        for value in [&first, &second] {
            assert!(
                !text.contains(value.as_str()),
                "response #{index} carries a bind value"
            );
        }
    }
    let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
    for value in [&first, &second, &"987654321012345".to_string()] {
        assert!(
            !logs.contains(value.as_str()),
            "a log line carries a bind value"
        );
    }
    for row in w.every_audit_row().await {
        let rendered = format!("{} {}", row.action, row.metadata);
        for value in [&first, &second] {
            assert!(
                !rendered.contains(value.as_str()),
                "the audit row {} carries a bind value",
                row.action
            );
        }
        assert!(
            !rendered.contains("BEGIN CERTIFICATE"),
            "the audit row {} carries trust anchor content",
            row.action
        );
    }
}

// ---------------------------------------------------------------------------
// Authorization, tenancy, service accounts, the rate limit
// ---------------------------------------------------------------------------

/// The six operations, each with a body that is well-formed enough to reach its
/// handler.
fn operations(
    tenant_id: Uuid,
) -> Vec<(
    &'static str,
    Method,
    String,
    serde_json::Value,
    &'static str,
)> {
    let base = directory_uri(tenant_id);
    vec![
        (
            "get",
            Method::GET,
            base.clone(),
            serde_json::Value::Null,
            "directory:read",
        ),
        (
            "sync-status",
            Method::GET,
            format!("{base}/sync-status"),
            serde_json::Value::Null,
            "directory:read",
        ),
        (
            "set",
            Method::PUT,
            base.clone(),
            config_body(Some(&bind_value())),
            "directory:write",
        ),
        (
            "update",
            Method::PATCH,
            base.clone(),
            serde_json::json!({ "enabled": false }),
            "directory:write",
        ),
        (
            "delete",
            Method::DELETE,
            base.clone(),
            serde_json::Value::Null,
            "directory:write",
        ),
        (
            "link",
            Method::POST,
            format!("{base}/links"),
            serde_json::json!({ "user_id": Uuid::new_v4() }),
            "directory:link",
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
    let app = app!(w.state(true), w.auth, w.authz);
    let holders = [
        (
            "a holder of nothing",
            user_holding(&w.db, w.tenant_id, &[]).await,
            "",
        ),
        (
            "directory:read",
            user_holding(&w.db, w.tenant_id, &["directory:read"]).await,
            "directory:read",
        ),
        (
            "directory:write",
            user_holding(&w.db, w.tenant_id, &["directory:write"]).await,
            "directory:write",
        ),
        (
            "directory:link",
            user_holding(&w.db, w.tenant_id, &["directory:link"]).await,
            "directory:link",
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
            &directory_uri(w.tenant_id),
            &w.token_for(viewer),
        ),
    )
    .await;
    assert_eq!(
        status, 403,
        "the viewer role does not read directory configuration"
    );
}

#[actix_rt::test]
async fn another_tenants_id_is_403_on_all_six() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
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

#[actix_rt::test]
async fn a_service_account_token_is_refused_on_all_six() {
    let w = world().await;
    let (account, _) = SurrealServiceAccountRepository::new(w.db.clone())
        .create(CreateServiceAccount {
            tenant_id: w.tenant_id,
            name: "directory-probe".into(),
            description: None,
        })
        .await
        .unwrap();
    // Even holding the broadest role in the tenant.
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
    let app = app!(w.state(true), w.auth, w.authz);
    for (name, method, uri, body, _) in operations(w.tenant_id) {
        let (status, _) = send(&app, with_body(request(method, &uri, &token), &body)).await;
        assert_eq!(status, 401, "a service-account token on {name}");
    }
}

#[actix_rt::test]
async fn the_write_bucket_is_pinned_at_30_and_fires_per_route() {
    assert_eq!(RateLimitConfig::default().directory_admin_per_min, 30);

    let w = world().await;
    let limits = RateLimitConfig {
        directory_admin_per_min: 2,
        ..RateLimitConfig::default()
    };
    let app = app!(w.state_with_directory(), w.auth, w.authz, limits);
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let (status, _, _) = put_config(&app, &w, config_body(Some(&bind_value()))).await;
        statuses.push(status);
    }
    assert_eq!(
        statuses[2], 429,
        "the third write in the minute: {statuses:?}"
    );
    assert_ne!(statuses[0], 429);
    assert_ne!(statuses[1], 429);

    // Reads are not in the bucket.
    for _ in 0..4 {
        let (status, _) = get_json(&app, &w, "").await;
        assert_eq!(status, 200, "a read after the write bucket is empty");
    }
    // The link route has a bucket of its own.
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            &format!("{}/links", directory_uri(w.tenant_id)),
            &w.admin_token(),
        )
        .set_json(serde_json::json!({ "user_id": Uuid::new_v4() })),
    )
    .await;
    assert_ne!(
        status, 429,
        "the link bucket is separate from the write bucket"
    );
}

// ---------------------------------------------------------------------------
// link_account
// ---------------------------------------------------------------------------

async fn link<S, B>(app: &S, w: &World, user_id: Uuid) -> (u16, serde_json::Value)
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
            &format!("{}/links", directory_uri(w.tenant_id)),
            &w.admin_token(),
        )
        .set_json(serde_json::json!({ "user_id": user_id })),
    )
    .await;
    (status, json_of(&text))
}

#[actix_rt::test]
async fn link_account_wraps_the_d28_function_and_maps_its_outcomes() {
    let w = world().await;
    let app = app!(w.state_with_directory(), w.auth, w.authz);
    let users = SurrealUserRepository::new(w.db.clone());
    let alice = active_user(&w.db, w.tenant_id, "alice").await;
    let bob = active_user(&w.db, w.tenant_id, "bob").await;
    let carol = active_user(&w.db, w.tenant_id, "carol").await;

    // 200: linked, with the five members of §30.2.
    w.entries.answer("alice", Ok(identity(ENTRY, "alice")));
    let (status, linked) = link(&app, &w, alice).await;
    assert_eq!(status, 200, "{linked}");
    assert_eq!(linked["user_id"], alice.to_string());
    assert_eq!(linked["directory_external_id"], ENTRY);
    assert_eq!(linked["was_already_linked"], false);
    assert!(linked["webauthn_credentials_deleted"].is_u64());
    assert!(linked["certificates_revoked"].is_u64());
    assert_eq!(linked.as_object().unwrap().len(), 5);
    let stored = users.get_by_id(w.tenant_id, alice).await.unwrap();
    assert_eq!(stored.directory_external_id.as_deref(), Some(ENTRY));
    assert_eq!(
        w.audit_rows("directory.account_linked").await.len(),
        1,
        "the service's own audit row is the one row"
    );

    // 200 again: already linked to that very entry.
    let (status, again) = link(&app, &w, alice).await;
    assert_eq!(status, 200);
    assert_eq!(again["was_already_linked"], true);

    // 404: an unknown account, and a directory with no single entry.
    let (status, _) = link(&app, &w, Uuid::new_v4()).await;
    assert_eq!(status, 404, "unknown user_id");
    let (status, _) = link(&app, &w, bob).await;
    assert_eq!(status, 404, "no single entry for the username");

    // 409: the entry is linked to another account.
    w.entries.answer("bob", Ok(identity(ENTRY, "bob")));
    let (status, text) = link(&app, &w, bob).await;
    assert_eq!(status, 409, "entry linked elsewhere: {text}");
    assert_eq!(text["error"], "conflict");

    // 409: the account is linked to a different entry.
    w.entries
        .answer("alice", Ok(identity(OTHER_ENTRY, "alice")));
    let (status, _) = link(&app, &w, alice).await;
    assert_eq!(status, 409, "account linked to a different entry");

    // 409: no enabled directory.
    w.entries
        .answer("carol", Err(DirectoryAuthError::NotConfigured));
    let (status, _) = link(&app, &w, carol).await;
    assert_eq!(status, 409, "no enabled directory");

    // 503: the directory cannot be asked.
    w.entries
        .answer("carol", Err(DirectoryAuthError::Unavailable));
    let (status, refusal) = link(&app, &w, carol).await;
    assert_eq!(status, 503);
    assert_eq!(refusal["error"], "service_unavailable");

    // 400: a deleted account.
    let dave = active_user(&w.db, w.tenant_id, "dave").await;
    users.delete(w.tenant_id, dave).await.unwrap();
    let (status, refusal) = link(&app, &w, dave).await;
    assert_eq!(status, 400, "a deleted account: {refusal}");
}

#[actix_rt::test]
async fn link_account_without_a_directory_in_the_deployment_is_503() {
    let w = world().await;
    let app = app!(w.state(true), w.auth, w.authz);
    let alice = active_user(&w.db, w.tenant_id, "alice").await;
    let (status, _) = link(&app, &w, alice).await;
    assert_eq!(status, 503, "no authenticator attached");
}

// ---------------------------------------------------------------------------
// The contract surface
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_spec_has_the_six_operations_and_the_secret_on_exactly_two_request_types() {
    let spec = serde_json::to_value(axiam_api_rest::openapi::api_doc()).unwrap();
    let base = "/api/v1/tenants/{tenant_id}/directory";
    for (path, method) in [
        (base.to_string(), "get"),
        (base.to_string(), "put"),
        (base.to_string(), "patch"),
        (base.to_string(), "delete"),
        (format!("{base}/links"), "post"),
        (format!("{base}/sync-status"), "get"),
    ] {
        let op = &spec["paths"][&path][method];
        assert!(op.is_object(), "{method} {path} is in the spec");
        assert_eq!(
            op["tags"],
            serde_json::json!(["directory"]),
            "{method} {path}"
        );
    }
    let schemas = spec["components"]["schemas"].as_object().unwrap();
    for name in [
        "DirectoryConfig",
        "SetDirectoryConfig",
        "UpdateDirectoryConfig",
        "LinkDirectoryAccount",
        "DirectoryLinkResult",
        "DirectorySyncStatus",
    ] {
        assert!(schemas.contains_key(name), "{name} is a component");
    }
    // `bind_secret` is on the two request types and nowhere else.
    let mut carriers: Vec<&str> = schemas
        .iter()
        .filter(|(_, schema)| schema["properties"].get("bind_secret").is_some())
        .map(|(name, _)| name.as_str())
        .collect();
    carriers.sort_unstable();
    assert_eq!(carriers, ["SetDirectoryConfig", "UpdateDirectoryConfig"]);
    // The one the PUT requires is a replacement: its required members are the
    // ones §30.2 names.
    let mut required: Vec<&str> = schemas["SetDirectoryConfig"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    required.sort_unstable();
    assert_eq!(
        required,
        [
            "base_dn",
            "bind_dn",
            "enabled",
            "kind",
            "start_tls",
            "url",
            "user_filter"
        ]
    );
    assert!(schemas["UpdateDirectoryConfig"].get("required").is_none());
}

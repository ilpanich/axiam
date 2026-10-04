//! The directory identity source against a real OpenLDAP and a real Samba
//! Active Directory domain controller (T23.3.6, G-3).
//!
//! Every other G-3 test drives an in-process `ldap3_proto` directory that
//! *we* scripted, so each of them proves the connector against our own reading
//! of LDAP. This file is the oracle for that reading: the same AXIAM code, a
//! server somebody else wrote.
//!
//! # What is real
//!
//! * the directories — OpenLDAP (slapd, ppolicy, TLS from a CA minted for the
//!   run) and Samba AD DC, in containers
//!   (`docker/docker-compose.directory.yml`, `docker/directory/README.md`);
//! * the §30 management routes (`PUT /api/v1/tenants/{id}/directory`), so
//!   `config::validate`, the address guard and the operator's allow-list are
//!   the ones that decide what is saved;
//! * `POST /api/v1/auth/login`, `AuthService`, the connector (rustls, the
//!   address guard, the frame relay), the just-in-time provisioner, the D-30
//!   group mapper, a real authorization engine and the D-31 sync job
//!   (`sweep_directories`, the very function the cleanup scheduler runs);
//! * the database is SurrealDB in memory, as in every other crate-level suite.
//!
//! # Gating
//!
//! `cargo test` needs no container: without `AXIAM_E2E_DIRECTORY=1` every test
//! prints `SKIPPED` and returns. With it set the suite is **not** allowed to
//! skip: a missing secrets directory or an unreachable server is a failure with
//! the command that fixes it, never a quiet pass.
//! `AXIAM_E2E_DIRECTORY_ONLY=openldap` (or `samba`) runs one server's tests.
//!
//! # Where the servers are
//!
//! On a private, non-loopback address (`172.28.77.10` and `.11`): the address
//! guard always refuses loopback, and refuses a private range unless the
//! operator lists it, so the harness sets the allow-list exactly as an operator
//! would (`AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS`, through the same parser
//! the server uses). The certificates name those addresses.
//!
//! # Credentials
//!
//! None is written in this file. The CA, the certificates and every password
//! are minted by `scripts/gen-directory-e2e-secrets.sh` into a gitignored
//! directory and read from there. Assertion messages name the case; none
//! formats a credential, a token or a body that carries one.

use std::collections::BTreeSet;
use std::future::Future;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Command;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use actix_web::http::Method;
use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_api_rest::state::bundles::DirectoryState;
use axiam_api_rest::{RateLimitConfig, register_api_v1_routes};
use axiam_auth::config::AuthConfig;
use axiam_auth::service::RepositoryDirectoryAuditSink;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::types::SubjectScope;
use axiam_authz::{AccessDecision, AccessRequest, AuthorizationEngine};
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, User, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, GroupRepository, OrganizationRepository, Pagination,
    PermissionRepository, ResourceRepository, RoleRepository, SessionRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealDirectoryConfigRepository,
    SurrealDirectorySyncStateRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealRefreshTokenRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealSessionRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use axiam_directory::address::{ALLOWED_PRIVATE_NETWORKS_ENV, parse_allowed_networks};
use axiam_directory::{
    AddressPolicy, ClientLimits, DirectoryClient, DirectorySync, MembershipChangeSlot,
    RepositoryDirectoryAuthenticator, RepositoryGroupMapper,
};
use axiam_server::cleanup::{DirectorySyncJob, sweep_directories};
use axiam_test_support::test_password;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use tokio::sync::watch;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:40000";

// ===========================================================================
// The gate, and where the servers are
// ===========================================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flavor {
    OpenLdap,
    Samba,
}

/// What `scripts/gen-directory-e2e-secrets.sh` wrote.
struct E2eEnv {
    ca_pem: String,
    values: Vec<(String, String)>,
}

impl E2eEnv {
    fn value(&self, name: &str) -> &str {
        self.values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("{name} is missing from the e2e env file"))
    }
}

fn secrets_dir() -> PathBuf {
    std::env::var_os("AXIAM_E2E_DIRECTORY_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docker/.secrets/directory")
        })
}

fn e2e_env() -> &'static E2eEnv {
    static ENV: OnceLock<E2eEnv> = OnceLock::new();
    ENV.get_or_init(|| {
        let dir = secrets_dir();
        let read = |name: &str| {
            std::fs::read_to_string(dir.join(name)).unwrap_or_else(|_| {
                panic!(
                    "AXIAM_E2E_DIRECTORY is set but {} is missing. Run \
                     `bash scripts/gen-directory-e2e-secrets.sh` and bring the stack up \
                     (docker/directory/README.md).",
                    dir.join(name).display()
                )
            })
        };
        let values = read("env")
            .lines()
            .filter_map(|line| line.split_once('='))
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        E2eEnv {
            ca_pem: read("ca.pem"),
            values,
        }
    })
}

/// `Some(flavor)` when this test should run; `None` (after saying so) when the
/// suite is not enabled. When it *is* enabled and the server is unreachable that
/// is a failure, not a skip.
fn gate(flavor: Flavor) -> Option<Flavor> {
    if std::env::var("AXIAM_E2E_DIRECTORY").as_deref() != Ok("1") {
        eprintln!(
            "SKIPPED: set AXIAM_E2E_DIRECTORY=1 (with the stack from \
             docker/docker-compose.directory.yml up) to run the directory e2e"
        );
        return None;
    }
    if let Ok(only) = std::env::var("AXIAM_E2E_DIRECTORY_ONLY") {
        let name = match flavor {
            Flavor::OpenLdap => "openldap",
            Flavor::Samba => "samba",
        };
        if !only.split(',').any(|part| part.trim() == name) {
            eprintln!("SKIPPED: AXIAM_E2E_DIRECTORY_ONLY={only} does not include {name}");
            return None;
        }
    }
    let address: SocketAddr = format!("{}:636", flavor.ip())
        .parse()
        .expect("a socket address");
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_secs(3)).is_ok(),
        "AXIAM_E2E_DIRECTORY is set but {flavor:?} does not answer on its LDAPS port. Bring the \
         stack up: docker compose -f docker/docker-compose.directory.yml --env-file \
         docker/.secrets/directory/env up -d --build --wait"
    );
    Some(flavor)
}

impl Flavor {
    fn ip(self) -> &'static str {
        match self {
            Self::OpenLdap => e2e_env().value("DIRECTORY_E2E_OPENLDAP_IP"),
            Self::Samba => e2e_env().value("DIRECTORY_E2E_SAMBA_IP"),
        }
    }

    fn container(self) -> &'static str {
        match self {
            Self::OpenLdap => "axiam-directory-e2e-openldap",
            Self::Samba => "axiam-directory-e2e-samba",
        }
    }

    fn bind_pw(self) -> &'static str {
        match self {
            Self::OpenLdap => e2e_env().value("OPENLDAP_BIND_PW"),
            Self::Samba => e2e_env().value("SAMBA_BIND_PW"),
        }
    }

    /// Every seeded person's password.
    fn user_pw(self) -> &'static str {
        match self {
            Self::OpenLdap => e2e_env().value("OPENLDAP_USER_PW"),
            Self::Samba => e2e_env().value("SAMBA_USER_PW"),
        }
    }

    fn bind_dn(self) -> &'static str {
        match self {
            Self::OpenLdap => "cn=reader,dc=example,dc=test",
            Self::Samba => "CN=reader,CN=Users,DC=example,DC=test",
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::OpenLdap => "open_ldap",
            Self::Samba => "active_directory",
        }
    }

    fn user_filter(self) -> &'static str {
        match self {
            Self::OpenLdap => "(&(objectClass=inetOrgPerson)(uid={username}))",
            Self::Samba => {
                "(&(objectClass=user)(objectCategory=person)(sAMAccountName={username}))"
            }
        }
    }

    fn user_base(self) -> &'static str {
        match self {
            Self::OpenLdap => "ou=people,dc=example,dc=test",
            // The domain root, as a real deployment configures it. It is also
            // where a real DC answers a subtree search with a search reference
            // to the Configuration partition, which the connector must ignore.
            Self::Samba => "DC=example,DC=test",
        }
    }

    fn group_dn(self, name: &str) -> String {
        match self {
            Self::OpenLdap => format!("cn={name},ou=groups,dc=example,dc=test"),
            Self::Samba => format!("CN={name},CN=Users,DC=example,DC=test"),
        }
    }

    /// The name of the entry whose login name holds filter metacharacters.
    fn odd_login(self) -> &'static str {
        match self {
            // `*`, `(`, `)` and `\`, every character RFC 4515 escapes.
            Self::OpenLdap => "odd*(name)\\z",
            // sAMAccountName may not hold `*` or `\`; parentheses it may.
            Self::Samba => "odd(name)",
        }
    }

    /// A one-entry-matching wildcard of a seeded name, and a closing-bracket
    /// payload that would also select exactly that entry if it reached the
    /// filter unescaped.
    fn injection_payloads(self) -> Vec<String> {
        let attr = match self {
            Self::OpenLdap => "uid",
            Self::Samba => "sAMAccountName",
        };
        vec![
            "adminu*".to_string(),
            format!("adminuser)({attr}=adminuser"),
            format!("adminuser)(|({attr}=nobody"),
            "*".to_string(),
            format!("*)({attr}=*"),
            "*)(objectClass=*".to_string(),
            "adminuser)(&".to_string(),
        ]
    }

    /// The `directory` write body for this server, with the secret.
    fn config_body(self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "enabled": true,
            "kind": self.kind(),
            "url": format!("ldaps://{}:636", self.ip()),
            "start_tls": false,
            "bind_dn": self.bind_dn(),
            "bind_secret": self.bind_pw(),
            "base_dn": self.user_base(),
            "user_filter": self.user_filter(),
            "group_nesting_depth": 5,
            "sync_interval_secs": 300,
            "jit_provisioning": true,
            "trust_anchors_pem": [e2e_env().ca_pem.clone()],
        });
        if self == Self::OpenLdap {
            body["group_base_dn"] = "ou=groups,dc=example,dc=test".into();
            body["group_filter"] = "(objectClass=groupOfNames)".into();
        }
        body
    }

    /// Add, lock or delete a person in the running directory, the way the
    /// directory's own administrator would (`docker/directory/*/e2e-mutate.sh`:
    /// local administrator, no password typed, nothing on the network).
    fn mutate(self, action: &str, name: &str) {
        let out = Command::new("docker")
            .args([
                "exec",
                self.container(),
                "sh",
                "/e2e/e2e-mutate.sh",
                action,
                name,
            ])
            .output()
            .expect("the docker CLI must be installed to run the directory e2e");
        assert!(
            out.status.success(),
            "{action} on {self:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A login name that exists in no directory.
fn unknown_name() -> String {
    format!("nobody-{}", Uuid::new_v4().simple())
}

/// A person this test makes up in the directory, so a run can be repeated
/// against the same containers.
fn fresh_person() -> String {
    format!("victim-{}", &Uuid::new_v4().simple().to_string()[..8])
}

// ===========================================================================
// The AXIAM side: the production composition, in process
// ===========================================================================

type Reply = (u16, String);
type ReplyFuture = Pin<Box<dyn Future<Output = Reply>>>;

/// The production route table behind one callable.
struct Api {
    call: Box<dyn Fn(test::TestRequest) -> ReplyFuture>,
}

impl Api {
    async fn new(state: AppState<TestDb>, auth: AuthConfig, authz: Arc<dyn AuthzChecker>) -> Self {
        // Neither the login bucket nor the directory write bucket is what this
        // suite is about; both have their own tests.
        let limits = RateLimitConfig {
            login_per_min: 100_000,
            directory_admin_per_min: 100_000,
            ..RateLimitConfig::default()
        };
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(auth))
                .app_data(web::Data::new(authz))
                .app_data(web::Data::new(state))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &limits)),
        )
        .await;
        let app = Rc::new(app);
        Self {
            call: Box::new(move |req| {
                let app = Rc::clone(&app);
                Box::pin(async move {
                    let resp = test::call_service(&*app, req.to_request()).await;
                    let status = resp.status().as_u16();
                    let body = test::read_body(resp).await;
                    (status, String::from_utf8_lossy(&body).into_owned())
                })
            }),
        }
    }

    async fn send(&self, req: test::TestRequest) -> Reply {
        (self.call)(req).await
    }
}

fn json_of(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or(serde_json::Value::Null)
}

fn jwt_pair() -> &'static (String, String) {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

fn sealing_bytes() -> [u8; 32] {
    static BYTES: OnceLock<[u8; 32]> = OnceLock::new();
    *BYTES.get_or_init(|| {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        out
    })
}

type Engine = AuthorizationEngine<
    SurrealRoleRepository<TestDb>,
    SurrealPermissionRepository<TestDb>,
    SurrealResourceRepository<TestDb>,
    SurrealScopeRepository<TestDb>,
    SurrealGroupRepository<TestDb>,
>;

struct Harness {
    flavor: Flavor,
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    admin: Uuid,
    auth: AuthConfig,
    api: Api,
    job: DirectorySyncJob<TestDb>,
    users: SurrealUserRepository<TestDb>,
    groups: SurrealGroupRepository<TestDb>,
    engine: Engine,
}

async fn active_user(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: name.into(),
            email: format!("{name}@axiam.test"),
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

impl Harness {
    async fn new(flavor: Flavor) -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();

        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Directory E2E Org".into(),
                slug: format!("dir-e2e-{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "Directory E2E".into(),
                slug: format!("dir-e2e-{}", Uuid::new_v4().simple()),
                metadata: None,
            })
            .await
            .unwrap();
        seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
            .await
            .unwrap();
        seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
            .await
            .unwrap();
        // A tenant administrator, with the seeded `admin` role (which carries
        // `directory:read`, `directory:write` and `directory:link`): the §30
        // routes are authorised by the real engine, not by a stub.
        let admin = active_user(&db, tenant.id, "tenantadmin").await;
        let roles = SurrealRoleRepository::new(db.clone());
        let admin_role = roles
            .list(
                tenant.id,
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
            .find(|r| r.name == "admin")
            .expect("the seeded admin role");
        roles
            .assign_to_user(tenant.id, admin, admin_role.id, AssignmentScope::global())
            .await
            .unwrap();

        let (private_pem, public_pem) = jwt_pair().clone();
        let auth = AuthConfig {
            jwt_private_key_pem: private_pem,
            jwt_public_key_pem: public_pem,
            access_token_lifetime_secs: 900,
            jwt_issuer: "axiam-test".into(),
            ..AuthConfig::default()
        };

        // The deployment's connector, composed as `axiam-server`'s
        // `directory_client` does: the operator's allow-list through the
        // server's own parser, the listener ports of a default deployment, the
        // default limits. The list is the compose network's subnet unless the
        // operator variable is set.
        let raw_networks = std::env::var(ALLOWED_PRIVATE_NETWORKS_ENV)
            .unwrap_or_else(|_| e2e_env().value("DIRECTORY_E2E_SUBNET").to_string());
        let (networks, rejected) = parse_allowed_networks(&raw_networks);
        assert!(
            rejected.is_empty() && !networks.is_empty(),
            "the allow-list for the e2e network must parse"
        );
        let policy = AddressPolicy::new()
            .with_allowed_private_networks(networks)
            .with_listener_ports([8090, 50051]);
        let client = Arc::new(
            DirectoryClient::new(ClientLimits::default()).with_address_policy(Arc::new(policy)),
        );

        let config_repo = SurrealDirectoryConfigRepository::new(db.clone(), Some(sealing_bytes()));
        let sync_state_repo = SurrealDirectorySyncStateRepository::new(db.clone());
        let authenticator = Arc::new(RepositoryDirectoryAuthenticator::with_client(
            config_repo.clone(),
            Arc::clone(&client),
        ));
        let groups = SurrealGroupRepository::new(db.clone());
        let mapper = Arc::new(
            RepositoryGroupMapper::new(Arc::clone(&authenticator), groups.clone())
                .with_change_slot(MembershipChangeSlot::new()),
        );
        let audit_sink = Arc::new(RepositoryDirectoryAuditSink(
            SurrealAuditLogRepository::new(db.clone()),
        ));
        let users = SurrealUserRepository::new(db.clone());
        let job = DirectorySync::new(
            config_repo.clone(),
            Arc::clone(&authenticator),
            users.clone(),
            SurrealSessionRepository::new(db.clone()),
            SurrealRefreshTokenRepository::new(db.clone()),
            sync_state_repo.clone(),
            Arc::clone(&mapper) as _,
            Arc::clone(&audit_sink) as _,
        );

        let mut state = AppState::for_test(db.clone(), auth.clone());
        state.directory = DirectoryState {
            config_repo,
            sync_state_repo,
            client: Arc::clone(&client),
        };
        state.auth_service = state
            .auth_service
            .clone()
            .with_directory_authenticator(authenticator)
            .with_directory_group_mapper(mapper)
            .with_directory_audit(audit_sink);

        // The same engine production composes, over the same repositories. The
        // routes' own authorisation is the real thing too.
        let engine = || {
            AuthorizationEngine::new(
                SurrealRoleRepository::new(db.clone()),
                SurrealPermissionRepository::new(db.clone()),
                SurrealResourceRepository::new(db.clone()),
                SurrealScopeRepository::new(db.clone()),
                SurrealGroupRepository::new(db.clone()),
            )
        };
        let route_authz: Arc<dyn AuthzChecker> = Arc::new(engine());
        let api = Api::new(state, auth.clone(), route_authz).await;

        Self {
            flavor,
            org_id: org.id,
            tenant_id: tenant.id,
            admin,
            auth,
            api,
            job,
            users,
            groups,
            engine: engine(),
            db,
        }
    }

    fn admin_token(&self) -> String {
        issue_access_token(
            self.admin,
            self.tenant_id,
            self.org_id,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap()
    }

    fn directory_uri(&self, suffix: &str) -> String {
        format!("/api/v1/tenants/{}/directory{suffix}", self.tenant_id)
    }

    async fn admin(
        &self,
        method: Method,
        suffix: &str,
        body: Option<serde_json::Value>,
    ) -> (u16, serde_json::Value, String) {
        let mut req = test::TestRequest::default()
            .method(method)
            .uri(&self.directory_uri(suffix))
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .insert_header(("Authorization", format!("Bearer {}", self.admin_token())));
        if let Some(body) = body {
            req = req.set_json(body);
        }
        let (status, text) = self.api.send(req).await;
        (status, json_of(&text), text)
    }

    /// Save the directory through the §30 route and require it to be created.
    async fn configure(&self, body: serde_json::Value) {
        let (status, json, _) = self.admin(Method::PUT, "", Some(body)).await;
        assert_eq!(status, 201, "the directory must be saved: {json}");
    }

    async fn configure_default(&self) {
        self.configure(self.flavor.config_body()).await;
    }

    /// `POST /api/v1/auth/login`.
    async fn login(&self, login_name: &str, credential: &str) -> (u16, serde_json::Value, String) {
        let (status, text) = self
            .api
            .send(
                test::TestRequest::post()
                    .uri("/api/v1/auth/login")
                    .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                    .set_json(serde_json::json!({
                        "org_id": self.org_id,
                        "tenant_id": self.tenant_id,
                        "username_or_email": login_name,
                        "password": credential,
                    })),
            )
            .await;
        (status, json_of(&text), text)
    }

    async fn sign_in(&self, login_name: &str) -> serde_json::Value {
        let (status, json, _) = self.login(login_name, self.flavor.user_pw()).await;
        assert_eq!(status, 200, "{login_name} must sign in");
        json
    }

    async fn account(&self, username: &str) -> Option<User> {
        self.users
            .get_by_username(self.tenant_id, username)
            .await
            .ok()
    }

    /// Every account in the tenant, by username.
    async fn usernames(&self) -> BTreeSet<String> {
        self.users
            .list(
                self.tenant_id,
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
            .map(|u| u.username)
            .collect()
    }

    async fn axiam_group(&self, name: &str) -> Uuid {
        self.groups
            .create(CreateGroup {
                tenant_id: self.tenant_id,
                name: name.into(),
                description: String::new(),
                metadata: None,
            })
            .await
            .unwrap()
            .id
    }

    async fn group_names_of(&self, user_id: Uuid) -> BTreeSet<String> {
        self.groups
            .get_user_groups(self.tenant_id, user_id)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.name)
            .collect()
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

    /// One pass of the sync job, exactly as the cleanup scheduler runs it.
    async fn sweep(&self) -> Result<u64, axiam_core::error::AxiamError> {
        let (_tx, rx) = watch::channel(false);
        sweep_directories(&self.job, rx).await
    }

    /// A resource, a role holding `read` on it, assigned to the AXIAM group
    /// `group_id` (never to a user), and the question "may this user read it?".
    async fn grant_read_through(&self, group_id: Uuid) -> Uuid {
        let resource = SurrealResourceRepository::new(self.db.clone())
            .create(CreateResource {
                tenant_id: self.tenant_id,
                name: "ledger".into(),
                resource_type: "service".into(),
                parent_id: None,
                metadata: None,
            })
            .await
            .unwrap()
            .id;
        let roles = SurrealRoleRepository::new(self.db.clone());
        let perms = SurrealPermissionRepository::new(self.db.clone());
        let role = roles
            .create(CreateRole {
                tenant_id: self.tenant_id,
                name: "ledger-reader".into(),
                description: String::new(),
                is_global: false,
            })
            .await
            .unwrap();
        let perm = perms
            .create(CreatePermission {
                tenant_id: self.tenant_id,
                action: "read".into(),
                description: String::new(),
            })
            .await
            .unwrap();
        perms
            .grant_to_role(self.tenant_id, role.id, perm.id)
            .await
            .unwrap();
        roles
            .assign_to_group(
                self.tenant_id,
                group_id,
                role.id,
                AssignmentScope::resource(resource),
            )
            .await
            .unwrap();
        resource
    }

    async fn may_read(&self, user_id: Uuid, resource_id: Uuid) -> bool {
        matches!(
            self.engine
                .check_access(&AccessRequest {
                    tenant_id: self.tenant_id,
                    subject_scope: SubjectScope::Tenant,
                    subject_id: user_id,
                    action: "read".into(),
                    resource_id,
                    scope: None,
                })
                .await
                .unwrap(),
            AccessDecision::Allow
        )
    }
}

/// The user id out of a login answer.
fn user_id_of(login: &serde_json::Value) -> Uuid {
    login["user"]["id"]
        .as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .expect("a login answer names its user")
}

// ===========================================================================
// The scenarios, each run against both servers
// ===========================================================================

/// Acceptance: login, and JIT provisioning creating the account `Active` and
/// marked (D-18, D-29).
async fn login_provisions_an_active_marked_account(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    h.configure_default().await;
    assert!(
        h.account("alice").await.is_none(),
        "the directory person has no account before the first sign-in"
    );

    let first = h.sign_in("alice").await;
    assert_eq!(first["user"]["username"], "alice");
    assert_eq!(first["user"]["email"], "alice@example.test");

    let account = h.account("alice").await.expect("a provisioned account");
    assert_eq!(account.status, UserStatus::Active, "JIT creates it Active");
    let marker = account
        .directory_external_id
        .as_deref()
        .expect("JIT marks the account as a directory account");
    assert!(
        Uuid::parse_str(marker).is_ok(),
        "the marker is the entry's entryUUID / objectGUID as text"
    );
    assert!(account.is_directory_account());
    assert_eq!(
        h.audit_rows("directory.jit_provisioned").await.len(),
        1,
        "one provisioning row, identifiers and counts only"
    );

    // The second sign-in is the existing-account path, and still the
    // directory's decision.
    let second = h.sign_in("alice").await;
    assert_eq!(user_id_of(&second), account.id);
    assert_eq!(h.account("alice").await.unwrap().id, account.id);
    assert_eq!(h.usernames().await.len(), 2, "one account was created");

    // A wrong password is the directory's refusal, and no hash is kept to fall
    // back on.
    let (status, _, _) = h.login("alice", e2e_env().value("WRONG_PW")).await;
    assert_eq!(status, 401, "a wrong password is refused");
    let (status, _, _) = h.login("alice", &test_password()).await;
    assert_eq!(
        status, 401,
        "no local credential exists for a directory account"
    );
}

/// Acceptance: group mapping into an existing role assignment.
async fn a_mapped_group_carries_a_role_that_is_effective(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    let staff = h.axiam_group("ax-staff").await;
    h.axiam_group("admins").await;
    let resource = h.grant_read_through(staff).await;

    let mut body = flavor.config_body();
    // `admins` exists in the directory (alice is in it) and in AXIAM, but is
    // NOT in the table: D-30, no match by name.
    body["group_mappings"] = serde_json::json!([
        { "directory_group_dn": flavor.group_dn("staff"), "group_id": staff },
    ]);
    h.configure(body).await;

    let alice = user_id_of(&h.sign_in("alice").await);
    assert_eq!(
        h.group_names_of(alice).await,
        BTreeSet::from(["ax-staff".to_string()]),
        "the mapped group, and only it"
    );
    assert!(
        h.may_read(alice, resource).await,
        "the role on the AXIAM group is effective for the directory member"
    );
    assert!(
        !h.group_names_of(alice).await.contains("admins"),
        "an unmapped directory group grants nothing, whatever AXIAM calls its own"
    );

    // Someone in no mapped group gets nothing.
    let outsider = user_id_of(&h.sign_in("adminuser").await);
    assert!(h.group_names_of(outsider).await.is_empty());
    assert!(!h.may_read(outsider, resource).await);
}

/// Acceptance: a nested group.
async fn a_nested_directory_group_maps(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    let staff = h.axiam_group("ax-staff").await;
    let devs = h.axiam_group("ax-devs").await;
    let resource = h.grant_read_through(staff).await;

    let mut body = flavor.config_body();
    body["group_mappings"] = serde_json::json!([
        { "directory_group_dn": flavor.group_dn("staff"), "group_id": staff },
        { "directory_group_dn": flavor.group_dn("devs"), "group_id": devs },
    ]);
    h.configure(body).await;

    // bob is in `devs`; `devs` is in `staff`. Nothing says bob is in staff but
    // the nesting.
    let bob = user_id_of(&h.sign_in("bob").await);
    assert_eq!(
        h.group_names_of(bob).await,
        BTreeSet::from(["ax-staff".to_string(), "ax-devs".to_string()]),
        "the direct group and the one it is nested in"
    );
    assert!(
        h.may_read(bob, resource).await,
        "the role on the outer group reaches the nested member"
    );

    // Depth 0 follows no nesting: the same directory, a different answer.
    let (status, json, _) = h
        .admin(
            Method::PATCH,
            "",
            Some(serde_json::json!({ "group_nesting_depth": 0 })),
        )
        .await;
    assert_eq!(status, 200, "the depth is editable: {json}");
    h.sign_in("bob").await;
    assert_eq!(
        h.group_names_of(bob).await,
        BTreeSet::from(["ax-devs".to_string()]),
        "with no nesting depth only the direct group maps, and the outer one is removed"
    );
    assert!(!h.may_read(bob, resource).await);
}

/// Acceptance: a disabled directory account is refused.
async fn a_disabled_directory_account_is_refused(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    h.configure_default().await;

    let (status, _, body) = h.login("dave", flavor.user_pw()).await;
    let (unknown_status, _, unknown_body) = h.login(&unknown_name(), flavor.user_pw()).await;
    assert_eq!(status, 401, "the disabled account does not sign in");
    assert_eq!(
        (status, body),
        (unknown_status, unknown_body),
        "and the answer is the unknown-user answer: a disabled account is not distinguishable"
    );
    assert!(
        h.account("dave").await.is_none(),
        "a refused sign-in provisions nothing"
    );
}

/// Acceptance: a filter injection attempt is refused, and an entry whose name
/// holds the metacharacters signs in only under its exact name.
async fn filter_injection_is_refused(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    h.configure_default().await;
    let before = h.usernames().await;

    let (unknown_status, _, unknown_body) = h.login(&unknown_name(), flavor.user_pw()).await;
    assert_eq!(unknown_status, 401);

    // Each payload is presented WITH the real password of the entry it would
    // select if it reached the filter unescaped (`adminuser`'s is everyone's),
    // so a success here would be a sign-in as someone else.
    for payload in flavor.injection_payloads() {
        let (status, _, body) = h.login(&payload, flavor.user_pw()).await;
        assert_eq!(status, 401, "an injection payload signed in: {payload:?}");
        assert_eq!(
            (status, body),
            (unknown_status, unknown_body.clone()),
            "an injection payload is answered as an unknown user: {payload:?}"
        );
    }
    assert_eq!(
        h.usernames().await,
        before,
        "no payload created or signed in as anyone"
    );
    assert!(h.account("adminuser").await.is_none());

    // The entry whose own name holds `*`, `(`, `)` (and `\` on OpenLDAP).
    let odd = flavor.odd_login();
    let answer = h.sign_in(odd).await;
    assert_eq!(
        answer["user"]["username"], odd,
        "the metacharacter entry signs in under its exact name"
    );
    let odd_id = h.account(odd).await.expect("its account").id;
    assert_eq!(user_id_of(&answer), odd_id);

    // ... and a prefix, a wildcard or a truncation of that name is nobody.
    let prefix: String = odd.chars().take(3).collect();
    for near in [
        format!("{prefix}*"),
        format!("{prefix}*{}", &odd[odd.len() - 1..]),
        odd[..odd.len() - 1].to_string(),
        "odd*".to_string(),
        "*(name)*".to_string(),
    ] {
        let (status, _, body) = h.login(&near, flavor.user_pw()).await;
        assert_eq!(
            (status, body),
            (unknown_status, unknown_body.clone()),
            "a near-miss of the metacharacter name is nobody: {near:?}"
        );
    }
    assert_eq!(
        h.usernames().await.len(),
        before.len() + 1,
        "only the exact name produced an account"
    );
}

/// Acceptance: a plaintext URL is refused at config time. Also the address
/// guard, over the real route.
async fn plaintext_and_unguarded_urls_are_refused_at_config_time(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    let port = 389;

    // ldap:// without StartTLS: the §30 400, and nothing stored.
    let mut plain = flavor.config_body();
    plain["url"] = format!("ldap://{}:{port}", flavor.ip()).into();
    let (status, json, text) = h.admin(Method::PUT, "", Some(plain)).await;
    assert_eq!(status, 400, "a plaintext URL is refused at config time");
    assert_eq!(json["error"], "validation_error");
    assert!(
        !text.contains(flavor.bind_pw()),
        "a refusal never echoes the bind secret"
    );
    assert_eq!(
        h.admin(Method::GET, "", None).await.0,
        404,
        "nothing stored"
    );

    // ldaps:// that also asks for StartTLS is contradictory, and refused.
    let mut both = flavor.config_body();
    both["start_tls"] = true.into();
    assert_eq!(h.admin(Method::PUT, "", Some(both)).await.0, 400);

    // Loopback is refused by the guard whatever the allow-list says.
    let mut loopback = flavor.config_body();
    loopback["url"] = "ldaps://127.0.0.1:636".into();
    assert_eq!(h.admin(Method::PUT, "", Some(loopback)).await.0, 400);

    // A private address outside the operator's list is refused.
    let mut outside = flavor.config_body();
    outside["url"] = "ldaps://10.254.254.254:636".into();
    assert_eq!(h.admin(Method::PUT, "", Some(outside)).await.0, 400);

    // The metadata address, likewise.
    let mut metadata = flavor.config_body();
    metadata["url"] = "ldaps://169.254.169.254:636".into();
    assert_eq!(h.admin(Method::PUT, "", Some(metadata)).await.0, 400);

    assert_eq!(
        h.admin(Method::GET, "", None).await.0,
        404,
        "no refused write stored anything"
    );

    // The accepted shapes against the very same server: LDAPS ...
    h.configure_default().await;
    // ... and StartTLS on the plain port (the guarded upgrade, then the bind).
    let mut starttls = flavor.config_body();
    starttls["url"] = format!("ldap://{}:{port}", flavor.ip()).into();
    starttls["start_tls"] = true.into();
    let (status, json, _) = h.admin(Method::PUT, "", Some(starttls)).await;
    assert_eq!(status, 200, "ldap:// with StartTLS is accepted: {json}");
    let answer = h.sign_in("alice").await;
    assert_eq!(
        answer["user"]["username"], "alice",
        "a StartTLS sign-in works against the real server"
    );
}

/// The trust anchors are the tenant's alone: without the CA that issued the
/// server's certificate the connection is refused, whatever the credentials.
async fn an_untrusted_server_certificate_is_refused(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    let mut body = flavor.config_body();
    // No anchors means the public roots; the e2e CA is not among them.
    body["trust_anchors_pem"] = serde_json::json!([]);
    h.configure(body).await;

    let (status, _, text) = h.login("alice", flavor.user_pw()).await;
    assert_ne!(
        status, 200,
        "a certificate no anchor vouches for signs nobody in"
    );
    assert!(
        !text.contains("access_token"),
        "and issues nothing: the answer carries no token"
    );
    assert!(h.account("alice").await.is_none());
}

/// Acceptance: the sync job removes a vanished user as a soft delete, and
/// revokes their sessions.
async fn sync_deactivates_a_vanished_user_and_keeps_the_row(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    h.configure_default().await;

    let victim = fresh_person();
    flavor.mutate("add-user", &victim);
    let stays = user_id_of(&h.sign_in("alice").await);
    let gone = user_id_of(&h.sign_in(&victim).await);
    assert_eq!(
        h.users.get_by_id(h.tenant_id, gone).await.unwrap().status,
        UserStatus::Active
    );
    let sessions = SurrealSessionRepository::new(h.db.clone());
    assert!(
        !sessions
            .list_by_user(h.tenant_id, gone)
            .await
            .unwrap()
            .is_empty(),
        "the victim holds a session"
    );

    // Nothing has changed in the directory: a full run changes nothing.
    assert_eq!(
        h.sweep().await.ok(),
        Some(0),
        "a quiet directory deactivates nobody"
    );
    assert_eq!(
        h.users.get_by_id(h.tenant_id, gone).await.unwrap().status,
        UserStatus::Active
    );

    flavor.mutate("delete-user", &victim);
    // The previous run left a watermark; deletions are the full run's.
    let outcome = h.sweep_full().await;
    assert!(outcome.is_ok(), "the sweep succeeds: {outcome:?}");

    let row = h
        .users
        .get_by_id(h.tenant_id, gone)
        .await
        .expect("the row is kept: a soft delete, never a hard one");
    assert_eq!(row.status, UserStatus::Inactive, "soft-deleted is Inactive");
    assert!(
        row.directory_external_id.is_some(),
        "the marker and the audit trail stay"
    );
    assert!(
        sessions
            .list_by_user(h.tenant_id, gone)
            .await
            .unwrap()
            .is_empty(),
        "its sessions are revoked"
    );
    assert_eq!(
        h.users.get_by_id(h.tenant_id, stays).await.unwrap().status,
        UserStatus::Active,
        "everyone else is untouched"
    );
    let (status, _, _) = h.login(&victim, flavor.user_pw()).await;
    assert_eq!(status, 401, "the vanished person cannot sign in again");
    assert!(
        !h.audit_rows("directory.sync_run").await.is_empty(),
        "the run is audited"
    );

    let (status, json, _) = h.admin(Method::GET, "/sync-status", None).await;
    assert_eq!(status, 200);
    assert_eq!(json["last_result"], "ok", "job health reads ok: {json}");
}

/// D-31: an entry the directory disabled is deactivated too (OpenLDAP's
/// ppolicy permanent lock, AD's `userAccountControl` bit 0x2).
async fn sync_deactivates_a_directory_disabled_user(flavor: Flavor) {
    let h = Harness::new(flavor).await;
    h.configure_default().await;

    let person = fresh_person();
    flavor.mutate("add-user", &person);
    let id = user_id_of(&h.sign_in(&person).await);
    assert_eq!(h.sweep().await.ok(), Some(0));
    assert_eq!(
        h.users.get_by_id(h.tenant_id, id).await.unwrap().status,
        UserStatus::Active
    );

    flavor.mutate("disable-user", &person);
    let outcome = h.sweep_full().await;
    assert!(outcome.is_ok(), "the sweep succeeds: {outcome:?}");
    assert_eq!(
        h.users.get_by_id(h.tenant_id, id).await.unwrap().status,
        UserStatus::Inactive,
        "a directory-disabled account is deactivated, row kept"
    );
    let (status, _, _) = h.login(&person, flavor.user_pw()).await;
    assert_eq!(status, 401, "and it does not sign in");
}

impl Harness {
    /// A sweep that is a full reconciliation: the state's watermark is dropped,
    /// which is what the 24-hour rule does on its own.
    async fn sweep_full(&self) -> Result<u64, axiam_core::error::AxiamError> {
        use axiam_core::repository::DirectorySyncStateRepository;
        SurrealDirectorySyncStateRepository::new(self.db.clone())
            .delete(self.tenant_id)
            .await
            .unwrap();
        self.sweep().await
    }
}

// ===========================================================================
// Registration: one test per server per scenario
// ===========================================================================

macro_rules! scenario {
    ($openldap:ident, $samba:ident, $body:ident) => {
        #[actix_rt::test]
        async fn $openldap() {
            if let Some(flavor) = gate(Flavor::OpenLdap) {
                $body(flavor).await;
            }
        }

        #[actix_rt::test]
        async fn $samba() {
            if let Some(flavor) = gate(Flavor::Samba) {
                $body(flavor).await;
            }
        }
    };
}

scenario!(
    openldap_login_provisions_an_active_marked_account,
    samba_login_provisions_an_active_marked_account,
    login_provisions_an_active_marked_account
);
scenario!(
    openldap_mapped_group_carries_an_effective_role,
    samba_mapped_group_carries_an_effective_role,
    a_mapped_group_carries_a_role_that_is_effective
);
scenario!(
    openldap_nested_group_maps,
    samba_nested_group_maps,
    a_nested_directory_group_maps
);
scenario!(
    openldap_disabled_account_is_refused,
    samba_disabled_account_is_refused,
    a_disabled_directory_account_is_refused
);
scenario!(
    openldap_filter_injection_is_refused,
    samba_filter_injection_is_refused,
    filter_injection_is_refused
);
scenario!(
    openldap_plaintext_and_unguarded_urls_are_refused,
    samba_plaintext_and_unguarded_urls_are_refused,
    plaintext_and_unguarded_urls_are_refused_at_config_time
);
scenario!(
    openldap_untrusted_certificate_is_refused,
    samba_untrusted_certificate_is_refused,
    an_untrusted_server_certificate_is_refused
);
scenario!(
    openldap_sync_deactivates_a_vanished_user,
    samba_sync_deactivates_a_vanished_user,
    sync_deactivates_a_vanished_user_and_keeps_the_row
);
scenario!(
    openldap_sync_deactivates_a_disabled_user,
    samba_sync_deactivates_a_disabled_user,
    sync_deactivates_a_directory_disabled_user
);

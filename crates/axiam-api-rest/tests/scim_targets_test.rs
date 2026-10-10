//! **T23.6.4** — the outbound SCIM target registry over HTTP (G-6, contract
//! §31, D-57, D-58): create, read, list, replace, delete and *reconcile now*
//! under `/api/v1/scim-targets`.
//!
//! Real RBAC, the production route table, the real repositories on an
//! in-memory database. The reconciliation trigger is a double that makes the
//! real datastore claim (`claim_reconciliation`) and records what it started;
//! the deliverer that makes a run lives in `axiam-scim`, which sits above this
//! crate and is tested there. Every test runs with permissive rate limits
//! except the one that pins the buckets.
//!
//! Credentials are generated at run time; no assertion or panic message
//! formats a credential or an address.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};

use actix_web::http::Method;
use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::{HUMAN_ONLY_FAMILIES, PERMISSION_REGISTRY, ROUTE_PERMISSION_MAP};
use axiam_api_rest::state::AppState;
use axiam_api_rest::state::bundles::{ScimReconcileStart, ScimReconcileTrigger};
use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::error::AxiamError;
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::group::CreateGroup;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::scim_target::{
    DeprovisionPolicy, NewScimTarget, ScimTarget, ScimTargetAuth, ScimTargetScope,
    ScimTargetUpdate, UserNameSource,
};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, GroupRepository, OrganizationRepository, Pagination,
    PermissionRepository, RoleRepository, ScimTargetRepository, ScimTargetStateRepository,
    ServiceAccountRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScimTargetRepository, SurrealScimTargetStateRepository, SurrealScopeRepository,
    SurrealServiceAccountRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use axiam_test_support::test_password;
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

type TestDb = Db;

const TEST_PEER: &str = "127.0.0.1:40200";
const BASE_URL: &str = "https://scim.example.test/scim/v2";
const OTHER_BASE_URL: &str = "https://scim-other.example.test/scim/v2";
const TOKEN_URL: &str = "https://idp.example.test/oauth/token";
const OTHER_TOKEN_URL: &str = "https://idp-other.example.test/oauth/token";
const TARGETS: &str = "/api/v1/scim-targets";

// ---------------------------------------------------------------------------
// Fixtures: nothing here is a literal credential
// ---------------------------------------------------------------------------

fn jwt_pair() -> &'static (String, String) {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

fn runtime_bytes() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

/// A downstream credential made at run time.
fn fresh_credential() -> String {
    format!("c{}", Uuid::new_v4().simple())
}

fn auth_config() -> AuthConfig {
    let (private_pem, public_pem) = jwt_pair().clone();
    AuthConfig {
        jwt_private_key_pem: private_pem,
        jwt_public_key_pem: public_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://iam.example.com".into(),
        ..AuthConfig::default()
    }
}

/// What the trigger double was asked to start, in order.
type Started = Arc<Mutex<Vec<(Uuid, Uuid)>>>;

/// [`ScimReconcileTrigger`] with the production claim and no run: the datastore
/// decides `Started` and `AlreadyClaimed`, exactly as the deliverer's
/// `start_reconcile_now` does, and the calls are recorded.
struct ClaimingTrigger {
    targets: SurrealScimTargetRepository<TestDb>,
    states: SurrealScimTargetStateRepository<TestDb>,
    started: Started,
    /// How long a claim holds, in seconds.
    window_secs: i64,
}

impl ScimReconcileTrigger for ClaimingTrigger {
    fn start<'a>(
        &'a self,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<ScimReconcileStart, AxiamError>> + Send + 'a>,
    > {
        Box::pin(async move {
            let target = self.targets.get(tenant_id, target_id).await?;
            if !target.enabled {
                return Ok(ScimReconcileStart::TargetDisabled);
            }
            if !self
                .states
                .claim_reconciliation(tenant_id, target_id, chrono::Utc::now(), self.window_secs)
                .await?
            {
                return Ok(ScimReconcileStart::AlreadyClaimed);
            }
            self.started.lock().unwrap().push((tenant_id, target_id));
            Ok(ScimReconcileStart::Started)
        })
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
    other_admin: Uuid,
    auth: AuthConfig,
    authz: Arc<dyn AuthzChecker>,
    sealing: [u8; 32],
    started: Started,
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

fn all_pages() -> Pagination {
    Pagination {
        offset: 0,
        limit: 10_000,
        search: None,
    }
}

async fn role_named(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    SurrealRoleRepository::new(db.clone())
        .list(tenant_id, all_pages())
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name == name)
        .expect("seeded role")
        .id
}

async fn admin_in(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    let admin = active_user(db, tenant_id, name).await;
    SurrealRoleRepository::new(db.clone())
        .assign_to_user(
            tenant_id,
            admin,
            role_named(db, tenant_id, "super-admin").await,
            AssignmentScope::global(),
        )
        .await
        .unwrap();
    admin
}

/// A user whose only grants are `actions`.
async fn user_holding(db: &Surreal<TestDb>, tenant_id: Uuid, actions: &[&str]) -> Uuid {
    let user_id = active_user(db, tenant_id, &format!("u{}", Uuid::new_v4().simple())).await;
    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
        .create(CreateRole {
            tenant_id,
            name: format!("r{}", Uuid::new_v4().simple()),
            description: "scim target test role".into(),
            is_global: true,
        })
        .await
        .unwrap();
    let permissions = SurrealPermissionRepository::new(db.clone());
    let all = permissions
        .list(tenant_id, all_pages())
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

async fn group_in(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
    SurrealGroupRepository::new(db.clone())
        .create(CreateGroup {
            tenant_id,
            name: name.into(),
            description: "scim target test group".into(),
            metadata: None,
        })
        .await
        .unwrap()
        .id
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SCIM Target Org".into(),
            slug: format!("scim-org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_id = tenant_in(&db, org.id, "scim-home").await;
    let other_tenant_id = tenant_in(&db, org.id, "scim-other").await;
    let admin = admin_in(&db, tenant_id, "admin").await;
    let other_admin = admin_in(&db, other_tenant_id, "other-admin").await;
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
        other_admin,
        auth: auth_config(),
        authz,
        sealing: runtime_bytes(),
        started: Arc::default(),
    }
}

impl World {
    fn token_for(&self, user_id: Uuid, tenant_id: Uuid) -> String {
        issue_access_token(
            user_id,
            tenant_id,
            self.org_id,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap()
    }

    fn admin_token(&self) -> String {
        self.token_for(self.admin, self.tenant_id)
    }

    fn other_admin_token(&self) -> String {
        self.token_for(self.other_admin, self.other_tenant_id)
    }

    fn repo(&self) -> SurrealScimTargetRepository<TestDb> {
        SurrealScimTargetRepository::new(self.db.clone(), Some(self.sealing))
    }

    fn states(&self) -> SurrealScimTargetStateRepository<TestDb> {
        SurrealScimTargetStateRepository::new(self.db.clone())
    }

    /// `AppState` with a sealing key and the claiming trigger.
    fn state(&self) -> AppState<TestDb> {
        self.state_with_window(300)
    }

    /// The same, with a claim that holds for `window_secs` (0: never held).
    fn state_with_window(&self, window_secs: i64) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state.scim_targets.target_repo = self.repo();
        state.scim_targets.reconcile = Some(Arc::new(ClaimingTrigger {
            targets: self.repo(),
            states: self.states(),
            started: self.started.clone(),
            window_secs,
        }));
        state
    }

    /// A target registered directly in the datastore.
    async fn target(&self, tenant_id: Uuid, enabled: bool) -> (ScimTarget, String) {
        let credential = fresh_credential();
        let target = self
            .repo()
            .create(NewScimTarget {
                tenant_id,
                name: "Downstream".into(),
                base_url: BASE_URL.into(),
                enabled,
                auth: ScimTargetAuth::Bearer,
                credential: Zeroizing::new(credential.clone()),
                scope: ScimTargetScope::AllUsers,
                push_groups: false,
                user_name_from: UserNameSource::Username,
                deprovision: DeprovisionPolicy::Deactivate,
            })
            .await
            .unwrap();
        (target, credential)
    }

    async fn audit_rows(&self, tenant_id: Uuid, action: &str) -> Vec<AuditLogEntry> {
        SurrealAuditLogRepository::new(self.db.clone())
            .list(
                tenant_id,
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

    fn started(&self) -> Vec<(Uuid, Uuid)> {
        self.started.lock().unwrap().clone()
    }
}

fn permissive_limits() -> RateLimitConfig {
    RateLimitConfig {
        scim_target_admin_per_min: 100_000,
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
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(cfg, &$limits, RouteOptions::default())
                }),
        )
        .await
    };
}

fn request(method: Method, uri: &str, token: Option<&str>) -> test::TestRequest {
    let req = test::TestRequest::default()
        .method(method)
        .uri(uri)
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap());
    match token {
        Some(t) => req.insert_header(("Authorization", format!("Bearer {t}"))),
        None => req,
    }
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

fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

fn bearer_body(name: &str, credential: Option<&str>) -> Value {
    let mut body = json!({
        "name": name,
        "base_url": BASE_URL,
        "auth": { "type": "bearer" },
        "scope": { "type": "all_users" },
    });
    if let Some(c) = credential {
        body["credential"] = json!(c);
    }
    body
}

fn oauth_body(name: &str, token_url: &str, credential: Option<&str>) -> Value {
    let mut body = json!({
        "name": name,
        "base_url": BASE_URL,
        "auth": {
            "type": "oauth2_client_credentials",
            "token_url": token_url,
            "client_id": "axiam-client",
            "scope": "scim",
        },
        "scope": { "type": "all_users" },
    });
    if let Some(c) = credential {
        body["credential"] = json!(c);
    }
    body
}

/// Every object key in `value`, at any depth.
fn keys_of(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (name, inner) in map {
                out.push(name.clone());
                keys_of(inner, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|i| keys_of(i, out)),
        _ => {}
    }
}

/// The response says nothing about a credential: no member that could carry one
/// or say whether one is stored, and not the value.
fn assert_no_credential(body: &str, credential: &str) {
    assert!(!body.contains(credential), "the credential was returned");
    let mut keys = Vec::new();
    keys_of(&json_of(body), &mut keys);
    for forbidden in [
        "credential",
        "credential_set",
        "secret",
        "client_secret",
        "token",
        "bearer_token",
        "cred_ciphertext",
        "cred_nonce",
        "secret_key_version",
    ] {
        assert!(
            !keys.iter().any(|k| k == forbidden),
            "the response carries a `{forbidden}` member"
        );
    }
}

fn target_uri(id: &str) -> String {
    format!("{TARGETS}/{id}")
}

// ---------------------------------------------------------------------------
// The registry: CRUD (contract §31.1)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn an_administrator_registers_reads_lists_replaces_and_deletes_a_target() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let credential = fresh_credential();

    let (status, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token))
            .set_json(bearer_body("Downstream HR", Some(&credential))),
    )
    .await;
    assert_eq!(status, 201, "create: {body}");
    assert_no_credential(&body, &credential);
    let created = json_of(&body);
    assert_eq!(created["name"], "Downstream HR");
    assert_eq!(created["tenant_id"], w.tenant_id.to_string());
    assert_eq!(created["enabled"], true);
    assert_eq!(created["auth"]["type"], "bearer");
    assert_eq!(created["scope"]["type"], "all_users");
    assert_eq!(created["push_groups"], false);
    assert_eq!(created["user_name_from"], "username");
    assert_eq!(created["deprovision"], "deactivate");
    // The projection of the delivery state, fresh.
    assert_eq!(created["state"]["consecutive_failures"], 0);
    assert_eq!(created["state"]["dead_lettered_total"], 0);
    assert!(created["state"]["last_success_at"].is_null());
    assert!(created["state"]["last_failure_reason"].is_null());
    // Created enabled: the initial synchronisation was started (and claimed).
    assert!(created["state"]["last_reconciled_at"].is_string());
    let id = created["id"].as_str().unwrap().to_owned();

    let (status, body) = send(&app, request(Method::GET, &target_uri(&id), Some(&token))).await;
    assert_eq!(status, 200);
    assert_no_credential(&body, &credential);
    assert_eq!(json_of(&body)["id"], id);

    let (status, body) = send(
        &app,
        request(Method::GET, &format!("{TARGETS}?search=HR"), Some(&token)),
    )
    .await;
    assert_eq!(status, 200);
    assert_no_credential(&body, &credential);
    let page = json_of(&body);
    assert_eq!(page["total"], 1);
    assert_eq!(page["items"][0]["id"], id);
    assert_eq!(page["items"][0]["state"]["dead_lettered_total"], 0);
    let (_, body) = send(
        &app,
        request(
            Method::GET,
            &format!("{TARGETS}?search=nomatch"),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(json_of(&body)["total"], 0);

    // A replacement: new name and mapping, the credential kept.
    let mut replacement = bearer_body("Downstream HR (renamed)", None);
    replacement["user_name_from"] = json!("email");
    replacement["deprovision"] = json!("delete");
    replacement["push_groups"] = json!(true);
    let (status, body) = send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(replacement),
    )
    .await;
    assert_eq!(status, 200, "replace: {body}");
    assert_no_credential(&body, &credential);
    let updated = json_of(&body);
    assert_eq!(updated["name"], "Downstream HR (renamed)");
    assert_eq!(updated["user_name_from"], "email");
    assert_eq!(updated["deprovision"], "delete");
    assert_eq!(updated["push_groups"], true);
    assert_ne!(updated["updated_at"], created["updated_at"]);
    // The stored credential is the one registered.
    let stored = w
        .repo()
        .decrypt_credential(w.tenant_id, id.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.as_str() == credential,
        "the stored credential is the one registered"
    );

    // Delete: the target, its state.
    let (status, body) = send(
        &app,
        request(Method::DELETE, &target_uri(&id), Some(&token)),
    )
    .await;
    assert_eq!(status, 204);
    assert!(body.is_empty());
    let (status, _) = send(&app, request(Method::GET, &target_uri(&id), Some(&token))).await;
    assert_eq!(status, 404);
    let (status, _) = send(
        &app,
        request(Method::DELETE, &target_uri(&id), Some(&token)),
    )
    .await;
    assert_eq!(status, 404, "a second delete");
    assert!(
        w.states()
            .get(w.tenant_id, id.parse().unwrap())
            .await
            .is_err(),
        "the delivery state went with the target"
    );
}

#[actix_rt::test]
async fn a_client_credentials_target_round_trips_and_shows_its_token_endpoint_but_no_secret() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let secret_value = fresh_credential();
    let (status, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token)).set_json(oauth_body(
            "Okta",
            TOKEN_URL,
            Some(&secret_value),
        )),
    )
    .await;
    assert_eq!(status, 201, "create: {body}");
    assert_no_credential(&body, &secret_value);
    let created = json_of(&body);
    assert_eq!(created["auth"]["type"], "oauth2_client_credentials");
    assert_eq!(created["auth"]["token_url"], TOKEN_URL);
    assert_eq!(created["auth"]["client_id"], "axiam-client");
    assert_eq!(created["auth"]["scope"], "scim");
}

#[actix_rt::test]
async fn a_groups_scope_is_stored_and_listed_in_its_order_without_duplicates() {
    let w = world().await;
    let first = group_in(&w.db, w.tenant_id, "eng").await;
    let second = group_in(&w.db, w.tenant_id, "ops").await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let mut body = bearer_body("Scoped", Some(&fresh_credential()));
    body["scope"] = json!({ "type": "groups", "group_ids": [second, first, second] });
    let (status, text) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token)).set_json(body),
    )
    .await;
    assert_eq!(status, 201, "{text}");
    let scope = &json_of(&text)["scope"];
    assert_eq!(scope["type"], "groups");
    assert_eq!(
        scope["group_ids"],
        json!([second.to_string(), first.to_string()])
    );
}

#[actix_rt::test]
async fn the_delivery_state_is_projected_in_a_fixed_vocabulary_and_nothing_else() {
    let w = world().await;
    let (target, credential) = w.target(w.tenant_id, true).await;
    let states = w.states();
    states
        .record_failure(w.tenant_id, target.id, "downstream unavailable")
        .await
        .unwrap();
    states
        .record_failure(w.tenant_id, target.id, "downstream unavailable")
        .await
        .unwrap();
    states
        .record_dead_letter(w.tenant_id, target.id, "downstream refused the credential")
        .await
        .unwrap();
    let app = app!(w.state(), w);
    let (status, body) = send(
        &app,
        request(
            Method::GET,
            &target_uri(&target.id.to_string()),
            Some(&w.admin_token()),
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_no_credential(&body, &credential);
    let state = &json_of(&body)["state"];
    assert_eq!(state["consecutive_failures"], 2);
    assert_eq!(state["dead_lettered_total"], 1);
    assert_eq!(
        state["last_failure_reason"],
        "downstream refused the credential"
    );
    assert!(state["last_failure_at"].is_string());
    let mut members: Vec<&str> = state
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        [
            "consecutive_failures",
            "dead_lettered_total",
            "last_failure_at",
            "last_failure_reason",
            "last_reconciled_at",
            "last_success_at",
        ],
        "the claim bookkeeping is not part of the projection"
    );
}

// ---------------------------------------------------------------------------
// Value rules (contract §31.3)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_base_url_or_token_url_that_breaks_the_outbound_address_policy_is_400_and_never_echoed() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let with_credentials = format!("https://user:{}@scim.example.test/scim", Uuid::new_v4());
    let bad_urls = [
        "http://scim.example.test/scim/v2".to_owned(),
        "https://127.0.0.1/scim/v2".to_owned(),
        "https://[::1]/scim/v2".to_owned(),
        "https://10.1.2.3/scim/v2".to_owned(),
        "https://192.168.0.9/scim/v2".to_owned(),
        "https://169.254.169.254/latest/meta-data".to_owned(),
        "https://localhost/scim/v2".to_owned(),
        "https://svc.internal/scim/v2".to_owned(),
        "https://printer.local/scim/v2".to_owned(),
        "https://scim.example.test/scim/v2#frag".to_owned(),
        "scim.example.test/scim/v2".to_owned(),
        with_credentials,
        String::new(),
        format!("https://scim.example.test/{}", "a".repeat(2100)),
    ];
    for url in &bad_urls {
        let mut body = bearer_body("Bad", Some(&fresh_credential()));
        body["base_url"] = json!(url);
        let (status, text) = send(
            &app,
            request(Method::POST, TARGETS, Some(&token)).set_json(body),
        )
        .await;
        assert_eq!(status, 400, "a base_url was accepted");
        assert!(
            json_of(&text).to_string().contains("base_url"),
            "the 400 names the field"
        );
        if url.len() < 200 && !url.is_empty() {
            assert!(!text.contains(url.as_str()), "the 400 echoed the URL");
        }
        // The same URL as a token endpoint.
        let mut body = oauth_body("Bad", url, Some(&fresh_credential()));
        body["base_url"] = json!(BASE_URL);
        let (status, text) = send(
            &app,
            request(Method::POST, TARGETS, Some(&token)).set_json(body),
        )
        .await;
        assert_eq!(status, 400, "a token_url was accepted");
        assert!(
            json_of(&text).to_string().contains("token_url"),
            "the 400 names the field"
        );
    }
    let (_, text) = send(&app, request(Method::GET, TARGETS, Some(&token))).await;
    assert_eq!(json_of(&text)["total"], 0, "nothing was registered");
}

#[actix_rt::test]
async fn the_value_rules_are_enforced_on_create_and_replace() {
    let w = world().await;
    let (existing, _) = w.target(w.tenant_id, true).await;
    let foreign_group = group_in(&w.db, w.other_tenant_id, "elsewhere").await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let credential = fresh_credential();

    let long_name = "n".repeat(129);
    let many_groups: Vec<Uuid> = (0..101).map(|_| Uuid::new_v4()).collect();
    let cases: Vec<(&str, Value)> = vec![
        ("an empty name", {
            let mut b = bearer_body("", Some(&credential));
            b["name"] = json!("   ");
            b
        }),
        (
            "a name over 128 bytes",
            bearer_body(&long_name, Some(&credential)),
        ),
        ("a missing credential", bearer_body("Ok", None)),
        ("an empty credential", bearer_body("Ok", Some(""))),
        (
            "a credential over 4096 bytes",
            bearer_body("Ok", Some(&"x".repeat(4097))),
        ),
        (
            "a bearer credential with a space",
            bearer_body("Ok", Some("two words")),
        ),
        (
            "a credential with a line break",
            bearer_body("Ok", Some("line\nbreak")),
        ),
        ("an empty groups scope", {
            let mut b = bearer_body("Ok", Some(&credential));
            b["scope"] = json!({ "type": "groups", "group_ids": [] });
            b
        }),
        ("more than 100 groups", {
            let mut b = bearer_body("Ok", Some(&credential));
            b["scope"] = json!({ "type": "groups", "group_ids": many_groups });
            b
        }),
        ("a group that does not exist", {
            let mut b = bearer_body("Ok", Some(&credential));
            b["scope"] = json!({ "type": "groups", "group_ids": [Uuid::new_v4()] });
            b
        }),
        ("another tenant's group", {
            let mut b = bearer_body("Ok", Some(&credential));
            b["scope"] = json!({ "type": "groups", "group_ids": [foreign_group] });
            b
        }),
        ("an empty client_id", {
            let mut b = oauth_body("Ok", TOKEN_URL, Some(&credential));
            b["auth"]["client_id"] = json!("");
            b
        }),
        ("a client_id over 256 bytes", {
            let mut b = oauth_body("Ok", TOKEN_URL, Some(&credential));
            b["auth"]["client_id"] = json!("c".repeat(257));
            b
        }),
        ("an oauth scope over 256 bytes", {
            let mut b = oauth_body("Ok", TOKEN_URL, Some(&credential));
            b["auth"]["scope"] = json!("s".repeat(257));
            b
        }),
        ("an unknown authentication kind", {
            let mut b = bearer_body("Ok", Some(&credential));
            b["auth"] = json!({ "type": "basic" });
            b
        }),
        ("an unknown deprovision policy", {
            let mut b = bearer_body("Ok", Some(&credential));
            b["deprovision"] = json!("purge");
            b
        }),
    ];
    for (what, body) in cases {
        let (status, text) = send(
            &app,
            request(Method::POST, TARGETS, Some(&token)).set_json(body.clone()),
        )
        .await;
        assert_eq!(status, 400, "create with {what}");
        assert!(
            !text.contains(&credential),
            "{what}: the 400 echoed the credential"
        );
        // The same body as a replacement. (A missing credential is a valid
        // replacement: absent keeps the stored one.)
        if what == "a missing credential" {
            continue;
        }
        let (status, _) = send(
            &app,
            request(
                Method::PUT,
                &target_uri(&existing.id.to_string()),
                Some(&token),
            )
            .set_json(body),
        )
        .await;
        assert_eq!(status, 400, "replace with {what}");
    }
    // None of them registered anything.
    let (_, text) = send(&app, request(Method::GET, TARGETS, Some(&token))).await;
    assert_eq!(json_of(&text)["total"], 1);
}

#[actix_rt::test]
async fn without_the_sealing_key_a_credential_cannot_be_stored() {
    let w = world().await;
    // The harness default: no key.
    let state = AppState::<TestDb>::for_test(w.db.clone(), w.auth.clone());
    let app = app!(state, w);
    let (status, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&w.admin_token()))
            .set_json(bearer_body("Keyless", Some(&fresh_credential()))),
    )
    .await;
    assert_eq!(status, 503, "{body}");
}

#[actix_rt::test]
async fn a_body_that_is_not_a_target_is_400_and_the_body_is_not_quoted() {
    let w = world().await;
    let app = app!(w.state(), w);
    let marker = Uuid::new_v4().simple().to_string();
    let (status, text) = send(
        &app,
        request(Method::POST, TARGETS, Some(&w.admin_token()))
            .set_json(json!({ "name": 7, "credential": marker })),
    )
    .await;
    assert_eq!(status, 400);
    assert!(!text.contains(&marker));
}

// ---------------------------------------------------------------------------
// The credential is bound to its URL (D-57)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_bearer_credential_does_not_follow_the_base_url_to_another_one() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let credential = fresh_credential();
    let (_, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token))
            .set_json(bearer_body("Bound", Some(&credential))),
    )
    .await;
    let id = json_of(&body)["id"].as_str().unwrap().to_owned();

    let mut moved = bearer_body("Bound", None);
    moved["base_url"] = json!(OTHER_BASE_URL);
    let (status, text) = send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(moved.clone()),
    )
    .await;
    assert_eq!(status, 400, "{text}");
    assert!(
        json_of(&text).to_string().contains("base_url"),
        "the 400 names the field"
    );
    let stored = w
        .repo()
        .get(w.tenant_id, id.parse().unwrap())
        .await
        .unwrap();
    assert_eq!(stored.base_url, BASE_URL, "nothing was written");

    // With the credential in the same write, the move lands.
    let replacement = fresh_credential();
    moved["credential"] = json!(replacement);
    let (status, text) = send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(moved),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert_no_credential(&text, &replacement);
    assert_eq!(json_of(&text)["base_url"], OTHER_BASE_URL);
    let opened = w
        .repo()
        .decrypt_credential(w.tenant_id, id.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        opened.as_str() == replacement,
        "the replacement is the one stored"
    );
}

#[actix_rt::test]
async fn a_client_secret_does_not_follow_the_token_url_nor_a_switch_of_kind() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let secret_value = fresh_credential();
    let (_, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token)).set_json(oauth_body(
            "Bound",
            TOKEN_URL,
            Some(&secret_value),
        )),
    )
    .await;
    let id = json_of(&body)["id"].as_str().unwrap().to_owned();

    // Another token endpoint without the secret: 400, naming it.
    let (status, text) = send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(oauth_body(
            "Bound",
            OTHER_TOKEN_URL,
            None,
        )),
    )
    .await;
    assert_eq!(status, 400, "{text}");
    assert!(json_of(&text).to_string().contains("token_url"));

    // A move of base_url alone: every access token the secret yields goes
    // there, so it is the secret's destination too (W5 F4, T-409). 400,
    // naming the field, and nothing changes.
    let mut other_base = oauth_body("Bound", TOKEN_URL, None);
    other_base["base_url"] = json!(OTHER_BASE_URL);
    let (status, text) = send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(other_base.clone()),
    )
    .await;
    assert_eq!(status, 400, "{text}");
    assert!(json_of(&text).to_string().contains("base_url"));
    let (_, text) = send(&app, request(Method::GET, &target_uri(&id), Some(&token))).await;
    assert_eq!(
        json_of(&text)["base_url"],
        BASE_URL,
        "a refused move changes nothing"
    );
    // With the secret in the same write it is an ordinary write.
    other_base["credential"] = json!(secret_value);
    let (status, text) = send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(other_base),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(json_of(&text)["base_url"], OTHER_BASE_URL);

    // A switch of kind without the credential: 400, naming the field.
    let (status, text) = send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(bearer_body("Bound", None)),
    )
    .await;
    assert_eq!(status, 400, "{text}");
    assert!(json_of(&text).to_string().contains("auth.type"));
    // And the other way round.
    let (_, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token))
            .set_json(bearer_body("Bearer", Some(&fresh_credential()))),
    )
    .await;
    let bearer_id = json_of(&body)["id"].as_str().unwrap().to_owned();
    let (status, text) = send(
        &app,
        request(Method::PUT, &target_uri(&bearer_id), Some(&token))
            .set_json(oauth_body("Bearer", TOKEN_URL, None)),
    )
    .await;
    assert_eq!(status, 400, "{text}");
    assert!(json_of(&text).to_string().contains("auth.type"));
    let (status, _) = send(
        &app,
        request(Method::PUT, &target_uri(&bearer_id), Some(&token)).set_json(oauth_body(
            "Bearer",
            TOKEN_URL,
            Some(&fresh_credential()),
        )),
    )
    .await;
    assert_eq!(status, 200, "a switch with the new credential");

    // The secret registered first is still the one stored.
    let opened = w
        .repo()
        .decrypt_credential(w.tenant_id, id.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        opened.as_str() == secret_value,
        "the secret registered first is still the one stored"
    );
}

// ---------------------------------------------------------------------------
// Two writers (T-406)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_replacement_overtaken_by_another_is_409_and_does_not_land() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let (target, _) = w.target(w.tenant_id, true).await;
    let uri = target_uri(&target.id.to_string());

    // Two administrators save at once. Each handler reads the target before
    // either writes (the first read of both is queued before the first write
    // can be), so one write lands and the other was prepared from a version
    // that is gone.
    let (a, b) = futures::future::join(
        send(
            &app,
            request(Method::PUT, &uri, Some(&token)).set_json(bearer_body("Writer A", None)),
        ),
        send(
            &app,
            request(Method::PUT, &uri, Some(&token)).set_json(bearer_body("Writer B", None)),
        ),
    )
    .await;
    let mut statuses = [a.0, b.0];
    statuses.sort_unstable();
    assert_eq!(statuses, [200, 409], "A: {} B: {}", a.1, b.1);
    let loser = if a.0 == 409 { &a.1 } else { &b.1 };
    assert!(
        json_of(loser).to_string().contains("changed"),
        "the 409 says the target changed"
    );
    let stored = w.repo().get(w.tenant_id, target.id).await.unwrap();
    assert!(stored.name == "Writer A" || stored.name == "Writer B");
}

#[actix_rt::test]
async fn two_reads_then_two_writes_the_second_is_a_conflict() {
    let w = world().await;
    let (target, _) = w.target(w.tenant_id, true).await;
    let repo = w.repo();
    // Two reads...
    let first = repo.get(w.tenant_id, target.id).await.unwrap();
    let second = repo.get(w.tenant_id, target.id).await.unwrap();
    // ...then two writes, each conditional on the version it read.
    let mut a = ScimTargetUpdate::from_target(&first);
    a.name = "A".into();
    repo.update(w.tenant_id, target.id, a).await.unwrap();
    let mut b = ScimTargetUpdate::from_target(&second);
    b.name = "B".into();
    let err = repo.update(w.tenant_id, target.id, b).await.unwrap_err();
    assert!(matches!(err, AxiamError::Conflict { .. }));
    assert_eq!(repo.get(w.tenant_id, target.id).await.unwrap().name, "A");
}

/// P23W5-09 (T-416): the version the client read travels in the body, so two
/// administrators who opened the form at the same version cannot both save.
#[actix_rt::test]
async fn two_puts_carrying_the_same_expected_updated_at_the_second_is_409() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let (target, _) = w.target(w.tenant_id, true).await;
    let uri = target_uri(&target.id.to_string());
    let read = w
        .repo()
        .get(w.tenant_id, target.id)
        .await
        .unwrap()
        .updated_at;

    let versioned = |name: &str| {
        let mut body = bearer_body(name, None);
        body["expected_updated_at"] = json!(read);
        body
    };
    let (status, body) = send(
        &app,
        request(Method::PUT, &uri, Some(&token)).set_json(versioned("First")),
    )
    .await;
    assert_eq!(status, 200, "the first save of the version lands: {body}");
    let (status, body) = send(
        &app,
        request(Method::PUT, &uri, Some(&token)).set_json(versioned("Second")),
    )
    .await;
    assert_eq!(status, 409, "the second save of the same version: {body}");
    assert!(json_of(&body).to_string().contains("changed"));
    let stored = w.repo().get(w.tenant_id, target.id).await.unwrap();
    assert_eq!(
        stored.name, "First",
        "the first administrator's edit survives"
    );

    // The version the first save produced is the next one to hold.
    let mut body = bearer_body("Third", None);
    body["expected_updated_at"] = json!(stored.updated_at);
    let (status, text) = send(
        &app,
        request(Method::PUT, &uri, Some(&token)).set_json(body),
    )
    .await;
    assert_eq!(status, 200, "{text}");
}

/// Additive: a body without the field is unchanged — conditional on the
/// version the server reads during the request, last-writer-wins between
/// administrators who each reload.
#[actix_rt::test]
async fn a_put_without_expected_updated_at_still_works() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let (target, _) = w.target(w.tenant_id, true).await;
    let uri = target_uri(&target.id.to_string());
    for name in ["One", "Two"] {
        let (status, body) = send(
            &app,
            request(Method::PUT, &uri, Some(&token)).set_json(bearer_body(name, None)),
        )
        .await;
        assert_eq!(status, 200, "{body}");
    }
    assert_eq!(
        w.repo().get(w.tenant_id, target.id).await.unwrap().name,
        "Two"
    );
}

// ---------------------------------------------------------------------------
// Tenant isolation, permissions, human-only
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn another_tenants_target_is_404_on_every_route_and_is_not_touched() {
    let w = world().await;
    let (foreign, credential) = w.target(w.other_tenant_id, true).await;
    let app = app!(w.state(), w);
    // The home administrator, with every permission, addresses the other
    // tenant's target by id.
    let token = w.admin_token();
    let uri = target_uri(&foreign.id.to_string());
    for (method, suffix, body) in [
        (Method::GET, "", None),
        (Method::PUT, "", Some(bearer_body("Hijack", None))),
        (Method::DELETE, "", None),
        (Method::POST, "/reconcile", None),
    ] {
        let mut req = request(method.clone(), &format!("{uri}{suffix}"), Some(&token));
        if let Some(body) = body {
            req = req.set_json(body);
        }
        let (status, text) = send(&app, req).await;
        assert_eq!(status, 404, "{method} {suffix}");
        assert!(!text.contains(&credential));
    }
    // The list shows the home tenant's own, which is none.
    let (_, text) = send(&app, request(Method::GET, TARGETS, Some(&token))).await;
    assert_eq!(json_of(&text)["total"], 0);
    // Untouched, and still the other tenant's.
    let still = w.repo().get(w.other_tenant_id, foreign.id).await.unwrap();
    assert_eq!(still.name, foreign.name);
    assert_eq!(still.updated_at, foreign.updated_at);
    assert!(w.started().is_empty());
    // Its own administrator reads it.
    let (status, _) = send(
        &app,
        request(Method::GET, &uri, Some(&w.other_admin_token())),
    )
    .await;
    assert_eq!(status, 200);
}

#[actix_rt::test]
async fn a_group_scope_cannot_name_another_tenants_group_even_when_replacing() {
    let w = world().await;
    let (target, _) = w.target(w.tenant_id, true).await;
    let foreign_group = group_in(&w.db, w.other_tenant_id, "elsewhere").await;
    let app = app!(w.state(), w);
    let mut body = bearer_body("Scoped", None);
    body["scope"] = json!({ "type": "groups", "group_ids": [foreign_group] });
    let (status, _) = send(
        &app,
        request(
            Method::PUT,
            &target_uri(&target.id.to_string()),
            Some(&w.admin_token()),
        )
        .set_json(body),
    )
    .await;
    assert_eq!(status, 400);
}

#[actix_rt::test]
async fn reads_need_scim_targets_read_and_writes_need_scim_targets_write() {
    let w = world().await;
    let (target, _) = w.target(w.tenant_id, true).await;
    let app = app!(w.state(), w);
    let reader = w.token_for(
        user_holding(&w.db, w.tenant_id, &["scim_targets:read"]).await,
        w.tenant_id,
    );
    let writer = w.token_for(
        user_holding(&w.db, w.tenant_id, &["scim_targets:write"]).await,
        w.tenant_id,
    );
    let nobody = w.token_for(user_holding(&w.db, w.tenant_id, &[]).await, w.tenant_id);
    let uri = target_uri(&target.id.to_string());

    for (caller, label) in [(&reader, "reader"), (&nobody, "nobody")] {
        let expected = if label == "reader" { 200 } else { 403 };
        for path in [TARGETS.to_owned(), uri.clone()] {
            let (status, _) = send(&app, request(Method::GET, &path, Some(caller))).await;
            assert_eq!(status, expected, "{label} GET {path}");
        }
    }
    for caller in [&reader, &nobody] {
        for (method, path, body) in [
            (
                Method::POST,
                TARGETS.to_owned(),
                Some(bearer_body("X", Some(&fresh_credential()))),
            ),
            (Method::PUT, uri.clone(), Some(bearer_body("X", None))),
            (Method::DELETE, uri.clone(), None),
            (Method::POST, format!("{uri}/reconcile"), None),
        ] {
            let mut req = request(method.clone(), &path, Some(caller));
            if let Some(body) = body {
                req = req.set_json(body);
            }
            let (status, _) = send(&app, req).await;
            assert_eq!(status, 403, "{method} {path} without scim_targets:write");
        }
    }
    // The writer may write (and read nothing).
    let (status, _) = send(&app, request(Method::GET, &uri, Some(&writer))).await;
    assert_eq!(status, 403, "write does not imply read");
    let (status, _) = send(
        &app,
        request(Method::PUT, &uri, Some(&writer)).set_json(bearer_body("Renamed", None)),
    )
    .await;
    assert_eq!(status, 200);
    // And no token at all.
    let (status, _) = send(&app, request(Method::GET, TARGETS, None)).await;
    assert_eq!(status, 401);
}

#[actix_rt::test]
async fn a_service_account_token_is_refused_on_every_route_even_with_every_role() {
    let w = world().await;
    let (target, _) = w.target(w.tenant_id, true).await;
    let account = SurrealServiceAccountRepository::new(w.db.clone())
        .create(CreateServiceAccount {
            tenant_id: w.tenant_id,
            name: "machine".into(),
            description: None,
        })
        .await
        .unwrap();
    SurrealRoleRepository::new(w.db.clone())
        .assign_to_service_account(
            w.tenant_id,
            account.0.id,
            role_named(&w.db, w.tenant_id, "super-admin").await,
            AssignmentScope::global(),
        )
        .await
        .unwrap();
    let machine = issue_service_account_token(
        account.0.id,
        w.tenant_id,
        w.org_id,
        Uuid::new_v4().to_string(),
        None,
        &w.auth,
    )
    .unwrap();
    let app = app!(w.state(), w);
    let uri = target_uri(&target.id.to_string());
    for (method, path, body) in [
        (Method::GET, TARGETS.to_owned(), None),
        (
            Method::POST,
            TARGETS.to_owned(),
            Some(bearer_body("X", Some(&fresh_credential()))),
        ),
        (Method::GET, uri.clone(), None),
        (Method::PUT, uri.clone(), Some(bearer_body("X", None))),
        (Method::DELETE, uri.clone(), None),
        (Method::POST, format!("{uri}/reconcile"), None),
    ] {
        let mut req = request(method.clone(), &path, Some(&machine));
        if let Some(body) = body {
            req = req.set_json(body);
        }
        let (status, _) = send(&app, req).await;
        assert_eq!(status, 401, "{method} {path} with a service-account token");
    }
    assert!(w.started().is_empty());
    assert_eq!(
        w.repo().get(w.tenant_id, target.id).await.unwrap().name,
        target.name
    );
}

#[actix_rt::test]
async fn the_family_is_human_only_and_every_route_requires_its_permission() {
    assert!(HUMAN_ONLY_FAMILIES.contains(&"scim_targets"));
    for wanted in ["scim_targets:read", "scim_targets:write"] {
        assert!(
            PERMISSION_REGISTRY.iter().any(|(a, _)| *a == wanted),
            "{wanted}"
        );
    }
    let mapped: Vec<(&str, &str, &str)> = ROUTE_PERMISSION_MAP
        .iter()
        .copied()
        .filter(|(_, path, _)| path.starts_with("/api/v1/scim-targets"))
        .collect();
    assert_eq!(mapped.len(), 6, "{mapped:?}");
    for (method, path, permission) in mapped {
        let expected = if method == "GET" {
            "scim_targets:read"
        } else {
            "scim_targets:write"
        };
        assert_eq!(permission, expected, "{method} {path}");
    }
}

// ---------------------------------------------------------------------------
// Reconciliation (D-58)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn reconcile_now_is_202_when_claimed_then_409_while_the_claim_is_held() {
    let w = world().await;
    let (target, _) = w.target(w.tenant_id, true).await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let uri = format!("{}/reconcile", target_uri(&target.id.to_string()));

    let (status, body) = send(&app, request(Method::POST, &uri, Some(&token))).await;
    assert_eq!(status, 202, "{body}");
    let accepted = json_of(&body);
    assert_eq!(accepted["status"], "started");
    assert_eq!(accepted["target_id"], target.id.to_string());
    assert_eq!(w.started(), vec![(w.tenant_id, target.id)]);

    let (status, body) = send(&app, request(Method::POST, &uri, Some(&token))).await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(w.started().len(), 1, "the second request started nothing");
    assert_eq!(
        w.audit_rows(w.tenant_id, "scim_target.reconcile_requested")
            .await
            .len(),
        1,
        "only the request that started a run is recorded"
    );

    // The claim is visible on the target's state as a reconciliation.
    // (the double's claim stamps it; the projection is the contract's.)
    let (_, body) = send(
        &app,
        request(
            Method::GET,
            &target_uri(&target.id.to_string()),
            Some(&token),
        ),
    )
    .await;
    assert_no_credential(&body, &fresh_credential());
}

#[actix_rt::test]
async fn reconcile_now_on_a_disabled_target_is_409_and_on_an_unknown_one_404() {
    let w = world().await;
    let (disabled, _) = w.target(w.tenant_id, false).await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            &format!("{}/reconcile", target_uri(&disabled.id.to_string())),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 409);
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            &format!("{}/reconcile", target_uri(&Uuid::new_v4().to_string())),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 404);
    assert!(w.started().is_empty());
}

#[actix_rt::test]
async fn reconcile_now_without_delivery_wired_is_503() {
    let w = world().await;
    let (target, _) = w.target(w.tenant_id, true).await;
    let mut state = w.state();
    state.scim_targets.reconcile = None;
    let app = app!(state, w);
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            &format!("{}/reconcile", target_uri(&target.id.to_string())),
            Some(&w.admin_token()),
        ),
    )
    .await;
    assert_eq!(status, 503);
}

#[actix_rt::test]
async fn an_enabled_target_starts_a_reconciliation_when_created_or_switched_on() {
    let w = world().await;
    let app = app!(w.state(), w);
    let token = w.admin_token();

    // Created disabled: nothing starts.
    let mut disabled = bearer_body("Later", Some(&fresh_credential()));
    disabled["enabled"] = json!(false);
    let (status, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token)).set_json(disabled),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    assert_eq!(json_of(&body)["enabled"], false);
    let later = json_of(&body)["id"].as_str().unwrap().to_owned();
    assert!(w.started().is_empty());

    // Switched on: one starts.
    let mut on = bearer_body("Later", None);
    on["enabled"] = json!(true);
    let (status, _) = send(
        &app,
        request(Method::PUT, &target_uri(&later), Some(&token)).set_json(on.clone()),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(w.started().len(), 1);
    assert_eq!(w.started()[0].1.to_string(), later);

    // Saved again while enabled: nothing new.
    let (status, _) = send(
        &app,
        request(Method::PUT, &target_uri(&later), Some(&token)).set_json(on),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(w.started().len(), 1);

    // Created enabled: one starts.
    let (status, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token))
            .set_json(bearer_body("Now", Some(&fresh_credential()))),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(w.started().len(), 2);
    assert_eq!(
        w.started()[1].1.to_string(),
        json_of(&body)["id"].as_str().unwrap()
    );
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn every_write_is_audited_with_names_never_a_url_or_the_credential() {
    let w = world().await;
    let app = app!(w.state_with_window(0), w);
    let token = w.admin_token();
    let credential = fresh_credential();
    let (_, body) = send(
        &app,
        request(Method::POST, TARGETS, Some(&token))
            .set_json(bearer_body("Audited", Some(&credential))),
    )
    .await;
    let id = json_of(&body)["id"].as_str().unwrap().to_owned();
    let mut moved = bearer_body("Audited again", Some(&fresh_credential()));
    moved["base_url"] = json!(OTHER_BASE_URL);
    send(
        &app,
        request(Method::PUT, &target_uri(&id), Some(&token)).set_json(moved),
    )
    .await;
    send(
        &app,
        request(
            Method::POST,
            &format!("{}/reconcile", target_uri(&id)),
            Some(&token),
        ),
    )
    .await;
    send(
        &app,
        request(Method::DELETE, &target_uri(&id), Some(&token)),
    )
    .await;

    for action in [
        "scim_target.created",
        "scim_target.updated",
        "scim_target.reconcile_requested",
        "scim_target.deleted",
    ] {
        let rows = w.audit_rows(w.tenant_id, action).await;
        assert_eq!(rows.len(), 1, "{action}");
        assert_eq!(rows[0].actor_id, w.admin);
        assert_eq!(rows[0].resource_id.map(|r| r.to_string()), Some(id.clone()));
        let rendered = serde_json::to_string(&rows[0].metadata).unwrap();
        assert!(!rendered.contains("example.test"), "{action}: a URL");
        assert!(!rendered.contains(&credential), "{action}: the credential");
    }
    let updated = w.audit_rows(w.tenant_id, "scim_target.updated").await;
    let changed = updated[0].metadata["changed"].clone();
    assert_eq!(changed, json!(["name", "base_url", "credential"]));
}

// ---------------------------------------------------------------------------
// Rate-limit buckets (plan §7 rule 6), pinned
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn every_write_route_has_its_own_bucket_and_reads_are_not_limited() {
    let w = world().await;
    let (a, _) = w.target(w.tenant_id, true).await;
    let (b, _) = w.target(w.tenant_id, true).await;
    let limits = RateLimitConfig {
        scim_target_admin_per_min: 1,
        ..RateLimitConfig::default()
    };
    let app = app!(w.state(), w, limits);
    let token = w.admin_token();

    // create: its own bucket.
    for expected in [201, 429] {
        let (status, _) = send(
            &app,
            request(Method::POST, TARGETS, Some(&token))
                .set_json(bearer_body("Bucket", Some(&fresh_credential()))),
        )
        .await;
        assert_eq!(status, expected, "create");
    }
    // update: untouched by create's spend, then spent.
    let uri_a = target_uri(&a.id.to_string());
    for expected in [200, 429] {
        let (status, _) = send(
            &app,
            request(Method::PUT, &uri_a, Some(&token)).set_json(bearer_body("A", None)),
        )
        .await;
        assert_eq!(status, expected, "update");
    }
    // reconcile: its own bucket.
    for expected in [202, 429] {
        let (status, _) = send(
            &app,
            request(Method::POST, &format!("{uri_a}/reconcile"), Some(&token)),
        )
        .await;
        assert_eq!(status, expected, "reconcile");
    }
    // delete: its own bucket.
    for expected in [204, 429] {
        let (status, _) = send(
            &app,
            request(Method::DELETE, &target_uri(&b.id.to_string()), Some(&token)),
        )
        .await;
        assert_eq!(status, expected, "delete");
    }
    // Reads are not limited.
    for _ in 0..4 {
        let (status, _) = send(&app, request(Method::GET, TARGETS, Some(&token))).await;
        assert_eq!(status, 200, "list");
        let (status, _) = send(&app, request(Method::GET, &uri_a, Some(&token))).await;
        assert_eq!(status, 200, "get");
    }
}

#[actix_rt::test]
async fn the_shipped_bucket_is_thirty_a_minute() {
    assert_eq!(RateLimitConfig::default().scim_target_admin_per_min, 30);
}

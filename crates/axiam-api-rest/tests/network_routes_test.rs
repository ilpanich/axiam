//! The ten network management routes against the real authorization engine and
//! the real write gate (RADIUS D4, W6.3;
//! `claude_dev/radius-reply-profile-design.md` §4.2, §5.1, §5.2, §5.4).
//!
//! What the routes add to the gate's own tests (`network_gate_test.rs`, and the
//! rule-by-rule unit tests in `axiam-authz`): the CRUD contract of each of the
//! ten operations, the permission each needs, that every write is conditional on
//! the `version` read, that an envelope write which would strand a profile is
//! refused naming it, that the reactor's veto hooks fire after the gate and
//! before the write, that another tenant's rows are invisible, that every write
//! and every refusal leaves exactly one audit row with the internal reason and
//! the values before and after, and that each write route has a bucket of its
//! own.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{issue_access_token, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::audit::{AuditLogEntry, AuditOutcome};
use axiam_core::models::network::{
    NETWORK_GRANT, NETWORK_JOIN, NETWORK_PROFILES_WRITE, NETWORK_READ, NETWORK_SEGMENTS_WRITE,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::PermissionEffect;
use axiam_core::models::reactor::{DynReactorGate, ReactorOutcome};
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, PermissionRepository,
    RoleRepository, ServiceAccountRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealServiceAccountRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";
const PEER: &str = "198.51.100.7:40000";

const SEGMENTS: &str = "/api/v1/network/segments";
const PROFILES: &str = "/api/v1/network/profiles";

fn test_auth_config() -> AuthConfig {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// Two tenants of one organization, each with the registry and the default
/// roles, as bootstrap leaves them.
struct World {
    db: Surreal<TestDb>,
    org: Uuid,
    tenant: Uuid,
    other_tenant: Uuid,
    auth: AuthConfig,
}

impl World {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Net Org".into(),
                slug: "net-org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenants = SurrealTenantRepository::new(db.clone());
        let mut ids = Vec::new();
        for slug in ["net-tenant", "other-tenant"] {
            let tenant = tenants
                .create(CreateTenant {
                    organization_id: org.id,
                    kind: TenantKind::Standard,
                    name: slug.into(),
                    slug: slug.into(),
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
            ids.push(tenant.id);
        }
        Self {
            db,
            org: org.id,
            tenant: ids[0],
            other_tenant: ids[1],
            auth: test_auth_config(),
        }
    }

    fn engine(&self) -> Arc<dyn AuthzChecker> {
        Arc::new(AuthorizationEngine::new(
            SurrealRoleRepository::new(self.db.clone()),
            SurrealPermissionRepository::new(self.db.clone()),
            SurrealResourceRepository::new(self.db.clone()),
            SurrealScopeRepository::new(self.db.clone()),
            SurrealGroupRepository::new(self.db.clone()),
        ))
    }

    async fn permission_id(&self, tenant: Uuid, action: &str) -> Uuid {
        SurrealPermissionRepository::new(self.db.clone())
            .list(tenant, page())
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|p| p.action == action)
            .unwrap_or_else(|| panic!("permission {action} not seeded"))
            .id
    }

    /// A non-global role of `tenant` carrying `grants` (allow), made directly:
    /// test setup is not the subject of these tests.
    async fn role(&self, tenant: Uuid, name: &str, grants: &[&str]) -> Uuid {
        let roles = SurrealRoleRepository::new(self.db.clone());
        let role = roles
            .create(CreateRole {
                tenant_id: tenant,
                name: name.into(),
                description: String::new(),
                is_global: false,
            })
            .await
            .unwrap();
        let perms = SurrealPermissionRepository::new(self.db.clone());
        for action in grants {
            perms
                .grant_to_role_with_effect(
                    tenant,
                    role.id,
                    self.permission_id(tenant, action).await,
                    vec![],
                    PermissionEffect::Allow,
                )
                .await
                .unwrap();
        }
        role.id
    }

    /// An active user of `tenant` holding `roles`, each tenant-wide or at a node.
    async fn user(&self, tenant: Uuid, roles: &[(Uuid, Option<Uuid>)]) -> Uuid {
        let users = SurrealUserRepository::new(self.db.clone());
        let user = users
            .create(CreateUser {
                tenant_id: tenant,
                username: format!("u{}", Uuid::new_v4().simple()),
                email: format!("{}@example.com", Uuid::new_v4().simple()),
                password: TEST_PASSWORD.into(),
                metadata: None,
            })
            .await
            .unwrap();
        users
            .update(
                tenant,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let assign = SurrealRoleRepository::new(self.db.clone());
        for (role, at) in roles {
            assign
                .assign_to_user(tenant, user.id, *role, AssignmentScope::from(*at))
                .await
                .unwrap();
        }
        user.id
    }

    /// A network administrator of `tenant`: read, both writes and `grant`,
    /// tenant-wide.
    async fn netadmin(&self, tenant: Uuid) -> String {
        let role = self
            .role(
                tenant,
                "netadmin",
                &[
                    NETWORK_READ,
                    NETWORK_SEGMENTS_WRITE,
                    NETWORK_PROFILES_WRITE,
                    NETWORK_GRANT,
                ],
            )
            .await;
        let user = self.user(tenant, &[(role, None)]).await;
        self.token(tenant, user)
    }

    /// The token of a user of the default tenant holding exactly `grants`,
    /// tenant-wide.
    async fn user_with(&self, grants: &[&str]) -> String {
        let role = self
            .role(
                self.tenant,
                &format!("r-{}", Uuid::new_v4().simple()),
                grants,
            )
            .await;
        let user = self.user(self.tenant, &[(role, None)]).await;
        self.token(self.tenant, user)
    }

    fn token(&self, tenant: Uuid, user: Uuid) -> String {
        issue_access_token(
            user,
            tenant,
            self.org,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            axiam_auth::token::AUD_USER,
        )
        .unwrap()
    }

    async fn sa_token(&self) -> String {
        let (account, _secret) = SurrealServiceAccountRepository::new(self.db.clone())
            .create(CreateServiceAccount {
                tenant_id: self.tenant,
                name: format!("sa-{}", Uuid::new_v4().simple()),
                description: None,
            })
            .await
            .unwrap();
        issue_service_account_token(
            account.id,
            self.tenant,
            self.org,
            Uuid::new_v4().to_string(),
            None,
            &self.auth,
        )
        .unwrap()
    }

    async fn audit_in(&self, tenant: Uuid, action: &str) -> Vec<AuditLogEntry> {
        SurrealAuditLogRepository::new(self.db.clone())
            .list(
                tenant,
                AuditLogFilter {
                    action: Some(action.into()),
                    ..Default::default()
                },
                page(),
            )
            .await
            .unwrap()
            .items
    }

    async fn audit(&self, action: &str) -> Vec<AuditLogEntry> {
        self.audit_in(self.tenant, action).await
    }
}

fn page() -> Pagination {
    Pagination {
        offset: 0,
        limit: 1000,
        search: None,
    }
}

/// A reactor gate that records what it is asked and vetoes the named events.
struct Gate {
    deny: Vec<&'static str>,
    seen: Mutex<Vec<(String, Value)>>,
}

impl Gate {
    fn new(deny: &[&'static str]) -> Arc<Self> {
        Arc::new(Self {
            deny: deny.to_vec(),
            seen: Mutex::new(Vec::new()),
        })
    }

    fn seen(&self) -> Vec<(String, Value)> {
        self.seen.lock().unwrap().clone()
    }
}

impl DynReactorGate for Gate {
    fn intercept_dyn<'a>(
        &'a self,
        _tenant_id: Uuid,
        event: &'static str,
        payload: Value,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ReactorOutcome> + Send + 'a>> {
        self.seen.lock().unwrap().push((event.to_owned(), payload));
        let outcome = if self.deny.contains(&event) {
            ReactorOutcome::Deny {
                reason: "second approver missing".into(),
            }
        } else {
            ReactorOutcome::Allow
        };
        Box::pin(std::future::ready(outcome))
    }

    fn can_dispatch_dyn(&self) -> bool {
        true
    }
}

macro_rules! app {
    ($w:expr) => {
        app!($w, RateLimitConfig::default(), None::<Arc<Gate>>)
    };
    ($w:expr, $limits:expr) => {
        app!($w, $limits, None::<Arc<Gate>>)
    };
    ($w:expr, $limits:expr, $gate:expr) => {{
        let mut state = AppState::for_test($w.db.clone(), $w.auth.clone());
        if let Some(gate) = $gate {
            state.events.reactor_gate = gate;
        }
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.engine()))
                .app_data(web::Data::new(state))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &$limits)),
        )
        .await
    }};
}

/// Send `method uri body` as `token`; the status and the JSON body (or null).
async fn call(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    method: &str,
    uri: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let req = match method {
        "POST" => test::TestRequest::post(),
        "PUT" => test::TestRequest::put(),
        "DELETE" => test::TestRequest::delete(),
        _ => test::TestRequest::get(),
    }
    .uri(uri)
    .peer_addr(PEER.parse::<SocketAddr>().unwrap())
    .insert_header(("Authorization", format!("Bearer {token}")))
    .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
    .insert_header(("X-CSRF-Token", CSRF_TOKEN));
    let req = match body {
        Some(b) => req.set_json(b),
        None => req,
    }
    .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn segment_body(name: &str, vlan: u16, rank: u32, filters: &[&str]) -> Value {
    json!({
        "kind": "access",
        "site_key": "hq",
        "name": name,
        "vlan_id": vlan,
        "filter_ids": filters,
        "rank": rank,
    })
}

fn profile_body(segment: &Value, timeout: u32, filter: Option<&str>) -> Value {
    json!({
        "segment_id": segment["id"],
        "segment_version": segment["version"],
        "profile": {
            "session_timeout_secs": timeout,
            "idle_timeout_secs": 600,
            "filter_id": filter,
        },
    })
}

/// A segment made through the route as `token`.
async fn make_segment(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    name: &str,
    vlan: u16,
    filters: &[&str],
) -> Value {
    let (status, segment) = call(
        app,
        token,
        "POST",
        SEGMENTS,
        Some(segment_body(name, vlan, u32::from(vlan), filters)),
    )
    .await;
    assert_eq!(status, 201, "{segment}");
    segment
}

/// The one refusal row of `action`, denied, with its metadata.
#[track_caller]
fn the_row(rows: &[AuditLogEntry]) -> &AuditLogEntry {
    assert_eq!(rows.len(), 1, "exactly one row: {rows:?}");
    &rows[0]
}

// ---------------------------------------------------------------------------
// The ten operations
// ---------------------------------------------------------------------------

/// Create, list, get, replace and delete of a segment, each with its audit row
/// carrying the values before and after.
#[actix_rt::test]
async fn segments_create_list_get_replace_delete() {
    let w = World::new().await;
    let token = w.netadmin(w.tenant).await;
    let app = app!(w);

    let (status, created) = call(
        &app,
        &token,
        "POST",
        SEGMENTS,
        Some(segment_body("corp", 10, 10, &["corp-acl"])),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["path"], "/network/zones/hq/corp");
    assert_eq!(created["kind"], "access");
    assert_eq!(created["vlan_id"], 10);
    assert_eq!(created["version"], 1);
    assert_eq!(created["tenant_id"], w.tenant.to_string());
    let id = created["id"].as_str().unwrap().to_owned();

    // A second site, so the list has something to narrow.
    let (status, _) = call(
        &app,
        &token,
        "POST",
        SEGMENTS,
        Some(json!({
            "kind": "quarantine", "site_key": "branch", "name": "q", "vlan_id": 999,
        })),
    )
    .await;
    assert_eq!(status, 201);

    let (status, list) = call(&app, &token, "GET", SEGMENTS, None).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["total"], 2);
    let (status, list) = call(&app, &token, "GET", &format!("{SEGMENTS}?site=hq"), None).await;
    assert_eq!(status, 200);
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["id"], id.as_str());
    let (_, list) = call(
        &app,
        &token,
        "GET",
        &format!("{SEGMENTS}?site=nowhere"),
        None,
    )
    .await;
    assert_eq!(list["total"], 0);

    let (status, got) = call(&app, &token, "GET", &format!("{SEGMENTS}/{id}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(got, created);

    // Replace: conditional on the version read; the version moves.
    let (status, replaced) = call(
        &app,
        &token,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        Some(json!({
            "version": 1, "vlan_id": 11, "filter_ids": ["corp-acl", "guest"],
            "rank": 12, "enabled": false,
        })),
    )
    .await;
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(replaced["vlan_id"], 11);
    assert_eq!(replaced["enabled"], false);
    assert_eq!(replaced["version"], 2);
    assert_eq!(
        replaced["path"], "/network/zones/hq/corp",
        "the place stays"
    );

    let (status, _) = call(
        &app,
        &token,
        "DELETE",
        &format!("{SEGMENTS}/{id}?version=2"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = call(&app, &token, "GET", &format!("{SEGMENTS}/{id}"), None).await;
    assert_eq!(status, 404);

    // One row per write, with the values before and after (§5.4).
    let rows = w.audit("network_segment.created").await;
    assert_eq!(rows.len(), 2);
    let created_row = rows
        .iter()
        .find(|r| r.resource_id.map(|i| i.to_string()) == Some(id.clone()))
        .unwrap();
    assert_eq!(created_row.outcome, AuditOutcome::Success);
    assert_eq!(created_row.metadata["after"]["vlan_id"], 10);
    assert_eq!(
        created_row.metadata["after"]["path"],
        "/network/zones/hq/corp"
    );
    let updated = w.audit("network_segment.updated").await;
    let row = the_row(&updated);
    assert_eq!(row.metadata["before"]["vlan_id"], 10);
    assert_eq!(row.metadata["after"]["vlan_id"], 11);
    assert_eq!(row.metadata["before"]["version"], 1);
    assert_eq!(row.metadata["after"]["version"], 2);
    let deleted = w.audit("network_segment.deleted").await;
    let row = the_row(&deleted);
    assert_eq!(row.metadata["before"]["vlan_id"], 11);
    assert_eq!(row.resource_id.map(|i| i.to_string()), Some(id));
}

/// Create, list, get, replace and delete of a reply profile, addressed by its
/// segment; the effective profile is what is returned.
#[actix_rt::test]
async fn profiles_create_list_get_replace_delete() {
    let w = World::new().await;
    let token = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &token, "corp", 10, &["corp-acl", "guest"]).await;
    let id = segment["id"].as_str().unwrap().to_owned();

    let (status, none) = call(&app, &token, "GET", &format!("{PROFILES}/{id}"), None).await;
    assert_eq!(status, 404, "{none}");

    let (status, created) = call(
        &app,
        &token,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["segment_id"], id.as_str());
    assert_eq!(created["dictionary"], "axiam-radius-reply/1");
    assert_eq!(created["session_timeout_secs"], 1800);
    assert_eq!(created["termination_action"], "radius_request");
    assert_eq!(created["filter_id"], "corp-acl");
    assert_eq!(created["version"], 1);

    let (status, got) = call(&app, &token, "GET", &format!("{PROFILES}/{id}"), None).await;
    assert_eq!(status, 200);
    assert_eq!(got, created);
    let (status, list) = call(&app, &token, "GET", PROFILES, None).await;
    assert_eq!(status, 200, "{list}");
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["segment_id"], id.as_str());

    let (status, replaced) = call(
        &app,
        &token,
        "PUT",
        &format!("{PROFILES}/{id}"),
        Some(json!({
            "version": 1,
            "segment_version": segment["version"],
            "profile": {
                "session_timeout_secs": 900,
                "termination_action": "default",
                "filter_id": "guest",
            },
        })),
    )
    .await;
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(replaced["session_timeout_secs"], 900);
    assert_eq!(replaced["termination_action"], "default");
    assert_eq!(replaced["version"], 2);
    assert_eq!(replaced["idle_timeout_secs"], Value::Null);

    let (status, _) = call(
        &app,
        &token,
        "DELETE",
        &format!("{PROFILES}/{id}?version=2"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = call(&app, &token, "GET", &format!("{PROFILES}/{id}"), None).await;
    assert_eq!(status, 404);
    let (_, list) = call(&app, &token, "GET", PROFILES, None).await;
    assert_eq!(list["total"], 0);

    let rows = w.audit("reply_profile.created").await;
    let row = the_row(&rows);
    assert_eq!(row.outcome, AuditOutcome::Success);
    assert_eq!(row.metadata["before"], Value::Null);
    assert_eq!(row.metadata["after"]["session_timeout_secs"], 1800);
    assert_eq!(row.metadata["after"]["dictionary"], "axiam-radius-reply/1");
    let rows = w.audit("reply_profile.replaced").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["before"]["session_timeout_secs"], 1800);
    assert_eq!(row.metadata["after"]["session_timeout_secs"], 900);
    assert_eq!(row.metadata["before"]["filter_id"], "corp-acl");
    assert_eq!(row.metadata["after"]["filter_id"], "guest");
    let rows = w.audit("reply_profile.deleted").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["before"]["session_timeout_secs"], 900);
    assert_eq!(row.resource_id.map(|i| i.to_string()), Some(id));
}

/// Deleting a segment takes its profile with it.
#[actix_rt::test]
async fn deleting_a_segment_deletes_its_profile() {
    let w = World::new().await;
    let token = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &token, "corp", 10, &["corp-acl"]).await;
    let id = segment["id"].as_str().unwrap();
    let (status, _) = call(
        &app,
        &token,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 201);
    let (status, _) = call(
        &app,
        &token,
        "DELETE",
        &format!("{SEGMENTS}/{id}?version=1"),
        None,
    )
    .await;
    assert_eq!(status, 204);
    let (_, list) = call(&app, &token, "GET", PROFILES, None).await;
    assert_eq!(list["total"], 0);
}

// ---------------------------------------------------------------------------
// Permissions, and the gate's refusals
// ---------------------------------------------------------------------------

/// A read needs `network:read`: at `/network` for a list, at the segment for a
/// get. A user with none is `403` on all four reads; one holding it only on a
/// segment can get that segment and cannot list.
#[actix_rt::test]
async fn reads_need_network_read() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &admin, "corp", 10, &["corp-acl"]).await;
    let id = segment["id"].as_str().unwrap();
    let other = make_segment(&app, &admin, "iot", 20, &[]).await;

    let nobody = w.user_with(&[]).await;
    for uri in [
        SEGMENTS.to_owned(),
        format!("{SEGMENTS}/{id}"),
        PROFILES.to_owned(),
        format!("{PROFILES}/{id}"),
    ] {
        let (status, body) = call(&app, &nobody, "GET", &uri, None).await;
        assert_eq!(status, 403, "{uri}: {body}");
        assert_eq!(body["action"], NETWORK_READ, "{uri}: {body}");
    }

    // network:read at one segment only.
    let role = w
        .role(w.tenant, "one-segment-reader", &[NETWORK_READ])
        .await;
    let at = id.parse::<Uuid>().unwrap();
    let reader = w.user(w.tenant, &[(role, Some(at))]).await;
    let reader = w.token(w.tenant, reader);
    let (status, _) = call(&app, &reader, "GET", &format!("{SEGMENTS}/{id}"), None).await;
    assert_eq!(status, 200);
    let (status, _) = call(
        &app,
        &reader,
        "GET",
        &format!("{SEGMENTS}/{}", other["id"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(&app, &reader, "GET", SEGMENTS, None).await;
    assert_eq!(status, 403, "a list reads /network");
}

/// A service-account token is `401`: the `network` family is human-only.
#[actix_rt::test]
async fn a_service_account_token_is_401() {
    let w = World::new().await;
    let app = app!(w);
    let token = w.sa_token().await;
    for (method, uri) in [("GET", SEGMENTS), ("GET", PROFILES)] {
        let (status, _) = call(&app, &token, method, uri, None).await;
        assert_eq!(status, 401, "{method} {uri}");
    }
    let (status, _) = call(
        &app,
        &token,
        "POST",
        SEGMENTS,
        Some(segment_body("corp", 10, 10, &[])),
    )
    .await;
    assert_eq!(status, 401);
}

/// Without `network:segments_write` every segment write is `403`, names the
/// permission, changes nothing and leaves a refusal row; without
/// `network:profiles_write` (H1) every profile write is.
#[actix_rt::test]
async fn writes_without_the_permission_are_403_with_a_refusal_row() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &admin, "corp", 10, &["corp-acl"]).await;
    let id = segment["id"].as_str().unwrap().to_owned();

    // Read only.
    let reader = w.user_with(&[NETWORK_READ]).await;
    let (status, err) = call(
        &app,
        &reader,
        "POST",
        SEGMENTS,
        Some(segment_body("evil", 99, 99, &[])),
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert_eq!(err["action"], NETWORK_SEGMENTS_WRITE);
    let (status, _) = call(
        &app,
        &reader,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        Some(json!({"version": 1, "vlan_id": 99, "filter_ids": [], "rank": 1, "enabled": true})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &app,
        &reader,
        "DELETE",
        &format!("{SEGMENTS}/{id}?version=1"),
        None,
    )
    .await;
    assert_eq!(status, 403);

    let rows = w.audit("network_segment.write_refused").await;
    assert_eq!(rows.len(), 3, "{rows:?}");
    for row in &rows {
        assert_eq!(row.outcome, AuditOutcome::Denied);
        assert_eq!(row.metadata["rule"], "4.2:segments_write");
        assert_eq!(row.metadata["missing_permission"], NETWORK_SEGMENTS_WRITE);
        assert_eq!(row.metadata["status"], 403);
    }
    let writes: Vec<&str> = rows
        .iter()
        .map(|r| r.metadata["write"].as_str().unwrap())
        .collect();
    for expected in ["segment_create", "segment_update", "segment_delete"] {
        assert!(writes.contains(&expected), "{expected} in {writes:?}");
    }
    let update_row = rows
        .iter()
        .find(|r| r.metadata["write"] == "segment_update")
        .unwrap();
    assert_eq!(update_row.metadata["before"]["vlan_id"], "10");
    assert_eq!(update_row.metadata["after"]["vlan_id"], "99");

    // The segment is untouched, and "evil" was not made.
    let (_, list) = call(&app, &admin, "GET", SEGMENTS, None).await;
    assert_eq!(list["total"], 1);
    assert_eq!(list["items"][0]["vlan_id"], 10);

    // Profile writes: segments_write is not profiles_write (H1).
    let segwriter = w.user_with(&[NETWORK_READ, NETWORK_SEGMENTS_WRITE]).await;
    let (status, err) = call(
        &app,
        &segwriter,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert_eq!(err["action"], NETWORK_PROFILES_WRITE);
    let rows = w.audit("reply_profile.write_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "H1");
    assert_eq!(row.metadata["before"]["profile"], "none");
    assert_eq!(row.metadata["after"]["session_timeout_secs"], "1800");
}

/// Writing a profile is a grant: `network:profiles_write` without
/// `network:grant` on the segment is `403` under H2, naming it; a `filter_id`
/// outside the envelope and a timeout above the cap are `403` under H3 (the
/// gate's answer, not the repository's `400`); a subject that can itself join
/// the segment is `403` under H6, whatever it holds. Each with its audit row.
#[actix_rt::test]
async fn the_h_rules_refuse_a_profile_write_with_the_internal_rule_audited() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &admin, "corp", 10, &["corp-acl"]).await;
    let id: Uuid = segment["id"].as_str().unwrap().parse().unwrap();

    // H2.
    let writer = w.user_with(&[NETWORK_READ, NETWORK_PROFILES_WRITE]).await;
    let (status, err) = call(
        &app,
        &writer,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert_eq!(err["action"], NETWORK_GRANT);
    assert_eq!(err["resource_id"], id.to_string());

    // H3: a filter id the segment does not declare, then a timeout above the
    // tenant's cap of 3600.
    let (status, _) = call(
        &app,
        &admin,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("not-declared"))),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &app,
        &admin,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 7200, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 403);

    // H6: the same administrator, who may also join the segment.
    let join = w.role(w.tenant, "joiner", &[NETWORK_JOIN]).await;
    let both = w
        .role(
            w.tenant,
            "writer-and-device",
            &[NETWORK_READ, NETWORK_PROFILES_WRITE, NETWORK_GRANT],
        )
        .await;
    let user = w.user(w.tenant, &[(both, None), (join, Some(id))]).await;
    let (status, _) = call(
        &app,
        &w.token(w.tenant, user),
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 403);

    let rows = w.audit("reply_profile.write_refused").await;
    let mut rules: Vec<String> = rows
        .iter()
        .map(|r| r.metadata["rule"].as_str().unwrap().to_owned())
        .collect();
    rules.sort();
    assert_eq!(
        rules,
        [
            "H2",
            "H3:envelope:filter_id",
            "H3:envelope:session_timeout",
            "H6"
        ]
    );
    for row in &rows {
        assert_eq!(row.outcome, AuditOutcome::Denied);
        assert_eq!(row.metadata["write"], "profile_write");
        assert_eq!(row.metadata["before"]["profile"], "none");
    }
    let (_, list) = call(&app, &admin, "GET", PROFILES, None).await;
    assert_eq!(list["total"], 0, "none of the four wrote anything");
}

/// A profile is a typed record: an unknown key is `400` naming it, and a value
/// outside the dictionary is `400`.
#[actix_rt::test]
async fn a_profile_is_a_closed_record() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &admin, "corp", 10, &[]).await;

    let mut body = profile_body(&segment, 1800, None);
    body["profile"]["cisco_avpair"] = json!("shell:priv-lvl=15");
    let (status, err) = call(&app, &admin, "POST", PROFILES, Some(body)).await;
    assert_eq!(status, 400, "{err}");
    assert!(
        err.to_string().contains("cisco_avpair"),
        "the unknown key is named: {err}"
    );

    // A segment field is not a profile field: the VLAN is the segment's.
    let mut body = profile_body(&segment, 1800, None);
    body["profile"]["vlan_id"] = json!(99);
    let (status, err) = call(&app, &admin, "POST", PROFILES, Some(body)).await;
    assert_eq!(status, 400, "{err}");

    // Below the Session-Timeout floor: the repository's value rule.
    let (status, err) = call(
        &app,
        &admin,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 5, None)),
    )
    .await;
    assert_eq!(status, 400, "{err}");
    let rows = w.audit("reply_profile.write_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "validation");
    assert_eq!(row.metadata["status"], 400);
}

// ---------------------------------------------------------------------------
// Conditional writes
// ---------------------------------------------------------------------------

/// Every write is conditional on the `version` read: a stale one is `409`,
/// writes nothing and is audited as a refusal.
#[actix_rt::test]
async fn a_stale_version_is_409_on_every_write_and_changes_nothing() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &admin, "corp", 10, &["corp-acl"]).await;
    let id = segment["id"].as_str().unwrap().to_owned();
    let (status, profile) = call(
        &app,
        &admin,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 201, "{profile}");

    // Segment replace and delete on a version nobody read.
    let (status, err) = call(
        &app,
        &admin,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        Some(json!({"version": 7, "vlan_id": 99, "filter_ids": ["corp-acl"], "rank": 10, "enabled": true})),
    )
    .await;
    assert_eq!(status, 409, "{err}");
    let (status, _) = call(
        &app,
        &admin,
        "DELETE",
        &format!("{SEGMENTS}/{id}?version=7"),
        None,
    )
    .await;
    assert_eq!(status, 409);

    // Profile replace: a stale profile version, then a stale segment version.
    let replace = |profile_version: u64, segment_version: u64| {
        json!({
            "version": profile_version,
            "segment_version": segment_version,
            "profile": {"session_timeout_secs": 600, "filter_id": "corp-acl"},
        })
    };
    let (status, _) = call(
        &app,
        &admin,
        "PUT",
        &format!("{PROFILES}/{id}"),
        Some(replace(9, 1)),
    )
    .await;
    assert_eq!(status, 409);
    let (status, _) = call(
        &app,
        &admin,
        "PUT",
        &format!("{PROFILES}/{id}"),
        Some(replace(1, 9)),
    )
    .await;
    assert_eq!(status, 409);
    // Profile create against a segment version that is not current.
    let (status, _) = call(
        &app,
        &admin,
        "DELETE",
        &format!("{PROFILES}/{id}?version=9"),
        None,
    )
    .await;
    assert_eq!(status, 409);
    let other = make_segment(&app, &admin, "iot", 20, &[]).await;
    let mut stale_create = profile_body(&other, 1800, None);
    stale_create["segment_version"] = json!(5);
    let (status, _) = call(&app, &admin, "POST", PROFILES, Some(stale_create)).await;
    assert_eq!(status, 409);

    // Nothing moved.
    let (_, got) = call(&app, &admin, "GET", &format!("{SEGMENTS}/{id}"), None).await;
    assert_eq!(got["version"], 1);
    assert_eq!(got["vlan_id"], 10);
    let (_, got) = call(&app, &admin, "GET", &format!("{PROFILES}/{id}"), None).await;
    assert_eq!(got["version"], 1);
    assert_eq!(got["session_timeout_secs"], 1800);

    let rows = w.audit("network_segment.write_refused").await;
    assert_eq!(rows.len(), 2);
    for row in &rows {
        assert_eq!(row.metadata["rule"], "version:stale");
        assert_eq!(row.metadata["status"], 409);
    }
    let update = rows
        .iter()
        .find(|r| r.metadata["write"] == "segment_update")
        .unwrap();
    assert_eq!(update.metadata["before"]["version"], 1);
    assert_eq!(update.metadata["after"]["expected_version"], 7);
    let rows = w.audit("reply_profile.write_refused").await;
    assert_eq!(rows.len(), 4, "{rows:?}");
    assert!(rows.iter().all(|r| r.metadata["status"] == 409));
}

/// An envelope write that would strand the segment's profile is `409`, naming
/// the profile; one that keeps it is accepted.
#[actix_rt::test]
async fn an_envelope_write_that_would_strand_a_profile_is_409_naming_it() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &admin, "corp", 10, &["a", "b"]).await;
    let id = segment["id"].as_str().unwrap().to_owned();
    let (status, _) = call(
        &app,
        &admin,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("a"))),
    )
    .await;
    assert_eq!(status, 201);

    let replace = |filters: Value| json!({"version": 1, "vlan_id": 10, "filter_ids": filters, "rank": 10, "enabled": true});
    let (status, err) = call(
        &app,
        &admin,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        Some(replace(json!(["b"]))),
    )
    .await;
    assert_eq!(status, 409, "{err}");
    let message = err.to_string();
    assert!(message.contains(&id), "names the profile: {message}");
    assert!(message.contains("'a'"), "names the filter id: {message}");

    let rows = w.audit("network_segment.write_refused").await;
    let row = the_row(&rows);
    assert_eq!(row.metadata["rule"], "5.2:strands-profile");
    assert_eq!(row.metadata["before"]["filter_ids"], json!(["a", "b"]));
    assert_eq!(row.metadata["after"]["filter_ids"], json!(["b"]));
    let (_, got) = call(&app, &admin, "GET", &format!("{SEGMENTS}/{id}"), None).await;
    assert_eq!(
        got["filter_ids"],
        json!(["a", "b"]),
        "the envelope is unchanged"
    );
    assert_eq!(got["version"], 1);

    // Keeping the profile's filter id is fine.
    let (status, ok) = call(
        &app,
        &admin,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        Some(replace(json!(["a", "c"]))),
    )
    .await;
    assert_eq!(status, 200, "{ok}");
}

// ---------------------------------------------------------------------------
// The reactor's veto hooks
// ---------------------------------------------------------------------------

/// `network.pre_segment_write` and `network.pre_profile_write` veto a write
/// after the gate cleared it and before the repository: `403` with the
/// reactor's reason, nothing written, one refusal row; the payload carries the
/// actor and the values before and after. A write the gate refuses never reaches
/// the reactor.
#[actix_rt::test]
async fn a_reactor_veto_refuses_the_write_and_is_audited() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    // A segment and its profile made while no reactor vetoes anything.
    let open = app!(w);
    let segment = make_segment(&open, &admin, "corp", 10, &["corp-acl"]).await;
    let id = segment["id"].as_str().unwrap().to_owned();
    let (status, _) = call(
        &open,
        &admin,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 201);

    let gate = Gate::new(&["network.pre_segment_write", "network.pre_profile_write"]);
    let app = app!(w, RateLimitConfig::default(), Some(gate.clone()));

    // Segment: create, replace, delete.
    let (status, err) = call(
        &app,
        &admin,
        "POST",
        SEGMENTS,
        Some(segment_body("iot", 20, 20, &[])),
    )
    .await;
    assert_eq!(status, 403, "{err}");
    assert!(
        err.to_string().contains("second approver missing"),
        "the reactor's reason reaches the administrator: {err}"
    );
    let (status, _) = call(
        &app,
        &admin,
        "PUT",
        &format!("{SEGMENTS}/{id}"),
        Some(json!({"version": 1, "vlan_id": 99, "filter_ids": ["corp-acl"], "rank": 10, "enabled": true})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &app,
        &admin,
        "DELETE",
        &format!("{SEGMENTS}/{id}?version=1"),
        None,
    )
    .await;
    assert_eq!(status, 403);
    // Profile: create, replace, delete.
    let other = {
        // `iot` was vetoed; make it through the open app.
        make_segment(&open, &admin, "iot", 20, &["x"]).await
    };
    let (status, _) = call(
        &app,
        &admin,
        "POST",
        PROFILES,
        Some(profile_body(&other, 1800, Some("x"))),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &app,
        &admin,
        "PUT",
        &format!("{PROFILES}/{id}"),
        Some(json!({"version": 1, "segment_version": 1, "profile": {"session_timeout_secs": 600}})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        &app,
        &admin,
        "DELETE",
        &format!("{PROFILES}/{id}?version=1"),
        None,
    )
    .await;
    assert_eq!(status, 403);

    // Nothing was written.
    let (_, got) = call(&open, &admin, "GET", &format!("{SEGMENTS}/{id}"), None).await;
    assert_eq!(
        (got["vlan_id"].clone(), got["version"].clone()),
        (json!(10), json!(1))
    );
    let (_, got) = call(&open, &admin, "GET", &format!("{PROFILES}/{id}"), None).await;
    assert_eq!(got["session_timeout_secs"], 1800);
    let (_, list) = call(&open, &admin, "GET", SEGMENTS, None).await;
    assert_eq!(list["total"], 2, "iot was made once, through the open app");

    for (action, writes) in [
        (
            "network_segment.write_refused",
            ["segment_create", "segment_update", "segment_delete"],
        ),
        (
            "reply_profile.write_refused",
            ["profile_write", "profile_write", "profile_delete"],
        ),
    ] {
        let rows = w.audit(action).await;
        assert_eq!(rows.len(), 3, "{action}: {rows:?}");
        for row in &rows {
            assert_eq!(row.metadata["rule"], "reactor:veto");
            assert_eq!(row.metadata["status"], 403);
            assert!(
                row.metadata["reason"]
                    .as_str()
                    .unwrap()
                    .contains("second approver missing")
            );
        }
        for write in writes {
            assert!(rows.iter().any(|r| r.metadata["write"] == write), "{write}");
        }
    }

    // The payload: who, what, before and after.
    let seen = gate.seen();
    assert_eq!(seen.len(), 6);
    let replace = seen
        .iter()
        .find(|(event, p)| event == "network.pre_segment_write" && p["operation"] == "replace")
        .expect("the replace was offered to the reactor");
    assert_eq!(replace.1["segment_id"], id.as_str());
    assert_eq!(replace.1["tenant_id"], w.tenant.to_string());
    assert_eq!(replace.1["actor_type"], "user");
    assert_eq!(replace.1["before"]["vlan_id"], 10);
    assert_eq!(replace.1["after"]["vlan_id"], 99);
    assert!(replace.1["actor_id"].is_string());

    // A write the gate refuses is never offered to the reactor.
    let reader = w.user_with(&[NETWORK_READ]).await;
    let before = gate.seen().len();
    let (status, _) = call(
        &app,
        &reader,
        "POST",
        SEGMENTS,
        Some(segment_body("sneaky", 30, 30, &[])),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(gate.seen().len(), before, "the gate refused first");
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

/// Another tenant's segment and profile are `404` on every operation, exactly
/// as one that does not exist; its lists do not show them; and the refused
/// writes are audited in the **caller's** tenant, never the owner's.
#[actix_rt::test]
async fn another_tenants_segments_and_profiles_are_invisible() {
    let w = World::new().await;
    let admin_a = w.netadmin(w.tenant).await;
    let admin_b = w.netadmin(w.other_tenant).await;
    let app = app!(w);
    let segment = make_segment(&app, &admin_a, "corp", 10, &["corp-acl"]).await;
    let id = segment["id"].as_str().unwrap().to_owned();
    let (status, _) = call(
        &app,
        &admin_a,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 201);

    // B sees nothing of A.
    let (_, list) = call(&app, &admin_b, "GET", SEGMENTS, None).await;
    assert_eq!(list["total"], 0);
    let (_, list) = call(&app, &admin_b, "GET", PROFILES, None).await;
    assert_eq!(list["total"], 0);
    for (method, uri, body) in [
        ("GET", format!("{SEGMENTS}/{id}"), None),
        ("GET", format!("{PROFILES}/{id}"), None),
        (
            "PUT",
            format!("{SEGMENTS}/{id}"),
            Some(
                json!({"version": 1, "vlan_id": 99, "filter_ids": [], "rank": 1, "enabled": true}),
            ),
        ),
        ("DELETE", format!("{SEGMENTS}/{id}?version=1"), None),
        (
            "PUT",
            format!("{PROFILES}/{id}"),
            Some(
                json!({"version": 1, "segment_version": 1, "profile": {"session_timeout_secs": 600}}),
            ),
        ),
        ("DELETE", format!("{PROFILES}/{id}?version=1"), None),
    ] {
        let (status, err) = call(&app, &admin_b, method, &uri, body).await;
        assert_eq!(status, 404, "{method} {uri}: {err}");
    }
    // A profile for A's segment through B's token.
    let (status, _) = call(
        &app,
        &admin_b,
        "POST",
        PROFILES,
        Some(profile_body(&segment, 1800, Some("corp-acl"))),
    )
    .await;
    assert_eq!(status, 404);

    // A's rows are untouched.
    let (_, got) = call(&app, &admin_a, "GET", &format!("{SEGMENTS}/{id}"), None).await;
    assert_eq!(
        (got["vlan_id"].clone(), got["version"].clone()),
        (json!(10), json!(1))
    );
    let (_, got) = call(&app, &admin_a, "GET", &format!("{PROFILES}/{id}"), None).await;
    assert_eq!(got["version"], 1);

    // The same names and VLANs are free in B: nothing collides across tenants.
    let b_segment = make_segment(&app, &admin_b, "corp", 10, &[]).await;
    assert_ne!(b_segment["id"], segment["id"]);
    assert_eq!(b_segment["tenant_id"], w.other_tenant.to_string());

    // B's refused writes are B's audit rows.
    let in_b = w
        .audit_in(w.other_tenant, "network_segment.write_refused")
        .await;
    assert_eq!(in_b.len(), 2, "{in_b:?}");
    assert!(in_b.iter().all(|r| r.metadata["rule"] == "not_found"));
    assert!(w.audit("network_segment.write_refused").await.is_empty());
}

// ---------------------------------------------------------------------------
// Rate-limit buckets (plan §7 rule 6), pinned
// ---------------------------------------------------------------------------

/// Each of the six write routes has a bucket of its own under
/// `network_admin_per_min`: past the allowance a route answers `429`, and a
/// sibling's bucket is untouched. Reads are not limited.
#[actix_rt::test]
async fn every_write_route_has_its_own_bucket_and_reads_are_not_limited() {
    let w = World::new().await;
    let admin = w.netadmin(w.tenant).await;
    let limits = RateLimitConfig {
        network_admin_per_min: 1,
        ..RateLimitConfig::default()
    };
    let app = app!(w, limits);
    let id = Uuid::new_v4();

    let routes: Vec<(&str, String, Option<Value>)> = vec![
        (
            "POST",
            SEGMENTS.to_owned(),
            Some(segment_body("corp", 10, 10, &[])),
        ),
        (
            "PUT",
            format!("{SEGMENTS}/{id}"),
            Some(
                json!({"version": 1, "vlan_id": 11, "filter_ids": [], "rank": 1, "enabled": true}),
            ),
        ),
        ("DELETE", format!("{SEGMENTS}/{id}?version=1"), None),
        (
            "POST",
            PROFILES.to_owned(),
            Some(json!({
                "segment_id": id, "segment_version": 1,
                "profile": {"session_timeout_secs": 600},
            })),
        ),
        (
            "PUT",
            format!("{PROFILES}/{id}"),
            Some(
                json!({"version": 1, "segment_version": 1, "profile": {"session_timeout_secs": 600}}),
            ),
        ),
        ("DELETE", format!("{PROFILES}/{id}?version=1"), None),
    ];
    for (method, uri, body) in &routes {
        let (first, _) = call(&app, &admin, method, uri, body.clone()).await;
        assert_ne!(
            first, 429,
            "{method} {uri}: the first write is within the allowance"
        );
        let (second, _) = call(&app, &admin, method, uri, body.clone()).await;
        assert_eq!(second, 429, "{method} {uri}: its own bucket is spent");
    }
    // Reads are not limited.
    for _ in 0..4 {
        for uri in [SEGMENTS.to_owned(), PROFILES.to_owned()] {
            let (status, _) = call(&app, &admin, "GET", &uri, None).await;
            assert_eq!(status, 200, "{uri}");
        }
    }
}

/// The bucket names the routes use are distinct and carry the `network_`
/// prefix: the shared registry keys its counters by name, so two routes with
/// one name would share an allowance, and the merge's bucket-name test reads
/// the prefix.
#[actix_rt::test]
async fn the_buckets_are_named_network_and_are_distinct() {
    let source = include_str!("../src/server.rs");
    let mut names: Vec<&str> = source
        .match_indices("\"network_")
        .map(|(at, _)| {
            let rest = &source[at + 1..];
            &rest[..rest.find('"').unwrap()]
        })
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "network_profile_create",
            "network_profile_delete",
            "network_profile_replace",
            "network_segment_create",
            "network_segment_delete",
            "network_segment_replace",
        ]
    );
}

#[actix_rt::test]
async fn the_shipped_bucket_is_thirty_a_minute() {
    assert_eq!(RateLimitConfig::default().network_admin_per_min, 30);
}

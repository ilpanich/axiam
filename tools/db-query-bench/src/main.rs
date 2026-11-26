//! Per-query SurrealDB **server** CPU and wall-clock latency for AXIAM's hot
//! paths, against a running server whose PID is sampled.
//!
//! See `claude_dev/db-query-optimization.md` for the method and the results.
//! Figures from this tool are relative: they compare query shapes and server
//! versions on one machine. They are not benchmark results.
//!
//! ```text
//! db-query-bench seed                      # DEFINE NS/DB, migrate, seed, write fixture
//! db-query-bench bench  [filter]           # every scenario, TSV on stdout
//! db-query-bench explain                   # EXPLAIN of every hot statement
//! db-query-bench audit-shed <rows/s> <s>   # the real audit worker against the server
//! ```
//!
//! Environment: `SURREAL_ADDR` (default `127.0.0.1:8001`), `SURREAL_PID`
//! (required for `bench`), `FIXTURE` (default `fixture.json`), `OPS`
//! (default 4000), `CONC` (default 16).

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::group::CreateGroup;
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::session::{Amr, CreateSession};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AuditLogRepository, GroupRepository, OAuth2ClientRepository, OrganizationRepository,
    PermissionRepository, ResourceRepository, RoleRepository, SessionRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealSessionRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use chrono::Utc;
use serde_json::{Value as Json, json};
use surrealdb::engine::remote::http::Http;
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Root;
use surrealdb::{Connection, Surreal};
use surrealdb_types::{RecordId, SurrealValue};
use uuid::Uuid;

const NS: &str = "axiam";
const DB: &str = "main";

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Fixture {
    tenant_id: Uuid,
    user_id: Uuid,
    session_ids: Vec<Uuid>,
    client_id: String,
    resource_id: Uuid,
}

impl Fixture {
    fn to_json(&self) -> Json {
        json!({
            "tenant_id": self.tenant_id, "user_id": self.user_id,
            "session_ids": self.session_ids, "client_id": self.client_id,
            "resource_id": self.resource_id,
        })
    }
    fn from_json(v: &Json) -> Result<Self> {
        let uuid = |k: &str| -> Result<Uuid> {
            Ok(v[k]
                .as_str()
                .ok_or_else(|| anyhow!("fixture: {k}"))?
                .parse()?)
        };
        Ok(Self {
            tenant_id: uuid("tenant_id")?,
            user_id: uuid("user_id")?,
            session_ids: v["session_ids"]
                .as_array()
                .ok_or_else(|| anyhow!("fixture: session_ids"))?
                .iter()
                .map(|s| s.as_str().unwrap().parse().unwrap())
                .collect(),
            client_id: v["client_id"].as_str().unwrap().to_owned(),
            resource_id: uuid("resource_id")?,
        })
    }
}

fn env(k: &str, d: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| d.to_owned())
}

async fn http() -> Result<Surreal<surrealdb::engine::remote::http::Client>> {
    let db = Surreal::new::<Http>(env("SURREAL_ADDR", "127.0.0.1:8001")).await?;
    db.signin(Root {
        username: "root".into(),
        password: "root".into(),
    })
    .await?;
    db.use_ns(NS).use_db(DB).await?;
    Ok(db)
}

async fn ws() -> Result<Surreal<surrealdb::engine::remote::ws::Client>> {
    let db = Surreal::new::<Ws>(env("SURREAL_ADDR", "127.0.0.1:8001")).await?;
    db.signin(Root {
        username: "root".into(),
        password: "root".into(),
    })
    .await?;
    db.use_ns(NS).use_db(DB).await?;
    Ok(db)
}

fn random_hash() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn new_session(tenant_id: Uuid, user_id: Uuid, token_hash: String) -> CreateSession {
    CreateSession {
        tenant_id,
        user_id,
        token_hash,
        ip_address: Some("10.0.0.1".into()),
        user_agent: Some("k6/0.50".into()),
        expires_at: Utc::now() + chrono::Duration::hours(8),
        authenticated_at: Utc::now(),
        amr: vec![Amr::Pwd],
        browser_token_hash: None,
        lineage_id: None,
    }
}

fn audit_entry(tenant_id: Uuid, actor: Uuid, i: usize) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id,
        actor_id: actor,
        actor_type: ActorType::User,
        action: "http.request".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: Some("10.0.0.1".into()),
        metadata: Some(json!({
            "method": "GET", "path": "/oauth2/userinfo", "status": 200,
            "authenticated": true, "seq": i,
        })),
    }
}

/// An `audit_log` row as the batched `INSERT` binds it. `None` fields are
/// omitted rather than sent as `null`: `option<string>` accepts NONE, not NULL.
fn audit_row_json(e: &CreateAuditLogEntry) -> Json {
    let mut m = serde_json::Map::new();
    m.insert("id".into(), json!(Uuid::new_v4().to_string()));
    m.insert("tenant_id".into(), json!(e.tenant_id.to_string()));
    m.insert("actor_id".into(), json!(e.actor_id.to_string()));
    m.insert("actor_type".into(), json!("User"));
    m.insert("action".into(), json!(e.action));
    m.insert("outcome".into(), json!("Success"));
    if let Some(ip) = &e.ip_address {
        m.insert("ip_address".into(), json!(ip));
    }
    m.insert("metadata".into(), e.metadata.clone().unwrap_or(json!({})));
    Json::Object(m)
}

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

async fn seed() -> Result<()> {
    let db = Surreal::new::<Http>(env("SURREAL_ADDR", "127.0.0.1:8001")).await?;
    db.signin(Root {
        username: "root".into(),
        password: "root".into(),
    })
    .await?;
    db.query(format!(
        "DEFINE NAMESPACE IF NOT EXISTS {NS}; USE NS {NS}; DEFINE DATABASE IF NOT EXISTS {DB};"
    ))
    .await?
    .check()?;
    db.use_ns(NS).use_db(DB).await?;
    let t0 = Instant::now();
    axiam_db::run_migrations(&db).await?;
    eprintln!("migrations: {:?}", t0.elapsed());

    let users_n: usize = env("SEED_USERS", "2000").parse()?;
    let sessions_n: usize = env("SEED_SESSIONS", "50000").parse()?;
    let audit_n: usize = env("SEED_AUDIT", "300000").parse()?;
    let resources_n: usize = env("SEED_RESOURCES", "2000").parse()?;

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Bench Org".into(),
            slug: "bench-org".into(),
            metadata: None,
        })
        .await?;
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let mut tenants = Vec::new();
    for i in 0..3 {
        tenants.push(
            tenant_repo
                .create(CreateTenant {
                    organization_id: org.id,
                    kind: TenantKind::Standard,
                    name: format!("Tenant {i}"),
                    slug: format!("tenant-{i}"),
                    metadata: None,
                })
                .await?,
        );
    }
    let tenant_id = tenants[0].id;

    // Users: Argon2id runs in the repository, so create them in parallel.
    let t0 = Instant::now();
    let user_repo = Arc::new(SurrealUserRepository::new(db.clone()));
    let mut user_ids = Vec::with_capacity(users_n);
    for chunk in (0..users_n).collect::<Vec<_>>().chunks(64) {
        let futs = chunk.iter().map(|&i| {
            let repo = Arc::clone(&user_repo);
            let t = tenants[i % 3].id;
            async move {
                repo.create(CreateUser {
                    tenant_id: t,
                    username: format!("user{i}"),
                    email: format!("user{i}@bench.dev"),
                    password: format!("Fx1!{}", Uuid::new_v4().simple()),
                    metadata: None,
                })
                .await
            }
        });
        for u in futures::future::join_all(futs).await {
            user_ids.push(u?);
        }
    }
    let bench_users: Vec<_> = user_ids
        .iter()
        .filter(|u| u.tenant_id == tenant_id)
        .collect();
    let user_id = bench_users[0].id;
    eprintln!("users: {} in {:?}", user_ids.len(), t0.elapsed());

    // Sessions.
    let t0 = Instant::now();
    let session_repo = Arc::new(SurrealSessionRepository::new(db.clone()));
    let mut session_ids = Vec::new();
    for chunk in (0..sessions_n).collect::<Vec<_>>().chunks(256) {
        let futs = chunk.iter().map(|&i| {
            let repo = Arc::clone(&session_repo);
            let u = &user_ids[i % user_ids.len()];
            let s = new_session(u.tenant_id, u.id, random_hash());
            async move { repo.create(s).await }
        });
        for s in futures::future::join_all(futs).await {
            let s = s?;
            if s.user_id == user_id && session_ids.len() < 256 {
                session_ids.push(s.id);
            }
        }
    }
    // The bench user's own sessions (what REST userinfo checks).
    for _ in 0..64 {
        session_ids.push(
            session_repo
                .create(new_session(tenant_id, user_id, random_hash()))
                .await?
                .id,
        );
    }
    eprintln!("sessions: {sessions_n} in {:?}", t0.elapsed());

    // Resources: 40 roots, each with a chain root -> mid -> leaf, plus flat leaves.
    let t0 = Instant::now();
    let res_repo = SurrealResourceRepository::new(db.clone());
    let mut resources = Vec::new();
    let mut bench_resource = None;
    let mut bench_parent = None;
    let mut i = 0;
    while resources.len() < resources_n {
        let root = res_repo
            .create(CreateResource {
                tenant_id,
                name: format!("root-{i}"),
                resource_type: "service".into(),
                parent_id: None,
                metadata: None,
            })
            .await?;
        let mid = res_repo
            .create(CreateResource {
                tenant_id,
                name: format!("mid-{i}"),
                resource_type: "api".into(),
                parent_id: Some(root.id),
                metadata: None,
            })
            .await?;
        resources.push(root.id);
        resources.push(mid.id);
        for j in 0..48 {
            let leaf = res_repo
                .create(CreateResource {
                    tenant_id,
                    name: format!("leaf-{i}-{j}"),
                    resource_type: "endpoint".into(),
                    parent_id: Some(mid.id),
                    metadata: None,
                })
                .await?;
            resources.push(leaf.id);
            if bench_resource.is_none() {
                bench_resource = Some(leaf.id);
                bench_parent = Some(mid.id);
            }
        }
        i += 1;
    }
    let resource_id = bench_resource.unwrap();
    eprintln!("resources: {} in {:?}", resources.len(), t0.elapsed());

    // Permissions, roles, grants.
    let t0 = Instant::now();
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let role_repo = SurrealRoleRepository::new(db.clone());
    let mut perms = Vec::new();
    for a in 0..100 {
        let action = if a == 0 {
            "read".to_owned()
        } else {
            format!("action{a}")
        };
        perms.push(
            perm_repo
                .create(CreatePermission {
                    tenant_id,
                    action,
                    description: "bench".into(),
                })
                .await?
                .id,
        );
    }
    let mut roles = Vec::new();
    for r in 0..100 {
        let role = role_repo
            .create(CreateRole {
                tenant_id,
                name: format!("role{r}"),
                description: "bench".into(),
                is_global: r % 2 == 0,
            })
            .await?;
        for k in 0..5 {
            perm_repo
                .grant_to_role(tenant_id, role.id, perms[(r * 7 + k * 13) % perms.len()])
                .await?;
        }
        roles.push(role.id);
    }
    // Every bench-tenant user: two assignments.
    for (n, u) in bench_users.iter().enumerate() {
        role_repo
            .assign_to_user(tenant_id, u.id, roles[n % 100], AssignmentScope::global())
            .await?;
        role_repo
            .assign_to_user(
                tenant_id,
                u.id,
                roles[(n + 37) % 100],
                AssignmentScope::resource(resources[(n * 11) % resources.len()]),
            )
            .await?;
    }
    // The benchmark subject: the shape seed.sh gives it — a role granting
    // "read" scoped to the benchmark resource — plus two global roles, one
    // role on the resource's parent, one on an unrelated resource and one
    // through a group.
    let read_role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "bench-reader".into(),
            description: "bench".into(),
            is_global: false,
        })
        .await?;
    perm_repo
        .grant_to_role(tenant_id, read_role.id, perms[0])
        .await?;
    role_repo
        .assign_to_user(
            tenant_id,
            user_id,
            read_role.id,
            AssignmentScope::resource(resource_id),
        )
        .await?;
    for (k, scope) in [
        AssignmentScope::global(),
        AssignmentScope::global(),
        AssignmentScope::resource(bench_parent.unwrap()),
        AssignmentScope::resource(resources[resources.len() - 1]),
    ]
    .into_iter()
    .enumerate()
    {
        // Skip the role index already assigned above (two edges with the same
        // (in, out) are refused by `idx_has_role_unique`).
        role_repo
            .assign_to_user(tenant_id, user_id, roles[(k * 17 + 5) % 100], scope)
            .await?;
    }
    let group_repo = SurrealGroupRepository::new(db.clone());
    let group = group_repo
        .create(CreateGroup {
            tenant_id,
            name: "bench-group".into(),
            description: "bench".into(),
            metadata: None,
        })
        .await?;
    group_repo.add_member(tenant_id, user_id, group.id).await?;
    role_repo
        .assign_to_group(tenant_id, group.id, roles[99], AssignmentScope::global())
        .await?;
    eprintln!("rbac: {:?}", t0.elapsed());

    // OAuth2 clients.
    let client_repo = SurrealOAuth2ClientRepository::new(db.clone());
    let mut client_id = String::new();
    for c in 0..200 {
        let (client, _secret) = client_repo
            .create(CreateOAuth2Client {
                tenant_id: tenants[c % 3].id,
                name: format!("client{c}"),
                redirect_uris: vec!["http://127.0.0.1/callback".into()],
                grant_types: vec!["client_credentials".into(), "refresh_token".into()],
                scopes: vec!["openid".into()],
                post_logout_redirect_uris: Vec::new(),
                backchannel_logout_uri: None,
                require_par: false,
                profile: ClientProfile::Standard,
                token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
                tls_client_auth_subject_dn: None,
                tls_client_auth_san_dns: None,
                tls_client_auth_san_uri: None,
                self_signed_tls_client_auth_thumbprints: Vec::new(),
                tls_client_certificate_bound_access_tokens: false,
                jwks: None,
                jwks_uri: None,
                dpop_bound_access_tokens: false,
                dpop_require_nonce: false,
                authn_request_params: AuthnRequestParamsMode::Ignore,
                browser_sso: false,
                allowed_resources: Vec::new(),
                managed_by: ManagedBy::Admin,
                ciba: Default::default(),
                default_idp: None,
            })
            .await?;
        if client.tenant_id == tenant_id && client_id.is_empty() {
            client_id = client.client_id.clone();
        }
    }

    // Audit log: the bulk of a long benchmark's database.
    let t0 = Instant::now();
    let mut done = 0;
    while done < audit_n {
        let n = 1000.min(audit_n - done);
        let rows: Vec<Json> = (0..n)
            .map(|k| audit_row_json(&audit_entry(tenants[(done + k) % 3].id, user_id, done + k)))
            .collect();
        db.query("INSERT INTO audit_log $rows RETURN NONE")
            .bind(("rows", rows))
            .await?
            .check()?;
        done += n;
    }
    eprintln!("audit_log: {audit_n} in {:?}", t0.elapsed());

    let fx = Fixture {
        tenant_id,
        user_id,
        session_ids,
        client_id,
        resource_id,
    };
    std::fs::write(
        env("FIXTURE", "fixture.json"),
        serde_json::to_vec_pretty(&fx.to_json())?,
    )?;

    let mut counts = db
        .query(
            "RETURN [count(SELECT 1 FROM user), count(SELECT 1 FROM session), \
             count(SELECT 1 FROM audit_log), count(SELECT 1 FROM resource), \
             count(SELECT 1 FROM has_role), count(SELECT 1 FROM grants)]",
        )
        .await?;
    let c: surrealdb::types::Value = counts.take(0)?;
    eprintln!("table sizes [user, session, audit_log, resource, has_role, grants]: {c:?}");
    Ok(())
}

// ---------------------------------------------------------------------------
// CPU sampling
// ---------------------------------------------------------------------------

/// Total on-CPU nanoseconds of every thread of `pid` (`/proc/<pid>/task/*/schedstat`).
fn cpu_ns(pid: u32) -> u64 {
    let mut total = 0u64;
    if let Ok(dir) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for t in dir.flatten() {
            if let Ok(s) = std::fs::read_to_string(t.path().join("schedstat"))
                && let Some(ns) = s.split_whitespace().next()
            {
                total += ns.parse::<u64>().unwrap_or(0);
            }
        }
    }
    total
}

#[derive(Debug)]
struct Sample {
    ops: usize,
    wall: Duration,
    cpu_ns: u64,
    lat_us: Vec<u64>,
}

async fn run<F, Fut>(pid: u32, conc: usize, ops: usize, f: Arc<F>) -> Result<Sample>
where
    F: Fn(usize) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send,
{
    // Warm-up, not measured.
    for i in 0..(ops / 20).max(20) {
        f(usize::MAX - i).await?;
    }
    let next = Arc::new(AtomicUsize::new(0));
    let cpu0 = cpu_ns(pid);
    let t0 = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..conc {
        let f = Arc::clone(&f);
        let next = Arc::clone(&next);
        handles.push(tokio::spawn(async move {
            let mut lat = Vec::new();
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= ops {
                    break;
                }
                let s = Instant::now();
                f(i).await?;
                lat.push(s.elapsed().as_micros() as u64);
            }
            Ok::<_, anyhow::Error>(lat)
        }));
    }
    let mut lat_us = Vec::with_capacity(ops);
    for h in handles {
        lat_us.extend(h.await??);
    }
    let wall = t0.elapsed();
    let cpu = cpu_ns(pid) - cpu0;
    lat_us.sort_unstable();
    Ok(Sample {
        ops,
        wall,
        cpu_ns: cpu,
        lat_us,
    })
}

fn pct(v: &[u64], p: f64) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v[((v.len() as f64 - 1.0) * p) as usize]
}

struct Ctx<C: Connection> {
    db: Surreal<C>,
    fx: Fixture,
    users: SurrealUserRepository<C>,
    sessions: SurrealSessionRepository<C>,
    tenants: SurrealTenantRepository<C>,
    clients: SurrealOAuth2ClientRepository<C>,
    roles: SurrealRoleRepository<C>,
    resources: SurrealResourceRepository<C>,
    perms: SurrealPermissionRepository<C>,
    audit: SurrealAuditLogRepository<C>,
    /// Pre-created sessions the refresh scenario consumes, by token hash.
    refresh_pool: std::sync::Mutex<Vec<String>>,
}

impl<C: Connection> Ctx<C> {
    fn new(db: Surreal<C>, fx: Fixture) -> Self {
        Self {
            users: SurrealUserRepository::new(db.clone()),
            sessions: SurrealSessionRepository::new(db.clone()),
            tenants: SurrealTenantRepository::new(db.clone()),
            clients: SurrealOAuth2ClientRepository::new(db.clone()),
            roles: SurrealRoleRepository::new(db.clone()),
            resources: SurrealResourceRepository::new(db.clone()),
            perms: SurrealPermissionRepository::new(db.clone()),
            audit: SurrealAuditLogRepository::new(db.clone()),
            db,
            fx,
            refresh_pool: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn session(&self, i: usize) -> Uuid {
        self.fx.session_ids[i % self.fx.session_ids.len()]
    }
}

// --- the statements of the merged (one-round-trip) prototypes ---------------

const SESSION_BY_ID: &str =
    "SELECT * FROM type::record('session', $sid) WHERE tenant_id = $tenant_id";
const USER_BY_ID: &str = "SELECT * FROM type::record('user', $uid) WHERE tenant_id = $tenant_id";
const TENANT_BY_ID: &str =
    "SELECT * FROM type::record('tenant', $tenant_id) WHERE deleted_at = NONE";
const CLIENT_BY_CLIENT_ID: &str = "SELECT meta::id(id) AS record_id, * FROM oauth2_client \
     WHERE tenant_id = $tenant_id AND client_id = $client_id";

const ROLE_ASSIGNMENTS: &str = "LET $subject_records = [\
         type::record('user', $user_id), type::record('service_account', $user_id)]; \
     LET $direct = (SELECT meta::id(out.id) AS record_id, out.tenant_id AS tenant_id, \
            out.name AS name, out.description AS description, out.is_global AS is_global, \
            out.created_at AS created_at, out.updated_at AS updated_at, \
            resource_id, tenant_scope, inherit, out AS role \
         FROM has_role WHERE in IN $subject_records AND out.tenant_id = $tenant_id); \
     LET $group_records = (SELECT VALUE out FROM member_of \
         WHERE in IN $subject_records AND out.tenant_id = $tenant_id); \
     LET $inherited = (SELECT meta::id(out.id) AS record_id, out.tenant_id AS tenant_id, \
            out.name AS name, out.description AS description, out.is_global AS is_global, \
            out.created_at AS created_at, out.updated_at AS updated_at, \
            resource_id, tenant_scope, inherit, out AS role \
         FROM has_role WHERE in IN $group_records AND out.tenant_id = $tenant_id);";

/// The ancestor walk of the hand-written prototypes (`*.merged`, `*.two_rt`,
/// `*.one_rt`). Depth 32 here, 50 in the product (`ancestors_sql` in
/// axiam-db); the benchmark resource is two levels deep, so the cap never
/// binds. Measurements of the product's own statement use the repositories.
fn ancestors_sql() -> String {
    "SELECT meta::id(id) AS record_id, tenant_id, name, resource_type, \
            parent_id, metadata, created_at, updated_at \
     FROM array::flatten(type::record('resource', $rid).{..32+path}(\
         ->child_of->(resource WHERE tenant_id = $tenant_id)));"
        .to_owned()
}

const GRANTS_FOR: &str = "SELECT meta::id(in) AS role_id, meta::id(out.id) AS record_id, \
         out.tenant_id AS tenant_id, out.action AS action, out.description AS description, \
         out.created_at AS created_at, out.updated_at AS updated_at, scope_ids, effect \
     FROM grants WHERE in IN $role_records AND out.tenant_id = $tenant_id";

type Op<C> = Arc<
    dyn Fn(Arc<Ctx<C>>, usize) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync,
>;

fn mk<C, F, Fut>(f: F) -> Op<C>
where
    C: Connection,
    F: Fn(Arc<Ctx<C>>, usize) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    Arc::new(move |c, i| Box::pin(f(c, i)))
}

macro_rules! op {
    (|$ctx:ident, $i:ident| $body:block) => {
        mk::<C, _, _>(move |$ctx: Arc<Ctx<C>>, $i: usize| async move { $body })
    };
}

fn applicable_roles(
    assignments: &[axiam_core::models::role::RoleAssignment],
    resource: Uuid,
    ancestors: &HashSet<Uuid>,
) -> Vec<Uuid> {
    let mut seen = HashSet::new();
    assignments
        .iter()
        .filter(|a| match a.resource_id {
            None => true,
            Some(r) => r == resource || ancestors.contains(&r),
        })
        .filter(|a| seen.insert(a.role.id))
        .map(|a| a.role.id)
        .collect()
}

fn scenarios<C: Connection>() -> Vec<(&'static str, Op<C>)> {
    let mut v: Vec<(&'static str, Op<C>)> = Vec::new();

    v.push((
        "rt.return1",
        op!(|c, _i| {
            c.db.query("RETURN 1").await?.check()?;
            Ok(())
        }),
    ));

    // -- single statements, through their repository method ---------------
    v.push((
        "stmt.session_get_by_id",
        op!(|c, i| {
            c.sessions.get_by_id(c.fx.tenant_id, c.session(i)).await?;
            Ok(())
        }),
    ));
    v.push((
        "stmt.user_get_by_id",
        op!(|c, _i| {
            c.users.get_by_id(c.fx.tenant_id, c.fx.user_id).await?;
            Ok(())
        }),
    ));
    // (c) query shape: the record id bound as a value instead of built by
    // `type::record(...)` in the statement.
    v.push((
        "shape.user_by_bound_record_id",
        op!(|c, _i| {
            let mut r =
                c.db.query("SELECT * FROM $rid WHERE tenant_id = $tenant_id")
                    .bind(("rid", RecordId::new("user", c.fx.user_id.to_string())))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.user_narrow_projection",
        op!(|c, _i| {
            let mut r =
                c.db.query(
                    "SELECT tenant_id, status, username, email FROM type::record('user', $uid) \
                 WHERE tenant_id = $tenant_id",
                )
                .bind(("uid", c.fx.user_id.to_string()))
                .bind(("tenant_id", c.fx.tenant_id.to_string()))
                .await?
                .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.tenant_by_type_record",
        op!(|c, _i| {
            let mut r =
                c.db.query(TENANT_BY_ID)
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    // The tenant predicate checked in the application instead of in a WHERE
    // on the record fetch.
    v.push((
        "shape.user_no_where",
        op!(|c, _i| {
            let mut r =
                c.db.query("SELECT * FROM type::record('user', $uid)")
                    .bind(("uid", c.fx.user_id.to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.session_no_where",
        op!(|c, i| {
            let mut r =
                c.db.query("SELECT * FROM type::record('session', $sid)")
                    .bind(("sid", c.session(i).to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.session_with_where",
        op!(|c, i| {
            let mut r =
                c.db.query(SESSION_BY_ID)
                    .bind(("sid", c.session(i).to_string()))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.tenant_no_where",
        op!(|c, _i| {
            let mut r =
                c.db.query("SELECT * FROM type::record('tenant', $tenant_id)")
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.user_where_literal",
        op!(|c, _i| {
            let mut r =
                c.db.query(format!(
                    "SELECT * FROM type::record('user', $uid) WHERE tenant_id = '{}'",
                    c.fx.tenant_id
                ))
                .bind(("uid", c.fx.user_id.to_string()))
                .await?
                .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.user_where_in_let",
        op!(|c, _i| {
            let mut r =
                c.db.query(
                    "LET $row = (SELECT * FROM ONLY type::record('user', $uid)); \
                 RETURN IF $row.tenant_id = $tenant_id THEN [$row] ELSE [] END;",
                )
                .bind(("uid", c.fx.user_id.to_string()))
                .bind(("tenant_id", c.fx.tenant_id.to_string()))
                .await?
                .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(1)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.user_where_param_other_field",
        op!(|c, _i| {
            // A parameter in the predicate, on a field other than tenant_id.
            let mut r =
                c.db.query("SELECT * FROM type::record('user', $uid) WHERE deleted_at = $none")
                    .bind(("uid", c.fx.user_id.to_string()))
                    .bind(("none", None::<String>))
                    .await?
                    .check()?;
            let _v: Vec<surrealdb::types::Value> = r.take(0)?;
            Ok(())
        }),
    ));
    v.push((
        "shape.params_1_unused",
        op!(|c, _i| {
            c.db.query("RETURN 1")
                .bind(("x", "a".to_string()))
                .await?
                .check()?;
            Ok(())
        }),
    ));
    v.push((
        "shape.params_2_unused",
        op!(|c, _i| {
            c.db.query("RETURN 1")
                .bind(("x", "a".to_string()))
                .bind(("y", "b".to_string()))
                .await?
                .check()?;
            Ok(())
        }),
    ));
    v.push((
        "shape.params_4_unused",
        op!(|c, _i| {
            c.db.query("RETURN 1")
                .bind(("x", "a".to_string()))
                .bind(("y", "b".to_string()))
                .bind(("z", "c".to_string()))
                .bind(("w", "d".to_string()))
                .await?
                .check()?;
            Ok(())
        }),
    ));
    v.push((
        "shape.params_0",
        op!(|c, _i| {
            c.db.query("RETURN 1").await?.check()?;
            Ok(())
        }),
    ));
    // Query text varies per request (a different literal session id every
    // time), so a plan cache keyed on the text cannot help it.
    v.push((
        "shape.session_where_literal_varying",
        op!(|c, i| {
            let mut r =
                c.db.query(format!(
                    "SELECT * FROM type::record('session', '{}') WHERE tenant_id = '{}'",
                    c.session(i),
                    c.fx.tenant_id
                ))
                .await?
                .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.session_where_param_varying",
        op!(|c, i| {
            let mut r =
                c.db.query(SESSION_BY_ID)
                    .bind(("sid", c.session(i).to_string()))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.session_where_param_cast",
        op!(|c, i| {
            let mut r =
                c.db.query(
                    "SELECT * FROM type::record('session', $sid) \
                 WHERE tenant_id = <string> $tenant_id",
                )
                .bind(("sid", c.session(i).to_string()))
                .bind(("tenant_id", c.fx.tenant_id.to_string()))
                .await?
                .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "shape.user_by_type_record",
        op!(|c, _i| {
            let mut r =
                c.db.query(USER_BY_ID)
                    .bind(("uid", c.fx.user_id.to_string()))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let v: Vec<surrealdb::types::Value> = r.take(0)?;
            if v.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "stmt.tenant_get_by_id",
        op!(|c, _i| {
            c.tenants.get_by_id(c.fx.tenant_id).await?;
            Ok(())
        }),
    ));
    v.push((
        "stmt.client_get_by_client_id",
        op!(|c, _i| {
            c.clients
                .get_by_client_id(c.fx.tenant_id, &c.fx.client_id)
                .await?;
            Ok(())
        }),
    ));
    v.push((
        "stmt.role_assignments",
        op!(|c, _i| {
            c.roles
                .get_user_role_assignments(c.fx.tenant_id, c.fx.user_id)
                .await?;
            Ok(())
        }),
    ));
    v.push((
        "stmt.ancestors",
        op!(|c, _i| {
            c.resources
                .get_ancestors(c.fx.tenant_id, c.fx.resource_id)
                .await?;
            Ok(())
        }),
    ));
    v.push((
        "stmt.grants_for_roles",
        op!(|c, _i| {
            let roles = applicable_ids_cached(&c).await?;
            c.perms
                .get_role_permission_grants_for_roles(c.fx.tenant_id, &roles)
                .await?;
            Ok(())
        }),
    ));
    v.push((
        "stmt.session_create",
        op!(|c, _i| {
            c.sessions
                .create(new_session(c.fx.tenant_id, c.fx.user_id, random_hash()))
                .await?;
            Ok(())
        }),
    ));
    v.push((
        "stmt.session_consume",
        op!(|c, _i| {
            let hash = c
                .refresh_pool
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| anyhow!("pool empty"))?;
            c.sessions
                .consume_by_token_hash(c.fx.tenant_id, &hash)
                .await?
                .ok_or_else(|| anyhow!("not consumed"))?;
            Ok(())
        }),
    ));
    // REST authorization as this branch runs it: the session check (tenant
    // checked in the repository) and the one-round-trip read.
    // A and B as implemented: one round trip each.
    v.push((
        "client_credentials.after",
        op!(|c, _i| {
            let l = c
                .clients
                .get_by_client_id_with_context(c.fx.tenant_id, &c.fx.client_id, None)
                .await?;
            l.tenant.ok_or_else(|| anyhow!("no tenant"))??;
            Ok(())
        }),
    ));
    v.push((
        "introspection.after",
        op!(|c, _i| {
            let l = c
                .clients
                .get_by_client_id_with_context(c.fx.tenant_id, &c.fx.client_id, Some(c.fx.user_id))
                .await?;
            l.tenant.ok_or_else(|| anyhow!("no tenant"))??;
            l.user.ok_or_else(|| anyhow!("no user"))??;
            Ok(())
        }),
    ));
    v.push((
        "userinfo_rest.after",
        op!(|c, i| {
            let (active, account) = c
                .sessions
                .is_session_active_checked_with_account(c.fx.tenant_id, c.session(i), c.fx.user_id)
                .await;
            if !active {
                return Err(anyhow!("session inactive"));
            }
            account.ok_or_else(|| anyhow!("no account"))??;
            Ok(())
        }),
    ));
    v.push((
        "authz_rest.after",
        op!(|c, i| {
            if !c
                .sessions
                .is_session_active_checked(c.fx.tenant_id, c.session(i))
                .await
            {
                return Err(anyhow!("session inactive"));
            }
            let inputs = c
                .roles
                .authorization_inputs(
                    c.fx.tenant_id,
                    c.fx.user_id,
                    c.fx.tenant_id,
                    c.fx.resource_id,
                )
                .await?
                .ok_or_else(|| anyhow!("not offered"))?;
            if inputs.grants_by_role.is_empty() {
                return Err(anyhow!("no grants"));
            }
            Ok(())
        }),
    ));
    v.push((
        "authz_grpc.repo_one_rt",
        op!(|c, _i| {
            let inputs = c
                .roles
                .authorization_inputs(
                    c.fx.tenant_id,
                    c.fx.user_id,
                    c.fx.tenant_id,
                    c.fx.resource_id,
                )
                .await?
                .ok_or_else(|| anyhow!("not offered"))?;
            if inputs.grants_by_role.is_empty() {
                return Err(anyhow!("no grants"));
            }
            Ok(())
        }),
    ));

    // -- userinfo ------------------------------------------------------------
    v.push((
        "userinfo_grpc.cur",
        op!(|c, _i| {
            c.users.get_by_id(c.fx.tenant_id, c.fx.user_id).await?;
            Ok(())
        }),
    ));
    v.push((
        "userinfo_rest.cur",
        op!(|c, i| {
            if !c
                .sessions
                .is_session_active_checked(c.fx.tenant_id, c.session(i))
                .await
            {
                return Err(anyhow!("session inactive"));
            }
            c.users.get_by_id(c.fx.tenant_id, c.fx.user_id).await?;
            Ok(())
        }),
    ));
    v.push((
        "userinfo_rest.merged",
        op!(|c, i| {
            let mut r =
                c.db.query(format!("{SESSION_BY_ID}; {USER_BY_ID};"))
                    .bind(("sid", c.session(i).to_string()))
                    .bind(("uid", c.fx.user_id.to_string()))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let s: Vec<surrealdb::types::Value> = r.take(0)?;
            let u: Vec<surrealdb::types::Value> = r.take(1)?;
            if s.is_empty() || u.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));

    // -- client credentials / introspection ----------------------------------
    v.push((
        "client_credentials.cur",
        op!(|c, _i| {
            c.clients
                .get_by_client_id(c.fx.tenant_id, &c.fx.client_id)
                .await?;
            c.tenants.get_by_id(c.fx.tenant_id).await?;
            Ok(())
        }),
    ));
    v.push((
        "client_credentials.merged",
        op!(|c, _i| {
            let mut r =
                c.db.query(format!("{CLIENT_BY_CLIENT_ID}; {TENANT_BY_ID};"))
                    .bind(("client_id", c.fx.client_id.clone()))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let a: Vec<surrealdb::types::Value> = r.take(0)?;
            let b: Vec<surrealdb::types::Value> = r.take(1)?;
            if a.is_empty() || b.is_empty() {
                return Err(anyhow!("missing row"));
            }
            Ok(())
        }),
    ));
    v.push((
        "introspection.cur",
        op!(|c, _i| {
            c.clients
                .get_by_client_id(c.fx.tenant_id, &c.fx.client_id)
                .await?;
            c.tenants.get_by_id(c.fx.tenant_id).await?;
            c.users.get_by_id(c.fx.tenant_id, c.fx.user_id).await?;
            Ok(())
        }),
    ));
    v.push((
        "introspection.merged",
        op!(|c, _i| {
            let mut r =
                c.db.query(format!(
                    "{CLIENT_BY_CLIENT_ID}; {TENANT_BY_ID}; {USER_BY_ID};"
                ))
                .bind(("client_id", c.fx.client_id.clone()))
                .bind(("uid", c.fx.user_id.to_string()))
                .bind(("tenant_id", c.fx.tenant_id.to_string()))
                .await?
                .check()?;
            for k in 0..3 {
                let a: Vec<surrealdb::types::Value> = r.take(k)?;
                if a.is_empty() {
                    return Err(anyhow!("missing row {k}"));
                }
            }
            Ok(())
        }),
    ));

    // -- authorization -------------------------------------------------------
    async fn authz_cur<C: Connection>(c: &Ctx<C>) -> Result<()> {
        let a = c
            .roles
            .get_user_role_assignments(c.fx.tenant_id, c.fx.user_id)
            .await?;
        let anc = c
            .resources
            .get_ancestors(c.fx.tenant_id, c.fx.resource_id)
            .await?;
        let ids: HashSet<Uuid> = anc.iter().map(|r| r.id).collect();
        let roles = applicable_roles(&a, c.fx.resource_id, &ids);
        let g = c
            .perms
            .get_role_permission_grants_for_roles(c.fx.tenant_id, &roles)
            .await?;
        if g.is_empty() {
            return Err(anyhow!("no grants"));
        }
        Ok(())
    }
    v.push(("authz_grpc.cur", op!(|c, _i| { authz_cur(&c).await })));
    v.push((
        "authz_rest.cur",
        op!(|c, i| {
            if !c
                .sessions
                .is_session_active_checked(c.fx.tenant_id, c.session(i))
                .await
            {
                return Err(anyhow!("session inactive"));
            }
            authz_cur(&c).await
        }),
    ));
    // Two round trips: assignments + ancestors together, then the exact grants.
    v.push((
        "authz_grpc.two_rt",
        op!(|c, _i| {
            let q = format!(
                "{ROLE_ASSIGNMENTS} RETURN $direct; RETURN $inherited; {}",
                ancestors_sql()
            );
            let mut r =
                c.db.query(q)
                    .bind(("user_id", c.fx.user_id.to_string()))
                    .bind(("rid", c.fx.resource_id.to_string()))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let direct: Vec<surrealdb::types::Value> = r.take(4)?;
            let inherited: Vec<surrealdb::types::Value> = r.take(5)?;
            let anc: Vec<surrealdb::types::Value> = r.take(6)?;
            if direct.is_empty() || inherited.is_empty() || anc.is_empty() {
                return Err(anyhow!("missing rows"));
            }
            // The applicable set is the same one `authz_cur` computes; the cost
            // that matters here is the second round trip's.
            let roles: Vec<RecordId> = applicable_ids_cached(&c)
                .await?
                .iter()
                .map(|id| RecordId::new("role", id.to_string()))
                .collect();
            c.db.query(GRANTS_FOR)
                .bind(("role_records", roles))
                .bind(("tenant_id", c.fx.tenant_id.to_string()))
                .await?
                .check()?;
            Ok(())
        }),
    ));
    // One round trip: grants for every assigned role (a superset), filtered
    // to the applicable roles in the application.
    v.push((
        "authz_grpc.one_rt",
        op!(|c, _i| {
            let q = format!(
                "{ROLE_ASSIGNMENTS} RETURN $direct; RETURN $inherited; {} \
             LET $role_records = array::distinct(array::concat($direct.role, $inherited.role)); \
             {GRANTS_FOR};",
                ancestors_sql()
            );
            let mut r =
                c.db.query(q)
                    .bind(("user_id", c.fx.user_id.to_string()))
                    .bind(("rid", c.fx.resource_id.to_string()))
                    .bind(("tenant_id", c.fx.tenant_id.to_string()))
                    .await?
                    .check()?;
            let g: Vec<surrealdb::types::Value> = r.take(8)?;
            if g.is_empty() {
                return Err(anyhow!("no grants"));
            }
            Ok(())
        }),
    ));

    // -- session refresh -----------------------------------------------------
    v.push((
        "refresh.cur",
        op!(|c, _i| {
            let hash = c
                .refresh_pool
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| anyhow!("pool empty"))?;
            let s = c
                .sessions
                .consume_by_token_hash(c.fx.tenant_id, &hash)
                .await?
                .ok_or_else(|| anyhow!("not consumed"))?;
            c.users.get_by_id(c.fx.tenant_id, s.user_id).await?;
            c.sessions
                .create(new_session(c.fx.tenant_id, s.user_id, random_hash()))
                .await?;
            Ok(())
        }),
    ));
    v.push((
        "refresh.merged",
        op!(|c, _i| {
            let hash = c
                .refresh_pool
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| anyhow!("pool empty"))?;
            let mut r =
                c.db.query(
                    "LET $before = (DELETE session WHERE tenant_id = $tenant_id \
                     AND token_hash = $token_hash RETURN BEFORE); \
                 SELECT meta::id(id) AS record_id, * FROM $before; \
                 SELECT * FROM type::record('user', $before[0].user_id) \
                     WHERE tenant_id = $tenant_id;",
                )
                .bind(("tenant_id", c.fx.tenant_id.to_string()))
                .bind(("token_hash", hash))
                .await?
                .check()?;
            let s: Vec<surrealdb::types::Value> = r.take(1)?;
            let u: Vec<surrealdb::types::Value> = r.take(2)?;
            if s.is_empty() || u.is_empty() {
                return Err(anyhow!("missing rows"));
            }
            c.sessions
                .create(new_session(c.fx.tenant_id, c.fx.user_id, random_hash()))
                .await?;
            Ok(())
        }),
    ));

    // -- audit ---------------------------------------------------------------
    v.push((
        "audit.append_cur",
        op!(|c, i| {
            c.audit
                .append(audit_entry(c.fx.tenant_id, c.fx.user_id, i))
                .await?;
            Ok(())
        }),
    ));
    v.push((
        "audit.create_return_none",
        op!(|c, i| {
            let e = audit_entry(c.fx.tenant_id, c.fx.user_id, i);
            c.db.query(
                "CREATE type::record('audit_log', $id) SET tenant_id = $tenant_id, \
             actor_id = $actor_id, actor_type = $actor_type, action = $action, \
             resource_id = $resource_id, outcome = $outcome, ip_address = $ip_address, \
             metadata = $metadata RETURN NONE",
            )
            .bind(("id", Uuid::new_v4().to_string()))
            .bind(("tenant_id", e.tenant_id.to_string()))
            .bind(("actor_id", e.actor_id.to_string()))
            .bind(("actor_type", "User".to_string()))
            .bind(("action", e.action))
            .bind(("resource_id", None::<String>))
            .bind(("outcome", "Success".to_string()))
            .bind(("ip_address", e.ip_address))
            .bind(("metadata", e.metadata.unwrap()))
            .await?
            .check()?;
            Ok(())
        }),
    ));
    v
}

/// Batched audit inserts through the repository's `append_many`: one op = one
/// call of `n` rows.
fn audit_batch<C: Connection>(n: usize) -> Op<C> {
    mk::<C, _, _>(move |c: Arc<Ctx<C>>, i: usize| async move {
        let rows: Vec<CreateAuditLogEntry> = (0..n)
            .map(|k| audit_entry(c.fx.tenant_id, c.fx.user_id, i.wrapping_mul(n) + k))
            .collect();
        for r in c.audit.append_many(rows).await {
            r?;
        }
        Ok(())
    })
}

/// The statement-per-row alternative: `n` `CREATE … CONTENT` statements in one
/// query — one round trip, but each row its own statement (and transaction),
/// so each gets its own `time::now()` and its own outcome.
#[derive(Debug, SurrealValue)]
struct AuditContent {
    id: RecordId,
    tenant_id: String,
    actor_id: String,
    actor_type: String,
    action: String,
    resource_id: Option<String>,
    outcome: String,
    ip_address: Option<String>,
    metadata: Json,
}

fn audit_multi_create<C: Connection>(n: usize) -> Op<C> {
    let sql: String = (0..n)
        .map(|k| format!("CREATE audit_log CONTENT $r{k} RETURN NONE;"))
        .collect::<Vec<_>>()
        .join(" ");
    mk::<C, _, _>(move |c: Arc<Ctx<C>>, i: usize| {
        let sql = sql.clone();
        async move {
            let mut q = c.db.query(sql);
            for k in 0..n {
                let e = audit_entry(c.fx.tenant_id, c.fx.user_id, i.wrapping_mul(n) + k);
                q = q.bind((
                    format!("r{k}"),
                    AuditContent {
                        id: RecordId::new("audit_log", Uuid::now_v7().to_string()),
                        tenant_id: e.tenant_id.to_string(),
                        actor_id: e.actor_id.to_string(),
                        actor_type: "User".into(),
                        action: e.action,
                        resource_id: None,
                        outcome: "Success".into(),
                        ip_address: e.ip_address,
                        metadata: e.metadata.unwrap_or(json!({})),
                    },
                ));
            }
            q.await?.check()?;
            Ok(())
        }
    })
}

async fn applicable_ids_cached<C: Connection>(c: &Ctx<C>) -> Result<Vec<Uuid>> {
    static IDS: std::sync::OnceLock<Vec<Uuid>> = std::sync::OnceLock::new();
    if let Some(v) = IDS.get() {
        return Ok(v.clone());
    }
    let a = c
        .roles
        .get_user_role_assignments(c.fx.tenant_id, c.fx.user_id)
        .await?;
    let anc = c
        .resources
        .get_ancestors(c.fx.tenant_id, c.fx.resource_id)
        .await?;
    let ids: HashSet<Uuid> = anc.iter().map(|r| r.id).collect();
    let v = applicable_roles(&a, c.fx.resource_id, &ids);
    let _ = IDS.set(v.clone());
    Ok(v)
}

async fn fill_refresh_pool<C: Connection>(c: &Ctx<C>, n: usize) -> Result<()> {
    let mut hashes = Vec::with_capacity(n);
    for chunk in (0..n).collect::<Vec<_>>().chunks(256) {
        let futs = chunk.iter().map(|_| {
            let h = random_hash();
            let s = new_session(c.fx.tenant_id, c.fx.user_id, h.clone());
            async move { c.sessions.create(s).await.map(|_| h) }
        });
        for h in futures::future::join_all(futs).await {
            hashes.push(h?);
        }
    }
    *c.refresh_pool.lock().unwrap() = hashes;
    Ok(())
}

async fn bench_engine<C: Connection>(
    engine: &str,
    db: Surreal<C>,
    fx: Fixture,
    pid: u32,
    filter: &str,
) -> Result<()> {
    let ops: usize = env("OPS", "4000").parse()?;
    let conc: usize = env("CONC", "16").parse()?;
    let ctx = Arc::new(Ctx::new(db, fx));
    let mut list = scenarios::<C>();
    for n in [1usize, 8, 32, 128] {
        let name: &'static str = Box::leak(format!("audit.append_many_{n}").into_boxed_str());
        list.push((name, audit_batch::<C>(n)));
        let name: &'static str = Box::leak(format!("audit.multi_create_{n}").into_boxed_str());
        list.push((name, audit_multi_create::<C>(n)));
    }
    // Idle CPU of the server, subtracted from every run. Measured only after
    // the connection has settled: the root signin's password hash runs on the
    // server just after connect, and an idle window taken then reads ~100 ms
    // of CPU per second that never recurs.
    for _ in 0..50 {
        ctx.db.query("RETURN 1").await?.check()?;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let c0 = cpu_ns(pid);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let idle_ns_per_s = (cpu_ns(pid) - c0) as f64 / 3.0;
    eprintln!(
        "[{engine}] server idle: {:.1} ms CPU/s",
        idle_ns_per_s / 1e6
    );

    for (name, f) in list {
        if !filter.is_empty() && !name.contains(filter) {
            continue;
        }
        let rows_per_op = name
            .strip_prefix("audit.append_many_")
            .or_else(|| name.strip_prefix("audit.multi_create_"))
            .and_then(|n| n.parse::<usize>().ok())
            .unwrap_or(1);
        for (cc, n) in [(1usize, ops / 4), (conc, ops)] {
            let n = (n / rows_per_op.max(1)).max(50);
            if name.starts_with("refresh.") || name == "stmt.session_consume" {
                fill_refresh_pool(&ctx, n + (n / 20).max(20) + 10).await?;
            }
            let ctx2 = Arc::clone(&ctx);
            let f2 = Arc::clone(&f);
            let s = run(pid, cc, n, Arc::new(move |i| f2(Arc::clone(&ctx2), i))).await?;
            let cpu = s.cpu_ns as f64 - idle_ns_per_s * s.wall.as_secs_f64();
            let per_op_us = cpu / s.ops as f64 / 1e3;
            println!(
                "{engine}\t{name}\tc={cc}\tops={}\tops_s={:.0}\tcpu_us_op={:.1}\tcpu_us_row={:.1}\tp50_us={}\tp95_us={}\tp99_us={}",
                s.ops,
                s.ops as f64 / s.wall.as_secs_f64(),
                per_op_us,
                per_op_us / rows_per_op as f64,
                pct(&s.lat_us, 0.5),
                pct(&s.lat_us, 0.95),
                pct(&s.lat_us, 0.99),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EXPLAIN
// ---------------------------------------------------------------------------

async fn explain(fx: &Fixture) -> Result<()> {
    let db = http().await?;
    let stmts: Vec<(&str, String)> = vec![
        ("session.get_by_id", SESSION_BY_ID.into()),
        ("user.get_by_id", USER_BY_ID.into()),
        ("tenant.get_by_id", TENANT_BY_ID.into()),
        ("oauth2_client.get_by_client_id", CLIENT_BY_CLIENT_ID.into()),
        ("session.by_token_hash", "SELECT * FROM session WHERE tenant_id = $tenant_id AND token_hash = $token_hash".into()),
        ("has_role.direct", "SELECT meta::id(out.id) AS record_id, out.tenant_id AS tenant_id, resource_id FROM has_role WHERE in IN [type::record('user', $uid), type::record('service_account', $uid)] AND out.tenant_id = $tenant_id".into()),
        ("member_of", "SELECT VALUE out FROM member_of WHERE in IN [type::record('user', $uid), type::record('service_account', $uid)] AND out.tenant_id = $tenant_id".into()),
        ("resource.ancestors", ancestors_sql().trim_end_matches(';').to_owned()),
        ("grants.for_roles", GRANTS_FOR.into()),
        ("audit_log.list_tenant", "SELECT * FROM audit_log WHERE tenant_id = $tenant_id ORDER BY timestamp DESC LIMIT 50".into()),
    ];
    let roles: Vec<RecordId> = applicable_ids_cached(&Ctx::new(db.clone(), fx.clone()))
        .await?
        .iter()
        .map(|id| RecordId::new("role", id.to_string()))
        .collect();
    for (name, sql) in stmts {
        let mut r = db
            .query(format!("{sql} EXPLAIN"))
            .bind(("sid", fx.session_ids[0].to_string()))
            .bind(("uid", fx.user_id.to_string()))
            .bind(("rid", fx.resource_id.to_string()))
            .bind(("tenant_id", fx.tenant_id.to_string()))
            .bind(("client_id", fx.client_id.clone()))
            .bind(("token_hash", "x".to_string()))
            .bind(("role_records", roles.clone()))
            .await?;
        let v: surrealdb::types::Value = r.take(0).unwrap_or_default();
        println!("=== {name}\n{}", v.into_json_value());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Audit shedding: the real middleware and worker against the real server
// ---------------------------------------------------------------------------

async fn audit_shed(rate: u64, secs: u64, fx: &Fixture) -> Result<()> {
    use actix_web::{App, HttpResponse, test, web};
    use axiam_audit::middleware::AuditMiddleware;

    let db = http().await?;
    let repo = SurrealAuditLogRepository::new(db.clone());
    let mw = AuditMiddleware::spawn(repo);
    let loss = mw.loss();
    let app = test::init_service(App::new().wrap(mw.clone()).route(
        "/probe",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;
    let mut before = db.query("RETURN count(SELECT 1 FROM audit_log)").await?;
    let before: Option<i64> = before.take(0)?;
    let total = rate * secs;
    let t0 = Instant::now();
    for i in 0..total {
        // Pace to `rate` requests per second.
        let due = Duration::from_secs_f64(i as f64 / rate as f64);
        let now = t0.elapsed();
        if due > now {
            tokio::time::sleep(due - now).await;
        }
        let req = test::TestRequest::get().uri("/probe").to_request();
        let _ = test::call_service(&app, req).await;
    }
    let offered_for = t0.elapsed();
    let snap_end = loss.snapshot();
    let drained = mw.drain(Duration::from_secs(120)).await;
    let drain_for = t0.elapsed() - offered_for;
    let mut after = db.query("RETURN count(SELECT 1 FROM audit_log)").await?;
    let after: Option<i64> = after.take(0)?;
    let written = after.unwrap_or(0) - before.unwrap_or(0);
    println!(
        "audit-shed\trate={rate}\tsecs={secs}\toffered={total}\toffered_in_s={:.1}\twritten={written}\tdropped={}\tfailed={}\tdrained={drained}\tdrain_s={:.1}\tworker_rows_s={:.0}",
        offered_for.as_secs_f64(),
        snap_end.dropped,
        snap_end.failed,
        drain_for.as_secs_f64(),
        written as f64 / (offered_for + drain_for).as_secs_f64(),
    );
    let _ = fx;
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantics probe for batched audit inserts
// ---------------------------------------------------------------------------

/// Does a multi-row `INSERT` write all or nothing, and does `time::now()`
/// stamp the rows of one statement in order? Both are what `append_many`'s
/// fallback and the audit trail's ordering rely on.
async fn probe() -> Result<()> {
    let db = http().await?;
    let t = Uuid::new_v4().to_string();
    let ids: Vec<String> = (0..3).map(|_| Uuid::new_v4().to_string()).collect();
    let rows: Vec<Json> = ids
        .iter()
        .enumerate()
        .map(|(k, id)| {
            json!({"id": id, "tenant_id": t, "actor_id": t,
                   "actor_type": if k == 1 { "Bogus" } else { "User" },
                   "action": "probe", "outcome": "Success", "metadata": {}})
        })
        .collect();
    let res = db
        .query("INSERT INTO audit_log $rows RETURN NONE")
        .bind(("rows", rows))
        .await?;
    let refused = res.check().is_err();
    let mut c = db
        .query("RETURN count(SELECT 1 FROM audit_log WHERE tenant_id = $t)")
        .bind(("t", t.clone()))
        .await?;
    let n: Option<i64> = c.take(0)?;
    println!(
        "probe	bad-row batch refused={refused}	rows written={}",
        n.unwrap_or(-1)
    );

    let repo = SurrealAuditLogRepository::new(db.clone());
    let tenant = Uuid::new_v4();
    let entries: Vec<CreateAuditLogEntry> =
        (0..64).map(|i| audit_entry(tenant, tenant, i)).collect();
    for r in repo.append_many(entries).await {
        r?;
    }
    let mut q = db
        .query("SELECT metadata.seq AS seq, timestamp FROM audit_log WHERE tenant_id = $t")
        .bind(("t", tenant.to_string()))
        .await?;
    let v: surrealdb::types::Value = q.take(0)?;
    let mut rows: Vec<(i64, String)> = v
        .into_json_value()
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (r["seq"].as_i64().unwrap(), r["timestamp"].to_string()))
        .collect();
    rows.sort();
    let monotonic = rows.windows(2).all(|w| w[0].1 <= w[1].1);
    let distinct = rows.windows(2).all(|w| w[0].1 != w[1].1);
    println!(
        "probe	append_many rows={}	timestamps non-decreasing in insertion order={monotonic}	all distinct={distinct}	first={}	last={}",
        rows.len(),
        rows.first().map(|r| r.1.as_str()).unwrap_or(""),
        rows.last().map(|r| r.1.as_str()).unwrap_or("")
    );
    let mut q = db
        .query("SELECT VALUE meta::tb(id) + ':' + <string> meta::id(id) FROM audit_log WHERE tenant_id = $t LIMIT 1")
        .bind(("t", tenant.to_string()))
        .await?;
    let v: surrealdb::types::Value = q.take(0)?;
    println!("probe	id shape={}", v.into_json_value());
    Ok(())
}

// ---------------------------------------------------------------------------
// WebSocket reconnect probe (the SDK #5750 question)
// ---------------------------------------------------------------------------

/// Issue a namespaced record read every `interval_ms` for `secs` seconds over
/// the chosen engine, printing every outcome change. Restart or stop the
/// server while it runs: a healthy engine recovers on its own and keeps
/// finding the record (no "not found" from a lost `use_ns`/`use_db`).
async fn reconnect_probe(engine: &str, secs: u64, interval_ms: u64, fx: &Fixture) -> Result<()> {
    async fn one<C: Connection>(
        db: &Surreal<C>,
        fx: &Fixture,
    ) -> std::result::Result<bool, String> {
        let mut r = db
            .query("SELECT * FROM type::record('user', $id)")
            .bind(("id", fx.user_id.to_string()))
            .await
            .map_err(|e| e.to_string())?;
        let rows: Vec<surrealdb::types::Value> = r.take(0).map_err(|e| e.to_string())?;
        Ok(!rows.is_empty())
    }
    let t0 = Instant::now();
    let (mut ok, mut missing, mut errors) = (0u64, 0u64, 0u64);
    let mut last = String::new();
    macro_rules! run {
        ($db:expr) => {{
            let db = $db;
            while t0.elapsed() < Duration::from_secs(secs) {
                let outcome = match tokio::time::timeout(Duration::from_secs(5), one(&db, fx)).await
                {
                    Ok(Ok(true)) => {
                        ok += 1;
                        "found".to_owned()
                    }
                    Ok(Ok(false)) => {
                        missing += 1;
                        "NOT FOUND (namespace lost?)".to_owned()
                    }
                    Ok(Err(e)) => {
                        errors += 1;
                        format!("error: {}", e.chars().take(120).collect::<String>())
                    }
                    Err(_) => {
                        errors += 1;
                        "timeout (5 s)".to_owned()
                    }
                };
                if outcome != last {
                    println!("{:>7.1}s  {outcome}", t0.elapsed().as_secs_f64());
                    last = outcome;
                }
                tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            }
        }};
    }
    match engine {
        "ws" => run!(ws().await?),
        _ => run!(http().await?),
    }
    println!("reconnect-probe\tengine={engine}\tfound={ok}\tnot_found={missing}\terrors={errors}");
    Ok(())
}

// ---------------------------------------------------------------------------
// AXIAM's own pool over either engine (AXIAM__DB__ENGINE)
// ---------------------------------------------------------------------------

/// Connect through `axiam_db::DbPool` — AXIAM's handles, re-signin and
/// reconnect loop — with the chosen engine, then read the fixture user through
/// the real repository every `interval_ms` for `secs` seconds, printing every
/// change of outcome. Restart the server while it runs.
async fn pool_probe(engine: &str, secs: u64, interval_ms: u64, fx: &Fixture) -> Result<()> {
    let config = axiam_db::DbConfig {
        url: env("SURREAL_ADDR", "127.0.0.1:8001"),
        namespace: NS.into(),
        database: DB.into(),
        engine: if engine == "ws" {
            axiam_db::DbEngine::Ws
        } else {
            axiam_db::DbEngine::Http
        },
        ..Default::default()
    };
    println!("endpoint {}", config.endpoint());
    let pool = axiam_db::DbPool::connect(&config).await?;
    let users = SurrealUserRepository::new(pool.handle_for_repo());
    let t0 = Instant::now();
    let (mut ok, mut missing, mut errors) = (0u64, 0u64, 0u64);
    let mut last = String::new();
    while t0.elapsed() < Duration::from_secs(secs) {
        let outcome = match tokio::time::timeout(
            Duration::from_secs(5),
            users.get_by_id(fx.tenant_id, fx.user_id),
        )
        .await
        {
            Ok(Ok(_)) => {
                ok += 1;
                "found".to_owned()
            }
            Ok(Err(axiam_core::error::AxiamError::NotFound { .. })) => {
                missing += 1;
                "NOT FOUND (namespace lost?)".to_owned()
            }
            Ok(Err(e)) => {
                errors += 1;
                format!(
                    "error: {}",
                    e.to_string().chars().take(100).collect::<String>()
                )
            }
            Err(_) => {
                errors += 1;
                "timeout (5 s)".to_owned()
            }
        };
        if outcome != last {
            println!("{:>7.1}s  {outcome}", t0.elapsed().as_secs_f64());
            last = outcome;
        }
        tokio::time::sleep(Duration::from_millis(interval_ms)).await;
    }
    println!("pool-probe\tengine={engine}\tfound={ok}\tnot_found={missing}\terrors={errors}");
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    if cmd == "seed" {
        // Client secrets are keyed by the pepper; a release build refuses to
        // hash without one. The value is irrelevant to the measurement.
        let config = axiam_auth::config::AuthConfig {
            pepper: Some(secrecy::SecretString::from(
                "db-query-bench-pepper-0123456789abcdef".to_owned(),
            )),
            ..Default::default()
        };
        axiam_auth::client_secret::install_from_config(&config)?;
        return seed().await;
    }
    let fx = Fixture::from_json(&serde_json::from_slice(
        &std::fs::read(env("FIXTURE", "fixture.json")).context("read fixture")?,
    )?)?;
    match cmd {
        "bench" => {
            let pid: u32 = env("SURREAL_PID", "").parse().context("SURREAL_PID")?;
            let filter = args.get(2).cloned().unwrap_or_default();
            let engines = env("ENGINES", "http");
            if engines.contains("http") {
                bench_engine("http", http().await?, fx.clone(), pid, &filter).await?;
            }
            if engines.contains("ws") {
                bench_engine("ws", ws().await?, fx.clone(), pid, &filter).await?;
            }
            Ok(())
        }
        "explain" => explain(&fx).await,
        "probe" => probe().await,
        "pool-probe" => {
            let engine = args.get(2).cloned().unwrap_or_else(|| "ws".into());
            let secs: u64 = args.get(3).map_or(Ok(60), |s| s.parse())?;
            let interval: u64 = args.get(4).map_or(Ok(200), |s| s.parse())?;
            pool_probe(&engine, secs, interval, &fx).await
        }
        "reconnect-probe" => {
            let engine = args.get(2).cloned().unwrap_or_else(|| "ws".into());
            let secs: u64 = args.get(3).map_or(Ok(60), |s| s.parse())?;
            let interval: u64 = args.get(4).map_or(Ok(200), |s| s.parse())?;
            reconnect_probe(&engine, secs, interval, &fx).await
        }
        "audit-shed" => {
            let rate: u64 = args.get(2).context("rate")?.parse()?;
            let secs: u64 = args.get(3).context("secs")?.parse()?;
            audit_shed(rate, secs, &fx).await
        }
        _ => Err(anyhow!(
            "usage: db-query-bench seed|bench [filter]|explain|audit-shed <rate> <secs>"
        )),
    }
}

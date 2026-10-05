//! **T23.8.1 (G-8, D-59)** — the composition root, booted with
//! `AXIAM__AMQP__ENABLED=false`: no broker, no connection, nothing to declare.
//!
//! `axiam_server::boot::serve` is the very function `main` calls, here over the
//! embedded in-memory datastore. The tests that refuse return from `serve`
//! before anything is served; the one that boots signs in over HTTP, makes the
//! server emit a webhook and an SSF Security Event Token, and watches both
//! arrive at loopback receivers through the in-process dispatcher — then reads
//! `/health`, the lease row and the audit trail.
//!
//! Keys, passwords and tokens are generated at run time; no assertion or panic
//! message formats one.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axiam_api_rest::HealthChecker;
use axiam_api_rest::health::AlwaysHealthy;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::webhook::WebhookDeliveryService;
use axiam_auth::config::AuthConfig;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::reactor::{CreateReactor, ReactorMode};
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::ssf::{
    NewSsfStream, SsfDeliveryMethod, SsfEventType, SsfStreamStatus, SsfSubjectFormat,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::models::webhook::CreateWebhook;
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, ReactorRepository,
    RoleRepository, SettingsRepository, SsfStreamRepository, TenantRepository, UserRepository,
    WebhookRepository,
};
use axiam_db::{
    DbPool, LeaseClaim, SurrealAuditLogRepository, SurrealMinimalProfileLeaseRepository,
    SurrealOrganizationRepository, SurrealReactorRepository, SurrealRoleRepository,
    SurrealSettingsRepository, SurrealSsfStreamRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebhookRepository, seed_default_roles, seed_permissions,
};
use axiam_server::boot::{AppConfig, ServeOptions, serve};
use axiam_server::profile::LeaseTiming;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

async fn fresh_db() -> Surreal<Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn auth_config() -> AuthConfig {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
    AuthConfig {
        jwt_private_key_pem: pair.serialize_pem(),
        jwt_public_key_pem: pair.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://iam.example.test".into(),
        ..AuthConfig::default()
    }
}

fn runtime_key() -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    out[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    out
}

/// A configuration for the minimal profile: no broker, no AMQP key, a loopback
/// gRPC listener on an ephemeral port.
fn minimal_config() -> AppConfig {
    let mut config = AppConfig::default();
    config.amqp.enabled = false;
    config.auth = auth_config();
    config.server.host = "127.0.0.1".into();
    config.grpc.host = "127.0.0.1".into();
    config.grpc.port = 0;
    config
}

fn pool_over(db: &Surreal<Db>) -> (Arc<DbPool<Db>>, Arc<dyn HealthChecker>) {
    (
        Arc::new(DbPool::from_embedded(db.clone())),
        Arc::new(AlwaysHealthy),
    )
}

/// Run [`serve`] on a thread of its own, with its own runtime.
///
/// The composition root is one very large future. In a debug build its frames
/// do not fit the 2 MiB a test thread gets, so it runs where the stack is
/// generous — the way `main` runs it on the process's main thread — and its
/// result comes back over a channel the test can await without blocking the
/// runtime the embedded datastore's tasks live on.
fn serve_on_big_stack(
    config: AppConfig,
    pool: Arc<DbPool<Db>>,
    health: Arc<dyn HealthChecker>,
    opts: ServeOptions,
) -> tokio::sync::oneshot::Receiver<std::io::Result<()>> {
    let (done, result) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("minimal-profile-server".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(32 * 1024 * 1024)
                .enable_all()
                .build()
                .unwrap();
            let _ = done.send(runtime.block_on(serve(config, pool, health, opts)));
        })
        .unwrap();
    result
}

/// Run `serve` to its first return, with a bound on how long that may take: a
/// refusal returns at once, so a hang is a failure, not a wait.
async fn refused(config: AppConfig, db: &Surreal<Db>, opts: ServeOptions) -> String {
    let (pool, health) = pool_over(db);
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        serve_on_big_stack(config, pool, health, opts),
    )
    .await
    .expect("a refusing boot returns promptly")
    .expect("the server thread reported");
    result.expect_err("the boot must be refused").to_string()
}

fn short_lease() -> LeaseTiming {
    LeaseTiming {
        ttl: Duration::from_millis(400),
        renew_every: Duration::from_millis(100),
        boot_wait: Duration::from_millis(300),
        boot_poll: Duration::from_millis(20),
        lost_stop_deadline: Duration::from_secs(10),
    }
}

// ---------------------------------------------------------------------------
// The refusals, through the real composition root
// ---------------------------------------------------------------------------

/// `decision_cache_broadcast_enabled = true` asks for cross-replica
/// invalidation over AMQP; with no broker there is nothing to broadcast to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_refuses_the_decision_cache_broadcast_without_a_broker() {
    let db = fresh_db().await;
    let mut config = minimal_config();
    config.authz.decision_cache_enabled = true;
    config.authz.decision_cache_broadcast_enabled = true;

    let message = refused(config, &db, ServeOptions::default()).await;
    assert!(message.contains("AXIAM__AMQP__ENABLED=false"), "{message}");
    assert!(message.contains("BROADCAST"), "{message}");
    assert!(
        message.contains("AXIAM__AMQP__ENABLED=true"),
        "names the fix"
    );
    // Refused before the datastore was touched: no lease was taken.
    assert!(
        SurrealMinimalProfileLeaseRepository::new(db.clone())
            .current()
            .await
            .unwrap()
            .is_none()
    );
}

/// An enabled reactor registration in ANY tenant: a `fail_closed` reactor with
/// no transport would deny logins there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_refuses_an_enabled_reactor_registration() {
    let db = fresh_db().await;
    SurrealReactorRepository::new(db.clone())
        .create(CreateReactor {
            tenant_id: Uuid::new_v4(),
            name: "fraud-veto".into(),
            description: String::new(),
            events: vec!["login.post_auth".into()],
            mode: ReactorMode::Intercept,
            priority: 0,
            timeout_ms: None,
            failure_policy: None,
            enabled: true,
        })
        .await
        .unwrap();

    let message = refused(minimal_config(), &db, ServeOptions::default()).await;
    assert!(message.contains("AXIAM__AMQP__ENABLED=false"), "{message}");
    assert!(message.contains("1 enabled reactor"), "{message}");
    assert!(
        message.contains("enabled: false"),
        "names the fix: {message}"
    );
}

/// A disabled registration is not a reason to refuse: the check is about what
/// would be dispatched to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_is_not_refused_by_a_disabled_reactor_registration() {
    let db = fresh_db().await;
    SurrealReactorRepository::new(db.clone())
        .create(CreateReactor {
            tenant_id: Uuid::new_v4(),
            name: "staged".into(),
            description: String::new(),
            events: vec!["login.post_auth".into()],
            mode: ReactorMode::Intercept,
            priority: 0,
            timeout_ms: None,
            failure_policy: None,
            enabled: false,
        })
        .await
        .unwrap();
    // The lease is the next guard: hold it as another instance so this boot
    // stops there, proving the reactor check was passed.
    SurrealMinimalProfileLeaseRepository::new(db.clone())
        .claim(
            "another-instance",
            chrono::Utc::now(),
            chrono::Duration::hours(1),
        )
        .await
        .unwrap();

    let message = refused(
        minimal_config(),
        &db,
        ServeOptions {
            lease_timing: short_lease(),
            ..ServeOptions::default()
        },
    )
    .await;
    assert!(message.contains("another-instance"), "{message}");
}

/// A second live instance: its lease is live and is not released within the
/// boot's wait. The refusal names the other instance and the fix.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_refuses_a_second_live_instance_after_waiting() {
    let db = fresh_db().await;
    let leases = SurrealMinimalProfileLeaseRepository::new(db.clone());
    assert_eq!(
        leases
            .claim(
                "the-first-instance",
                chrono::Utc::now(),
                chrono::Duration::hours(1)
            )
            .await
            .unwrap(),
        LeaseClaim::Acquired
    );

    let started = tokio::time::Instant::now();
    let message = refused(
        minimal_config(),
        &db,
        ServeOptions {
            lease_timing: short_lease(),
            ..ServeOptions::default()
        },
    )
    .await;
    assert!(
        started.elapsed() >= short_lease().boot_wait,
        "the boot waited for the other lease before refusing"
    );
    assert!(message.contains("the-first-instance"), "{message}");
    assert!(message.contains("AXIAM__AMQP__ENABLED=false"), "{message}");
    assert!(message.contains("single-instance"), "{message}");
    assert_eq!(
        leases.current().await.unwrap().unwrap().holder,
        "the-first-instance",
        "the refused boot left the first instance's lease alone"
    );
}

// ---------------------------------------------------------------------------
// A loopback receiver
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Recorded {
    headers: HashMap<String, String>,
    body: String,
}

struct Receiver {
    port: u16,
    seen: Arc<Mutex<Vec<Recorded>>>,
}

impl Receiver {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_task = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let seen = seen_for_task.clone();
                tokio::spawn(async move {
                    let mut raw = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, mut body) = loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        raw.extend_from_slice(&chunk[..n]);
                        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                            let body = raw.split_off(at + 4);
                            break (String::from_utf8_lossy(&raw).into_owned(), body);
                        }
                    };
                    let headers: HashMap<String, String> = head
                        .lines()
                        .skip(1)
                        .filter_map(|l| l.split_once(':'))
                        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
                        .collect();
                    let wanted: usize = headers
                        .get("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    while body.len() < wanted {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        body.extend_from_slice(&chunk[..n]);
                    }
                    seen.lock().unwrap().push(Recorded {
                        headers,
                        body: String::from_utf8_lossy(&body).into_owned(),
                    });
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, seen }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn requests(&self) -> Vec<Recorded> {
        self.seen.lock().unwrap().clone()
    }
}

async fn eventually<T>(what: &str, mut probe: impl AsyncFnMut() -> Option<T>) -> T {
    for _ in 0..400 {
        if let Some(found) = probe().await {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for {what}");
}

/// The access token a login puts in its `Set-Cookie`.
fn access_cookie(resp: &reqwest::Response) -> String {
    resp.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix("axiam_access="))
        .and_then(|rest| rest.split(';').next())
        .expect("the login sets the access cookie")
        .to_owned()
}

// ---------------------------------------------------------------------------
// The boot
// ---------------------------------------------------------------------------

/// Flag off boots with no broker and serves a login, a webhook delivery and an
/// SSF push end to end, through the in-process dispatcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_server_boots_without_a_broker_and_serves_login_webhook_and_ssf_push() {
    // ---- the world: one org, one tenant, one administrator --------------
    let db = fresh_db().await;
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Minimal Org".into(),
            slug: format!("minimal-org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let mut settings = system_defaults();
    settings.ssf_enabled = true;
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, settings)
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Minimal Tenant".into(),
            slug: format!("minimal-tenant-{}", Uuid::new_v4().simple()),
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
    let password = axiam_test_support::test_password();
    let users = SurrealUserRepository::new(db.clone());
    let admin = users
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: password.clone(),
            metadata: None,
        })
        .await
        .unwrap();
    users
        .update(
            tenant.id,
            admin.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let roles = SurrealRoleRepository::new(db.clone());
    let super_admin = roles
        .list(
            tenant.id,
            Pagination {
                offset: 0,
                limit: 10_000,
                search: None,
            },
        )
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name == "super-admin")
        .expect("the seeded role")
        .id;
    roles
        .assign_to_user(tenant.id, admin.id, super_admin, AssignmentScope::global())
        .await
        .unwrap();

    // ---- the receivers, and what they are registered as ------------------
    let sealing = runtime_key();
    let hook_receiver = Receiver::start().await;
    let ssf_receiver = Receiver::start().await;

    let sealer =
        WebhookDeliveryService::new(SurrealWebhookRepository::new(db.clone()), Some(sealing));
    let webhook = SurrealWebhookRepository::new(db.clone())
        .create(CreateWebhook {
            tenant_id: tenant.id,
            url: hook_receiver.url("/hook"),
            events: vec!["user.created".into()],
            secret: sealer
                .encrypt_secret(&axiam_test_support::other_password())
                .unwrap(),
            retry_policy: None,
        })
        .await
        .unwrap();

    let audience = format!("https://rp.example.test/aud/{}", Uuid::new_v4().simple());
    let stream = SurrealSsfStreamRepository::new(db.clone(), Some(sealing))
        .create(NewSsfStream {
            tenant_id: tenant.id,
            receiver_client_id: "receiver".into(),
            audience: audience.clone(),
            description: None,
            delivery_method: SsfDeliveryMethod::Push,
            endpoint_url: Some(ssf_receiver.url("/ssf/events")),
            authorization_header: Some(Zeroizing::new(format!(
                "Bearer {}",
                Uuid::new_v4().simple()
            ))),
            events_allowed: vec![SsfEventType::SessionRevoked],
            events_requested: vec![SsfEventType::SessionRevoked],
            subject_format: SsfSubjectFormat::IssSub,
            status: SsfStreamStatus::Enabled,
            status_reason: None,
        })
        .await
        .unwrap();

    // ---- boot ------------------------------------------------------------
    let mut config = minimal_config();
    config.pki_encryption_key = Some(sealing);
    let jwt_public_pem = config.auth.jwt_public_key_pem.clone();
    // Process-wide, once: what `main` installs before it calls `serve`.
    let _ = rustls::crypto::ring::default_provider().install_default();
    axiam_auth::client_secret::install_from_config(&config.auth)
        .expect("the client-secret hasher installs");
    config
        .auth
        .resolve_keys()
        .expect("the Ed25519 keys parse (CQ-B14)");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rest_port = listener.local_addr().unwrap().port();
    config.server.port = rest_port;
    let (pool, health) = pool_over(&db);
    let opts = ServeOptions {
        rest_listener: Some(listener),
        admit_private_networks_for_tests: true,
        ..ServeOptions::default()
    };
    let mut stopped = serve_on_big_stack(config, pool, health, opts);

    let base = format!("http://127.0.0.1:{rest_port}");
    let http = reqwest::Client::new();

    // ---- it is up, and says which profile it is --------------------------
    let health: serde_json::Value = eventually("the REST listener", async || {
        let resp = http.get(format!("{base}/health")).send().await.ok()?;
        resp.json().await.ok()
    })
    .await;
    assert_eq!(health["status"], "ok");
    assert_eq!(health["profile"], "minimal");
    assert_eq!(
        health["unavailable"],
        serde_json::json!([
            "reactors",
            "amqp_authz",
            "amqp_audit_ingestion",
            "decision_cache_broadcast"
        ])
    );

    // ---- the lease: this instance holds it -------------------------------
    let lease = SurrealMinimalProfileLeaseRepository::new(db.clone())
        .current()
        .await
        .unwrap()
        .expect("the booted instance holds the singleton lease");
    assert!(lease.expires_at > chrono::Utc::now());

    // ---- sign in -----------------------------------------------------------
    let resp = http
        .post(format!("{base}/api/v1/auth/login"))
        .json(&serde_json::json!({
            "tenant_id": tenant.id,
            "org_id": org.id,
            "username_or_email": "admin",
            "password": password,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "the login is served");
    let token = access_cookie(&resp);
    let me = http
        .get(format!("{base}/api/v1/auth/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status().as_u16(), 200, "the session is live");

    // ---- a webhook, through the in-process dispatcher ----------------------
    let created = http
        .post(format!("{base}/api/v1/users"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "username": "bob",
            "email": "bob@example.com",
            "password": axiam_test_support::other_password(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "the user is created");

    let delivered = eventually("the webhook POST", async || {
        hook_receiver.requests().into_iter().next()
    })
    .await;
    assert_eq!(delivered.headers["x-axiam-event"], "user.created");
    assert!(
        delivered.headers.contains_key("x-axiam-signature"),
        "the delivery is signed"
    );
    assert!(
        delivered.headers.contains_key("x-axiam-timestamp"),
        "and timestamped"
    );
    let payload: serde_json::Value = serde_json::from_str(&delivered.body).unwrap();
    assert_eq!(payload["username"], "bob");

    let audit = SurrealAuditLogRepository::new(db.clone());
    let rows_of = async |action: &str| {
        audit
            .list(
                tenant.id,
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
    };
    let success = eventually("the webhook success audit row", async || {
        let rows = rows_of("webhook.delivery_succeeded").await;
        (!rows.is_empty()).then_some(rows)
    })
    .await;
    assert_eq!(success.len(), 1, "one delivery, one success row");
    assert_eq!(success[0].resource_id, Some(webhook.id));

    // ---- an SSF push, through the same dispatcher --------------------------
    let logout = http
        .post(format!("{base}/api/v1/auth/logout"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status().as_u16(), 204);

    let pushed = eventually("the SSF push", async || {
        ssf_receiver.requests().into_iter().next()
    })
    .await;
    assert_eq!(pushed.headers["content-type"], "application/secevent+jwt");
    let key = DecodingKey::from_ed_pem(jwt_public_pem.as_bytes()).unwrap();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.set_audience(&[audience.as_str()]);
    let claims = jsonwebtoken::decode::<serde_json::Value>(pushed.body.trim(), &key, &validation)
        .expect("the SET verifies against the deployment key")
        .claims;
    assert!(
        claims["events"]
            .as_object()
            .unwrap()
            .keys()
            .any(|uri| uri == SsfEventType::SessionRevoked.uri()),
        "the SET carries session-revoked"
    );
    let ssf_success = eventually("the SSF success audit row", async || {
        let rows = rows_of("ssf_push.delivery_succeeded").await;
        (!rows.is_empty()).then_some(rows)
    })
    .await;
    assert_eq!(ssf_success[0].resource_id, Some(stream.id));

    // ---- reactor administration is the minimal profile's 409 ---------------
    let token = {
        // The first session was just revoked: sign in again.
        let resp = http
            .post(format!("{base}/api/v1/auth/login"))
            .json(&serde_json::json!({
                "tenant_id": tenant.id,
                "org_id": org.id,
                "username_or_email": "admin",
                "password": password,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        access_cookie(&resp)
    };
    let refused = http
        .post(format!("{base}/api/v1/reactors"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "fraud-veto",
            "events": ["login.post_auth"],
            "mode": "intercept",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 409);
    let body = refused.text().await.unwrap();
    assert!(body.contains("minimal profile"), "{body}");
    let staged = http
        .post(format!("{base}/api/v1/reactors"))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "name": "staged",
            "events": ["login.post_auth"],
            "mode": "intercept",
            "enabled": false,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        staged.status().as_u16(),
        201,
        "a disabled registration is fine"
    );

    // ---- and it is still serving ---------------------------------------------
    assert!(
        matches!(
            stopped.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "the server is still running"
    );
}

// ---------------------------------------------------------------------------
// A lost lease (T23.8.2, P23W5-A1)
// ---------------------------------------------------------------------------

/// Requests audited before the loss, each one row in the system trail.
const AUDITED_BEFORE_THE_LOSS: usize = 20;

/// An instance whose lease another instance takes over stops through the
/// orderly path — the REST listener stops, the audit queue is drained, the
/// cleanup task finishes — and `serve` returns an error naming the lease, which
/// is `main`'s non-zero exit. Before T23.8.2 the reaction was
/// `std::process::exit(1)` from the renewal task: every audit row still queued
/// in the middleware's channel, a request between its write and its audit row,
/// and a GDPR purge between the erasure and `gdpr.user_pseudonymized` were lost
/// with the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_instance_that_loses_its_lease_stops_in_order_and_keeps_its_audit_rows() {
    let db = fresh_db().await;
    let mut config = minimal_config();
    let _ = rustls::crypto::ring::default_provider().install_default();
    axiam_auth::client_secret::install_from_config(&config.auth)
        .expect("the client-secret hasher installs");
    config
        .auth
        .resolve_keys()
        .expect("the Ed25519 keys parse (CQ-B14)");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let rest_port = listener.local_addr().unwrap().port();
    config.server.port = rest_port;

    // The backstop is what runs if the orderly stop does not finish in time;
    // here it only records that it ran.
    let backstop_ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = Arc::clone(&backstop_ran);
    let (pool, health) = pool_over(&db);
    let opts = ServeOptions {
        rest_listener: Some(listener),
        lease_timing: short_lease(),
        lease_lost_backstop: Arc::new(move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst)
        }),
        ..ServeOptions::default()
    };
    let stopped = serve_on_big_stack(config, pool, health, opts);

    // No idle keep-alive connection: the orderly stop waits for open ones.
    let http = reqwest::Client::builder()
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{rest_port}");
    eventually("the REST listener", async || {
        let resp = http.get(format!("{base}/health")).send().await.ok()?;
        resp.status().is_success().then_some(())
    })
    .await;
    for _ in 0..AUDITED_BEFORE_THE_LOSS {
        http.get(format!("{base}/api/v1/auth/me"))
            .send()
            .await
            .unwrap();
    }

    // Another instance takes the lease over.
    db.query(
        "UPDATE type::record('minimal_profile_lease', 'instance') \
         SET holder = 'the-usurper', renewed_at = time::now(), expires_at = time::now() + 1h",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    // The instance stops on its own, in order, and says why.
    let result = tokio::time::timeout(Duration::from_secs(20), stopped)
        .await
        .expect("an instance whose lease was taken stops")
        .expect("the server thread reported");
    let message = result
        .expect_err("a lost lease is a non-zero exit")
        .to_string();
    assert!(message.contains("lease"), "{message}");
    assert!(
        !backstop_ran.load(std::sync::atomic::Ordering::SeqCst),
        "the orderly stop finished before the backstop was needed"
    );

    // Every request audited before the loss is in the trail.
    let rows = SurrealAuditLogRepository::new(db.clone())
        .list_system(
            AuditLogFilter {
                action: Some("GET /api/v1/auth/me".into()),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 1_000,
                search: None,
            },
        )
        .await
        .unwrap()
        .items;
    assert_eq!(rows.len(), AUDITED_BEFORE_THE_LOSS);

    // And the other instance's lease was left alone.
    assert_eq!(
        SurrealMinimalProfileLeaseRepository::new(db.clone())
            .current()
            .await
            .unwrap()
            .unwrap()
            .holder,
        "the-usurper"
    );
}

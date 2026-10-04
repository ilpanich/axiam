//! **T23.5.2** — the SSF transmitter over HTTP (G-5, contract §31, D-45 …
//! D-51): the stream registry's management routes, the receiver's stream
//! management API, and `/.well-known/ssf-configuration`.
//!
//! Real RBAC, the production route table, the real repositories on an
//! in-memory database. The outbox is a recording double (delivery is
//! T23.5.3's); what it records is signed here with the production signer and
//! verified against the published JWKS. Every test runs with permissive rate
//! limits except the ones that pin a bucket.
//!
//! Keys, headers and tokens are generated at run time; no assertion or panic
//! message formats a header, a token or an address.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock};

use actix_web::http::Method;
use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_USER, issue_access_token, issue_client_credentials_token, issue_service_account_token,
};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::service_account::CreateServiceAccount;
use axiam_core::models::settings::{SetTenantOverride, system_defaults};
use axiam_core::models::ssf::{
    NewSsfStream, SsfDeliveryMethod, SsfEventType, SsfFuture, SsfOutbox, SsfOutboxError,
    SsfPendingEvent, SsfStream, SsfStreamStatus, SsfSubjectFormat, VERIFICATION_EVENT_URI,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OAuth2ClientRepository, OrganizationRepository, Pagination,
    PermissionRepository, RoleRepository, ServiceAccountRepository, SettingsRepository,
    SsfStreamRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealServiceAccountRepository,
    SurrealSettingsRepository, SurrealSsfStreamRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use axiam_test_support::test_password;
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use zeroize::Zeroizing;

type TestDb = Db;

const TEST_PEER: &str = "127.0.0.1:40100";
const ROOT_ISSUER: &str = "https://iam.example.com";
const RECEIVER: &str = "ssf-receiver-a";
const OTHER_RECEIVER: &str = "ssf-receiver-b";
const PUSH_URL: &str = "https://rp.example.test/ssf/events";

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

/// A push credential value made at run time.
fn header_value() -> String {
    format!("Bearer {}", Uuid::new_v4().simple())
}

fn auth_config(tenant_paths: bool) -> AuthConfig {
    let (private_pem, public_pem) = jwt_pair().clone();
    AuthConfig {
        jwt_private_key_pem: private_pem,
        jwt_public_key_pem: public_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ROOT_ISSUER.into(),
        tenant_issuer_paths: tenant_paths,
        ..AuthConfig::default()
    }
}

/// What the outbox was handed, in order.
#[derive(Default)]
struct RecordingOutbox {
    submitted: Mutex<Vec<(SsfStream, SsfPendingEvent)>>,
}

impl SsfOutbox for RecordingOutbox {
    fn submit<'a>(
        &'a self,
        stream: &'a SsfStream,
        event: &'a SsfPendingEvent,
    ) -> SsfFuture<'a, Result<(), SsfOutboxError>> {
        Box::pin(async move {
            if stream.status == SsfStreamStatus::Disabled {
                return Err(SsfOutboxError::Disabled);
            }
            self.submitted
                .lock()
                .unwrap()
                .push((stream.clone(), event.clone()));
            Ok(())
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
    auth: AuthConfig,
    authz: Arc<dyn AuthzChecker>,
    sealing: [u8; 32],
    outbox: Arc<RecordingOutbox>,
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

/// A user whose only grants are `actions`.
async fn user_holding(db: &Surreal<TestDb>, tenant_id: Uuid, actions: &[&str]) -> Uuid {
    let user_id = active_user(db, tenant_id, &format!("u{}", Uuid::new_v4().simple())).await;
    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
        .create(CreateRole {
            tenant_id,
            name: format!("r{}", Uuid::new_v4().simple()),
            description: "ssf test role".into(),
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

/// An OAuth2 client of `tenant_id` with the client-credentials grant and
/// `scopes`.
async fn client_in(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str, scopes: &[&str]) -> String {
    let input: CreateOAuth2Client = serde_json::from_value(json!({
        "tenant_id": tenant_id,
        "name": name,
        "redirect_uris": [],
        "grant_types": ["client_credentials"],
        "scopes": scopes,
    }))
    .expect("a client-credentials client");
    let (client, _issued) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(input)
        .await
        .unwrap();
    client.client_id
}

async fn world_with(tenant_paths: bool) -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SSF Org".into(),
            slug: format!("ssf-org-{}", Uuid::new_v4().simple()),
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
    let tenant_id = tenant_in(&db, org.id, "ssf-home").await;
    let other_tenant_id = tenant_in(&db, org.id, "ssf-other").await;
    let admin = active_user(&db, tenant_id, "admin").await;
    SurrealRoleRepository::new(db.clone())
        .assign_to_user(
            tenant_id,
            admin,
            role_named(&db, tenant_id, "super-admin").await,
            AssignmentScope::global(),
        )
        .await
        .unwrap();
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
        auth: auth_config(tenant_paths),
        authz,
        sealing: runtime_bytes(),
        outbox: Arc::new(RecordingOutbox::default()),
    }
}

async fn world() -> World {
    world_with(false).await
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

    /// A receiver token: client credentials for `client_id` in `tenant_id`.
    fn client_token(&self, client_id: &str, tenant_id: Uuid, scopes: &[&str]) -> String {
        let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
        issue_client_credentials_token(client_id, tenant_id, self.org_id, &scopes, &self.auth)
            .unwrap()
    }

    fn receiver_token(&self) -> String {
        self.client_token(RECEIVER, self.tenant_id, &["ssf.manage"])
    }

    fn repo(&self) -> SurrealSsfStreamRepository<TestDb> {
        SurrealSsfStreamRepository::new(self.db.clone(), Some(self.sealing))
    }

    /// `AppState` with a sealing key and the recording outbox.
    fn state(&self) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state.ssf.stream_repo = self.repo();
        state.ssf.outbox = Some(self.outbox.clone() as Arc<dyn SsfOutbox>);
        state
    }

    /// A stream registered directly in the datastore.
    async fn stream(
        &self,
        tenant_id: Uuid,
        receiver: &str,
        method: SsfDeliveryMethod,
        status: SsfStreamStatus,
    ) -> SsfStream {
        let push = method == SsfDeliveryMethod::Push;
        self.repo()
            .create(NewSsfStream {
                tenant_id,
                receiver_client_id: receiver.into(),
                audience: format!("https://rp.example.test/aud/{}", Uuid::new_v4().simple()),
                description: None,
                delivery_method: method,
                endpoint_url: push.then(|| PUSH_URL.to_owned()),
                authorization_header: push.then(|| Zeroizing::new(header_value())),
                events_allowed: vec![
                    SsfEventType::SessionRevoked,
                    SsfEventType::CredentialChange,
                    SsfEventType::AccountDisabled,
                ],
                events_requested: vec![
                    SsfEventType::SessionRevoked,
                    SsfEventType::CredentialChange,
                ],
                subject_format: SsfSubjectFormat::IssSub,
                status,
                status_reason: None,
            })
            .await
            .unwrap()
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

    async fn ssf_off_for(&self, tenant_id: Uuid) {
        SurrealSettingsRepository::new(self.db.clone())
            .set_tenant_override(
                tenant_id,
                SetTenantOverride {
                    ssf_enabled: Some(false),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
}

fn permissive_limits() -> RateLimitConfig {
    RateLimitConfig {
        ssf_per_min: 100_000,
        ssf_admin_per_min: 100_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! app {
    ($state:expr, $w:expr) => {
        app!($state, $w, permissive_limits(), false)
    };
    ($state:expr, $w:expr, $limits:expr, $paths:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.authz.clone()))
                .app_data(web::Data::new($state))
                .configure(|cfg| {
                    register_api_v1_routes_with::<TestDb>(
                        cfg,
                        &$limits,
                        RouteOptions {
                            tenant_issuer_paths: $paths,
                            ..RouteOptions::default()
                        },
                    )
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

fn streams_uri(tenant_id: Uuid) -> String {
    format!("/api/v1/tenants/{tenant_id}/ssf/streams")
}

fn push_body(audience: &str, header: Option<&str>) -> Value {
    let mut body = json!({
        "receiver_client_id": RECEIVER,
        "audience": audience,
        "delivery_method": "push",
        "endpoint_url": PUSH_URL,
        "events_allowed": [
            SsfEventType::SessionRevoked.uri(),
            SsfEventType::AccountDisabled.uri(),
        ],
    });
    if let Some(h) = header {
        body["authorization_header"] = json!(h);
    }
    body
}

async fn with_receiver_client(w: &World) {
    client_in(&w.db, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
}

/// `client_in` mints its own `client_id`; the tests address receivers by a
/// fixed name, so the binding is rewritten to the name after creation.
async fn named_client(w: &World, tenant_id: Uuid, name: &str, scopes: &[&str]) {
    let minted = client_in(&w.db, tenant_id, name, scopes).await;
    w.db.query("UPDATE oauth2_client SET client_id = $name WHERE client_id = $minted")
        .bind(("name", name.to_owned()))
        .bind(("minted", minted))
        .await
        .unwrap()
        .check()
        .unwrap();
}

// ---------------------------------------------------------------------------
// The management API (contract §31.1 – §31.3)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn an_administrator_registers_reads_lists_replaces_and_deletes_a_stream() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let header = header_value();

    let (status, body) = send(
        &app,
        request(Method::POST, &streams_uri(w.tenant_id), Some(&token))
            .set_json(push_body("https://rp.example.test/aud-crud", Some(&header))),
    )
    .await;
    assert_eq!(status, 201, "create: {body}");
    assert!(!body.contains(&header), "the header must never be returned");
    let created = json_of(&body);
    assert_eq!(created["authorization_header_set"], true);
    assert_eq!(created["receiver_client_id"], RECEIVER);
    assert_eq!(created["delivery_method"], "push");
    assert_eq!(created["subject_format"], "iss_sub");
    assert_eq!(created["status"], "enabled");
    assert_eq!(created["status_actor"], "admin");
    // events_requested defaults to the allowance; delivered is their intersection.
    assert_eq!(created["events_requested"], created["events_allowed"]);
    assert_eq!(created["events_delivered"], created["events_allowed"]);
    let id = created["id"].as_str().unwrap().to_owned();

    let (status, body) = send(
        &app,
        request(
            Method::GET,
            &format!("{}/{id}", streams_uri(w.tenant_id)),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert!(!body.contains(&header));

    let (status, body) = send(
        &app,
        request(
            Method::GET,
            &format!("{}?search=aud-crud", streams_uri(w.tenant_id)),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 200);
    let page = json_of(&body);
    assert_eq!(page["total"], 1);
    assert_eq!(page["items"][0]["id"], id.as_str());

    // Replace: narrow the receiver's events, keep the header (same origin).
    let mut replacement = push_body("https://rp.example.test/aud-crud", None);
    replacement["events_requested"] = json!([SsfEventType::SessionRevoked.uri()]);
    replacement["endpoint_url"] = json!("https://rp.example.test/ssf/v2/events");
    replacement["subject_format"] = json!("email");
    let (status, body) = send(
        &app,
        request(
            Method::PUT,
            &format!("{}/{id}", streams_uri(w.tenant_id)),
            Some(&token),
        )
        .set_json(replacement),
    )
    .await;
    assert_eq!(status, 200, "update: {body}");
    let updated = json_of(&body);
    assert_eq!(updated["authorization_header_set"], true);
    assert_eq!(updated["subject_format"], "email");
    assert_eq!(
        updated["events_delivered"],
        json!([SsfEventType::SessionRevoked.uri()])
    );
    let stream_id = Uuid::parse_str(&id).unwrap();
    let opened = w
        .repo()
        .decrypt_authorization_header(w.tenant_id, stream_id)
        .await
        .unwrap()
        .unwrap();
    assert!(opened.as_str() == header, "the kept header is the original");

    // Audit rows carry names, never the header.
    let rows = w.audit_rows(w.tenant_id, "ssf_stream.updated").await;
    assert_eq!(rows.len(), 1);
    let changed = rows[0].metadata["changed"].as_array().unwrap();
    assert!(changed.contains(&json!("events_requested")));
    assert!(changed.contains(&json!("subject_format")));
    for action in ["ssf_stream.created", "ssf_stream.updated"] {
        for row in w.audit_rows(w.tenant_id, action).await {
            assert!(!row.metadata.to_string().contains(&header));
        }
    }

    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &format!("{}/{id}", streams_uri(w.tenant_id)),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 204);
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &format!("{}/{id}", streams_uri(w.tenant_id)),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(
        w.audit_rows(w.tenant_id, "ssf_stream.deleted").await.len(),
        1
    );
}

#[actix_rt::test]
async fn every_value_rule_and_the_receiver_binding_are_400s_that_name_the_rule() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    named_client(&w, w.tenant_id, "no-scope-client", &["openid"]).await;
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let base = || push_body(&format!("https://rp.example.test/{}", Uuid::new_v4()), None);
    let cases: Vec<(&str, Value)> = vec![
        ("endpoint_url", {
            let mut b = base();
            b.as_object_mut().unwrap().remove("endpoint_url");
            b
        }),
        ("non-public", {
            let mut b = base();
            b["endpoint_url"] = json!("https://169.254.169.254/latest/meta-data");
            b
        }),
        ("https", {
            let mut b = base();
            b["endpoint_url"] = json!("http://rp.example.test/events");
            b
        }),
        ("local or internal", {
            let mut b = base();
            b["endpoint_url"] = json!("https://localhost/events");
            b
        }),
        ("poll stream has no endpoint_url", {
            let mut b = base();
            b["delivery_method"] = json!("poll");
            b
        }),
        ("at least one event", {
            let mut b = base();
            b["events_allowed"] = json!([]);
            b
        }),
        ("subset of events_allowed", {
            let mut b = base();
            b["events_requested"] = json!([SsfEventType::AccountPurged.uri()]);
            b
        }),
        ("audience", {
            let mut b = base();
            b["audience"] = json!("");
            b
        }),
        ("not an OAuth2 client of this tenant", {
            let mut b = base();
            b["receiver_client_id"] = json!("nobody");
            b
        }),
        ("ssf.manage", {
            let mut b = base();
            b["receiver_client_id"] = json!("no-scope-client");
            b
        }),
        ("authorization_header", {
            let mut b = base();
            b["authorization_header"] = json!(format!("Bearer {}\r\nX: y", Uuid::new_v4()));
            b
        }),
    ];
    for (rule, body) in cases {
        let (status, text) = send(
            &app,
            request(Method::POST, &streams_uri(w.tenant_id), Some(&token)).set_json(body),
        )
        .await;
        assert_eq!(status, 400, "{rule}");
        let message = json_of(&text)["message"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(message.contains(rule), "the message names the rule {rule}");
    }
    // An unknown event-type URI is refused by the decoder.
    let mut unknown = base();
    unknown["events_allowed"] = json!(["urn:example:unknown"]);
    let (status, _) = send(
        &app,
        request(Method::POST, &streams_uri(w.tenant_id), Some(&token)).set_json(unknown),
    )
    .await;
    assert_eq!(status, 400);
}

#[actix_rt::test]
async fn an_audience_is_unique_across_tenants_and_a_header_needs_the_sealing_key() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    // The other tenant already uses the audience.
    let taken = w
        .stream(
            w.other_tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            &streams_uri(w.tenant_id),
            Some(&w.admin_token()),
        )
        .set_json(push_body(&taken.audience, None)),
    )
    .await;
    assert_eq!(status, 409, "{body}");

    // A deployment without pki_encryption_key cannot store a header: 503, and
    // the same stream without one is fine.
    let mut keyless = AppState::for_test(w.db.clone(), w.auth.clone());
    keyless.ssf.outbox = None;
    let app = app!(keyless, w);
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            &streams_uri(w.tenant_id),
            Some(&w.admin_token()),
        )
        .set_json(push_body(
            "https://rp.example.test/aud-keyless",
            Some(&header_value()),
        )),
    )
    .await;
    assert_eq!(status, 503);
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            &streams_uri(w.tenant_id),
            Some(&w.admin_token()),
        )
        .set_json(push_body("https://rp.example.test/aud-keyless", None)),
    )
    .await;
    assert_eq!(status, 201, "{body}");
}

#[actix_rt::test]
async fn moving_the_endpoint_to_another_origin_needs_the_header_again() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let uri = format!("{}/{}", streams_uri(w.tenant_id), stream.id);
    let mut moved = push_body(&stream.audience, None);
    moved["endpoint_url"] = json!("https://attacker.example.test/collect");
    let (status, text) = send(
        &app,
        request(Method::PUT, &uri, Some(&w.admin_token())).set_json(moved.clone()),
    )
    .await;
    assert_eq!(status, 400);
    assert!(text.contains("authorization_header again"));
    // Explicitly cleared: accepted, and nothing follows it.
    moved["clear_authorization_header"] = json!(true);
    let (status, body) = send(
        &app,
        request(Method::PUT, &uri, Some(&w.admin_token())).set_json(moved),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(json_of(&body)["authorization_header_set"], false);
}

#[actix_rt::test]
async fn each_operation_needs_its_permission_its_tenant_and_a_human() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let reader = w.token_for(user_holding(&w.db, w.tenant_id, &["ssf_streams:read"]).await);
    let nobody = w.token_for(user_holding(&w.db, w.tenant_id, &[]).await);
    let one = format!("{}/{}", streams_uri(w.tenant_id), stream.id);
    let writes = [
        (
            Method::POST,
            streams_uri(w.tenant_id),
            push_body("https://rp.example.test/p", None),
        ),
        (Method::PUT, one.clone(), push_body(&stream.audience, None)),
        (Method::DELETE, one.clone(), Value::Null),
    ];
    for (method, uri, body) in &writes {
        let req = request(method.clone(), uri, Some(&reader));
        let req = if body.is_null() {
            req
        } else {
            req.set_json(body.clone())
        };
        let (status, _) = send(&app, req).await;
        assert_eq!(status, 403, "{method} {uri} with read only");
    }
    for uri in [streams_uri(w.tenant_id), one.clone()] {
        let (status, _) = send(&app, request(Method::GET, &uri, Some(&nobody))).await;
        assert_eq!(status, 403, "a read without ssf_streams:read");
        let (status, _) = send(&app, request(Method::GET, &uri, Some(&reader))).await;
        assert_eq!(status, 200);
    }
    // Another tenant's registry, with every permission.
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &streams_uri(w.other_tenant_id),
            Some(&w.admin_token()),
        ),
    )
    .await;
    assert_eq!(status, 403);
    // A service-account token is refused like on every human-only family.
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
    let (status, _) = send(
        &app,
        request(Method::GET, &streams_uri(w.tenant_id), Some(&machine)),
    )
    .await;
    assert_eq!(status, 401);
}

#[actix_rt::test]
async fn an_admin_status_change_announces_the_new_status() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let mut body = json!({
        "receiver_client_id": RECEIVER,
        "audience": stream.audience,
        "delivery_method": "poll",
        "events_allowed": [SsfEventType::SessionRevoked.uri()],
        "status": "disabled",
        "status_reason": "contract ended",
    });
    let (status, text) = send(
        &app,
        request(
            Method::PUT,
            &format!("{}/{}", streams_uri(w.tenant_id), stream.id),
            Some(&w.admin_token()),
        )
        .set_json(body.clone()),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let submitted = w.outbox.submitted.lock().unwrap().clone();
    assert_eq!(
        submitted.len(),
        0,
        "the recording outbox refuses a disabled stream"
    );
    // Re-enabling is announced.
    body["status"] = json!("enabled");
    let (status, _) = send(
        &app,
        request(
            Method::PUT,
            &format!("{}/{}", streams_uri(w.tenant_id), stream.id),
            Some(&w.admin_token()),
        )
        .set_json(body),
    )
    .await;
    assert_eq!(status, 200);
    let submitted = w.outbox.submitted.lock().unwrap().clone();
    assert_eq!(submitted.len(), 1);
    let (announced_for, event) = &submitted[0];
    assert_eq!(announced_for.id, stream.id);
    assert_eq!(
        event.event_uri,
        axiam_core::models::ssf::STREAM_UPDATED_EVENT_URI
    );
    assert_eq!(event.event["status"], "enabled");
    // It signs: it announces the status the stream is in.
    assert!(axiam_oauth2::ssf::sign_set(&w.auth, announced_for, event).is_ok());
}

// ---------------------------------------------------------------------------
// The receiver's stream management API (contract §31.6)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn the_receiver_api_needs_a_client_token_with_the_scope() {
    let w = world().await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let uri = format!("/ssf/v1/stream?stream_id={}", stream.id);
    let (status, _) = send(&app, request(Method::GET, &uri, None)).await;
    assert_eq!(status, 401, "no token");
    let unscoped = w.client_token(RECEIVER, w.tenant_id, &["openid"]);
    let (status, body) = send(&app, request(Method::GET, &uri, Some(&unscoped))).await;
    assert_eq!(status, 403, "a client token without ssf.manage");
    assert!(body.contains("ssf.manage"));
    let (status, _) = send(&app, request(Method::GET, &uri, Some(&w.admin_token()))).await;
    assert_eq!(status, 403, "a user token, even an administrator's");
    let (status, body) = send(&app, request(Method::GET, &uri, Some(&w.receiver_token()))).await;
    assert_eq!(status, 200, "{body}");
    let view = json_of(&body);
    assert_eq!(view["stream_id"], stream.id.to_string());
    assert_eq!(view["iss"], ROOT_ISSUER);
    assert_eq!(view["aud"], stream.audience.as_str());
    assert_eq!(view["delivery"]["method"], "urn:ietf:rfc:8936");
    assert_eq!(
        view["delivery"]["endpoint_url"],
        format!("{ROOT_ISSUER}/ssf/v1/poll/{}", stream.id)
    );
    assert_eq!(view["min_verification_interval"], 60);
}

#[actix_rt::test]
async fn another_receivers_or_another_tenants_stream_is_not_found() {
    let w = world().await;
    let mine = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let theirs = w
        .stream(
            w.tenant_id,
            OTHER_RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    // Same client_id string, another tenant.
    let foreign = w
        .stream(
            w.other_tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();
    for other in [theirs.id, foreign.id] {
        for (method, uri, body) in [
            (
                Method::GET,
                format!("/ssf/v1/stream?stream_id={other}"),
                Value::Null,
            ),
            (
                Method::GET,
                format!("/ssf/v1/status?stream_id={other}"),
                Value::Null,
            ),
            (
                Method::PATCH,
                "/ssf/v1/stream".to_owned(),
                json!({"stream_id": other, "description": "x"}),
            ),
            (
                Method::POST,
                "/ssf/v1/status".to_owned(),
                json!({"stream_id": other, "status": "paused"}),
            ),
            (
                Method::POST,
                "/ssf/v1/verify".to_owned(),
                json!({"stream_id": other}),
            ),
            (
                Method::DELETE,
                format!("/ssf/v1/stream?stream_id={other}"),
                Value::Null,
            ),
        ] {
            let req = request(method.clone(), &uri, Some(&token));
            let req = if body.is_null() {
                req
            } else {
                req.set_json(body)
            };
            let (status, _) = send(&app, req).await;
            assert_eq!(status, 404, "{method} {uri}");
        }
    }
    // The list holds only the receiver's own stream.
    let (status, body) = send(&app, request(Method::GET, "/ssf/v1/stream", Some(&token))).await;
    assert_eq!(status, 200);
    let list = json_of(&body);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["stream_id"], mine.id.to_string());
    // A receiver may not create or delete streams.
    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/stream", Some(&token)).set_json(json!({})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &format!("/ssf/v1/stream?stream_id={}", mine.id),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 403);
}

#[actix_rt::test]
async fn a_receiver_narrows_its_events_and_cannot_widen_them() {
    let w = world().await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();
    // Widening: AccountPurged is not in the administrator's allowance.
    let (status, body) = send(
        &app,
        request(Method::PATCH, "/ssf/v1/stream", Some(&token)).set_json(json!({
            "stream_id": stream.id,
            "events_requested": [SsfEventType::AccountPurged.uri()],
        })),
    )
    .await;
    assert_eq!(status, 400);
    assert!(body.contains("not allowed"));
    // Asking for an allowed one it did not have yet is fine (within the ceiling).
    let (status, body) = send(
        &app,
        request(Method::PATCH, "/ssf/v1/stream", Some(&token)).set_json(json!({
            "stream_id": stream.id,
            "events_requested": [
                SsfEventType::AccountDisabled.uri(),
                "urn:example:ignored"
            ],
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let view = json_of(&body);
    assert_eq!(
        view["events_delivered"],
        json!([SsfEventType::AccountDisabled.uri()])
    );
    assert_eq!(
        w.repo()
            .get(w.tenant_id, stream.id)
            .await
            .unwrap()
            .events_allowed
            .len(),
        3,
        "the allowance is untouched"
    );
    assert_eq!(
        w.audit_rows(w.tenant_id, "ssf_stream.receiver_updated")
            .await
            .len(),
        1
    );
}

#[actix_rt::test]
async fn a_receiver_cannot_repoint_its_endpoint_to_a_refused_address() {
    let w = world().await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();
    let header = header_value();
    for refused in [
        "https://169.254.169.254/latest/meta-data",
        "https://127.0.0.1/events",
        "https://[::1]/events",
        "https://10.1.2.3/events",
        "https://metadata.google.internal/x",
        "http://rp.example.test/events",
    ] {
        let (status, body) = send(
            &app,
            request(Method::PATCH, "/ssf/v1/stream", Some(&token)).set_json(json!({
                "stream_id": stream.id,
                "delivery": {"endpoint_url": refused, "authorization_header": header},
            })),
        )
        .await;
        assert_eq!(status, 400, "a refused endpoint");
        assert!(
            !body.contains(&header),
            "the answer never echoes the header"
        );
    }
    // Another public origin without the header again.
    let (status, _) = send(
        &app,
        request(Method::PATCH, "/ssf/v1/stream", Some(&token)).set_json(json!({
            "stream_id": stream.id,
            "delivery": {"endpoint_url": "https://other.example.test/events"},
        })),
    )
    .await;
    assert_eq!(status, 400);
    // With it: accepted, and stored sealed.
    let (status, body) = send(
        &app,
        request(Method::PATCH, "/ssf/v1/stream", Some(&token)).set_json(json!({
            "stream_id": stream.id,
            "delivery": {"endpoint_url": "https://other.example.test/events", "authorization_header": header},
        })),
    )
    .await;
    assert_eq!(status, 200);
    assert!(!body.contains(&header));
    let opened = w
        .repo()
        .decrypt_authorization_header(w.tenant_id, stream.id)
        .await
        .unwrap()
        .unwrap();
    assert!(opened.as_str() == header, "the receiver's header is stored");
    // The method is the administrator's.
    let (status, _) = send(
        &app,
        request(Method::PATCH, "/ssf/v1/stream", Some(&token)).set_json(json!({
            "stream_id": stream.id,
            "delivery": {"method": "urn:ietf:rfc:8936"},
        })),
    )
    .await;
    assert_eq!(status, 400);
}

#[actix_rt::test]
async fn the_receiver_sets_its_status_unless_an_administrator_stopped_the_stream() {
    let w = world().await;
    let running = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let stopped = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Disabled,
        )
        .await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();
    let (status, body) = send(
        &app,
        request(Method::POST, "/ssf/v1/status", Some(&token)).set_json(json!({
            "stream_id": running.id, "status": "paused", "reason": "maintenance"
        })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(json_of(&body)["status"], "paused");
    let (status, body) = send(
        &app,
        request(
            Method::GET,
            &format!("/ssf/v1/status?stream_id={}", running.id),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        json_of(&body),
        json!({"stream_id": running.id.to_string(), "status": "paused", "reason": "maintenance"})
    );
    // And back.
    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/status", Some(&token))
            .set_json(json!({"stream_id": running.id, "status": "enabled"})),
    )
    .await;
    assert_eq!(status, 200);
    // An unknown status.
    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/status", Some(&token))
            .set_json(json!({"stream_id": running.id, "status": "on"})),
    )
    .await;
    assert_eq!(status, 400);
    // What an administrator disabled stays disabled.
    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/status", Some(&token))
            .set_json(json!({"stream_id": stopped.id, "status": "enabled"})),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(
        w.repo().get(w.tenant_id, stopped.id).await.unwrap().status,
        SsfStreamStatus::Disabled
    );
}

#[actix_rt::test]
async fn the_verification_event_is_submitted_signed_on_delivery_and_rate_limited_per_stream() {
    let w = world().await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();
    let state_value = Uuid::new_v4().to_string();
    let (status, body) = send(
        &app,
        request(Method::POST, "/ssf/v1/verify", Some(&token))
            .set_json(json!({"stream_id": stream.id, "state": state_value})),
    )
    .await;
    assert_eq!(status, 204, "{body}");
    let submitted = w.outbox.submitted.lock().unwrap().clone();
    assert_eq!(submitted.len(), 1);
    let (for_stream, event) = &submitted[0];
    assert_eq!(for_stream.id, stream.id);
    assert_eq!(event.event_uri, VERIFICATION_EVENT_URI);
    assert_eq!(event.event, json!({"state": state_value}));
    assert_eq!(
        event.sub_id,
        json!({"format": "opaque", "id": stream.id.to_string()})
    );

    // Signed as delivery will sign it, it verifies against the published JWKS.
    let set = axiam_oauth2::ssf::sign_set(&w.auth, for_stream, event).unwrap();
    let jwks = axiam_oauth2::oidc::build_jwks(&w.auth.jwt_public_key_pem).unwrap();
    let key = jsonwebtoken::DecodingKey::from_ed_components(&jwks.keys[0].x).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.set_audience(&[stream.audience.as_str()]);
    validation.set_issuer(&[ROOT_ISSUER]);
    let claims = jsonwebtoken::decode::<Value>(&set, &key, &validation)
        .unwrap()
        .claims;
    assert_eq!(
        claims["events"][VERIFICATION_EVENT_URI]["state"],
        state_value.as_str()
    );

    // A second request inside min_verification_interval.
    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/verify", Some(&token))
            .set_json(json!({"stream_id": stream.id})),
    )
    .await;
    assert_eq!(status, 429);
    assert_eq!(w.outbox.submitted.lock().unwrap().len(), 1);
    assert_eq!(
        w.audit_rows(w.tenant_id, "ssf_stream.verification_requested")
            .await
            .len(),
        1
    );
}

#[actix_rt::test]
async fn verification_needs_a_live_stream_and_a_wired_outbox() {
    let w = world().await;
    let disabled = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Disabled,
        )
        .await;
    let enabled = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/verify", Some(&w.receiver_token()))
            .set_json(json!({"stream_id": disabled.id})),
    )
    .await;
    assert_eq!(status, 400, "a disabled stream transmits nothing");
    assert!(w.outbox.submitted.lock().unwrap().is_empty());

    let mut unwired = w.state();
    unwired.ssf.outbox = None;
    let app = app!(unwired, w);
    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/verify", Some(&w.receiver_token()))
            .set_json(json!({"stream_id": enabled.id})),
    )
    .await;
    assert_eq!(status, 503);
}

#[actix_rt::test]
async fn with_the_transmitter_off_the_receiver_sees_no_stream() {
    let w = world().await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    w.ssf_off_for(w.tenant_id).await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &format!("/ssf/v1/stream?stream_id={}", stream.id),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 404);
    let (status, body) = send(&app, request(Method::GET, "/ssf/v1/stream", Some(&token))).await;
    assert_eq!(status, 200);
    assert_eq!(json_of(&body), json!([]));
    // The administrator still manages it (D-45).
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &format!("{}/{}", streams_uri(w.tenant_id), stream.id),
            Some(&w.admin_token()),
        ),
    )
    .await;
    assert_eq!(status, 200);
}

// ---------------------------------------------------------------------------
// Discovery (D-45)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn discovery_on_the_root_issuer_lists_the_endpoints_and_events() {
    let w = world().await;
    let app = app!(w.state(), w);
    let (status, body) = send(
        &app,
        request(
            Method::GET,
            &format!("/.well-known/ssf-configuration?tenant_id={}", w.tenant_id),
            None,
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let doc = json_of(&body);
    assert_eq!(doc["spec_version"], "1_0");
    assert_eq!(doc["issuer"], ROOT_ISSUER);
    assert_eq!(doc["jwks_uri"], format!("{ROOT_ISSUER}/oauth2/jwks"));
    assert_eq!(
        doc["configuration_endpoint"],
        format!("{ROOT_ISSUER}/ssf/v1/stream")
    );
    assert_eq!(
        doc["status_endpoint"],
        format!("{ROOT_ISSUER}/ssf/v1/status")
    );
    assert_eq!(
        doc["verification_endpoint"],
        format!("{ROOT_ISSUER}/ssf/v1/verify")
    );
    assert_eq!(
        doc["delivery_methods_supported"],
        json!(["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"])
    );
    assert_eq!(
        doc["events_supported"],
        json!(SsfEventType::uris(&SsfEventType::ALL))
    );
    assert_eq!(
        doc["authorization_schemes"],
        json!([{"spec_urn": "urn:ietf:rfc:6749"}])
    );
    assert!(doc.get("add_subject_endpoint").is_none());
}

#[actix_rt::test]
async fn discovery_on_a_tenant_path_issuer_names_the_tenant_issuer() {
    let w = world_with(true).await;
    let app = app!(w.state(), w, permissive_limits(), true);
    let tenant_iss = format!("{ROOT_ISSUER}/t/{}", w.tenant_id);
    for uri in [
        format!("/.well-known/ssf-configuration/t/{}", w.tenant_id),
        format!("/.well-known/ssf-configuration?tenant_id={}", w.tenant_id),
    ] {
        let (status, body) = send(&app, request(Method::GET, &uri, None)).await;
        assert_eq!(status, 200, "{uri}");
        let doc = json_of(&body);
        assert_eq!(doc["issuer"], tenant_iss.as_str());
        assert_eq!(doc["jwks_uri"], format!("{tenant_iss}/oauth2/jwks"));
        assert_eq!(
            doc["configuration_endpoint"],
            format!("{ROOT_ISSUER}/ssf/v1/stream")
        );
    }
    // The tenant path form does not exist without tenant issuers.
    let w2 = world().await;
    let app = app!(w2.state(), w2);
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &format!("/.well-known/ssf-configuration/t/{}", w2.tenant_id),
            None,
        ),
    )
    .await;
    assert_eq!(status, 404);
}

#[actix_rt::test]
async fn discovery_answers_one_empty_404_for_every_way_of_having_nothing_to_say() {
    let w = world_with(true).await;
    w.ssf_off_for(w.other_tenant_id).await;
    let app = app!(w.state(), w, permissive_limits(), true);
    let mut answers = Vec::new();
    for uri in [
        format!(
            "/.well-known/ssf-configuration?tenant_id={}",
            w.other_tenant_id
        ),
        format!("/.well-known/ssf-configuration/t/{}", w.other_tenant_id),
        format!(
            "/.well-known/ssf-configuration?tenant_id={}",
            Uuid::new_v4()
        ),
        format!("/.well-known/ssf-configuration/t/{}", Uuid::new_v4()),
        "/.well-known/ssf-configuration?tenant_id=not-a-uuid".to_owned(),
        "/.well-known/ssf-configuration".to_owned(),
        "/.well-known/ssf-configuration/t/not-a-uuid".to_owned(),
    ] {
        let (status, body) = send(&app, request(Method::GET, &uri, None)).await;
        assert_eq!(status, 404, "{uri}");
        answers.push(body);
    }
    assert!(answers.iter().all(|b| b.is_empty()), "every 404 is empty");
}

// ---------------------------------------------------------------------------
// Rate-limit buckets (plan §7 rule 6), pinned
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn every_ssf_route_has_its_own_bucket() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let limits = RateLimitConfig {
        ssf_per_min: 2,
        ssf_admin_per_min: 1,
        ..RateLimitConfig::default()
    };
    let app = app!(w.state(), w, limits, false);
    let token = w.receiver_token();
    let status_uri = format!("/ssf/v1/status?stream_id={}", stream.id);
    for expected in [200, 200, 429] {
        let (status, _) = send(&app, request(Method::GET, &status_uri, Some(&token))).await;
        assert_eq!(status, expected, "status endpoint");
    }
    // Another route's bucket is untouched.
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &format!("/ssf/v1/stream?stream_id={}", stream.id),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 200, "the stream endpoint has its own bucket");
    let discovery = format!("/.well-known/ssf-configuration?tenant_id={}", w.tenant_id);
    for expected in [200, 200, 429] {
        let (status, _) = send(&app, request(Method::GET, &discovery, None)).await;
        assert_eq!(status, expected, "discovery");
    }
    // The administrator's create bucket.
    for (expected, aud) in [
        (201, "https://rp.example.test/rl1"),
        (429, "https://rp.example.test/rl2"),
    ] {
        let (status, _) = send(
            &app,
            request(
                Method::POST,
                &streams_uri(w.tenant_id),
                Some(&w.admin_token()),
            )
            .set_json(push_body(aud, None)),
        )
        .await;
        assert_eq!(status, expected, "create bucket");
    }
    // Reads of the registry are not limited.
    for _ in 0..3 {
        let (status, _) = send(
            &app,
            request(
                Method::GET,
                &streams_uri(w.tenant_id),
                Some(&w.admin_token()),
            ),
        )
        .await;
        assert_eq!(status, 200);
    }
}

#[actix_rt::test]
async fn the_seeded_permissions_include_the_ssf_family() {
    let w = world().await;
    let all = SurrealPermissionRepository::new(w.db.clone())
        .list(w.tenant_id, all_pages())
        .await
        .unwrap()
        .items;
    for wanted in ["ssf_streams:read", "ssf_streams:write"] {
        assert!(all.iter().any(|p| p.action == wanted), "{wanted}");
    }
    assert!(axiam_api_rest::permissions::HUMAN_ONLY_FAMILIES.contains(&"ssf_streams"));
    // Unused helper kept honest: the receiver client exists when named.
    with_receiver_client(&w).await;
    assert!(
        SurrealOAuth2ClientRepository::new(w.db.clone())
            .list(w.tenant_id, all_pages())
            .await
            .unwrap()
            .total
            >= 1
    );
}

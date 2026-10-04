//! **T23.5.2** — the SSF transmitter over HTTP (G-5, contract §32, D-45 …
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
use axiam_core::models::session::{Amr, CreateSession, Session};
use axiam_core::models::settings::{SetTenantOverride, system_defaults};
use axiam_core::models::ssf::{
    NewSsfStream, SsfDeliveryMethod, SsfEventType, SsfFuture, SsfOutbox, SsfOutboxError,
    SsfPendingEvent, SsfStatusActor, SsfStream, SsfStreamStatus, SsfStreamUpdate, SsfSubjectFormat,
    VERIFICATION_EVENT_URI,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::models::webauthn_credential::{CreateWebauthnCredential, WebauthnCredentialType};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OAuth2ClientRepository, OrganizationRepository, Pagination,
    PermissionRepository, RoleRepository, ServiceAccountRepository, SessionRepository,
    SettingsRepository, SsfEventBufferRepository, SsfStepUpRepository, SsfStreamRepository,
    TenantRepository, UserRepository, WebauthnCredentialRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealServiceAccountRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealSsfEventBufferRepository,
    SurrealSsfStepUpRepository, SurrealSsfStreamRepository, SurrealTenantRepository,
    SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use axiam_oauth2::ssf::{SharedIssuerCheck, SsfIssuerGate};
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
        // A TOTP authenticator is sealed under this key (T23.5.3's enrolment test).
        mfa_encryption_key: Some(runtime_bytes()),
        totp_issuer: "AXIAM-Test".into(),
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
    /// The second tenant of a two-tenant world ([`world_of`]).
    other_tenant_id: Option<Uuid>,
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

/// A world of `tenants` tenants (1 or 2) in one organization whose baseline has
/// SSF on, with `tenant_paths` as the deployment's issuer mode.
///
/// D-55: SSF is off for every tenant of a deployment of more than one tenant
/// without per-tenant issuers, so a world that needs SSF *and* a second tenant
/// runs with paths on; two tenants with paths off is a world in which only the
/// stream registry works.
async fn world_of(tenants: usize, tenant_paths: bool) -> World {
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
    let other_tenant_id = if tenants > 1 {
        Some(tenant_in(&db, org.id, "ssf-other").await)
    } else {
        None
    };
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

/// One tenant, the root issuer.
async fn world() -> World {
    world_of(1, false).await
}

/// Two tenants with per-tenant issuers: SSF works for both.
async fn world_with(tenant_paths: bool) -> World {
    world_of(2, tenant_paths).await
}

impl World {
    /// The second tenant; only a two-tenant world has one.
    fn other_tenant(&self) -> Uuid {
        self.other_tenant_id.expect("a two-tenant world")
    }

    /// The D-55 reading for this world, as the transmitter makes it.
    fn issuer_check(&self) -> SharedIssuerCheck {
        let tenants = if self.other_tenant_id.is_some() { 2 } else { 1 };
        SharedIssuerCheck::evaluate(self.auth.tenant_issuer_paths, tenants)
    }

    /// A D-55 gate over this world's datastore, as the server builds one.
    fn gate(&self) -> Arc<SsfIssuerGate> {
        Arc::new(SsfIssuerGate::new(
            self.auth.tenant_issuer_paths,
            Arc::new(SurrealTenantRepository::new(self.db.clone())),
        ))
    }

    /// The issuer this world's SETs carry for the home tenant.
    fn issuer(&self) -> String {
        if self.auth.tenant_issuer_paths {
            format!("{ROOT_ISSUER}/t/{}", self.tenant_id)
        } else {
            ROOT_ISSUER.to_owned()
        }
    }

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
        // Binds the emitter too (T23.5.3), so the change sites emit into the
        // recording outbox as they do into the real one.
        state
            .ssf
            .bind_outbox(self.outbox.clone() as Arc<dyn SsfOutbox>);
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
        app!($state, $w, permissive_limits(), $w.auth.tenant_issuer_paths)
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
// The management API (contract §32.1 – §32.3)
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
    // Two tenants and one issuer (D-55): SSF is off, the registry still works.
    let w = world_of(2, false).await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    // The other tenant already uses the audience.
    let taken = w
        .stream(
            w.other_tenant(),
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
    // Two tenants and one issuer (D-55): SSF is off, the registry still works.
    let w = world_of(2, false).await;
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
            &streams_uri(w.other_tenant()),
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
    assert!(axiam_oauth2::ssf::sign_set(&w.auth, w.issuer_check(), announced_for, event).is_ok());
}

#[actix_rt::test]
async fn a_status_change_is_not_announced_while_ssf_is_off_for_the_tenant() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    let stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Paused,
        )
        .await;
    w.ssf_off_for(w.tenant_id).await;
    let app = app!(w.state(), w);
    let mut body = json!({
        "receiver_client_id": RECEIVER,
        "audience": stream.audience,
        "delivery_method": "poll",
        "events_allowed": [SsfEventType::SessionRevoked.uri()],
        "status": "enabled",
    });
    // The administrator's write goes through: streams are registered before the
    // switch is turned on.
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
    assert!(
        w.outbox.submitted.lock().unwrap().is_empty(),
        "nothing is announced while the tenant's switch is off"
    );

    // The same change with the switch on is announced.
    SurrealSettingsRepository::new(w.db.clone())
        .set_tenant_override(
            w.tenant_id,
            SetTenantOverride {
                ssf_enabled: Some(true),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    body["status"] = json!("paused");
    let (status, _) = send(
        &app,
        request(
            Method::PUT,
            &format!("{}/{}", streams_uri(w.tenant_id), stream.id),
            Some(&w.admin_token()),
        )
        .set_json(body.clone()),
    )
    .await;
    assert_eq!(status, 200);
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
    assert!(
        submitted
            .iter()
            .any(|(_, e)| e.event["status"] == "enabled"),
        "the enabled status is announced once the switch is on"
    );
}

// ---------------------------------------------------------------------------
// assurance-level-change: the step-up record (D-53 (1))
// ---------------------------------------------------------------------------

const ACR_1FA: &str = "urn:axiam:acr:1fa";
const ACR_MFA: &str = "urn:axiam:acr:mfa";
const RP_CALLBACK: &str = "https://rp.example.com/callback";

/// A tenant whose receiver carries `assurance-level-change`, an honour-lane
/// OAuth2 client, and the recording outbox in place of delivery.
struct StepUpWorld {
    w: World,
    client_id: String,
}

async fn step_up_world() -> StepUpWorld {
    let w = world().await;
    w.repo()
        .create(NewSsfStream {
            tenant_id: w.tenant_id,
            receiver_client_id: RECEIVER.into(),
            audience: format!("https://rp.example.test/aud/{}", Uuid::new_v4().simple()),
            description: None,
            delivery_method: SsfDeliveryMethod::Poll,
            endpoint_url: None,
            authorization_header: None,
            events_allowed: vec![SsfEventType::AssuranceLevelChange],
            events_requested: vec![SsfEventType::AssuranceLevelChange],
            subject_format: SsfSubjectFormat::IssSub,
            status: SsfStreamStatus::Enabled,
            status_reason: None,
        })
        .await
        .unwrap();
    let input: CreateOAuth2Client = serde_json::from_value(json!({
        "tenant_id": w.tenant_id,
        "name": "Step-up RP",
        "redirect_uris": [RP_CALLBACK],
        "grant_types": ["authorization_code"],
        "scopes": ["openid"],
        "authn_request_params": "honour",
        "browser_sso": true,
    }))
    .expect("an honour-lane client");
    let (client, _issued) = SurrealOAuth2ClientRepository::new(w.db.clone())
        .create(input)
        .await
        .unwrap();
    StepUpWorld {
        w,
        client_id: client.client_id,
    }
}

impl StepUpWorld {
    /// A session of `user` with the given evidence, and the token that arrives
    /// as it (`jti` = the session id, the convention the authorize handler
    /// reads).
    async fn session(&self, user: Uuid, amr: Vec<Amr>) -> (Uuid, String) {
        let session = SurrealSessionRepository::new(self.w.db.clone())
            .create(CreateSession {
                tenant_id: self.w.tenant_id,
                user_id: user,
                token_hash: axiam_auth::token::hash_refresh_token(&Uuid::new_v4().to_string()),
                ip_address: None,
                user_agent: None,
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                authenticated_at: chrono::Utc::now(),
                amr,
                browser_token_hash: None,
            })
            .await
            .unwrap();
        let token = issue_access_token(
            user,
            self.w.tenant_id,
            self.w.org_id,
            &[],
            &self.w.auth,
            session.id.to_string(),
            AUD_USER,
        )
        .unwrap();
        (session.id, token)
    }

    async fn user(&self, name: &str) -> Uuid {
        active_user(
            &self.w.db,
            self.w.tenant_id,
            &format!("{name}-{}", Uuid::new_v4().simple()),
        )
        .await
    }

    /// `GET /oauth2/authorize` as `token`; the status and the `Location`.
    async fn authorize<S, B>(&self, app: &S, token: &str, extra: &str) -> (u16, String)
    where
        S: actix_web::dev::Service<
                actix_http::Request,
                Response = actix_web::dev::ServiceResponse<B>,
                Error = actix_web::Error,
            >,
        B: actix_web::body::MessageBody,
    {
        let resp = test::call_service(
            app,
            request(
                Method::GET,
                &format!(
                    "/oauth2/authorize?response_type=code&client_id={}&redirect_uri={RP_CALLBACK}\
                     &scope=openid&state=step-up{extra}",
                    self.client_id
                ),
                Some(token),
            )
            .to_request(),
        )
        .await;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        (status, location)
    }

    /// The step-up request: the relying party wants multi-factor.
    async fn ask_for_mfa<S, B>(&self, app: &S, token: &str) -> (u16, String)
    where
        S: actix_web::dev::Service<
                actix_http::Request,
                Response = actix_web::dev::ServiceResponse<B>,
                Error = actix_web::Error,
            >,
        B: actix_web::body::MessageBody,
    {
        self.authorize(app, token, &format!("&acr_values={ACR_MFA}"))
            .await
    }

    /// The return leg of the login hop: the marker the sign-in page adds, with
    /// no acr preference left to satisfy.
    async fn return_leg<S, B>(&self, app: &S, token: &str) -> (u16, String)
    where
        S: actix_web::dev::Service<
                actix_http::Request,
                Response = actix_web::dev::ServiceResponse<B>,
                Error = actix_web::Error,
            >,
        B: actix_web::body::MessageBody,
    {
        self.authorize(app, token, "&axiam_login_hop=1").await
    }

    fn records(&self) -> SurrealSsfStepUpRepository<TestDb> {
        SurrealSsfStepUpRepository::new(self.w.db.clone())
    }

    async fn record_count(&self) -> u64 {
        self.records()
            .count_for_tenant(self.w.tenant_id)
            .await
            .unwrap()
    }

    fn told(&self) -> Vec<SsfPendingEvent> {
        self.w
            .outbox
            .submitted
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.event_uri == SsfEventType::AssuranceLevelChange.uri())
            .map(|(_, e)| e.clone())
            .collect()
    }
}

fn mfa_evidence() -> Vec<Amr> {
    vec![Amr::Pwd, Amr::Otp, Amr::Mfa]
}

/// The upgrade: a password session sent to step up, back with an MFA session of
/// the same user. One event, `previous_level` the password class, the direction
/// from the published order, the user the initiator, the subject the user.
#[actix_rt::test]
async fn a_step_up_upgrade_emits_assurance_level_change_with_previous_level_and_direction() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("upgrade").await;
    let (first, first_token) = su.session(user, vec![Amr::Pwd]).await;

    let (status, location) = su.ask_for_mfa(&app, &first_token).await;
    assert_eq!(status, 302);
    assert!(location.starts_with("/login?"), "the step-up interaction");
    assert_eq!(su.record_count().await, 1, "the Interact leg remembered it");
    assert!(su.told().is_empty(), "nothing is told until the return leg");

    let (second, second_token) = su.session(user, mfa_evidence()).await;
    assert_ne!(first, second);
    let (status, location) = su.return_leg(&app, &second_token).await;
    assert_eq!(status, 302);
    assert!(location.starts_with(RP_CALLBACK), "the code is issued");

    let told = su.told();
    assert_eq!(told.len(), 1, "one assurance-level-change");
    let event = &told[0].event;
    assert_eq!(event["namespace"], "urn:axiam:acr");
    assert_eq!(event["previous_level"], ACR_1FA);
    assert_eq!(event["current_level"], ACR_MFA);
    assert_eq!(event["change_direction"], "increase");
    assert_eq!(event["initiating_entity"], "user");
    assert_eq!(
        told[0].sub_id,
        json!({"format": "iss_sub", "iss": ROOT_ISSUER, "sub": user.to_string()})
    );
    assert_eq!(su.record_count().await, 0, "the record was consumed");
}

/// "Only when the `acr` differs": a step-up that came back at the same level
/// tells nobody — and the record is still spent.
#[actix_rt::test]
async fn a_return_with_the_same_acr_emits_nothing() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("same-acr").await;
    let (_, first_token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &first_token).await.0, 302);
    assert_eq!(su.record_count().await, 1);

    let (_, second_token) = su.session(user, vec![Amr::Pwd]).await;
    let (status, _) = su.return_leg(&app, &second_token).await;
    assert_eq!(status, 302);

    assert!(su.told().is_empty(), "1fa back to 1fa is not a change");
    assert_eq!(su.record_count().await, 0, "and the record is spent");
}

/// The same session coming back is nothing stepped up, whatever its level —
/// and, since F4 W4 (P23W4-02), it does not spend the record either: the
/// session the step-up was asked of is not the one that will come back from
/// it, so a return leg in that session is not the return of this step-up.
#[actix_rt::test]
async fn the_same_session_returning_emits_nothing() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("same-session").await;
    let (_, token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &token).await.0, 302);

    let (status, _) = su.return_leg(&app, &token).await;
    assert_eq!(status, 302);

    assert!(su.told().is_empty());
    assert_eq!(
        su.record_count().await,
        1,
        "a return leg in the session that was asked to step up does not spend the record"
    );
}

/// F4 W4 P23W4-02 (T-404): the return-leg marker is a query parameter anyone
/// can put on a link. A page that sends the user's browser to
/// `/oauth2/authorize?axiam_login_hop=1` — no client, or a request the
/// authorization endpoint refuses — must not spend the user's step-up record
/// (which would suppress the `assurance-level-change` the real return leg
/// should produce), and must not produce one either.
#[actix_rt::test]
async fn a_return_leg_the_authorization_endpoint_refuses_spends_nothing() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("forged-return").await;
    let (_, first_token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &first_token).await.0, 302);
    assert_eq!(su.record_count().await, 1);

    // Mid step-up: the user now holds an MFA session; a third-party page
    // navigates the browser to the return-leg marker with no valid request.
    let (_, second_token) = su.session(user, mfa_evidence()).await;
    for forged in [
        "/oauth2/authorize?axiam_login_hop=1".to_owned(),
        format!(
            "/oauth2/authorize?axiam_login_hop=1&response_type=code&client_id=no-such-client\
             &redirect_uri={RP_CALLBACK}&scope=openid"
        ),
        format!(
            "/oauth2/authorize?axiam_login_hop=1&response_type=code&client_id={}\
             &redirect_uri=https://attacker.example.test/cb&scope=openid",
            su.client_id
        ),
    ] {
        let resp = test::call_service(
            &app,
            request(Method::GET, &forged, Some(&second_token)).to_request(),
        )
        .await;
        assert_ne!(resp.status().as_u16(), 500);
    }
    assert!(su.told().is_empty(), "a refused request tells nobody");
    assert_eq!(su.record_count().await, 1, "and spends nothing");

    // The real return leg still produces the event.
    let (status, location) = su.return_leg(&app, &second_token).await;
    assert_eq!(status, 302);
    assert!(location.starts_with(RP_CALLBACK));
    assert_eq!(su.told().len(), 1);
    assert_eq!(su.record_count().await, 0);
}

/// A different user's return leg neither emits nor spends the record.
#[actix_rt::test]
async fn a_different_users_return_leg_emits_nothing_and_leaves_the_record() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let (user, other) = (su.user("owner").await, su.user("other").await);
    let (_, first_token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &first_token).await.0, 302);

    let (_, others_token) = su.session(other, mfa_evidence()).await;
    let (status, _) = su.return_leg(&app, &others_token).await;
    assert_eq!(status, 302);
    assert!(
        su.told().is_empty(),
        "another person's sign-in tells nothing"
    );
    assert_eq!(
        su.record_count().await,
        1,
        "the owner's record is untouched"
    );

    // The owner's own return still works.
    let (_, owners_new) = su.session(user, mfa_evidence()).await;
    assert_eq!(su.return_leg(&app, &owners_new).await.0, 302);
    assert_eq!(su.told().len(), 1);
}

/// An expired record is no record.
#[actix_rt::test]
async fn an_expired_record_emits_nothing() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("expired").await;
    let (_, first_token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &first_token).await.0, 302);
    su.w.db
        .query("UPDATE ssf_step_up SET expires_at = time::now() - 1m")
        .await
        .unwrap()
        .check()
        .unwrap();

    let (_, second_token) = su.session(user, mfa_evidence()).await;
    assert_eq!(su.return_leg(&app, &second_token).await.0, 302);

    assert!(su.told().is_empty(), "ten minutes had passed");
    assert_eq!(su.record_count().await, 0);
}

/// Single use: a second return leg (a replay, or a second tab) finds nothing.
#[actix_rt::test]
async fn a_step_up_record_is_consumed_once() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("once").await;
    let (_, first_token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &first_token).await.0, 302);

    let (_, second_token) = su.session(user, mfa_evidence()).await;
    assert_eq!(su.return_leg(&app, &second_token).await.0, 302);
    assert_eq!(su.told().len(), 1);

    let (_, third_token) = su.session(user, mfa_evidence()).await;
    assert_eq!(su.return_leg(&app, &third_token).await.0, 302);
    assert_eq!(su.return_leg(&app, &second_token).await.0, 302);
    assert_eq!(su.told().len(), 1, "a replayed return leg tells nobody");
}

/// A later step-up replaces an earlier one: the return leg reports the level
/// the **latest** step-up started from.
#[actix_rt::test]
async fn the_latest_step_up_replaces_the_earlier_one() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("latest").await;
    let (_, first_token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &first_token).await.0, 302);
    let (_, again_token) = su.session(user, vec![Amr::Pwd]).await;
    assert_eq!(su.ask_for_mfa(&app, &again_token).await.0, 302);
    assert_eq!(su.record_count().await, 1, "one record per user");

    let (_, stepped) = su.session(user, mfa_evidence()).await;
    assert_eq!(su.return_leg(&app, &stepped).await.0, 302);
    assert_eq!(su.told().len(), 1);
}

/// "No OP session means no record": a request that arrives with no session
/// behind it is sent to sign in, and nothing is remembered about a level that
/// was never achieved.
#[actix_rt::test]
async fn without_a_valid_op_session_no_step_up_record_is_written() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("no-session").await;
    // A token whose `jti` names no session row.
    let token = issue_access_token(
        user,
        su.w.tenant_id,
        su.w.org_id,
        &[],
        &su.w.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();

    let (status, location) = su.ask_for_mfa(&app, &token).await;
    assert_eq!(status, 302);
    assert!(location.starts_with("/login?"), "sent to sign in");
    assert_eq!(su.record_count().await, 0);

    // …and the return leg of that hop has nothing to consume or tell.
    let (_, new_token) = su.session(user, mfa_evidence()).await;
    assert_eq!(su.return_leg(&app, &new_token).await.0, 302);
    assert!(su.told().is_empty());
}

/// Only a step-up is remembered: `prompt=login` interacts too, with a valid
/// session, and is not one.
#[actix_rt::test]
async fn an_interaction_that_is_not_a_step_up_writes_no_record() {
    let su = step_up_world().await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("prompt-login").await;
    let (_, token) = su.session(user, vec![Amr::Pwd]).await;

    let (status, location) = su.authorize(&app, &token, "&prompt=login").await;
    assert_eq!(status, 302);
    assert!(location.starts_with("/login?"));
    assert_eq!(su.record_count().await, 0);
}

/// D-45: with SSF off for the tenant nothing is produced, and nothing is
/// remembered for a producer that will not be told.
#[actix_rt::test]
async fn with_ssf_off_for_the_tenant_no_step_up_record_is_written() {
    let su = step_up_world().await;
    su.w.ssf_off_for(su.w.tenant_id).await;
    let app = app!(su.w.state(), su.w);
    let user = su.user("ssf-off").await;
    let (_, first_token) = su.session(user, vec![Amr::Pwd]).await;

    assert_eq!(su.ask_for_mfa(&app, &first_token).await.0, 302);
    assert_eq!(su.record_count().await, 0);
    let (_, second_token) = su.session(user, mfa_evidence()).await;
    assert_eq!(su.return_leg(&app, &second_token).await.0, 302);
    assert!(su.told().is_empty());
}

// ---------------------------------------------------------------------------
// The receiver's stream management API (contract §32.6)
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
    // Two tenants need their own issuers for SSF to run (D-55).
    let w = world_with(true).await;
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
            w.other_tenant(),
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
    let set = axiam_oauth2::ssf::sign_set(&w.auth, w.issuer_check(), for_stream, event).unwrap();
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
    w.ssf_off_for(w.other_tenant()).await;
    let app = app!(w.state(), w, permissive_limits(), true);
    let mut answers = Vec::new();
    for uri in [
        format!(
            "/.well-known/ssf-configuration?tenant_id={}",
            w.other_tenant()
        ),
        format!("/.well-known/ssf-configuration/t/{}", w.other_tenant()),
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

// ===========================================================================
// T23.5.3 — poll delivery (RFC 8936, D-48)
// ===========================================================================

use axiam_oauth2::ssf::{InitiatingEntity, SsfEvent, SsfSubject, prepare_event, sign_set};
use chrono::{Duration, Utc};

fn poll_uri(stream_id: Uuid) -> String {
    format!("/ssf/v1/poll/{stream_id}")
}

fn buffer(w: &World) -> SurrealSsfEventBufferRepository<TestDb> {
    SurrealSsfEventBufferRepository::new(w.db.clone())
}

/// A session-revoked event about a made-up user, as the emitter would have
/// prepared it for `stream`.
fn held_event(w: &World, stream: &SsfStream) -> SsfPendingEvent {
    prepare_event(
        &w.auth,
        stream,
        &SsfEvent::SessionRevoked {
            initiating_entity: Some(InitiatingEntity::Admin),
            event_timestamp: Utc::now().timestamp(),
        },
        &SsfSubject {
            user_id: Uuid::new_v4(),
            email: None,
            email_vouched: false,
            session_id: Some(Uuid::new_v4()),
        },
        Some("txn-held"),
        Utc::now(),
    )
    .unwrap()
}

/// `n` events held for `stream`, oldest first.
async fn hold(w: &World, stream: &SsfStream, n: usize) -> Vec<SsfPendingEvent> {
    let repo = buffer(w);
    let start = Utc::now();
    let mut out = Vec::new();
    for i in 0..n {
        let event = held_event(w, stream);
        repo.push(
            stream.tenant_id,
            stream.id,
            &event,
            start + Duration::milliseconds(i as i64),
        )
        .await
        .unwrap();
        out.push(event);
    }
    out
}

async fn set_status_via_repo(w: &World, stream: &SsfStream, status: SsfStreamStatus) {
    // From the stream as it is now: an update carries the version it was
    // prepared from (F4 W4 P23W4-01).
    let current = w.repo().get(stream.tenant_id, stream.id).await.unwrap();
    let mut update = SsfStreamUpdate::from_stream(&current);
    update.status = status;
    w.repo()
        .update(stream.tenant_id, stream.id, update)
        .await
        .unwrap();
}

/// Verify `set` against the JWKS AXIAM publishes, the way a receiver does.
fn verify_set(w: &World, set: &str, audience: &str) -> Value {
    let jwks = axiam_oauth2::oidc::build_jwks(&w.auth.jwt_public_key_pem).unwrap();
    let header = jsonwebtoken::decode_header(set).unwrap();
    let jwk = jwks
        .keys
        .iter()
        .find(|k| Some(&k.kid) == header.kid.as_ref())
        .expect("the header's kid is in the JWKS");
    let key = jsonwebtoken::DecodingKey::from_ed_components(&jwk.x).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.set_audience(&[audience]);
    validation.set_issuer(&[w.issuer()]);
    jsonwebtoken::decode::<Value>(set, &key, &validation)
        .expect("the SET verifies against the JWKS")
        .claims
}

async fn poll_with<S, B>(app: &S, token: &str, stream_id: Uuid, body: Value) -> (u16, Value)
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
        request(Method::POST, &poll_uri(stream_id), Some(token)).set_json(body),
    )
    .await;
    (status, json_of(&text))
}

#[actix_rt::test]
async fn a_poll_returns_held_events_as_signed_sets_and_an_unacknowledged_one_comes_back() {
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
    let held = hold(&w, &stream, 3).await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();

    let (status, first) =
        poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
    assert_eq!(status, 200);
    assert_eq!(first["moreAvailable"], false);
    let sets = first["sets"].as_object().unwrap();
    assert_eq!(sets.len(), 3);
    for event in &held {
        let set = sets[&event.jti].as_str().unwrap();
        let claims = verify_set(&w, set, &stream.audience);
        assert_eq!(claims["jti"], event.jti.as_str());
        assert_eq!(claims["txn"], "txn-held");
        assert!(claims.get("exp").is_none() && claims.get("sub").is_none());
    }

    // Nothing was acknowledged: the same SETs, byte for byte, come back.
    let (_, second) = poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
    assert!(first["sets"] == second["sets"]);
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 3);
}

/// D-48: `ack` deletes exactly the named rows of that stream, and an event
/// acknowledged in a request is not returned by it.
#[actix_rt::test]
async fn an_acknowledgement_drains_exactly_the_named_rows_of_that_stream() {
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
    let sibling = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let held = hold(&w, &stream, 3).await;
    // The sibling stream holds an event with the very same jti.
    buffer(&w)
        .push(w.tenant_id, sibling.id, &held[0], Utc::now())
        .await
        .unwrap();
    let app = app!(w.state(), w);
    let token = w.receiver_token();

    let (status, answer) = poll_with(
        &app,
        &token,
        stream.id,
        json!({"returnImmediately": true, "ack": [held[0].jti, held[1].jti, "not-a-jti"]}),
    )
    .await;
    assert_eq!(status, 200);
    let sets = answer["sets"].as_object().unwrap();
    assert_eq!(sets.len(), 1, "what was acknowledged is not returned");
    assert!(sets.contains_key(&held[2].jti));
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 1);
    assert_eq!(
        buffer(&w).count(w.tenant_id, sibling.id).await.unwrap(),
        1,
        "another stream's row with the same jti is untouched"
    );

    // Acknowledging the rest drains the buffer.
    let (_, answer) = poll_with(
        &app,
        &token,
        stream.id,
        json!({"returnImmediately": true, "ack": [held[2].jti]}),
    )
    .await;
    assert!(answer["sets"].as_object().unwrap().is_empty());
    assert_eq!(answer["moreAvailable"], false);
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 0);
}

/// RFC 8936 §2.4: a `setErrs` entry deletes its row and is audited with the
/// `err` code; the receiver's description is not stored.
#[actix_rt::test]
async fn a_set_error_deletes_the_row_and_writes_an_audit_row_with_the_code() {
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
    let held = hold(&w, &stream, 3).await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();
    let free_text = format!("call {}", Uuid::new_v4().simple());
    let unknown = "0123456789abcdef0123456789abcdef";

    let (status, answer) = poll_with(
        &app,
        &token,
        stream.id,
        json!({
            "returnImmediately": true,
            "setErrs": {
                held[0].jti.clone(): {"err": "invalid_key", "description": free_text},
                held[1].jti.clone(): {"err": "made up by the receiver"},
                unknown: {"err": "invalid_issuer"},
            },
        }),
    )
    .await;
    assert_eq!(status, 200);
    // Both reported rows are gone; the third event is offered.
    assert_eq!(answer["sets"].as_object().unwrap().len(), 1);
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 1);

    let rows = w.audit_rows(w.tenant_id, "ssf_stream.poll_set_error").await;
    assert_eq!(rows.len(), 3);
    let find = |jti: &str| {
        rows.iter()
            .find(|r| r.metadata["jti"] == jti)
            .expect("an audit row for the jti")
    };
    assert_eq!(find(&held[0].jti).metadata["err"], "invalid_key");
    assert_eq!(find(&held[0].jti).metadata["held"], true);
    assert_eq!(find(&held[1].jti).metadata["err"], "unrecognized");
    assert_eq!(find(unknown).metadata["err"], "invalid_issuer");
    assert_eq!(find(unknown).metadata["held"], false);
    for row in &rows {
        assert_eq!(row.resource_id, Some(stream.id));
        assert!(!row.metadata.to_string().contains(&free_text));
    }
}

/// D-48: `maxEvents` is clamped to 100, `0` acknowledges only, oldest first.
#[actix_rt::test]
async fn max_events_is_clamped_and_the_oldest_come_first() {
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
    let held = hold(&w, &stream, 105).await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();

    let (_, answer) = poll_with(
        &app,
        &token,
        stream.id,
        json!({"returnImmediately": true, "maxEvents": 1_000_000}),
    )
    .await;
    assert_eq!(answer["sets"].as_object().unwrap().len(), 100);
    assert_eq!(answer["moreAvailable"], true);

    let (_, answer) = poll_with(
        &app,
        &token,
        stream.id,
        json!({"returnImmediately": true, "maxEvents": 2}),
    )
    .await;
    let sets = answer["sets"].as_object().unwrap();
    assert_eq!(sets.len(), 2);
    assert!(sets.contains_key(&held[0].jti) && sets.contains_key(&held[1].jti));
    assert_eq!(answer["moreAvailable"], true);

    // Zero asks for the acknowledgements only: nothing is returned, and the
    // acknowledgement is still applied.
    let (status, answer) = poll_with(
        &app,
        &token,
        stream.id,
        json!({"maxEvents": 0, "ack": [held[0].jti]}),
    )
    .await;
    assert_eq!(status, 200);
    assert!(answer["sets"].as_object().unwrap().is_empty());
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 104);

    let (status, _) = poll_with(&app, &token, stream.id, json!({"maxEvents": -1})).await;
    assert_eq!(status, 400);
}

#[actix_rt::test]
async fn an_empty_poll_returns_at_once_or_waits_for_an_event() {
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
    let token = w.receiver_token();

    let began = std::time::Instant::now();
    let (status, answer) =
        poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
    assert_eq!(status, 200);
    assert!(answer["sets"].as_object().unwrap().is_empty());
    assert!(began.elapsed() < std::time::Duration::from_secs(5));

    // A long poll (the default) answers as soon as something is held.
    let writer_db = w.db.clone();
    let writer_stream = stream.clone();
    let event = held_event(&w, &stream);
    let jti = event.jti.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        SurrealSsfEventBufferRepository::new(writer_db)
            .push(
                writer_stream.tenant_id,
                writer_stream.id,
                &event,
                Utc::now(),
            )
            .await
            .unwrap();
    });
    let began = std::time::Instant::now();
    let (status, answer) = poll_with(&app, &token, stream.id, json!({})).await;
    assert_eq!(status, 200);
    assert!(answer["sets"].as_object().unwrap().contains_key(&jti));
    let waited = began.elapsed();
    assert!(waited >= std::time::Duration::from_millis(500), "it waited");
    assert!(
        waited < std::time::Duration::from_secs(10),
        "it did not wait out the cap"
    );

    // The cap itself (D-48): thirty seconds.
    assert_eq!(
        axiam_api_rest::handlers::ssf::POLL_LONG_POLL_MAX,
        std::time::Duration::from_secs(30)
    );
}

/// D-53 (11): at most one long poll waits per stream per instance. A second one
/// on the same stream answers at once; another stream's long poll still waits;
/// and the slot is free again when the first one has answered.
#[actix_rt::test]
async fn a_second_long_poll_on_a_stream_answers_at_once_while_one_is_waiting() {
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
    let state = w.state();
    let waiters = state.ssf.poll_waiters.clone();
    let app = app!(state, w);
    let token = w.receiver_token();

    let event = held_event(&w, &stream);
    let jti = event.jti.clone();
    let writer_db = w.db.clone();
    let writer_stream = stream.clone();
    let waiters_seen = waiters.clone();
    let second_answer = async {
        // Let the first long poll reach its wait.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(waiters_seen.waiting(), 1, "the first long poll is waiting");
        let began = std::time::Instant::now();
        let (status, answer) = poll_with(&app, &token, stream.id, json!({})).await;
        let took = began.elapsed();
        assert_eq!(status, 200);
        assert!(answer["sets"].as_object().unwrap().is_empty());
        assert!(
            took < std::time::Duration::from_millis(400),
            "the second long poll did not wait one step"
        );
        // The first one is undisturbed: an event arriving now still reaches it.
        SurrealSsfEventBufferRepository::new(writer_db)
            .push(
                writer_stream.tenant_id,
                writer_stream.id,
                &event,
                Utc::now(),
            )
            .await
            .unwrap();
    };
    let (first, ()) =
        futures::future::join(poll_with(&app, &token, stream.id, json!({})), second_answer).await;
    assert_eq!(first.0, 200);
    assert!(first.1["sets"].as_object().unwrap().contains_key(&jti));
    assert_eq!(waiters.waiting(), 0, "the slot is released with the answer");

    // Free again: a long poll that finds an event answers, and a later one
    // may wait.
    buffer(&w)
        .delete_by_jti(w.tenant_id, stream.id, &[jti])
        .await
        .unwrap();
    let (status, answer) =
        poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
    assert_eq!(status, 200);
    assert!(answer["sets"].as_object().unwrap().is_empty());
}

/// D-51: a paused stream answers an empty `sets` and keeps what it holds; a
/// disabled one answers empty; enabled again, the held events are served.
#[actix_rt::test]
async fn a_paused_or_disabled_stream_answers_an_empty_set_list() {
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
    hold(&w, &stream, 2).await;
    let app = app!(w.state(), w);
    let token = w.receiver_token();

    for status in [SsfStreamStatus::Paused, SsfStreamStatus::Disabled] {
        set_status_via_repo(&w, &stream, status).await;
        let (code, answer) =
            poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
        assert_eq!(code, 200);
        assert!(answer["sets"].as_object().unwrap().is_empty());
        assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 2);
    }
    set_status_via_repo(&w, &stream, SsfStreamStatus::Enabled).await;
    let (_, answer) = poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
    assert_eq!(answer["sets"].as_object().unwrap().len(), 2);
}

/// D-48: a stream narrowed meanwhile does not get what it no longer wants, and
/// an expired event is never served.
#[actix_rt::test]
async fn a_narrowed_stream_and_an_expired_event_are_not_served() {
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
    // A credential-change held, then the receiver narrows to session-revoked.
    let credential = prepare_event(
        &w.auth,
        &stream,
        &SsfEvent::CredentialChange {
            credential_type: axiam_oauth2::ssf::CredentialType::Password,
            change_type: axiam_oauth2::ssf::ChangeType::Update,
            initiating_entity: None,
            event_timestamp: Utc::now().timestamp(),
            x509_issuer: None,
            x509_serial: None,
            fido2_aaguid: None,
        },
        &SsfSubject {
            user_id: Uuid::new_v4(),
            email: None,
            email_vouched: false,
            session_id: None,
        },
        None,
        Utc::now(),
    )
    .unwrap();
    buffer(&w)
        .push(w.tenant_id, stream.id, &credential, Utc::now())
        .await
        .unwrap();
    let mut update = SsfStreamUpdate::from_stream(&stream);
    update.events_requested = vec![SsfEventType::SessionRevoked];
    w.repo()
        .update(w.tenant_id, stream.id, update)
        .await
        .unwrap();
    // And one event held eight days ago.
    let stale = held_event(&w, &stream);
    buffer(&w)
        .push(
            w.tenant_id,
            stream.id,
            &stale,
            Utc::now() - Duration::days(8),
        )
        .await
        .unwrap();
    let app = app!(w.state(), w);
    let token = w.receiver_token();

    let (status, answer) =
        poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
    assert_eq!(status, 200);
    assert!(answer["sets"].as_object().unwrap().is_empty());
    // The one the stream no longer carries was dropped; the expired one waits
    // for the sweep.
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 1);
    assert_eq!(buffer(&w).delete_expired(Utc::now()).await.unwrap(), 1);
}

#[actix_rt::test]
async fn the_poll_endpoint_is_the_receivers_alone() {
    // Two tenants need their own issuers for SSF to run (D-55).
    let w = world_with(true).await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    named_client(&w, w.tenant_id, OTHER_RECEIVER, &["ssf.manage"]).await;
    let poll_stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let push_stream = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let foreign = w
        .stream(
            w.other_tenant(),
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Enabled,
        )
        .await;
    let app = app!(w.state(), w);
    let body = json!({"returnImmediately": true});

    // No token, a user token, a client token without the scope.
    let (status, _) = send(
        &app,
        request(Method::POST, &poll_uri(poll_stream.id), None).set_json(body.clone()),
    )
    .await;
    assert_eq!(status, 401);
    let (status, _) = poll_with(&app, &w.admin_token(), poll_stream.id, body.clone()).await;
    assert_eq!(status, 403);
    let unscoped = w.client_token(RECEIVER, w.tenant_id, &["read"]);
    let (status, _) = poll_with(&app, &unscoped, poll_stream.id, body.clone()).await;
    assert_eq!(status, 403);

    // One 404 for another receiver's stream, another tenant's, an unknown id and
    // a malformed one.
    let other = w.client_token(OTHER_RECEIVER, w.tenant_id, &["ssf.manage"]);
    let (status, _) = poll_with(&app, &other, poll_stream.id, body.clone()).await;
    assert_eq!(status, 404);
    let (status, _) = poll_with(&app, &w.receiver_token(), foreign.id, body.clone()).await;
    assert_eq!(status, 404);
    let (status, _) = poll_with(&app, &w.receiver_token(), Uuid::new_v4(), body.clone()).await;
    assert_eq!(status, 404);
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            "/ssf/v1/poll/not-a-uuid",
            Some(&w.receiver_token()),
        )
        .set_json(body.clone()),
    )
    .await;
    assert_eq!(status, 404);

    // A push stream has nothing to poll.
    let (status, _) = poll_with(&app, &w.receiver_token(), push_stream.id, body.clone()).await;
    assert_eq!(status, 400);

    // The receiver's own stream works.
    let (status, _) = poll_with(&app, &w.receiver_token(), poll_stream.id, body).await;
    assert_eq!(status, 200);

    // With the transmitter off the stream is not there at all.
    w.ssf_off_for(w.tenant_id).await;
    let (status, _) = poll_with(
        &app,
        &w.receiver_token(),
        poll_stream.id,
        json!({"returnImmediately": true}),
    )
    .await;
    assert_eq!(status, 404);
}

#[actix_rt::test]
async fn the_poll_body_is_optional_and_bounded() {
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
    let token = w.receiver_token();

    // An empty body is `{}`: with nothing held and returnImmediately false it
    // would wait, so hold one event to make it answer.
    hold(&w, &stream, 1).await;
    let (status, text) = send(
        &app,
        request(Method::POST, &poll_uri(stream.id), Some(&token)),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(json_of(&text)["sets"].as_object().unwrap().len(), 1);

    let (status, _) = send(
        &app,
        request(Method::POST, &poll_uri(stream.id), Some(&token)).set_payload("{not json"),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = send(
        &app,
        request(Method::POST, &poll_uri(stream.id), Some(&token))
            .set_payload(format!(r#"{{"pad":"{}"}}"#, "x".repeat(40_000))),
    )
    .await;
    assert_eq!(status, 413);
    // Too many acknowledgements.
    let acks: Vec<String> = (0..1_001).map(|i| format!("{i:032x}")).collect();
    let (status, _) = poll_with(&app, &token, stream.id, json!({"ack": acks})).await;
    assert!(status == 400 || status == 413);
}

/// Plan §7 rule 6: the poll route is limited, on a bucket of its own.
#[actix_rt::test]
async fn the_poll_route_has_its_own_rate_limit_bucket() {
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
        ssf_admin_per_min: 100_000,
        ..RateLimitConfig::default()
    };
    let app = app!(w.state(), w, limits, false);
    let token = w.receiver_token();
    for expected in [200, 200, 429] {
        let (status, _) =
            poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
        assert_eq!(status, expected, "poll bucket");
    }
    // The other receiver routes' buckets are untouched.
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &format!("/ssf/v1/stream?stream_id={}", stream.id),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 200);
}

// ===========================================================================
// T23.5.3 — the event sources (D-52)
// ===========================================================================

/// A stream that carries every event and names users as `format` does.
async fn all_events_stream(
    w: &World,
    method: SsfDeliveryMethod,
    format: SsfSubjectFormat,
) -> SsfStream {
    let push = method == SsfDeliveryMethod::Push;
    w.repo()
        .create(NewSsfStream {
            tenant_id: w.tenant_id,
            receiver_client_id: RECEIVER.into(),
            audience: format!("https://rp.example.test/aud/{}", Uuid::new_v4().simple()),
            description: None,
            delivery_method: method,
            endpoint_url: push.then(|| PUSH_URL.to_owned()),
            authorization_header: None,
            events_allowed: SsfEventType::ALL.to_vec(),
            events_requested: SsfEventType::ALL.to_vec(),
            subject_format: format,
            status: SsfStreamStatus::Enabled,
            status_reason: None,
        })
        .await
        .unwrap()
}

async fn session_row(w: &World, user_id: Uuid) -> Session {
    SurrealSessionRepository::new(w.db.clone())
        .create(CreateSession {
            tenant_id: w.tenant_id,
            user_id,
            token_hash: Uuid::new_v4().simple().to_string(),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::days(1),
            authenticated_at: Utc::now(),
            amr: Vec::new(),
            browser_token_hash: None,
        })
        .await
        .unwrap()
}

impl World {
    /// An access token whose `jti` is `session_id`, the session it belongs to.
    fn token_in_session(&self, user_id: Uuid, session_id: Uuid) -> String {
        issue_access_token(
            user_id,
            self.tenant_id,
            self.org_id,
            &[],
            &self.auth,
            session_id.to_string(),
            AUD_USER,
        )
        .unwrap()
    }

    fn submitted(&self) -> Vec<(SsfStream, SsfPendingEvent)> {
        self.outbox.submitted.lock().unwrap().clone()
    }

    /// What was submitted of one event type, oldest first.
    fn submitted_of(&self, event: SsfEventType) -> Vec<(SsfStream, SsfPendingEvent)> {
        self.submitted()
            .into_iter()
            .filter(|(_, e)| e.event_uri == event.uri())
            .collect()
    }
}

#[actix_rt::test]
async fn a_logout_reports_session_revoked_to_the_streams_that_carry_it() {
    // Two tenants need their own issuers for SSF to run (D-55).
    let w = world_with(true).await;
    let carrying = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let held = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Paused,
        )
        .await;
    // Not reported to: a disabled stream, another tenant's, and one that did not
    // ask for the event.
    w.stream(
        w.tenant_id,
        RECEIVER,
        SsfDeliveryMethod::Push,
        SsfStreamStatus::Disabled,
    )
    .await;
    w.stream(
        w.other_tenant(),
        RECEIVER,
        SsfDeliveryMethod::Push,
        SsfStreamStatus::Enabled,
    )
    .await;
    let uninterested = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Push,
            SsfStreamStatus::Enabled,
        )
        .await;
    let mut away = SsfStreamUpdate::from_stream(&uninterested);
    away.events_requested = vec![SsfEventType::CredentialChange];
    w.repo()
        .update(w.tenant_id, uninterested.id, away)
        .await
        .unwrap();

    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let session = session_row(&w, user).await;
    let state = w.state();
    let session_repo = state.session_repo.clone();
    let app = app!(state, w);
    let token = w.token_in_session(user, session.id);

    let (status, _) = send(
        &app,
        request(Method::POST, "/api/v1/auth/logout", Some(&token)),
    )
    .await;
    assert_eq!(status, 204);

    let reported = w.submitted_of(SsfEventType::SessionRevoked);
    let mut streams: Vec<Uuid> = reported.iter().map(|(s, _)| s.id).collect();
    streams.sort();
    let mut expected = vec![carrying.id, held.id];
    expected.sort();
    assert_eq!(
        streams, expected,
        "exactly the streams that carry the event"
    );
    for (stream, pending) in &reported {
        assert_eq!(pending.event["initiating_entity"], "user");
        assert_eq!(
            pending.sub_id,
            json!({
                "format": "complex",
                "user": {"format": "iss_sub", "iss": w.issuer(), "sub": user.to_string()},
                "session": {"format": "opaque", "id": session.id.to_string()},
            })
        );
        assert!(pending.txn.is_some());
        // It verifies against the JWKS once signed as delivery will sign it.
        if stream.status == SsfStreamStatus::Enabled {
            let set = sign_set(&w.auth, w.issuer_check(), stream, pending).unwrap();
            let claims = verify_set(&w, &set, &stream.audience);
            assert_eq!(claims["sub_id"]["session"]["id"], session.id.to_string());
        }
    }

    // A redemption is not a revocation: `consume` reports nothing.
    let before = w.submitted().len();
    let redeemed = session_row(&w, user).await;
    assert!(
        session_repo
            .consume(w.tenant_id, redeemed.id)
            .await
            .unwrap()
    );
    assert_eq!(w.submitted().len(), before);
}

#[actix_rt::test]
async fn nothing_is_emitted_with_the_transmitter_off_or_no_stream_registered() {
    let w = world().await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;

    // No stream: the logout works and nothing is submitted.
    let session = session_row(&w, user).await;
    let app = app!(w.state(), w);
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            "/api/v1/auth/logout",
            Some(&w.token_in_session(user, session.id)),
        ),
    )
    .await;
    assert_eq!(status, 204);
    assert!(w.submitted().is_empty());

    // A stream, with the tenant's switch off.
    w.stream(
        w.tenant_id,
        RECEIVER,
        SsfDeliveryMethod::Push,
        SsfStreamStatus::Enabled,
    )
    .await;
    w.ssf_off_for(w.tenant_id).await;
    let session = session_row(&w, user).await;
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            "/api/v1/auth/logout",
            Some(&w.token_in_session(user, session.id)),
        ),
    )
    .await;
    assert_eq!(status, 204);
    assert!(w.submitted().is_empty());
}

/// D-52: a password change is a `credential-change`, its session revocations are
/// `session-revoked`, and all of them share one `txn`.
#[actix_rt::test]
async fn a_password_change_reports_the_credential_change_and_the_revoked_sessions_under_one_txn() {
    let w = world().await;
    let stream = all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::IssSub).await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let current = session_row(&w, user).await;
    let other = session_row(&w, user).await;
    let app = app!(w.state(), w);

    let (status, body) = send(
        &app,
        request(
            Method::POST,
            "/api/v1/auth/password/change",
            Some(&w.token_in_session(user, current.id)),
        )
        .set_json(json!({
            "current_password": test_password(),
            "new_password": axiam_test_support::other_password(),
        })),
    )
    .await;
    assert_eq!(status, 204, "{body}");

    let credential = w.submitted_of(SsfEventType::CredentialChange);
    assert_eq!(credential.len(), 1);
    let (for_stream, pending) = &credential[0];
    assert_eq!(for_stream.id, stream.id);
    let timestamp = pending.event["event_timestamp"].clone();
    assert_eq!(
        pending.event,
        json!({
            "credential_type": "password",
            "change_type": "update",
            "initiating_entity": "user",
            "event_timestamp": timestamp,
        })
    );
    assert_eq!(
        pending.sub_id,
        json!({"format": "iss_sub", "iss": ROOT_ISSUER, "sub": user.to_string()})
    );

    // The other session was revoked (the caller's own is kept), by the same cause.
    let revoked = w.submitted_of(SsfEventType::SessionRevoked);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].1.sub_id["session"]["id"], other.id.to_string());
    assert_eq!(revoked[0].1.event["initiating_entity"], "user");
    assert!(pending.txn.is_some());
    assert_eq!(pending.txn, revoked[0].1.txn, "one operation, one txn");
}

#[actix_rt::test]
async fn totp_enrolment_and_an_mfa_reset_are_credential_changes() {
    let w = world().await;
    all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::IssSub).await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let session = session_row(&w, user).await;
    let app = app!(w.state(), w);
    let token = w.token_in_session(user, session.id);

    // Enrol and confirm a TOTP authenticator.
    let (status, text) = send(
        &app,
        request(Method::POST, "/api/v1/auth/mfa/enroll", Some(&token)),
    )
    .await;
    assert_eq!(status, 200, "the TOTP enrolment");
    let secret =
        totp_rs::Secret::try_from_base32(json_of(&text)["secret_base32"].as_str().unwrap())
            .unwrap()
            .as_bytes()
            .to_vec();
    let totp = totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some("AXIAM-Test"))
        .with_account_name("alice@example.com")
        .build()
        .unwrap();
    let (status, text) = send(
        &app,
        request(Method::POST, "/api/v1/auth/mfa/confirm", Some(&token))
            .set_json(json!({"totp_code": totp.generate_current().to_string()})),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let created = w.submitted_of(SsfEventType::CredentialChange);
    assert_eq!(created.len(), 1);
    assert_eq!(created[0].1.event["credential_type"], "app");
    assert_eq!(created[0].1.event["change_type"], "create");
    assert_eq!(created[0].1.event["initiating_entity"], "user");

    // An administrator resets the account's MFA: the authenticator is removed and
    // every session goes — one cause, initiated by the administrator.
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            &format!("/api/v1/users/{user}/reset-mfa"),
            Some(&w.admin_token()),
        ),
    )
    .await;
    assert_eq!(status, 204);
    let changes = w.submitted_of(SsfEventType::CredentialChange);
    assert_eq!(changes.len(), 2);
    let removed = &changes[1].1;
    assert_eq!(removed.event["credential_type"], "app");
    assert_eq!(removed.event["change_type"], "delete");
    assert_eq!(removed.event["initiating_entity"], "admin");
    let revoked = w.submitted_of(SsfEventType::SessionRevoked);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].1.sub_id["session"]["id"], session.id.to_string());
    assert_eq!(revoked[0].1.event["initiating_entity"], "admin");
    assert_eq!(removed.txn, revoked[0].1.txn);
}

#[actix_rt::test]
async fn deleting_a_passkey_reports_a_fido2_credential_change_with_its_aaguid() {
    let w = world().await;
    all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::IssSub).await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let session = session_row(&w, user).await;
    let aaguid = Uuid::new_v4();
    let credentials = SurrealWebauthnCredentialRepository::new(w.db.clone());
    let create = |kind: WebauthnCredentialType, aaguid: Option<Uuid>| CreateWebauthnCredential {
        tenant_id: w.tenant_id,
        user_id: user,
        credential_id: Uuid::new_v4().simple().to_string(),
        name: "key".into(),
        credential_type: kind,
        passkey_json: "{}".into(),
        aaguid,
        attestation_format: None,
        attested: false,
        authenticator_name: None,
    };
    let passkey = credentials
        .create(create(WebauthnCredentialType::Passkey, Some(aaguid)))
        .await
        .unwrap();
    let security_key = credentials
        .create(create(WebauthnCredentialType::SecurityKey, None))
        .await
        .unwrap();
    let app = app!(w.state(), w);
    let token = w.token_in_session(user, session.id);

    for id in [passkey.id, security_key.id] {
        let (status, _) = send(
            &app,
            request(
                Method::DELETE,
                &format!("/api/v1/users/{user}/mfa-methods/{id}"),
                Some(&token),
            ),
        )
        .await;
        assert_eq!(status, 204);
    }
    let changes = w.submitted_of(SsfEventType::CredentialChange);
    assert_eq!(changes.len(), 2);
    assert_eq!(changes[0].1.event["credential_type"], "fido2-platform");
    assert_eq!(changes[0].1.event["change_type"], "delete");
    assert_eq!(changes[0].1.event["fido2_aaguid"], aaguid.to_string());
    assert_eq!(changes[1].1.event["credential_type"], "fido2-roaming");
    assert!(changes[1].1.event.get("fido2_aaguid").is_none());

    // A method the user does not hold is a 404 and reports nothing.
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &format!("/api/v1/users/{user}/mfa-methods/{}", Uuid::new_v4()),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(w.submitted_of(SsfEventType::CredentialChange).len(), 2);
}

#[actix_rt::test]
async fn an_administrators_status_writes_are_account_disabled_and_enabled_and_a_lockout_is_neither()
{
    let w = world().await;
    all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::IssSub).await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let app = app!(w.state(), w);
    let admin = w.admin_token();
    let put = |status: &str| {
        request(Method::PUT, &format!("/api/v1/users/{user}"), Some(&admin))
            .set_json(json!({ "status": status }))
    };

    let (code, body) = send(&app, put("Inactive")).await;
    assert_eq!(code, 200, "{body}");
    let disabled = w.submitted_of(SsfEventType::AccountDisabled);
    assert_eq!(disabled.len(), 1);
    assert_eq!(
        disabled[0].1.sub_id,
        json!({"format": "iss_sub", "iss": ROOT_ISSUER, "sub": user.to_string()})
    );
    assert_eq!(disabled[0].1.event, json!({}));

    // Inactive again: not a change.
    assert_eq!(send(&app, put("Inactive")).await.0, 200);
    assert_eq!(w.submitted_of(SsfEventType::AccountDisabled).len(), 1);

    // Inactive -> Active is `account-enabled`.
    assert_eq!(send(&app, put("Active")).await.0, 200);
    assert_eq!(w.submitted_of(SsfEventType::AccountEnabled).len(), 1);

    // A lockout is neither, and Locked -> Active is not an enabling either.
    assert_eq!(send(&app, put("Locked")).await.0, 200);
    assert_eq!(send(&app, put("Active")).await.0, 200);
    assert_eq!(w.submitted_of(SsfEventType::AccountDisabled).len(), 1);
    assert_eq!(w.submitted_of(SsfEventType::AccountEnabled).len(), 1);

    // A self-update cannot set a status, so reports none.
    let session = session_row(&w, user).await;
    let own = w.token_in_session(user, session.id);
    let (code, _) = send(
        &app,
        request(Method::PUT, &format!("/api/v1/users/{user}"), Some(&own))
            .set_json(json!({"status": "Inactive"})),
    )
    .await;
    assert_eq!(code, 200);
    assert_eq!(w.submitted_of(SsfEventType::AccountDisabled).len(), 1);
}

/// D-52: the subject of an `account-purged` is captured **before** the write —
/// afterwards the account has no address — so an `email` stream still names it.
#[actix_rt::test]
async fn a_deleted_account_is_purged_with_the_subject_captured_before_the_write() {
    let w = world().await;
    let by_email = all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::Email).await;
    let by_id = all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::IssSub).await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let address = SurrealUserRepository::new(w.db.clone())
        .get_by_id(w.tenant_id, user)
        .await
        .unwrap()
        .email;
    let session = session_row(&w, user).await;
    let app = app!(w.state(), w);

    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &format!("/api/v1/users/{user}"),
            Some(&w.admin_token()),
        ),
    )
    .await;
    assert_eq!(status, 204);

    let purged = w.submitted_of(SsfEventType::AccountPurged);
    assert_eq!(purged.len(), 2);
    let on = |stream: &SsfStream| {
        &purged
            .iter()
            .find(|(s, _)| s.id == stream.id)
            .expect("a purge for the stream")
            .1
    };
    assert_eq!(
        on(&by_id).sub_id,
        json!({"format": "iss_sub", "iss": ROOT_ISSUER, "sub": user.to_string()})
    );
    assert!(
        on(&by_email).sub_id == json!({"format": "email", "email": address}),
        "the address as it was before the delete"
    );
    // The account no longer has it.
    let after = SurrealUserRepository::new(w.db.clone())
        .get_by_id(w.tenant_id, user)
        .await
        .unwrap();
    assert!(after.email != address);

    // The sessions the delete revoked are the same cause, an administrator's.
    let revoked = w.submitted_of(SsfEventType::SessionRevoked);
    assert!(!revoked.is_empty());
    assert_eq!(revoked[0].1.sub_id["session"]["id"], session.id.to_string());
    assert_eq!(revoked[0].1.event["initiating_entity"], "admin");
    assert_eq!(on(&by_id).txn, revoked[0].1.txn);
}

/// D-46: an account whose address nothing vouches for is not sent on an
/// `email` stream — and never with `iss_sub` instead.
#[actix_rt::test]
async fn an_unvouched_address_is_not_sent_on_an_email_stream() {
    let w = world().await;
    let by_email = all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::Email).await;
    let by_id = all_events_stream(&w, SsfDeliveryMethod::Push, SsfSubjectFormat::IssSub).await;
    // A freshly created account: pending, address not verified.
    let pending_user = SurrealUserRepository::new(w.db.clone())
        .create(CreateUser {
            tenant_id: w.tenant_id,
            username: "pending".into(),
            email: "pending@example.com".into(),
            password: test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    let app = app!(w.state(), w);
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &format!("/api/v1/users/{}", pending_user.id),
            Some(&w.admin_token()),
        ),
    )
    .await;
    assert_eq!(status, 204);
    let purged = w.submitted_of(SsfEventType::AccountPurged);
    assert_eq!(purged.len(), 1);
    assert_eq!(purged[0].0.id, by_id.id);
    assert!(purged.iter().all(|(s, _)| s.id != by_email.id));
}

// ===========================================================================
// T23.5.3 — end to end: the real emitter, outbox and push deliverer against a
// receiver listening on loopback (D-48, D-49, D-51, D-52)
//
// The dispatcher is in process (one attempt per message, in the background): the
// broker, the retry queue and the dead-letter queue are `axiam-amqp`'s and are
// pinned by its own tests; what is under test here is everything on either side
// of them. The deliverer is the production one except for the hidden seam that
// lets its first hop reach `127.0.0.1` over plain http; the test that pins the
// address guard builds it without.
// ===========================================================================

use axiam_core::outbound::{
    DeliveryOutcome, OutboundDeliverer, OutboundError, OutboundFuture, OutboundMessage,
    OutboundPublisher,
};
use axiam_oauth2::ssf_delivery::{SsfOutboxService, SsfPushDeliverer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// What the receiver was sent.
#[derive(Clone)]
struct Received {
    headers: std::collections::HashMap<String, String>,
    body: String,
}

/// A receiver on loopback that answers every push `202`.
struct LoopbackReceiver {
    port: u16,
    seen: Arc<Mutex<Vec<Received>>>,
}

impl LoopbackReceiver {
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
                    let headers: std::collections::HashMap<String, String> = head
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
                    seen.lock().unwrap().push(Received {
                        headers,
                        body: String::from_utf8_lossy(&body).into_owned(),
                    });
                    let _ = socket
                        .write_all(
                            b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        Self { port, seen }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}/ssf/events", self.port)
    }

    fn requests(&self) -> Vec<Received> {
        self.seen.lock().unwrap().clone()
    }

    /// Wait until `n` pushes have arrived, or `within` has passed. Returns how
    /// long it took, or `None`.
    async fn arrived(&self, n: usize, within: std::time::Duration) -> Option<std::time::Duration> {
        let began = std::time::Instant::now();
        while began.elapsed() < within {
            if self.requests().len() >= n {
                return Some(began.elapsed());
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        (self.requests().len() >= n).then(|| began.elapsed())
    }
}

/// The dispatcher in process: `enqueue` makes one delivery attempt in the
/// background and records what the deliverer decided.
#[derive(Clone)]
struct InProcessDispatcher {
    deliverer: Arc<dyn OutboundDeliverer>,
    outcomes: Arc<Mutex<Vec<DeliveryOutcome>>>,
}

impl InProcessDispatcher {
    fn new(deliverer: impl OutboundDeliverer + 'static) -> Self {
        Self {
            deliverer: Arc::new(deliverer),
            outcomes: Arc::default(),
        }
    }
}

impl OutboundPublisher for InProcessDispatcher {
    fn enqueue<'a>(
        &'a self,
        msg: &'a OutboundMessage,
    ) -> OutboundFuture<'a, Result<(), OutboundError>> {
        Box::pin(async move {
            let (deliverer, outcomes, msg) =
                (self.deliverer.clone(), self.outcomes.clone(), msg.clone());
            tokio::spawn(async move {
                let outcome = deliverer.deliver_attempt(&msg).await.unwrap_or_else(|e| {
                    DeliveryOutcome::Retry {
                        reason: e.to_string(),
                    }
                });
                outcomes.lock().unwrap().push(outcome);
            });
            Ok(())
        })
    }
}

impl World {
    /// `AppState` whose outbox is the real one in front of `dispatcher`.
    fn delivering_state(&self, dispatcher: &InProcessDispatcher) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state.ssf.stream_repo = self.repo();
        let outbox = SsfOutboxService::new(buffer(self), Arc::new(dispatcher.clone()));
        state.ssf.bind_outbox(Arc::new(outbox));
        state
    }

    fn loopback_dispatcher(&self) -> InProcessDispatcher {
        InProcessDispatcher::new(
            SsfPushDeliverer::new(self.repo(), buffer(self), self.auth.clone(), self.gate())
                .admitting_private_networks_for_tests(),
        )
    }

    /// A push stream pointing at `receiver`, registered directly (the
    /// write-time endpoint policy would refuse a loopback `http` URL, and
    /// delivery is what is under test).
    async fn push_stream_to(
        &self,
        receiver: &LoopbackReceiver,
        header: Option<&str>,
        status: SsfStreamStatus,
    ) -> SsfStream {
        let created = self
            .repo()
            .create(NewSsfStream {
                tenant_id: self.tenant_id,
                receiver_client_id: RECEIVER.into(),
                audience: format!("https://rp.example.test/aud/{}", Uuid::new_v4().simple()),
                description: None,
                delivery_method: SsfDeliveryMethod::Push,
                endpoint_url: Some(receiver.url()),
                authorization_header: header.map(|h| Zeroizing::new(h.to_owned())),
                events_allowed: vec![SsfEventType::SessionRevoked],
                events_requested: vec![SsfEventType::SessionRevoked],
                subject_format: SsfSubjectFormat::IssSub,
                status,
                status_reason: None,
            })
            .await
            .unwrap();
        // The receiver owns the status of this stream, so it may change it.
        let mut update = SsfStreamUpdate::from_stream(&created);
        update.status_actor = SsfStatusActor::Receiver;
        self.repo()
            .update(self.tenant_id, created.id, update)
            .await
            .unwrap()
    }
}

/// Fetch the JWKS the way a receiver does — from the route — and verify `set`
/// against the key its header names.
async fn verify_against_published_jwks<S, B>(app: &S, set: &str, audience: &str) -> Value
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let (status, text) = send(app, request(Method::GET, "/oauth2/jwks", None)).await;
    assert_eq!(status, 200);
    let jwks = json_of(&text);
    let header = jsonwebtoken::decode_header(set).unwrap();
    assert_eq!(header.typ.as_deref(), Some("secevent+jwt"));
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"].as_str() == header.kid.as_deref())
        .expect("the header's kid is published");
    let key = jsonwebtoken::DecodingKey::from_ed_components(jwk["x"].as_str().unwrap()).unwrap();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.set_audience(&[audience]);
    validation.set_issuer(&[ROOT_ISSUER]);
    jsonwebtoken::decode::<Value>(set, &key, &validation)
        .expect("the SET verifies against the published JWKS")
        .claims
}

async fn logout_in<S, B>(app: &S, w: &World, user: Uuid) -> Session
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    let session = session_row(w, user).await;
    let (status, _) = send(
        app,
        request(
            Method::POST,
            "/api/v1/auth/logout",
            Some(&w.token_in_session(user, session.id)),
        ),
    )
    .await;
    assert_eq!(status, 204);
    session
}

/// The acceptance test of T23.5.3: a receiver gets a SET within one second of a
/// session revocation and verifies it against the JWKS.
#[actix_rt::test]
async fn a_receiver_gets_the_set_within_one_second_of_a_session_revocation() {
    let w = world().await;
    let receiver = LoopbackReceiver::start().await;
    let header = header_value();
    let stream = w
        .push_stream_to(&receiver, Some(&header), SsfStreamStatus::Enabled)
        .await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let dispatcher = w.loopback_dispatcher();
    let app = app!(w.delivering_state(&dispatcher), w);

    let began = std::time::Instant::now();
    let session = logout_in(&app, &w, user).await;
    let waited = receiver
        .arrived(1, std::time::Duration::from_secs(1))
        .await
        .expect("a push within one second of the revocation");
    assert!(began.elapsed() < std::time::Duration::from_secs(1));
    assert!(waited < std::time::Duration::from_secs(1));

    let seen = receiver.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].headers["content-type"], "application/secevent+jwt");
    assert!(
        seen[0].headers.get("authorization") == Some(&header),
        "the registered Authorization header travels with the push"
    );
    let claims = verify_against_published_jwks(&app, &seen[0].body, &stream.audience).await;
    assert_eq!(claims["iss"], ROOT_ISSUER);
    assert_eq!(claims["aud"], stream.audience.as_str());
    assert!(claims.get("exp").is_none() && claims.get("sub").is_none());
    assert_eq!(claims["jti"].as_str().unwrap().len(), 32);
    let events = claims["events"].as_object().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(
        claims["sub_id"],
        json!({
            "format": "complex",
            "user": {"format": "iss_sub", "iss": ROOT_ISSUER, "sub": user.to_string()},
            "session": {"format": "opaque", "id": session.id.to_string()},
        })
    );
    assert_eq!(
        events[SsfEventType::SessionRevoked.uri()]["initiating_entity"],
        "user"
    );
    assert!(dispatcher.outcomes.lock().unwrap().len() <= 1);
}

/// D-51: a disabled stream delivers nothing — push or poll — and holds nothing.
#[actix_rt::test]
async fn a_disabled_stream_delivers_and_holds_nothing() {
    let w = world().await;
    let receiver = LoopbackReceiver::start().await;
    let push = w
        .push_stream_to(&receiver, None, SsfStreamStatus::Disabled)
        .await;
    let poll = w
        .stream(
            w.tenant_id,
            RECEIVER,
            SsfDeliveryMethod::Poll,
            SsfStreamStatus::Disabled,
        )
        .await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let dispatcher = w.loopback_dispatcher();
    let app = app!(w.delivering_state(&dispatcher), w);

    logout_in(&app, &w, user).await;
    assert!(
        receiver
            .arrived(1, std::time::Duration::from_millis(600))
            .await
            .is_none(),
        "nothing is pushed to a disabled stream"
    );
    assert!(dispatcher.outcomes.lock().unwrap().is_empty());
    assert_eq!(buffer(&w).count(w.tenant_id, push.id).await.unwrap(), 0);
    assert_eq!(buffer(&w).count(w.tenant_id, poll.id).await.unwrap(), 0);
}

/// D-48, D-51: a paused stream holds its events, and enabling it releases them
/// to the receiver, oldest first.
#[actix_rt::test]
async fn a_paused_stream_holds_and_delivers_on_resume() {
    let w = world().await;
    named_client(&w, w.tenant_id, RECEIVER, &["ssf.manage"]).await;
    let receiver = LoopbackReceiver::start().await;
    let stream = w
        .push_stream_to(&receiver, None, SsfStreamStatus::Paused)
        .await;
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let dispatcher = w.loopback_dispatcher();
    let app = app!(w.delivering_state(&dispatcher), w);

    let first = logout_in(&app, &w, user).await;
    let second = logout_in(&app, &w, user).await;
    assert!(
        receiver
            .arrived(1, std::time::Duration::from_millis(600))
            .await
            .is_none(),
        "nothing is pushed while the stream is paused"
    );
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 2);

    // The receiver enables its stream again.
    let (status, body) = send(
        &app,
        request(Method::POST, "/ssf/v1/status", Some(&w.receiver_token()))
            .set_json(json!({"stream_id": stream.id, "status": "enabled"})),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    receiver
        .arrived(2, std::time::Duration::from_secs(2))
        .await
        .expect("the held events are pushed on resume");
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 0);
    let mut sessions: Vec<String> = Vec::new();
    for pushed in receiver.requests() {
        let claims = verify_against_published_jwks(&app, &pushed.body, &stream.audience).await;
        sessions.push(
            claims["sub_id"]["session"]["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    sessions.sort();
    let mut expected = vec![first.id.to_string(), second.id.to_string()];
    expected.sort();
    assert_eq!(sessions, expected);
}

/// D-48: a poll stream's events wait in the buffer; the receiver polls them,
/// verifies them against the JWKS and, by acknowledging them, drains the buffer.
#[actix_rt::test]
async fn a_poll_receiver_drains_the_buffer_by_acknowledging() {
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
    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let dispatcher = w.loopback_dispatcher();
    let app = app!(w.delivering_state(&dispatcher), w);
    let token = w.receiver_token();

    let session = logout_in(&app, &w, user).await;
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 1);
    assert!(dispatcher.outcomes.lock().unwrap().is_empty());

    let (status, answer) =
        poll_with(&app, &token, stream.id, json!({"returnImmediately": true})).await;
    assert_eq!(status, 200);
    let sets = answer["sets"].as_object().unwrap();
    assert_eq!(sets.len(), 1);
    let (jti, set) = sets.iter().next().unwrap();
    let claims = verify_against_published_jwks(&app, set.as_str().unwrap(), &stream.audience).await;
    assert_eq!(claims["jti"], jti.as_str());
    assert_eq!(claims["sub_id"]["session"]["id"], session.id.to_string());

    let (status, answer) = poll_with(
        &app,
        &token,
        stream.id,
        json!({"returnImmediately": true, "ack": [jti]}),
    )
    .await;
    assert_eq!(status, 200);
    assert!(answer["sets"].as_object().unwrap().is_empty());
    assert_eq!(buffer(&w).count(w.tenant_id, stream.id).await.unwrap(), 0);
}

/// T-392: the push goes only through the address guard. The production
/// deliverer — no loopback admission — refuses a registered endpoint that
/// resolves to the receiver's own loopback address, and nothing arrives.
#[actix_rt::test]
async fn the_address_guard_refuses_a_private_endpoint_at_delivery_end_to_end() {
    let w = world().await;
    let receiver = LoopbackReceiver::start().await;
    let stream = w
        .push_stream_to(&receiver, Some(&header_value()), SsfStreamStatus::Enabled)
        .await;
    // Registered as https, which the write-time policy also wants; the name
    // resolves to loopback.
    let mut update = SsfStreamUpdate::from_stream(&stream);
    update.endpoint_url = Some(format!("https://localhost:{}/ssf/events", receiver.port));
    update.authorization_header =
        axiam_core::models::ssf::SecretChange::Set(Zeroizing::new(header_value()));
    w.repo()
        .update(w.tenant_id, stream.id, update)
        .await
        .unwrap();

    let user = active_user(&w.db, w.tenant_id, "alice").await;
    let dispatcher = InProcessDispatcher::new(SsfPushDeliverer::new(
        w.repo(),
        buffer(&w),
        w.auth.clone(),
        w.gate(),
    ));
    let app = app!(w.delivering_state(&dispatcher), w);
    logout_in(&app, &w, user).await;

    let began = std::time::Instant::now();
    while dispatcher.outcomes.lock().unwrap().is_empty()
        && began.elapsed() < std::time::Duration::from_secs(3)
    {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let outcomes = dispatcher.outcomes.lock().unwrap().clone();
    assert_eq!(outcomes.len(), 1);
    assert!(matches!(outcomes[0], DeliveryOutcome::Retry { .. }));
    assert!(receiver.requests().is_empty());
}

// ---------------------------------------------------------------------------
// F4 W4 P23W4-03: a held event that cannot be signed during a long poll
// ---------------------------------------------------------------------------

/// A writer the test reads back: what the subscriber printed.
#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The deployment key failing to sign a held event is the operator's to fix,
/// and the event stays for the next poll — but a long poll looks at the buffer
/// every 500 ms for 30 s, and before F4 W4 it wrote an `ERROR` line on every
/// look: about sixty lines per waiting receiver per half minute, a log flood a
/// receiver could keep up by polling. One line per request now. And a long poll
/// the receiver abandons gives its wait slot back (D-53 (11)).
#[actix_rt::test]
async fn an_unsignable_held_event_is_logged_once_per_poll_and_an_abandoned_poll_frees_its_slot() {
    let capture = CapturedLog::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

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
    hold(&w, &stream, 1).await;

    // The receiver's token verifies (the public key is sound); signing a SET
    // fails (the private key the state signs with is not a key).
    let mut state = w.state();
    state.auth_config.jwt_encoding_key = None;
    state.auth_config.jwt_private_key_pem = "unusable".into();
    let waiters = state.ssf.poll_waiters.clone();
    let app = app!(state, w);
    let token = w.receiver_token();

    let call = test::call_service(
        &app,
        request(Method::POST, &poll_uri(stream.id), Some(&token))
            .set_json(json!({}))
            .to_request(),
    );
    // Abandoned after about four looks at the buffer.
    let abandoned = tokio::time::timeout(std::time::Duration::from_millis(1_700), call).await;
    assert!(abandoned.is_err(), "the long poll was still waiting");
    assert_eq!(
        waiters.waiting(),
        0,
        "an abandoned long poll frees its slot"
    );

    let printed = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let lines = printed
        .lines()
        .filter(|l| l.contains("ERROR") && l.contains("could not be signed"))
        .count();
    assert_eq!(lines, 1, "one line per poll request, not one per look");
}

//! The world the D-55 tests share (F4 W4, P23W4-11, ilpanich/axiam#539): one
//! organization with SSF switched on and one or more tenants, the production
//! route table, the real repositories on an in-memory database and the real
//! shared-issuer gate (`AppState::for_test` builds it as the server does); the
//! outbox is a recording double.
//!
//! Two binaries use it: `ssf_shared_issuer_test.rs`, and
//! `ssf_shared_issuer_log_test.rs`, which captures the gate's `WARN` line in a
//! process of its own (a thread-local subscriber shares the process-wide
//! callsite interest cache with every concurrent test, see
//! `axiam-amqp/tests/mail_consumer_template_test.rs`).
//!
//! Keys, headers and tokens are generated at run time; no assertion or panic
//! message formats a header, a token or an address.

#![allow(dead_code)]

pub use std::net::SocketAddr;
pub use std::sync::{Arc, Mutex, OnceLock};

pub use actix_web::http::Method;
pub use actix_web::{App, test, web};
pub use axiam_api_rest::authz::AuthzChecker;
pub use axiam_api_rest::permissions::PERMISSION_REGISTRY;
pub use axiam_api_rest::state::AppState;
pub use axiam_api_rest::{RateLimitConfig, RouteOptions, register_api_v1_routes_with};
pub use axiam_auth::config::AuthConfig;
pub use axiam_auth::token::{AUD_USER, issue_access_token, issue_client_credentials_token};
pub use axiam_authz::AuthorizationEngine;
pub use axiam_core::models::audit::AuditLogEntry;
pub use axiam_core::models::oauth2_client::CreateOAuth2Client;
pub use axiam_core::models::organization::CreateOrganization;
pub use axiam_core::models::role::AssignmentScope;
pub use axiam_core::models::settings::system_defaults;
pub use axiam_core::models::ssf::{
    NewSsfStream, SsfDeliveryMethod, SsfEventType, SsfFuture, SsfOutbox, SsfOutboxError,
    SsfPendingEvent, SsfStream, SsfStreamStatus, SsfSubjectFormat,
};
pub use axiam_core::models::tenant::{CreateTenant, TenantKind};
pub use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
pub use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, OAuth2ClientRepository, OrganizationRepository, Pagination,
    RoleRepository, SettingsRepository, SsfEventBufferRepository, SsfStreamRepository,
    TenantRepository, UserRepository,
};
pub use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealOAuth2ClientRepository,
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealSettingsRepository,
    SurrealSsfEventBufferRepository, SurrealSsfStreamRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
pub use axiam_db::{seed_default_roles, seed_permissions};
pub use axiam_oauth2::ssf::{
    ChangeType, CredentialType, InitiatingEntity, SsfEvent, SsfSubject, prepare_event,
};
pub use axiam_test_support::test_password;
pub use chrono::Utc;
pub use serde_json::{Value, json};
pub use surrealdb::Surreal;
pub use surrealdb::engine::local::{Db, Mem};
pub use uuid::Uuid;

pub type TestDb = Db;

pub const TEST_PEER: &str = "127.0.0.1:40107";
pub const ROOT_ISSUER: &str = "https://iam.example.com";
pub const RECEIVER: &str = "ssf-receiver-d55";
pub const INACTIVE_ACTION: &str = "ssf.inactive_shared_issuer";

// ---------------------------------------------------------------------------
// Fixtures: nothing here is a literal credential
// ---------------------------------------------------------------------------

pub fn jwt_pair() -> &'static (String, String) {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    })
}

pub fn auth_config(tenant_paths: bool) -> AuthConfig {
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

#[derive(Default)]
pub struct RecordingOutbox {
    pub submitted: Mutex<Vec<(SsfStream, SsfPendingEvent)>>,
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

/// A writer the test reads back: what the subscriber printed.
#[derive(Clone, Default)]
pub struct CapturedLog(pub Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The world: one organization with SSF switched on, one or two tenants
// ---------------------------------------------------------------------------

pub struct World {
    pub db: Surreal<TestDb>,
    pub org_id: Uuid,
    pub tenant_id: Uuid,
    pub admin: Uuid,
    pub user: Uuid,
    pub auth: AuthConfig,
    pub authz: Arc<dyn AuthzChecker>,
    pub outbox: Arc<RecordingOutbox>,
}

pub async fn tenant_in(db: &Surreal<TestDb>, org_id: Uuid, slug: &str) -> Uuid {
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

pub async fn active_user(db: &Surreal<TestDb>, tenant_id: Uuid, name: &str) -> Uuid {
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

pub fn all_pages() -> Pagination {
    Pagination {
        offset: 0,
        limit: 10_000,
        search: None,
    }
}

/// A world of `tenants` tenants (1 or 2) in one organization whose baseline has
/// SSF on, with `tenant_paths` as the deployment's issuer mode. The first tenant
/// holds the administrator, a user, and a receiver client.
pub async fn world(tenants: usize, tenant_paths: bool) -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "D-55 Org".into(),
            slug: format!("d55-org-{}", Uuid::new_v4().simple()),
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
    let tenant_id = tenant_in(&db, org.id, "d55-home").await;
    for i in 1..tenants {
        tenant_in(&db, org.id, &format!("d55-other-{i}")).await;
    }
    let admin = active_user(&db, tenant_id, "admin").await;
    let super_admin = SurrealRoleRepository::new(db.clone())
        .list(tenant_id, all_pages())
        .await
        .unwrap()
        .items
        .into_iter()
        .find(|r| r.name == "super-admin")
        .expect("seeded role")
        .id;
    SurrealRoleRepository::new(db.clone())
        .assign_to_user(tenant_id, admin, super_admin, AssignmentScope::global())
        .await
        .unwrap();
    let user = active_user(&db, tenant_id, "subject").await;
    let input: CreateOAuth2Client = serde_json::from_value(json!({
        "tenant_id": tenant_id,
        "name": RECEIVER,
        "redirect_uris": [],
        "grant_types": ["client_credentials"],
        "scopes": ["ssf.manage"],
    }))
    .unwrap();
    let (client, _issued) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(input)
        .await
        .unwrap();
    db.query("UPDATE oauth2_client SET client_id = $name WHERE client_id = $minted")
        .bind(("name", RECEIVER.to_owned()))
        .bind(("minted", client.client_id))
        .await
        .unwrap()
        .check()
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
        admin,
        user,
        auth: auth_config(tenant_paths),
        authz,
        outbox: Arc::new(RecordingOutbox::default()),
    }
}

impl World {
    pub fn state(&self) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state
            .ssf
            .bind_outbox(self.outbox.clone() as Arc<dyn SsfOutbox>);
        state
    }

    pub fn admin_token(&self) -> String {
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

    pub fn receiver_token(&self) -> String {
        issue_client_credentials_token(
            RECEIVER,
            self.tenant_id,
            self.org_id,
            &["ssf.manage".to_owned()],
            &self.auth,
        )
        .unwrap()
    }

    pub async fn stream(&self, method: SsfDeliveryMethod) -> SsfStream {
        SurrealSsfStreamRepository::new(self.db.clone(), None)
            .create(NewSsfStream {
                tenant_id: self.tenant_id,
                receiver_client_id: RECEIVER.into(),
                audience: format!("https://rp.example.test/aud/{}", Uuid::new_v4().simple()),
                description: None,
                delivery_method: method,
                endpoint_url: (method == SsfDeliveryMethod::Push)
                    .then(|| "https://rp.example.test/ssf/events".to_owned()),
                authorization_header: None,
                events_allowed: vec![SsfEventType::CredentialChange, SsfEventType::SessionRevoked],
                events_requested: vec![
                    SsfEventType::CredentialChange,
                    SsfEventType::SessionRevoked,
                ],
                subject_format: SsfSubjectFormat::IssSub,
                status: SsfStreamStatus::Enabled,
                status_reason: None,
            })
            .await
            .unwrap()
    }

    /// One event held for a poll stream, as the emitter would have prepared it.
    pub async fn hold_one(&self, stream: &SsfStream) {
        let pending = prepare_event(
            &self.auth,
            stream,
            &SsfEvent::SessionRevoked {
                initiating_entity: Some(InitiatingEntity::Admin),
                event_timestamp: Utc::now().timestamp(),
            },
            &SsfSubject {
                user_id: self.user,
                email: None,
                email_vouched: false,
                session_id: Some(Uuid::new_v4()),
            },
            Some("txn-d55"),
            Utc::now(),
        )
        .unwrap();
        SurrealSsfEventBufferRepository::new(self.db.clone())
            .push(stream.tenant_id, stream.id, &pending, Utc::now())
            .await
            .unwrap();
    }

    /// An emission as a change site makes it: a password change of the user.
    pub async fn emit(&self, state: &AppState<TestDb>) {
        state
            .ssf
            .emitter
            .emit_for_user(
                self.tenant_id,
                self.user,
                SsfEvent::CredentialChange {
                    credential_type: CredentialType::Password,
                    change_type: ChangeType::Update,
                    initiating_entity: Some(InitiatingEntity::User),
                    event_timestamp: Utc::now().timestamp(),
                    x509_issuer: None,
                    x509_serial: None,
                    fido2_aaguid: None,
                },
            )
            .await;
    }

    pub fn told(&self) -> usize {
        self.outbox.submitted.lock().unwrap().len()
    }

    pub async fn audit_rows(&self, tenant_id: Uuid) -> Vec<AuditLogEntry> {
        SurrealAuditLogRepository::new(self.db.clone())
            .list(
                tenant_id,
                AuditLogFilter {
                    action: Some(INACTIVE_ACTION.into()),
                    ..Default::default()
                },
                all_pages(),
            )
            .await
            .unwrap()
            .items
    }

    pub async fn tenant_ids(&self) -> Vec<Uuid> {
        SurrealTenantRepository::new(self.db.clone())
            .list_by_organization(self.org_id, all_pages())
            .await
            .unwrap()
            .items
            .into_iter()
            .map(|t| t.id)
            .collect()
    }
}

pub fn permissive_limits() -> RateLimitConfig {
    RateLimitConfig {
        ssf_per_min: 100_000,
        ssf_admin_per_min: 100_000,
        ..RateLimitConfig::default()
    }
}

macro_rules! app {
    ($state:expr, $w:expr) => {
        $crate::ssf_shared_issuer_support::test::init_service(
            $crate::ssf_shared_issuer_support::App::new()
                .app_data($crate::ssf_shared_issuer_support::web::Data::new(
                    $w.auth.clone(),
                ))
                .app_data($crate::ssf_shared_issuer_support::web::Data::new(
                    $w.authz.clone(),
                ))
                .app_data($crate::ssf_shared_issuer_support::web::Data::new($state))
                .configure(|cfg| {
                    $crate::ssf_shared_issuer_support::register_api_v1_routes_with::<
                        $crate::ssf_shared_issuer_support::TestDb,
                    >(
                        cfg,
                        &$crate::ssf_shared_issuer_support::permissive_limits(),
                        $crate::ssf_shared_issuer_support::RouteOptions {
                            tenant_issuer_paths: $w.auth.tenant_issuer_paths,
                            ..$crate::ssf_shared_issuer_support::RouteOptions::default()
                        },
                    )
                }),
        )
        .await
    };
}

pub fn request(method: Method, uri: &str, token: Option<&str>) -> test::TestRequest {
    let req = test::TestRequest::default()
        .method(method)
        .uri(uri)
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap());
    match token {
        Some(t) => req.insert_header(("Authorization", format!("Bearer {t}"))),
        None => req,
    }
}

pub async fn send<S, B>(app: &S, req: test::TestRequest) -> (u16, String)
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
    let body = test::read_body(resp).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

pub fn json_of(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

pub fn discovery_uri(tenant_id: Uuid) -> String {
    format!("/.well-known/ssf-configuration?tenant_id={tenant_id}")
}

/// Wait briefly for the audit writer the gate spawns.
pub async fn settle() {
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

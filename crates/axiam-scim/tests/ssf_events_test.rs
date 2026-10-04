//! **T23.5.3** — what a SCIM write tells SSF receivers (G-5, D-52).
//!
//! `active: false` disables an account that was not disabled, `active: true`
//! enables one that was, a password write is a `credential-change` an
//! administrator made, a `DELETE` is an `account-purged` whose subject was read
//! before the write (D-53 (2)), and the credentials the write revokes are
//! `session-revoked` events of the **same** cause (one `txn`). An unchanged
//! status, a lock-out and a no-op patch tell nobody anything.
//!
//! The outbox is a recording double; the emitter, the repositories and the
//! SCIM routes are the real ones. Keys and secrets are generated at run time.

use std::sync::{Arc, Mutex, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::session::CreateSession;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::ssf::{
    NewSsfStream, SsfDeliveryMethod, SsfEventType, SsfFuture, SsfOutbox, SsfOutboxError,
    SsfPendingEvent, SsfStream, SsfStreamStatus, SsfSubjectFormat,
};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, RoleRepository, SessionRepository, SettingsRepository,
    SsfStreamRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealSessionRepository, SurrealSettingsRepository, SurrealSsfStreamRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use serde_json::json;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const ROOT_ISSUER: &str = "https://iam.example.com";

fn generated(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn auth_config() -> AuthConfig {
    static PAIR: OnceLock<(String, String)> = OnceLock::new();
    let (private, public) = PAIR.get_or_init(|| {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
        (pair.serialize_pem(), pair.public_key_pem())
    });
    AuthConfig {
        jwt_private_key_pem: private.clone(),
        jwt_public_key_pem: public.clone(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ROOT_ISSUER.into(),
        ..AuthConfig::default()
    }
}

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
            self.submitted
                .lock()
                .unwrap()
                .push((stream.clone(), event.clone()));
            Ok(())
        })
    }
}

struct World {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    auth: AuthConfig,
    authz: Arc<dyn AuthzChecker>,
    outbox: Arc<RecordingOutbox>,
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SCIM SSF Org".into(),
            slug: generated("org"),
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
            name: "SCIM SSF Tenant".into(),
            slug: generated("tenant"),
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
    let authz: Arc<dyn AuthzChecker> = Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ));
    SurrealSsfStreamRepository::new(db.clone(), None)
        .create(NewSsfStream {
            tenant_id: tenant.id,
            receiver_client_id: "receiver".into(),
            audience: format!("https://rp.example.test/{}", Uuid::new_v4().simple()),
            description: None,
            delivery_method: SsfDeliveryMethod::Push,
            endpoint_url: Some("https://rp.example.test/events".into()),
            authorization_header: None,
            events_allowed: SsfEventType::ALL.to_vec(),
            events_requested: SsfEventType::ALL.to_vec(),
            subject_format: SsfSubjectFormat::IssSub,
            status: SsfStreamStatus::Enabled,
            status_reason: None,
        })
        .await
        .unwrap();
    World {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        auth: auth_config(),
        authz,
        outbox: Arc::new(RecordingOutbox::default()),
    }
}

impl World {
    fn state(&self) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state
            .ssf
            .bind_outbox(self.outbox.clone() as Arc<dyn SsfOutbox>);
        state
    }

    fn of(&self, event: SsfEventType) -> Vec<SsfPendingEvent> {
        self.outbox
            .submitted
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.event_uri == event.uri())
            .map(|(_, e)| e.clone())
            .collect()
    }

    async fn user(&self, role: &str, status: UserStatus) -> Uuid {
        let users = SurrealUserRepository::new(self.db.clone());
        let user = users
            .create(CreateUser {
                tenant_id: self.tenant_id,
                username: generated("u"),
                email: format!("{}@example.com", generated("u")),
                password: generated("pw"),
                metadata: None,
            })
            .await
            .unwrap();
        users
            .update(
                self.tenant_id,
                user.id,
                UpdateUser {
                    status: Some(status),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let roles = SurrealRoleRepository::new(self.db.clone());
        let role = roles
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
            .find(|r| r.name == role)
            .expect("a seeded role");
        roles
            .assign_to_user(self.tenant_id, user.id, role.id, AssignmentScope::global())
            .await
            .unwrap();
        user.id
    }

    async fn session(&self, user_id: Uuid) -> Uuid {
        SurrealSessionRepository::new(self.db.clone())
            .create(CreateSession {
                tenant_id: self.tenant_id,
                user_id,
                token_hash: axiam_auth::token::hash_refresh_token(&generated("session")),
                ip_address: None,
                user_agent: None,
                expires_at: chrono::Utc::now() + chrono::Duration::days(7),
                authenticated_at: chrono::Utc::now(),
                amr: vec![],
                browser_token_hash: None,
            })
            .await
            .unwrap()
            .id
    }

    fn token(&self, user_id: Uuid) -> String {
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
}

macro_rules! app {
    ($w:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.authz.clone()))
                .app_data(web::Data::new($w.state()))
                .configure(axiam_scim::scim_routes::<TestDb>),
        )
        .await
    };
}

fn peer() -> std::net::SocketAddr {
    "203.0.113.9:5000".parse().expect("a test peer")
}

fn patch(user: Uuid, token: &str, operation: serde_json::Value) -> actix_http::Request {
    test::TestRequest::patch()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{user}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [operation],
        }))
        .to_request()
}

#[actix_rt::test]
async fn deactivating_and_reactivating_through_patch_are_account_disabled_and_enabled() {
    let w = world().await;
    let app = app!(w);
    let provisioner = w.user("admin", UserStatus::Active).await;
    let token = w.token(provisioner);
    let target = w.user("viewer", UserStatus::Active).await;
    let active = |value: bool| json!({"op": "replace", "path": "active", "value": value});

    assert_eq!(
        test::call_service(&app, patch(target, &token, active(false)))
            .await
            .status()
            .as_u16(),
        200
    );
    let disabled = w.of(SsfEventType::AccountDisabled);
    assert_eq!(disabled.len(), 1);
    assert_eq!(
        disabled[0].sub_id,
        json!({"format": "iss_sub", "iss": ROOT_ISSUER, "sub": target.to_string()})
    );

    // Deactivating an account that is already inactive is not a change.
    test::call_service(&app, patch(target, &token, active(false))).await;
    assert_eq!(w.of(SsfEventType::AccountDisabled).len(), 1);

    assert_eq!(
        test::call_service(&app, patch(target, &token, active(true)))
            .await
            .status()
            .as_u16(),
        200
    );
    assert_eq!(w.of(SsfEventType::AccountEnabled).len(), 1);
    // Active again: re-asserting it is not a change either.
    test::call_service(&app, patch(target, &token, active(true))).await;
    assert_eq!(w.of(SsfEventType::AccountEnabled).len(), 1);
}

#[actix_rt::test]
async fn a_put_deactivation_is_an_account_disabled_and_the_revoked_session_shares_its_txn() {
    let w = world().await;
    let app = app!(w);
    let provisioner = w.user("admin", UserStatus::Active).await;
    let token = w.token(provisioner);
    let target = w.user("viewer", UserStatus::Active).await;
    let session = w.session(target).await;

    let req = test::TestRequest::put()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": generated("put"),
            "emails": [{"value": format!("{}@example.com", generated("put")), "primary": true}],
            "active": false,
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

    let disabled = w.of(SsfEventType::AccountDisabled);
    assert_eq!(disabled.len(), 1);
    let revoked = w.of(SsfEventType::SessionRevoked);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].sub_id["session"]["id"], session.to_string());
    assert_eq!(revoked[0].event["initiating_entity"], "admin");
    assert!(disabled[0].txn.is_some());
    assert_eq!(disabled[0].txn, revoked[0].txn, "one SCIM write, one txn");
}

#[actix_rt::test]
async fn a_scim_password_write_is_a_credential_change_by_an_administrator() {
    let w = world().await;
    let app = app!(w);
    let provisioner = w.user("admin", UserStatus::Active).await;
    let token = w.token(provisioner);
    let target = w.user("viewer", UserStatus::Active).await;
    let session = w.session(target).await;

    let op = json!({"op": "replace", "path": "password", "value": generated("new-pw")});
    assert_eq!(
        test::call_service(&app, patch(target, &token, op))
            .await
            .status()
            .as_u16(),
        200
    );
    let changes = w.of(SsfEventType::CredentialChange);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0].event["credential_type"], "password");
    assert_eq!(changes[0].event["change_type"], "update");
    assert_eq!(changes[0].event["initiating_entity"], "admin");
    let revoked = w.of(SsfEventType::SessionRevoked);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].sub_id["session"]["id"], session.to_string());
    assert_eq!(changes[0].txn, revoked[0].txn);
}

#[actix_rt::test]
async fn a_patch_that_changes_nothing_that_matters_tells_nobody() {
    let w = world().await;
    let app = app!(w);
    let provisioner = w.user("admin", UserStatus::Active).await;
    let token = w.token(provisioner);
    let target = w.user("viewer", UserStatus::Active).await;
    w.session(target).await;

    let op = json!({"op": "replace", "path": "externalId", "value": generated("ext")});
    assert_eq!(
        test::call_service(&app, patch(target, &token, op))
            .await
            .status()
            .as_u16(),
        200
    );
    assert!(w.outbox.submitted.lock().unwrap().is_empty());
}

#[actix_rt::test]
async fn a_scim_delete_is_an_account_purged_with_the_subject_captured_before_the_write() {
    let w = world().await;
    let app = app!(w);
    let provisioner = w.user("admin", UserStatus::Active).await;
    let token = w.token(provisioner);
    let target = w.user("viewer", UserStatus::Active).await;
    let session = w.session(target).await;

    let req = test::TestRequest::delete()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    let purged = w.of(SsfEventType::AccountPurged);
    assert_eq!(purged.len(), 1);
    assert_eq!(
        purged[0].sub_id,
        json!({"format": "iss_sub", "iss": ROOT_ISSUER, "sub": target.to_string()})
    );
    // RISC's `account-purged` carries no members; the revocations carry the
    // initiator.
    assert_eq!(purged[0].event, json!({}));
    // The credentials the delete revokes are the same cause.
    let revoked = w.of(SsfEventType::SessionRevoked);
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].sub_id["session"]["id"], session.to_string());
    assert_eq!(revoked[0].event["initiating_entity"], "admin");
    assert!(purged[0].txn.is_some());
    assert_eq!(purged[0].txn, revoked[0].txn, "one SCIM delete, one txn");
}

#[actix_rt::test]
async fn a_scim_delete_of_a_user_that_does_not_exist_tells_nobody() {
    let w = world().await;
    let app = app!(w);
    let provisioner = w.user("admin", UserStatus::Active).await;
    let token = w.token(provisioner);

    let req = test::TestRequest::delete()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);
    assert!(w.of(SsfEventType::AccountPurged).is_empty());
}

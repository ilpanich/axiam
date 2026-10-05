//! The REST API's writers report to the provisioning sink (T23.6.2, G-6, D-57).
//!
//! The user and group repositories of the application state carry a recording
//! sink — as `axiam-server` gives them the shared one — and the real handlers
//! run over them: user create, update, disable, delete; group create, rename,
//! delete, add and remove member. What a downstream SCIM service provider is
//! then told is the provisioner's and deliverer's (`axiam-scim`).
//!
//! Keys and passwords are generated at run time.

use std::sync::{Arc, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::provisioning::{ProvisioningEvent, RecordingProvisioningSink};
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// The double-submit CSRF value (SEC-046): the middleware only checks that the
/// cookie and the header agree.
const CSRF_TOKEN: &str = "csrf-double-submit";

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
        ..AuthConfig::default()
    }
}

struct World {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    auth: AuthConfig,
    sink: Arc<RecordingProvisioningSink>,
    admin: Uuid,
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: format!("tenant-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let admin = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;
    World {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        auth: auth_config(),
        sink: RecordingProvisioningSink::new(),
        admin,
    }
}

impl World {
    /// The application state with the sink on the user and group repositories.
    fn state(&self) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state.user_repo =
            SurrealUserRepository::new(self.db.clone()).with_provisioning_sink(self.sink.clone());
        state.group_repo =
            SurrealGroupRepository::new(self.db.clone()).with_provisioning_sink(self.sink.clone());
        state
    }

    fn token(&self) -> String {
        issue_access_token(
            self.admin,
            self.tenant_id,
            self.org_id,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            axiam_auth::token::AUD_USER,
        )
        .unwrap()
    }

    fn user(&self, id: Uuid) -> ProvisioningEvent {
        ProvisioningEvent::User {
            tenant_id: self.tenant_id,
            user_id: id,
        }
    }

    fn group(&self, id: Uuid) -> ProvisioningEvent {
        ProvisioningEvent::Group {
            tenant_id: self.tenant_id,
            group_id: id,
        }
    }

    fn member(&self, group: Uuid, user: Uuid) -> ProvisioningEvent {
        ProvisioningEvent::Membership {
            tenant_id: self.tenant_id,
            group_id: group,
            user_id: user,
        }
    }
}

macro_rules! app {
    ($w:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.state()))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

macro_rules! call {
    ($app:expr, $w:expr, $method:ident, $uri:expr, $body:expr) => {{
        let mut request = test::TestRequest::$method()
            .insert_header(("X-Forwarded-For", "127.0.0.1"))
            .uri($uri)
            .insert_header(("Authorization", format!("Bearer {}", $w.token())))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN));
        let body: Option<Value> = $body;
        if let Some(body) = body {
            request = request.set_json(body);
        }
        let response = test::call_service(&$app, request.to_request()).await;
        let status = response.status().as_u16();
        let value: Value = if status == 204 {
            Value::Null
        } else {
            test::read_body_json(response).await
        };
        (status, value)
    }};
}

fn id_of(body: &Value) -> Uuid {
    Uuid::parse_str(body["id"].as_str().expect("an id")).unwrap()
}

#[actix_rt::test]
async fn rest_user_create_update_disable_and_delete_are_reported() {
    let w = world().await;
    let app = app!(w);

    // Create.
    let (status, body) = call!(
        app,
        w,
        post,
        "/api/v1/users",
        Some(json!({
            "username": "alice",
            "email": "alice@example.com",
            "password": axiam_test_support::test_password(),
        }))
    );
    assert_eq!(status, 201);
    let alice = id_of(&body);
    assert_eq!(w.sink.events(), vec![w.user(alice)], "create");

    // Update a provisioned field.
    w.sink.clear();
    let (status, _) = call!(
        app,
        w,
        put,
        &format!("/api/v1/users/{alice}"),
        Some(json!({"username": "alice2"}))
    );
    assert_eq!(status, 200);
    assert_eq!(w.sink.events(), vec![w.user(alice)], "update");

    // Disable.
    w.sink.clear();
    let (status, body) = call!(
        app,
        w,
        put,
        &format!("/api/v1/users/{alice}"),
        Some(json!({"status": "Inactive"}))
    );
    assert_eq!(status, 200);
    assert_eq!(body["status"], "Inactive");
    assert_eq!(w.sink.events(), vec![w.user(alice)], "disable");

    // Delete.
    w.sink.clear();
    let (status, _) = call!(app, w, delete, &format!("/api/v1/users/{alice}"), None);
    assert_eq!(status, 204);
    assert!(
        w.sink.events().contains(&w.user(alice)),
        "delete reports the user"
    );

    // A read reports nothing.
    w.sink.clear();
    let (status, _) = call!(app, w, get, "/api/v1/users", None);
    assert_eq!(status, 200);
    assert!(w.sink.events().is_empty());
}

#[actix_rt::test]
async fn rest_group_create_rename_membership_and_delete_are_reported() {
    let w = world().await;
    let app = app!(w);
    let member = SurrealUserRepository::new(w.db.clone())
        .create(CreateUser {
            tenant_id: w.tenant_id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap()
        .id;

    let (status, body) = call!(
        app,
        w,
        post,
        "/api/v1/groups",
        Some(json!({"name": "Team", "description": "A team"}))
    );
    assert_eq!(status, 201);
    let group = id_of(&body);
    assert_eq!(w.sink.events(), vec![w.group(group)], "create");

    w.sink.clear();
    let (status, _) = call!(
        app,
        w,
        put,
        &format!("/api/v1/groups/{group}"),
        Some(json!({"name": "Squad"}))
    );
    assert_eq!(status, 200);
    assert_eq!(w.sink.events(), vec![w.group(group)], "rename");

    w.sink.clear();
    let (status, _) = call!(
        app,
        w,
        post,
        &format!("/api/v1/groups/{group}/members"),
        Some(json!({"user_id": member}))
    );
    assert_eq!(status, 204);
    assert_eq!(w.sink.events(), vec![w.member(group, member)], "add member");

    w.sink.clear();
    let (status, _) = call!(
        app,
        w,
        delete,
        &format!("/api/v1/groups/{group}/members/{member}"),
        None
    );
    assert_eq!(status, 204);
    assert_eq!(
        w.sink.events(),
        vec![w.member(group, member)],
        "remove member"
    );

    // A group delete reports the group and each member it took the membership of.
    call!(
        app,
        w,
        post,
        &format!("/api/v1/groups/{group}/members"),
        Some(json!({"user_id": member}))
    );
    w.sink.clear();
    let (status, _) = call!(app, w, delete, &format!("/api/v1/groups/{group}"), None);
    assert_eq!(status, 204);
    let events = w.sink.events();
    assert!(events.contains(&w.group(group)));
    assert!(events.contains(&w.member(group, member)));
}

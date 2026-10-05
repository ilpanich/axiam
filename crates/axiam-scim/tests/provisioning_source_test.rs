//! SCIM inbound writers report to the provisioning sink (T23.6.2, G-6, D-57).
//!
//! An identity provider provisions into AXIAM through `/scim/v2`; that is one of
//! the writers whose change a *downstream* service provider must hear about, and
//! it is covered by the repositories reporting, not by the handlers. The state's
//! user and group repositories carry a recording sink and the real SCIM routes
//! run over them: user create, a `PATCH` that disables, a `DELETE`, group create
//! with members, a group `PATCH` that adds and removes a member, and a group
//! `DELETE`.
//!
//! Keys and credentials are generated at run time.

use std::sync::{Arc, OnceLock};

use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::provisioning::{ProvisioningEvent, RecordingProvisioningSink};
use axiam_core::repository::{
    OrganizationRepository, Pagination, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

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
        ..AuthConfig::default()
    }
}

struct World {
    db: Surreal<TestDb>,
    org_id: Uuid,
    tenant_id: Uuid,
    auth: AuthConfig,
    authz: Arc<dyn AuthzChecker>,
    sink: Arc<RecordingProvisioningSink>,
}

async fn world() -> World {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SCIM Org".into(),
            slug: generated("org"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "SCIM Tenant".into(),
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
    World {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        auth: auth_config(),
        authz,
        sink: RecordingProvisioningSink::new(),
    }
}

impl World {
    fn state(&self) -> AppState<TestDb> {
        let mut state = AppState::for_test(self.db.clone(), self.auth.clone());
        state.user_repo =
            SurrealUserRepository::new(self.db.clone()).with_provisioning_sink(self.sink.clone());
        state.group_repo =
            SurrealGroupRepository::new(self.db.clone()).with_provisioning_sink(self.sink.clone());
        state
    }

    /// A user created **without** the sink (so that setup reports nothing),
    /// holding `role`.
    async fn user(&self, role: &str) -> Uuid {
        let users = SurrealUserRepository::new(self.db.clone());
        let user = users
            .create(CreateUser {
                tenant_id: self.tenant_id,
                username: generated("u"),
                email: format!("{}@example.com", generated("u")),
                password: axiam_test_support::test_password(),
                metadata: None,
            })
            .await
            .unwrap();
        users
            .update(
                self.tenant_id,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Active),
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

    fn user_event(&self, id: Uuid) -> ProvisioningEvent {
        ProvisioningEvent::User {
            tenant_id: self.tenant_id,
            user_id: id,
        }
    }

    fn group_event(&self, id: Uuid) -> ProvisioningEvent {
        ProvisioningEvent::Group {
            tenant_id: self.tenant_id,
            group_id: id,
        }
    }

    fn member_event(&self, group: Uuid, user: Uuid) -> ProvisioningEvent {
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

macro_rules! scim {
    ($app:expr, $token:expr, $method:ident, $uri:expr, $body:expr) => {{
        let mut request = test::TestRequest::$method()
            .peer_addr(peer())
            .uri($uri)
            .insert_header(("Authorization", format!("Bearer {}", $token)));
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

fn patch_op(operations: Value) -> Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": operations,
    })
}

#[actix_rt::test]
async fn scim_inbound_user_create_disable_and_delete_are_reported() {
    let w = world().await;
    let app = app!(w);
    let token = w.token(w.user("admin").await);
    w.sink.clear();

    let (status, body) = scim!(
        app,
        token,
        post,
        "/scim/v2/Users",
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": generated("alice"),
            "emails": [{"value": format!("{}@example.com", generated("alice")), "primary": true}],
            "name": {"givenName": "Alice", "familyName": "Example"},
            "active": true,
        }))
    );
    assert_eq!(status, 201);
    let alice = id_of(&body);
    assert!(
        w.sink.events().contains(&w.user_event(alice)),
        "an IdP-provisioned user is reported"
    );

    // `active: false` is a status change.
    w.sink.clear();
    let (status, _) = scim!(
        app,
        token,
        patch,
        &format!("/scim/v2/Users/{alice}"),
        Some(patch_op(
            json!([{"op": "replace", "path": "active", "value": false}])
        ))
    );
    assert_eq!(status, 200);
    assert_eq!(w.sink.events(), vec![w.user_event(alice)]);

    // A rename (userName) too; a name the mapping carries as well.
    w.sink.clear();
    let (status, _) = scim!(
        app,
        token,
        patch,
        &format!("/scim/v2/Users/{alice}"),
        Some(patch_op(
            json!([{"op": "replace", "path": "name.givenName", "value": "Alicia"}])
        ))
    );
    assert_eq!(status, 200);
    assert_eq!(w.sink.events(), vec![w.user_event(alice)]);

    w.sink.clear();
    let (status, _) = scim!(app, token, delete, &format!("/scim/v2/Users/{alice}"), None);
    assert_eq!(status, 204);
    assert!(w.sink.events().contains(&w.user_event(alice)));
}

#[actix_rt::test]
async fn scim_inbound_group_create_and_patch_report_the_group_and_its_membership() {
    let w = world().await;
    let app = app!(w);
    let token = w.token(w.user("admin").await);
    let alice = w.user("viewer").await;
    let bob = w.user("viewer").await;
    w.sink.clear();

    let (status, body) = scim!(
        app,
        token,
        post,
        "/scim/v2/Groups",
        Some(json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": generated("team"),
            "members": [{"value": alice}],
        }))
    );
    assert_eq!(status, 201);
    let group = id_of(&body);
    let events = w.sink.events();
    assert!(events.contains(&w.group_event(group)));
    assert!(events.contains(&w.member_event(group, alice)));

    // A `PATCH` that adds one member and removes another.
    w.sink.clear();
    let (status, _) = scim!(
        app,
        token,
        patch,
        &format!("/scim/v2/Groups/{group}"),
        Some(patch_op(json!([
            {"op": "add", "path": "members", "value": [{"value": bob}]},
            {"op": "remove", "path": format!("members[value eq \"{alice}\"]")},
        ])))
    );
    assert_eq!(status, 200);
    let events = w.sink.events();
    assert!(events.contains(&w.member_event(group, bob)), "bob joined");
    assert!(events.contains(&w.member_event(group, alice)), "alice left");

    // A rename through `PATCH`.
    w.sink.clear();
    let (status, _) = scim!(
        app,
        token,
        patch,
        &format!("/scim/v2/Groups/{group}"),
        Some(patch_op(
            json!([{"op": "replace", "path": "displayName", "value": generated("renamed")}])
        ))
    );
    assert_eq!(status, 200);
    assert!(w.sink.events().contains(&w.group_event(group)));

    // Delete: the group, and the member it took the membership of.
    w.sink.clear();
    let (status, _) = scim!(
        app,
        token,
        delete,
        &format!("/scim/v2/Groups/{group}"),
        None
    );
    assert_eq!(status, 204);
    let events = w.sink.events();
    assert!(events.contains(&w.group_event(group)));
    assert!(events.contains(&w.member_event(group, bob)));
}

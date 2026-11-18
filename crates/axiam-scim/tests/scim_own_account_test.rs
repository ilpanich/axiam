//! SR6-1 (SA-04 / N6, "Own-account guard") — SCIM's JWT arm must not let a
//! token AXIAM minted for an OAuth2 client rewrite or delete the caller's OWN
//! record. `replace`, `patch` and `delete` on `/scim/v2/Users/{id}` demand a
//! first-party sign-in when `id` is the caller; an administrator's client-minted
//! token on ANOTHER user, a console sign-in on its own record and a
//! provisioning token are unchanged.

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::extractors::scim_token::{ScimTokenPrincipal, ScimTokenResolver};
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token, issue_access_token_for_client};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use serde_json::json;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Generated, never a literal: a fixture that carries a credential is a
/// secret-scanner finding waiting to happen.
fn generated_secret(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn test_auth_config() -> AuthConfig {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

fn make_authz(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

macro_rules! test_app {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($authz.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .configure(axiam_scim::scim_routes::<TestDb>),
        )
        .await
    };
}

fn peer() -> std::net::SocketAddr {
    "203.0.113.9:5000".parse().expect("valid test peer address")
}

async fn setup_tenant() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "SEC-098 Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "SEC-098 Tenant".into(),
            slug: format!("tenant-{}", Uuid::new_v4().simple()),
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
    (db, org.id, tenant.id)
}

async fn user_with_role(db: &Surreal<TestDb>, tenant_id: Uuid, role_name: &str) -> Uuid {
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: format!("u-{}", Uuid::new_v4().simple()),
            email: format!("u-{}@example.com", Uuid::new_v4().simple()),
            password: generated_secret("pw"),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
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

    let role_repo = SurrealRoleRepository::new(db.clone());
    let role = role_repo
        .list(
            tenant_id,
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
        .find(|r| r.name == role_name)
        .unwrap_or_else(|| panic!("default role `{role_name}` not seeded"));
    role_repo
        .assign_to_user(tenant_id, user.id, role.id, AssignmentScope::global())
        .await
        .unwrap();
    user.id
}

fn client_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token_for_client(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
        None,
        None,
        Some("oa_relying_party_x"),
        Some(Uuid::new_v4()),
        &[],
    )
    .unwrap()
}

fn console_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

async fn stored(db: &Surreal<TestDb>, tenant_id: Uuid, id: Uuid) -> axiam_core::models::user::User {
    SurrealUserRepository::new(db.clone())
        .get_by_id(tenant_id, id)
        .await
        .unwrap()
}

const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

async fn call(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    method: &str,
    id: Uuid,
    token: &str,
    body: Option<serde_json::Value>,
) -> u16 {
    let mut req = match method {
        "PATCH" => test::TestRequest::patch(),
        "PUT" => test::TestRequest::put(),
        _ => test::TestRequest::delete(),
    }
    .peer_addr(peer())
    .uri(&format!("/scim/v2/Users/{id}"))
    .insert_header(("Authorization", format!("Bearer {token}")));
    if let Some(b) = body {
        req = req.set_json(b);
    }
    test::call_service(app, req.to_request())
        .await
        .status()
        .as_u16()
}

fn put_body(email: &str) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": email.replace('@', "-"),
        "emails": [{ "value": email, "primary": true }],
        "active": true
    })
}

#[actix_rt::test]
async fn sr6_1_a_client_minted_token_cannot_rewrite_or_delete_its_own_scim_record() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let me = user_with_role(&db, tenant_id, "admin").await;
    let before = stored(&db, tenant_id, me).await;
    let token = client_token(&auth, me, tenant_id, org_id);

    // Password op.
    let status = call(
        &app,
        "PATCH",
        me,
        &token,
        Some(json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{ "op": "replace", "path": "password", "value": generated_secret("new-pw") }]
        })),
    )
    .await;
    assert_eq!(status, 403, "client-minted PATCH of own password");
    // Email via PATCH and via PUT.
    let status = call(
        &app,
        "PATCH",
        me,
        &token,
        Some(json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{ "op": "replace", "path": "emails", "value": [{"value": "x@attacker.example", "primary": true}] }]
        })),
    )
    .await;
    assert_eq!(status, 403, "client-minted PATCH of own email");
    let status = call(
        &app,
        "PUT",
        me,
        &token,
        Some(put_body("y@attacker.example")),
    )
    .await;
    assert_eq!(status, 403, "client-minted PUT of own record");
    // Deactivation by PATCH.
    let status = call(
        &app,
        "PATCH",
        me,
        &token,
        Some(json!({
            "schemas": [PATCH_SCHEMA],
            "Operations": [{ "op": "replace", "path": "active", "value": false }]
        })),
    )
    .await;
    assert_eq!(status, 403, "client-minted self-deactivation");
    // Delete.
    assert_eq!(
        call(&app, "DELETE", me, &token, None).await,
        403,
        "client-minted self-DELETE"
    );

    let after = stored(&db, tenant_id, me).await;
    assert_eq!(after.password_hash, before.password_hash, "hash unchanged");
    assert_eq!(
        after.credential_version, before.credential_version,
        "version unchanged"
    );
    assert_eq!(after.email, before.email, "email unchanged");
    assert_eq!(after.username, before.username, "username unchanged");
    assert_eq!(after.status, before.status, "status unchanged");
}

#[actix_rt::test]
async fn sr6_1_controls_console_sign_in_other_user_and_provisioning_token_are_unchanged() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);

    let me = user_with_role(&db, tenant_id, "admin").await;
    let other = user_with_role(&db, tenant_id, "viewer").await;
    let provisioner = user_with_role(&db, tenant_id, "admin").await;
    let principal = ScimTokenPrincipal {
        token_id: Uuid::new_v4(),
        user_id: provisioner,
        tenant_id,
    };
    let resolver: Arc<dyn ScimTokenResolver> = Arc::new(StubResolver {
        handle: "axiam_scim_goodhandle".into(),
        principal,
    });
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(authz.clone()))
            .app_data(web::Data::new(resolver))
            .app_data(web::Data::new(AppState::for_test(db.clone(), auth.clone())))
            .configure(axiam_scim::scim_routes::<TestDb>),
    )
    .await;

    // Console sign-in on its own record still succeeds.
    let console = console_token(&auth, me, tenant_id, org_id);
    assert_eq!(
        call(&app, "PUT", me, &console, Some(put_body("me2@example.com"))).await,
        200,
        "console sign-in rewrites its own record"
    );
    assert_eq!(stored(&db, tenant_id, me).await.email, "me2@example.com");

    // An admin's client-minted token on ANOTHER user still succeeds.
    let client = client_token(&auth, me, tenant_id, org_id);
    assert_eq!(
        call(
            &app,
            "PUT",
            other,
            &client,
            Some(put_body("other2@example.com"))
        )
        .await,
        200,
        "client-minted admin token on another user"
    );
    assert_eq!(
        stored(&db, tenant_id, other).await.email,
        "other2@example.com"
    );

    // A provisioning token is unchanged.
    assert_eq!(
        call(
            &app,
            "PATCH",
            other,
            "axiam_scim_goodhandle",
            Some(json!({
                "schemas": [PATCH_SCHEMA],
                "Operations": [{ "op": "replace", "path": "active", "value": true }]
            }))
        )
        .await,
        200,
        "provisioning token"
    );
    assert_eq!(
        call(&app, "DELETE", other, "axiam_scim_goodhandle", None).await,
        204
    );
}

struct StubResolver {
    handle: String,
    principal: ScimTokenPrincipal,
}
impl ScimTokenResolver for StubResolver {
    fn resolve<'a>(
        &'a self,
        raw: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<ScimTokenPrincipal>> + Send + 'a>>
    {
        let hit = raw == self.handle;
        let p = self.principal;
        Box::pin(async move { hit.then_some(p) })
    }
    fn touch<'a>(
        &'a self,
        _t: Uuid,
        _i: Uuid,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

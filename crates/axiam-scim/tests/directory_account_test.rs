//! Directory accounts through SCIM (G-3, T23.3.2).
//!
//! SCIM is the one administrative path that writes a password (RFC 7643
//! §4.1.1, `PATCH /scim/v2/Users/{id}`), so it is the "admin set password" door
//! for a directory account, and it is refused: a local hash written here would
//! be a second credential for the account that the directory's policy never
//! sees. SCIM also cannot set or clear the directory marker, by any attribute.
//!
//! Assertion messages name the case; none formats a password or a hash.

use std::sync::Arc;

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

const ENTRY: &str = "6f9619ff-8b86-d011-b42d-00c04fc964ff";

fn generated_secret(prefix: &str) -> String {
    format!("{prefix}-{}", Uuid::new_v4().simple())
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----"
            .into(),
        jwt_public_key_pem: "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----"
            .into(),
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

fn peer() -> std::net::SocketAddr {
    "203.0.113.9:5000".parse().expect("valid test peer address")
}

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Directory SCIM Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Directory SCIM Tenant".into(),
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
    let users = SurrealUserRepository::new(db.clone());
    let user = users
        .create(CreateUser {
            tenant_id,
            username: format!("u-{}", Uuid::new_v4().simple()),
            email: format!("u-{}@example.com", Uuid::new_v4().simple()),
            password: generated_secret("pw"),
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
    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
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
        .expect("default role seeded");
    roles
        .assign_to_user(tenant_id, user.id, role.id, AssignmentScope::global())
        .await
        .unwrap();
    user.id
}

fn bearer(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
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

macro_rules! app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(make_authz(&$db)))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .configure(axiam_scim::scim_routes::<TestDb>),
        )
        .await
    };
}

/// The admin "set password" door: refused for a directory account with RFC
/// 7644's own `mutability` code, and nothing is written.
#[actix_rt::test]
async fn a_scim_password_write_is_refused_for_a_directory_account() {
    let (db, org_id, tenant_id) = setup().await;
    let auth = auth_config();
    let app = app!(db, auth);
    let provisioner = user_with_role(&db, tenant_id, "admin").await;
    let token = bearer(&auth, provisioner, tenant_id, org_id);
    let target = user_with_role(&db, tenant_id, "viewer").await;
    let users = SurrealUserRepository::new(db.clone());
    users
        .mark_directory_account(tenant_id, target, ENTRY)
        .await
        .unwrap();
    let before = users
        .get_by_id(tenant_id, target)
        .await
        .unwrap()
        .password_hash;

    let req = test::TestRequest::patch()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                { "op": "replace", "path": "password", "value": generated_secret("new-pw") }
            ]
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "the password write must be refused"
    );
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["scimType"], "mutability");
    let after = users.get_by_id(tenant_id, target).await.unwrap();
    assert_eq!(after.password_hash, before, "no hash may be written");
    assert!(after.is_directory_account());
}

/// SCIM has no attribute that reaches the marker: `externalId` lands in
/// metadata, a `directory_external_id` path is not a SCIM attribute, and a PUT
/// replaces the resource without touching it.
#[actix_rt::test]
async fn scim_cannot_set_or_clear_the_marker() {
    let (db, org_id, tenant_id) = setup().await;
    let auth = auth_config();
    let app = app!(db, auth);
    let provisioner = user_with_role(&db, tenant_id, "admin").await;
    let token = bearer(&auth, provisioner, tenant_id, org_id);
    let local = user_with_role(&db, tenant_id, "viewer").await;
    let directory = user_with_role(&db, tenant_id, "viewer").await;
    let users = SurrealUserRepository::new(db.clone());
    users
        .mark_directory_account(tenant_id, directory, ENTRY)
        .await
        .unwrap();

    for target in [local, directory] {
        for ops in [
            json!([{ "op": "replace", "path": "externalId", "value": ENTRY }]),
            json!([{ "op": "replace", "path": "directory_external_id", "value": ENTRY }]),
            json!([{ "op": "remove", "path": "directory_external_id" }]),
        ] {
            let req = test::TestRequest::patch()
                .peer_addr(peer())
                .uri(&format!("/scim/v2/Users/{target}"))
                .insert_header(("Authorization", format!("Bearer {token}")))
                .set_json(json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": ops,
                }))
                .to_request();
            let _ = test::call_service(&app, req).await;
        }
        let req = test::TestRequest::put()
            .peer_addr(peer())
            .uri(&format!("/scim/v2/Users/{target}"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": format!("put-{}", Uuid::new_v4().simple()),
                "externalId": ENTRY,
                "directory_external_id": null,
                "emails": [{ "value": format!("put-{}@example.com", Uuid::new_v4().simple()), "primary": true }],
                "active": true
            }))
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
    }
    assert!(
        !users
            .get_by_id(tenant_id, local)
            .await
            .unwrap()
            .is_directory_account(),
        "SCIM must not set the marker"
    );
    assert_eq!(
        users
            .get_by_id(tenant_id, directory)
            .await
            .unwrap()
            .directory_external_id
            .as_deref(),
        Some(ENTRY),
        "SCIM must not clear the marker"
    );
}

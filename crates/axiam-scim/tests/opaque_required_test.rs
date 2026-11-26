//! SA-06 (S-7) — under `opaque_mode = required` a SCIM password write is
//! refused, because it would delete the user's only usable credential.
//!
//! `UserRepository::update` deletes the user's OPAQUE record in the same
//! transaction as any write of `password_hash`; SCIM carries a plaintext
//! password and cannot supply a replacement record, and under `required` the
//! Argon2 login is refused. So before the fix a SCIM password PATCH answered
//! 200 and left the account with no way to sign in.

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::opaque::{OpaqueKsf, OpaqueMode, OpaqueSuite};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, RoleRepository, SettingsRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOpaqueCredentialRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
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
            name: "SA-06 Org".into(),
            slug: format!("org-{}", Uuid::new_v4().simple()),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "SA-06 Tenant".into(),
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
            password: axiam_test_support::test_password(),
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

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
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

async fn set_opaque_mode(db: &Surreal<TestDb>, org_id: Uuid, mode: OpaqueMode) {
    let mut defaults = system_defaults();
    defaults.opaque_mode = mode;
    defaults.opaque_suite = OpaqueSuite::Ristretto255Sha512;
    defaults.opaque_ksf = OpaqueKsf::Argon2id;
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org_id, defaults)
        .await
        .unwrap();
}

/// Give `user_id` an OPAQUE record (any well-formed one: the test asks only
/// whether it survives).
async fn give_opaque_record(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) {
    use axiam_core::models::opaque::{CreateOpaqueCredential, OpaqueKsfParams};
    use axiam_core::repository::OpaqueCredentialRepository;
    SurrealOpaqueCredentialRepository::new(db.clone())
        .upsert(CreateOpaqueCredential {
            tenant_id,
            user_id,
            credential_identifier: hex::encode([7u8; 32]),
            suite: OpaqueSuite::Ristretto255Sha512,
            ksf_params: OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id),
            record: hex::encode([1u8; 192]),
        })
        .await
        .unwrap();
}

async fn has_record(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) -> bool {
    use axiam_core::repository::OpaqueCredentialRepository;
    SurrealOpaqueCredentialRepository::new(db.clone())
        .get_by_user(tenant_id, user_id)
        .await
        .is_ok()
}

fn patch_password() -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            { "op": "replace", "path": "password", "value": generated_secret("new-pw") }
        ]
    })
}

fn scim_user_body(password: Option<String>) -> serde_json::Value {
    let mut body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": format!("scim-{}", Uuid::new_v4().simple()),
        "emails": [{ "value": format!("scim-{}@example.com", Uuid::new_v4().simple()), "primary": true }],
        "active": true,
    });
    if let Some(p) = password {
        body["password"] = json!(p);
    }
    body
}

macro_rules! scenario {
    ($mode:expr) => {{
        let (db, org_id, tenant_id) = setup_tenant().await;
        set_opaque_mode(&db, org_id, $mode).await;
        let auth = test_auth_config();
        let authz = make_authz(&db);
        let app = test_app!(db, auth, authz);
        let provisioner = user_with_role(&db, tenant_id, "admin").await;
        let token = mint_token(&auth, provisioner, tenant_id, org_id);
        let target = user_with_role(&db, tenant_id, "viewer").await;
        give_opaque_record(&db, tenant_id, target).await;
        (db, tenant_id, app, token, target)
    }};
}

async fn status_and_type(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    req: actix_http::Request,
) -> (u16, Option<String>) {
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let body: serde_json::Value = test::read_body_json(resp).await;
    (status, body["scimType"].as_str().map(str::to_owned))
}

#[actix_rt::test]
async fn s7_a_scim_password_patch_is_refused_under_required_and_the_record_survives() {
    let (db, tenant_id, app, token, target) = scenario!(OpaqueMode::Required);
    let req = test::TestRequest::patch()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(patch_password())
        .to_request();
    assert_eq!(
        status_and_type(&app, req).await,
        (400, Some("mutability".into()))
    );
    assert!(
        has_record(&db, tenant_id, target).await,
        "the refused write must leave the OPAQUE record in place"
    );
}

#[actix_rt::test]
async fn s7_a_scim_create_with_a_password_is_refused_under_required() {
    let (_db, _tenant_id, app, token, _target) = scenario!(OpaqueMode::Required);
    let req = test::TestRequest::post()
        .peer_addr(peer())
        .uri("/scim/v2/Users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(scim_user_body(Some(generated_secret("pw"))))
        .to_request();
    assert_eq!(
        status_and_type(&app, req).await,
        (400, Some("mutability".into()))
    );
    // Control: a create that carries no password writes no credential and is
    // unchanged.
    let req = test::TestRequest::post()
        .peer_addr(peer())
        .uri("/scim/v2/Users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(scim_user_body(None))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 201);
}

#[actix_rt::test]
async fn s7_a_scim_put_carrying_a_password_is_refused_under_required() {
    let (db, tenant_id, app, token, target) = scenario!(OpaqueMode::Required);
    let req = test::TestRequest::put()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(scim_user_body(Some(generated_secret("pw"))))
        .to_request();
    assert_eq!(
        status_and_type(&app, req).await,
        (400, Some("mutability".into()))
    );
    assert!(has_record(&db, tenant_id, target).await);
}

/// Controls: `optional` and `off` are unchanged — the write succeeds, and (as
/// before) retires the record, because the Argon2 login still works there. A
/// write that carries no password is unchanged under `required` too.
#[actix_rt::test]
async fn s7_optional_and_off_are_unchanged_and_a_non_password_write_is_allowed_under_required() {
    for mode in [OpaqueMode::Optional, OpaqueMode::Disabled] {
        let (db, tenant_id, app, token, target) = scenario!(mode);
        let req = test::TestRequest::patch()
            .peer_addr(peer())
            .uri(&format!("/scim/v2/Users/{target}"))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_json(patch_password())
            .to_request();
        assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
        assert!(!has_record(&db, tenant_id, target).await);
    }

    let (db, tenant_id, app, token, target) = scenario!(OpaqueMode::Required);
    let req = test::TestRequest::patch()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{ "op": "replace", "path": "active", "value": false }]
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);
    assert!(has_record(&db, tenant_id, target).await);
}

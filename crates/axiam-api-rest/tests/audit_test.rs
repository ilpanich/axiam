//! Integration tests for audit log query endpoint.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AuditLogRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Test-only placeholder password — not a real credential.
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

fn test_keypair() -> (String, String) {
    let private_key = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM
-----END PRIVATE KEY-----";
    let public_key = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
    (private_key.into(), public_key.into())
}

fn test_auth_config() -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Test Org".into(),
            slug: "test-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Test Tenant".into(),
            slug: "test-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id)
}

async fn create_admin_user(db: &Surreal<TestDb>, tenant_id: Uuid) -> Uuid {
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
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
        uuid::Uuid::new_v4().to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
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

async fn seed_audit_entries(
    repo: &SurrealAuditLogRepository<TestDb>,
    tenant_id: Uuid,
    actor_id: Uuid,
) {
    repo.append(CreateAuditLogEntry {
        tenant_id,
        actor_id,
        actor_type: ActorType::User,
        action: "GET /api/v1/users".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: Some("127.0.0.1".into()),
        metadata: None,
    })
    .await
    .unwrap();

    repo.append(CreateAuditLogEntry {
        tenant_id,
        actor_id,
        actor_type: ActorType::User,
        action: "DELETE /api/v1/users/123".into(),
        resource_id: None,
        outcome: AuditOutcome::Denied,
        ip_address: Some("127.0.0.1".into()),
        metadata: None,
    })
    .await
    .unwrap();

    repo.append(CreateAuditLogEntry {
        tenant_id,
        actor_id,
        actor_type: ActorType::System,
        action: "POST /api/v1/users".into(),
        resource_id: None,
        outcome: AuditOutcome::Failure,
        ip_address: None,
        metadata: None,
    })
    .await
    .unwrap();
}

#[actix_rt::test]
async fn list_audit_logs_returns_paginated_results() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    seed_audit_entries(&audit_repo, tenant_id, user_id).await;

    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 3);
    assert_eq!(body["items"].as_array().unwrap().len(), 3);
}

#[actix_rt::test]
async fn list_audit_logs_filters_by_action() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    seed_audit_entries(&audit_repo, tenant_id, user_id).await;

    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs?action=GET%20/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["action"], "GET /api/v1/users");
}

#[actix_rt::test]
async fn list_audit_logs_filters_by_outcome() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    seed_audit_entries(&audit_repo, tenant_id, user_id).await;

    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs?outcome=Denied")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["outcome"], "Denied");
}

#[actix_rt::test]
async fn list_audit_logs_pagination_limit() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    seed_audit_entries(&audit_repo, tenant_id, user_id).await;

    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs?limit=2&offset=0")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 3);
    assert_eq!(body["items"].as_array().unwrap().len(), 2);
}

#[actix_rt::test]
async fn list_audit_logs_requires_auth() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

/// The caller lives in the organization's reserved scope: the system
/// partition is organization-level (SA-02, N1), and a caller of an ordinary
/// tenant is refused it whatever its permissions.
#[actix_rt::test]
async fn list_system_audit_logs_returns_only_nil_tenant() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let scope = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org_id))
        .await
        .unwrap();
    let user_id = create_admin_user(&db, scope.id).await;
    let token = mint_token(&auth, user_id, scope.id, org_id);

    let audit_repo = SurrealAuditLogRepository::new(db.clone());

    // Seed a tenant-scoped entry.
    seed_audit_entries(&audit_repo, tenant_id, user_id).await;

    // Seed a system (nil tenant) entry.
    audit_repo
        .append(CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "GET /auth/login".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            ip_address: Some("10.0.0.1".into()),
            metadata: None,
        })
        .await
        .unwrap();

    let app = test_app!(db, auth);

    // System endpoint should only return the nil-tenant entry.
    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs/system")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["action"], "GET /auth/login");
    assert_eq!(body["items"][0]["actor_type"], "System");
}

#[actix_rt::test]
async fn list_system_audit_logs_requires_auth() {
    let (db, _org_id, _tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs/system")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

// -------------------------------------------------------------------------
// SA-02 (N1): the system partition is not a tenant administrator's to read
// -------------------------------------------------------------------------

/// The real engine, so the seeded roles' grants decide `RequirePermission`
/// rather than `AllowAllAuthzChecker`.
fn real_authz(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    use axiam_db::repository::{
        SurrealGroupRepository, SurrealPermissionRepository, SurrealResourceRepository,
        SurrealRoleRepository, SurrealScopeRepository,
    };
    Arc::new(axiam_authz::AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

macro_rules! real_authz_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new(real_authz(&$db)))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

/// Seed the permission registry and default roles into `tenant_id`, as the
/// tenant-create path does for every new tenant.
async fn seed_tenant(db: &Surreal<TestDb>, tenant_id: Uuid) {
    use axiam_api_rest::permissions::PERMISSION_REGISTRY;
    axiam_db::seed_permissions(db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    axiam_db::seed_default_roles(db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
}

/// A user in `tenant_id` holding the seeded role `role_name`, or — with
/// `action` — a fresh global role granting only that action.
async fn tenant_user(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    username: &str,
    role_name: Option<&str>,
    action: Option<&str>,
) -> Uuid {
    use axiam_core::models::role::{AssignmentScope, CreateRole};
    use axiam_core::repository::{Pagination, PermissionRepository, RoleRepository};
    use axiam_db::repository::{SurrealPermissionRepository, SurrealRoleRepository};

    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    let role_repo = SurrealRoleRepository::new(db.clone());
    let page = Pagination {
        offset: 0,
        limit: 1000,
        search: None,
    };
    let role_id = if let Some(name) = role_name {
        role_repo
            .list(tenant_id, page)
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("default role `{name}` not seeded"))
            .id
    } else {
        let action = action.expect("a role name or an action");
        let role = role_repo
            .create(CreateRole {
                tenant_id,
                name: format!("role-{username}"),
                description: format!("grants only {action}"),
                is_global: true,
            })
            .await
            .unwrap();
        let perm_repo = SurrealPermissionRepository::new(db.clone());
        let perm = perm_repo
            .list(tenant_id, page)
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|p| p.action == action)
            .unwrap_or_else(|| panic!("permission `{action}` not seeded"));
        perm_repo
            .grant_to_role(tenant_id, role.id, perm.id)
            .await
            .unwrap();
        role.id
    };
    role_repo
        .assign_to_user(tenant_id, user.id, role_id, AssignmentScope::global())
        .await
        .unwrap();
    user.id
}

/// The row the request audit middleware writes for a request it cannot
/// attribute to a tenant (`middleware.rs`, nil tenant, `METHOD /path` as the
/// action) — here, tenant B's SCIM call from 192.0.2.10.
async fn sibling_traffic_in_the_system_partition(db: &Surreal<TestDb>) {
    SurrealAuditLogRepository::new(db.clone())
        .append(CreateAuditLogEntry {
            tenant_id: Uuid::nil(),
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "POST /scim/v2/Users".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: Some("192.0.2.10".into()),
            metadata: None,
        })
        .await
        .unwrap();
}

/// N1: tenant A's seeded admin cannot read the deployment-wide nil-tenant
/// partition, which holds other tenants' request metadata.
///
/// The second caller holds `audit_logs:list_system` explicitly in tenant A — an
/// operator-made role, or a grant an older seeder made — and only the scope
/// guard refuses it.
#[actix_rt::test]
async fn standard_tenant_admin_cannot_read_the_system_audit_partition() {
    let (db, org_id, tenant_a) = setup_db().await;
    let tenant_b = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Tenant B".into(),
            slug: "tenant-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    seed_tenant(&db, tenant_a).await;
    seed_tenant(&db, tenant_b.id).await;
    sibling_traffic_in_the_system_partition(&db).await;

    let seeded_admin = tenant_user(&db, tenant_a, "a-admin", Some("admin"), None).await;
    let explicit = tenant_user(
        &db,
        tenant_a,
        "a-system-reader",
        None,
        Some("audit_logs:list_system"),
    )
    .await;

    let auth = test_auth_config();
    let app = real_authz_app!(db, auth);
    for (who, user_id) in [("seeded admin", seeded_admin), ("explicit grant", explicit)] {
        let token = mint_token(&auth, user_id, tenant_a, org_id);
        let req = test::TestRequest::get()
            .uri("/api/v1/audit-logs/system")
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        let status = resp.status().as_u16();
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert_eq!(
            status, 403,
            "tenant A's {who} must not read the system audit partition; body: {body}"
        );
        assert!(
            !body.contains("192.0.2.10"),
            "tenant B's traffic leaked to tenant A's {who}"
        );
    }
}

/// N1, the other side: an organization-level principal holding
/// `audit_logs:list_system` still reads the partition.
#[actix_rt::test]
async fn organization_principal_reads_the_system_audit_partition() {
    let (db, org_id, _tenant_id) = setup_db().await;
    let scope = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant::organization_scope(org_id))
        .await
        .unwrap();
    seed_tenant(&db, scope.id).await;
    sibling_traffic_in_the_system_partition(&db).await;
    let operator = tenant_user(&db, scope.id, "org-admin", Some("super-admin"), None).await;

    let auth = test_auth_config();
    let app = real_authz_app!(db, auth);
    let token = mint_token(&auth, operator, scope.id, org_id);
    let req = test::TestRequest::get()
        .uri("/api/v1/audit-logs/system")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["ip_address"], "192.0.2.10");
}

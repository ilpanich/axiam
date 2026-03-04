//! Integration tests for audit log query endpoint.

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    AuditLogRepository, OrganizationRepository, TenantRepository, UserRepository,
};
use axiam_db::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

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
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    user.id
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(user_id, tenant_id, org_id, auth).unwrap()
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(SurrealAuditLogRepository::new($db.clone())))
                .configure(register_api_v1_routes::<TestDb>),
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

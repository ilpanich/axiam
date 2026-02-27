//! Integration tests for service account endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::register_api_v1_routes;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealServiceAccountRepository, SurrealTenantRepository, SurrealUserRepository,
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
                .app_data(web::Data::new(SurrealOrganizationRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealTenantRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealUserRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealGroupRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealRoleRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealPermissionRepository::new(
                    $db.clone(),
                )))
                .app_data(web::Data::new(SurrealResourceRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealScopeRepository::new($db.clone())))
                .app_data(web::Data::new(SurrealServiceAccountRepository::new(
                    $db.clone(),
                )))
                .configure(register_api_v1_routes::<TestDb>),
        )
        .await
    };
}

#[actix_rt::test]
async fn create_service_account_returns_201_with_secret() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "CI Bot" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "CI Bot");
    assert!(body["client_id"].is_string());
    assert!(body["client_secret"].is_string());
    // Secret should be non-empty
    assert!(!body["client_secret"].as_str().unwrap().is_empty());
}

#[actix_rt::test]
async fn create_service_account_omits_secret_hash() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "Deploy Bot" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("client_secret_hash").is_none());
}

#[actix_rt::test]
async fn list_service_accounts_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "Bot 1" }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::get()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1);
    assert!(body["items"][0].get("client_secret_hash").is_none());
}

#[actix_rt::test]
async fn get_service_account_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "My Bot" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let sa_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/service-accounts/{sa_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "My Bot");
    assert!(body.get("client_secret_hash").is_none());
}

#[actix_rt::test]
async fn update_service_account_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "Old Bot" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let sa_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::put()
        .uri(&format!("/api/v1/service-accounts/{sa_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "New Bot" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "New Bot");
}

#[actix_rt::test]
async fn delete_service_account_returns_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "Temp Bot" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let sa_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/service-accounts/{sa_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

#[actix_rt::test]
async fn rotate_secret_returns_new_secret() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/service-accounts")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({ "name": "Rotate Bot" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let sa_id = created["id"].as_str().unwrap();
    let old_secret = created["client_secret"].as_str().unwrap().to_string();

    // Rotate
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/service-accounts/{sa_id}/rotate-secret"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body["client_secret"].is_string());
    assert_ne!(body["client_secret"].as_str().unwrap(), old_secret);
}

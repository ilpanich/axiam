//! Integration tests for the MFA method management endpoints
//! (`/api/v1/users/{user_id}/mfa-methods`).
//!
//! In-memory SurrealDB + `AllowAllAuthzChecker`; exercises the own-resource
//! vs. admin-permission branch and the list/delete handlers.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::{SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository};
use serde_json::Value;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow

/// Matching CSRF header/cookie value for the double-submit middleware.
const CSRF_TOKEN: &str = "test-csrf-token";

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

async fn setup() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "MFA Org".into(),
            slug: "mfa-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "MFA Tenant".into(),
            slug: "mfa-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "mfa-admin".into(),
            email: "mfa-admin@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
}

fn mint_token(auth: &AuthConfig, user_id: Uuid, tenant_id: Uuid, org_id: Uuid) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        Uuid::new_v4().to_string(),
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

#[actix_web::test]
async fn list_own_mfa_methods_is_ok() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Caller lists their OWN methods (is_own_resource == true, no admin check).
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{user_id}/mfa-methods"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert!(body.is_array(), "expected a JSON array of methods");
}

#[actix_web::test]
async fn list_other_user_mfa_methods_takes_permission_branch() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    // A real second user in the same tenant: the caller is NOT this user, so
    // the RequirePermission("users:admin") branch runs (passed by AllowAll).
    let other = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "mfa-other".into(),
            email: "mfa-other@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let app = test_app!(db, auth);
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}/mfa-methods", other.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
}

#[actix_web::test]
async fn delete_mfa_method_is_idempotent() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Removing a method for a user with MFA disabled exercises the delete
    // handler; with no last-method guard tripped it succeeds idempotently.
    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/users/{user_id}/mfa-methods/totp"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

#[actix_web::test]
async fn delete_other_user_mfa_method_takes_permission_branch() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    let other = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "mfa-other-del".into(),
            email: "mfa-other-del@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let app = test_app!(db, auth);
    // Deleting another user's method forces the admin-permission branch.
    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/users/{}/mfa-methods/totp", other.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

#[actix_web::test]
async fn mfa_methods_require_authentication() {
    let (db, _org_id, _tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{user_id}/mfa-methods"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 401);
}

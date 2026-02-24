//! Integration tests for authentication extractors and authorization guards.

use std::sync::Arc;

use actix_web::web;
use actix_web::{App, HttpResponse};
use axiam_api_rest::RequirePermission;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::error::AxiamApiError;
use axiam_api_rest::extractors::auth::AuthenticatedUser;
use axiam_api_rest::extractors::tenant::TenantContext;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::CreatePermission;
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::CreateRole;
use axiam_core::models::scope::CreateScope;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{
    OrganizationRepository, PermissionRepository, ResourceRepository, RoleRepository,
    ScopeRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use serde::Deserialize;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

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

fn test_auth_config(lifetime: u64) -> AuthConfig {
    let (priv_pem, pub_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: priv_pem,
        jwt_public_key_pem: pub_pem,
        access_token_lifetime_secs: lifetime,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        pepper: None,
        min_password_length: 12,
        mfa_encryption_key: None,
        mfa_challenge_lifetime_secs: 300,
        totp_issuer: "AXIAM-Test".into(),
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
    }
}

/// Create in-memory DB with org + tenant + user, return IDs.
async fn setup_db() -> (
    Surreal<surrealdb::engine::local::Db>,
    Uuid, // org_id
    Uuid, // tenant_id
    Uuid, // user_id
) {
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

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: "pass123456789".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
}

fn make_authz(db: &Surreal<surrealdb::engine::local::Db>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

// -----------------------------------------------------------------------
// Test handlers
// -----------------------------------------------------------------------

async fn echo_user(user: AuthenticatedUser) -> Result<HttpResponse, AxiamApiError> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "user_id": user.user_id.to_string(),
        "tenant_id": user.tenant_id.to_string(),
        "org_id": user.org_id.to_string(),
    })))
}

async fn echo_tenant(ctx: TenantContext) -> Result<HttpResponse, AxiamApiError> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "tenant_id": ctx.tenant_id.to_string(),
        "org_id": ctx.org_id.to_string(),
    })))
}

async fn guarded_endpoint(
    user: AuthenticatedUser,
    authz: web::Data<Arc<dyn AuthzChecker>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    let resource_id = path.into_inner();
    RequirePermission::new("read", resource_id)
        .check(&user, authz.get_ref().as_ref())
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "ok"})))
}

async fn scoped_endpoint(
    user: AuthenticatedUser,
    authz: web::Data<Arc<dyn AuthzChecker>>,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, AxiamApiError> {
    let (resource_id, scope) = path.into_inner();
    RequirePermission::new("read", resource_id)
        .with_scope(scope)
        .check(&user, authz.get_ref().as_ref())
        .await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "ok"})))
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[derive(Deserialize)]
struct UserEcho {
    user_id: String,
    tenant_id: String,
    org_id: String,
}

#[derive(Deserialize)]
struct TenantEcho {
    tenant_id: String,
    org_id: String,
}

#[actix_web::test]
async fn missing_auth_header_returns_401() {
    let config = test_auth_config(900);
    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/me", web::get().to(echo_user)),
    )
    .await;

    let req = actix_web::test::TestRequest::get().uri("/me").to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn invalid_token_returns_401() {
    let config = test_auth_config(900);
    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/me", web::get().to(echo_user)),
    )
    .await;

    let req = actix_web::test::TestRequest::get()
        .uri("/me")
        .insert_header(("Authorization", "Bearer garbage.token.here"))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn wrong_auth_scheme_returns_401() {
    let config = test_auth_config(900);

    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/me", web::get().to(echo_user)),
    )
    .await;

    // Use Basic scheme instead of Bearer.
    let req = actix_web::test::TestRequest::get()
        .uri("/me")
        .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn valid_token_extracts_user() {
    let config = test_auth_config(900);
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    let token = issue_access_token(user_id, tenant_id, org_id, &config).unwrap();

    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/me", web::get().to(echo_user)),
    )
    .await;

    let req = actix_web::test::TestRequest::get()
        .uri("/me")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: UserEcho = actix_web::test::read_body_json(resp).await;
    assert_eq!(body.user_id, user_id.to_string());
    assert_eq!(body.tenant_id, tenant_id.to_string());
    assert_eq!(body.org_id, org_id.to_string());
}

#[actix_web::test]
async fn tenant_context_matches_jwt() {
    let config = test_auth_config(900);
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();

    let token = issue_access_token(user_id, tenant_id, org_id, &config).unwrap();

    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/tenant", web::get().to(echo_tenant)),
    )
    .await;

    let req = actix_web::test::TestRequest::get()
        .uri("/tenant")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);

    let body: TenantEcho = actix_web::test::read_body_json(resp).await;
    assert_eq!(body.tenant_id, tenant_id.to_string());
    assert_eq!(body.org_id, org_id.to_string());
}

#[actix_web::test]
async fn authorized_request_returns_200() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let config = test_auth_config(900);
    let authz = make_authz(&db);

    // Create resource + role + permission + assignment.
    let resource_repo = SurrealResourceRepository::new(db.clone());
    let resource = resource_repo
        .create(CreateResource {
            tenant_id,
            name: "api".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let role_repo = SurrealRoleRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "reader".into(),
            description: "Can read".into(),
            is_global: false,
        })
        .await
        .unwrap();

    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "read".into(),
            description: "Read access".into(),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role(tenant_id, role.id, perm.id)
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant_id, user_id, role.id, Some(resource.id))
        .await
        .unwrap();

    let token = issue_access_token(user_id, tenant_id, org_id, &config).unwrap();

    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(authz))
            .route("/resource/{id}", web::get().to(guarded_endpoint)),
    )
    .await;

    let req = actix_web::test::TestRequest::get()
        .uri(&format!("/resource/{}", resource.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn unauthorized_request_returns_403() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let config = test_auth_config(900);
    let authz = make_authz(&db);

    // Create resource but NO role/permission assignment.
    let resource_repo = SurrealResourceRepository::new(db.clone());
    let resource = resource_repo
        .create(CreateResource {
            tenant_id,
            name: "secret".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let token = issue_access_token(user_id, tenant_id, org_id, &config).unwrap();

    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(authz))
            .route("/resource/{id}", web::get().to(guarded_endpoint)),
    )
    .await;

    let req = actix_web::test::TestRequest::get()
        .uri(&format!("/resource/{}", resource.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403);
}

#[actix_web::test]
async fn scope_authorization_check() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let config = test_auth_config(900);
    let authz = make_authz(&db);

    // Create resource with scope.
    let resource_repo = SurrealResourceRepository::new(db.clone());
    let resource = resource_repo
        .create(CreateResource {
            tenant_id,
            name: "api".into(),
            resource_type: "service".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let scope_repo = SurrealScopeRepository::new(db.clone());
    let scope = scope_repo
        .create(CreateScope {
            tenant_id,
            resource_id: resource.id,
            name: "users:list".into(),
            description: "list users".into(),
        })
        .await
        .unwrap();

    // Grant with scope constraint.
    let role_repo = SurrealRoleRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id,
            name: "scoped-reader".into(),
            description: "Scoped read".into(),
            is_global: false,
        })
        .await
        .unwrap();

    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let perm = perm_repo
        .create(CreatePermission {
            tenant_id,
            action: "read".into(),
            description: "Read".into(),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role_with_scopes(tenant_id, role.id, perm.id, vec![scope.id])
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant_id, user_id, role.id, Some(resource.id))
        .await
        .unwrap();

    let token = issue_access_token(user_id, tenant_id, org_id, &config).unwrap();

    let app = actix_web::test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .app_data(web::Data::new(authz))
            .route(
                "/resource/{id}/scope/{scope}",
                web::get().to(scoped_endpoint),
            ),
    )
    .await;

    // Matching scope → 200.
    let req = actix_web::test::TestRequest::get()
        .uri(&format!("/resource/{}/scope/users:list", resource.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = actix_web::test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

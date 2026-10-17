//! Integration tests for user management endpoints.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_authz::AuthorizationEngine;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::repository::{OrganizationRepository, TenantRepository, UserRepository};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealResourceRepository, SurrealRoleRepository, SurrealScopeRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{seed_default_roles, seed_permissions};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Arbitrary CSRF token for the double-submit check (SEC-046). These
/// Bearer-token tests have no login/`axiam_csrf` cookie, so we send a matching
/// `axiam_csrf` cookie + `X-CSRF-Token` header; the middleware only checks they
/// are equal (no session lookup). Safe (GET) requests ignore it.
const CSRF_TOKEN: &str = "test-csrf-token";

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

/// Set up in-memory DB with org + tenant, return (db, org_id, tenant_id).
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

/// Create a user in the DB and return its ID (for minting JWT).
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

/// Fresh in-memory DB with org+tenant AND the real permission registry +
/// default roles seeded — required for RBAC-gated (non-`AllowAllAuthzChecker`)
/// tests (FUNC-04).
async fn setup_db_with_rbac() -> (Surreal<TestDb>, Uuid, Uuid) {
    let (db, org_id, tenant_id) = setup_db().await;
    seed_permissions(&db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    seed_default_roles(&db, tenant_id, PERMISSION_REGISTRY)
        .await
        .unwrap();
    (db, org_id, tenant_id)
}

/// Real RBAC engine (not `AllowAllAuthzChecker`) — needed to genuinely
/// exercise `RequirePermission` gates rather than bypass them.
fn make_real_authz(db: &Surreal<TestDb>) -> Arc<dyn AuthzChecker> {
    Arc::new(AuthorizationEngine::new(
        SurrealRoleRepository::new(db.clone()),
        SurrealPermissionRepository::new(db.clone()),
        SurrealResourceRepository::new(db.clone()),
        SurrealScopeRepository::new(db.clone()),
        SurrealGroupRepository::new(db.clone()),
    ))
}

/// Create a user with NO role assigned — lacks every permission, including
/// `users:list` (FUNC-04 non-privileged-caller fixture).
async fn create_user_no_role(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    username: &str,
    email: &str,
) -> Uuid {
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id,
            username: username.into(),
            email: email.into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();
    user.id
}

macro_rules! test_app_real_authz {
    ($db:expr, $auth:expr, $authz:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new($authz.clone()))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
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

#[actix_rt::test]
async fn create_user_returns_201() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "alice",
            "email": "alice@example.com",
            "password": "securepass123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "alice");
    assert_eq!(body["email"], "alice@example.com");
    assert!(body["id"].is_string());
    assert_eq!(body["status"], "PendingVerification");
}

#[actix_rt::test]
async fn create_user_omits_sensitive_fields() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "bob",
            "email": "bob@example.com",
            "password": "securepass123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert!(body.get("password_hash").is_none());
    assert!(body.get("mfa_secret").is_none());
    // failed_login_attempts and locked_until are now exposed in UserResponse
    // for admin visibility of lockout state
    assert!(body["failed_login_attempts"].is_number());
    assert!(body.get("locked_until").is_some()); // present (may be null)
}

#[actix_rt::test]
async fn list_users_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["total"], 1); // admin user created in setup
    assert!(body["items"].is_array());
    assert!(body["items"][0].get("password_hash").is_none());
}

#[actix_rt::test]
async fn get_user_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "admin");
    assert_eq!(body["email"], "admin@example.com");
}

#[actix_rt::test]
async fn update_user_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "admin-updated",
            "status": "Active"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], "admin-updated");
    // SEC-050: `status` is stripped on self-update (a user cannot change their
    // own account status), so it stays at the created default rather than the
    // requested "Active". This positively asserts the privilege-escalation guard.
    assert_eq!(body["status"], "PendingVerification");
}

#[actix_rt::test]
async fn delete_user_returns_204() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // Create a second user to delete
    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "username": "to-delete",
            "email": "delete@example.com",
            "password": "securepass123"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let delete_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{delete_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

/// CQ-B16: DELETE of a nonexistent user id must return 404, not silently 204.
#[actix_rt::test]
async fn delete_nonexistent_user_returns_404() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let fake_id = Uuid::new_v4();
    let req = test::TestRequest::delete()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{fake_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn user_response_includes_lock_state_fields() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    // is_locked should be present and false for a freshly created user
    assert_eq!(body["is_locked"], false);
    // locked_until should be present (null for a non-locked user)
    assert!(body.get("locked_until").is_some());
    // failed_login_attempts should be 0
    assert_eq!(body["failed_login_attempts"], 0);
}

#[actix_rt::test]
async fn unlock_user_returns_200() {
    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    // POST to unlock endpoint — user is not locked but unlock is idempotent
    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}/unlock"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["is_locked"], false);
    assert_eq!(body["failed_login_attempts"], 0);
    assert!(body["locked_until"].is_null());
    // status should be Active after unlock
    assert_eq!(body["status"], "Active");
}

/// FUNC-04 (Task 3, verify-only): a caller lacking `users:list` must be
/// denied (403) on `GET /api/v1/users`. Uses the real `AuthorizationEngine`
/// (not `AllowAllAuthzChecker`) so the existing
/// `RequirePermission::new("users:list", ...)` gate in `handlers/users.rs`
/// is genuinely exercised end-to-end. No handler code was changed — this
/// test only proves the pre-existing gate works.
#[actix_rt::test]
async fn list_users_non_privileged_caller_returns_403() {
    let (db, org_id, tenant_id) = setup_db_with_rbac().await;
    let auth = test_auth_config();
    let authz = make_real_authz(&db);
    let no_role_user_id =
        create_user_no_role(&db, tenant_id, "no-role", "no-role@example.com").await;
    let token = mint_token(&auth, no_role_user_id, tenant_id, org_id);
    let app = test_app_real_authz!(db, auth, authz);

    let req = test::TestRequest::get()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/users")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);
}

/// #533 — deleting a user revokes the `User` certificates issued for them —
/// by the binding, and for a certificate issued before it by the convention on
/// the account's username — and not another account's certificate that only
/// shares the name. Revoked, not deleted: each stays on its issuer's list. One
/// `user.certificates_revoked` audit row carries the count.
#[actix_rt::test]
async fn deleting_a_user_revokes_their_user_certificates_and_no_one_elses() {
    use axiam_core::models::certificate::{
        CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
    };
    use axiam_core::repository::{
        AuditLogFilter, AuditLogRepository, CertificateRepository, Pagination,
    };
    use axiam_db::repository::{SurrealAuditLogRepository, SurrealCertificateRepository};

    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, admin, tenant_id, org_id);
    let alice = create_user_no_role(&db, tenant_id, "alice", "alice@example.com").await;
    let bob = create_user_no_role(&db, tenant_id, "bob", "bob@example.com").await;
    let app = test_app!(db, auth);

    let certs = SurrealCertificateRepository::new(db.clone());
    let issuer = Uuid::new_v4();
    let leaf = |fingerprint: &str, subject: &str, user_id: Option<Uuid>| StoreCertificate {
        tenant_id,
        issuer_ca_id: issuer,
        subject: subject.into(),
        public_cert_pem: "not-a-parsed-certificate".into(),
        fingerprint: fingerprint.into(),
        cert_type: CertificateType::User,
        key_algorithm: KeyAlgorithm::Ed25519,
        not_before: chrono::Utc::now() - chrono::Duration::minutes(1),
        not_after: chrono::Utc::now() + chrono::Duration::days(30),
        metadata: serde_json::json!({}),
        user_id,
    };
    let bound = certs
        .create(leaf("fp-bound", "alice-laptop", Some(alice)))
        .await
        .unwrap();
    let legacy = certs
        .create(leaf("fp-legacy", "Alice", None))
        .await
        .unwrap();
    let bobs = certs
        .create(leaf("fp-bob", "alice", Some(bob)))
        .await
        .unwrap();

    let req = test::TestRequest::delete()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{alice}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    for (label, cert, expected) in [
        ("bound", &bound, CertificateStatus::Revoked),
        ("legacy", &legacy, CertificateStatus::Revoked),
        ("bob's", &bobs, CertificateStatus::Active),
    ] {
        let read = certs.get_by_id(tenant_id, cert.id).await.unwrap();
        assert_eq!(read.status, expected, "the {label} certificate");
    }
    let listed: Vec<String> = certs
        .list_revoked_by_issuer(issuer, chrono::Utc::now())
        .await
        .unwrap()
        .into_iter()
        .map(|entry| {
            assert!(entry.revoked_at.is_some(), "the revocation is dated");
            entry.fingerprint
        })
        .collect();
    assert_eq!(listed.len(), 2, "both on the issuer's list");

    let rows = SurrealAuditLogRepository::new(db.clone())
        .list(
            tenant_id,
            AuditLogFilter {
                action: Some("user.certificates_revoked".into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert_eq!(rows.items.len(), 1, "one summary row");
    let row = &rows.items[0];
    assert_eq!(row.actor_id, admin);
    assert_eq!(row.resource_id, Some(alice));
    assert_eq!(row.metadata["certificates_revoked"], 2);
}

/// R101W1-01 — deleting an account does not revoke another account's
/// certificate by a name the two share only up to case: `alice`'s unbound
/// CN-`alice` certificate, issued before `Alice` existed, stays active when an
/// administrator deletes `Alice`.
#[actix_rt::test]
async fn deleting_an_account_leaves_an_older_namesakes_certificate_alone() {
    use axiam_core::models::certificate::{
        CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
    };
    use axiam_core::repository::CertificateRepository;
    use axiam_db::repository::SurrealCertificateRepository;

    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, admin, tenant_id, org_id);
    create_user_no_role(&db, tenant_id, "alice", "alice@example.com").await;

    let certs = SurrealCertificateRepository::new(db.clone());
    let alices = certs
        .create(StoreCertificate {
            tenant_id,
            issuer_ca_id: Uuid::new_v4(),
            subject: "alice".into(),
            public_cert_pem: "not-a-parsed-certificate".into(),
            fingerprint: "fp-alice".into(),
            cert_type: CertificateType::User,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: chrono::Utc::now() - chrono::Duration::minutes(1),
            not_after: chrono::Utc::now() + chrono::Duration::days(30),
            metadata: serde_json::json!({}),
            user_id: None,
        })
        .await
        .unwrap();
    // Created after the certificate, named after its CN in another case.
    let upper = create_user_no_role(&db, tenant_id, "Alice", "ALICE@example.com").await;
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{upper}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    assert_eq!(
        certs.get_by_id(tenant_id, alices.id).await.unwrap().status,
        CertificateStatus::Active,
        "alice's certificate is not Alice's"
    );
}

/// R101W1-09 (c): `DELETE` of an id no account of the tenant has answers `404`
/// and revokes nothing — not even a certificate whose `metadata.user_id` names
/// that id, which the deletion of a real account would revoke. Before the fix
/// the revocation ran by the id alone, ahead of the `404`.
#[actix_rt::test]
async fn deleting_an_unknown_user_revokes_nothing() {
    use axiam_core::models::certificate::{
        CertificateStatus, CertificateType, KeyAlgorithm, StoreCertificate,
    };
    use axiam_core::repository::{
        AuditLogFilter, AuditLogRepository, CertificateRepository, Pagination,
    };
    use axiam_db::repository::{SurrealAuditLogRepository, SurrealCertificateRepository};

    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let admin = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, admin, tenant_id, org_id);
    let unknown = Uuid::new_v4();

    let certs = SurrealCertificateRepository::new(db.clone());
    let named = certs
        .create(StoreCertificate {
            tenant_id,
            issuer_ca_id: Uuid::new_v4(),
            subject: "someones-laptop".into(),
            public_cert_pem: "not-a-parsed-certificate".into(),
            fingerprint: "fp-named-by-metadata".into(),
            cert_type: CertificateType::User,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: chrono::Utc::now() - chrono::Duration::minutes(1),
            not_after: chrono::Utc::now() + chrono::Duration::days(30),
            metadata: serde_json::json!({ "user_id": unknown.to_string() }),
            user_id: None,
        })
        .await
        .unwrap();
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{unknown}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 404);

    let read = certs.get_by_id(tenant_id, named.id).await.unwrap();
    assert_eq!(read.status, CertificateStatus::Active, "nothing revoked");
    let rows = SurrealAuditLogRepository::new(db.clone())
        .list(
            tenant_id,
            AuditLogFilter {
                action: Some("user.certificates_revoked".into()),
                ..Default::default()
            },
            Pagination::default(),
        )
        .await
        .unwrap();
    assert!(rows.items.is_empty(), "and no revocation recorded");
}

/// Item A of the 1.1.0 atomicity audit, end to end through the routes.
///
/// The attack: the account holds an unredeemed verification link for the
/// address it has (A), changes its address by self-service to one it does not
/// own (B), and redeems the link. Before v102 the token named no address, so
/// it verified B and activated the account. Now the change spends both links
/// mailed to A — the verification link and a reset link — in the write that
/// moves the address, and the token is bound to A besides.
#[actix_rt::test]
async fn a_self_email_change_spends_the_old_address_verification_and_reset_links() {
    use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
    use axiam_core::models::email_verification::CreateEmailVerificationToken;
    use axiam_core::models::password_reset::CreatePasswordResetToken;
    use axiam_core::models::user::UserStatus;
    use axiam_core::repository::{EmailVerificationTokenRepository, PasswordResetTokenRepository};
    use axiam_db::repository::{
        SurrealEmailVerificationTokenRepository, SurrealPasswordResetTokenRepository,
    };

    let (db, org_id, tenant_id) = setup_db().await;
    let auth = test_auth_config();
    let user_id = create_admin_user(&db, tenant_id).await;
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let users = SurrealUserRepository::new(db.clone());
    let before = users.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(before.status, UserStatus::PendingVerification);

    // Both links mailed to A.
    let verify_raw = generate_refresh_token();
    SurrealEmailVerificationTokenRepository::new(db.clone())
        .create(CreateEmailVerificationToken {
            tenant_id,
            user_id,
            token_hash: hash_refresh_token(&verify_raw),
            email: before.email.clone(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        })
        .await
        .unwrap();
    let reset_raw = generate_refresh_token();
    SurrealPasswordResetTokenRepository::new(db.clone())
        .create(CreatePasswordResetToken {
            tenant_id,
            user_id,
            token_hash: hash_refresh_token(&reset_raw),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        })
        .await
        .unwrap();

    // The self-service change to B.
    let req = test::TestRequest::put()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri(&format!("/api/v1/users/{user_id}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "email": "victim@b.example" }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

    // Both rows went with the old address, in the same write.
    assert!(
        SurrealEmailVerificationTokenRepository::new(db.clone())
            .get_by_token_hash(tenant_id, &hash_refresh_token(&verify_raw))
            .await
            .is_err(),
        "the verification link for A is gone"
    );
    assert!(
        SurrealPasswordResetTokenRepository::new(db.clone())
            .get_by_token_hash(tenant_id, &hash_refresh_token(&reset_raw))
            .await
            .is_err(),
        "the reset link mailed to A is gone"
    );

    // Redeeming A's link verifies nothing.
    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/auth/verify-email")
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "tenant_id": tenant_id, "token": verify_raw }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);

    // And A's reset link resets nothing.
    let req = test::TestRequest::post()
        .insert_header(("X-Forwarded-For", "127.0.0.1"))
        .uri("/api/v1/auth/reset/confirm")
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "tenant_id": tenant_id,
            "token": reset_raw,
            "new_password": "AnotherStr0ngPassword77",
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 400);

    let after = users.get_by_id(tenant_id, user_id).await.unwrap();
    assert_eq!(after.email, "victim@b.example");
    assert!(after.email_verified_at.is_none(), "B is not verified");
    assert_eq!(after.status, UserStatus::PendingVerification);
    assert_eq!(
        after.password_hash, before.password_hash,
        "the password is unchanged"
    );
}

/// An update that leaves the address as it is spends no link: the deletion
/// is decided against the stored value, not by the request naming `email`.
#[actix_rt::test]
async fn an_update_naming_the_same_address_keeps_the_links() {
    use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
    use axiam_core::models::email_verification::CreateEmailVerificationToken;
    use axiam_core::models::user::UpdateUser;
    use axiam_core::repository::EmailVerificationTokenRepository;
    use axiam_db::repository::SurrealEmailVerificationTokenRepository;

    let (db, _org_id, tenant_id) = setup_db().await;
    let user_id = create_admin_user(&db, tenant_id).await;
    let users = SurrealUserRepository::new(db.clone());
    let tokens = SurrealEmailVerificationTokenRepository::new(db.clone());
    let raw = generate_refresh_token();
    tokens
        .create(CreateEmailVerificationToken {
            tenant_id,
            user_id,
            token_hash: hash_refresh_token(&raw),
            email: "admin@example.com".into(),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24),
        })
        .await
        .unwrap();
    users
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                email: Some("admin@example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        tokens
            .get_by_token_hash(tenant_id, &hash_refresh_token(&raw))
            .await
            .is_ok()
    );
}

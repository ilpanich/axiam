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
use axiam_core::models::tenant::{CreateTenant, TenantKind};
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
            kind: TenantKind::Standard,
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

// ---------------------------------------------------------------------------
// M-1 — the administrative reset evicts WebAuthn credentials too (T-34)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn reset_mfa_removes_passkeys_as_well_as_totp() {
    use axiam_core::models::user::UpdateUser;
    use axiam_core::models::webauthn_credential::{
        CreateWebauthnCredential, WebauthnCredentialType,
    };
    use axiam_core::repository::WebauthnCredentialRepository;
    use axiam_db::SurrealWebauthnCredentialRepository;

    let (db, org_id, tenant_id, user_id) = setup().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);

    // A user with both kinds of factor: a confirmed TOTP secret and a passkey.
    let user_repo = SurrealUserRepository::new(db.clone());
    user_repo
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                mfa_enabled: Some(true),
                mfa_secret: Some(Some("encrypted-secret-placeholder".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let cred_repo = SurrealWebauthnCredentialRepository::new(db.clone());
    cred_repo
        .create(CreateWebauthnCredential {
            tenant_id,
            user_id,
            credential_id: "cred-suspect".into(),
            name: "Suspected authenticator".into(),
            credential_type: WebauthnCredentialType::Passkey,
            passkey_json: r#"{"dummy":"passkey"}"#.into(),
            aaguid: None,
            attestation_format: None,
            attested: false,
            authenticator_name: None,
        })
        .await
        .unwrap();

    let app = test_app!(db, auth);

    // Both factors are listed before the reset.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{user_id}/mfa-methods"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let body: Value = test::read_body_json(test::call_service(&app, req).await).await;
    assert_eq!(body.as_array().unwrap().len(), 2);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    // The admin UI says the reset "removes ALL MFA methods". Through the wire,
    // it now does — before M-1 the passkey was still here.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{user_id}/mfa-methods"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let body: Value = test::read_body_json(test::call_service(&app, req).await).await;
    assert_eq!(
        body.as_array().unwrap().len(),
        0,
        "every factor must be gone after an administrative reset, got {body}"
    );
    assert_eq!(
        cred_repo.count_by_user(tenant_id, user_id).await.unwrap(),
        0
    );
}

// ---------------------------------------------------------------------------
// M-2 — self-service reset refused where the tenant enforces MFA (D-1, T-267)
// ---------------------------------------------------------------------------

/// Enable `mfa_enforced` at the organization level, which every tenant under
/// it inherits (`clamp_enable_only!`: a tenant may not switch off what the
/// organization enforces).
async fn enforce_mfa(db: &Surreal<TestDb>, org_id: Uuid) {
    use axiam_core::models::settings::system_defaults;
    use axiam_core::repository::SettingsRepository;

    let mut defaults = system_defaults();
    defaults.mfa_enforced = true;
    axiam_db::SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org_id, defaults)
        .await
        .unwrap();
}

/// Give the user a TOTP factor, so that a reset that went through would have
/// something to remove — otherwise the refusal and a no-op look alike.
async fn give_totp(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) {
    use axiam_core::models::user::UpdateUser;

    SurrealUserRepository::new(db.clone())
        .update(
            tenant_id,
            user_id,
            UpdateUser {
                mfa_enabled: Some(true),
                mfa_secret: Some(Some("encrypted-secret-placeholder".into())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

#[actix_web::test]
async fn self_reset_is_refused_under_an_enforcing_tenant() {
    let (db, org_id, tenant_id, user_id) = setup().await;
    enforce_mfa(&db, org_id).await;
    give_totp(&db, tenant_id, user_id).await;

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 403);

    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["error"], "mfa_enforced",
        "the code must be distinguishable from `authorization_denied`: the \
         caller holds every permission, and only an administrator can act \
         against the policy — got {body}"
    );

    // The factor is untouched. A refusal that had already removed something
    // would be the hole with an error message on it.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/users/{user_id}/mfa-methods"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let body: Value = test::read_body_json(test::call_service(&app, req).await).await;
    assert_eq!(body.as_array().unwrap().len(), 1);
}

#[actix_web::test]
async fn self_reset_still_works_where_mfa_is_optional() {
    // D-1's other half: a user of a non-enforcing tenant was free to run at
    // one factor anyway, so nothing is protected by refusing them.
    let (db, org_id, tenant_id, user_id) = setup().await;
    give_totp(&db, tenant_id, user_id).await;

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/users/{user_id}/reset-mfa"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);
}

#[actix_web::test]
async fn admin_reset_ignores_the_enforcement_flag() {
    // The endpoint exists so that an administrator can unlock a user who lost
    // their only factor. An enforcing tenant is exactly where that matters
    // most, so the enforcement check must not reach this branch.
    let (db, org_id, tenant_id, admin_id) = setup().await;
    enforce_mfa(&db, org_id).await;

    let target = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id,
            username: "locked-out".into(),
            email: "locked-out@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    give_totp(&db, tenant_id, target.id).await;

    let auth = test_auth_config();
    let token = mint_token(&auth, admin_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/users/{}/reset-mfa", target.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        204,
        "`users:admin` is unaffected by the enforcement flag"
    );
}

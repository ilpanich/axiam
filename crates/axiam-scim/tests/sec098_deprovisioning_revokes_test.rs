//! SEC-098 — a SCIM credential change must not leave a live credential behind.
//!
//! Before this, every SCIM write called `invalidate_subject` — the
//! *authorization decision* cache — and nothing else. That clears cached
//! `Allow`s; it does not touch a single credential. So:
//!
//! * a password rotated through SCIM to lock out a compromised account left
//!   the attacker's session and OAuth2 refresh token spendable, and
//! * an `active: false` or `DELETE /Users/{id}` written by an IdP's
//!   offboarding job did the same — on the one path an IdP drives
//!   *deprovisioning* through, which is precisely where immediacy is assumed.
//!
//! Each test below creates a live session **and** a live OAuth2 refresh token
//! for the target, drives the SCIM write, and asserts both are gone. Every one
//! fails before the fix.

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, Pagination, RefreshTokenRepository, RoleRepository, SessionRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealRefreshTokenRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealSessionRepository, SurrealTenantRepository,
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
        .assign_to_user(tenant_id, user.id, role.id, None)
        .await
        .unwrap();
    user.id
}

/// A live session **and** a live OAuth2 refresh token for `user_id` — the two
/// separate tables `AuthService::revoke_all_sessions` hits, both of which SCIM
/// used to leave alone.
async fn give_live_credentials(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) -> String {
    SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: axiam_auth::token::hash_refresh_token(&generated_secret("session")),
            ip_address: None,
            user_agent: None,
            expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        })
        .await
        .expect("create session");

    let raw = generated_secret("refresh");
    SurrealRefreshTokenRepository::new(db.clone())
        .create(CreateRefreshToken {
            tenant_id,
            token_hash: axiam_auth::token::hash_refresh_token(&raw),
            client_id: "oa_test_client".into(),
            user_id: Some(user_id),
            scopes: vec!["openid".into()],
            session_id: None,
            expires_at: chrono::Utc::now() + chrono::Duration::days(7),
        })
        .await
        .expect("create oauth2 refresh token");
    raw
}

async fn live_session_count(db: &Surreal<TestDb>, tenant_id: Uuid, user_id: Uuid) -> usize {
    SurrealSessionRepository::new(db.clone())
        .list_by_user(tenant_id, user_id)
        .await
        .expect("list sessions")
        .len()
}

/// `get_by_token_hash` looks up a **non-revoked, non-expired** token, so a
/// successful lookup is exactly "this refresh token is still spendable".
async fn refresh_token_is_spendable(db: &Surreal<TestDb>, tenant_id: Uuid, raw: &str) -> bool {
    SurrealRefreshTokenRepository::new(db.clone())
        .get_by_token_hash(tenant_id, &axiam_auth::token::hash_refresh_token(raw))
        .await
        .is_ok()
}

async fn assert_all_revoked(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    user_id: Uuid,
    raw_refresh: &str,
    what: &str,
) {
    assert_eq!(
        live_session_count(db, tenant_id, user_id).await,
        0,
        "{what} must revoke every live session"
    );
    assert!(
        !refresh_token_is_spendable(db, tenant_id, raw_refresh).await,
        "{what} must revoke every live OAuth2 refresh token — the second of the two \
         tables a credential change has to hit"
    );
}

#[actix_rt::test]
async fn a_scim_password_write_revokes_every_live_credential() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let provisioner = user_with_role(&db, tenant_id, "admin").await;
    let token = mint_token(&auth, provisioner, tenant_id, org_id);
    let target = user_with_role(&db, tenant_id, "viewer").await;
    let raw_refresh = give_live_credentials(&db, tenant_id, target).await;

    assert_eq!(live_session_count(&db, tenant_id, target).await, 1);
    assert!(refresh_token_is_spendable(&db, tenant_id, &raw_refresh).await);

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
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

    assert_all_revoked(
        &db,
        tenant_id,
        target,
        &raw_refresh,
        "a SCIM password write",
    )
    .await;
}

#[actix_rt::test]
async fn a_scim_deactivation_revokes_every_live_credential() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let provisioner = user_with_role(&db, tenant_id, "admin").await;
    let token = mint_token(&auth, provisioner, tenant_id, org_id);
    let target = user_with_role(&db, tenant_id, "viewer").await;
    let raw_refresh = give_live_credentials(&db, tenant_id, target).await;

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

    assert_all_revoked(
        &db,
        tenant_id,
        target,
        &raw_refresh,
        "a SCIM `active: false`",
    )
    .await;
}

#[actix_rt::test]
async fn a_scim_delete_revokes_every_live_credential() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let provisioner = user_with_role(&db, tenant_id, "admin").await;
    let token = mint_token(&auth, provisioner, tenant_id, org_id);
    let target = user_with_role(&db, tenant_id, "viewer").await;
    let raw_refresh = give_live_credentials(&db, tenant_id, target).await;

    let req = test::TestRequest::delete()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    assert_all_revoked(
        &db,
        tenant_id,
        target,
        &raw_refresh,
        "a SCIM DELETE (offboarding)",
    )
    .await;
}

/// The negative half: an ordinary SCIM attribute edit must NOT log everybody
/// out. A revocation on every write would make an IdP's routine reconciliation
/// sweep a fleet-wide logout.
#[actix_rt::test]
async fn an_ordinary_scim_attribute_edit_revokes_nothing() {
    let (db, org_id, tenant_id) = setup_tenant().await;
    let auth = test_auth_config();
    let authz = make_authz(&db);
    let app = test_app!(db, auth, authz);

    let provisioner = user_with_role(&db, tenant_id, "admin").await;
    let token = mint_token(&auth, provisioner, tenant_id, org_id);
    let target = user_with_role(&db, tenant_id, "viewer").await;
    let raw_refresh = give_live_credentials(&db, tenant_id, target).await;

    let req = test::TestRequest::patch()
        .peer_addr(peer())
        .uri(&format!("/scim/v2/Users/{target}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [
                { "op": "replace", "path": "name.givenName", "value": "Renamed" }
            ]
        }))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 200);

    assert_eq!(live_session_count(&db, tenant_id, target).await, 1);
    assert!(refresh_token_is_spendable(&db, tenant_id, &raw_refresh).await);
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

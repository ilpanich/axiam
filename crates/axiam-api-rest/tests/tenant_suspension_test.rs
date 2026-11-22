//! SA-13 (N16, D-3): suspending a tenant refuses its principals at every door.
//!
//! `TenantStatus::Suspended` was stored and never read: a suspended tenant's
//! users signed in, its tokens kept passing, its clients kept minting. These
//! tests pin the decision D-3 records — suspension refuses sign-in, token
//! issuance, refresh and API requests for the tenant's principals with
//! `tenant_suspended`, revokes its live sessions and refresh tokens, keeps its
//! data, and leaves organization principals able to read it and set it back.

use std::sync::Arc;

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::issue_access_token;
use axiam_core::models::oauth2_client::{CreateOAuth2Client, CreateRefreshToken};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::CreateSession;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OAuth2ClientRepository, OrganizationRepository, RefreshTokenRepository, SessionRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// Arbitrary CSRF token for the double-submit check (SEC-046).
const CSRF_TOKEN: &str = "test-csrf-token";
const TEST_PEER: &str = "127.0.0.1:12345";

fn test_auth_config() -> AuthConfig {
    // Test-only non-secret Ed25519 key pair used solely for JWT signing in tests.
    let private_key = [
        "-----BEGIN PRIVATE KEY-----\n", // nosemgrep: generic.secrets.security.detected-private-key
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----",
    ]
    .concat();
    let public_key = [
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----",
    ]
    .concat();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// The fixture: an organization, its scope tenant with an administrator in
/// it, and a Standard tenant `T` holding an active `alice` and a confidential
/// OAuth2 client.
struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    org_tenant: Uuid,
    admin: Uuid,
    tenant: Uuid,
    alice: Uuid,
    client_id: String,
    client_secret: String,
}

async fn fixture() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Suspension Org".into(),
            slug: "suspension-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenants = SurrealTenantRepository::new(db.clone());
    let org_tenant = tenants
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();
    let tenant = tenants
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant T".into(),
            slug: "tenant-t".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let users = SurrealUserRepository::new(db.clone());
    let admin = users
        .create(CreateUser {
            tenant_id: org_tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    let alice = users
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();
    for (tenant_id, user_id) in [(org_tenant.id, admin.id), (tenant.id, alice.id)] {
        users
            .update(
                tenant_id,
                user_id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    let client_input: CreateOAuth2Client = serde_json::from_value(serde_json::json!({
        "tenant_id": tenant.id,
        "name": "portal",
        "redirect_uris": ["https://portal.example.com/cb"],
        "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
        "scopes": ["openid"],
    }))
    .unwrap();
    let (client, client_secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(client_input)
        .await
        .unwrap();

    Fixture {
        db,
        org_id: org.id,
        org_tenant: org_tenant.id,
        admin: admin.id,
        tenant: tenant.id,
        alice: alice.id,
        client_id: client.client_id,
        client_secret,
    }
}

/// A session row for `user_id` in `tenant_id`, and an access token naming it,
/// so the token passes the per-request session check.
async fn session_backed_token(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
) -> String {
    let session = SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: format!("fixture-{}", Uuid::new_v4()),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            amr: Vec::new(),
            browser_token_hash: None,
            lineage_id: None,
        })
        .await
        .unwrap();
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        auth,
        session.id.to_string(),
        axiam_auth::token::AUD_USER,
    )
    .unwrap()
}

/// The app the production server composes, as far as authentication goes: the
/// per-request session check and the tenant resolver the extractor consults.
macro_rules! app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(
                    Arc::new(SurrealSessionRepository::new($db.clone()))
                        as Arc<dyn axiam_api_rest::SessionValidator>,
                ))
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($db.clone()))
                        as Arc<dyn axiam_api_rest::TenantScopeResolver>,
                ))
                .app_data(web::Data::new({
                    // A CA service that can sign (OD-13c's signing-CA tests);
                    // nothing else here touches it.
                    let mut state = AppState::for_test($db.clone(), $auth.clone());
                    state.pki.ca_service = axiam_pki::CaService::new(
                        axiam_db::SurrealCaCertificateRepository::new($db.clone()),
                        axiam_pki::PkiConfig {
                            encryption_key: Some([0u8; 32]), // gitleaks:allow
                            ..Default::default()
                        },
                        Arc::new(tokio::sync::Semaphore::new(4)),
                        Arc::new(
                            axiam_pki::custodians_from_env(Some([0u8; 32])) // gitleaks:allow
                                .expect("test CA key custodians"),
                        ),
                    );
                    state
                }))
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

/// Sign `alice` in to `tenant_id`: `Ok((access, refresh))` or `Err((status, body))`.
macro_rules! sign_in {
    ($app:expr, $org_id:expr, $tenant_id:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse().unwrap())
            .uri("/api/v1/auth/login")
            .set_json(serde_json::json!({
                "tenant_id": $tenant_id,
                "org_id": $org_id,
                "username_or_email": "alice",
                "password": axiam_test_support::test_password()
            }))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let cookie = |name: &str| {
            resp.response()
                .cookies()
                .find(|c| c.name() == name)
                .map(|c| c.value().to_owned())
        };
        match (cookie("axiam_access"), cookie("axiam_refresh")) {
            (Some(access), Some(refresh)) if status == 200 => Ok((access, refresh)),
            _ => {
                let body = test::read_body(resp).await;
                Err((
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body)
                        .unwrap_or(serde_json::Value::Null),
                ))
            }
        }
    }};
}

/// One refresh rotation: the status it answered.
macro_rules! refresh_status {
    ($app:expr, $tenant_id:expr, $refresh:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse().unwrap())
            .uri("/api/v1/auth/refresh")
            .insert_header((
                "Cookie",
                format!("axiam_refresh={}; axiam_csrf={CSRF_TOKEN}", $refresh),
            ))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({ "tenant_id": $tenant_id }))
            .to_request();
        test::call_service(&$app, req).await.status().as_u16()
    }};
}

/// `GET path` with `token`: the status and the JSON body (`Null` when none).
macro_rules! get_with {
    ($app:expr, $path:expr, $token:expr) => {{
        let req = test::TestRequest::get()
            .uri($path)
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body = test::read_body(resp).await;
        (
            status,
            serde_json::from_slice::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null),
        )
    }};
}

/// `PUT` the tenant's status as the organization administrator.
macro_rules! set_status {
    ($app:expr, $fx:expr, $admin_token:expr, $status:expr) => {{
        let req = test::TestRequest::put()
            .uri(&format!(
                "/api/v1/organizations/{}/tenants/{}",
                $fx.org_id, $fx.tenant
            ))
            .insert_header(("Authorization", format!("Bearer {}", $admin_token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({ "status": $status }))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(status, 200, "the status update must succeed: {body}");
        assert_eq!(body["status"], $status);
    }};
}

/// POST a form to an OAuth2 endpoint of `tenant_id`: the status and the JSON.
async fn post_oauth2_form(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    path: &str,
    tenant_id: Uuid,
    body: String,
) -> (u16, serde_json::Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse().unwrap())
        .uri(&format!("{path}?tenant_id={tenant_id}"))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// An OAuth2 refresh token for `alice` held by the fixture's client.
async fn oauth2_refresh_token(fx: &Fixture) -> String {
    let raw = format!("rt-{}", Uuid::new_v4());
    SurrealRefreshTokenRepository::new(fx.db.clone())
        .create(CreateRefreshToken {
            tenant_id: fx.tenant,
            token_hash: axiam_auth::token::hash_refresh_token(&raw),
            client_id: fx.client_id.clone(),
            user_id: Some(fx.alice),
            scopes: vec!["openid".into()],
            session_id: None,
            requested_userinfo_claims: Vec::new(),
            resource: None,
            auth_time: None,
            acr: None,
            amr: Vec::new(),
            dpop_jkt: None,
            expires_at: Utc::now() + Duration::days(30),
            lineage_id: None,
        })
        .await
        .unwrap();
    raw
}

async fn count(db: &Surreal<TestDb>, query: &str, tenant: Uuid) -> u64 {
    let mut result = db
        .query(query)
        .bind(("tenant", tenant.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<axiam_db::CountRow> = result.take(0).unwrap();
    rows.first().map_or(0, |r| r.total)
}

/// The report's validation plan (N16, *Local*): suspend `T` as an organization
/// principal; `alice` cannot sign in, and the token she held from before the
/// suspension no longer passes an authenticated route. Both answered 200 before
/// the fix.
#[actix_rt::test]
async fn a_suspended_tenant_refuses_sign_in_and_a_pre_suspension_token() {
    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);

    let (access, _refresh) = sign_in!(app, fx.org_id, fx.tenant).expect("sign-in while active");
    assert_eq!(get_with!(app, "/api/v1/settings", access).0, 200);

    set_status!(app, fx, admin_token, "Suspended");

    // Password sign-in: refused, with the stable code.
    let (status, body) = sign_in!(app, fx.org_id, fx.tenant)
        .expect_err("a suspended tenant's user must not sign in");
    assert_eq!(status, 403, "sign-in refusal: {body}");
    assert_eq!(body["error"], "tenant_suspended", "sign-in refusal: {body}");

    // The pre-suspension token: refused.
    let (status, body) = get_with!(app, "/api/v1/settings", access);
    assert!(
        status == 401 || status == 403,
        "a pre-suspension token must be refused, got {status}: {body}"
    );
}

/// The transition revokes, in the request, every session and refresh token of
/// the tenant (as the tombstone does) — and nothing of another tenant.
#[actix_rt::test]
async fn suspending_revokes_the_tenants_sessions_and_refresh_tokens() {
    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);

    let (_access, refresh) = sign_in!(app, fx.org_id, fx.tenant).expect("sign-in while active");
    oauth2_refresh_token(&fx).await;
    let sessions = "SELECT count() AS total FROM session WHERE tenant_id = $tenant GROUP ALL";
    let live_refresh = "SELECT count() AS total FROM oauth2_refresh_token \
                        WHERE tenant_id = $tenant AND revoked = false GROUP ALL";
    assert!(count(&fx.db, sessions, fx.tenant).await > 0);
    assert_eq!(count(&fx.db, live_refresh, fx.tenant).await, 1);

    set_status!(app, fx, admin_token, "Suspended");

    assert_eq!(
        count(&fx.db, sessions, fx.tenant).await,
        0,
        "the suspended tenant's sessions are revoked"
    );
    assert_eq!(
        count(&fx.db, live_refresh, fx.tenant).await,
        0,
        "the suspended tenant's OAuth2 refresh tokens are revoked"
    );
    assert!(
        count(&fx.db, sessions, fx.org_tenant).await > 0,
        "the organization administrator's own session is untouched"
    );
    // Refresh: refused.
    let status = refresh_status!(app, fx.tenant, refresh);
    assert!(
        status == 401 || status == 403,
        "a suspended tenant's session must not refresh, got {status}"
    );
}

/// The REST principal extractor itself refuses the suspended tenant's
/// principals, not only through the revoked session: a session that exists
/// (one written by a sign-in that raced the suspension) and a service
/// account's machine token (which names no session at all).
#[actix_rt::test]
async fn the_principal_extractor_refuses_a_suspended_tenants_tokens() {
    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);

    let machine = axiam_auth::token::issue_service_account_client_credentials_token(
        Uuid::new_v4(),
        fx.tenant,
        fx.org_id,
        &[],
        &auth,
    )
    .unwrap();
    assert_eq!(get_with!(app, "/api/v1/roles", machine).0, 200);

    set_status!(app, fx, admin_token, "Suspended");

    // A session written after the suspension's revocation pass.
    let raced = session_backed_token(&fx.db, &auth, fx.alice, fx.tenant, fx.org_id).await;
    let (status, body) = get_with!(app, "/api/v1/settings", raced);
    assert_eq!(status, 403, "user token: {body}");
    assert_eq!(body["error"], "tenant_suspended", "user token: {body}");

    let (status, body) = get_with!(app, "/api/v1/roles", machine);
    assert_eq!(status, 403, "service-account token: {body}");
    assert_eq!(
        body["error"], "tenant_suspended",
        "service-account token: {body}"
    );
}

/// The token endpoint refuses every grant of the suspended tenant's clients
/// with `tenant_suspended`: `client_credentials` and `refresh_token` here (the
/// code, device, CIBA and exchange grants authenticate the client through the
/// same check).
#[actix_rt::test]
async fn the_token_endpoint_refuses_a_suspended_tenants_clients() {
    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let creds = format!(
        "client_id={}&client_secret={}",
        fx.client_id, fx.client_secret
    );

    let (status, body) = post_oauth2_form(
        &app,
        "/oauth2/token",
        fx.tenant,
        format!("grant_type=client_credentials&{creds}"),
    )
    .await;
    assert_eq!(status, 200, "client_credentials while active: {body}");
    let refresh = oauth2_refresh_token(&fx).await;
    let (status, body) = post_oauth2_form(
        &app,
        "/oauth2/token",
        fx.tenant,
        format!("grant_type=refresh_token&refresh_token={refresh}&{creds}"),
    )
    .await;
    assert_eq!(status, 200, "refresh_token while active: {body}");
    let refresh = body["refresh_token"].as_str().unwrap().to_owned();

    set_status!(app, fx, admin_token, "Suspended");

    for (grant, form) in [
        (
            "client_credentials",
            format!("grant_type=client_credentials&{creds}"),
        ),
        (
            "refresh_token",
            format!("grant_type=refresh_token&refresh_token={refresh}&{creds}"),
        ),
    ] {
        let (status, body) = post_oauth2_form(&app, "/oauth2/token", fx.tenant, form).await;
        assert_eq!(status, 400, "{grant}: {body}");
        assert_eq!(body["error"], "tenant_suspended", "{grant}: {body}");
    }
}

/// Organization principals keep read access to the suspended tenant and can
/// set it back; un-suspending restores sign-in, but only through a new
/// session: the refresh token revoked by the suspension stays revoked.
#[actix_rt::test]
async fn an_organization_principal_reads_and_unsuspends_and_sign_in_needs_a_new_session() {
    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);

    let (old_access, old_refresh) =
        sign_in!(app, fx.org_id, fx.tenant).expect("sign-in while active");

    set_status!(app, fx, admin_token, "Suspended");

    let tenant_path = format!("/api/v1/organizations/{}/tenants/{}", fx.org_id, fx.tenant);
    let (status, body) = get_with!(app, &tenant_path, admin_token);
    assert_eq!(
        status, 200,
        "the organization principal still reads it: {body}"
    );
    assert_eq!(body["status"], "Suspended");
    assert!(sign_in!(app, fx.org_id, fx.tenant).is_err());

    set_status!(app, fx, admin_token, "Active");

    let (access, _refresh) =
        sign_in!(app, fx.org_id, fx.tenant).expect("un-suspending restores sign-in");
    assert_eq!(get_with!(app, "/api/v1/settings", access).0, 200);

    // The session and refresh token the suspension revoked stay revoked.
    assert_eq!(get_with!(app, "/api/v1/settings", old_access).0, 401);
    assert_eq!(refresh_status!(app, fx.tenant, old_refresh), 401);
}

/// A SCIM provisioning token for `alice`, and the resolver the `/scim/v2`
/// extractor consults.
async fn scim_token(fx: &Fixture) -> (String, axiam_api_rest::SurrealScimTokenResolver<TestDb>) {
    use axiam_core::models::scim_token::CreateScimToken;
    use axiam_core::repository::ScimTokenRepository;
    use axiam_db::SurrealScimTokenRepository;

    let raw = format!("scim-{}", Uuid::new_v4());
    let tokens = SurrealScimTokenRepository::new(fx.db.clone());
    tokens
        .create(CreateScimToken {
            tenant_id: fx.tenant,
            user_id: fx.alice,
            name: "okta".into(),
            token_hash: axiam_auth::token::hash_refresh_token(&raw),
            created_by: fx.admin,
            expires_at: Utc::now() + Duration::days(30),
        })
        .await
        .unwrap();
    let resolver = axiam_api_rest::SurrealScimTokenResolver::new(
        tokens,
        SurrealUserRepository::new(fx.db.clone()),
        SurrealTenantRepository::new(fx.db.clone()),
    );
    (raw, resolver)
}

/// SCIM token resolution refuses a suspended tenant's provisioning tokens —
/// they are kept, and un-suspending restores them.
#[actix_rt::test]
async fn scim_token_resolution_refuses_a_suspended_tenant() {
    use axiam_api_rest::ScimTokenResolver;
    use axiam_core::models::tenant::{TenantStatus, UpdateTenant};

    let fx = fixture().await;
    let (raw, resolver) = scim_token(&fx).await;
    assert!(resolver.resolve(&raw).await.is_some(), "active tenant");

    let tenants = SurrealTenantRepository::new(fx.db.clone());
    let set_status = |status| UpdateTenant {
        status: Some(status),
        ..Default::default()
    };
    tenants
        .update(fx.tenant, set_status(TenantStatus::Suspended))
        .await
        .unwrap();
    assert!(
        resolver.resolve(&raw).await.is_none(),
        "a suspended tenant's provisioning token resolves to no principal"
    );

    tenants
        .update(fx.tenant, set_status(TenantStatus::Active))
        .await
        .unwrap();
    assert!(
        resolver.resolve(&raw).await.is_some(),
        "un-suspending restores the provisioning token"
    );
}

/// The tombstone revokes the tenant's SCIM tokens in its own transaction, and
/// the resolver refuses a tombstoned tenant's token in any case.
#[actix_rt::test]
async fn the_tombstone_revokes_the_tenants_scim_tokens() {
    use axiam_api_rest::ScimTokenResolver;

    let fx = fixture().await;
    let (raw, resolver) = scim_token(&fx).await;
    assert!(resolver.resolve(&raw).await.is_some(), "live tenant");

    SurrealTenantRepository::new(fx.db.clone())
        .delete(fx.tenant)
        .await
        .unwrap();

    let live = "SELECT count() AS total FROM scim_token \
                WHERE tenant_id = $tenant AND revoked_at = NONE GROUP ALL";
    assert_eq!(
        count(&fx.db, live, fx.tenant).await,
        0,
        "the tombstone revokes every SCIM token of the tenant"
    );
    assert!(resolver.resolve(&raw).await.is_none());
}

/// One authenticated request as `token`, optionally acting on `act_on` through
/// `X-Axiam-Tenant`, with the CSRF double-submit pair a state-changing request
/// needs: the status and the JSON body (`Null` when none).
async fn send(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    method: actix_web::http::Method,
    path: &str,
    token: &str,
    act_on: Option<Uuid>,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value) {
    let mut req = test::TestRequest::default()
        .method(method)
        .uri(path)
        // The rate-limited routes (`/authz/check`) key on the peer.
        .peer_addr(TEST_PEER.parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN));
    if let Some(tenant) = act_on {
        req = req.insert_header((axiam_api_rest::ACTIVE_TENANT_HEADER, tenant.to_string()));
    }
    if let Some(body) = body {
        req = req.set_json(body);
    }
    let resp = test::call_service(app, req.to_request()).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// OD-13a, at the repository: suspending the organization's own tenant is
/// refused with `OrganizationTenantNotSuspendable` — the status write is not
/// made and nothing of the tenant is revoked. Every caller of the status write
/// goes through here, so no handler can bypass it.
#[actix_rt::test]
async fn the_repository_refuses_to_suspend_the_organization_tenant() {
    use axiam_core::error::AxiamError;
    use axiam_core::models::tenant::{TenantStatus, UpdateTenant};

    let fx = fixture().await;
    let auth = test_auth_config();
    session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let sessions = "SELECT count() AS total FROM session WHERE tenant_id = $tenant GROUP ALL";
    let before = count(&fx.db, sessions, fx.org_tenant).await;
    assert!(before > 0);

    let tenants = SurrealTenantRepository::new(fx.db.clone());
    let result = tenants
        .update(
            fx.org_tenant,
            UpdateTenant {
                status: Some(TenantStatus::Suspended),
                ..Default::default()
            },
        )
        .await;
    assert!(
        matches!(result, Err(AxiamError::OrganizationTenantNotSuspendable)),
        "suspending the organization tenant must be refused, got {result:?}"
    );
    assert_eq!(
        tenants.get_by_id(fx.org_tenant).await.unwrap().status,
        TenantStatus::Active,
        "the status is unchanged"
    );
    assert_eq!(
        count(&fx.db, sessions, fx.org_tenant).await,
        before,
        "the organization tenant's sessions are untouched"
    );
}

/// OD-13a, over REST: `PUT .../tenants/{organization tenant}` with
/// `status = Suspended` answers `409 organization_tenant_not_suspendable`, the
/// status stays `Active`, and the administrator's own session still works.
#[actix_rt::test]
async fn suspending_the_organization_tenant_over_rest_is_a_409() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let sessions = "SELECT count() AS total FROM session WHERE tenant_id = $tenant GROUP ALL";
    let before = count(&fx.db, sessions, fx.org_tenant).await;

    let path = format!(
        "/api/v1/organizations/{}/tenants/{}",
        fx.org_id, fx.org_tenant
    );
    let (status, body) = send(
        &app,
        Method::PUT,
        &path,
        &admin_token,
        None,
        Some(serde_json::json!({ "status": "Suspended" })),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(
        body["error"], "organization_tenant_not_suspendable",
        "{body}"
    );

    let (status, body) = get_with!(app, &path, admin_token);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "Active", "the status is unchanged: {body}");
    assert_eq!(
        count(&fx.db, sessions, fx.org_tenant).await,
        before,
        "nothing of the organization tenant is revoked"
    );
    assert_eq!(get_with!(app, "/api/v1/settings", admin_token).0, 200);
}

/// OD-13b: an organization principal acting on a suspended tenant through
/// `X-Axiam-Tenant` may read it and change its status, and nothing else. A
/// write scoped to it is `403 tenant_suspended`; an update of the tenant record
/// that changes more than its status is refused the same way; the status-only
/// un-suspend goes through — with the header too, as the admin UI sends it —
/// and the tenant's user then signs in again with a new session.
#[actix_rt::test]
async fn an_organization_principal_only_reads_and_unsuspends_a_suspended_tenant() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let tenant_path = format!("/api/v1/organizations/{}/tenants/{}", fx.org_id, fx.tenant);

    set_status!(app, fx, admin_token, "Suspended");

    // Reads of the suspended tenant: allowed.
    let (status, body) = send(
        &app,
        Method::GET,
        "/api/v1/roles",
        &admin_token,
        Some(fx.tenant),
        None,
    )
    .await;
    assert_eq!(status, 200, "a read scoped to the suspended tenant: {body}");
    let (status, body) = send(
        &app,
        Method::GET,
        &tenant_path,
        &admin_token,
        Some(fx.tenant),
        None,
    )
    .await;
    assert_eq!(status, 200, "reading the tenant record: {body}");

    // A write scoped to it: refused, and not made.
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/roles",
        &admin_token,
        Some(fx.tenant),
        Some(serde_json::json!({
            "name": "written-while-suspended",
            "description": "must not exist",
            "is_global": true,
        })),
    )
    .await;
    assert_eq!(
        status, 403,
        "a write scoped to the suspended tenant: {body}"
    );
    assert_eq!(body["error"], "tenant_suspended", "{body}");
    let roles = "SELECT count() AS total FROM role \
                 WHERE tenant_id = $tenant AND name = 'written-while-suspended' GROUP ALL";
    assert_eq!(count(&fx.db, roles, fx.tenant).await, 0, "nothing written");

    // An update of the tenant record that changes more than its status:
    // refused, with or without the header, and nothing changes.
    for act_on in [None, Some(fx.tenant)] {
        let (status, body) = send(
            &app,
            Method::PUT,
            &tenant_path,
            &admin_token,
            act_on,
            Some(serde_json::json!({ "status": "Active", "name": "Renamed" })),
        )
        .await;
        assert_eq!(status, 403, "status and name ({act_on:?}): {body}");
        assert_eq!(body["error"], "tenant_suspended", "{body}");
    }
    let (_, body) = get_with!(app, &tenant_path, admin_token);
    assert_eq!(body["status"], "Suspended", "{body}");
    assert_eq!(body["name"], "Tenant T", "{body}");
    assert!(sign_in!(app, fx.org_id, fx.tenant).is_err());

    // The status-only un-suspend, as the admin UI sends it (header set).
    let (status, body) = send(
        &app,
        Method::PUT,
        &tenant_path,
        &admin_token,
        Some(fx.tenant),
        Some(serde_json::json!({ "status": "Active" })),
    )
    .await;
    assert_eq!(status, 200, "un-suspend: {body}");
    assert_eq!(body["status"], "Active", "{body}");

    let (access, _refresh) =
        sign_in!(app, fx.org_id, fx.tenant).expect("un-suspending restores sign-in");
    assert_eq!(get_with!(app, "/api/v1/settings", access).0, 200);
}

/// The control for OD-13b: the same write on an ACTIVE tenant through the
/// same header still succeeds.
#[actix_rt::test]
async fn an_organization_principal_still_writes_to_an_active_tenant() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);

    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/roles",
        &admin_token,
        Some(fx.tenant),
        Some(serde_json::json!({
            "name": "written-while-active",
            "description": "a write on an active tenant",
            "is_global": true,
        })),
    )
    .await;
    assert_eq!(status, 201, "a write scoped to an active tenant: {body}");
    let roles = "SELECT count() AS total FROM role \
                 WHERE tenant_id = $tenant AND name = 'written-while-active' GROUP ALL";
    assert_eq!(count(&fx.db, roles, fx.tenant).await, 1);

    let (status, body) = send(
        &app,
        Method::PUT,
        &format!("/api/v1/organizations/{}/tenants/{}", fx.org_id, fx.tenant),
        &admin_token,
        Some(fx.tenant),
        Some(serde_json::json!({ "name": "Renamed" })),
    )
    .await;
    assert_eq!(status, 200, "renaming an active tenant: {body}");
    assert_eq!(body["name"], "Renamed", "{body}");
}

/// The organization CA every signing-CA test signs under: minted as the
/// organization administrator, an organization-level act that names no tenant.
async fn organization_ca(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    fx: &Fixture,
    admin_token: &str,
) -> String {
    use actix_web::http::Method;
    let (status, body) = send(
        app,
        Method::POST,
        &format!("/api/v1/organizations/{}/ca-certificates", fx.org_id),
        admin_token,
        None,
        Some(serde_json::json!({
            "subject": "Suspension Org CA",
            "key_algorithm": "Ed25519",
            "validity_days": 365
        })),
    )
    .await;
    assert_eq!(status, 201, "organization CA: {body}");
    body["id"].as_str().unwrap().to_string()
}

const TENANT_CAS: &str =
    "SELECT count() AS total FROM ca_certificate WHERE tenant_id = $tenant GROUP ALL";

/// OD-13c, path-scoped writes: while `T` is suspended, minting a signing CA for
/// it and signing a CSR into one — both addressed by path, without the header —
/// are `403 tenant_suspended`, and no CA is written. Listing its signing CAs
/// (a read) still answers. Both writes answered 201/400 before OD-13c.
#[actix_rt::test]
async fn path_scoped_signing_ca_writes_are_refused_on_a_suspended_tenant() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let org_ca = organization_ca(&app, &fx, &admin_token).await;
    let cas = format!(
        "/api/v1/organizations/{}/tenants/{}/signing-cas",
        fx.org_id, fx.tenant
    );

    set_status!(app, fx, admin_token, "Suspended");

    let (status, body) = send(
        &app,
        Method::POST,
        &cas,
        &admin_token,
        None,
        Some(serde_json::json!({
            "parent_ca_id": org_ca,
            "subject": "Tenant Signing CA",
            "key_algorithm": "Ed25519",
            "validity_days": 364
        })),
    )
    .await;
    assert_eq!(status, 403, "signing CA for a suspended tenant: {body}");
    assert_eq!(body["error"], "tenant_suspended", "{body}");

    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{cas}/sign-csr"),
        &admin_token,
        None,
        Some(serde_json::json!({
            "parent_ca_id": org_ca,
            "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----",
            "validity_days": 364
        })),
    )
    .await;
    assert_eq!(status, 403, "CSR signing for a suspended tenant: {body}");
    assert_eq!(body["error"], "tenant_suspended", "{body}");

    assert_eq!(
        count(&fx.db, TENANT_CAS, fx.tenant).await,
        0,
        "no CA written"
    );

    let (status, body) = send(&app, Method::GET, &cas, &admin_token, None, None).await;
    assert_eq!(
        status, 200,
        "listing a suspended tenant's signing CAs: {body}"
    );
}

/// OD-13c, what stays open on a suspended tenant: the audit export — by path,
/// and with the header naming the tenant (a `POST` that only reads) — and the
/// tenant `DELETE`, a lifecycle act like the un-suspend. The header-scoped
/// export answered 403 before OD-13c.
#[actix_rt::test]
async fn audit_export_and_delete_stay_open_on_a_suspended_tenant() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let tenant_path = format!("/api/v1/organizations/{}/tenants/{}", fx.org_id, fx.tenant);
    let export = format!("{tenant_path}/audit-export");

    set_status!(app, fx, admin_token, "Suspended");

    for act_on in [None, Some(fx.tenant)] {
        let (status, body) = send(&app, Method::POST, &export, &admin_token, act_on, None).await;
        assert_eq!(status, 200, "audit export ({act_on:?}): {body}");
    }

    // QR1-1: the DELETE with `X-Axiam-Tenant` naming the suspended tenant —
    // what the admin UI sends while the tenant is selected — is allowed too.
    let (status, body) = send(
        &app,
        Method::DELETE,
        &tenant_path,
        &admin_token,
        Some(fx.tenant),
        None,
    )
    .await;
    assert_eq!(
        status, 204,
        "deleting a suspended tenant with the header naming it: {body}"
    );

    // And by path alone, on a second suspended tenant.
    let fx = fixture().await;
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let tenant_path = format!("/api/v1/organizations/{}/tenants/{}", fx.org_id, fx.tenant);
    set_status!(app, fx, admin_token, "Suspended");
    let (status, body) = send(
        &app,
        Method::POST,
        &format!("{tenant_path}/audit-export"),
        &admin_token,
        None,
        None,
    )
    .await;
    assert_eq!(status, 200, "audit export: {body}");
    let (status, body) = send(&app, Method::DELETE, &tenant_path, &admin_token, None, None).await;
    assert_eq!(status, 204, "deleting a suspended tenant: {body}");
}

/// OD-13c, header-scoped read-only `POST`s: an authorization check, single and
/// batch, naming a suspended tenant through `X-Axiam-Tenant` is a read and is
/// answered. Both answered 403 before OD-13c.
#[actix_rt::test]
async fn header_scoped_authz_checks_are_reads_on_a_suspended_tenant() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);

    set_status!(app, fx, admin_token, "Suspended");

    let check = serde_json::json!({ "action": "roles:list", "resource_id": Uuid::new_v4() });
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/authz/check",
        &admin_token,
        Some(fx.tenant),
        Some(check.clone()),
    )
    .await;
    assert_eq!(status, 200, "authz check on a suspended tenant: {body}");
    let (status, body) = send(
        &app,
        Method::POST,
        "/api/v1/authz/check/batch",
        &admin_token,
        Some(fx.tenant),
        Some(serde_json::json!({ "checks": [check] })),
    )
    .await;
    assert_eq!(
        status, 200,
        "batch authz check on a suspended tenant: {body}"
    );
}

/// The control for OD-13c: the same signing-CA creation on an ACTIVE tenant
/// still succeeds and writes the CA.
#[actix_rt::test]
async fn signing_ca_creation_on_an_active_tenant_still_succeeds() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let org_ca = organization_ca(&app, &fx, &admin_token).await;

    let (status, body) = send(
        &app,
        Method::POST,
        &format!(
            "/api/v1/organizations/{}/tenants/{}/signing-cas",
            fx.org_id, fx.tenant
        ),
        &admin_token,
        None,
        Some(serde_json::json!({
            "parent_ca_id": org_ca,
            "subject": "Tenant Signing CA",
            "key_algorithm": "Ed25519",
            "validity_days": 364
        })),
    )
    .await;
    assert_eq!(status, 201, "signing CA for an active tenant: {body}");
    assert_eq!(count(&fx.db, TENANT_CAS, fx.tenant).await, 1);
}

// ---------------------------------------------------------------------------
// Wave 2 review gate, round 2
// ---------------------------------------------------------------------------

/// `POST /api/v1/auth/login` as `alice` with `password`: the status and body.
async fn login_status(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    fx: &Fixture,
    password: String,
) -> (u16, serde_json::Value) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(serde_json::json!({
            "tenant_id": fx.tenant,
            "org_id": fx.org_id,
            "username_or_email": "alice",
            "password": password,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let bytes = test::read_body(resp).await;
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// QR1-3 / SR1-8: password login on a suspended tenant says `tenant_suspended`
/// only to a caller whose credential verified. A wrong password gets the
/// uniform `401` an unknown tenant or user gets, so an anonymous caller cannot
/// probe which tenants are suspended. It answered `403 tenant_suspended`
/// before the fix.
#[actix_rt::test]
async fn sign_in_reveals_a_suspension_only_after_the_password_verifies() {
    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);

    set_status!(app, fx, admin_token, "Suspended");

    let (status, body) = login_status(&app, &fx, "not-the-password".into()).await;
    assert_eq!(status, 401, "wrong password on a suspended tenant: {body}");
    assert_ne!(body["error"], "tenant_suspended", "{body}");

    let (status, body) = login_status(&app, &fx, axiam_test_support::test_password()).await;
    assert_eq!(status, 403, "right password on a suspended tenant: {body}");
    assert_eq!(body["error"], "tenant_suspended", "{body}");
}

/// QR1-5: a suspend that fails — here on a slug another tenant holds, `409` —
/// leaves the tenant `Active` and its sessions and refresh tokens intact. They
/// were revoked before the failing write before the fix.
#[actix_rt::test]
async fn a_failed_suspend_revokes_nothing() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    SurrealTenantRepository::new(fx.db.clone())
        .create(CreateTenant {
            organization_id: fx.org_id,
            kind: TenantKind::Standard,
            name: "Taken".into(),
            slug: "taken".into(),
            metadata: None,
        })
        .await
        .unwrap();

    sign_in!(app, fx.org_id, fx.tenant).expect("sign-in while active");
    oauth2_refresh_token(&fx).await;
    let sessions = "SELECT count() AS total FROM session WHERE tenant_id = $tenant GROUP ALL";
    let live_refresh = "SELECT count() AS total FROM oauth2_refresh_token \
                        WHERE tenant_id = $tenant AND revoked = false GROUP ALL";
    let sessions_before = count(&fx.db, sessions, fx.tenant).await;
    assert!(sessions_before > 0);

    let tenant_path = format!("/api/v1/organizations/{}/tenants/{}", fx.org_id, fx.tenant);
    let (status, body) = send(
        &app,
        Method::PUT,
        &tenant_path,
        &admin_token,
        None,
        Some(serde_json::json!({ "status": "Suspended", "slug": "taken" })),
    )
    .await;
    // The slug conflict fails the status write. (It answers `500` rather
    // than `409` today: the unique-index violation surfaces from inside the
    // suspend transaction. The failure, not its code, is what this pins.)
    assert!(
        status >= 400,
        "suspend with a taken slug must fail, got {status}: {body}"
    );

    let (_, body) = get_with!(app, &tenant_path, admin_token);
    assert_eq!(body["status"], "Active", "{body}");
    assert_eq!(
        count(&fx.db, sessions, fx.tenant).await,
        sessions_before,
        "a failed suspend must not end the tenant's sessions"
    );
    assert_eq!(
        count(&fx.db, live_refresh, fx.tenant).await,
        1,
        "a failed suspend must not revoke the tenant's refresh tokens"
    );
}

/// Make `tenant`'s stored record unreadable (its `organization_id` is no
/// UUID), so every read of it fails with a datastore error rather than
/// `NotFound`.
async fn corrupt_tenant(db: &Surreal<TestDb>, tenant: Uuid) {
    db.query("UPDATE type::record('tenant', $id) SET organization_id = 'not-a-uuid'")
        .bind(("id", tenant.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
}

/// QR1-6: the path-scoped suspension check fails closed. When the named
/// tenant cannot be read (a datastore error, not "no such tenant"), a write
/// into it is refused rather than let through. The CA was minted (201)
/// before the fix.
#[actix_rt::test]
async fn path_scoped_writes_fail_closed_when_the_tenant_cannot_be_read() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let org_ca = organization_ca(&app, &fx, &admin_token).await;

    corrupt_tenant(&fx.db, fx.tenant).await;

    let (status, body) = send(
        &app,
        Method::POST,
        &format!(
            "/api/v1/organizations/{}/tenants/{}/signing-cas",
            fx.org_id, fx.tenant
        ),
        &admin_token,
        None,
        Some(serde_json::json!({
            "parent_ca_id": org_ca,
            "subject": "Tenant Signing CA",
            "key_algorithm": "Ed25519",
            "validity_days": 364
        })),
    )
    .await;
    assert_ne!(
        status, 201,
        "a write must not proceed on an unreadable tenant: {body}"
    );
    assert_eq!(
        count(&fx.db, TENANT_CAS, fx.tenant).await,
        0,
        "no CA written"
    );
}

/// SR1-7: the UMA Protection API and the SSF stream-management API take an
/// OAuth2 client's token, which no session backs; their extractors refuse a
/// suspended tenant's tokens. Both answered (200 and 404) before the fix.
#[actix_rt::test]
async fn the_uma_and_ssf_extractors_refuse_a_suspended_tenants_tokens() {
    use actix_web::http::Method;

    let fx = fixture().await;
    let auth = test_auth_config();
    let admin_token = session_backed_token(&fx.db, &auth, fx.admin, fx.org_tenant, fx.org_id).await;
    let app = app!(fx.db, auth);
    let client_token = |scope: &str| {
        axiam_auth::token::issue_client_credentials_token(
            &fx.client_id,
            fx.tenant,
            fx.org_id,
            &[scope.to_owned()],
            &auth,
        )
        .unwrap()
    };
    let pat = client_token(axiam_core::models::uma::UMA_PROTECTION_SCOPE);
    let receiver = client_token(axiam_core::models::ssf::SSF_MANAGE_SCOPE);
    let uma = "/uma2/rreg/resource_set";
    let ssf = "/ssf/v1/stream";

    let (status, body) = send(&app, Method::GET, uma, &pat, None, None).await;
    assert_eq!(status, 200, "UMA while active: {body}");

    set_status!(app, fx, admin_token, "Suspended");

    for (path, token) in [(uma, &pat), (ssf, &receiver)] {
        let (status, body) = send(&app, Method::GET, path, token, None, None).await;
        assert_eq!(status, 403, "{path} on a suspended tenant: {body}");
        assert_eq!(body["error"], "tenant_suspended", "{path}: {body}");
    }
}

/// An in-memory `MakeWriter`, so a test can read what was logged.
#[derive(Clone, Default)]
struct LogBuf(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// QR1-11: a tenant lookup that fails is logged as what it is, not as a
/// suspension. It was logged `reason = "tenant_suspended"` before the fix.
#[actix_rt::test]
async fn scim_token_resolution_logs_an_unreadable_tenant_as_unavailable() {
    use axiam_api_rest::ScimTokenResolver;

    let fx = fixture().await;
    let (raw, resolver) = scim_token(&fx).await;
    corrupt_tenant(&fx.db, fx.tenant).await;

    let logs = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .finish();
    let resolved = {
        let _guard = tracing::subscriber::set_default(subscriber);
        resolver.resolve(&raw).await
    };
    assert!(resolved.is_none(), "an unreadable tenant admits nobody");
    let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("scim.token_rejected"), "{text}");
    assert!(
        !text.contains("tenant_suspended"),
        "a lookup error is not a suspension: {text}"
    );
    assert!(text.contains("tenant_unavailable"), "{text}");
}

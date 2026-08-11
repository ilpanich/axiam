//! Integration tests for the UMA 2.0 HTTP surface (X2).
//!
//! The ticket arithmetic and the grant's own refusal logic are unit-tested in
//! `axiam-oauth2::uma`. What this file exercises is what only exists once the
//! endpoints are mounted: that `/uma2/perm` is routed and rejects a token that
//! is not a PAT, that the uma-ticket grant reaches the **real** RBAC engine —
//! so a deny rule vetoes an RPT exactly as it vetoes a live check — and that
//! the RPT carries the permissions claim.
//!
//! The authz checker here is a real [`AuthorizationEngine`], not
//! `AllowAllAuthzChecker`. That is the point: X2's acceptance criterion is
//! about what the engine decides, and an allow-all fake would pass every test
//! in this file while proving nothing.
//!
//! Every test is named after the thing it stops.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_M2M, AUD_USER, SubjectKind, issue_access_token};
use axiam_authz::AuthorizationEngine;
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::{CreatePermission, PermissionEffect};
use axiam_core::models::resource::CreateResource;
use axiam_core::models::role::CreateRole;
use axiam_core::models::scope::CreateScope;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::uma::UMA_TICKET_GRANT_TYPE;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    GroupRepository, OAuth2ClientRepository, OrganizationRepository, PermissionRepository,
    ResourceRepository, RoleRepository, ScopeRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealGroupRepository, SurrealOAuth2ClientRepository, SurrealOrganizationRepository,
    SurrealPermissionRepository, SurrealResourceRepository, SurrealRoleRepository,
    SurrealScopeRepository, SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const TEST_PEER: &str = "127.0.0.1:34567";

const REDIRECT_URI: &str = "https://rs.test.example/callback";

fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
}

fn test_auth_config() -> AuthConfig {
    let (private_key, public_key) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.test.example".into(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    org_id: Uuid,
    /// The requesting party — granted `view` on `resource_id`, denied
    /// `redact` by an explicit deny rule.
    user_id: Uuid,
    resource_id: Uuid,
    /// The resource server. The Protection API binds a ticket to whichever
    /// client minted it, so the binding tests need a second registered client
    /// to present the same ticket as somebody else.
    rs_client_id: String,
    rs_client_secret: String,
    other_client_id: String,
    other_client_secret: String,
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

/// Seeds one resource declaring three scopes, and a user holding a role that
/// **allows** `view`, **denies** `redact`, and says nothing about `export`.
///
/// Those three cases are the whole point of the fixture: allow, explicit deny,
/// and default-deny are three different outcomes and the grant must tell them
/// apart.
async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "UMA Org".into(),
            slug: "org-uma".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "UMA Tenant".into(),
            slug: "tenant-uma".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "requesting-party".into(),
            email: "rq@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let resource = SurrealResourceRepository::new(db.clone())
        .create(CreateResource {
            tenant_id: tenant.id,
            name: "patient-record-42".into(),
            resource_type: "document".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    // The declared scope set: the allow-list of names a resource server may
    // ask for. `export` is declared but never granted, which is what makes
    // "declared but denied" distinguishable from "never declared".
    let scope_repo = SurrealScopeRepository::new(db.clone());
    for name in ["view", "redact", "export"] {
        scope_repo
            .create(CreateScope {
                tenant_id: tenant.id,
                resource_id: resource.id,
                name: name.into(),
                description: String::new(),
            })
            .await
            .unwrap();
    }

    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id: tenant.id,
            name: "record-reader".into(),
            description: String::new(),
            is_global: false,
        })
        .await
        .unwrap();

    let view = perm_repo
        .create(CreatePermission {
            tenant_id: tenant.id,
            action: "view".into(),
            description: String::new(),
        })
        .await
        .unwrap();
    let redact = perm_repo
        .create(CreatePermission {
            tenant_id: tenant.id,
            action: "redact".into(),
            description: String::new(),
        })
        .await
        .unwrap();

    perm_repo
        .grant_to_role_with_effect(tenant.id, role.id, view.id, vec![], PermissionEffect::Allow)
        .await
        .unwrap();
    perm_repo
        .grant_to_role_with_effect(
            tenant.id,
            role.id,
            redact.id,
            vec![],
            PermissionEffect::Deny,
        )
        .await
        .unwrap();

    role_repo
        .assign_to_user(tenant.id, user.id, role.id, Some(resource.id))
        .await
        .unwrap();

    let client_repo = SurrealOAuth2ClientRepository::new(db.clone());
    let (rs, rs_secret) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "resource-server-1".into(),
            redirect_uris: vec![REDIRECT_URI.into()],
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["uma_protection".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
        })
        .await
        .unwrap();
    let (other, other_secret) = client_repo
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "resource-server-2".into(),
            redirect_uris: vec![REDIRECT_URI.into()],
            grant_types: vec!["client_credentials".into()],
            scopes: vec!["uma_protection".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
        })
        .await
        .unwrap();

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        org_id: org.id,
        user_id: user.id,
        resource_id: resource.id,
        rs_client_id: rs.client_id,
        rs_client_secret: rs_secret,
        other_client_id: other.client_id,
        other_client_secret: other_secret,
    }
}

macro_rules! test_app {
    ($f:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $f.db.clone(),
                    $f.auth.clone(),
                )))
                .app_data(web::Data::new(make_authz(&$f.db)))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

/// A Protection API Token: an OAuth2-client-subject token carrying
/// `uma_protection`. `sub` is the client id, which is what the ticket binds to.
fn pat(f: &Fixture, client_id: &str) -> String {
    client_token(f, client_id, &["uma_protection".to_string()])
}

/// A client-credentials-shaped token. Built with the same claim shape
/// `issue_client_credentials_token` produces (`sub` = client id, `sub_kind` =
/// `OAuth2Client`, `aud` = m2m) so the PAT checks see a realistic token.
fn client_token(f: &Fixture, client_id: &str, scopes: &[String]) -> String {
    axiam_auth::token::issue_client_credentials_token(
        client_id,
        f.tenant_id,
        f.org_id,
        scopes,
        &f.auth,
    )
    .unwrap()
}

/// The requesting party's own access token — the `claim_token` of the grant.
fn user_token(f: &Fixture) -> String {
    issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &[],
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// POST /uma2/perm with the given bearer token and requested pairs.
macro_rules! perm {
    ($app:expr, $f:expr, $token:expr, $body:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/uma2/perm")
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .set_json($body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let json: Value = test::read_body_json(resp).await;
        (status, json)
    }};
}

/// Redeem a ticket at the token endpoint.
macro_rules! redeem {
    ($app:expr, $f:expr, $client_id:expr, $secret:expr, $ticket:expr, $claim_token:expr) => {{
        let body = format!(
            "grant_type={}&client_id={}&client_secret={}&ticket={}&claim_token={}",
            UMA_TICKET_GRANT_TYPE.replace(':', "%3A"),
            $client_id,
            $secret,
            $ticket,
            $claim_token
        );
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(&format!("/oauth2/token?tenant_id={}", $f.tenant_id))
            .insert_header(("content-type", "application/x-www-form-urlencoded"))
            .set_payload(body)
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let json: Value = test::read_body_json(resp).await;
        (status, json)
    }};
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// The discovery document must not advertise an endpoint that does not exist:
/// a conforming client routes on the strength of it.
#[actix_web::test]
async fn discovery_advertises_only_the_endpoints_v1_actually_serves() {
    let f = setup().await;
    let app = test_app!(f);

    let req = test::TestRequest::get()
        .uri("/.well-known/uma2-configuration")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let doc: Value = test::read_body_json(resp).await;

    assert_eq!(
        doc["permission_endpoint"],
        "https://id.test.example/uma2/perm"
    );
    assert_eq!(
        doc["token_endpoint"],
        "https://id.test.example/oauth2/token"
    );
    assert_eq!(
        doc["grant_types_supported"][0], UMA_TICKET_GRANT_TYPE,
        "the ticket grant must be advertised"
    );
    assert!(
        doc.get("claims_interaction_endpoint").is_none(),
        "claims-gathering is deferred to v2 and must not be advertised"
    );
    assert!(
        doc.get("resource_registration_endpoint").is_none(),
        "the rreg API is not implemented yet and must not be advertised"
    );
}

// ---------------------------------------------------------------------------
// The permission endpoint authenticates as a PAT
// ---------------------------------------------------------------------------

/// Without the `uma_protection` scope an ordinary client token is not a PAT,
/// and the Protection API must say so rather than minting a ticket.
#[actix_web::test]
async fn permission_endpoint_refuses_a_token_without_the_protection_scope() {
    let f = setup().await;
    let app = test_app!(f);

    let token = client_token(&f, &f.rs_client_id, &["openid".to_string()]);
    let (status, _) = perm!(
        app,
        f,
        token,
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view"] }])
    );
    assert_eq!(status, 403, "a token without uma_protection is not a PAT");
}

/// A user token has no client identity in it. Minting a ticket from one would
/// mean inventing the `client_id` the ticket is bound to.
#[actix_web::test]
async fn permission_endpoint_refuses_a_user_token_even_with_the_scope() {
    let f = setup().await;
    let app = test_app!(f);

    // A user-subject token that nonetheless carries the scope.
    let token = issue_access_token(
        f.user_id,
        f.tenant_id,
        f.org_id,
        &["uma_protection".to_string()],
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();

    let (status, _) = perm!(
        app,
        f,
        token,
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view"] }])
    );
    assert_eq!(
        status, 403,
        "a permission ticket must be bound to a client, and a user token names none"
    );
}

/// A scope the resource never declared is refused at mint time. The resource
/// server learns it asked for something that does not exist, rather than
/// receiving a credential guaranteed to fail 60 seconds later.
#[actix_web::test]
async fn permission_endpoint_refuses_an_undeclared_scope_rather_than_minting() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, _) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["incinerate"] }])
    );
    assert_eq!(
        status, 400,
        "an undeclared scope is a bad request, not a denial"
    );
}

// ---------------------------------------------------------------------------
// The grant reaches the real engine
// ---------------------------------------------------------------------------

/// The happy path, end to end: mint a ticket for an allowed pair, redeem it,
/// and get an RPT whose `permissions` claim names what was granted.
#[actix_web::test]
async fn an_allowed_pair_yields_an_rpt_carrying_the_permissions_claim() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view"] }])
    );
    assert_eq!(status, 201, "minting failed: {body}");
    let ticket = body["ticket"].as_str().unwrap().to_string();

    let (status, body) = redeem!(
        app,
        f,
        f.rs_client_id,
        f.rs_client_secret,
        ticket,
        user_token(&f)
    );
    assert_eq!(status, 200, "redemption failed: {body}");

    let rpt = body["access_token"].as_str().unwrap();
    let claims = axiam_auth::token::validate_access_token(rpt, &f.auth)
        .expect("the RPT must be an ordinary, verifiable AXIAM access token")
        .0;

    assert_eq!(
        claims.sub,
        f.user_id.to_string(),
        "the RPT is the requesting party's"
    );
    assert_eq!(claims.sub_kind, SubjectKind::User);
    let permissions = claims
        .permissions
        .expect("an RPT without a permissions claim is not an RPT");
    assert_eq!(permissions.len(), 1);
    assert_eq!(permissions[0].resource_id, f.resource_id);
    assert_eq!(permissions[0].resource_scopes, vec!["view".to_string()]);

    // X2: an RPT must never outlive the authorization it rests on.
    let expires_in = body["expires_in"].as_i64().unwrap();
    assert!(
        expires_in <= 300,
        "RPT lifetime {expires_in} exceeds the 300 s protocol ceiling"
    );
}

/// **The X2 acceptance criterion.** An explicit deny rule must veto an RPT
/// exactly as it vetoes a live check. This is the test that would fail if the
/// UMA scope were ever remapped onto the AXIAM `scope` field instead of the
/// action, because deny-override would stop applying.
#[actix_web::test]
async fn a_deny_rule_vetoes_an_rpt_exactly_as_it_vetoes_a_live_check() {
    let f = setup().await;
    let app = test_app!(f);

    let (status, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["redact"] }])
    );
    assert_eq!(
        status, 201,
        "the ticket mints — `redact` is a declared scope"
    );
    let ticket = body["ticket"].as_str().unwrap().to_string();

    let (status, body) = redeem!(
        app,
        f,
        f.rs_client_id,
        f.rs_client_secret,
        ticket,
        user_token(&f)
    );
    assert_eq!(status, 403, "a deny rule must refuse the exchange: {body}");
    assert_eq!(body["error"], "access_denied");
}

/// Default-deny is a refusal too: a declared scope nobody granted must not
/// produce an RPT just because no deny rule names it.
#[actix_web::test]
async fn a_scope_with_no_grant_at_all_is_refused() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["export"] }])
    );
    let ticket = body["ticket"].as_str().unwrap().to_string();

    let (status, _) = redeem!(
        app,
        f,
        f.rs_client_id,
        f.rs_client_secret,
        ticket,
        user_token(&f)
    );
    assert_eq!(status, 403, "no grant means no RPT");
}

/// Partial grants are refused whole, never trimmed. A trimmed RPT would hand
/// the client a token that silently does less than it asked for.
#[actix_web::test]
async fn a_ticket_mixing_an_allowed_and_a_denied_pair_is_refused_whole() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view", "redact"] }])
    );
    let ticket = body["ticket"].as_str().unwrap().to_string();

    let (status, _) = redeem!(
        app,
        f,
        f.rs_client_id,
        f.rs_client_secret,
        ticket,
        user_token(&f)
    );
    assert_eq!(
        status, 403,
        "one denied pair refuses the whole ticket rather than trimming it"
    );
}

// ---------------------------------------------------------------------------
// Ticket single-use and binding
// ---------------------------------------------------------------------------

/// UMA 2.0 §3.3 requires a ticket to be single-use. This is the HTTP-level
/// regression test for it; the datastore-level race is covered — and its
/// residual documented — in `axiam-db`.
#[actix_web::test]
async fn a_ticket_cannot_be_redeemed_twice() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view"] }])
    );
    let ticket = body["ticket"].as_str().unwrap().to_string();

    let (first, _) = redeem!(
        app,
        f,
        f.rs_client_id,
        f.rs_client_secret,
        ticket.clone(),
        user_token(&f)
    );
    assert_eq!(first, 200);

    let (second, body) = redeem!(
        app,
        f,
        f.rs_client_id,
        f.rs_client_secret,
        ticket,
        user_token(&f)
    );
    assert_eq!(second, 400, "a replayed ticket must be refused");
    assert_eq!(body["error"], "invalid_grant");
}

/// A ticket leaked to another client is not a usable credential — and, just as
/// importantly, the wrong client's attempt must not **burn** it. Destroying the
/// rightful holder's ticket on someone else's failed attempt would turn a leak
/// into a denial of service.
#[actix_web::test]
async fn a_wrong_client_redemption_neither_succeeds_nor_burns_the_ticket() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view"] }])
    );
    let ticket = body["ticket"].as_str().unwrap().to_string();

    let (status, _) = redeem!(
        app,
        f,
        f.other_client_id,
        f.other_client_secret,
        ticket.clone(),
        user_token(&f)
    );
    assert_eq!(
        status, 400,
        "a ticket is bound to the client that minted it"
    );

    let (status, body) = redeem!(
        app,
        f,
        f.rs_client_id,
        f.rs_client_secret,
        ticket,
        user_token(&f)
    );
    assert_eq!(
        status, 200,
        "the rightful holder's ticket must survive someone else's attempt: {body}"
    );
}

// ---------------------------------------------------------------------------
// The grant's own required parameters
// ---------------------------------------------------------------------------

/// `claim_token` is the only channel through which v1 can name a requesting
/// party. Its absence must be an explicit refusal, not a default subject.
#[actix_web::test]
async fn the_grant_refuses_a_ticket_with_no_claim_token() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view"] }])
    );
    let ticket = body["ticket"].as_str().unwrap();

    let body = format!(
        "grant_type={}&client_id={}&client_secret={}&ticket={}",
        UMA_TICKET_GRANT_TYPE.replace(':', "%3A"),
        f.rs_client_id,
        f.rs_client_secret,
        ticket
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={}", f.tenant_id))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
    let json: Value = test::read_body_json(resp).await;
    assert_eq!(json["error"], "invalid_request");
}

/// A claim token from another tenant must not be evaluated against this
/// tenant's grants. Without the check, tenant isolation would depend on the
/// subject id not colliding across tenants.
#[actix_web::test]
async fn the_grant_refuses_a_claim_token_from_another_tenant() {
    let f = setup().await;
    let app = test_app!(f);

    let (_, body) = perm!(
        app,
        f,
        pat(&f, &f.rs_client_id),
        json!([{ "resource_id": f.resource_id, "resource_scopes": ["view"] }])
    );
    let ticket = body["ticket"].as_str().unwrap().to_string();

    let foreign = issue_access_token(
        f.user_id,
        Uuid::new_v4(), // a tenant this ticket was not minted in
        f.org_id,
        &[],
        &f.auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();

    let (status, body) = redeem!(app, f, f.rs_client_id, f.rs_client_secret, ticket, foreign);
    assert_eq!(status, 400, "cross-tenant redemption must be refused");
    assert_eq!(body["error"], "invalid_grant");
}

/// The PAT audience is a machine audience — asserted so that a future change to
/// `issue_client_credentials_token` cannot silently turn PATs into user tokens.
#[actix_web::test]
async fn a_pat_is_a_machine_token() {
    let f = setup().await;
    let claims = axiam_auth::token::validate_access_token(&pat(&f, &f.rs_client_id), &f.auth)
        .unwrap()
        .0;
    assert_eq!(claims.aud.as_deref(), Some(AUD_M2M));
    assert_eq!(claims.sub, f.rs_client_id);
    assert_eq!(claims.sub_kind, SubjectKind::OAuth2Client);
}

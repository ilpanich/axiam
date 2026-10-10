//! Integration tests for tenant CRUD endpoints.

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
    AuditLogFilter, AuditLogRepository, OrganizationRepository, Pagination, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealOrganizationRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};
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
    // Test-only non-secret Ed25519 key pair used solely for JWT signing in unit tests.
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
    (private_key, public_key)
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

/// A fresh organization, its reserved scope tenant, one ordinary tenant, and an
/// administrator **in the reserved tenant**.
///
/// Returns `(db, org_id, tenant_id, user_id, org_tenant_id)`, where `tenant_id`
/// is the ordinary tenant these tests act *on* and `org_tenant_id` is where the
/// caller lives.
///
/// The split is the point. Tenant create, update and delete are
/// organization-level actions, and `require_organization_principal` refuses
/// them to any caller whose own record does not live in the organization's
/// reserved tenant, whatever permissions it holds (B-04) — a tenant
/// administrator creating sibling tenants is exactly what that guard exists to
/// stop. So the caller moves into the reserved tenant, and the subject stays an
/// ordinary tenant, because acting on the organization's own scope tenant is a
/// different thing from acting on one of its tenants.
async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid, Uuid) {
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
    let org_tenant = tenant_repo
        .create(CreateTenant::organization_scope(org.id))
        .await
        .unwrap();
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

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: org_tenant.id,
            username: "admin".into(),
            email: "admin@example.com".into(),
            password: "password12345".into(),
            metadata: None,
        })
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id, org_tenant.id)
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

/// Run the audit export for `tenant_id` and return the response body as text.
///
/// Asserts 200 on the way through: every caller here needs the export to have
/// happened, and a silent non-200 would turn a real regression into a
/// confusing failure three assertions later.
macro_rules! export_audit_body {
    ($app:expr, $token:expr, $org_id:expr, $tenant_id:expr) => {{
        let req = test::TestRequest::post()
            .uri(&format!(
                "/api/v1/organizations/{}/tenants/{}/audit-export",
                $org_id, $tenant_id
            ))
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        assert_eq!(resp.status().as_u16(), 200, "audit export must succeed");
        let body = test::read_body(resp).await;
        String::from_utf8(body.to_vec()).expect("export is UTF-8")
    }};
}

/// The export's trailing manifest line, parsed.
fn manifest_of(body: &str) -> serde_json::Value {
    let last = body
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .expect("export has at least the manifest line");
    serde_json::from_str(last).expect("manifest line is JSON")
}

#[actix_rt::test]
async fn create_tenant_returns_201() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "New Tenant",
            "slug": "new-tenant"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 201);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "New Tenant");
    assert_eq!(body["slug"], "new-tenant");
    assert_eq!(body["organization_id"], org_id.to_string());
}

#[actix_rt::test]
async fn list_tenants_returns_200() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    // Two: the ordinary tenant and the organization's own reserved scope, which
    // `setup_db` creates because the caller has to live somewhere.
    //
    // The reserved tenant is deliberately *in* the roster rather than filtered
    // out of it. It is a real tenant of the organization and an organization
    // administrator acts on it, so hiding it server-side would make it
    // unreachable through the API; the admin console filters it where offering
    // it would be wrong instead (`useReachableTenants` drops `kind ==
    // "organization"` from the tenant-scope picker, because scoping a grant to
    // the organization scope is the unrestricted grant).
    assert_eq!(body["total"], 2);
    let items = body["items"].as_array().expect("items must be an array");
    assert_eq!(items.len(), 2);
    let kinds: Vec<&str> = items
        .iter()
        .map(|t| t["kind"].as_str().unwrap_or_default())
        .collect();
    assert!(
        kinds.contains(&"organization"),
        "the organization's own scope is a tenant of it and must be listed: {kinds:?}"
    );
    assert!(
        kinds.contains(&"standard"),
        "the ordinary tenant must be listed: {kinds:?}"
    );
}

#[actix_rt::test]
async fn get_tenant_returns_200() {
    let (db, org_id, tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{tenant_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Test Tenant");
}

#[actix_rt::test]
async fn update_tenant_returns_200() {
    let (db, org_id, tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{tenant_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Updated Tenant" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["name"], "Updated Tenant");
}

#[actix_rt::test]
async fn delete_tenant_returns_204() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);
    let app = test_app!(db, auth);

    // Create a second tenant to delete
    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "To Delete",
            "slug": "to-delete"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    let created: serde_json::Value = test::read_body_json(resp).await;
    let delete_id = created["id"].as_str().unwrap();

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{delete_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        409,
        "T-118: deleting a tenant without a fresh audit export must be refused"
    );

    // Export the trail, then the same DELETE succeeds.
    let _ = export_audit_body!(app, token, org_id, delete_id);

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{delete_id}"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 204);
}

// ---------------------------------------------------------------------------
// T-118: a tenant's audit trail must be exported before it can be destroyed
// ---------------------------------------------------------------------------

/// The export writes a receipt, and that receipt is what unblocks DELETE.
#[actix_rt::test]
async fn audit_export_emits_a_manifest_and_unblocks_delete() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);
    let app = test_app!(db, auth);

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let doomed = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Doomed".into(),
            slug: "doomed".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let body = export_audit_body!(app, token, org_id, doomed.id);
    let manifest = manifest_of(&body);
    assert_eq!(manifest["axiam_export"], "tenant_audit");
    assert_eq!(manifest["tenant_id"], doomed.id.to_string());
    assert_eq!(manifest["exported_by"], user_id.to_string());
    assert_eq!(manifest["record_count"], 0, "a fresh tenant has no entries");
    assert!(
        manifest["digest"].as_str().unwrap().starts_with("sha256:"),
        "manifest carries a digest over the exported entries"
    );
    assert!(manifest["receipt_id"].is_string());

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{}",
            doomed.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);
}

/// The export streams the tenant's entries, one JSON object per line, and the
/// digest in the manifest is over exactly those lines.
#[actix_rt::test]
async fn audit_export_streams_every_entry_and_digests_them() {
    let (db, org_id, tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);

    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    for i in 0..3 {
        audit_repo
            .append(CreateAuditLogEntry {
                tenant_id,
                actor_id: user_id,
                actor_type: ActorType::User,
                action: format!("test.action_{i}"),
                resource_id: None,
                outcome: AuditOutcome::Success,
                ip_address: None,
                metadata: None,
            })
            .await
            .unwrap();
    }

    let app = test_app!(db, auth);
    let body = export_audit_body!(app, token, org_id, tenant_id);

    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    let manifest = manifest_of(&body);
    assert_eq!(manifest["record_count"], 3);
    assert_eq!(lines.len(), 4, "three entries plus the manifest");

    let actions: Vec<String> = lines[..3]
        .iter()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["action"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    for i in 0..3 {
        assert!(
            actions.contains(&format!("test.action_{i}")),
            "entry {i} missing from the export: {actions:?}"
        );
    }

    // The digest must cover the entry lines and NOT the manifest line — so
    // re-hashing the file minus its last line reproduces it.
    let entry_bytes = lines[..3]
        .iter()
        .map(|l| format!("{l}\n"))
        .collect::<String>();
    let mut hasher = Sha256::new();
    hasher.update(entry_bytes.as_bytes());
    assert_eq!(
        manifest["digest"].as_str().unwrap(),
        format!("sha256:{}", hex::encode(hasher.finalize())),
        "the manifest digest must be reproducible from the exported lines"
    );
}

/// An export receipt older than the six-hour window does not unblock DELETE.
///
/// Written straight to the audit log with a backdated timestamp — going
/// through the endpoint and waiting six hours is not a test.
#[actix_rt::test]
async fn a_stale_export_receipt_does_not_unblock_delete() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let doomed = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Stale".into(),
            slug: "stale-receipt".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let receipt = audit_repo
        .append(CreateAuditLogEntry {
            tenant_id: doomed.id,
            actor_id: user_id,
            actor_type: ActorType::User,
            action: axiam_api_rest::handlers::tenants::AUDIT_EXPORT_ACTION.to_string(),
            resource_id: Some(doomed.id),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: None,
        })
        .await
        .unwrap();

    // Backdate it past the window. `timestamp` is set by the datastore on
    // insert, so this is the one place the test has to reach around the
    // repository — the append-only rule is about the API surface, not about
    // what a test may set up.
    let stale = Utc::now()
        - Duration::hours(axiam_api_rest::handlers::tenants::AUDIT_EXPORT_MAX_AGE_HOURS + 1);
    db.query("UPDATE type::record('audit_log', $id) SET timestamp = $ts")
        .bind(("id", receipt.id.to_string()))
        .bind(("ts", stale))
        .await
        .unwrap()
        .check()
        .unwrap();

    let app = test_app!(db, auth);
    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{}",
            doomed.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        409,
        "an export older than the window must not authorise a deletion"
    );
}

/// An export of a DIFFERENT tenant must not unblock this one.
#[actix_rt::test]
async fn an_export_of_another_tenant_does_not_unblock_delete() {
    let (db, org_id, tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let doomed = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Doomed".into(),
            slug: "doomed-other".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let app = test_app!(db, auth);
    // Export the CALLER's tenant, not the one about to be deleted.
    let _ = export_audit_body!(app, token, org_id, tenant_id);

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{}",
            doomed.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        409,
        "an export receipt is scoped to the tenant it was taken from"
    );
}

/// The deletion is recorded in the SYSTEM audit log — the tenant's own entries
/// are gone, so this is the only record that survives it.
#[actix_rt::test]
async fn deleting_a_tenant_records_it_in_the_system_audit_log() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let doomed = tenant_repo
        .create(CreateTenant {
            organization_id: org_id,
            kind: TenantKind::Standard,
            name: "Doomed".into(),
            slug: "doomed-audited".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let app = test_app!(db, auth);
    let _ = export_audit_body!(app, token, org_id, doomed.id);

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{org_id}/tenants/{}",
            doomed.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let system = audit_repo
        .list_system(
            AuditLogFilter {
                action: Some(axiam_api_rest::handlers::tenants::TENANT_DELETED_ACTION.to_string()),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .await
        .unwrap();
    let entry = system
        .items
        .iter()
        .find(|e| e.resource_id == Some(doomed.id))
        .expect("tenant deletion must be recorded in the system audit log");
    assert_eq!(entry.actor_id, user_id);
    assert_eq!(entry.metadata["tenant_slug"], "doomed-audited");
    assert!(
        entry.metadata["audit_export_receipt_id"].is_string(),
        "the deletion record names the export that authorised it"
    );
}

/// Cross-org probing is refused on the export endpoint too — otherwise it
/// would be a read of another organization's audit trail.
#[actix_rt::test]
async fn cross_org_audit_export_returns_403() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-export".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}/audit-export",
            org_b.id,
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// SEC-002: Cross-org 403 negative tests
// ---------------------------------------------------------------------------

/// A caller authenticated for org A gets 403 on GET /organizations/{org_B_id}/tenants.
/// Regression guard: same-org caller gets 200.
#[actix_rt::test]
async fn cross_org_list_tenants_returns_403() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    // Create org B with a distinct id.
    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let org_b_id = org_b.id;

    // Token claims org A.
    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    // Cross-org list: path org_id = org_B, JWT org_id = org_A -> 403.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_b_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant list must return 403"
    );

    // Same-org regression guard.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_a_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "same-org tenant list must return 200"
    );
}

/// A caller authenticated for org A gets 403 on POST /organizations/{org_B_id}/tenants.
#[actix_rt::test]
async fn cross_org_create_tenant_returns_403() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-create".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{}/tenants", org_b.id))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Sneaky Tenant",
            "slug": "sneaky-tenant"
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant create must return 403"
    );
}

/// A caller authenticated for org A gets 403 on GET a single tenant under org B.
/// The ownership guard must reject before any DB read.
#[actix_rt::test]
async fn cross_org_get_tenant_returns_403() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-get".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_b.id,
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant get must return 403"
    );
}

/// A caller authenticated for org A gets 403 on PUT a single tenant under org B
/// (the same top-of-handler ownership guard as GET, exercised for `update`).
#[actix_rt::test]
async fn cross_org_update_tenant_returns_403() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-update".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_b.id,
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Sneaky Update" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant update must return 403"
    );
}

/// A caller authenticated for org A gets 403 on DELETE a single tenant under
/// org B (same top-of-handler ownership guard, exercised for `delete`).
#[actix_rt::test]
async fn cross_org_delete_tenant_returns_403() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-delete".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_b.id,
            Uuid::new_v4()
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        403,
        "cross-org tenant delete must return 403"
    );
}

// ---------------------------------------------------------------------------
// Tenant-belongs-to-a-different-org 404s: distinct from the 403 guards above.
// The caller's org DOES match the URL's org_id (passes the ownership guard),
// but the tenant_id in the URL names a tenant that actually belongs to some
// OTHER organization — the handler must look the tenant up and then 404
// rather than trusting the path alone.
// ---------------------------------------------------------------------------

/// GET a tenant that exists but under a different org than the URL/token's
/// org_id -> 404 (not 200), even though the ownership guard itself passes.
#[actix_rt::test]
async fn get_tenant_wrong_org_returns_404() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-tenant-mismatch-get".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let other_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            kind: TenantKind::Standard,
            name: "Org B's Tenant".into(),
            slug: "org-b-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    // Token's org_id is org A, and the URL's org_id is also org A (guard
    // passes), but the tenant_id in the path belongs to org B.
    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_a_id, other_tenant.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "a tenant belonging to a different org must 404, not leak via 200"
    );
}

/// PUT a tenant that exists but under a different org -> 404.
#[actix_rt::test]
async fn update_tenant_wrong_org_returns_404() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-tenant-mismatch-update".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let other_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            kind: TenantKind::Standard,
            name: "Org B's Tenant".into(),
            slug: "org-b-tenant-update".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_a_id, other_tenant.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({ "name": "Should Not Apply" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "updating a tenant belonging to a different org must 404"
    );
}

/// DELETE a tenant that exists but under a different org -> 404 (and it must
/// NOT actually be deleted).
#[actix_rt::test]
async fn delete_tenant_wrong_org_returns_404() {
    let (db, org_a_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org_b = org_repo
        .create(CreateOrganization {
            name: "Org B".into(),
            slug: "org-b-tenant-mismatch-delete".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let other_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org_b.id,
            kind: TenantKind::Standard,
            name: "Org B's Tenant".into(),
            slug: "org-b-tenant-delete".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let token = mint_token(&auth, user_id, org_tenant, org_a_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::delete()
        .uri(&format!(
            "/api/v1/organizations/{}/tenants/{}",
            org_a_id, other_tenant.id
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        404,
        "deleting a tenant belonging to a different org must 404"
    );

    // Still there, under its real org.
    let still_there = tenant_repo.get_by_id(other_tenant.id).await.unwrap();
    assert_eq!(still_there.organization_id, org_b.id);
}

/// `create`'s permission-seeding step (`seed_permissions`) is best-effort but
/// its failure must be surfaced as a mapped 500, not silently swallowed or a
/// raw internal error. Forced by redefining the `permission.action` field to
/// an incompatible type so the seeder's UPSERT fails with a genuine SurrealDB
/// coercion error — no production code changes, just DB-level fault
/// injection ahead of the request.
#[actix_rt::test]
async fn create_tenant_seed_permissions_failure_returns_500() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);

    // Force every subsequent `permission` UPSERT (including the one
    // `seed_permissions` issues for the newly-created tenant) to fail.
    db.query("DEFINE FIELD OVERWRITE action ON TABLE permission TYPE int PERMISSIONS FULL")
        .await
        .unwrap();

    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "name": "Broken Seed Tenant",
            "slug": "broken-seed-tenant"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        500,
        "a seed_permissions failure must map to a 500, not succeed or panic"
    );
}

// ---------------------------------------------------------------------------
// #523 (P23W2-04, D-4): a deleted tenant is tombstoned, its sessions and
// refresh tokens are revoked in the request, and the purge removes every
// tenant-scoped row
// ---------------------------------------------------------------------------

const TEST_PEER: &str = "127.0.0.1:12345";

/// `test_app!` plus the per-request session check the production server
/// registers, so an access token whose session was revoked is refused.
macro_rules! session_checked_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(Arc::new(
                    axiam_db::repository::SurrealSessionRepository::new($db.clone()),
                )
                    as Arc<dyn axiam_api_rest::SessionValidator>))
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

/// Create a tenant through the API, as an administrator does (so it carries
/// the seeded permissions and seeder state too), and return its id.
macro_rules! create_tenant_via_api {
    ($app:expr, $token:expr, $org_id:expr, $slug:expr) => {{
        let req = test::TestRequest::post()
            .uri(&format!("/api/v1/organizations/{}/tenants", $org_id))
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .set_json(serde_json::json!({ "name": $slug, "slug": $slug }))
            .to_request();
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        if status == 201 {
            let body: serde_json::Value = test::read_body_json(resp).await;
            Ok(Uuid::parse_str(body["id"].as_str().unwrap()).unwrap())
        } else {
            Err(status)
        }
    }};
}

/// Sign `alice` in to `tenant_id` and return `(access token, refresh token)`.
macro_rules! sign_in {
    ($app:expr, $org_id:expr, $tenant_id:expr) => {{
        let req = test::TestRequest::post()
            .peer_addr(TEST_PEER.parse().unwrap())
            .uri("/api/v1/auth/login")
            .set_json(serde_json::json!({
                "tenant_id": $tenant_id,
                "org_id": $org_id,
                "username_or_email": "alice",
                "password": "password12345"
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
            _ => Err(status),
        }
    }};
}

/// One refresh rotation; `Ok(new refresh token)` or the status it was refused
/// with.
macro_rules! refresh {
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
        let resp = test::call_service(&$app, req).await;
        let status = resp.status().as_u16();
        let rotated = resp
            .response()
            .cookies()
            .find(|c| c.name() == "axiam_refresh")
            .map(|c| c.value().to_owned());
        match rotated {
            Some(r) if status == 200 => Ok(r),
            _ => Err(status),
        }
    }};
}

/// An access token for the organization administrator backed by a real
/// session, so it passes the per-request session check `session_checked_app!`
/// registers.
async fn session_backed_token(
    db: &Surreal<TestDb>,
    auth: &AuthConfig,
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
) -> String {
    use axiam_core::models::session::CreateSession;
    use axiam_core::repository::SessionRepository;
    let session = axiam_db::repository::SurrealSessionRepository::new(db.clone())
        .create(CreateSession {
            tenant_id,
            user_id,
            token_hash: format!("admin-{user_id}"),
            ip_address: None,
            user_agent: None,
            expires_at: Utc::now() + Duration::hours(1),
            authenticated_at: Utc::now(),
            amr: Vec::new(),
            browser_token_hash: None,
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

/// The status of an authenticated read made with `access`.
macro_rules! whoami_status {
    ($app:expr, $access:expr) => {{
        let req = test::TestRequest::get()
            .uri("/api/v1/auth/me")
            .insert_header(("Authorization", format!("Bearer {}", $access)))
            .to_request();
        test::call_service(&$app, req).await.status().as_u16()
    }};
}

/// Fill `tenant_id` the way a tenant in use is filled: an active `alice` who
/// can sign in, a second account, a group and a role (with their graph edges),
/// a permission and a resource, an OAuth2 client with two refresh tokens, a
/// webhook, a certificate, a federation configuration, an e-mail configuration,
/// a consent and audit entries.
async fn populate_tenant(db: &Surreal<TestDb>, tenant_id: Uuid) {
    use axiam_core::models::certificate::{CertificateType, KeyAlgorithm, StoreCertificate};
    use axiam_core::models::federation::CreateFederationConfig;
    use axiam_core::models::gdpr::CreateConsent;
    use axiam_core::models::group::CreateGroup;
    use axiam_core::models::oauth2_client::{CreateOAuth2Client, CreateRefreshToken};
    use axiam_core::models::permission::CreatePermission;
    use axiam_core::models::resource::CreateResource;
    use axiam_core::models::role::{AssignmentScope, CreateRole};
    use axiam_core::models::user::{UpdateUser, UserStatus};
    use axiam_core::models::webhook::CreateWebhook;
    use axiam_core::repository::{
        CertificateRepository, ConsentRepository, FederationConfigRepository, GroupRepository,
        OAuth2ClientRepository, PermissionRepository, RefreshTokenRepository, ResourceRepository,
        RoleRepository, WebhookRepository,
    };
    use axiam_db::repository::{
        SurrealCertificateRepository, SurrealConsentRepository, SurrealFederationConfigRepository,
        SurrealGroupRepository, SurrealOAuth2ClientRepository, SurrealPermissionRepository,
        SurrealRefreshTokenRepository, SurrealResourceRepository, SurrealRoleRepository,
        SurrealWebhookRepository,
    };

    let users = SurrealUserRepository::new(db.clone());
    let mut user_ids = Vec::new();
    for name in ["alice", "bob"] {
        let user = users
            .create(CreateUser {
                tenant_id,
                username: name.into(),
                email: format!("{name}@example.com"),
                password: "password12345".into(),
                metadata: None,
            })
            .await
            .unwrap();
        users
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
        user_ids.push(user.id);
    }
    let alice = user_ids[0];

    let group = SurrealGroupRepository::new(db.clone())
        .create(CreateGroup {
            tenant_id,
            name: "staff".into(),
            description: String::new(),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealGroupRepository::new(db.clone())
        .add_member(tenant_id, alice, group.id)
        .await
        .unwrap();
    let roles = SurrealRoleRepository::new(db.clone());
    let role = roles
        .create(CreateRole {
            tenant_id,
            name: "editor".into(),
            description: String::new(),
            is_global: true,
        })
        .await
        .unwrap();
    roles
        .assign_to_user(tenant_id, alice, role.id, AssignmentScope::global())
        .await
        .unwrap();
    SurrealPermissionRepository::new(db.clone())
        .create(CreatePermission {
            tenant_id,
            action: "documents:edit".into(),
            description: String::new(),
        })
        .await
        .unwrap();
    SurrealResourceRepository::new(db.clone())
        .create(CreateResource {
            tenant_id,
            name: "documents".into(),
            resource_type: "collection".into(),
            parent_id: None,
            metadata: None,
        })
        .await
        .unwrap();

    let client_input: CreateOAuth2Client = serde_json::from_value(serde_json::json!({
        "tenant_id": tenant_id,
        "name": "portal",
        "redirect_uris": ["https://portal.example.com/cb"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid"],
    }))
    .unwrap();
    let (client, _secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(client_input)
        .await
        .unwrap();
    let refresh_tokens = SurrealRefreshTokenRepository::new(db.clone());
    for n in 0..2 {
        refresh_tokens
            .create(CreateRefreshToken {
                tenant_id,
                token_hash: format!("hash-{tenant_id}-{n}"),
                client_id: client.client_id.clone(),
                user_id: Some(alice),
                scopes: vec!["openid".into()],
                session_id: None,
                requested_userinfo_claims: Vec::new(),
                resource: None,
                auth_time: None,
                acr: None,
                amr: Vec::new(),
                expires_at: Utc::now() + Duration::days(30),
            })
            .await
            .unwrap();
    }

    SurrealWebhookRepository::new(db.clone())
        .create(CreateWebhook {
            tenant_id,
            url: "https://hooks.example.com/axiam".into(),
            events: vec!["user.created".into()],
            secret: "whsec-0123456789abcdef".into(),
            retry_policy: None,
        })
        .await
        .unwrap();
    SurrealCertificateRepository::new(db.clone())
        .create(StoreCertificate {
            tenant_id,
            issuer_ca_id: Uuid::new_v4(),
            subject: "device-001".into(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".into(),
            fingerprint: format!("fp-{tenant_id}"),
            cert_type: CertificateType::User,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - Duration::minutes(1),
            not_after: Utc::now() + Duration::days(365),
            metadata: serde_json::json!({}),
        })
        .await
        .unwrap();
    let federation: CreateFederationConfig = serde_json::from_value(serde_json::json!({
        "tenant_id": tenant_id,
        "provider": "okta",
        "protocol": "OidcConnect",
        "metadata_url": "https://idp.example.com/.well-known/openid-configuration",
        "client_id": "cid",
        "client_secret": "federation-secret",
    }))
    .unwrap();
    SurrealFederationConfigRepository::new(db.clone())
        .create(federation)
        .await
        .unwrap();
    // The tenant-scoped e-mail configuration, as an override row holds it.
    db.query(
        "CREATE email_config SET scope = 'tenant', scope_id = $tenant, \
         from_name = 'Tenant', from_email = 'noreply@example.com', \
         provider_kind = 'smtp', smtp_host = 'smtp.example.com', \
         smtp_password_ciphertext = 'sealed', smtp_password_nonce = 'nonce'",
    )
    .bind(("tenant", tenant_id.to_string()))
    .await
    .unwrap()
    .check()
    .unwrap();
    SurrealConsentRepository::new(db.clone())
        .create(CreateConsent {
            tenant_id,
            user_id: alice,
            consent_type: "terms".into(),
            version: "1".into(),
            ip_address: None,
            user_agent: None,
        })
        .await
        .unwrap();
    SurrealAuditLogRepository::new(db.clone())
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: alice,
            actor_type: ActorType::User,
            action: "documents.edited".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: Some("192.0.2.1".into()),
            metadata: None,
        })
        .await
        .unwrap();
}

/// How many rows of each tenant-scoped table name `tenant_id`, in purge order.
async fn tenant_rows(db: &Surreal<TestDb>, tenant_id: Uuid) -> Vec<(&'static str, u64)> {
    use axiam_db::repository::tenant_purge::{TENANT_PURGE_ORDER, TenantKey};
    let mut counts = Vec::new();
    for step in TENANT_PURGE_ORDER {
        let filter = match step.key {
            TenantKey::TenantId => "tenant_id = $tenant",
            TenantKey::Scope => "scope = 'tenant' AND scope_id = $tenant",
        };
        let mut result = db
            .query(format!(
                "SELECT count() AS total FROM {} WHERE {filter} GROUP ALL",
                step.table
            ))
            .bind(("tenant", tenant_id.to_string()))
            .await
            .unwrap()
            .check()
            .unwrap();
        let rows: Vec<axiam_db::CountRow> = result.take(0).unwrap();
        counts.push((step.table, rows.first().map_or(0, |r| r.total)));
    }
    counts
}

/// Rows of a graph edge table, all tenants together.
async fn edges(db: &Surreal<TestDb>, table: &str) -> u64 {
    let mut result = db
        .query(format!("SELECT count() AS total FROM {table} GROUP ALL"))
        .await
        .unwrap();
    let rows: Vec<axiam_db::CountRow> = result.take(0).unwrap();
    rows.first().map_or(0, |r| r.total)
}

/// The issue's test (#523): delete a populated tenant; its last session can no
/// longer refresh, its access token is refused and nobody can sign in to it,
/// from the `204` on; the purge then leaves every tenant-scoped table empty for
/// it — and another tenant of the organization keeps every row and its own
/// sessions.
#[actix_rt::test]
async fn deleting_a_populated_tenant_revokes_its_last_session_and_the_purge_empties_every_table() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = session_backed_token(&db, &auth, user_id, org_tenant, org_id).await;
    let app = session_checked_app!(db, auth);

    let doomed = create_tenant_via_api!(app, token, org_id, "doomed-populated").unwrap();
    let bystander = create_tenant_via_api!(app, token, org_id, "bystander").unwrap();
    populate_tenant(&db, doomed).await;
    populate_tenant(&db, bystander).await;

    // Both tenants are in use: alice is signed in to each, and her session in
    // the doomed tenant refreshes once — its LAST session is the rotated one.
    let (doomed_access, doomed_refresh) = sign_in!(app, org_id, doomed).unwrap();
    let doomed_refresh = refresh!(app, doomed, doomed_refresh).expect("refresh before delete");
    let (bystander_access, bystander_refresh) = sign_in!(app, org_id, bystander).unwrap();
    assert_eq!(whoami_status!(app, bystander_access), 200);
    let bystander_before = tenant_rows(&db, bystander).await;
    for table in [
        "user",
        "session",
        "oauth2_refresh_token",
        "webhook",
        "email_config",
    ] {
        let (_, n) = bystander_before.iter().find(|(t, _)| *t == table).unwrap();
        assert!(*n > 0, "the bystander tenant has {table} rows to keep");
    }
    let doomed_before = tenant_rows(&db, doomed).await;
    assert!(
        doomed_before.iter().filter(|(_, n)| *n > 0).count() >= 15,
        "the doomed tenant is populated: {doomed_before:?}"
    );

    let _ = export_audit_body!(app, token, org_id, doomed);
    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants/{doomed}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(
        test::call_service(&app, req).await.status().as_u16(),
        204,
        "the status code is unchanged: the purge is not the caller's to wait for"
    );

    // Immediately, before any purge: the last session cannot refresh, the
    // access token fails the session check, nobody can sign in, and every
    // OAuth2 refresh token of the tenant is revoked.
    assert_eq!(refresh!(app, doomed, doomed_refresh), Err(401));
    assert_eq!(whoami_status!(app, doomed_access), 401);
    assert!(
        sign_in!(app, org_id, doomed).is_err(),
        "no sign-in to a deleted tenant"
    );
    let mut live = db
        .query(
            "SELECT count() AS total FROM oauth2_refresh_token \
             WHERE tenant_id = $tenant AND revoked = false GROUP ALL",
        )
        .bind(("tenant", doomed.to_string()))
        .await
        .unwrap();
    let live: Vec<axiam_db::CountRow> = live.take(0).unwrap();
    assert_eq!(
        live.first().map_or(0, |r| r.total),
        0,
        "refresh tokens revoked"
    );
    let tenants = SurrealTenantRepository::new(db.clone());
    assert!(
        tenants.get_by_id(doomed).await.is_err(),
        "gone from every read"
    );

    // The purge (the cleanup job's `tenant_purge` sweep) empties every
    // tenant-scoped table for the tenant, then removes its row.
    tenants.purge_tombstoned(doomed).await.unwrap();
    for (table, n) in tenant_rows(&db, doomed).await {
        assert_eq!(n, 0, "{table} still holds the deleted tenant's rows");
    }
    assert!(tenants.list_tombstoned().await.unwrap().is_empty());
    // The graph edges went with their records: only the bystander's remain.
    assert_eq!(edges(&db, "member_of").await, 1);
    let has_role = edges(&db, "has_role").await;
    assert!(has_role >= 1, "the bystander keeps its role assignment");

    // The system-log record of the deletion is kept.
    let system = SurrealAuditLogRepository::new(db.clone())
        .list_system(
            AuditLogFilter {
                action: Some(axiam_api_rest::handlers::tenants::TENANT_DELETED_ACTION.to_string()),
                ..Default::default()
            },
            Pagination {
                offset: 0,
                limit: 10,
                search: None,
            },
        )
        .await
        .unwrap();
    assert!(system.items.iter().any(|e| e.resource_id == Some(doomed)));

    // The other tenant is untouched: every row, and its session.
    assert_eq!(tenant_rows(&db, bystander).await, bystander_before);
    assert_eq!(whoami_status!(app, bystander_access), 200);
    assert!(refresh!(app, bystander, bystander_refresh).is_ok());
}

/// #523: a tombstoned tenant keeps its slug until it is purged — a new tenant
/// asking for it is refused with `409` — and the slug is free once the purge
/// has removed the old tenant's rows.
#[actix_rt::test]
async fn a_deleted_tenants_slug_is_refused_until_the_purge_frees_it() {
    let (db, org_id, _tenant_id, user_id, org_tenant) = setup_db().await;
    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, org_tenant, org_id);
    let app = test_app!(db, auth);

    let doomed = create_tenant_via_api!(app, token, org_id, "reused-slug").unwrap();
    let _ = export_audit_body!(app, token, org_id, doomed);
    let req = test::TestRequest::delete()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants/{doomed}"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    assert_eq!(test::call_service(&app, req).await.status().as_u16(), 204);

    assert_eq!(
        create_tenant_via_api!(app, token, org_id, "reused-slug"),
        Err(409),
        "the slug of a tenant whose rows are still there is not reused"
    );
    // Nor does the tombstoned tenant appear in the organization's list.
    let req = test::TestRequest::get()
        .uri(&format!("/api/v1/organizations/{org_id}/tenants"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let listed: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert!(
        !listed.to_string().contains(&doomed.to_string()),
        "a deleted tenant is not listed"
    );

    SurrealTenantRepository::new(db.clone())
        .purge_tombstoned(doomed)
        .await
        .unwrap();
    let reborn = create_tenant_via_api!(app, token, org_id, "reused-slug")
        .expect("the slug is free once the old tenant is purged");
    assert_ne!(reborn, doomed);
}

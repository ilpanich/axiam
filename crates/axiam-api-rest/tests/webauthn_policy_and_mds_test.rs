//! Integration tests for the X3 wave 3 admin endpoints:
//! `handlers::webauthn_policy` (`GET`/`PUT .../attestation-policy`,
//! `GET .../compliance-report`) and `handlers::mds`
//! (`GET /api/v1/mds/status`, `POST /api/v1/mds/refresh`).
//!
//! Uses `AllowAllAuthzChecker` (permission gating itself is covered by
//! `tests/rbac_test.rs`'s `all_routes_have_permission` static check plus the
//! generic RBAC guard tests) so these focus on each handler's own logic:
//! D5 defaults, D5 validation, D9's pre-X3 "unknown" case, and D10's
//! disabled-by-default refusal.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::models::webauthn_credential::{CreateWebauthnCredential, WebauthnCredentialType};
use axiam_core::repository::{
    OrganizationRepository, TenantRepository, UserRepository, WebauthnCredentialRepository,
};
use axiam_db::SurrealWebauthnCredentialRepository;
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";

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
        mfa_encryption_key: Some([9u8; 32]),
        opaque_session_key: None,
        opaque_setup_key: None,
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        ..AuthConfig::default()
    }
}

async fn setup_tenant(db: &Surreal<TestDb>, slug_suffix: &str) -> (Uuid, Uuid, Uuid) {
    setup_scope(db, slug_suffix, TenantKind::Standard).await
}

/// A fresh organization with one tenant of the given kind, and an active user
/// in it.
///
/// The kind is a parameter because one endpoint here is not like the others:
/// the WebAuthn policy is per-tenant, but `POST /mds/refresh` is
/// organization-level (B-08) — the MDS tables are server-**global**, so a
/// tenant super-admin refreshing them would rewrite the FIDO attestation trust
/// store for the whole deployment. `require_organization_principal` refuses a
/// caller whose own record does not live in the organization's reserved tenant,
/// and it does so before the handler gets as far as asking whether ingestion is
/// enabled.
async fn setup_scope(
    db: &Surreal<TestDb>,
    slug_suffix: &str,
    kind: TenantKind,
) -> (Uuid, Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {slug_suffix}"),
            slug: format!("org-wp-{slug_suffix}"),
            metadata: None,
        })
        .await
        .unwrap();
    let create = match kind {
        TenantKind::Organization => CreateTenant::organization_scope(org.id),
        _ => CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {slug_suffix}"),
            slug: format!("tenant-wp-{slug_suffix}"),
            metadata: None,
        },
    };
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(create)
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: format!("wp-user-{slug_suffix}"),
            email: format!("wp-user-{slug_suffix}@example.com"),
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

    (org.id, tenant.id, user.id)
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

// ---------------------------------------------------------------------------
// webauthn_policy — GET (D5 defaults)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn get_policy_with_no_row_returns_defaults_not_404() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "getdefault").await;

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "absent row must not be a 404");
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["mode"], "none");
    assert_eq!(body["require_fido_certified"], false);
    // `null` = "use this mode's default" (deny under direct_required, allow
    // otherwise). The resolved action is reported alongside it so a client
    // never has to re-derive that rule.
    assert!(
        body["unknown_aaguid"].is_null(),
        "the default policy stores no explicit action, got {}",
        body["unknown_aaguid"]
    );
    assert_eq!(body["effective_unknown_aaguid"], "allow");
}

// ---------------------------------------------------------------------------
// webauthn_policy — PUT (D5 validation + round trip)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn put_policy_rejects_require_fido_certified_with_mode_none() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "putbad").await;

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "mode": "none",
            "require_fido_certified": true,
            "min_certification": null,
            "allowed_aaguids": null,
            "blocked_aaguids": [],
            "block_revoked_status": true,
            "unknown_aaguid": "allow",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "require_fido_certified with mode: none is a D5 config error"
    );
}

#[actix_web::test]
async fn put_then_get_policy_round_trips_and_is_cross_tenant_isolated() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_a, tenant_a, user_a) = setup_tenant(&db, "puta").await;
    let (_org_b, tenant_b, _user_b) = setup_tenant(&db, "putb").await;

    let auth = test_auth_config();
    let token_a = mint_token(&auth, user_a, tenant_a, org_a);
    let app = test_app!(db, auth);

    let put_req = test::TestRequest::put()
        .uri(&format!(
            "/api/v1/tenants/{tenant_a}/webauthn/attestation-policy"
        ))
        .insert_header(("Authorization", format!("Bearer {token_a}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(json!({
            "mode": "direct_required",
            "require_fido_certified": false,
            "min_certification": null,
            "allowed_aaguids": null,
            "blocked_aaguids": [],
            "block_revoked_status": true,
            "unknown_aaguid": "deny",
        }))
        .to_request();
    let put_resp = test::call_service(&app, put_req).await;
    assert_eq!(put_resp.status().as_u16(), 200);

    let get_a_req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/tenants/{tenant_a}/webauthn/attestation-policy"
        ))
        .insert_header(("Authorization", format!("Bearer {token_a}")))
        .to_request();
    let get_a_resp = test::call_service(&app, get_a_req).await;
    let body_a: Value = test::read_body_json(get_a_resp).await;
    assert_eq!(body_a["mode"], "direct_required");
    assert_eq!(body_a["unknown_aaguid"], "deny");

    // Tenant B never had its policy touched — still the default, proving the
    // write above did not leak across tenants.
    let get_b_req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/tenants/{tenant_b}/webauthn/attestation-policy"
        ))
        .insert_header(("Authorization", format!("Bearer {token_a}")))
        .to_request();
    let get_b_resp = test::call_service(&app, get_b_req).await;
    // Cross-tenant read with tenant A's token must be refused, not leak B's data.
    assert_eq!(get_b_resp.status().as_u16(), 403);
}

// ---------------------------------------------------------------------------
// webauthn_policy — compliance report (D9 pre-X3 "unknown" case)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn compliance_report_reports_pre_x3_credential_as_unknown_not_a_violation() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "compliance").await;

    // A credential with NO recorded aaguid — exactly what every pre-X3 row
    // looks like (D6: aaguid defaults to None on old rows).
    let cred_repo = SurrealWebauthnCredentialRepository::new(db.clone());
    cred_repo
        .create(CreateWebauthnCredential {
            tenant_id,
            user_id,
            credential_id: "legacy-cred-1".into(),
            name: "Old Security Key".into(),
            credential_type: WebauthnCredentialType::SecurityKey,
            passkey_json: r#"{"encrypted":"placeholder"}"#.into(),
            aaguid: None,
            attestation_format: None,
            attested: false,
            authenticator_name: None,
        })
        .await
        .unwrap();

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri(&format!(
            "/api/v1/tenants/{tenant_id}/webauthn/compliance-report"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    // D9: "never as a violation" — compliant stays true, with the fixed
    // pre-X3 explanation as the reason.
    assert_eq!(entries[0]["compliant"], true);
    assert_eq!(
        entries[0]["reason"],
        "registered before attestation policy was enabled"
    );
}

// ---------------------------------------------------------------------------
// mds — status (never-ingested) and refresh (disabled by default)
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn mds_status_with_nothing_ingested_returns_nulls_not_404() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "mdsstatus").await;

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let req = test::TestRequest::get()
        .uri("/api/v1/mds/status")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["no"], Value::Null);
    assert_eq!(body["entry_count"], 0);
    assert_eq!(body["stale"], false);
}

#[actix_web::test]
async fn mds_refresh_refuses_when_disabled_by_default() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    // Organization-level (B-08): the caller must live in the organization's own
    // reserved tenant, or it is refused before the disabled-ingestion check.
    let (org_id, tenant_id, user_id) =
        setup_scope(&db, "mdsrefresh", TenantKind::Organization).await;

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    // AppState::for_test's PkiConfig uses `..Default::default()`, i.e.
    // `mds_enabled: false` — the D10 shipped default — so this proves the
    // REST endpoint itself refuses to run, not just that the background job
    // isn't spawned.
    let app = test_app!(db, auth);

    let req = test::TestRequest::post()
        .uri("/api/v1/mds/refresh")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        400,
        "MDS ingestion disabled (the default) must refuse to run, making zero outbound calls"
    );
}

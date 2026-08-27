//! X3 wave 3 (scope B): proves the WebAuthn REST handlers actually dispatch
//! on the tenant's attestation policy, not just that `axiam-auth`'s
//! `WebauthnService::*_for_policy` methods exist.
//!
//! This is the single most important behavior in the wave: if
//! `handlers::webauthn::start_registration` kept calling
//! `WebauthnService::start_registration` directly, every tenant's policy
//! would be silently inert — no error, no audit line, just attestation
//! enforcement that never fires. These tests distinguish the two ceremonies
//! by the one place their difference is externally observable without a
//! real authenticator: `webauthn-rs` hard-codes
//! `AttestationConveyancePreference::None` for the unattested ceremony and
//! `::Direct` for the attested one (verified by reading
//! `webauthn-rs-0.5.5/src/lib.rs`'s `start_passkey_registration` /
//! `start_attested_passkey_registration` — see `axiam-auth::webauthn`'s
//! module docs, which cite the same source), and that value is echoed back
//! verbatim in `CreationChallengeResponse.publicKey.attestation` — a field
//! the client can read without ever touching an authenticator.
//!
//! A `direct_required` tenant additionally needs a non-empty
//! `AttestationCaList` to even reach the attested ceremony (W2-D3 fails
//! closed otherwise), so this seeds one MDS entry with a self-signed test
//! root — the same vendored test certificate `axiam-auth::attestation`'s own
//! unit tests use (real, parseable X.509 DER; not a wire-format fake).

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::models::mds::{MdsBlobMeta, MdsEntry};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::models::webauthn_policy::{AttestationMode, WebauthnAttestationPolicy};
use axiam_core::repository::{
    MdsRepository, OrganizationRepository, TenantRepository, UserRepository,
    WebauthnAttestationPolicyRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{SurrealMdsRepository, SurrealWebauthnAttestationPolicyRepository};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

/// `/auth/webauthn/*` is `build_governor`-wrapped, whose per-peer key extractor
/// 500s with "no peer address" when none is set — see `auth_test.rs`, which does
/// the same for the login and MFA routes.
const TEST_PEER: &str = "127.0.0.1:12345";
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const CSRF_TOKEN: &str = "test-csrf-token";

/// Vendored self-signed Ed25519 X.509 test root (`CN=axiam-test-root`) — the
/// exact same certificate `axiam-auth::attestation`'s unit tests use as
/// `TEST_ROOT_DER_B64`. Real, parseable X.509 DER — `AttestationCaListBuilder`
/// only needs *some* valid certificate, not a genuine FIDO root, to build a
/// non-empty `AttestationCaList`.
const TEST_ROOT_DER_B64: &str = "MIIBSDCB+6ADAgECAhQDiCypHmzEedN6JiRFDyTXDBUgRTAFBgMrZXAwGjEYMBYGA1UEAwwPYXhpYW0tdGVzdC1yb290MB4XDTI2MDgxMzA4MjcwOFoXDTM2MDgxMDA4MjcwOFowGjEYMBYGA1UEAwwPYXhpYW0tdGVzdC1yb290MCowBQYDK2VwAyEAyypYyUSxb2Q2w4Oz0JcGvoSJNHAsOCvC4s1wElt2yv6jUzBRMB0GA1UdDgQWBBQ5bN+q4O+R/Q4nq5Sq7Mc7GFMcuTAfBgNVHSMEGDAWgBQ5bN+q4O+R/Q4nq5Sq7Mc7GFMcuTAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAL3cY5942daBVLRMfhDxBVL02x8Ps7eO5Sokw1mRyX+OcrdRXhRbjl9+8FBtbXiAp4F0JSLg6JWzYC+gQ8AVcQQ=";

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
        mfa_encryption_key: Some([7u8; 32]),
        opaque_session_key: None,
        opaque_setup_key: None,
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        ..AuthConfig::default()
    }
}

async fn setup_tenant(db: &Surreal<TestDb>, slug_suffix: &str) -> (Uuid, Uuid, Uuid) {
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: format!("Org {slug_suffix}"),
            slug: format!("org-wae-{slug_suffix}"),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: format!("Tenant {slug_suffix}"),
            slug: format!("tenant-wae-{slug_suffix}"),
            metadata: None,
        })
        .await
        .unwrap();
    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: format!("wae-user-{slug_suffix}"),
            email: format!("wae-user-{slug_suffix}@example.com"),
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

/// Extract `(status, attestation)` from a `POST .../register/start`
/// response body. `test::call_service`'s app type is an unnameable opaque
/// generic, so this only handles the already-`await`ed response rather than
/// taking the app/request as parameters.
async fn read_start_registration_attestation(
    resp: actix_web::dev::ServiceResponse<impl actix_web::body::MessageBody>,
) -> (u16, Option<String>) {
    let status = resp.status().as_u16();
    if status != 200 {
        return (status, None);
    }
    let body: Value = test::read_body_json(resp).await;
    let attestation = body["challenge"]["publicKey"]["attestation"]
        .as_str()
        .map(str::to_string);
    (status, attestation)
}

macro_rules! start_registration {
    ($app:expr, $token:expr) => {{
        let req = test::TestRequest::post()
            .uri("/api/v1/auth/webauthn/register/start")
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
            .insert_header(("X-CSRF-Token", CSRF_TOKEN))
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .to_request();
        let resp = test::call_service(&$app, req).await;
        read_start_registration_attestation(resp).await
    }};
}

/// A default-policy tenant (no `webauthn_attestation_policy` row) must take
/// the UNATTESTED ceremony — `attestation: "none"` — proving
/// `start_registration_for_policy` really does short-circuit on `mode: none`
/// (D8 step 1) via the REST handler, not just in `axiam-auth`'s own tests.
#[actix_web::test]
async fn default_tenant_registration_start_is_unattested() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "default").await;

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (status, attestation) = start_registration!(app, token);
    assert_eq!(status, 200, "default-policy tenant must register normally");
    assert_eq!(
        attestation.as_deref(),
        Some("none"),
        "no policy row => WebauthnAttestationPolicy::default() (mode: none) => the \
         UNATTESTED ceremony, whose CreationChallengeResponse always carries \
         attestation: \"none\" (webauthn-rs start_passkey_registration)"
    );
}

/// A `direct_required` tenant with a usable MDS-backed `AttestationCaList`
/// must take the ATTESTED ceremony — `attestation: "direct"` — proving the
/// REST handler resolves the policy and calls
/// `start_attested_passkey_registration` under the hood instead of silently
/// staying on the unattested path. This is exactly the regression the wave
/// spec calls "the single most important change": if the handler still
/// called `WebauthnService::start_registration` unconditionally, this
/// assertion would observe `"none"` here too, indistinguishable from the
/// default-tenant case above.
#[actix_web::test]
async fn direct_required_tenant_registration_start_is_attested() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "direct").await;

    // Seed one MDS entry with a real, parseable X.509 root so the CA-list
    // cache (W2-D3) builds non-empty — otherwise the attested ceremony would
    // fail closed with WebauthnAttestationUnavailable (503) before ever
    // reaching webauthn-rs, which would prove fail-closed behavior but not
    // the attestation-conveyance switch this test targets.
    let aaguid = Uuid::new_v4();
    let mds_repo = SurrealMdsRepository::new(db.clone());
    mds_repo
        .replace_entries(
            vec![MdsEntry {
                aaguid,
                description: Some("Test Authenticator".into()),
                attestation_root_certificates: vec![TEST_ROOT_DER_B64.to_string()],
                status_reports: Vec::new(),
                time_of_last_status_change: None,
            }],
            MdsBlobMeta {
                no: 1,
                next_update: chrono::Utc::now().date_naive() + chrono::Duration::days(14),
                entry_count: 1,
                last_refreshed_at: chrono::Utc::now(),
                stale: false,
            },
        )
        .await
        .unwrap();
    // Sanity: the seeded cert must actually decode, or the CA-list cache
    // would build empty and this test would (mis)prove the fail-closed path
    // instead of the conveyance switch.
    assert!(STANDARD.decode(TEST_ROOT_DER_B64).unwrap().len() > 32);

    // Direct-required policy for the tenant.
    SurrealWebauthnAttestationPolicyRepository::new(db.clone())
        .set(
            tenant_id,
            WebauthnAttestationPolicy {
                mode: AttestationMode::DirectRequired,
                ..WebauthnAttestationPolicy::default()
            },
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (status, attestation) = start_registration!(app, token);
    assert_eq!(
        status, 200,
        "an ingested MDS root must let the attested ceremony start successfully"
    );
    assert_eq!(
        attestation.as_deref(),
        Some("direct"),
        "mode: direct_required => the ATTESTED ceremony => webauthn-rs's \
         start_attested_passkey_registration, which always requests \
         AttestationConveyancePreference::Direct (W2-D1) regardless of AXIAM's \
         own mode naming — this is the observable proof the REST handler is on \
         the attested path, not the unattested one"
    );
}

/// A `direct_required` tenant with NO ingested MDS data must fail closed
/// (W2-D3) rather than silently falling back to the unattested ceremony —
/// the fail-closed twin of the two tests above, proving the handler doesn't
/// paper over an empty CA list.
#[actix_web::test]
async fn direct_required_tenant_without_mds_data_fails_closed() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "nomds").await;

    SurrealWebauthnAttestationPolicyRepository::new(db.clone())
        .set(
            tenant_id,
            WebauthnAttestationPolicy {
                mode: AttestationMode::DirectRequired,
                ..WebauthnAttestationPolicy::default()
            },
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let token = mint_token(&auth, user_id, tenant_id, org_id);
    let app = test_app!(db, auth);

    let (status, _attestation) = start_registration!(app, token);
    assert_eq!(
        status, 503,
        "no MDS data ingested => empty AttestationCaList => \
         WebauthnAttestationUnavailable (W2-D3 fail-closed), never a silent \
         downgrade to the unattested ceremony"
    );
}

// ---------------------------------------------------------------------------
// T-153 — MDS staleness bound on attested registration
// ---------------------------------------------------------------------------
//
// The threat: staleness deliberately never hard-fails ingestion, so an
// authenticator model revoked since the last successful refresh keeps passing
// attestation policy. `AXIAM__PKI__MDS_MAX_STALE_DAYS` lets an operator bound
// that window. These tests pin the three conditions that gate it, because each
// one is a way the control could be silently wrong: on when it should be off
// (denying registrations nobody asked it to deny), or off when it should be on.

/// Build the app with a specific `mds_max_stale_days`, seeding an MDS BLOB
/// whose `next_update` is `blob_age_days` in the past.
async fn state_with_stale_blob(
    db: &Surreal<TestDb>,
    tenant_id: Uuid,
    auth: &AuthConfig,
    max_stale_days: u32,
    blob_age_days: i64,
    mode: AttestationMode,
) -> AppState<TestDb> {
    let aaguid = Uuid::new_v4();
    SurrealMdsRepository::new(db.clone())
        .replace_entries(
            vec![MdsEntry {
                aaguid,
                description: Some("Test Authenticator".into()),
                attestation_root_certificates: vec![TEST_ROOT_DER_B64.to_string()],
                status_reports: Vec::new(),
                time_of_last_status_change: None,
            }],
            MdsBlobMeta {
                no: 1,
                next_update: chrono::Utc::now().date_naive()
                    - chrono::Duration::days(blob_age_days),
                entry_count: 1,
                last_refreshed_at: chrono::Utc::now() - chrono::Duration::days(blob_age_days),
                stale: blob_age_days > 0,
            },
        )
        .await
        .unwrap();

    SurrealWebauthnAttestationPolicyRepository::new(db.clone())
        .set(
            tenant_id,
            WebauthnAttestationPolicy {
                mode,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let mut state = AppState::for_test(db.clone(), auth.clone());
    state.webauthn.pki_config.mds_max_stale_days = max_stale_days;
    state
}

/// `POST .../register/finish` with a deliberately bogus ceremony payload.
///
/// The payload never has to be valid: the freshness gate runs BEFORE the
/// ceremony is finished, so a 403 proves the gate fired and anything else
/// proves it did not — the request got far enough to fail on its own merits.
async fn finish_status(
    state: AppState<TestDb>,
    auth: &AuthConfig,
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
) -> (u16, String) {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(state))
            .app_data(web::Data::new(
                Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
            ))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;

    let token = mint_token(auth, user_id, tenant_id, org_id);
    let req = test::TestRequest::post()
        .uri("/api/v1/auth/webauthn/register/finish")
        .insert_header(("Authorization", format!("Bearer {token}")))
        // Without these the request is refused by CSRF middleware BEFORE the
        // handler runs, and every one of these tests would pass or fail on a
        // 403 that has nothing to do with MDS staleness.
        .cookie(actix_web::cookie::Cookie::new("axiam_csrf", CSRF_TOKEN))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "state_token": "not.a.token",
            "credential_name": "k",
            "response": {
                "id": "x", "rawId": "eA", "type": "public-key",
                "response": {"attestationObject": "eA", "clientDataJSON": "eA"},
                "extensions": {}
            }
        }))
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let body = String::from_utf8_lossy(&test::read_body(resp).await).into_owned();
    (status, body)
}

#[actix_rt::test]
async fn a_blob_staler_than_the_bound_denies_attested_registration() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("t").use_db("t").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "t153-deny").await;
    let auth = test_auth_config();

    let state = state_with_stale_blob(
        &db,
        tenant_id,
        &auth,
        /* max */ 7,
        /* age */ 30,
        AttestationMode::DirectRequired,
    )
    .await;
    let (status, body) = finish_status(state, &auth, user_id, tenant_id, org_id).await;
    assert_eq!(
        status, 403,
        "a BLOB 30 days past nextUpdate must be refused under a 7-day bound; got {body}"
    );
}

#[actix_rt::test]
async fn a_blob_within_the_bound_is_not_denied_for_staleness() {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("t").use_db("t").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "t153-fresh").await;
    let auth = test_auth_config();

    let state = state_with_stale_blob(
        &db,
        tenant_id,
        &auth,
        /* max */ 30,
        /* age */ 3,
        AttestationMode::DirectRequired,
    )
    .await;
    let (status, body) = finish_status(state, &auth, user_id, tenant_id, org_id).await;
    // 401 on the deliberately bogus state token is the PASS signal: the
    // freshness gate runs first, so reaching the ceremony at all proves it did
    // not fire. Asserting merely "not 403" would also pass on a CSRF rejection.
    assert_eq!(
        status, 401,
        "3 days past nextUpdate is inside a 30-day bound and must not be refused; got {body}"
    );
}

#[actix_rt::test]
async fn the_bound_is_off_by_default_however_stale_the_blob_is() {
    // The documented fail-open default. A FIDO Alliance outage must not brick
    // registration for deployments that never opted in.
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("t").use_db("t").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "t153-off").await;
    let auth = test_auth_config();

    let state = state_with_stale_blob(
        &db,
        tenant_id,
        &auth,
        /* max */ 0,
        /* age */ 3650,
        AttestationMode::DirectRequired,
    )
    .await;
    let (status, body) = finish_status(state, &auth, user_id, tenant_id, org_id).await;
    // 401 on the deliberately bogus state token is the PASS signal: the
    // freshness gate runs first, so reaching the ceremony at all proves it did
    // not fire. Asserting merely "not 403" would also pass on a CSRF rejection.
    assert_eq!(
        status, 401,
        "max_stale_days=0 must not deny, even on a ten-year-old BLOB; got {body}"
    );
}

#[actix_rt::test]
async fn an_unattested_policy_is_unaffected_by_a_stale_blob() {
    // Under AttestationMode::None no metadata is consulted, so stale metadata
    // cannot have misled the decision. Denying here would refuse a
    // registration for a reason that does not apply to it.
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("t").use_db("t").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let (org_id, tenant_id, user_id) = setup_tenant(&db, "t153-none").await;
    let auth = test_auth_config();

    let state = state_with_stale_blob(
        &db,
        tenant_id,
        &auth,
        /* max */ 1,
        /* age */ 3650,
        AttestationMode::None,
    )
    .await;
    let (status, body) = finish_status(state, &auth, user_id, tenant_id, org_id).await;
    // 401 on the deliberately bogus state token is the PASS signal: the
    // freshness gate runs first, so reaching the ceremony at all proves it did
    // not fire. Asserting merely "not 403" would also pass on a CSRF rejection.
    assert_eq!(
        status, 401,
        "an unattested ceremony must not be refused for metadata staleness; got {body}"
    );
}

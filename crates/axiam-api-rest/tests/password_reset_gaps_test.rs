//! Additional handler-level coverage for `src/handlers/password_reset.rs`
//! not exercised by the inline `#[cfg(test)]` unit tests (which only
//! simulate handler logic) or `tests/password_reset_revokes_sessions.rs`
//! (happy-path only): real HTTP round trips for the enumeration-safe
//! branches of `request_reset`, and the `confirm_reset` error branches
//! (unknown tenant, invalid/consumed token, weak new password).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{generate_refresh_token, hash_refresh_token};
use axiam_core::error::AxiamResult;
use axiam_core::models::mail::OutboundMailMessage;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::password_reset::CreatePasswordResetToken;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    MailPublisher, OrganizationRepository, PasswordResetTokenRepository, SettingsRepository,
    TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealPasswordResetTokenRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const TEST_PEER: &str = "127.0.0.1:12345";
const INITIAL_PASSWORD: &str = "InitialPassw0rdStrong"; // gitleaks:allow
const NEW_STRONG_PASSWORD: &str = "AnotherStr0ngPassword77"; // gitleaks:allow

type TestDb = surrealdb::engine::local::Db;

/// Generates a fresh Ed25519 JWT signing keypair at test runtime (no literal
/// key material in source — avoids new secret-scanner findings).
fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
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

struct Fixture {
    db: Surreal<TestDb>,
    #[allow(dead_code)]
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org_repo = SurrealOrganizationRepository::new(db.clone());
    let org = org_repo
        .create(CreateOrganization {
            name: "Reset Gaps Org".into(),
            slug: "reset-gaps-org".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    let tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            name: "Reset Gaps Tenant".into(),
            slug: "reset-gaps-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "reset-gaps-user".into(),
            email: "reset-gaps-user@example.com".into(),
            password: INITIAL_PASSWORD.into(),
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

    Fixture {
        db,
        org_id: org.id,
        tenant_id: tenant.id,
        user_id: user.id,
    }
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

/// Records every enqueued mail message for assertions.
#[derive(Clone, Default)]
struct RecordingPublisher {
    sent: Arc<Mutex<Vec<OutboundMailMessage>>>,
}

impl MailPublisher for RecordingPublisher {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        self.sent.lock().unwrap().push(msg);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// request_reset — enumeration-safe branches, real HTTP round trip
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn request_reset_unknown_email_returns_sent_true() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "email": "no-such-user@example.com",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));
    assert!(body.get("token").is_none());
}

#[actix_rt::test]
async fn request_reset_missing_tenant_context_returns_sent_true() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    // No tenant_id, no org_slug/tenant_slug — unresolvable, must still 200.
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({ "email": "reset-gaps-user@example.com" }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));
}

#[actix_rt::test]
async fn request_reset_via_org_and_tenant_slug_enqueues_mail() {
    let f = setup().await;
    let auth = test_auth_config();

    let recorder = RecordingPublisher::default();
    let sent_handle = recorder.sent.clone();
    let mut state = AppState::for_test(f.db.clone(), auth.clone());
    state.mail_outbound_publisher = Arc::new(recorder);

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

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({
            "email": "reset-gaps-user@example.com",
            "org_slug": "reset-gaps-org",
            "tenant_slug": "reset-gaps-tenant",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));

    let sent = sent_handle.lock().unwrap();
    assert_eq!(
        sent.len(),
        1,
        "org_slug/tenant_slug resolution must resolve the real tenant and enqueue a mail"
    );
    assert_eq!(sent[0].tenant_id, f.tenant_id);
}

// ---------------------------------------------------------------------------
// confirm_reset — error branches
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn confirm_reset_unknown_tenant_errors() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset/confirm")
        .set_json(json!({
            "tenant_id": Uuid::new_v4(),
            "token": "irrelevant-token",
            "new_password": NEW_STRONG_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 404);
}

#[actix_rt::test]
async fn confirm_reset_invalid_token_returns_400() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset/confirm")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "token": "never-issued-token",
            "new_password": NEW_STRONG_PASSWORD,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn confirm_reset_consumed_token_rejected_on_second_use() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let raw_token = generate_refresh_token();
    let token_hash = hash_refresh_token(&raw_token);
    SurrealPasswordResetTokenRepository::new(f.db.clone())
        .create(CreatePasswordResetToken {
            tenant_id: f.tenant_id,
            user_id: f.user_id,
            token_hash,
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let make_req = |password: &str| {
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/reset/confirm")
            .set_json(json!({
                "tenant_id": f.tenant_id,
                "token": raw_token,
                "new_password": password,
            }))
            .to_request()
    };

    let first = test::call_service(&app, make_req(NEW_STRONG_PASSWORD)).await;
    assert_eq!(first.status().as_u16(), 200);

    // Re-using the same (now-consumed) token must be rejected.
    let second = test::call_service(&app, make_req("YetAnotherStr0ngPass88")).await;
    assert_eq!(second.status().as_u16(), 400);
}

#[actix_rt::test]
async fn confirm_reset_weak_password_returns_400() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let raw_token = generate_refresh_token();
    let token_hash = hash_refresh_token(&raw_token);
    SurrealPasswordResetTokenRepository::new(f.db.clone())
        .create(CreatePasswordResetToken {
            tenant_id: f.tenant_id,
            user_id: f.user_id,
            token_hash,
            expires_at: Utc::now() + Duration::hours(1),
        })
        .await
        .unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset/confirm")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "token": raw_token,
            "new_password": "short",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    // A password-policy violation surfaces as AxiamError::Validation (400),
    // per the handler's own doc comment — not AxiamError::PasswordPolicy (422).
    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// R4: request_reset — RateLimited-swallow branch (real service call, not the
// inline `#[cfg(test)]` unit tests which only simulate the match arms) and
// mail-publish-failure branch via a real HTTP round trip.
// ---------------------------------------------------------------------------

/// Mail publisher that always fails — proves `request_reset` swallows a
/// publish error and still returns the uniform `{"sent": true}` (D-15),
/// exercised through the real HTTP handler rather than the file's own
/// `#[cfg(test)]` simulated-branch unit tests.
#[derive(Clone, Default)]
struct FailingPublisher;

impl MailPublisher for FailingPublisher {
    async fn publish(&self, _msg: OutboundMailMessage) -> AxiamResult<()> {
        Err(axiam_core::error::AxiamError::Internal(
            "mock publish failure".into(),
        ))
    }
}

#[actix_rt::test]
async fn request_reset_mail_publish_failure_still_returns_sent_true() {
    let f = setup().await;
    let auth = test_auth_config();

    let mut state = AppState::for_test(f.db.clone(), auth.clone());
    state.mail_outbound_publisher = Arc::new(FailingPublisher);

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

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "email": "reset-gaps-user@example.com",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["sent"], true,
        "a mail-publish failure must still funnel into the uniform sent:true response (D-15)"
    );
}

/// After a successful `initiate_reset` (user found, mail enqueued), the
/// handler resolves `org_id` for the mail message via a SEPARATE
/// `tenant_repo.get_by_id` lookup. Deleting the tenant row between user
/// creation and the request (SurrealDB has no FK enforcement, so the user
/// row survives) makes that second lookup fail while `initiate_reset`
/// itself still succeeds (it only queries the user table) — proving the
/// `Err(e) => { warn!(...); Uuid::nil() }` fallback branch is taken and the
/// response is still the uniform `{"sent": true}` (D-15), never a 500.
#[actix_rt::test]
async fn request_reset_org_id_resolution_failure_still_returns_sent_true() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    SurrealTenantRepository::new(f.db.clone())
        .delete(f.tenant_id)
        .await
        .unwrap();

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "email": "reset-gaps-user@example.com",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(
        body["sent"], true,
        "org_id resolution failure must still funnel into sent:true (D-15), not a 500"
    );
}

/// `request_reset`'s D-15 swallow only covers `Ok(None)`, `Ok(Some(..))`,
/// and `Err(RateLimited)` — any OTHER service error must still propagate as
/// a real error response via `Err(e) => return Err(e.into())`, not be
/// silently absorbed. A `Surreal` handle with no namespace/database
/// selected makes every repository call fail with a generic (non-NotFound)
/// error, forcing `initiate_reset`'s `user_repo.get_by_email` to hit that
/// exact fallthrough (a raw `tenant_id` is supplied so tenant resolution
/// itself never touches the DB and short-circuits to `Some(id)` first).
#[actix_rt::test]
async fn request_reset_propagates_non_ratelimited_service_error() {
    let auth = test_auth_config();
    let broken_db = Surreal::new::<Mem>(()).await.unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(AppState::for_test(
                broken_db,
                auth.clone(),
            )))
            .app_data(web::Data::new(
                Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
            ))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({
            "tenant_id": Uuid::new_v4(),
            "email": "whoever@example.com",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        500,
        "a non-RateLimited service error must propagate as a real error, not be swallowed into sent:true"
    );
}

/// After `MAX_RESETS_PER_DAY` (3) successful requests for the SAME user, a
/// further request must be swallowed into the SAME `{"sent": true}` response
/// (D-15 — a distinct 429 would let an attacker enumerate valid accounts by
/// timing when the per-user limit trips). Uses a permissive per-IP
/// `RateLimitConfig` override so the assertion actually reaches the
/// per-user service-level limit instead of being pre-empted by the
/// route's own IP-based governor (default `password_reset_per_min: 3`
/// would otherwise 429 the 4th request before the handler ever runs).
#[actix_rt::test]
async fn request_reset_rate_limited_after_max_per_day_still_returns_sent_true() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(AppState::for_test(
                f.db.clone(),
                auth.clone(),
            )))
            .app_data(web::Data::new(
                Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
            ))
            .configure(|cfg| {
                register_api_v1_routes::<TestDb>(
                    cfg,
                    &RateLimitConfig {
                        password_reset_per_min: 100,
                        ..RateLimitConfig::default()
                    },
                )
            }),
    )
    .await;

    let make_req = || {
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/reset")
            .set_json(json!({
                "tenant_id": f.tenant_id,
                "email": "reset-gaps-user@example.com",
            }))
            .to_request()
    };

    // First 3 requests consume the per-user daily allowance (MAX_RESETS_PER_DAY).
    for i in 0..3 {
        let resp = test::call_service(&app, make_req()).await;
        assert_eq!(resp.status().as_u16(), 200, "request #{i} must return 200");
        let body: Value = test::read_body_json(resp).await;
        assert_eq!(body["sent"], true);
    }

    // 4th request exceeds MAX_RESETS_PER_DAY -> service returns
    // Err(RateLimited), which the handler must swallow into the SAME
    // uniform 200 {"sent": true} (D-15), not a 429/500.
    let resp = test::call_service(&app, make_req()).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a per-user rate-limited request must still return 200 (D-15 swallow)"
    );
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], true);
    assert!(body.get("token").is_none());
}

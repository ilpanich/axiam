//! Handler-level integration tests for `src/handlers/email_verification.rs`,
//! driven through the real actix routes (`/api/v1/auth/verify-email` and
//! `/api/v1/auth/resend-verification`). The existing inline
//! `#[cfg(test)]` module in the handler file only simulates the logic;
//! there was previously no full HTTP-level test file for this handler at
//! all.

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
use axiam_core::models::email_verification::CreateEmailVerificationToken;
use axiam_core::models::mail::OutboundMailMessage;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::CreateTenant;
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    EmailVerificationTokenRepository, MailPublisher, OrganizationRepository, TenantRepository,
    UserRepository,
};
use axiam_db::repository::{
    SurrealEmailVerificationTokenRepository, SurrealOrganizationRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

const TEST_PEER: &str = "127.0.0.1:12345";
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
/// Arbitrary CSRF token for the double-submit check (SEC-046). Neither
/// `/auth/verify-email` nor `/auth/resend-verification` is in the CSRF
/// exempt-suffix list, so every POST here needs a matching cookie + header.
const CSRF_TOKEN: &str = "test-csrf-token";

/// Attach a matching CSRF cookie + header to a POST/PUT/DELETE request.
fn with_csrf(rb: test::TestRequest) -> test::TestRequest {
    rb.insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
}

type TestDb = surrealdb::engine::local::Db;

fn test_auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
            "-----END PRIVATE KEY-----"
        )
        .into(),
        jwt_public_key_pem: concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
            "-----END PUBLIC KEY-----"
        )
        .into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    tenant_id: Uuid,
    /// PendingVerification (the default status on creation).
    pending_user_id: Uuid,
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Verify Org".into(),
            slug: "verify-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            name: "Verify Tenant".into(),
            slug: "verify-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "pending-user".into(),
            email: "pending-user@example.com".into(),
            password: TEST_PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    // Newly-created users default to PendingVerification — no explicit
    // status transition needed here.

    Fixture {
        db,
        tenant_id: tenant.id,
        pending_user_id: user.id,
    }
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test($db.clone(), $auth.clone())))
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
// verify_email
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn verify_email_invalid_token_returns_400() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = with_csrf(test::TestRequest::post())
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/verify-email")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "token": "never-issued-token",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

#[actix_rt::test]
async fn verify_email_success_then_replay_is_rejected() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let raw_token = generate_refresh_token();
    let token_hash = hash_refresh_token(&raw_token);
    SurrealEmailVerificationTokenRepository::new(f.db.clone())
        .create(CreateEmailVerificationToken {
            tenant_id: f.tenant_id,
            user_id: f.pending_user_id,
            token_hash,
            expires_at: Utc::now() + Duration::hours(24),
        })
        .await
        .unwrap();

    let make_req = || {
        with_csrf(test::TestRequest::post())
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri("/api/v1/auth/verify-email")
            .set_json(json!({
                "tenant_id": f.tenant_id,
                "token": raw_token,
            }))
            .to_request()
    };

    let first = test::call_service(&app, make_req()).await;
    assert_eq!(first.status().as_u16(), 200);
    let body: Value = test::read_body_json(first).await;
    assert_eq!(body["verified"], json!(true));

    // The user should now be Active — check via a real repository read,
    // proving the status transition actually happened (not just a 200).
    let updated = SurrealUserRepository::new(f.db.clone())
        .get_by_id(f.tenant_id, f.pending_user_id)
        .await
        .unwrap();
    assert_eq!(updated.status, UserStatus::Active);
    assert!(updated.email_verified_at.is_some());

    // Replaying the same (now-consumed) token must be rejected.
    let second = test::call_service(&app, make_req()).await;
    assert_eq!(second.status().as_u16(), 400);
}

#[actix_rt::test]
async fn verify_email_already_verified_user_returns_400() {
    let f = setup().await;
    // Mark the user already verified + Active up front.
    SurrealUserRepository::new(f.db.clone())
        .update(
            f.tenant_id,
            f.pending_user_id,
            UpdateUser {
                status: Some(UserStatus::Active),
                email_verified_at: Some(Some(Utc::now())),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let raw_token = generate_refresh_token();
    let token_hash = hash_refresh_token(&raw_token);
    SurrealEmailVerificationTokenRepository::new(f.db.clone())
        .create(CreateEmailVerificationToken {
            tenant_id: f.tenant_id,
            user_id: f.pending_user_id,
            token_hash,
            expires_at: Utc::now() + Duration::hours(24),
        })
        .await
        .unwrap();

    let req = with_csrf(test::TestRequest::post())
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/verify-email")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "token": raw_token,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 400);
}

// ---------------------------------------------------------------------------
// resend_verification
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn resend_verification_unknown_email_returns_sent_true() {
    let f = setup().await;
    let auth = test_auth_config();
    let app = test_app!(f.db, auth);

    let req = with_csrf(test::TestRequest::post())
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/resend-verification")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "email": "no-such-address@example.com",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));
    assert!(body.get("token").is_none());
}

#[actix_rt::test]
async fn resend_verification_pending_user_enqueues_mail() {
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

    let req = with_csrf(test::TestRequest::post())
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/resend-verification")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "email": "pending-user@example.com",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));
    assert!(body.get("token").is_none());

    let sent = sent_handle.lock().unwrap();
    assert_eq!(
        sent.len(),
        1,
        "a PendingVerification user's resend request must enqueue exactly one mail"
    );
    assert_eq!(sent[0].tenant_id, f.tenant_id);
    assert_eq!(sent[0].user_id, f.pending_user_id);
}

#[actix_rt::test]
async fn resend_verification_already_active_user_sends_without_enqueue() {
    let f = setup().await;
    SurrealUserRepository::new(f.db.clone())
        .update(
            f.tenant_id,
            f.pending_user_id,
            UpdateUser {
                status: Some(UserStatus::Active),
                email_verified_at: Some(Some(Utc::now())),
                ..Default::default()
            },
        )
        .await
        .unwrap();

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

    let req = with_csrf(test::TestRequest::post())
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/resend-verification")
        .set_json(json!({
            "tenant_id": f.tenant_id,
            "email": "pending-user@example.com",
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));

    let sent = sent_handle.lock().unwrap();
    assert!(
        sent.is_empty(),
        "an already-Active user must not trigger a new verification mail"
    );
}

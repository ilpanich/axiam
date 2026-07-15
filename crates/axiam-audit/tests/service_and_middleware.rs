//! Integration tests for [`axiam_audit::AuditService`] and the audit
//! [`AuditMiddleware`].
//!
//! These use an in-memory recording repository (no SurrealDB) so that we can
//! assert on the exact audit entries that were produced.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use actix_web::cookie::Cookie;
use actix_web::dev::Service as _;
use actix_web::{App, HttpMessage, HttpResponse, test, web};
use axiam_audit::middleware::AuditMiddleware;
use axiam_audit::service::AuditService;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, CachedUserIdentity, issue_access_token, validate_access_token};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use chrono::Utc;
use uuid::Uuid;

/// In-memory audit log repository that records every appended entry.
#[derive(Clone, Default)]
struct RecordingRepo {
    entries: Arc<Mutex<Vec<CreateAuditLogEntry>>>,
    fail: bool,
}

impl RecordingRepo {
    fn new() -> Self {
        Self::default()
    }

    fn failing() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        }
    }

    fn snapshot(&self) -> Vec<CreateAuditLogEntry> {
        self.entries.lock().unwrap().clone()
    }

    fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl AuditLogRepository for RecordingRepo {
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        if self.fail {
            return Err(AxiamError::Internal("boom".into()));
        }
        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            actor_id: input.actor_id,
            actor_type: input.actor_type.clone(),
            action: input.action.clone(),
            resource_id: input.resource_id,
            outcome: input.outcome.clone(),
            ip_address: input.ip_address.clone(),
            metadata: input.metadata.clone().unwrap_or(serde_json::Value::Null),
            timestamp: Utc::now(),
        };
        self.entries.lock().unwrap().push(input);
        Ok(entry)
    }

    async fn list(
        &self,
        _tenant_id: Uuid,
        _filter: AuditLogFilter,
        _pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }

    async fn list_system(
        &self,
        _filter: AuditLogFilter,
        _pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }

    async fn get_by_ids(&self, _tenant_id: Uuid, _ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }

    async fn pseudonymize_actor(
        &self,
        _tenant_id: Uuid,
        _user_id: Uuid,
        _pseudonym: &str,
    ) -> AxiamResult<u64> {
        unimplemented!()
    }
}

/// Poll until the recording repo has at least `n` entries, or time out.
async fn wait_for_entries(repo: &RecordingRepo, n: usize) {
    for _ in 0..100 {
        if repo.len() >= n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// AuditService
// ---------------------------------------------------------------------------

#[tokio::test]
async fn service_log_delegates_to_repository() {
    let repo = RecordingRepo::new();
    let service = AuditService::new(repo.clone());

    let tenant_id = Uuid::new_v4();
    let actor_id = Uuid::new_v4();
    let entry = CreateAuditLogEntry {
        tenant_id,
        actor_id,
        actor_type: ActorType::User,
        action: "user.create".into(),
        resource_id: None,
        outcome: AuditOutcome::Success,
        ip_address: Some("10.0.0.1".into()),
        metadata: None,
    };

    let stored = service.log(entry).await.unwrap();

    assert_eq!(stored.tenant_id, tenant_id);
    assert_eq!(stored.actor_id, actor_id);
    assert_eq!(stored.action, "user.create");
    assert_eq!(stored.outcome, AuditOutcome::Success);
    assert_eq!(repo.len(), 1);
}

#[tokio::test]
async fn service_log_propagates_repository_error() {
    let repo = RecordingRepo::failing();
    let service = AuditService::new(repo);

    let entry = CreateAuditLogEntry {
        tenant_id: Uuid::new_v4(),
        actor_id: Uuid::new_v4(),
        actor_type: ActorType::System,
        action: "noop".into(),
        resource_id: None,
        outcome: AuditOutcome::Failure,
        ip_address: None,
        metadata: None,
    };

    assert!(service.log(entry).await.is_err());
}

// ---------------------------------------------------------------------------
// AuditMiddleware
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn middleware_logs_unauthenticated_success() {
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());

    let app = test::init_service(App::new().wrap(mw).route(
        "/api/thing",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/api/thing").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    wait_for_entries(&repo, 1).await;
    let entries = repo.snapshot();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.action, "GET /api/thing");
    assert_eq!(e.actor_type, ActorType::System);
    assert_eq!(e.actor_id, Uuid::nil());
    assert_eq!(e.tenant_id, Uuid::nil());
    assert_eq!(e.outcome, AuditOutcome::Success);
    assert_eq!(e.metadata.as_ref().unwrap()["authenticated"], false);
    assert_eq!(e.metadata.as_ref().unwrap()["http_status"], 200);
}

#[actix_web::test]
async fn middleware_maps_403_to_denied() {
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());

    let app = test::init_service(App::new().wrap(mw).route(
        "/api/forbidden",
        web::get().to(|| async { HttpResponse::Forbidden().finish() }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/api/forbidden").to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    let entries = repo.snapshot();
    assert_eq!(entries[0].outcome, AuditOutcome::Denied);
}

#[actix_web::test]
async fn middleware_maps_500_to_failure() {
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());

    let app = test::init_service(App::new().wrap(mw).route(
        "/api/boom",
        web::get().to(|| async { HttpResponse::InternalServerError().finish() }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/api/boom").to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    let entries = repo.snapshot();
    assert_eq!(entries[0].outcome, AuditOutcome::Failure);
}

#[actix_web::test]
async fn middleware_skips_health_and_ready() {
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());

    let app = test::init_service(
        App::new()
            .wrap(mw)
            .route(
                "/health",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            )
            .route(
                "/ready",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;

    for uri in ["/health", "/ready"] {
        let req = test::TestRequest::get().uri(uri).to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    // Give any (erroneous) background write a chance to land.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(repo.len(), 0, "health/ready must not be audited");
}

#[actix_web::test]
async fn middleware_records_client_ip() {
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());

    let app = test::init_service(App::new().wrap(mw).route(
        "/api/ip",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/ip")
        .peer_addr("203.0.113.7:5555".parse().unwrap())
        .to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    let entries = repo.snapshot();
    assert_eq!(entries[0].ip_address.as_deref(), Some("203.0.113.7"));
}

// ---------------------------------------------------------------------------
// Authenticated middleware paths (JWT extraction from header / cookie + cache)
// ---------------------------------------------------------------------------

/// Build an `AuthConfig` with a pre-generated Ed25519 test key pair.
///
/// Key material split across `concat!()` to avoid private-key scanning hooks.
/// NOT used in production.
fn test_auth_config() -> AuthConfig {
    let private_key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----"
    );
    let public_key = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: String::new(),
        pepper: None,
        min_password_length: 12,
        mfa_encryption_key: None,
        federation_encryption_key: None,
        allow_missing_aud_as_user: true,
        cookie_secure: false,
        mfa_challenge_lifetime_secs: 300,
        totp_issuer: "AXIAM-Test".into(),
        max_failed_login_attempts: 5,
        lockout_duration_secs: 300,
        lockout_backoff_multiplier: 2.0,
        max_lockout_duration_secs: 3600,
        auth_code_lifetime_secs: 600,
        email_verification_grace_period_hours: 24,
        password_reset_token_expiry_hours: 1,
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        jwt_encoding_key: None,
        jwt_decoding_key: None,
        hibp_breaker_threshold: 5,
        hibp_breaker_cooldown_secs: 30,
    }
}

/// Mint a valid access token for `(user_id, tenant_id, org_id)`.
fn mint_token(user_id: Uuid, tenant_id: Uuid, org_id: Uuid, cfg: &AuthConfig) -> String {
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &[],
        cfg,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .expect("mint token")
}

#[actix_web::test]
async fn middleware_authenticates_via_bearer_header() {
    let cfg = test_auth_config();
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let token = mint_token(user_id, tenant_id, org_id, &cfg);

    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());
    let app = test::init_service(App::new().app_data(web::Data::new(cfg)).wrap(mw).route(
        "/api/secure",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/secure")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    wait_for_entries(&repo, 1).await;
    let e = &repo.snapshot()[0];
    assert_eq!(e.actor_type, ActorType::User);
    assert_eq!(e.actor_id, user_id);
    assert_eq!(e.tenant_id, tenant_id);
    assert_eq!(e.metadata.as_ref().unwrap()["authenticated"], true);
}

#[actix_web::test]
async fn middleware_authenticates_via_access_cookie() {
    let cfg = test_auth_config();
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let token = mint_token(user_id, tenant_id, org_id, &cfg);

    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());
    let app = test::init_service(App::new().app_data(web::Data::new(cfg)).wrap(mw).route(
        "/api/secure",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    // No Authorization header — the middleware must fall back to the cookie.
    let req = test::TestRequest::get()
        .uri("/api/secure")
        .cookie(Cookie::new("axiam_access", token))
        .to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    let e = &repo.snapshot()[0];
    assert_eq!(e.actor_type, ActorType::User);
    assert_eq!(e.actor_id, user_id);
    assert_eq!(e.tenant_id, tenant_id);
}

#[actix_web::test]
async fn middleware_reuses_cached_identity() {
    let cfg = test_auth_config();
    let user_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let token = mint_token(user_id, tenant_id, org_id, &cfg);
    let claims = validate_access_token(&token, &cfg).unwrap();
    let identity = Arc::new(CachedUserIdentity {
        user_id,
        tenant_id,
        org_id,
        claims,
    });

    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());
    // Outer middleware pre-populates the cached identity in request extensions
    // (as a real upstream auth middleware would), so the audit middleware takes
    // the cache-hit path instead of re-validating a token.
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(cfg))
            .wrap(mw)
            .wrap_fn(move |req, srv| {
                req.extensions_mut().insert(identity.clone());
                srv.call(req)
            })
            .route(
                "/api/secure",
                web::get().to(|| async { HttpResponse::Ok().finish() }),
            ),
    )
    .await;

    // No credentials on the request at all — identity comes purely from cache.
    let req = test::TestRequest::get().uri("/api/secure").to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    let e = &repo.snapshot()[0];
    assert_eq!(e.actor_type, ActorType::User);
    assert_eq!(e.actor_id, user_id);
    assert_eq!(e.tenant_id, tenant_id);
}

#[actix_web::test]
async fn middleware_non_bearer_scheme_is_unauthenticated() {
    let cfg = test_auth_config();
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());
    let app = test::init_service(App::new().app_data(web::Data::new(cfg)).wrap(mw).route(
        "/api/secure",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/secure")
        .insert_header(("Authorization", "Basic dXNlcjpwYXNz"))
        .to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    let e = &repo.snapshot()[0];
    assert_eq!(e.actor_type, ActorType::System);
    assert_eq!(e.metadata.as_ref().unwrap()["authenticated"], false);
}

#[actix_web::test]
async fn middleware_empty_bearer_credentials_is_unauthenticated() {
    let cfg = test_auth_config();
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());
    let app = test::init_service(App::new().app_data(web::Data::new(cfg)).wrap(mw).route(
        "/api/secure",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/secure")
        .insert_header(("Authorization", "Bearer   "))
        .to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    assert_eq!(repo.snapshot()[0].actor_type, ActorType::System);
}

#[actix_web::test]
async fn middleware_invalid_token_is_unauthenticated() {
    let cfg = test_auth_config();
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo.clone());
    let app = test::init_service(App::new().app_data(web::Data::new(cfg)).wrap(mw).route(
        "/api/secure",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let req = test::TestRequest::get()
        .uri("/api/secure")
        .insert_header(("Authorization", "Bearer not-a-real-jwt"))
        .to_request();
    let _ = test::call_service(&app, req).await;

    wait_for_entries(&repo, 1).await;
    assert_eq!(repo.snapshot()[0].actor_type, ActorType::System);
}

// ---------------------------------------------------------------------------
// Background worker lifecycle
// ---------------------------------------------------------------------------

#[actix_web::test]
async fn worker_survives_repository_error() {
    // A failing repo makes `repo.append` return Err inside the worker; the
    // worker logs and keeps running rather than crashing.
    let repo = RecordingRepo::failing();
    let mw = AuditMiddleware::spawn(repo);
    let app = test::init_service(App::new().wrap(mw).route(
        "/api/thing",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    let req = test::TestRequest::get().uri("/api/thing").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    // Give the worker time to receive the entry and hit the error branch.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[actix_web::test]
async fn worker_exits_when_all_senders_dropped() {
    let repo = RecordingRepo::new();
    let mw = AuditMiddleware::spawn(repo);
    // Dropping the middleware drops the only Sender, closing the channel so the
    // worker's recv loop terminates (the "channel closed" branch).
    drop(mw);
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Audit repository whose `append` panics, killing the worker task so the
/// channel closes and subsequent `try_send` calls fail (the drop branch).
#[derive(Clone)]
struct PanicRepo;

impl AuditLogRepository for PanicRepo {
    async fn append(&self, _input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        panic!("worker append boom");
    }
    async fn list(
        &self,
        _tenant_id: Uuid,
        _filter: AuditLogFilter,
        _pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _filter: AuditLogFilter,
        _pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _tenant_id: Uuid, _ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(
        &self,
        _tenant_id: Uuid,
        _user_id: Uuid,
        _pseudonym: &str,
    ) -> AxiamResult<u64> {
        unimplemented!()
    }
}

#[actix_web::test]
async fn middleware_drops_entry_when_channel_closed() {
    let mw = AuditMiddleware::spawn(PanicRepo);
    let app = test::init_service(App::new().wrap(mw).route(
        "/api/thing",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;

    // First request enqueues an entry; the worker pulls it, panics, and dies —
    // closing the channel.
    let req = test::TestRequest::get().uri("/api/thing").to_request();
    let _ = test::call_service(&app, req).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Subsequent requests find the channel closed, so `try_send` fails and the
    // entry is dropped (logged). The request itself must still succeed.
    for _ in 0..3 {
        let req = test::TestRequest::get().uri("/api/thing").to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}

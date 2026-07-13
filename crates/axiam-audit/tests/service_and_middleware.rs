//! Integration tests for [`axiam_audit::AuditService`] and the audit
//! [`AuditMiddleware`].
//!
//! These use an in-memory recording repository (no SurrealDB) so that we can
//! assert on the exact audit entries that were produced.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use actix_web::{App, HttpResponse, test, web};
use axiam_audit::middleware::AuditMiddleware;
use axiam_audit::service::AuditService;
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

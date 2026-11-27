//! The request-audit worker writes a backlog several rows to a round trip
//! (`AuditLogRepository::append_many`) — and loses nothing it did not lose
//! before: rows are written in the order the requests finished, a lone row is
//! written alone and at once, a row the store refuses is counted and
//! dead-lettered on its own, and `drain` still waits for every row queued
//! before it.
//!
//! The datastore is a test double that records every call, so the tests assert
//! how many round trips the worker made, not how long they took.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use actix_web::{App, HttpResponse, test, web};
use axiam_audit::DeadLetterWriter;
use axiam_audit::dead_letter::decode_line;
use axiam_audit::middleware::{AuditMiddleware, MAX_APPEND_BATCH};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{AuditLogEntry, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, PaginatedResult, Pagination};
use chrono::Utc;
use tokio::sync::watch;
use uuid::Uuid;

/// Records every row it writes, and the size of every `append_many` call.
/// Refuses any row whose action contains `poison`. Holds every call until
/// `open` is `true`, so a test can build a backlog behind the first one.
#[derive(Clone)]
struct Store {
    written: Arc<Mutex<Vec<String>>>,
    calls: Arc<Mutex<Vec<usize>>>,
    open: watch::Receiver<bool>,
}

impl Store {
    fn new(open: watch::Receiver<bool>) -> Self {
        Self {
            written: Arc::default(),
            calls: Arc::default(),
            open,
        }
    }
    fn written(&self) -> Vec<String> {
        self.written.lock().unwrap().clone()
    }
    fn calls(&self) -> Vec<usize> {
        self.calls.lock().unwrap().clone()
    }
    fn write(&self, input: &CreateAuditLogEntry) -> AxiamResult<()> {
        if input.action.contains("poison") {
            return Err(AxiamError::Database("refused by the schema".into()));
        }
        self.written.lock().unwrap().push(input.action.clone());
        Ok(())
    }
}

impl AuditLogRepository for Store {
    async fn datastore_now(&self) -> AxiamResult<chrono::DateTime<Utc>> {
        Ok(Utc::now())
    }
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        let _ = self.open.clone().wait_for(|o| *o).await;
        self.calls.lock().unwrap().push(1);
        self.write(&input)?;
        Ok(AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            actor_id: input.actor_id,
            actor_type: input.actor_type,
            action: input.action,
            resource_id: input.resource_id,
            outcome: input.outcome,
            ip_address: input.ip_address,
            metadata: input.metadata.unwrap_or(serde_json::Value::Null),
            timestamp: Utc::now(),
            organization_id: input.organization_id,
        })
    }
    async fn append_many(&self, inputs: Vec<CreateAuditLogEntry>) -> Vec<AxiamResult<()>> {
        let _ = self.open.clone().wait_for(|o| *o).await;
        self.calls.lock().unwrap().push(inputs.len());
        inputs.iter().map(|i| self.write(i)).collect()
    }
    async fn list(
        &self,
        _: Uuid,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _: Uuid,
        _: AuditLogFilter,
        _: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _: Uuid, _: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(&self, _: Uuid, _: Uuid, _: &str) -> AxiamResult<u64> {
        unimplemented!()
    }
    async fn prune_older_than(&self, _: chrono::DateTime<Utc>) -> AxiamResult<u64> {
        unimplemented!()
    }
}

/// `GET /r/<name>` once per name, in order, through the middleware.
async fn requests(mw: &AuditMiddleware, names: &[String]) {
    let app = test::init_service(App::new().wrap(mw.clone()).route(
        "/r/{name}",
        web::get().to(|| async { HttpResponse::Ok().finish() }),
    ))
    .await;
    for name in names {
        let req = test::TestRequest::get()
            .uri(&format!("/r/{name}"))
            .to_request();
        assert!(test::call_service(&app, req).await.status().is_success());
    }
}

fn names(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("row-{i:04}")).collect()
}

fn actions(names: &[String]) -> Vec<String> {
    names.iter().map(|n| format!("GET /r/{n}")).collect()
}

#[actix_web::test]
async fn a_backlog_is_written_in_batches_and_in_request_order() {
    let (release, open) = watch::channel(false);
    let store = Store::new(open);
    let mw =
        AuditMiddleware::spawn_configured(store.clone(), None, DeadLetterWriter::disabled(), 4096);

    // The first row's append is held, so the other 299 queue behind it.
    let names = names(300);
    requests(&mw, &names).await;
    release.send(true).unwrap();
    assert!(mw.drain(Duration::from_secs(10)).await);

    assert_eq!(
        store.written(),
        actions(&names),
        "every row, in request order"
    );
    let calls = store.calls();
    assert!(
        calls.iter().all(|&n| n <= MAX_APPEND_BATCH),
        "no batch over {MAX_APPEND_BATCH}: {calls:?}"
    );
    // The worker holds whatever it took before the store blocked (at least
    // one row), then writes the rest in full batches: never more round trips
    // than one plus 299 rows' worth of batches, never fewer than 300 rows'.
    let most = 1 + 299_usize.div_ceil(MAX_APPEND_BATCH);
    let least = 300_usize.div_ceil(MAX_APPEND_BATCH);
    assert!(
        (least..=most).contains(&calls.len()),
        "300 rows in {least}..={most} round trips, not 300: {calls:?}"
    );
    let s = mw.loss().snapshot();
    assert_eq!((s.dropped, s.failed), (0, 0));
}

#[actix_web::test]
async fn a_lone_row_is_written_alone_and_without_waiting_for_company() {
    let (_release, open) = watch::channel(true);
    let store = Store::new(open);
    let mw =
        AuditMiddleware::spawn_configured(store.clone(), None, DeadLetterWriter::disabled(), 4096);

    let names = names(3);
    for name in &names {
        requests(&mw, std::slice::from_ref(name)).await;
        // Written before the next request, with no batching delay to wait out.
        let expected = actions(std::slice::from_ref(name));
        for _ in 0..200 {
            if store.written().ends_with(&expected) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(store.written().ends_with(&expected));
    }
    assert_eq!(store.calls(), vec![1, 1, 1]);
}

#[actix_web::test]
async fn a_refused_row_in_a_batch_is_dead_lettered_alone() {
    let path: PathBuf =
        std::env::temp_dir().join(format!("axiam-audit-batch-dlq-{}.jsonl", Uuid::new_v4()));
    let (release, open) = watch::channel(false);
    let store = Store::new(open);
    let mw = AuditMiddleware::spawn_configured(
        store.clone(),
        None,
        DeadLetterWriter::spawn(&path),
        4096,
    );

    let mut names = names(40);
    names[17] = "poison-a".into();
    names[31] = "poison-b".into();
    requests(&mw, &names).await;
    release.send(true).unwrap();
    assert!(mw.drain(Duration::from_secs(10)).await);

    let good: Vec<String> = actions(&names)
        .into_iter()
        .filter(|a| !a.contains("poison"))
        .collect();
    assert_eq!(
        store.written(),
        good,
        "every other row is written, in order"
    );
    assert!(store.calls().len() < names.len(), "and in batches");

    let s = mw.loss().snapshot();
    assert_eq!(s.failed, 2, "exactly the two refused rows are lost");
    assert_eq!(s.dropped, 0);
    let dead: Vec<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .map(|l| decode_line(l).unwrap().entry.action)
        .collect();
    assert_eq!(dead, vec!["GET /r/poison-a", "GET /r/poison-b"]);
    let _ = std::fs::remove_file(&path);
}

#[actix_web::test]
async fn drain_waits_for_every_row_queued_before_it() {
    let (release, open) = watch::channel(false);
    let store = Store::new(open);
    let mw =
        AuditMiddleware::spawn_configured(store.clone(), None, DeadLetterWriter::disabled(), 4096);

    let names = names(150);
    requests(&mw, &names).await;
    // Not yet released: drain cannot have reached its barrier.
    assert!(!mw.drain(Duration::from_millis(100)).await);
    release.send(true).unwrap();
    assert!(mw.drain(Duration::from_secs(10)).await);
    assert_eq!(store.written(), actions(&names));
}

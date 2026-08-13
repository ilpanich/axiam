//! Integration tests for the MDS ingestion orchestrator (`axiam_db::mds_ingest`,
//! X3 wave 2, D4 step 8 applied to storage). Covers all four
//! `MdsIngestOutcome` variants against an in-memory `MdsRepository`.

use axiam_core::models::mds::{MdsBlobMeta, MdsEntry};
use axiam_core::repository::MdsRepository;
use axiam_db::mds_ingest::{MdsIngestOutcome, ingest_blob};
use axiam_db::repository::SurrealMdsRepository;
use axiam_pki::mds::MdsBlob;
use chrono::{NaiveDate, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

async fn setup() -> Surreal<surrealdb::engine::local::Db> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn entry(aaguid: Uuid) -> MdsEntry {
    MdsEntry {
        aaguid,
        description: Some("Test".into()),
        attestation_root_certificates: vec![],
        status_reports: vec![],
        time_of_last_status_change: None,
    }
}

fn blob(no: i64, entries: Vec<MdsEntry>) -> MdsBlob {
    MdsBlob {
        meta: MdsBlobMeta {
            no,
            next_update: NaiveDate::from_ymd_opt(2026, 12, 31).unwrap(),
            entry_count: entries.len() as u64,
            last_refreshed_at: Utc::now(),
            stale: false,
        },
        entries,
    }
}

#[tokio::test]
async fn first_ingestion_is_initial() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let id = Uuid::new_v4();

    let outcome = ingest_blob(&repo, blob(100, vec![entry(id)]))
        .await
        .unwrap();
    assert_eq!(
        outcome,
        MdsIngestOutcome::Initial {
            no: 100,
            entry_count: 1
        }
    );
    assert!(repo.get_by_aaguid(id).await.unwrap().is_some());
    assert_eq!(repo.get_meta().await.unwrap().unwrap().no, 100);
}

#[tokio::test]
async fn newer_no_replaces() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();

    ingest_blob(&repo, blob(100, vec![entry(first)]))
        .await
        .unwrap();
    let outcome = ingest_blob(&repo, blob(101, vec![entry(second)]))
        .await
        .unwrap();

    assert_eq!(
        outcome,
        MdsIngestOutcome::Replaced {
            no: 101,
            entry_count: 1
        }
    );
    assert!(
        repo.get_by_aaguid(first).await.unwrap().is_none(),
        "the old entry set must be gone after a replace"
    );
    assert!(repo.get_by_aaguid(second).await.unwrap().is_some());
}

#[tokio::test]
async fn equal_no_is_a_noop_refresh() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let id = Uuid::new_v4();

    ingest_blob(&repo, blob(100, vec![entry(id)]))
        .await
        .unwrap();
    let before = repo.get_meta().await.unwrap().unwrap();

    // Same `no`, but a DIFFERENT entry set — if this were mistakenly treated
    // as a replace, the entries would change; a no-op refresh must leave them
    // exactly as they were.
    let other_id = Uuid::new_v4();
    let outcome = ingest_blob(&repo, blob(100, vec![entry(other_id)]))
        .await
        .unwrap();

    assert_eq!(outcome, MdsIngestOutcome::NoOpRefresh { no: 100 });
    assert!(
        repo.get_by_aaguid(id).await.unwrap().is_some(),
        "a no-op refresh must not touch the stored entries"
    );
    assert!(
        repo.get_by_aaguid(other_id).await.unwrap().is_none(),
        "the incoming (same-no) entry set must be discarded, not merged in"
    );
    let after = repo.get_meta().await.unwrap().unwrap();
    assert_eq!(after.entry_count, before.entry_count);
}

#[tokio::test]
async fn lower_no_is_rejected_as_rollback() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let id = Uuid::new_v4();

    ingest_blob(&repo, blob(100, vec![entry(id)]))
        .await
        .unwrap();

    let stale_id = Uuid::new_v4();
    let outcome = ingest_blob(&repo, blob(99, vec![entry(stale_id)]))
        .await
        .unwrap();

    assert_eq!(
        outcome,
        MdsIngestOutcome::RollbackRejected {
            attempted_no: 99,
            stored_no: 100
        }
    );
    assert!(
        repo.get_by_aaguid(id).await.unwrap().is_some(),
        "the stored (newer) entries must survive a rejected rollback"
    );
    assert!(
        repo.get_by_aaguid(stale_id).await.unwrap().is_none(),
        "the rejected (older) blob's entries must never be written"
    );
    assert_eq!(repo.get_meta().await.unwrap().unwrap().no, 100);
}

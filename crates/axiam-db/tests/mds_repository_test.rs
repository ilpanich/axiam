//! Integration tests for `SurrealMdsRepository` (X3, D10) — server-global
//! FIDO MDS3 storage.

use axiam_core::models::mds::{
    CertificationLevel, MdsAuthenticatorStatus, MdsBlobMeta, MdsEntry, MdsStatusReport,
};
use axiam_core::repository::MdsRepository;
use axiam_db::repository::SurrealMdsRepository;
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

fn uuid(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

fn sample_entry(aaguid: Uuid) -> MdsEntry {
    MdsEntry {
        aaguid,
        description: Some("Test Authenticator".into()),
        attestation_root_certificates: vec!["deadbeef".into(), "cafef00d".into()],
        status_reports: vec![
            MdsStatusReport {
                status: MdsAuthenticatorStatus::FidoCertifiedL2,
                effective_date: Some("2024-01-01".into()),
                certification_descriptor: Some("lab report #1".into()),
            },
            MdsStatusReport {
                status: MdsAuthenticatorStatus::UpdateAvailable,
                effective_date: Some("2024-06-01".into()),
                certification_descriptor: None,
            },
        ],
        time_of_last_status_change: Some("2024-06-01".into()),
    }
}

fn sample_meta(no: i64, entry_count: u64) -> MdsBlobMeta {
    MdsBlobMeta {
        no,
        next_update: NaiveDate::from_ymd_opt(2026, 12, 31).unwrap(),
        entry_count,
        last_refreshed_at: Utc::now(),
        stale: false,
    }
}

// ---------------------------------------------------------------------------
// replace_entries / get_by_aaguid / get_meta round trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn replace_entries_then_get_by_aaguid_round_trips() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let id = uuid(1);
    let entry = sample_entry(id);

    repo.replace_entries(vec![entry.clone()], sample_meta(100, 1))
        .await
        .unwrap();

    let fetched = repo.get_by_aaguid(id).await.unwrap().unwrap();
    assert_eq!(fetched.aaguid, id);
    assert_eq!(fetched.description, entry.description);
    assert_eq!(
        fetched.attestation_root_certificates,
        entry.attestation_root_certificates
    );
    assert_eq!(fetched.status_reports.len(), 2);
    assert_eq!(
        fetched.status_reports[0].status,
        MdsAuthenticatorStatus::FidoCertifiedL2
    );
    assert_eq!(
        fetched.highest_certification_level(),
        Some(CertificationLevel::L2)
    );
    assert!(!fetched.is_compromised_or_revoked());
}

#[tokio::test]
async fn get_by_aaguid_unknown_returns_none() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    assert!(repo.get_by_aaguid(uuid(9)).await.unwrap().is_none());
}

#[tokio::test]
async fn get_meta_before_any_ingestion_returns_none() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    assert!(repo.get_meta().await.unwrap().is_none());
}

#[tokio::test]
async fn replace_entries_stores_and_returns_meta() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let meta = sample_meta(276, 1);
    repo.replace_entries(vec![sample_entry(uuid(1))], meta.clone())
        .await
        .unwrap();

    let fetched = repo.get_meta().await.unwrap().unwrap();
    assert_eq!(fetched.no, 276);
    assert_eq!(fetched.entry_count, 1);
    assert_eq!(fetched.next_update, meta.next_update);
    assert!(!fetched.stale);
}

#[tokio::test]
async fn replace_entries_is_a_true_replace_not_an_append() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let first = uuid(1);
    let second = uuid(2);

    repo.replace_entries(vec![sample_entry(first)], sample_meta(1, 1))
        .await
        .unwrap();
    repo.replace_entries(vec![sample_entry(second)], sample_meta(2, 1))
        .await
        .unwrap();

    assert!(
        repo.get_by_aaguid(first).await.unwrap().is_none(),
        "the first entry set must be fully replaced, not merged with the second"
    );
    assert!(repo.get_by_aaguid(second).await.unwrap().is_some());
    assert_eq!(repo.list_all().await.unwrap().len(), 1);
}

#[tokio::test]
async fn replace_entries_with_empty_set_clears_the_table() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    repo.replace_entries(vec![sample_entry(uuid(1))], sample_meta(1, 1))
        .await
        .unwrap();
    assert_eq!(repo.list_all().await.unwrap().len(), 1);

    // A BLOB with zero aaguid-bearing entries (all UAF/U2F, D1) is a
    // legitimate input — must not error and must genuinely empty the table.
    repo.replace_entries(vec![], sample_meta(2, 0))
        .await
        .unwrap();
    assert_eq!(repo.list_all().await.unwrap().len(), 0);
    assert_eq!(repo.get_meta().await.unwrap().unwrap().no, 2);
}

#[tokio::test]
async fn list_all_returns_every_entry() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let entries: Vec<MdsEntry> = (1..=5u8).map(|n| sample_entry(uuid(n))).collect();
    repo.replace_entries(entries.clone(), sample_meta(1, 5))
        .await
        .unwrap();

    let all = repo.list_all().await.unwrap();
    assert_eq!(all.len(), 5);
    for e in &entries {
        assert!(all.iter().any(|a| a.aaguid == e.aaguid));
    }
}

#[tokio::test]
async fn touch_refreshed_at_updates_only_the_timestamp() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let original_meta = sample_meta(100, 1);
    repo.replace_entries(vec![sample_entry(uuid(1))], original_meta.clone())
        .await
        .unwrap();

    let new_ts = Utc::now() + chrono::Duration::seconds(3600);
    repo.touch_refreshed_at(new_ts).await.unwrap();

    let fetched = repo.get_meta().await.unwrap().unwrap();
    assert_eq!(fetched.no, 100, "no must be unchanged");
    assert_eq!(fetched.entry_count, 1, "entry_count must be unchanged");
    assert_eq!(
        fetched.last_refreshed_at.timestamp(),
        new_ts.timestamp(),
        "only last_refreshed_at changes"
    );
}

#[tokio::test]
async fn stale_flag_round_trips() {
    let db = setup().await;
    let repo = SurrealMdsRepository::new(db);
    let mut meta = sample_meta(1, 1);
    meta.stale = true;
    repo.replace_entries(vec![sample_entry(uuid(1))], meta)
        .await
        .unwrap();

    assert!(repo.get_meta().await.unwrap().unwrap().stale);
}

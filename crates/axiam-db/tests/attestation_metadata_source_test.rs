//! Integration tests for `MdsAttestationMetadataSource` (X3 wave 2, W2-D4) —
//! the `axiam_core::repository::AttestationMetadataSource` adapter over
//! `SurrealMdsRepository`.

use axiam_core::models::mds::{MdsBlobMeta, MdsEntry};
use axiam_core::repository::{AttestationMetadataSource, MdsRepository};
use axiam_db::attestation_metadata_source::MdsAttestationMetadataSource;
use axiam_db::repository::SurrealMdsRepository;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
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

fn entry(aaguid: Uuid, roots_b64: Vec<&str>) -> MdsEntry {
    MdsEntry {
        aaguid,
        description: Some(format!("Authenticator {aaguid}")),
        attestation_root_certificates: roots_b64.into_iter().map(String::from).collect(),
        status_reports: vec![],
        time_of_last_status_change: None,
    }
}

fn meta(count: u64) -> MdsBlobMeta {
    MdsBlobMeta {
        no: 1,
        next_update: NaiveDate::from_ymd_opt(2026, 12, 31).unwrap(),
        entry_count: count,
        last_refreshed_at: Utc::now(),
        stale: false,
    }
}

#[tokio::test]
async fn get_entry_delegates_to_the_wrapped_repository() {
    let db = setup().await;
    let mds_repo = SurrealMdsRepository::new(db);
    let id = uuid(1);
    mds_repo
        .replace_entries(vec![entry(id, vec![])], meta(1))
        .await
        .unwrap();

    let source = MdsAttestationMetadataSource::new(mds_repo);
    let fetched = source.get_entry(id).await.unwrap();
    assert!(fetched.is_some());
    assert_eq!(fetched.unwrap().aaguid, id);
    assert!(source.get_entry(uuid(9)).await.unwrap().is_none());
}

#[tokio::test]
async fn attestation_roots_decodes_base64_der_and_flattens_pairs() {
    let db = setup().await;
    let mds_repo = SurrealMdsRepository::new(db);
    let id = uuid(1);
    let root_a = STANDARD.encode(b"root-a-der-bytes");
    let root_b = STANDARD.encode(b"root-b-der-bytes");
    mds_repo
        .replace_entries(vec![entry(id, vec![&root_a, &root_b])], meta(1))
        .await
        .unwrap();

    let source = MdsAttestationMetadataSource::new(mds_repo);
    let roots = source.attestation_roots(None).await.unwrap();
    assert_eq!(roots.len(), 2, "one root material per (aaguid, cert) pair");
    assert!(roots.iter().all(|r| r.aaguid == id));
    let ders: Vec<&[u8]> = roots.iter().map(|r| r.der.as_slice()).collect();
    assert!(ders.contains(&b"root-a-der-bytes".as_slice()));
    assert!(ders.contains(&b"root-b-der-bytes".as_slice()));
}

#[tokio::test]
async fn attestation_roots_with_no_filter_covers_every_entry() {
    let db = setup().await;
    let mds_repo = SurrealMdsRepository::new(db);
    let a = uuid(1);
    let b = uuid(2);
    let root = STANDARD.encode(b"some-der");
    mds_repo
        .replace_entries(vec![entry(a, vec![&root]), entry(b, vec![&root])], meta(2))
        .await
        .unwrap();

    let source = MdsAttestationMetadataSource::new(mds_repo);
    let roots = source.attestation_roots(None).await.unwrap();
    assert_eq!(roots.len(), 2);
}

#[tokio::test]
async fn attestation_roots_with_allowlist_is_restricted_to_it() {
    let db = setup().await;
    let mds_repo = SurrealMdsRepository::new(db);
    let allowed = uuid(1);
    let not_allowed = uuid(2);
    let root = STANDARD.encode(b"some-der");
    mds_repo
        .replace_entries(
            vec![entry(allowed, vec![&root]), entry(not_allowed, vec![&root])],
            meta(2),
        )
        .await
        .unwrap();

    let source = MdsAttestationMetadataSource::new(mds_repo);
    let roots = source.attestation_roots(Some(&[allowed])).await.unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].aaguid, allowed);
}

#[tokio::test]
async fn attestation_roots_with_empty_allowlist_returns_nothing() {
    let db = setup().await;
    let mds_repo = SurrealMdsRepository::new(db);
    let root = STANDARD.encode(b"some-der");
    mds_repo
        .replace_entries(vec![entry(uuid(1), vec![&root])], meta(1))
        .await
        .unwrap();

    let source = MdsAttestationMetadataSource::new(mds_repo);
    let roots = source.attestation_roots(Some(&[])).await.unwrap();
    assert!(roots.is_empty());
}

#[tokio::test]
async fn malformed_base64_root_is_skipped_not_fatal() {
    let db = setup().await;
    let mds_repo = SurrealMdsRepository::new(db);
    let id = uuid(1);
    let good = STANDARD.encode(b"good-der");
    mds_repo
        .replace_entries(vec![entry(id, vec!["not valid base64!!", &good])], meta(1))
        .await
        .unwrap();

    let source = MdsAttestationMetadataSource::new(mds_repo);
    let roots = source.attestation_roots(None).await.unwrap();
    assert_eq!(roots.len(), 1, "only the parseable root survives");
    assert_eq!(roots[0].der, b"good-der".to_vec());
}

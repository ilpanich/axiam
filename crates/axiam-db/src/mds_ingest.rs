//! FIDO MDS3 ingestion orchestrator (X3 wave 2) — ties `axiam-pki`'s
//! fetch/verify pipeline to `MdsRepository` storage.
//!
//! `axiam-pki::mds::verify_and_parse` and `decide_ingest_outcome` are pure
//! (wave 1, no storage access — see their module docs for why `no stored
//! `no`` lives outside their signature). This module is the "ingestion
//! orchestrator" the wave-1 docs call out as later-wave work: it reads the
//! currently stored serial via [`MdsRepository::get_meta`], asks
//! `decide_ingest_outcome` what that means, and only then calls
//! [`MdsRepository::replace_entries`] / [`MdsRepository::touch_refreshed_at`]
//! — exactly the order D4 step 8 requires, and never in the other order (a
//! blind replace would defeat the rollback guard entirely).
//!
//! Lives in `axiam-db` rather than `axiam-pki` (spec's stated scope for wave
//! 2, section A) — `axiam-db` gained a regular dependency on `axiam-pki` for
//! this (see its `Cargo.toml`); the direction is acyclic since `axiam-pki`
//! depends only on `axiam-core` in its own regular dependencies.
//!
//! Background-job/admin-endpoint wiring (calling these functions on a
//! schedule or from `POST /api/v1/mds/refresh`) is `axiam-server`/REST work,
//! out of scope for this wave.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::repository::MdsRepository;
use axiam_pki::mds::{BlobIngestOutcome, MdsBlob, MdsError, decide_ingest_outcome};

/// The outcome of one ingestion attempt, covering all four
/// [`BlobIngestOutcome`] cases plus enough context to report them (D11:
/// `mds.refreshed` / `mds.refresh_failed` audit actions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdsIngestOutcome {
    /// First-ever ingestion — no stored serial existed.
    Initial { no: i64, entry_count: usize },
    /// A newer BLOB replaced the stored entries.
    Replaced { no: i64, entry_count: usize },
    /// The fetched BLOB's `no` equalled the stored serial — only
    /// `last_refreshed_at` was bumped, entries were already current.
    NoOpRefresh { no: i64 },
    /// The fetched BLOB's `no` was lower than the stored serial — rejected as
    /// a rollback attempt. Nothing was written.
    RollbackRejected { attempted_no: i64, stored_no: i64 },
}

/// Ingest an already-verified [`MdsBlob`] (D4 step 8, applied to storage).
///
/// Split out from the fetch/load entry points below so ingestion-outcome
/// logic has exactly one implementation regardless of transport (network vs.
/// air-gapped local file) and is directly testable against an in-memory
/// `MdsRepository` without a network or filesystem seam.
pub async fn ingest_blob<M: MdsRepository>(
    mds_repo: &M,
    blob: MdsBlob,
) -> AxiamResult<MdsIngestOutcome> {
    let stored_meta = mds_repo.get_meta().await?;
    let stored_no = stored_meta.as_ref().map(|m| m.no);

    match decide_ingest_outcome(blob.meta.no, stored_no) {
        BlobIngestOutcome::Initial => {
            let entry_count = blob.entries.len();
            let no = blob.meta.no;
            mds_repo.replace_entries(blob.entries, blob.meta).await?;
            Ok(MdsIngestOutcome::Initial { no, entry_count })
        }
        BlobIngestOutcome::Replace => {
            let entry_count = blob.entries.len();
            let no = blob.meta.no;
            mds_repo.replace_entries(blob.entries, blob.meta).await?;
            Ok(MdsIngestOutcome::Replaced { no, entry_count })
        }
        BlobIngestOutcome::NoOpRefresh => {
            let no = blob.meta.no;
            mds_repo
                .touch_refreshed_at(blob.meta.last_refreshed_at)
                .await?;
            Ok(MdsIngestOutcome::NoOpRefresh { no })
        }
        BlobIngestOutcome::RollbackRejected => {
            let attempted_no = blob.meta.no;
            let stored_no = stored_no.unwrap_or_default();
            tracing::warn!(
                action = "mds.refresh_failed",
                reason = "rollback",
                attempted_no,
                stored_no,
                "rejected an MDS BLOB whose serial is older than the stored one"
            );
            Ok(MdsIngestOutcome::RollbackRejected {
                attempted_no,
                stored_no,
            })
        }
    }
}

fn log_fetch_failure(source: &str, err: &MdsError) {
    tracing::error!(
        action = "mds.refresh_failed",
        reason = "verify_failed",
        source,
        error = %err,
        "FIDO MDS3 BLOB fetch/verification failed"
    );
}

/// Fetch, verify, and ingest the MDS3 BLOB from `url` (D10's network path,
/// through `axiam-pki`'s SSRF-guarded fetch).
pub async fn ingest_from_url<M: MdsRepository>(
    mds_repo: &M,
    url: &str,
    expected_leaf_dns: &str,
    allow_private: bool,
) -> AxiamResult<MdsIngestOutcome> {
    let blob = axiam_pki::mds::fetch_verified_blob(url, expected_leaf_dns, allow_private)
        .await
        .map_err(|e| {
            log_fetch_failure(url, &e);
            AxiamError::ServiceUnavailable(format!("MDS BLOB fetch/verification failed: {e}"))
        })?;
    ingest_blob(mds_repo, blob).await
}

/// Load, verify, and ingest the MDS3 BLOB from a local file — the air-gapped
/// deployment path (`AXIAM__PKI__MDS_BLOB_PATH`, D10). No network I/O.
pub async fn ingest_from_file<M: MdsRepository>(
    mds_repo: &M,
    path: &std::path::Path,
    expected_leaf_dns: &str,
) -> AxiamResult<MdsIngestOutcome> {
    let blob =
        axiam_pki::mds::load_verified_blob_from_file(path, expected_leaf_dns).map_err(|e| {
            log_fetch_failure(&path.display().to_string(), &e);
            AxiamError::ServiceUnavailable(format!("MDS BLOB load/verification failed: {e}"))
        })?;
    ingest_blob(mds_repo, blob).await
}

//! SurrealDB implementation of [`MdsRepository`] (X3, D10) — server-global
//! FIDO MDS3 metadata storage.
//!
//! `status_reports` is stored as a JSON string column (`status_reports_json`)
//! rather than a nested SurrealDB array-of-objects: it is opaque, read-only-
//! as-a-whole policy data (`axiam_core::models::webauthn_policy::evaluate`
//! only ever iterates the *whole* list, never a sub-field), so a JSON blob
//! avoids re-modelling FIDO's `StatusReport` schema a second time in DDL.

use axiam_core::error::AxiamResult;
use axiam_core::models::mds::{MdsBlobMeta, MdsEntry, MdsStatusReport};
use axiam_core::repository::MdsRepository;
use chrono::{DateTime, NaiveDate, Utc};
use surrealdb::Connection;
use surrealdb_types::SurrealValue;
use uuid::Uuid;

use crate::error::DbError;
use crate::handle::DbHandle;
use crate::helpers::parse_uuid;

/// The single `mds_blob_meta` row's fixed record key (D10: "server-global,
/// single row"). Using a constant key as the primary key is the same
/// "deterministic id as the uniqueness constraint" pattern
/// `_migration_lock:startup` already uses elsewhere in this schema.
const BLOB_META_KEY: &str = "singleton";

// ---------------------------------------------------------------------------
// Row structs
// ---------------------------------------------------------------------------

#[derive(Debug, SurrealValue)]
struct MdsEntryInsertRow {
    aaguid: String,
    description: Option<String>,
    attestation_root_certificates: Vec<String>,
    status_reports_json: String,
    time_of_last_status_change: Option<String>,
}

#[derive(Debug, SurrealValue)]
struct MdsEntryRow {
    aaguid: String,
    description: Option<String>,
    attestation_root_certificates: Vec<String>,
    status_reports_json: String,
    time_of_last_status_change: Option<String>,
}

impl MdsEntryRow {
    fn try_into_entry(self) -> Result<MdsEntry, DbError> {
        let aaguid = parse_uuid(&self.aaguid, "aaguid")?;
        let status_reports: Vec<MdsStatusReport> = serde_json::from_str(&self.status_reports_json)
            .map_err(|e| DbError::Serialization(format!("invalid status_reports_json: {e}")))?;
        Ok(MdsEntry {
            aaguid,
            description: self.description,
            attestation_root_certificates: self.attestation_root_certificates,
            status_reports,
            time_of_last_status_change: self.time_of_last_status_change,
        })
    }
}

#[derive(Debug, SurrealValue)]
struct BlobMetaRow {
    no: i64,
    next_update: String,
    entry_count: i64,
    last_refreshed_at: DateTime<Utc>,
    stale: bool,
}

impl BlobMetaRow {
    fn try_into_meta(self) -> Result<MdsBlobMeta, DbError> {
        let next_update =
            NaiveDate::parse_from_str(&self.next_update, "%Y-%m-%d").map_err(|e| {
                DbError::Serialization(format!("invalid mds_blob_meta.next_update: {e}"))
            })?;
        Ok(MdsBlobMeta {
            no: self.no,
            next_update,
            entry_count: self.entry_count.max(0) as u64,
            last_refreshed_at: self.last_refreshed_at,
            stale: self.stale,
        })
    }
}

fn entry_to_insert_row(entry: &MdsEntry) -> Result<MdsEntryInsertRow, DbError> {
    let status_reports_json = serde_json::to_string(&entry.status_reports)
        .map_err(|e| DbError::Serialization(format!("failed to serialize status_reports: {e}")))?;
    Ok(MdsEntryInsertRow {
        aaguid: entry.aaguid.to_string(),
        description: entry.description.clone(),
        attestation_root_certificates: entry.attestation_root_certificates.clone(),
        status_reports_json,
        time_of_last_status_change: entry.time_of_last_status_change.clone(),
    })
}

// ---------------------------------------------------------------------------
// Repository
// ---------------------------------------------------------------------------

/// SurrealDB implementation of the server-global FIDO MDS3 repository.
#[derive(Clone)]
pub struct SurrealMdsRepository<C: Connection> {
    db: DbHandle<C>,
}

impl<C: Connection> SurrealMdsRepository<C> {
    pub fn new(db: impl Into<DbHandle<C>>) -> Self {
        Self { db: db.into() }
    }
}

impl<C: Connection> MdsRepository for SurrealMdsRepository<C> {
    async fn replace_entries(&self, entries: Vec<MdsEntry>, meta: MdsBlobMeta) -> AxiamResult<()> {
        let rows = entries
            .iter()
            .map(entry_to_insert_row)
            .collect::<Result<Vec<_>, DbError>>()?;

        // Atomic replace: DELETE the whole table then INSERT the fresh set,
        // plus the meta upsert, in one transaction — a reader never observes
        // a half-replaced entry set (D10/D4 step 8: the caller already
        // decided via `decide_ingest_outcome` that this is a genuine
        // replace, not a rollback or no-op).
        //
        // `INSERT INTO mds_entry $entries` is skipped entirely when there are
        // no aaguid-bearing entries (an all-UAF/U2F BLOB, or a test fixture)
        // rather than binding an empty array — SurrealQL's `INSERT INTO`
        // wants at least one row.
        let insert_clause = if rows.is_empty() {
            String::new()
        } else {
            "INSERT INTO mds_entry $entries;\n".to_string()
        };

        let query = format!(
            "BEGIN TRANSACTION;\n\
             DELETE mds_entry;\n\
             {insert_clause}\
             UPSERT type::record('mds_blob_meta', $meta_key) SET \
                 no = $no, \
                 next_update = $next_update, \
                 entry_count = $entry_count, \
                 last_refreshed_at = $last_refreshed_at, \
                 stale = $stale;\n\
             COMMIT TRANSACTION"
        );

        let db = self.db.current();
        let mut builder = db
            .query(query)
            .bind(("meta_key", BLOB_META_KEY.to_string()))
            .bind(("no", meta.no))
            .bind(("next_update", meta.next_update.to_string()))
            .bind(("entry_count", meta.entry_count as i64))
            .bind(("last_refreshed_at", meta.last_refreshed_at))
            .bind(("stale", meta.stale));

        if !rows.is_empty() {
            builder = builder.bind(("entries", rows));
        }

        builder
            .await
            .map_err(DbError::from)?
            .check()
            .map_err(|e| DbError::Migration(e.to_string()))?;

        tracing::info!(
            action = "mds.refreshed",
            no = meta.no,
            entry_count = meta.entry_count,
            stale = meta.stale,
            "FIDO MDS3 entries replaced"
        );

        Ok(())
    }

    async fn get_by_aaguid(&self, aaguid: Uuid) -> AxiamResult<Option<MdsEntry>> {
        let mut result = self
            .db
            .current()
            .query("SELECT * FROM mds_entry WHERE aaguid = $aaguid LIMIT 1")
            .bind(("aaguid", aaguid.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<MdsEntryRow> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.try_into_entry()?)),
            None => Ok(None),
        }
    }

    async fn list_all(&self) -> AxiamResult<Vec<MdsEntry>> {
        let mut result = self
            .db
            .current()
            .query("SELECT * FROM mds_entry")
            .await
            .map_err(DbError::from)?;

        let rows: Vec<MdsEntryRow> = result.take(0).map_err(DbError::from)?;
        rows.into_iter()
            .map(|r| r.try_into_entry().map_err(Into::into))
            .collect()
    }

    async fn get_meta(&self) -> AxiamResult<Option<MdsBlobMeta>> {
        let mut result = self
            .db
            .current()
            .query("SELECT * FROM type::record('mds_blob_meta', $meta_key)")
            .bind(("meta_key", BLOB_META_KEY.to_string()))
            .await
            .map_err(DbError::from)?;

        let rows: Vec<BlobMetaRow> = result.take(0).map_err(DbError::from)?;
        match rows.into_iter().next() {
            Some(row) => Ok(Some(row.try_into_meta()?)),
            None => Ok(None),
        }
    }

    async fn touch_refreshed_at(&self, at: DateTime<Utc>) -> AxiamResult<()> {
        self.db
            .current()
            .query("UPDATE type::record('mds_blob_meta', $meta_key) SET last_refreshed_at = $at")
            .bind(("meta_key", BLOB_META_KEY.to_string()))
            .bind(("at", at))
            .await
            .map_err(DbError::from)?;

        Ok(())
    }
}

//! FIDO MDS3 admin endpoints (X3 wave 3, D10) — server-global, NOT
//! tenant-scoped: `mds_entry`/`mds_blob_meta` hold one shared trust picture
//! for the whole deployment (see `axiam_core::repository::MdsRepository`'s
//! module docs), so unlike every other handler module in this crate these
//! two routes take no `{tenant_id}` path segment.
//!
//! ## Permission choice
//!
//! Gated by the existing `ca_certificates:list` (`GET /status`) /
//! `ca_certificates:generate` (`POST /refresh`) permissions rather than a
//! new permission tier. MDS ingestion is the same class of privilege as CA
//! certificate management — `axiam_pki::mds`'s module docs put it exactly
//! this way: "PKI owns this because MDS ingestion is fundamentally a
//! trust-anchor concern ... not a WebAuthn concern: it verifies a signed
//! BLOB's chain of custody back to a vendored root, exactly like
//! `axiam-pki::mtls` does for mTLS client certificates". Reusing the
//! existing PKI-admin permission pair means an operator who already holds
//! CA-admin privilege can manage MDS without a fresh privilege category
//! being invented for one feature. Both checks use `Uuid::nil()` (global,
//! not resource-scoped), matching every other admin surface in this crate.

use actix_web::{HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::repository::MdsRepository;
use axiam_db::mds_ingest::{self, MdsIngestOutcome};
use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// `GET /api/v1/mds/status` response. `no`/`next_update`/`last_refreshed_at`
/// are `None` and `stale` is `false` when MDS has never been ingested — a
/// meaningful, valid answer ("nothing ingested yet"), not an error.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MdsStatusResponse {
    pub no: Option<i64>,
    #[schema(value_type = Option<String>)]
    pub next_update: Option<NaiveDate>,
    pub entry_count: u64,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    pub stale: bool,
}

/// `POST /api/v1/mds/refresh` response — the outcome of one ingestion
/// attempt (mirrors `axiam_db::mds_ingest::MdsIngestOutcome`).
#[derive(Debug, Serialize, utoipa::ToSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum MdsRefreshOutcome {
    /// First-ever ingestion — no stored serial existed.
    Initial { no: i64, entry_count: usize },
    /// A newer BLOB replaced the stored entries.
    Replaced { no: i64, entry_count: usize },
    /// The fetched BLOB's `no` equalled the stored serial — a no-op refresh.
    NoOpRefresh { no: i64 },
    /// The fetched BLOB's `no` was lower than the stored serial — rejected
    /// as a rollback attempt. Nothing was written.
    RollbackRejected { attempted_no: i64, stored_no: i64 },
}

impl From<MdsIngestOutcome> for MdsRefreshOutcome {
    fn from(o: MdsIngestOutcome) -> Self {
        match o {
            MdsIngestOutcome::Initial { no, entry_count } => Self::Initial { no, entry_count },
            MdsIngestOutcome::Replaced { no, entry_count } => Self::Replaced { no, entry_count },
            MdsIngestOutcome::NoOpRefresh { no } => Self::NoOpRefresh { no },
            MdsIngestOutcome::RollbackRejected {
                attempted_no,
                stored_no,
            } => Self::RollbackRejected {
                attempted_no,
                stored_no,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/mds/status`
#[utoipa::path(
    get,
    path = "/api/v1/mds/status",
    tag = "mds",
    responses(
        (status = 200, description = "Current FIDO MDS3 ingestion status \
            (never-ingested returns nulls, not a 404)", body = MdsStatusResponse),
    ),
    security(("bearer" = []))
)]
pub async fn status<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:list", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;

    let response = match state.webauthn.mds_repo.get_meta().await? {
        Some(m) => MdsStatusResponse {
            no: Some(m.no),
            next_update: Some(m.next_update),
            entry_count: m.entry_count,
            last_refreshed_at: Some(m.last_refreshed_at),
            stale: m.stale,
        },
        None => MdsStatusResponse {
            no: None,
            next_update: None,
            entry_count: 0,
            last_refreshed_at: None,
            stale: false,
        },
    };
    Ok(HttpResponse::Ok().json(response))
}

/// `POST /api/v1/mds/refresh`
///
/// Fetches (or, when `AXIAM__PKI__MDS_BLOB_PATH` is set, loads locally),
/// verifies, and ingests the FIDO MDS3 BLOB. Refuses to run when MDS
/// ingestion is disabled (`AXIAM__PKI__MDS_ENABLED=false`, the default) —
/// per `PkiConfig`'s documented contract, the master switch being off means
/// this endpoint makes no outbound call at all, not just that the
/// background job doesn't run.
#[utoipa::path(
    post,
    path = "/api/v1/mds/refresh",
    tag = "mds",
    responses(
        (status = 200, description = "Ingestion attempt completed (see `outcome` — a \
            rejected rollback or no-op refresh is still a 200, not an error)",
         body = MdsRefreshOutcome),
        (status = 400, description = "MDS ingestion is disabled"),
        (status = 503, description = "Fetch or cryptographic verification of the BLOB failed"),
    ),
    security(("bearer" = []))
)]
pub async fn refresh<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("ca_certificates:generate", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    // B-08: `mds_entry`/`mds_blob_meta` are server-global — the schema says so
    // in as many words — so this route mutates the attestation trust picture of
    // every tenant in the deployment. Reachable from inside one tenant it is
    // the same shape as B-04: a deployment-wide trust store writable by a
    // tenant administrator. The module docs above already argue that MDS
    // ingestion "is the same class of privilege as CA certificate management";
    // that class became organization-level, so this follows it.
    //
    // `GET /status` is deliberately left alone: it is a read, and reads are
    // outside this guard everywhere else too.
    crate::handlers::org_scope::require_organization_principal(&user, state.get_ref()).await?;

    if !state.webauthn.pki_config.mds_enabled {
        return Err(AxiamApiError(AxiamError::Validation {
            message: "MDS ingestion is disabled (set AXIAM__PKI__MDS_ENABLED=true to enable it)"
                .into(),
        }));
    }

    let outcome = match &state.webauthn.pki_config.mds_blob_path {
        Some(path) => {
            mds_ingest::ingest_from_file(
                &state.webauthn.mds_repo,
                path,
                &state.webauthn.pki_config.mds_leaf_dns,
            )
            .await?
        }
        None => {
            mds_ingest::ingest_from_url(
                &state.webauthn.mds_repo,
                &state.webauthn.pki_config.mds_blob_url,
                &state.webauthn.pki_config.mds_leaf_dns,
                false, // production: never allow private/loopback targets
            )
            .await?
        }
    };

    // W2-D3: only a genuine change to the set of known attestation roots
    // needs the cache rebuilt — a no-op refresh or rejected rollback left it
    // untouched. `mds_ingest`'s own `ingest_blob`/`log_fetch_failure` already
    // emitted the `mds.refreshed`/`mds.refresh_failed` structured events
    // (D11) before this returns.
    if matches!(
        outcome,
        MdsIngestOutcome::Initial { .. } | MdsIngestOutcome::Replaced { .. }
    ) {
        state.webauthn.attestation_ca_cache.invalidate();
    }

    Ok(HttpResponse::Ok().json(MdsRefreshOutcome::from(outcome)))
}

//! GDPR Art. 15 (data export) and Art. 17 (erasure) REST endpoints.
//!
//! Endpoints:
//! - `POST /api/v1/account/export`  — enqueue an async data-export job (D-12)
//! - `GET  /api/v1/account/export/{token}` — single-use download link (D-13)
//! - `POST /api/v1/account/delete`  — request account erasure / 30-day grace (D-07/D-08)
//! - `GET  /api/v1/auth/account/delete/cancel?token=<opaque>` — public cancel (D-09)

use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write as _;

use actix_web::{HttpResponse, web};
use axiam_auth::crypto::decrypt_separate;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditLogEntry, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::gdpr::{AccountDeletionStatus, CreateExportJob};
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::repository::{
    AccountDeletionRepository, AuditLogRepository, ExportJobRepository, TenantRepository,
    UserRepository,
};
use axiam_db::SurrealAuditLogRepository;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission, is_own_resource};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Optional target for admin-acting-on-behalf requests.
#[derive(Debug, Deserialize)]
pub struct ExportRequest {
    /// The user whose data to export. Defaults to the authenticated user.
    pub user_id: Option<Uuid>,
}

/// Optional target for admin erasure requests.
#[derive(Debug, Deserialize)]
pub struct DeleteRequest {
    /// The user to erase. Defaults to the authenticated user.
    pub user_id: Option<Uuid>,
}

/// Query-string for the public cancel endpoint.
#[derive(Debug, Deserialize)]
pub struct CancelQuery {
    pub token: String,
}

/// Download token path parameter.
#[derive(Debug, Deserialize)]
pub struct DownloadPath {
    pub token: String,
}

/// Response bodies.
#[derive(Debug, Serialize)]
struct QueuedResponse {
    queued: bool,
}

#[derive(Debug, Serialize)]
struct ScheduledResponse {
    scheduled: bool,
}

#[derive(Debug, Serialize)]
struct CancelledResponse {
    cancelled: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// SHA-256 hex of `raw_token`.
pub fn sha256_hex(raw: &str) -> String {
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// Generate a cryptographically-random 256-bit (32-byte) cancel token,
/// hex-encoded as a 64-character string (CQ-B39).
///
/// Replaces the previous `Uuid::new_v4().to_string()` (128-bit) token.
fn generate_cancel_token() -> String {
    use rand::RngExt;
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Append a GDPR audit log entry, logging any failure without propagating it.
///
/// Factored out of the individual GDPR handlers to eliminate the repeated
/// audit-append block pattern (CQ-B39).  The fire-and-forget `let _ = …`
/// pattern is intentional: an audit failure must not block the user response,
/// but failures are logged at `error!` level since GDPR audit trails are legally
/// significant (CQ-B31 / T-12-01).
async fn append_gdpr_audit<C: Connection + Clone>(
    audit_repo: &SurrealAuditLogRepository<C>,
    tenant_id: Uuid,
    actor_id: Uuid,
    action: &str,
    resource_id: Option<Uuid>,
    metadata: Option<serde_json::Value>,
) {
    if let Err(e) = audit_repo
        .append(axiam_core::models::audit::CreateAuditLogEntry {
            tenant_id,
            actor_id,
            actor_type: ActorType::User,
            action: action.into(),
            resource_id,
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata,
        })
        .await
    {
        tracing::error!(
            error = %e,
            %tenant_id,
            "gdpr: failed to write audit log for GDPR request (legally significant)"
        );
    }
}

// ---------------------------------------------------------------------------
// Erasure audit dead-letter queue (SECHRD-12 / T-24-61, T-24-62, D-02)
// ---------------------------------------------------------------------------

/// Environment variable naming the append-only dead-letter file for the GDPR
/// erasure audit event. Intended to point at a mounted volume so the file
/// survives container restarts. Absent = the file sink is skipped for this
/// event (the structured tracing event sink below still fires
/// unconditionally on failure).
pub const GDPR_AUDIT_DLQ_FILE_ENV: &str = "AXIAM__GDPR_AUDIT_DLQ_FILE";

/// Injectable seam for the erasure audit DB-write (SECHRD-12).
///
/// `SurrealAuditLogRepository<C>` is the production implementation (forwards
/// to [`AuditLogRepository::append`]); tests inject a failing double to drive
/// the dead-letter path in [`write_erasure_audit_with_dlq`] without a live
/// broken database. Defined here (not in `axiam-core::repository`) so it
/// stays out of the generic repository trait surface owned by another plan.
pub trait AuditWriteSink: Send + Sync {
    fn write(
        &self,
        entry: CreateAuditLogEntry,
    ) -> impl Future<Output = AxiamResult<AuditLogEntry>> + Send;
}

impl<C: Connection> AuditWriteSink for SurrealAuditLogRepository<C> {
    fn write(
        &self,
        entry: CreateAuditLogEntry,
    ) -> impl Future<Output = AxiamResult<AuditLogEntry>> + Send {
        self.append(entry)
    }
}

/// Write the erasure audit record via `sink`. If the DB write fails, the
/// record is dead-lettered to BOTH an append-only local file AND a
/// structured `tracing` audit event (D-02), so a legally-significant
/// erasure event is never silently lost to a transient DB failure (T-24-61).
///
/// Never propagates the DB error — the caller (the cleanup ticker, T-04-36)
/// must not panic or abort the sweep on this failure path; the two
/// dead-letter sinks ARE the durability guarantee for this branch.
pub async fn write_erasure_audit_with_dlq<S: AuditWriteSink>(sink: &S, entry: CreateAuditLogEntry) {
    let dlq_entry = entry.clone();
    if let Err(e) = sink.write(entry).await {
        tracing::error!(
            error = %e,
            tenant_id = %dlq_entry.tenant_id,
            action = %dlq_entry.action,
            "gdpr: erasure audit DB-write failed — dead-lettering to append-only file + \
             structured event (legally significant, SECHRD-12)"
        );
        dead_letter_erasure_audit(&dlq_entry, &e);
    }
}

/// Dead-letter a failed erasure audit record to the two durable sinks (D-02).
fn dead_letter_erasure_audit(entry: &CreateAuditLogEntry, db_error: &AxiamError) {
    // Sink 1: append-only local file on a mounted volume (T-24-62). Opened
    // with `.append(true)` — an existing file is never truncated/rewritten,
    // matching AXIAM's append-only audit posture.
    match std::env::var(GDPR_AUDIT_DLQ_FILE_ENV) {
        Ok(path) => match serde_json::to_string(entry) {
            Ok(line) => match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(mut file) => {
                    if let Err(e) = writeln!(file, "{line}") {
                        tracing::error!(
                            error = %e,
                            path = %path,
                            "gdpr: failed to append erasure audit dead-letter file"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        path = %path,
                        "gdpr: failed to open erasure audit dead-letter file"
                    );
                }
            },
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "gdpr: failed to serialize erasure audit dead-letter record"
                );
            }
        },
        Err(_) => {
            tracing::warn!(
                env_var = GDPR_AUDIT_DLQ_FILE_ENV,
                "gdpr: erasure audit dead-letter FILE sink skipped (env var not set); \
                 structured event sink below still fires"
            );
        }
    }

    // Sink 2: structured `tracing` audit event — the "audit syslog" sink
    // (RESEARCH Assumption A4: satisfied by a structured tracing JSON event
    // captured by the container log driver, NOT a literal syslog(3) socket;
    // the distroless deployment has no local syslogd, per 06-01 decisions).
    tracing::error!(
        target: "axiam.audit.dlq",
        tenant_id = %entry.tenant_id,
        actor_id = %entry.actor_id,
        action = %entry.action,
        resource_id = ?entry.resource_id,
        db_error = %db_error,
        "gdpr_audit_dlq"
    );
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/account/export`
///
/// Enqueues an async GDPR Art. 15 data-export job.  Returns immediately with
/// `{"queued": true}`; the cleanup sweep generates the encrypted JSON, stores
/// it, and emails a single-use 24 h download link (D-12).
///
/// Self-service (own account) or admin with `gdpr:export` permission.
#[utoipa::path(
    post,
    path = "/api/v1/account/export",
    tag = "gdpr",
    request_body = inline(serde_json::Value),
    responses(
        (status = 200, description = "Export job enqueued"),
        (status = 403, description = "Forbidden"),
    ),
    security(("bearer" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn request_account_export<C: Connection + Clone>(
    auth_user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<ExportRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let target_id = req.user_id.unwrap_or(auth_user.user_id);

    // Ownership check: self OR gdpr:export permission.
    if !is_own_resource(&auth_user, target_id) {
        RequirePermission::new("gdpr:export", Uuid::nil())
            .check(&auth_user, authz.get_ref().as_ref())
            .await?;
    }

    // CQ-B39: Deduplicate concurrent export requests — reject if a queued
    // export already exists for this user to avoid duplicate processing.
    if state
        .export_job_repo
        .has_pending_for_user(auth_user.tenant_id, target_id)
        .await?
    {
        return Err(AxiamError::AlreadyExists {
            entity: "export_job".into(),
        }
        .into());
    }

    // Create a queued export job.
    state
        .export_job_repo
        .create(CreateExportJob {
            tenant_id: auth_user.tenant_id,
            user_id: target_id,
        })
        .await?;

    // Audit: gdpr.data_export_requested.
    append_gdpr_audit(
        &state.audit_repo,
        auth_user.tenant_id,
        auth_user.user_id,
        "gdpr.data_export_requested",
        Some(target_id),
        Some(serde_json::json!({ "subject_id": target_id.to_string() })),
    )
    .await;

    Ok(HttpResponse::Ok().json(QueuedResponse { queued: true }))
}

/// `GET /api/v1/account/export/{token}`
///
/// Single-use download of the GDPR export blob (D-13).  Looks up the job by
/// SHA-256(token), verifies it is ready and not expired/used, decrypts the
/// blob, marks it as downloaded, and deletes the record.
///
/// Requires authentication (self or admin with `gdpr:export`).
#[utoipa::path(
    get,
    path = "/api/v1/account/export/{token}",
    tag = "gdpr",
    params(("token" = String, Path, description = "Single-use download token")),
    responses(
        (status = 200, description = "Export JSON"),
        (status = 404, description = "Token not found or expired"),
    ),
    security(("bearer" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn download_account_export<C: Connection + Clone>(
    auth_user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<DownloadPath>,
) -> Result<HttpResponse, AxiamApiError> {
    let token = path.into_inner().token;
    let token_hash = sha256_hex(&token);

    let job = state
        .export_job_repo
        .find_by_download_token_hash(auth_user.tenant_id, &token_hash)
        .await?
        .ok_or_else(|| AxiamError::NotFound {
            entity: "export_job".into(),
            id: "by-token".into(),
        })?;

    // Ownership check.
    if !is_own_resource(&auth_user, job.user_id) {
        RequirePermission::new("gdpr:export", Uuid::nil())
            .check(&auth_user, authz.get_ref().as_ref())
            .await?;
    }

    // Validate status and expiry (D-13: single-use, 24h TTL).
    use axiam_core::models::gdpr::ExportJobStatus;
    if job.status != ExportJobStatus::Ready {
        return Err(AxiamError::AuthorizationDenied {
            reason: "export token already used or not ready".into(),
            action: None,
            resource_id: None,
        }
        .into());
    }
    if let Some(expires_at) = job.expires_at
        && expires_at < Utc::now()
    {
        return Err(AxiamError::AuthorizationDenied {
            reason: "export token expired".into(),
            action: None,
            resource_id: None,
        }
        .into());
    }

    // Decrypt the blob.
    let (nonce, ciphertext) = match (&job.blob_nonce, &job.encrypted_blob) {
        (Some(n), Some(ct)) => (n.clone(), ct.clone()),
        _ => {
            return Err(AxiamError::Internal("export blob missing on ready job".into()).into());
        }
    };
    let key = state
        .email_encryption_key
        .as_ref()
        .ok_or_else(|| AxiamError::Internal("export encryption key not configured".into()))?;

    let plaintext_bytes = decrypt_separate(key, &nonce, &ciphertext)
        .map_err(|e| AxiamError::Internal(format!("export decrypt failed: {e}")))?;

    // Atomic single-use consume: UPDATE WHERE status = 'ready' + DELETE.
    // If 0 rows were updated the token was already consumed (TOCTTOU-safe,
    // D-13 / CQ-B38 / REQ-14 AC-5).
    let consumed = state
        .export_job_repo
        .consume_ready_and_delete(job.id)
        .await?;
    if !consumed {
        return Err(AxiamError::AuthorizationDenied {
            reason: "export token already consumed".into(),
            action: None,
            resource_id: None,
        }
        .into());
    }

    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|e| AxiamError::Internal(format!("export UTF-8 decode: {e}")))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(plaintext))
}

/// `POST /api/v1/account/delete`
///
/// Initiates Art. 17 erasure: immediately disables the account, revokes all
/// sessions, emails a single-use cancel link, and schedules purge at +30 d
/// (D-07/D-08/D-09).
///
/// Self-service (own account) or admin with `users:erase` permission.
#[utoipa::path(
    post,
    path = "/api/v1/account/delete",
    tag = "gdpr",
    request_body = inline(serde_json::Value),
    responses(
        (status = 200, description = "Deletion scheduled"),
        (status = 403, description = "Forbidden"),
    ),
    security(("bearer" = []))
)]
#[allow(clippy::too_many_arguments)]
pub async fn request_account_delete<C: Connection + Clone>(
    auth_user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<DeleteRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let req = body.into_inner();
    let target_id = req.user_id.unwrap_or(auth_user.user_id);

    // Ownership check: self OR users:erase permission.
    if !is_own_resource(&auth_user, target_id) {
        RequirePermission::new("users:erase", Uuid::nil())
            .check(&auth_user, authz.get_ref().as_ref())
            .await?;
    }

    // Load target user to get email for the cancel mail.
    let target_user = state
        .user_repo
        .get_by_id(auth_user.tenant_id, target_id)
        .await?;

    // Schedule purge at +30 days (D-08).
    let scheduled_purge_at = Utc::now() + chrono::Duration::days(30);

    // Generate cancel token: 256-bit random token, hex-encoded (CQ-B39).
    // Only the SHA-256 hash is stored in the DB; the raw token is emailed.
    let raw_cancel_token = generate_cancel_token();
    let cancel_token_hash = sha256_hex(&raw_cancel_token);

    // D-14: mark the user deletion-pending AND create the account_deletion
    // row (holding the cancel_token_hash) in ONE transaction — a create
    // failure (e.g. a duplicate pending-deletion conflict) must never
    // strand the user in deletion_pending=true with no account_deletion row
    // to hold a cancellable token (CQ-B39 residual / uncancellable purge).
    state
        .account_deletion_repo
        .create_with_pending_flag(
            auth_user.tenant_id,
            target_id,
            scheduled_purge_at,
            cancel_token_hash,
        )
        .await?;

    // Revoke all sessions immediately (D-08: account disabled). Kept as a
    // separate, subsequent call — not part of the D-14 strand-risk
    // transaction: a failure here leaves an unrevoked session, a lesser and
    // pre-existing concern, not an uncancellable purge.
    state
        .auth_service
        .revoke_all_sessions(auth_user.tenant_id, target_id)
        .await?;

    // Resolve org_id for the mail message.
    let org_id = match state.tenant_repo.get_by_id(auth_user.tenant_id).await {
        Ok(tenant) => tenant.organization_id,
        Err(e) => {
            tracing::warn!(error = %e, "failed to resolve org_id for delete-cancel mail");
            Uuid::nil()
        }
    };

    // Enqueue the cancel-link email (D-09).
    let cancel_url = format!(
        "/api/v1/auth/account/delete/cancel?token={}",
        raw_cancel_token
    );
    let msg = OutboundMailMessage {
        mail_type: MailType::DeletionCancel,
        tenant_id: auth_user.tenant_id,
        org_id,
        user_id: target_id,
        to_address: target_user.email.clone(),
        template_context: serde_json::json!({
            "action_url": cancel_url,
            "expiry_time": scheduled_purge_at.to_rfc3339(),
        }),
        attempt_count: 0,
        enqueued_at: Utc::now(),
    };
    if let Err(e) = state.mail_outbound_publisher.publish(msg).await {
        tracing::warn!(error = %e, "failed to enqueue delete-cancel email; continuing");
    }

    // Audit: gdpr.erasure_requested.
    append_gdpr_audit(
        &state.audit_repo,
        auth_user.tenant_id,
        auth_user.user_id,
        "gdpr.erasure_requested",
        Some(target_id),
        Some(serde_json::json!({
            "subject_id": target_id.to_string(),
            "scheduled_purge_at": scheduled_purge_at.to_rfc3339(),
        })),
    )
    .await;

    Ok(HttpResponse::Ok().json(ScheduledResponse { scheduled: true }))
}

/// `GET /api/v1/auth/account/delete/cancel?token=<opaque>`
///
/// **Public endpoint** (token-authenticated; listed in `PUBLIC_PATHS`).
///
/// Validates the single-use cancel token; if the deletion is still pending
/// and within the grace window, aborts it and re-enables the account (D-09).
/// A second call with the same token is rejected (single-use).
#[utoipa::path(
    get,
    path = "/api/v1/auth/account/delete/cancel",
    tag = "gdpr",
    params(("token" = String, Query, description = "Single-use cancel token")),
    responses(
        (status = 200, description = "Deletion cancelled"),
        (status = 400, description = "Token invalid or expired"),
    )
)]
pub async fn cancel_account_delete<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    query: web::Query<CancelQuery>,
) -> Result<HttpResponse, AxiamApiError> {
    let token_hash = sha256_hex(&query.token);

    // Global lookup by token hash (no auth context — public endpoint, D-09).
    let deletion = state
        .account_deletion_repo
        .find_by_token_hash_global(&token_hash)
        .await?
        .ok_or_else(|| AxiamError::NotFound {
            entity: "account_deletion".into(),
            id: "by-token".into(),
        })?;

    // Validate: must be pending and within grace window.
    if deletion.status != AccountDeletionStatus::Pending {
        return Err(AxiamError::AuthorizationDenied {
            reason: "cancel token already used".into(),
            action: None,
            resource_id: None,
        }
        .into());
    }
    if deletion.scheduled_purge_at < Utc::now() {
        return Err(AxiamError::AuthorizationDenied {
            reason: "grace window expired — cannot cancel".into(),
            action: None,
            resource_id: None,
        }
        .into());
    }

    // Abort deletion: mark cancelled (single-use) + re-enable account.
    state
        .account_deletion_repo
        .mark_cancelled(deletion.tenant_id, deletion.id)
        .await?;

    state
        .user_repo
        .clear_deletion_pending(deletion.tenant_id, deletion.user_id)
        .await?;

    Ok(HttpResponse::Ok().json(CancelledResponse { cancelled: true }))
}

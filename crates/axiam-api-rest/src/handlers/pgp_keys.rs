//! OpenPGP key management endpoints.

use actix_web::{HttpResponse, web};
use axiam_core::models::pgp_key::{
    CreatePgpKey, EncryptRequest, EncryptedExport, GeneratedPgpKey, PgpKey, SignAuditBatchRequest,
    SignedAuditBatch,
};
use axiam_core::repository::{AuditLogRepository, PaginatedResult, Pagination};
use axiam_db::{SurrealAuditLogRepository, SurrealPgpKeyRepository};
use axiam_pki::PgpService;
use surrealdb::Connection;
use uuid::Uuid;

use crate::AuthenticatedUser;
use crate::error::AxiamApiError;

/// `POST /api/v1/pgp-keys`
#[utoipa::path(
    post,
    path = "/api/v1/pgp-keys",
    tag = "pgp-keys",
    request_body = CreatePgpKey,
    responses(
        (status = 201, description = "PGP key generated",
         body = GeneratedPgpKey),
    ),
    security(("bearer" = []))
)]
pub async fn generate<C: Connection>(
    user: AuthenticatedUser,
    service: web::Data<PgpService<SurrealPgpKeyRepository<C>>>,
    body: web::Json<CreatePgpKey>,
) -> Result<HttpResponse, AxiamApiError> {
    let mut input = body.into_inner();
    input.tenant_id = user.tenant_id;
    let result = service.generate(input).await?;
    Ok(HttpResponse::Created().json(result))
}

/// `GET /api/v1/pgp-keys`
#[utoipa::path(
    get,
    path = "/api/v1/pgp-keys",
    tag = "pgp-keys",
    params(Pagination),
    responses(
        (status = 200, description = "List of PGP keys",
         body = inline(PaginatedResult<PgpKey>)),
    ),
    security(("bearer" = []))
)]
pub async fn list<C: Connection>(
    user: AuthenticatedUser,
    service: web::Data<PgpService<SurrealPgpKeyRepository<C>>>,
    pagination: web::Query<Pagination>,
) -> Result<HttpResponse, AxiamApiError> {
    let result = service
        .list(user.tenant_id, pagination.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `GET /api/v1/pgp-keys/{id}`
#[utoipa::path(
    get,
    path = "/api/v1/pgp-keys/{id}",
    tag = "pgp-keys",
    params(("id" = Uuid, Path, description = "PGP key ID")),
    responses(
        (status = 200, description = "PGP key found", body = PgpKey),
    ),
    security(("bearer" = []))
)]
pub async fn get<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    service: web::Data<PgpService<SurrealPgpKeyRepository<C>>>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    let result = service.get(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `POST /api/v1/pgp-keys/{id}/revoke`
#[utoipa::path(
    post,
    path = "/api/v1/pgp-keys/{id}/revoke",
    tag = "pgp-keys",
    params(("id" = Uuid, Path, description = "PGP key ID")),
    responses(
        (status = 200, description = "PGP key revoked"),
    ),
    security(("bearer" = []))
)]
pub async fn revoke<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    service: web::Data<PgpService<SurrealPgpKeyRepository<C>>>,
) -> Result<HttpResponse, AxiamApiError> {
    let id = path.into_inner();
    service.revoke(user.tenant_id, id).await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({"status": "revoked"})))
}

/// `POST /api/v1/pgp-keys/sign-audit-batch`
#[utoipa::path(
    post,
    path = "/api/v1/pgp-keys/sign-audit-batch",
    tag = "pgp-keys",
    request_body = SignAuditBatchRequest,
    responses(
        (status = 200, description = "Audit batch signed",
         body = SignedAuditBatch),
    ),
    security(("bearer" = []))
)]
pub async fn sign_audit_batch<C: Connection>(
    user: AuthenticatedUser,
    pgp_service: web::Data<PgpService<SurrealPgpKeyRepository<C>>>,
    audit_repo: web::Data<SurrealAuditLogRepository<C>>,
    body: web::Json<SignAuditBatchRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let request = body.into_inner();

    // Reject empty or duplicate entry IDs
    if request.entry_ids.is_empty() {
        return Err(axiam_core::error::AxiamError::Validation {
            message: "entry_ids must not be empty".into(),
        }
        .into());
    }
    let unique_ids: std::collections::HashSet<_> = request.entry_ids.iter().collect();
    if unique_ids.len() != request.entry_ids.len() {
        return Err(axiam_core::error::AxiamError::Validation {
            message: "entry_ids must not contain duplicates".into(),
        }
        .into());
    }

    let entries = audit_repo
        .get_by_ids(user.tenant_id, &request.entry_ids)
        .await?;

    if entries.len() != request.entry_ids.len() {
        let found_ids: std::collections::HashSet<_> = entries.iter().map(|e| e.id).collect();
        let missing: Vec<_> = request
            .entry_ids
            .iter()
            .filter(|id| !found_ids.contains(id))
            .collect();
        return Err(axiam_core::error::AxiamError::Validation {
            message: format!("audit entries not found: {missing:?}"),
        }
        .into());
    }

    let result = pgp_service
        .sign_audit_batch(user.tenant_id, entries)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

/// `POST /api/v1/pgp-keys/{id}/encrypt`
#[utoipa::path(
    post,
    path = "/api/v1/pgp-keys/{id}/encrypt",
    tag = "pgp-keys",
    request_body = EncryptRequest,
    params(("id" = Uuid, Path, description = "PGP key ID")),
    responses(
        (status = 200, description = "Data encrypted",
         body = EncryptedExport),
    ),
    security(("bearer" = []))
)]
pub async fn encrypt<C: Connection>(
    user: AuthenticatedUser,
    path: web::Path<Uuid>,
    service: web::Data<PgpService<SurrealPgpKeyRepository<C>>>,
    body: web::Json<EncryptRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let key_id = path.into_inner();
    let plaintext = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &body.data_base64,
    )
    .map_err(|e| axiam_core::error::AxiamError::Validation {
        message: format!("invalid base64: {e}"),
    })?;

    let result = service
        .encrypt_for_export(user.tenant_id, key_id, &plaintext)
        .await?;
    Ok(HttpResponse::Ok().json(result))
}

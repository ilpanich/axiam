//! Authorization check endpoints (FND-04).
//!
//! Exposes `POST /api/v1/authz/check` (single) and
//! `POST /api/v1/authz/check/batch` so the TypeScript browser SDK and
//! other REST-only clients can evaluate permissions without a gRPC channel.
//!
//! Both endpoints delegate to the **same** `AuthzChecker::check_access`
//! path as the gRPC `AuthorizationService` (D-08). Identity is derived
//! exclusively from the verified JWT (`user.tenant_id`, `user.user_id`);
//! no identity field is accepted from the request body.
//!
//! The `subject_id` field in the body enables cross-subject ("check-as")
//! queries. Callers must hold the `authz:check_as` permission (T-15-01).
//! Every cross-subject query is written to the append-only audit log before
//! returning, regardless of the engine's decision (T-15-04, D-06).

use actix_web::{HttpResponse, web};
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::AuditLogRepository;
use axiam_db::SurrealAuditLogRepository;
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;

// ---------------------------------------------------------------------------
// Request / response schemas
// ---------------------------------------------------------------------------

/// Body for a single authorization check.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CheckAccessBody {
    /// The action to check (e.g. `"users:get"`).
    pub action: String,
    /// The resource UUID the action targets.
    pub resource_id: Uuid,
    /// Optional scope for sub-resource granularity.
    pub scope: Option<String>,
    /// Subject to check on behalf of.
    ///
    /// When `Some`, the caller must hold `authz:check_as` (T-15-01).
    /// When `None`, the check is performed for the authenticated caller.
    pub subject_id: Option<Uuid>,
}

/// Result of a single authorization check.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CheckAccessResponse {
    /// Whether access was granted.
    pub allowed: bool,
    /// Engine-provided deny reason (T-15-02: generic string only, no resource-structure hints).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Body for a batch authorization check.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct BatchCheckAccessBody {
    /// Ordered list of checks to evaluate.
    pub checks: Vec<CheckAccessBody>,
}

/// Result of a batch authorization check.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BatchCheckAccessResponse {
    /// Ordered results — same length and order as the input `checks`.
    pub results: Vec<CheckAccessResponse>,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn decision_to_response(decision: AccessDecision) -> CheckAccessResponse {
    match decision {
        AccessDecision::Allow => CheckAccessResponse {
            allowed: true,
            reason: None,
        },
        AccessDecision::Deny(reason) => CheckAccessResponse {
            allowed: false,
            // T-15-02: reason is the engine's generic string — no structural hints added.
            reason: Some(reason),
        },
    }
}

/// Append an authz.check_as audit entry, fire-and-forget (legally significant).
///
/// Failures are logged at `error!` level but never propagated — the audit trail
/// must not block the caller response (T-15-04).
async fn append_check_as_audit<C: Connection>(
    audit_repo: &SurrealAuditLogRepository<C>,
    tenant_id: Uuid,
    actor_id: Uuid,
    queried_subject: Uuid,
    resource_id: Uuid,
) {
    if let Err(e) = audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id,
            actor_type: ActorType::User,
            action: "authz.check_as".into(),
            resource_id: Some(resource_id),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "queried_subject": queried_subject.to_string()
            })),
        })
        .await
    {
        tracing::error!(
            error = %e,
            %tenant_id,
            %actor_id,
            %queried_subject,
            "authz_check: failed to write authz.check_as audit log (legally significant)"
        );
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/v1/authz/check`
///
/// Evaluate a single authorization check for the authenticated caller (or, if
/// the caller holds `authz:check_as`, for an arbitrary subject).
///
/// `tenant_id` is always taken from the JWT — it cannot be supplied in the body.
#[utoipa::path(
    post,
    path = "/api/v1/authz/check",
    tag = "authz",
    request_body = CheckAccessBody,
    responses(
        (status = 200, description = "Authorization decision", body = CheckAccessResponse),
        (status = 403, description = "Forbidden — caller lacks authz:check_as for subject_id override"),
        (status = 401, description = "Unauthenticated"),
    ),
    security(("bearer" = []))
)]
pub async fn check_access<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    audit_repo: web::Data<SurrealAuditLogRepository<C>>,
    body: web::Json<CheckAccessBody>,
) -> Result<HttpResponse, AxiamApiError> {
    let body = body.into_inner();
    let resource_id = body.resource_id;

    // T-15-01: subject_id override requires authz:check_as; T-15-03: tenant_id
    // is always user.tenant_id (never from body).
    let effective_subject = if let Some(sid) = body.subject_id {
        RequirePermission::new("authz:check_as", user.tenant_id)
            .check(&user, authz.get_ref().as_ref())
            .await?;
        // T-15-04: audit every cross-subject query before returning.
        append_check_as_audit(&audit_repo, user.tenant_id, user.user_id, sid, resource_id).await;
        sid
    } else {
        user.user_id
    };

    let access_req = AccessRequest {
        tenant_id: user.tenant_id,
        subject_id: effective_subject,
        action: body.action,
        resource_id,
        scope: body.scope,
    };

    let decision = authz
        .check_access(&access_req)
        .await
        .map_err(AxiamApiError::from)?;

    Ok(HttpResponse::Ok().json(decision_to_response(decision)))
}

/// `POST /api/v1/authz/check/batch`
///
/// Evaluate an ordered list of authorization checks.  Returns results in the
/// same order and length as the input `checks` array.
///
/// If **any** check in the batch includes a `subject_id`, the caller must hold
/// `authz:check_as` — the permission is verified once up front (not per item).
#[utoipa::path(
    post,
    path = "/api/v1/authz/check/batch",
    tag = "authz",
    request_body = BatchCheckAccessBody,
    responses(
        (status = 200, description = "Ordered batch of authorization decisions", body = BatchCheckAccessResponse),
        (status = 403, description = "Forbidden — caller lacks authz:check_as for subject_id override"),
        (status = 401, description = "Unauthenticated"),
    ),
    security(("bearer" = []))
)]
pub async fn batch_check_access<C: Connection>(
    user: AuthenticatedUser,
    authz: AuthzData,
    audit_repo: web::Data<SurrealAuditLogRepository<C>>,
    body: web::Json<BatchCheckAccessBody>,
) -> Result<HttpResponse, AxiamApiError> {
    let body = body.into_inner();

    // T-15-01: validate authz:check_as ONCE up front if any check uses subject_id override.
    let has_override = body.checks.iter().any(|c| c.subject_id.is_some());
    if has_override {
        RequirePermission::new("authz:check_as", user.tenant_id)
            .check(&user, authz.get_ref().as_ref())
            .await?;
    }

    let mut results = Vec::with_capacity(body.checks.len());

    for check in body.checks {
        let resource_id = check.resource_id;
        let effective_subject = if let Some(sid) = check.subject_id {
            // T-15-04: audit each cross-subject item individually.
            append_check_as_audit(&audit_repo, user.tenant_id, user.user_id, sid, resource_id)
                .await;
            sid
        } else {
            user.user_id
        };

        let access_req = AccessRequest {
            tenant_id: user.tenant_id,
            subject_id: effective_subject,
            action: check.action,
            resource_id,
            scope: check.scope,
        };

        let decision = authz
            .check_access(&access_req)
            .await
            .map_err(AxiamApiError::from)?;

        results.push(decision_to_response(decision));
    }

    Ok(HttpResponse::Ok().json(BatchCheckAccessResponse { results }))
}

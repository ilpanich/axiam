//! Tenant WebAuthn attestation policy admin endpoints (X3 wave 3).
//!
//! Three admin-gated, tenant-scoped endpoints:
//!
//! - `GET  /api/v1/tenants/{tenant_id}/webauthn/attestation-policy` — the
//!   effective policy. An absent row returns
//!   [`WebauthnAttestationPolicy::default`] (D5), never a 404: "no policy
//!   configured" is a valid, meaningful answer (today's `mode: none`
//!   behavior, unchanged) rather than a missing resource.
//! - `PUT  /api/v1/tenants/{tenant_id}/webauthn/attestation-policy` —
//!   replace the policy. Validates the D5 invariants
//!   (`require_fido_certified`/`min_certification` with `mode: none` is
//!   rejected as a config error), persists, and invalidates the
//!   process-wide [`AttestationCaCache`](axiam_auth::AttestationCaCache) —
//!   a cached CA list built under the OLD `allowed_aaguids` restriction
//!   must not survive a policy change (W2-D3).
//! - `GET  /api/v1/tenants/{tenant_id}/webauthn/compliance-report` — D9.
//!   Evaluates the *current* policy against every credential's recorded
//!   `aaguid`/`attestation_format`. Read-only: never mutates or revokes
//!   anything (revocation stays the existing admin credential-delete path).
//!
//! ## Permission choice
//!
//! Gated by dedicated `webauthn_policy:read` (both `GET`s) /
//! `webauthn_policy:write` (`PUT`) permissions, mirroring the
//! `email_config:read`/`email_config:write` pair, rather than reusing the
//! generic `settings:get`/`settings:update` pair `handlers::settings` uses.
//! The attestation policy is deliberately NOT part of `SecuritySettings`'s
//! org/tenant inheritance model (see `axiam_core::models::webauthn_policy`'s
//! module docs for why — no total order on AAGUID allow/block lists), so it
//! should not share that pair's permission surface either: an admin with
//! `settings:update` should not automatically be able to change which
//! security keys a tenant accepts.

use actix_web::{HttpResponse, web};
use axiam_auth::attestation::{ComplianceStatus, UNKNOWN_CREDENTIAL_REASON};
use axiam_core::error::AxiamError;
use axiam_core::models::webauthn_policy::{
    UnknownAaguidAction, WebauthnAttestationPolicy, validate_attestation_policy,
};
use axiam_core::repository::{WebauthnAttestationPolicyRepository, WebauthnCredentialRepository};
use serde::Serialize;
use surrealdb::Connection;
use uuid::Uuid;

use crate::authz::{AuthzData, RequirePermission};
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

/// `GET` response: the stored policy plus the unknown-AAGUID action it
/// currently *resolves to*.
///
/// `unknown_aaguid` is nullable, where `null` means "use this mode's
/// default" (deny under `direct_required`, allow otherwise). A client that
/// only saw the stored `null` would have to re-derive that rule itself to
/// display what the policy actually does — and a security rule implemented
/// twice is a security rule that will eventually disagree with itself. So
/// the server resolves it once, here, and reports both: the admin's stored
/// intent and its effect.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PolicyResponse {
    #[serde(flatten)]
    pub policy: WebauthnAttestationPolicy,
    /// The action actually applied to an AAGUID with no MDS metadata,
    /// with `unknown_aaguid: null` resolved against `mode`. Read-only —
    /// `PUT` ignores it.
    pub effective_unknown_aaguid: UnknownAaguidAction,
}

impl From<WebauthnAttestationPolicy> for PolicyResponse {
    fn from(policy: WebauthnAttestationPolicy) -> Self {
        Self {
            effective_unknown_aaguid: policy.effective_unknown_aaguid(),
            policy,
        }
    }
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// One credential's compliance outcome (D9).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ComplianceReportEntry {
    pub credential_id: Uuid,
    pub user_id: Uuid,
    /// The credential's user-assigned name (`WebauthnCredential::name`),
    /// not the owning user's account name.
    pub name: String,
    pub aaguid: Option<Uuid>,
    pub authenticator_name: Option<String>,
    /// `false` only for a genuine policy violation
    /// ([`ComplianceStatus::NonCompliant`]) — a credential with no recorded
    /// AAGUID ([`ComplianceStatus::Unknown`], D9's pre-X3 case) is always
    /// `true` here, never reported as a violation.
    pub compliant: bool,
    /// `None` only when `compliant` and the credential has a recorded
    /// AAGUID; set for every non-compliant *and* every "unknown" (pre-X3)
    /// credential.
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tenant_scope_check(user: &AuthenticatedUser, tenant_id: Uuid) -> Result<(), AxiamApiError> {
    if tenant_id != user.tenant_id {
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason: "cannot access WebAuthn attestation policy for a different tenant".into(),
            action: None,
            resource_id: None,
        }));
    }
    Ok(())
}

/// `AttestationDenyReason` serializes `snake_case` (its own
/// `#[serde(rename_all = "snake_case")]`) — reuse that exact wire
/// representation for the compliance report's `reason` string instead of a
/// separate `{reason:?}` Debug format, so the two surfaces agree.
fn deny_reason_str(reason: axiam_core::models::webauthn_policy::AttestationDenyReason) -> String {
    serde_json::to_value(reason)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{reason:?}"))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/v1/tenants/{tenant_id}/webauthn/attestation-policy`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy",
    tag = "webauthn-policy",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Effective WebAuthn attestation policy \
            (defaults returned when no policy row exists — D5)",
         body = PolicyResponse),
    ),
    security(("bearer" = []))
)]
pub async fn get_policy<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("webauthn_policy:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    tenant_scope_check(&user, tenant_id)?;

    let policy = state
        .webauthn_attestation_policy_repo
        .get_by_tenant(tenant_id)
        .await?
        .unwrap_or_default();
    Ok(HttpResponse::Ok().json(PolicyResponse::from(policy)))
}

/// `PUT /api/v1/tenants/{tenant_id}/webauthn/attestation-policy`
#[utoipa::path(
    put,
    path = "/api/v1/tenants/{tenant_id}/webauthn/attestation-policy",
    tag = "webauthn-policy",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    request_body = WebauthnAttestationPolicy,
    responses(
        (status = 200, description = "Policy updated", body = WebauthnAttestationPolicy),
        (status = 400, description = "Config error — e.g. require_fido_certified/\
            min_certification set with mode: none"),
    ),
    security(("bearer" = []))
)]
pub async fn set_policy<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
    body: web::Json<WebauthnAttestationPolicy>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("webauthn_policy:write", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    tenant_scope_check(&user, tenant_id)?;

    let input = body.into_inner();
    validate_attestation_policy(&input)?;

    let saved = state
        .webauthn_attestation_policy_repo
        .set(tenant_id, input)
        .await?;

    // W2-D3: a stale cached AttestationCaList built under the OLD
    // allowed_aaguids restriction must not survive a policy change. The
    // repository's own `.set()` already emits the `webauthn.policy_updated`
    // structured audit event (D11); this HTTP mutation is additionally
    // captured by the generic per-request `AuditMiddleware` wired in
    // `axiam-server/src/main.rs` (method + path + actor + outcome).
    state.attestation_ca_cache.invalidate();

    Ok(HttpResponse::Ok().json(saved))
}

/// `GET /api/v1/tenants/{tenant_id}/webauthn/compliance-report`
#[utoipa::path(
    get,
    path = "/api/v1/tenants/{tenant_id}/webauthn/compliance-report",
    tag = "webauthn-policy",
    params(
        ("tenant_id" = Uuid, Path, description = "Tenant ID"),
    ),
    responses(
        (status = 200, description = "Per-credential compliance report against the \
            current policy — never mutates or revokes anything",
         body = [ComplianceReportEntry]),
    ),
    security(("bearer" = []))
)]
pub async fn compliance_report<C: Connection + Clone>(
    user: AuthenticatedUser,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, AxiamApiError> {
    RequirePermission::new("webauthn_policy:read", Uuid::nil())
        .check(&user, authz.get_ref().as_ref())
        .await?;
    let tenant_id = path.into_inner();
    tenant_scope_check(&user, tenant_id)?;

    let policy = state
        .webauthn_attestation_policy_repo
        .get_by_tenant(tenant_id)
        .await?
        .unwrap_or_default();

    let credentials = state
        .webauthn_credential_repo
        .list_by_tenant(tenant_id)
        .await?;

    let mut out = Vec::with_capacity(credentials.len());
    for cred in credentials {
        let status = axiam_auth::attestation::evaluate_credential_compliance(
            &policy,
            cred.aaguid,
            cred.attestation_format.as_deref(),
            &state.attestation_metadata_source,
        )
        .await?;

        let (compliant, reason) = match status {
            ComplianceStatus::Compliant => (true, None),
            ComplianceStatus::NonCompliant(r) => (false, Some(deny_reason_str(r))),
            // D9: "never as a violation" — always compliant=true, with the
            // fixed pre-X3 explanation as the reason.
            ComplianceStatus::Unknown => (true, Some(UNKNOWN_CREDENTIAL_REASON.to_string())),
        };

        out.push(ComplianceReportEntry {
            credential_id: cred.id,
            user_id: cred.user_id,
            name: cred.name,
            aaguid: cred.aaguid,
            authenticator_name: cred.authenticator_name,
            compliant,
            reason,
        });
    }

    Ok(HttpResponse::Ok().json(out))
}

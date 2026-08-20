//! Secure Remote Password endpoints — `POST /api/v1/auth/srp/challenge` and
//! `POST /api/v1/auth/srp/verify`.
//!
//! These are a *sibling* of `POST /api/v1/auth/login`, not a replacement. They
//! establish the same fact — this principal knows the password — by a route
//! that never puts the password on the wire, and then hand off to the exact
//! same post-credential path
//! ([`axiam_auth::AuthService::complete_authenticated_login`]), so MFA policy,
//! account status, the `login.post_auth` reactor hook, lockout accounting and
//! session issuance are identical on both. That shared tail is the point: two
//! parallel implementations of "what happens after a successful login" is how a
//! deployment ends up with MFA enforced on one path and not the other.
//!
//! # Enumeration
//!
//! `/auth/srp/challenge` answers `200` for every syntactically valid request,
//! including one naming a user who does not exist, a user in another tenant, or
//! a user with no verifier. The fabricated challenge is described in
//! [`axiam_auth::srp`]. Anything else here would make this endpoint a faster
//! account-enumeration oracle than the rest of the API, which is exactly the
//! kind of regression that "we added a security feature" is supposed to
//! preclude.
//!
//! The one case that is *not* disguised is `srp_mode = disabled`, which returns
//! `404`: that is a property of the tenant, not of any user, so revealing it
//! leaks nothing about who exists.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::LoginResult;
use axiam_core::error::AxiamError;
use axiam_core::models::srp::{SrpKdfParams, SrpMode, SrpVerifyRequest};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, SrpCredentialRepository, TenantRepository,
    UserRepository,
};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::client_info::{client_ip, user_agent};
use crate::handlers::auth::{
    MfaRequiredResponse, MfaSetupRequiredResponse, cookie_response_from_output,
};
use crate::state::AppState;

// -----------------------------------------------------------------------
// Wire types
// -----------------------------------------------------------------------

/// Request body for `POST /api/v1/auth/srp/challenge`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct SrpChallengeRequest {
    /// Tenant UUID. Either this or `tenant_slug` is required.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    /// Organization UUID. Either this or `org_slug` is required.
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// Tenant slug alternative to `tenant_id`.
    #[serde(default)]
    pub tenant_slug: Option<String>,
    /// Organization slug alternative to `org_id`.
    #[serde(default)]
    pub org_slug: Option<String>,
    /// Username or email the human typed. The response's `identity` field, not
    /// this, is what goes into the KDF.
    #[serde(alias = "username")]
    pub username_or_email: String,
    /// Client public ephemeral `A = g^a mod N`, lowercase hex.
    pub client_public: String,
}

/// `POST /api/v1/auth/srp/verify` success body.
///
/// Shape-compatible with `LoginSuccessResponse` plus `server_proof`; tokens
/// still arrive as `Set-Cookie`, exactly as on the password path.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct SrpVerifyResponse {
    /// Server proof `M2`, lowercase hex.
    ///
    /// A client MUST check this before treating the session as good. Skipping
    /// it throws away half of what SRP provides — without it the client has
    /// authenticated itself to the server but has not authenticated the
    /// server, so a rogue endpoint that never knew the verifier is
    /// indistinguishable from the real one.
    pub server_proof: String,
}

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/auth/srp/challenge`
#[utoipa::path(
    post,
    path = "/api/v1/auth/srp/challenge",
    tag = "auth",
    request_body = SrpChallengeRequest,
    responses(
        (status = 200, description = "SRP challenge (identical shape for unknown identities)", body = axiam_core::models::srp::SrpChallenge),
        (status = 400, description = "Malformed client public value or missing workspace identity"),
        (status = 404, description = "SRP is not enabled for this tenant"),
        (status = 503, description = "SRP is enabled but the server has no session key configured"),
    )
)]
pub async fn srp_challenge<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<SrpChallengeRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let (org_id, tenant_id) = resolve_workspace(
        &state,
        b.org_id,
        b.org_slug.as_deref(),
        b.tenant_id,
        b.tenant_slug.as_deref(),
    )
    .await?;

    let settings = state
        .settings_repo
        .get_effective_settings(org_id, tenant_id)
        .await?;
    let policy = &settings.srp;

    if policy.srp_mode == SrpMode::Disabled {
        return Err(AxiamApiError(AxiamError::NotFound {
            entity: "srp".into(),
            id: "disabled".into(),
        }));
    }

    // A configured policy with no key is a misconfiguration, and it must look
    // like one. Falling through to "no SRP available" would let an operator
    // believe a control is on while every client silently uses password login.
    let Some(srp) = state.srp_server.as_ref() else {
        return Err(AxiamApiError(AxiamError::Internal(
            "SRP is enabled but AXIAM__AUTH__SRP_SESSION_KEY is not configured".into(),
        )));
    };

    // Look up the user; a miss at any step falls through to the simulated
    // branch rather than returning an error, so all four outcomes — unknown
    // name, wrong tenant, known user without a verifier, known user with one —
    // are indistinguishable from outside.
    let credential = match lookup_user_id(&state, tenant_id, &b.username_or_email).await {
        Some(user_id) => state
            .srp_credential_repo
            .get_by_user(tenant_id, user_id)
            .await
            .ok(),
        None => None,
    };

    let challenge = match credential {
        Some(cred) => srp
            .challenge(&cred, org_id, &b.client_public)
            .map_err(AxiamError::from)?,
        None => srp
            .simulated_challenge(
                policy.srp_group,
                SrpKdfParams::defaults_for(policy.srp_kdf),
                &b.username_or_email,
                tenant_id,
                org_id,
                &b.client_public,
            )
            .map_err(AxiamError::from)?,
    };

    Ok(HttpResponse::Ok().json(challenge))
}

/// `POST /api/v1/auth/srp/verify`
///
/// Returns the same three outcomes as `POST /api/v1/auth/login` — `200` with
/// session cookies, `202` for an MFA challenge, `403` for MFA setup — so a
/// client can share one result handler across both login paths.
#[utoipa::path(
    post,
    path = "/api/v1/auth/srp/verify",
    tag = "auth",
    request_body = SrpVerifyRequest,
    responses(
        (status = 200, description = "Login successful; body carries the server proof M2", body = SrpVerifyResponse),
        (status = 202, description = "MFA challenge required", body = MfaRequiredResponse),
        (status = 403, description = "MFA setup required", body = MfaSetupRequiredResponse),
        (status = 401, description = "Invalid proof, expired session, or unknown identity"),
    )
)]
pub async fn srp_verify<C: Connection + Clone>(
    req: HttpRequest,
    state: web::Data<AppState<C>>,
    body: web::Json<SrpVerifyRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();

    let Some(srp) = state.srp_server.as_ref() else {
        return Err(AxiamApiError(AxiamError::Internal(
            "SRP is enabled but AXIAM__AUTH__SRP_SESSION_KEY is not configured".into(),
        )));
    };

    let verified = match srp.verify(&b.srp_session, &b.client_proof) {
        Ok(verified) => verified,
        Err(rejection) => {
            // A wrong proof is a wrong password: it must move the lockout
            // counter exactly as a failed Argon2id verify on `/auth/login`
            // does. Without this, enabling SRP would quietly remove
            // brute-force protection from the accounts that adopted it.
            if let axiam_auth::SrpRejection::BadProof {
                tenant_id,
                user_id: Some(user_id),
            } = rejection
            {
                // Best-effort: a bookkeeping failure must not turn a 401 into
                // a 500 and hand the caller a way to tell the two apart.
                if let Err(e) = state
                    .auth_service
                    .record_failed_srp_attempt(tenant_id, user_id)
                    .await
                {
                    tracing::warn!(
                        target: "axiam::auth",
                        tenant_id = %tenant_id,
                        user_id = %user_id,
                        error = %e,
                        "failed to record an SRP lockout attempt"
                    );
                }
            }
            // Every rejection reason collapses to one 401 here; the variants
            // exist for the accounting above, never for the caller.
            return Err(AxiamApiError(AxiamError::AuthenticationFailed {
                reason: "invalid credentials".into(),
            }));
        }
    };

    let user = state
        .user_repo
        .get_by_id(verified.tenant_id, verified.user_id)
        .await
        .map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid credentials".into(),
        })?;

    // Lockout is checked here rather than at challenge time on purpose: the
    // challenge must stay indistinguishable for every identity, and refusing it
    // for a locked account would announce that the account exists and is under
    // attack.
    if axiam_auth::lockout::is_locked_out(&user) {
        return Err(AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "invalid credentials".into(),
        }));
    }

    let mfa_policy = Some(
        state
            .settings_repo
            .get_effective_settings(verified.org_id, verified.tenant_id)
            .await
            .map(|s| s.mfa)?,
    );

    let result = state
        .auth_service
        .complete_authenticated_login(
            user,
            verified.tenant_id,
            verified.org_id,
            client_ip(&req),
            user_agent(&req),
            mfa_policy,
        )
        .await?;

    match result {
        LoginResult::Success(out) => {
            // The same builder the password path uses, so the cookie set, the
            // CSRF header and the body shape cannot drift between the two.
            cookie_response_from_output(
                &out,
                &state.auth_config,
                &state.user_repo,
                &state.tenant_repo,
                &state.org_repo,
                Some(verified.server_proof),
            )
            .await
        }
        LoginResult::MfaRequired(mut challenge) => {
            if let Ok((user_id, tenant_id, _org_id)) = state
                .auth_service
                .decode_mfa_challenge_ids(&challenge.challenge_token)
                && let Ok(types) = state
                    .mfa_method_service
                    .available_method_types(tenant_id, user_id)
                    .await
            {
                challenge.available_methods = types;
            }
            Ok(HttpResponse::Accepted().json(serde_json::json!({
                "mfa_required": true,
                "challenge_token": challenge.challenge_token,
                "available_methods": challenge.available_methods,
                "server_proof": verified.server_proof,
            })))
        }
        LoginResult::MfaSetupRequired(setup) => {
            Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "mfa_setup_required": true,
                "setup_token": setup.setup_token,
                "server_proof": verified.server_proof,
            })))
        }
    }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Resolve `(org_id, tenant_id)` from UUIDs or slugs and prove the tenant
/// belongs to the organization.
///
/// The binding check is the same one `POST /auth/login` performs (NEW-1): a
/// client passing raw UUIDs could otherwise bind their own tenant to a foreign
/// `org_id` and get a token scoped to that organization. Every failure maps to
/// an enumeration-safe `Validation`/`NotFound` that says nothing about which
/// part was wrong.
async fn resolve_workspace<C: Connection + Clone>(
    state: &AppState<C>,
    org_id: Option<Uuid>,
    org_slug: Option<&str>,
    tenant_id: Option<Uuid>,
    tenant_slug: Option<&str>,
) -> Result<(Uuid, Uuid), AxiamApiError> {
    let org_id = match (org_id, org_slug) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            state
                .org_repo
                .get_by_slug(slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid credentials".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide org_id or org_slug".into(),
            }));
        }
    };

    let tenant_id = match (tenant_id, tenant_slug) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            state
                .tenant_repo
                .get_by_slug(org_id, slug)
                .await
                .map_err(|_| AxiamError::AuthenticationFailed {
                    reason: "invalid credentials".into(),
                })?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide tenant_id or tenant_slug".into(),
            }));
        }
    };

    let tenant = state.tenant_repo.get_by_id(tenant_id).await.map_err(|_| {
        AxiamError::AuthenticationFailed {
            reason: "invalid credentials".into(),
        }
    })?;
    if tenant.organization_id != org_id {
        return Err(AxiamApiError(AxiamError::AuthenticationFailed {
            reason: "invalid credentials".into(),
        }));
    }

    Ok((tenant.organization_id, tenant_id))
}

/// Resolve a username-or-email to a user id, or `None`.
///
/// Deliberately swallows every error into `None`: the caller's next step is the
/// enumeration-safe simulated challenge, and surfacing "no such user" as an
/// error here would defeat it.
async fn lookup_user_id<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    username_or_email: &str,
) -> Option<Uuid> {
    if let Ok(user) = state
        .user_repo
        .get_by_username(tenant_id, username_or_email)
        .await
    {
        return Some(user.id);
    }
    state
        .user_repo
        .get_by_email(tenant_id, username_or_email)
        .await
        .ok()
        .map(|user| user.id)
}

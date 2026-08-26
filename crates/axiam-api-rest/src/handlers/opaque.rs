//! OPAQUE endpoints — `POST /api/v1/auth/opaque/register/start`,
//! `POST /api/v1/auth/opaque/login/start` and
//! `POST /api/v1/auth/opaque/login/finish`.
//!
//! The login pair is a *sibling* of `POST /api/v1/auth/login`, not a
//! replacement. They establish the same fact — this principal knows the
//! password — by a route that never puts the password on the wire, and then
//! hand off to the exact same post-credential path
//! ([`axiam_auth::AuthService::complete_authenticated_login`]), so MFA policy,
//! account status, the `login.post_auth` reactor hook, lockout accounting and
//! session issuance are identical on both. That shared tail is the point: two
//! parallel implementations of "what happens after a successful login" is how
//! a deployment ends up with MFA enforced on one path and not the other.
//!
//! # Why there is no `register/finish` endpoint
//!
//! A registration record can only be built at a moment when the plaintext
//! password legitimately exists on the client, and every one of those moments
//! — user creation, an authenticated password change, reset completion,
//! first-run bootstrap — is already an endpoint that takes a password. Each of
//! those grew an `opaque` field carrying the finished record, exactly where
//! the SRP implementation carried an `srp` verifier. A free-standing finish
//! would be an endpoint whose only job is to attach a credential to an
//! account, which is a thing worth not having.
//!
//! # Enumeration
//!
//! `/auth/opaque/login/start` answers `200` for every syntactically valid
//! request, including one naming a user who does not exist, a user in another
//! tenant, or a user with no record. The decoy exchange is described in
//! [`axiam_auth::opaque`]. Anything else here would make this endpoint a
//! faster account-enumeration oracle than the rest of the API, which is
//! exactly the kind of regression that "we added a security feature" is
//! supposed to preclude.
//!
//! The one case that is *not* disguised is `opaque_mode = disabled`, which
//! returns `404`: that is a property of the tenant, not of any user, so
//! revealing it leaks nothing about who exists.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::LoginResult;
use axiam_core::error::AxiamError;
use axiam_core::models::opaque::{
    OpaqueKsfParams, OpaqueLoginFinishRequest, OpaqueLoginStartRequest, OpaqueMode,
    OpaqueRegisterStartRequest,
};
use axiam_core::repository::{
    OpaqueCredentialRepository, OpaqueServerSetupRepository, OrganizationRepository,
    SettingsRepository, TenantRepository, UserRepository,
};
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;
use crate::extractors::client_info::{client_ip, user_agent};
use crate::handlers::auth::{
    MfaRequiredResponse, MfaSetupRequiredResponse, cookie_response_from_output,
};
use crate::state::AppState;

// -----------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------

/// `POST /api/v1/auth/opaque/register/start`
#[utoipa::path(
    post,
    path = "/api/v1/auth/opaque/register/start",
    tag = "auth",
    request_body = OpaqueRegisterStartRequest,
    responses(
        (status = 200, description = "OPRF evaluation and the KSF parameters to stretch with", body = axiam_core::models::opaque::OpaqueRegisterStartResponse),
        (status = 400, description = "Malformed registration request or missing workspace identity"),
        (status = 404, description = "OPAQUE is not enabled for this tenant"),
        (status = 503, description = "OPAQUE is enabled but the server has no keys configured"),
    )
)]
pub async fn opaque_register_start<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<OpaqueRegisterStartRequest>,
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
    let policy = &settings.opaque;

    if policy.opaque_mode == OpaqueMode::Disabled {
        return Err(AxiamApiError(AxiamError::NotFound {
            entity: "opaque".into(),
            id: "disabled".into(),
        }));
    }

    let opaque = opaque_server(&state)?;
    let setup = server_setup(&state, tenant_id, policy.opaque_suite).await?;

    let response = opaque
        .register_start(
            &setup,
            OpaqueKsfParams::defaults_for(policy.opaque_ksf),
            &b.registration_request,
        )
        .map_err(AxiamError::from)?;

    Ok(HttpResponse::Ok().json(response))
}

/// `POST /api/v1/auth/opaque/login/start`
#[utoipa::path(
    post,
    path = "/api/v1/auth/opaque/login/start",
    tag = "auth",
    request_body = OpaqueLoginStartRequest,
    responses(
        (status = 200, description = "KE2 (identical shape for unknown identities)", body = axiam_core::models::opaque::OpaqueLoginStartResponse),
        (status = 400, description = "Malformed KE1 or missing workspace identity"),
        (status = 404, description = "OPAQUE is not enabled for this tenant"),
        (status = 503, description = "OPAQUE is enabled but the server has no keys configured"),
    )
)]
pub async fn opaque_login_start<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<OpaqueLoginStartRequest>,
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
    let policy = &settings.opaque;

    if policy.opaque_mode == OpaqueMode::Disabled {
        return Err(AxiamApiError(AxiamError::NotFound {
            entity: "opaque".into(),
            id: "disabled".into(),
        }));
    }

    let opaque = opaque_server(&state)?;
    let setup = server_setup(&state, tenant_id, policy.opaque_suite).await?;

    // Look up the user; a miss at any step falls through to the decoy branch
    // rather than returning an error, so all four outcomes — unknown name,
    // wrong tenant, known user without a record, known user with one — are
    // indistinguishable from outside.
    let credential = match lookup_user_id(&state, tenant_id, &b.username_or_email).await {
        Some(user_id) => state
            .opaque_credential_repo
            .get_by_user(tenant_id, user_id)
            .await
            .ok(),
        None => None,
    };

    let mut started = match credential {
        Some(cred) => opaque
            .login_start(&setup, &cred, org_id, &b.ke1)
            .map_err(AxiamError::from)?,
        None => opaque
            .login_start_decoy(
                &setup,
                OpaqueKsfParams::defaults_for(policy.opaque_ksf),
                &b.username_or_email,
                tenant_id,
                org_id,
                &b.ke1,
            )
            .map_err(AxiamError::from)?,
    };

    // Stamped here rather than in `axiam-auth`, which holds no settings. It is
    // the same value for both branches above — a property of the tenant, not
    // of whether this particular identity has a record — so it cannot be used
    // to tell the decoy exchange from a real one.
    started.mode = policy.opaque_mode;

    Ok(HttpResponse::Ok().json(started))
}

/// `POST /api/v1/auth/opaque/login/finish`
///
/// Returns the same three outcomes as `POST /api/v1/auth/login` — `200` with
/// session cookies, `202` for an MFA challenge, `403` for MFA setup — so a
/// client can share one result handler across both login paths.
///
/// Note what this response does *not* carry, where the SRP one did: a server
/// proof. Under SRP the client had to verify `M2` itself or it would have
/// authenticated to a server that never knew the verifier. RFC 9807's AKE
/// authenticates the server as part of the handshake — a client that
/// successfully opens `KE2` has already proved the server holds the record —
/// so there is nothing left for the client to check afterwards, and an SDK
/// cannot forget to.
#[utoipa::path(
    post,
    path = "/api/v1/auth/opaque/login/finish",
    tag = "auth",
    request_body = OpaqueLoginFinishRequest,
    responses(
        (status = 200, description = "Login successful; tokens arrive as cookies"),
        (status = 202, description = "MFA challenge required", body = MfaRequiredResponse),
        (status = 403, description = "MFA setup required", body = MfaSetupRequiredResponse),
        (status = 401, description = "Invalid credentials, expired session, or unknown identity"),
    )
)]
pub async fn opaque_login_finish<C: Connection + Clone>(
    req: HttpRequest,
    state: web::Data<AppState<C>>,
    body: web::Json<OpaqueLoginFinishRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let opaque = opaque_server(&state)?;

    let verified = match opaque.login_finish(&b.opaque_session, &b.ke3) {
        Ok(verified) => verified,
        Err(rejection) => {
            // A failed KE3 is a wrong password: it must move the lockout
            // counter exactly as a failed Argon2id verify on `/auth/login`
            // does. Without this, enabling OPAQUE would quietly remove
            // brute-force protection from the accounts that adopted it.
            if let axiam_auth::OpaqueRejection::BadCredentials {
                tenant_id,
                user_id: Some(user_id),
            } = rejection
            {
                // Meter against the tenant's own threshold, the same one
                // `/auth/login` uses — otherwise the accounts that adopted
                // OPAQUE would lock on a different (and higher, deployment
                // default) count than the administrator configured.
                //
                // Resolving it needs the organization, and the only thing in
                // hand at this point is the tenant: `login_finish` rejected
                // before establishing anything else. A lookup failure falls
                // through to `None`, which meters against the deployment
                // default rather than not metering at all.
                let lockout_policy = match state.tenant_repo.get_by_id(tenant_id).await {
                    Ok(tenant) => state
                        .settings_repo
                        .get_effective_settings(tenant.organization_id, tenant_id)
                        .await
                        .ok()
                        .map(|s| s.lockout),
                    Err(_) => None,
                };

                // Best-effort: a bookkeeping failure must not turn a 401 into
                // a 500 and hand the caller a way to tell the two apart.
                if let Err(e) = state
                    .auth_service
                    .record_failed_opaque_attempt(tenant_id, user_id, lockout_policy.as_ref())
                    .await
                {
                    tracing::warn!(
                        target: "axiam::auth",
                        tenant_id = %tenant_id,
                        user_id = %user_id,
                        error = %e,
                        "failed to record an OPAQUE lockout attempt"
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

    // Lockout is checked here rather than at login/start on purpose: the start
    // response must stay indistinguishable for every identity, and refusing it
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
            })))
        }
        LoginResult::MfaSetupRequired(setup) => {
            Ok(HttpResponse::Forbidden().json(serde_json::json!({
                "mfa_setup_required": true,
                "setup_token": setup.setup_token,
            })))
        }
    }
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Fetch the configured OPAQUE server, or fail loudly.
///
/// A configured policy with no keys is a misconfiguration, and it must look
/// like one. Falling through to "no OPAQUE available" would let an operator
/// believe a control is on while every client silently uses password login.
pub(crate) fn opaque_server<C: Connection + Clone>(
    state: &AppState<C>,
) -> Result<&axiam_auth::OpaqueServer, AxiamApiError> {
    state.opaque_server.as_ref().ok_or_else(|| {
        AxiamApiError(AxiamError::Internal(
            "OPAQUE is enabled but AXIAM__AUTH__OPAQUE_SESSION_KEY / \
             AXIAM__AUTH__OPAQUE_SETUP_KEY are not configured"
                .into(),
        ))
    })
}

/// Fetch a tenant's OPAQUE key material, minting it on first use.
///
/// The mint-on-first-use is why this is a helper rather than an inline read:
/// `get_or_create` must be the only way key material comes into existence, so
/// that two concurrent first logins cannot end up writing two different OPRF
/// seeds for one tenant. A tenant with two seeds has records that only
/// sometimes open, which presents as an intermittent wrong password.
pub(crate) async fn server_setup<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    suite: axiam_core::models::opaque::OpaqueSuite,
) -> Result<axiam_core::models::opaque::OpaqueServerSetup, AxiamApiError> {
    let opaque = opaque_server(state)?;
    let fresh = opaque
        .create_server_setup(tenant_id, suite)
        .map_err(AxiamError::from)?;
    Ok(state.opaque_setup_repo.get_or_create(fresh).await?)
}

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
/// enumeration-safe decoy exchange, and surfacing "no such user" as an error
/// here would defeat it.
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

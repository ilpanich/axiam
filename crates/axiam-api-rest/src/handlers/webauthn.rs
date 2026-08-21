//! WebAuthn passkey registration and authentication endpoints.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::models::webauthn_credential::WebauthnCredentialType;
use axiam_core::repository::WebauthnAttestationPolicyRepository;
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;
use webauthn_rs_proto::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::{client_ip, user_agent};
use crate::state::AppState;

// -------------------------------------------------------------------
// Request / response types
// -------------------------------------------------------------------

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StartRegistrationResponse {
    #[schema(value_type = Object)]
    pub challenge: CreationChallengeResponse,
    pub state_token: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FinishRegistrationRequest {
    pub state_token: String,
    pub credential_name: String,
    #[schema(value_type = Object)]
    pub response: RegisterPublicKeyCredential,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CredentialResponse {
    pub id: Uuid,
    pub credential_id: String,
    pub name: String,
    pub credential_type: WebauthnCredentialType,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StartAuthenticationRequest {
    pub challenge_token: String,
}

/// Body of `POST /api/v1/auth/webauthn/authenticate/discoverable/start`.
///
/// There is no `challenge_token` here, and that is the whole point: a
/// usernameless ceremony has no prior login step to carry one. What it does
/// need is the workspace, because a discoverable credential still has to be
/// resolved inside one tenant's isolation boundary. Slugs and UUIDs are both
/// accepted, matching `POST /api/v1/auth/login`.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StartDiscoverableAuthenticationRequest {
    #[serde(default)]
    pub org_id: Option<Uuid>,
    #[serde(default)]
    pub org_slug: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    #[serde(default)]
    pub tenant_slug: Option<String>,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct StartAuthenticationResponse {
    #[schema(value_type = Object)]
    pub challenge: RequestChallengeResponse,
    pub state_token: String,
}

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct FinishAuthenticationRequest {
    pub state_token: String,
    #[schema(value_type = Object)]
    pub response: PublicKeyCredential,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct WebauthnLoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub expires_in: u64,
}

// -------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------

/// Extract tenant_id from an unverified JWT state token by
/// base64-decoding the payload segment.  This is safe because the
/// token will be fully verified by `WebauthnService::finish_authentication`;
/// we only peek to route the request to the correct tenant scope.
fn peek_tenant_id(state_token: &str) -> Result<Uuid, AxiamApiError> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let parts: Vec<&str> = state_token.split('.').collect();
    if parts.len() != 3 {
        return Err(AxiamApiError(
            axiam_core::error::AxiamError::AuthenticationFailed {
                reason: "invalid state token".into(),
            },
        ));
    }

    let payload = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| {
        AxiamApiError(axiam_core::error::AxiamError::AuthenticationFailed {
            reason: "invalid state token payload".into(),
        })
    })?;

    #[derive(Deserialize)]
    struct Peek {
        tenant_id: String,
    }

    let peek: Peek = serde_json::from_slice(&payload).map_err(|_| {
        AxiamApiError(axiam_core::error::AxiamError::AuthenticationFailed {
            reason: "invalid state token claims".into(),
        })
    })?;

    peek.tenant_id.parse().map_err(|_| {
        AxiamApiError(axiam_core::error::AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id in state token".into(),
        })
    })
}

// -------------------------------------------------------------------
// Handlers
// -------------------------------------------------------------------

/// `POST /api/v1/auth/webauthn/register/start`
///
/// Begin a WebAuthn passkey registration ceremony for the
/// authenticated user.
///
/// X3 wave 3: routes through
/// [`WebauthnService::start_registration_for_policy`], resolving the
/// tenant's [`WebauthnAttestationPolicy`](axiam_core::models::webauthn_policy::WebauthnAttestationPolicy)
/// first (an absent row is `WebauthnAttestationPolicy::default()` — `mode:
/// none`, today's behavior unchanged). This is the single call-site switch
/// that makes attestation enforcement live: calling
/// [`WebauthnService::start_registration`] directly here would silently
/// downgrade every tenant to the unattested ceremony regardless of policy.
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/register/start",
    tag = "webauthn",
    responses(
        (status = 200, description = "Registration challenge",
         body = StartRegistrationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 503, description = "Attestation policy requires attestation but no \
            FIDO metadata is available (W2-D3 fail-closed)"),
    ),
    security(("bearer" = []))
)]
pub async fn start_registration<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let user_name = user.user_id.to_string();
    let policy = state
        .webauthn
        .webauthn_attestation_policy_repo
        .get_by_tenant(user.tenant_id)
        .await?
        .unwrap_or_default();

    let (challenge, state_token) = state
        .webauthn
        .webauthn_service
        .start_registration_for_policy(
            user.tenant_id,
            user.org_id,
            user.user_id,
            &user_name,
            &policy,
            &state.webauthn.attestation_metadata_source,
            &state.webauthn.attestation_ca_cache,
        )
        .await?;

    Ok(HttpResponse::Ok().json(StartRegistrationResponse {
        challenge,
        state_token,
    }))
}

/// `POST /api/v1/auth/webauthn/register/finish`
///
/// Complete a WebAuthn passkey registration ceremony.
///
/// X3 wave 3: routes through
/// [`WebauthnService::finish_registration_for_policy`], which dispatches on
/// which ceremony the state token was minted for and re-checks it against
/// the policy **currently** in force (see that method's docs for why a
/// policy tightened mid-ceremony still denies).
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/register/finish",
    tag = "webauthn",
    request_body = FinishRegistrationRequest,
    responses(
        (status = 201, description = "Credential registered",
         body = CredentialResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Denied by the tenant's attestation policy \
            (this security key model is not permitted by your organization)"),
    ),
    security(("bearer" = []))
)]
pub async fn finish_registration<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
    body: web::Json<FinishRegistrationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let policy = state
        .webauthn
        .webauthn_attestation_policy_repo
        .get_by_tenant(user.tenant_id)
        .await?
        .unwrap_or_default();

    let cred = state
        .webauthn
        .webauthn_service
        .finish_registration_for_policy(
            user.tenant_id,
            user.user_id,
            &b.state_token,
            &b.credential_name,
            &b.response,
            &policy,
            &state.webauthn.attestation_metadata_source,
            &state.webauthn.attestation_ca_cache,
        )
        .await?;

    Ok(HttpResponse::Created().json(CredentialResponse {
        id: cred.id,
        credential_id: cred.credential_id,
        name: cred.name,
        credential_type: cred.credential_type,
        created_at: cred.created_at.to_rfc3339(),
        last_used_at: cred.last_used_at.map(|t| t.to_rfc3339()),
    }))
}

/// `POST /api/v1/auth/webauthn/authenticate/start`
///
/// Begin a WebAuthn passkey authentication ceremony.  Requires a
/// valid MFA challenge token (obtained from the login flow).
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/authenticate/start",
    tag = "webauthn",
    request_body = StartAuthenticationRequest,
    responses(
        (status = 200, description = "Authentication challenge",
         body = StartAuthenticationResponse),
        (status = 401, description = "Invalid challenge token"),
    )
)]
pub async fn start_authentication<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<StartAuthenticationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let (user_id, tenant_id, org_id) = state
        .auth_service
        .decode_mfa_challenge_ids(&body.challenge_token)
        .map_err(|e| AxiamApiError(e.into()))?;

    let (challenge, state_token) = state
        .webauthn
        .webauthn_service
        .start_authentication(tenant_id, org_id, user_id)
        .await?;

    Ok(HttpResponse::Ok().json(StartAuthenticationResponse {
        challenge,
        state_token,
    }))
}

/// `POST /api/v1/auth/webauthn/authenticate/discoverable/start`
///
/// Begin a **usernameless** WebAuthn ceremony for a workspace. Needs no
/// challenge token and no username: the returned challenge carries an empty
/// `allowCredentials`, so the authenticator offers whichever discoverable
/// credential it holds and the assertion names the user.
///
/// Backs both client mediation modes — the explicit "sign in with a passkey"
/// button and conditional-mediation passkey autofill. They differ only in how
/// the browser surfaces the prompt, not in the ceremony.
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/authenticate/discoverable/start",
    tag = "webauthn",
    request_body = StartDiscoverableAuthenticationRequest,
    responses(
        (status = 200, description = "Discoverable authentication challenge",
         body = StartAuthenticationResponse),
        (status = 400, description = "Neither slug nor id given for org or tenant"),
        (status = 401, description = "Unknown organization or tenant"),
    )
)]
pub async fn start_discoverable_authentication<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    body: web::Json<StartDiscoverableAuthenticationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let (tenant_id, org_id) = resolve_workspace(&state, &b).await?;

    let (challenge, state_token) = state
        .webauthn
        .webauthn_service
        .start_discoverable_authentication(tenant_id, org_id)
        .await?;

    Ok(HttpResponse::Ok().json(StartAuthenticationResponse {
        challenge,
        state_token,
    }))
}

/// Resolve `(tenant_id, org_id)` for a usernameless ceremony.
///
/// Mirrors `handlers::auth::login`, including the two properties that matter
/// more here than they look:
///
/// * slug-resolution failures become 401 `AuthenticationFailed`, not 404, so
///   this endpoint cannot be used to enumerate which organizations and tenants
///   exist — it is reachable without any credential at all;
/// * the org is derived from the **tenant record**, never from what the client
///   sent. NEW-1 is the same bug in `login`: a caller who supplies a raw
///   `org_id` alongside their own tenant would otherwise get a ceremony — and
///   then a session token — scoped to a foreign organization.
async fn resolve_workspace<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    b: &StartDiscoverableAuthenticationRequest,
) -> Result<(Uuid, Uuid), AxiamApiError> {
    use axiam_core::error::AxiamError;
    use axiam_core::repository::{OrganizationRepository, TenantRepository};

    let unauthenticated = || AxiamError::AuthenticationFailed {
        reason: "invalid credentials".into(),
    };

    let org_id = match (b.org_id, b.org_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            state
                .org_repo
                .get_by_slug(slug)
                .await
                .map_err(|_| unauthenticated())?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide org_id or org_slug".into(),
            }));
        }
    };

    let tenant_id = match (b.tenant_id, b.tenant_slug.as_deref()) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            state
                .tenant_repo
                .get_by_slug(org_id, slug)
                .await
                .map_err(|_| unauthenticated())?
                .id
        }
        (None, None) => {
            return Err(AxiamApiError(AxiamError::Validation {
                message: "must provide tenant_id or tenant_slug".into(),
            }));
        }
    };

    // NEW-1: authoritative org comes from the tenant record, and a client that
    // named a different one is refused rather than quietly corrected.
    let tenant = state
        .tenant_repo
        .get_by_id(tenant_id)
        .await
        .map_err(|_| unauthenticated())?;
    if tenant.organization_id != org_id {
        return Err(AxiamApiError(unauthenticated()));
    }

    Ok((tenant_id, tenant.organization_id))
}

/// `POST /api/v1/auth/webauthn/authenticate/discoverable/finish`
///
/// Complete a usernameless ceremony. The user is identified by the assertion
/// itself; on success a session is created and tokens are issued.
///
/// # Why this fires `login.post_auth` when `authenticate/finish` does not
///
/// `sdks/CONTRACT.md` §22.5 excludes the ordinary WebAuthn finish because it
/// "continues a login that was already gated at its first step" — the password
/// step fired the event before ever issuing the MFA challenge token. A
/// usernameless sign-in has no such first step; it *is* the first step. Leaving
/// it out would hand an operator's `login.post_auth` veto — the embargoed-region
/// example in the feature's own docs — a bypass consisting of clicking "Sign in
/// with a passkey". That is SEC-095 exactly, which is why this uses the shared
/// `intercept_federated_login_post_auth` rather than a fourth private copy.
///
/// It takes the *federated* variant because, like SAML and OIDC, this path
/// completes in one round trip and has no step-up branch to route a
/// `require_mfa` verdict into. A reactor demanding step-up here is refused
/// rather than silently dropped. The passkey has already provided user
/// verification, so this is a UV-backed factor, not an unverified one.
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/authenticate/discoverable/finish",
    tag = "webauthn",
    request_body = FinishAuthenticationRequest,
    responses(
        (status = 200, description = "Authentication successful",
         body = WebauthnLoginResponse),
        (status = 401, description = "Authentication failed"),
    )
)]
pub async fn finish_discoverable_authentication<C: Connection + Clone>(
    req: HttpRequest,
    state: web::Data<AppState<C>>,
    body: web::Json<FinishAuthenticationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    use axiam_core::repository::UserRepository;

    let b = body.into_inner();
    let tenant_id = peek_tenant_id(&b.state_token)?;

    let (user_id, org_id) = state
        .webauthn
        .webauthn_service
        .finish_discoverable_authentication(tenant_id, &b.state_token, &b.response)
        .await?;

    let user = state
        .user_repo
        .get_by_id(tenant_id, user_id)
        .await
        .map_err(AxiamApiError)?;

    // A passkey proves possession; it does not say the account may sign in.
    // The username-bound ceremony inherits that gate from the password step
    // that minted its challenge token — this one has no such step, so a
    // deactivated, locked or anonymised user would otherwise get a session.
    state
        .auth_service
        .ensure_can_sign_in(&user)
        .map_err(|e| AxiamApiError(e.into()))?;

    // X1/SEC-095: after the assertion verifies, before any session exists.
    state
        .auth_service
        .intercept_federated_login_post_auth(
            tenant_id,
            org_id,
            &user,
            client_ip(&req).as_deref(),
            user_agent(&req).as_deref(),
        )
        .await
        .map_err(AxiamApiError)?;

    let out = state
        .auth_service
        .create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            client_ip(&req),
            user_agent(&req),
        )
        .await?;

    Ok(HttpResponse::Ok().json(WebauthnLoginResponse {
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        session_id: out.session_id,
        expires_in: out.expires_in,
    }))
}

/// `POST /api/v1/auth/webauthn/authenticate/finish`
///
/// Complete a WebAuthn passkey authentication ceremony.  On success
/// a session is created and access/refresh tokens are issued.
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/authenticate/finish",
    tag = "webauthn",
    request_body = FinishAuthenticationRequest,
    responses(
        (status = 200, description = "Authentication successful",
         body = WebauthnLoginResponse),
        (status = 401, description = "Authentication failed"),
    )
)]
pub async fn finish_authentication<C: Connection + Clone>(
    req: HttpRequest,
    state: web::Data<AppState<C>>,
    body: web::Json<FinishAuthenticationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let tenant_id = peek_tenant_id(&b.state_token)?;

    let (user_id, org_id) = state
        .webauthn
        .webauthn_service
        .finish_authentication(tenant_id, &b.state_token, &b.response)
        .await?;

    let out = state
        .auth_service
        .create_session_and_tokens(
            user_id,
            tenant_id,
            org_id,
            client_ip(&req),
            user_agent(&req),
        )
        .await?;

    Ok(HttpResponse::Ok().json(WebauthnLoginResponse {
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        session_id: out.session_id,
        expires_in: out.expires_in,
    }))
}

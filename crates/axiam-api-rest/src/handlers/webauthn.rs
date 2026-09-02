//! WebAuthn passkey registration and authentication endpoints.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::models::webauthn_credential::WebauthnCredentialType;
use axiam_core::repository::{
    MdsRepository, SettingsRepository, WebauthnAttestationPolicyRepository,
};
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
use crate::middleware::csrf::{
    HEADER_CSRF, access_cookie, csrf_cookie, generate_csrf_token, refresh_cookie,
};
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
/// accepted, matching `POST /api/v1/auth/login` — including what naming no
/// tenant means: the organization's own reserved scope, where
/// organization-level principals live.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StartDiscoverableAuthenticationRequest {
    #[serde(default)]
    pub org_id: Option<Uuid>,
    #[serde(default)]
    pub org_slug: Option<String>,
    /// Omit both tenant fields — or send an empty slug — for the
    /// organization's own scope.
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

/// Build the response for a completed WebAuthn sign-in.
///
/// Both passkey ceremonies end here, and both are **primary authentication** —
/// the same thing `POST /api/v1/auth/login` is — so they must leave the caller
/// in the same state that endpoint does.
///
/// They did not. Until this helper existed, the two `authenticate/*/finish`
/// handlers answered with the token pair in the JSON body and set no cookies at
/// all, which made a browser passkey sign-in impossible to complete: the admin
/// UI runs the ceremony, then calls `GET /api/v1/auth/me` to hydrate the
/// session, and that endpoint reads `axiam_access` from a cookie that had never
/// been set. The ceremony succeeded, the session existed server-side, and the
/// user was bounced back to the login page. `POST /api/v1/auth/refresh` was
/// unreachable for the same reason (it reads the refresh token from
/// `axiam_refresh`, never from a body), and every state-changing call after it
/// would have failed CSRF, there being no `axiam_csrf` to echo.
///
/// So this emits the same `Set-Cookie` triple and the same `X-CSRF-Token`
/// header as `cookie_response_from_output`, the password path's builder.
///
/// **The body keeps its tokens.** They are what a non-browser client uses —
/// CONTRACT.md §24 has the SDKs adopt them directly rather than digging a value
/// back out of a cookie jar — and dropping them to "match login exactly" would
/// break every such caller for a symmetry nobody asked for. Adding cookies
/// beside an unchanged body is additive on the wire: a client that reads only
/// the body sees no difference.
fn webauthn_session_response(
    config: &axiam_auth::config::AuthConfig,
    out: axiam_auth::LoginOutput,
) -> HttpResponse {
    let csrf_token = generate_csrf_token();

    HttpResponse::Ok()
        .cookie(access_cookie(
            &out.access_token,
            config.access_token_lifetime_secs,
            config.cookie_secure,
        ))
        .cookie(refresh_cookie(
            &out.refresh_token,
            config.refresh_token_lifetime_secs,
            config.cookie_secure,
        ))
        .cookie(csrf_cookie(
            &csrf_token,
            // Session lifetime, not access-token lifetime — see the note in
            // `handlers::auth`'s login response.
            config.refresh_token_lifetime_secs,
            config.cookie_secure,
        ))
        // CONTRACT.md §3 "Non-browser SDKs" — same reason as the password
        // path: a cookie jar is awkward to read one value out of, so the
        // freshly-minted CSRF token is echoed as a header too. No new
        // disclosure; `axiam_csrf` is not httpOnly and carries the same value.
        .insert_header((HEADER_CSRF, csrf_token))
        .json(WebauthnLoginResponse {
            access_token: out.access_token,
            refresh_token: out.refresh_token,
            session_id: out.session_id,
            expires_in: out.expires_in,
        })
}

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
    // Registration is about the CALLER'S OWN account, so every tenant here is
    // the one the caller lives in — never the one it is acting on. They differ
    // only for an organization-level principal that has selected a child tenant
    // in the admin UI, and reading the selected one enrolled the credential
    // against a tenant that holds no such account. The attestation policy is
    // read from the same tenant for the same reason: the policy that governs a
    // credential is the policy of the tenant the credential is stored in.
    let scope = user.principal_tenant_id;
    let policy = state
        .webauthn
        .webauthn_attestation_policy_repo
        .get_by_tenant(scope)
        .await?
        .unwrap_or_default();

    // The user-verification policy is read from the same tenant, for the same
    // reason as the attestation policy above: the policy that governs a
    // credential is the policy of the tenant the credential is stored in.
    let user_verification = state
        .settings_repo
        .get_effective_settings(user.org_id, scope)
        .await?
        .webauthn
        .webauthn_user_verification;

    let (challenge, state_token) = state
        .webauthn
        .webauthn_service
        .start_registration_for_policy(
            scope,
            user.org_id,
            user.user_id,
            &user_name,
            &policy,
            user_verification,
            &state.webauthn.attestation_metadata_source,
            &state.webauthn.attestation_ca_cache,
        )
        .await?;

    Ok(HttpResponse::Ok().json(StartRegistrationResponse {
        challenge,
        state_token,
    }))
}

/// T-153: refuse an attested registration when the ingested MDS BLOB is too
/// far past its `nextUpdate` for the operator's taste.
///
/// Runs BEFORE the ceremony is finished, not after, so a registration that is
/// going to be refused is refused without first writing a credential.
///
/// Three conditions must all hold, and each omission is deliberate:
///
/// - **The tenant's policy requires attestation.** Under
///   `AttestationMode::None` no metadata is consulted, so stale metadata
///   cannot have misled the decision and refusing would deny a registration
///   for a reason that does not apply to it.
/// - **`mds_max_stale_days > 0`.** Opt-in. The default keeps the documented
///   fail-open behaviour: a FIDO Alliance outage must not brick registration.
/// - **A BLOB has actually been ingested.** "Never ingested" is a different
///   condition from "ingested and old", and it is already handled by the
///   policy's `unknown_aaguid` setting — an empty metadata source makes every
///   AAGUID unknown. Treating never-ingested as stale here would make
///   `mds_max_stale_days` silently disable WebAuthn on a deployment that has
///   not enabled MDS at all.
async fn enforce_mds_freshness<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    policy: &axiam_core::models::webauthn_policy::WebauthnAttestationPolicy,
    tenant_id: Uuid,
    user_id: Uuid,
) -> Result<(), AxiamApiError> {
    use axiam_core::models::webauthn_policy::{AttestationDenyReason, AttestationMode};

    let max_days = state.webauthn.pki_config.mds_max_stale_days;
    if max_days == 0 || policy.mode == AttestationMode::None {
        return Ok(());
    }

    let Some(meta) = state.webauthn.mds_repo.get_meta().await? else {
        return Ok(());
    };

    let days_past = chrono::Utc::now()
        .date_naive()
        .signed_duration_since(meta.next_update)
        .num_days();
    if days_past <= i64::from(max_days) {
        return Ok(());
    }

    tracing::warn!(
        action = "webauthn.attestation_denied",
        tenant_id = %tenant_id,
        user_id = %user_id,
        reason = ?AttestationDenyReason::MetadataStale,
        days_past_next_update = days_past,
        max_stale_days = max_days,
        mds_no = meta.no,
        "WebAuthn registration denied: the ingested FIDO MDS BLOB is further past \
         its nextUpdate than AXIAM__PKI__MDS_MAX_STALE_DAYS permits, so an \
         authenticator revoked since the last refresh could not be detected"
    );
    Err(AxiamApiError(
        axiam_auth::error::AuthError::WebauthnAttestationDenied {
            reason: AttestationDenyReason::MetadataStale,
        }
        .into(),
    ))
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
    // The caller's own account — same rule as `start_registration` above.
    let scope = user.principal_tenant_id;
    let policy = state
        .webauthn
        .webauthn_attestation_policy_repo
        .get_by_tenant(scope)
        .await?
        .unwrap_or_default();

    enforce_mds_freshness(&state, &policy, scope, user.user_id).await?;

    let cred = state
        .webauthn
        .webauthn_service
        .finish_registration_for_policy(
            scope,
            user.user_id,
            &b.state_token,
            &b.credential_name,
            &b.response,
            &policy,
            &state.webauthn.attestation_metadata_source,
            &state.webauthn.attestation_ca_cache,
        )
        .await?;

    // A registered factor is a *required* factor. Without this the credential
    // was listed on the profile page and accepted at
    // `/auth/webauthn/authenticate`, but `AuthService::login` gates its MFA
    // challenge on `mfa_enabled` — which only `confirm_mfa` ever set — so a
    // user whose sole factor was a passkey or a security key signed in with a
    // password and nothing else. Enrolling one now means the same thing
    // enrolling TOTP means.
    //
    // Deliberately after the credential is persisted, and deliberately not
    // failing the request if it goes wrong: the credential exists either way,
    // and reporting the registration as failed would invite the user to
    // register a second one. A failure here leaves MFA off, which the next
    // enrollment or the profile page's own state will correct — and it is
    // logged loudly rather than swallowed.
    if let Err(e) = state
        .mfa_method_service
        .enable_after_enrollment(scope, user.user_id)
        .await
    {
        tracing::error!(
            action = "webauthn.enable_mfa_failed",
            tenant_id = %scope,
            user_id = %user.user_id,
            credential_id = %cred.id,
            error = %e,
            "registered a WebAuthn credential but could not mark MFA as required \
             for this account — sign-in will not challenge for it until the flag \
             is set"
        );
    }

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

    // Second-factor authentication follows the tenant's policy. Relaxing it
    // cannot relax a credential already enrolled under `required` — see
    // `axiam_auth::webauthn`'s module docs.
    let user_verification = state
        .settings_repo
        .get_effective_settings(org_id, tenant_id)
        .await?
        .webauthn
        .webauthn_user_verification;

    let (challenge, state_token) = state
        .webauthn
        .webauthn_service
        .start_authentication(tenant_id, org_id, user_id, user_verification)
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
        (status = 400, description = "Neither slug nor id given for the organization"),
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

    // A blank slug is not a slug — see `handlers::auth::blank_is_unnamed`. The
    // login page collects the workspace in one step and hands both fields to
    // this ceremony, so an organization-level sign-in arrives here with an
    // empty tenant.
    let org_slug = crate::handlers::auth::blank_is_unnamed(b.org_slug.as_deref());
    let tenant_slug = crate::handlers::auth::blank_is_unnamed(b.tenant_slug.as_deref());

    let org_id = match (b.org_id, org_slug) {
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

    let tenant_id = match (b.tenant_id, tenant_slug) {
        (Some(id), _) => id,
        (None, Some(slug)) => {
            state
                .tenant_repo
                .get_by_slug(org_id, slug)
                .await
                .map_err(|_| unauthenticated())?
                .id
        }
        // No tenant named: the organization's own scope, as `login` does. An
        // organization-level principal holds passkeys like any other, and
        // demanding a tenant here made the one credential it could sign in with
        // unusable to it.
        (None, None) => {
            state
                .tenant_repo
                .get_organization_tenant(org_id)
                .await
                .map_err(|_| unauthenticated())?
                .id
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
        (status = 200,
         description = "Authentication successful. Sets the axiam_access, \
                        axiam_refresh and axiam_csrf cookies and echoes the \
                        CSRF token in X-CSRF-Token, exactly as POST \
                        /api/v1/auth/login does.",
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

    Ok(webauthn_session_response(&state.auth_config, out))
}

/// `POST /api/v1/auth/webauthn/authenticate/finish`
///
/// Complete a WebAuthn passkey authentication ceremony.  On success a session
/// is created and access/refresh tokens are issued **both** as the
/// `axiam_access`/`axiam_refresh`/`axiam_csrf` cookie triple and in the
/// response body — see `webauthn_session_response` for why it is both.
#[utoipa::path(
    post,
    path = "/api/v1/auth/webauthn/authenticate/finish",
    tag = "webauthn",
    request_body = FinishAuthenticationRequest,
    responses(
        (status = 200,
         description = "Authentication successful. Sets the axiam_access, \
                        axiam_refresh and axiam_csrf cookies and echoes the \
                        CSRF token in X-CSRF-Token, exactly as POST \
                        /api/v1/auth/login does.",
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

    Ok(webauthn_session_response(&state.auth_config, out))
}

// -------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::SET_COOKIE;
    use axiam_auth::config::AuthConfig;

    fn out() -> axiam_auth::LoginOutput {
        axiam_auth::LoginOutput {
            access_token: "access-token-value".into(),
            refresh_token: "refresh-token-value".into(),
            session_id: Uuid::nil(),
            expires_in: 900,
        }
    }

    fn cookies(res: &HttpResponse) -> Vec<String> {
        res.headers()
            .get_all(SET_COOKIE)
            .map(|v| v.to_str().unwrap().to_owned())
            .collect()
    }

    fn cookie_named<'a>(set: &'a [String], name: &str) -> &'a str {
        set.iter()
            .find(|c| c.starts_with(&format!("{name}=")))
            .unwrap_or_else(|| panic!("no {name} cookie in {set:?}"))
    }

    /// The regression this helper exists for: a completed passkey ceremony
    /// used to set no cookies at all, so the browser had no session and
    /// `GET /api/v1/auth/me` answered 401 immediately afterwards.
    #[test]
    fn sets_the_same_cookie_triple_as_password_login() {
        let config = AuthConfig {
            cookie_secure: true,
            ..AuthConfig::default()
        };
        let set = cookies(&webauthn_session_response(&config, out()));

        let access = cookie_named(&set, "axiam_access");
        assert!(access.contains("access-token-value"));
        assert!(
            access.contains("HttpOnly"),
            "access cookie must be httpOnly"
        );

        let refresh = cookie_named(&set, "axiam_refresh");
        assert!(refresh.contains("refresh-token-value"));
        assert!(
            refresh.contains("HttpOnly"),
            "refresh cookie must be httpOnly"
        );

        // Readable by JavaScript on purpose — the SPA has to echo it back in
        // `X-CSRF-Token`, which it cannot do with an httpOnly cookie.
        let csrf = cookie_named(&set, "axiam_csrf");
        assert!(!csrf.contains("HttpOnly"), "csrf cookie must be readable");
    }

    /// §3's non-browser rule: the same token, in the header and the cookie.
    /// An SDK reads the header; a mismatch would make the very first
    /// state-changing call after a passkey sign-in fail CSRF validation.
    #[test]
    fn echoes_the_csrf_token_in_the_header_and_the_cookie() {
        let res = webauthn_session_response(&AuthConfig::default(), out());

        let header = res
            .headers()
            .get(HEADER_CSRF)
            .expect("X-CSRF-Token header")
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!header.is_empty());

        let set = cookies(&res);
        let csrf = cookie_named(&set, "axiam_csrf");
        assert!(
            csrf.contains(&header),
            "cookie {csrf} must carry the header value {header}"
        );
    }

    /// A fresh token per sign-in, not a constant.
    #[test]
    fn mints_a_distinct_csrf_token_per_response() {
        let config = AuthConfig::default();
        let first = webauthn_session_response(&config, out());
        let second = webauthn_session_response(&config, out());
        assert_ne!(
            first.headers().get(HEADER_CSRF).unwrap(),
            second.headers().get(HEADER_CSRF).unwrap()
        );
    }

    /// Adding cookies must not have taken the tokens out of the body: the
    /// non-browser SDKs adopt them from there (CONTRACT.md §24.3).
    #[test]
    fn keeps_the_token_pair_in_the_body() {
        let config = AuthConfig::default();
        let res = webauthn_session_response(&config, out());
        assert_eq!(res.status(), actix_web::http::StatusCode::OK);

        let body = actix_web::body::to_bytes(res.into_body());
        let body = futures::executor::block_on(body).expect("body");
        let parsed: serde_json::Value = serde_json::from_slice(&body).expect("json body");

        assert_eq!(parsed["access_token"], "access-token-value");
        assert_eq!(parsed["refresh_token"], "refresh-token-value");
        assert_eq!(parsed["expires_in"], 900);
        assert!(parsed.get("session_id").is_some());
    }
}

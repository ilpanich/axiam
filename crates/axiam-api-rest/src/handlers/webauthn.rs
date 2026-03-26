//! WebAuthn passkey registration and authentication endpoints.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::{AuthService, WebauthnService};
use axiam_core::models::webauthn_credential::WebauthnCredentialType;
use axiam_db::{
    SurrealFederationLinkRepository, SurrealSessionRepository, SurrealUserRepository,
    SurrealWebauthnCredentialRepository,
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

type AuthSvc<C> = AuthService<
    SurrealUserRepository<C>,
    SurrealSessionRepository<C>,
    SurrealFederationLinkRepository<C>,
>;

type WebauthnSvc<C> = WebauthnService<SurrealWebauthnCredentialRepository<C>>;

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

/// Maximum length for an IP address string (IPv6 with zone ID).
const MAX_IP_LEN: usize = 45;
/// Maximum length for a User-Agent string.
const MAX_UA_LEN: usize = 512;

fn client_ip(req: &HttpRequest) -> Option<String> {
    req.connection_info()
        .realip_remote_addr()
        .map(|s| s.chars().take(MAX_IP_LEN).collect())
}

fn user_agent(req: &HttpRequest) -> Option<String> {
    req.headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(MAX_UA_LEN).collect())
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

/// `POST /auth/webauthn/register/start`
///
/// Begin a WebAuthn passkey registration ceremony for the
/// authenticated user.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/start",
    tag = "webauthn",
    responses(
        (status = 200, description = "Registration challenge",
         body = StartRegistrationResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = []))
)]
pub async fn start_registration<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<WebauthnSvc<C>>,
) -> Result<HttpResponse, AxiamApiError> {
    let user_name = user.user_id.to_string();
    let (challenge, state_token) = svc
        .start_registration(user.tenant_id, user.org_id, user.user_id, &user_name)
        .await?;

    Ok(HttpResponse::Ok().json(StartRegistrationResponse {
        challenge,
        state_token,
    }))
}

/// `POST /auth/webauthn/register/finish`
///
/// Complete a WebAuthn passkey registration ceremony.
#[utoipa::path(
    post,
    path = "/auth/webauthn/register/finish",
    tag = "webauthn",
    request_body = FinishRegistrationRequest,
    responses(
        (status = 201, description = "Credential registered",
         body = CredentialResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer" = []))
)]
pub async fn finish_registration<C: Connection>(
    user: AuthenticatedUser,
    svc: web::Data<WebauthnSvc<C>>,
    body: web::Json<FinishRegistrationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let cred = svc
        .finish_registration(
            user.tenant_id,
            &b.state_token,
            &b.credential_name,
            &b.response,
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

/// `POST /auth/webauthn/authenticate/start`
///
/// Begin a WebAuthn passkey authentication ceremony.  Requires a
/// valid MFA challenge token (obtained from the login flow).
#[utoipa::path(
    post,
    path = "/auth/webauthn/authenticate/start",
    tag = "webauthn",
    request_body = StartAuthenticationRequest,
    responses(
        (status = 200, description = "Authentication challenge",
         body = StartAuthenticationResponse),
        (status = 401, description = "Invalid challenge token"),
    )
)]
pub async fn start_authentication<C: Connection>(
    auth_svc: web::Data<AuthSvc<C>>,
    svc: web::Data<WebauthnSvc<C>>,
    body: web::Json<StartAuthenticationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let (user_id, tenant_id, org_id) = auth_svc
        .decode_mfa_challenge_ids(&body.challenge_token)
        .map_err(|e| AxiamApiError(e.into()))?;

    let (challenge, state_token) = svc.start_authentication(tenant_id, org_id, user_id).await?;

    Ok(HttpResponse::Ok().json(StartAuthenticationResponse {
        challenge,
        state_token,
    }))
}

/// `POST /auth/webauthn/authenticate/finish`
///
/// Complete a WebAuthn passkey authentication ceremony.  On success
/// a session is created and access/refresh tokens are issued.
#[utoipa::path(
    post,
    path = "/auth/webauthn/authenticate/finish",
    tag = "webauthn",
    request_body = FinishAuthenticationRequest,
    responses(
        (status = 200, description = "Authentication successful",
         body = WebauthnLoginResponse),
        (status = 401, description = "Authentication failed"),
    )
)]
pub async fn finish_authentication<C: Connection>(
    req: HttpRequest,
    auth_svc: web::Data<AuthSvc<C>>,
    svc: web::Data<WebauthnSvc<C>>,
    body: web::Json<FinishAuthenticationRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    let b = body.into_inner();
    let tenant_id = peek_tenant_id(&b.state_token)?;

    let (user_id, org_id) = svc
        .finish_authentication(tenant_id, &b.state_token, &b.response)
        .await?;

    let out = auth_svc
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

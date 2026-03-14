//! OAuth2 authorization and token endpoints.

use actix_web::{HttpResponse, web};
use axiam_auth::config::AuthConfig;
use axiam_core::repository::UserRepository;
use axiam_db::{
    SurrealAuthorizationCodeRepository, SurrealOAuth2ClientRepository,
    SurrealRefreshTokenRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_oauth2::authorize::{AuthorizeRequest, AuthorizeService};
use axiam_oauth2::error::OAuth2Error;
use axiam_oauth2::oidc::{
    JwksDocument, OidcDiscoveryDocument, UserInfoResponse, build_discovery_document, build_jwks,
};
use axiam_oauth2::token::{
    IntrospectRequest, IntrospectionResponse, RevokeRequest, TokenRequest, TokenResponse,
    TokenService,
};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::extractors::auth::AuthenticatedUser;

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Query parameters for the authorization endpoint.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct AuthorizeQuery {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// Query parameter for the token endpoint tenant routing.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct TenantQuery {
    pub tenant_id: Uuid,
}

/// RFC 6749 error response body.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OAuth2ErrorResponse {
    pub error: String,
    pub error_description: String,
}

// ---------------------------------------------------------------------------
// Type alias for the concrete TokenService used in handlers
// ---------------------------------------------------------------------------

type ConcreteTokenService<C> = TokenService<
    SurrealOAuth2ClientRepository<C>,
    SurrealAuthorizationCodeRepository<C>,
    SurrealTenantRepository<C>,
    SurrealRefreshTokenRepository<C>,
    SurrealUserRepository<C>,
>;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /oauth2/authorize` -- OAuth2 authorization endpoint.
///
/// The user must be authenticated (redirected to login first if not).
/// On success, redirects to `redirect_uri?code=...&state=...`.
/// On error, redirects with `?error=...&error_description=...&state=...`.
#[utoipa::path(
    get,
    path = "/oauth2/authorize",
    tag = "oauth2",
    params(AuthorizeQuery),
    responses(
        (status = 302, description = "Redirect with authorization code"),
    ),
    security(("bearer" = []))
)]
pub async fn authorize<C: Connection>(
    user: AuthenticatedUser,
    query: web::Query<AuthorizeQuery>,
    authz_service: web::Data<
        AuthorizeService<SurrealOAuth2ClientRepository<C>, SurrealAuthorizationCodeRepository<C>>,
    >,
) -> HttpResponse {
    let q = query.into_inner();

    let req = AuthorizeRequest {
        tenant_id: user.tenant_id,
        user_id: user.user_id,
        response_type: q.response_type,
        client_id: q.client_id,
        redirect_uri: q.redirect_uri.clone(),
        scope: q.scope,
        state: q.state.clone(),
        code_challenge: q.code_challenge,
        code_challenge_method: q.code_challenge_method,
        nonce: q.nonce,
    };

    match authz_service.authorize(req).await {
        Ok(resp) => {
            match url::Url::parse(&resp.redirect_uri) {
                Ok(mut url) => {
                    url.query_pairs_mut().append_pair("code", &resp.code);
                    if let Some(ref state) = resp.state {
                        url.query_pairs_mut().append_pair("state", state);
                    }
                    HttpResponse::Found()
                        .append_header(("Location", url.to_string()))
                        .finish()
                }
                Err(_) => {
                    // Never leak the authorization code to an
                    // unknown host.
                    HttpResponse::InternalServerError().json(OAuth2ErrorResponse {
                        error: "server_error".into(),
                        error_description: "invalid redirect_uri in \
                                 authorization response"
                            .into(),
                    })
                }
            }
        }
        Err(e) => {
            // Per RFC 6749: only redirect when the redirect_uri has
            // been validated. For InvalidClient / redirect_uri
            // errors, return a direct HTTP error instead.
            match &e {
                OAuth2Error::InvalidClient(_) | OAuth2Error::InvalidRedirectUri(_) => {
                    build_oauth2_error_response(&e)
                }
                _ => {
                    // These errors occur after client+redirect_uri
                    // were validated — safe to redirect.
                    build_error_redirect(&q.redirect_uri, &e, q.state.as_deref())
                }
            }
        }
    }
}

/// `POST /oauth2/token` -- OAuth2 token endpoint.
///
/// Accepts form-encoded body per RFC 6749. Supports authorization_code,
/// client_credentials, and refresh_token grant types. The `tenant_id` is
/// passed as a query parameter since the token endpoint is unauthenticated
/// (the client is authenticating itself here).
#[utoipa::path(
    post,
    path = "/oauth2/token",
    tag = "oauth2",
    params(TenantQuery),
    request_body(
        content_type = "application/x-www-form-urlencoded",
        content = TokenRequest,
    ),
    responses(
        (status = 200, description = "Token response",
         body = TokenResponse),
        (status = 400, description = "OAuth2 error",
         body = OAuth2ErrorResponse),
    ),
)]
pub async fn token<C: Connection>(
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<TokenRequest>,
    token_service: web::Data<ConcreteTokenService<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    match token_service.exchange(tenant_id, form.into_inner()).await {
        Ok(resp) => HttpResponse::Ok()
            .append_header(("Cache-Control", "no-store"))
            .append_header(("Pragma", "no-cache"))
            .json(resp),
        Err(e) => build_oauth2_error_response(&e),
    }
}

/// `POST /oauth2/revoke` -- Token revocation endpoint (RFC 7009).
///
/// Accepts form-encoded body. Always returns 200 per the spec — invalid
/// tokens are silently ignored.
#[utoipa::path(
    post,
    path = "/oauth2/revoke",
    tag = "oauth2",
    params(TenantQuery),
    request_body(
        content_type = "application/x-www-form-urlencoded",
        content = RevokeRequest,
    ),
    responses(
        (status = 200, description = "Token revoked (or was already invalid)"),
        (status = 401, description = "Client authentication failed",
         body = OAuth2ErrorResponse),
    ),
)]
pub async fn revoke<C: Connection>(
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<RevokeRequest>,
    token_service: web::Data<ConcreteTokenService<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    match token_service
        .revoke_token(tenant_id, form.into_inner())
        .await
    {
        Ok(()) => HttpResponse::Ok().finish(),
        Err(e) => build_oauth2_error_response(&e),
    }
}

/// `POST /oauth2/introspect` -- Token introspection endpoint (RFC 7662).
///
/// Accepts form-encoded body. Returns an `IntrospectionResponse` with
/// `active: true/false` and optional metadata.
#[utoipa::path(
    post,
    path = "/oauth2/introspect",
    tag = "oauth2",
    params(TenantQuery),
    request_body(
        content_type = "application/x-www-form-urlencoded",
        content = IntrospectRequest,
    ),
    responses(
        (status = 200, description = "Token introspection result",
         body = IntrospectionResponse),
        (status = 401, description = "Client authentication failed",
         body = OAuth2ErrorResponse),
    ),
)]
pub async fn introspect<C: Connection>(
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<IntrospectRequest>,
    token_service: web::Data<ConcreteTokenService<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    match token_service
        .introspect_token(tenant_id, form.into_inner())
        .await
    {
        Ok(resp) => HttpResponse::Ok().json(resp),
        Err(e) => build_oauth2_error_response(&e),
    }
}

// ---------------------------------------------------------------------------
// OIDC endpoints
// ---------------------------------------------------------------------------

/// `GET /.well-known/openid-configuration` -- OIDC Discovery document.
///
/// Returns the OpenID Provider metadata per OpenID Connect Discovery 1.0.
/// The issuer URL is taken from `AuthConfig::oauth2_issuer_url` when set,
/// falling back to `AuthConfig::jwt_issuer` otherwise.
#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "oidc",
    responses(
        (status = 200, description = "OpenID Connect Discovery document",
         body = OidcDiscoveryDocument),
    ),
)]
pub async fn discovery(auth_config: web::Data<AuthConfig>) -> HttpResponse {
    let issuer = auth_config.effective_issuer();
    // Guard: effective_issuer must be a valid URL for a compliant
    // discovery document.  Startup validation should catch this, but
    // defend in depth at the endpoint level.
    if url::Url::parse(issuer).is_err() {
        return HttpResponse::InternalServerError().json(OAuth2ErrorResponse {
            error: "server_error".into(),
            error_description: "OIDC issuer is not configured as a \
                valid URL"
                .into(),
        });
    }
    let doc = build_discovery_document(issuer);
    HttpResponse::Ok().json(doc)
}

/// `GET /oauth2/jwks` -- JSON Web Key Set.
///
/// Returns the public signing keys used by the authorization server
/// so that relying parties can verify JWTs without sharing a secret.
#[utoipa::path(
    get,
    path = "/oauth2/jwks",
    tag = "oidc",
    responses(
        (status = 200, description = "JWKS document", body = JwksDocument),
        (status = 500, description = "Key parsing error"),
    ),
)]
pub async fn jwks(auth_config: web::Data<AuthConfig>) -> HttpResponse {
    match build_jwks(&auth_config.jwt_public_key_pem) {
        Ok(doc) => HttpResponse::Ok().json(doc),
        Err(e) => HttpResponse::InternalServerError().json(OAuth2ErrorResponse {
            error: "server_error".into(),
            error_description: e,
        }),
    }
}

/// `GET /oauth2/userinfo` -- OIDC UserInfo endpoint.
///
/// Returns claims about the authenticated user. Requires a valid
/// Bearer access token. Email and username are included based on
/// the scopes present in the access token.
#[utoipa::path(
    get,
    path = "/oauth2/userinfo",
    tag = "oidc",
    responses(
        (status = 200, description = "UserInfo response",
         body = UserInfoResponse),
        (status = 401, description = "Invalid or missing access token"),
    ),
    security(("bearer" = []))
)]
pub async fn userinfo<C: Connection>(
    user: AuthenticatedUser,
    user_repo: web::Data<SurrealUserRepository<C>>,
) -> HttpResponse {
    let scopes: Vec<String> = user
        .claims
        .0
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(String::from)
        .collect();

    let has_scope = |s: &str| scopes.iter().any(|sc| sc == s);

    // Fetch user details for email/username when the relevant
    // scopes are present.
    let (email, preferred_username) = if has_scope("email") || has_scope("profile") {
        match user_repo.get_by_id(user.tenant_id, user.user_id).await {
            Ok(u) => (
                if has_scope("email") {
                    Some(u.email)
                } else {
                    None
                },
                if has_scope("profile") {
                    Some(u.username)
                } else {
                    None
                },
            ),
            Err(e) => {
                tracing::error!(
                    user_id = %user.user_id,
                    tenant_id = %user.tenant_id,
                    error = %e,
                    "userinfo: failed to fetch user for scoped claims"
                );
                return HttpResponse::InternalServerError().json(OAuth2ErrorResponse {
                    error: "server_error".into(),
                    error_description: "failed to retrieve user claims".into(),
                });
            }
        }
    } else {
        (None, None)
    };

    HttpResponse::Ok().json(UserInfoResponse {
        sub: user.user_id.to_string(),
        email,
        preferred_username,
        tenant_id: user.tenant_id.to_string(),
        org_id: user.org_id.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a redirect response with error parameters per RFC 6749
/// section 4.1.2.1.
fn build_error_redirect(
    redirect_uri: &str,
    error: &OAuth2Error,
    state: Option<&str>,
) -> HttpResponse {
    let mut url = match url::Url::parse(redirect_uri) {
        Ok(u) => u,
        Err(_) => {
            // Unparseable redirect_uri — return direct error
            return HttpResponse::BadRequest().json(OAuth2ErrorResponse {
                error: error.error_code().to_string(),
                error_description: error.error_description(),
            });
        }
    };
    url.query_pairs_mut()
        .append_pair("error", error.error_code())
        .append_pair("error_description", &error.error_description());
    if let Some(state) = state {
        url.query_pairs_mut().append_pair("state", state);
    }
    HttpResponse::Found()
        .append_header(("Location", url.to_string()))
        .finish()
}

/// Build an OAuth2 JSON error response with the appropriate HTTP status.
///
/// `invalid_client` returns 401.  No `WWW-Authenticate` header is sent
/// because the token endpoint uses `client_secret_post` (credentials in
/// the request body), not HTTP Basic authentication.
fn build_oauth2_error_response(e: &OAuth2Error) -> HttpResponse {
    let status = match e {
        OAuth2Error::InvalidClient(_) => actix_web::http::StatusCode::UNAUTHORIZED,
        OAuth2Error::ServerError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        _ => actix_web::http::StatusCode::BAD_REQUEST,
    };
    HttpResponse::build(status).json(OAuth2ErrorResponse {
        error: e.error_code().to_string(),
        error_description: e.error_description(),
    })
}

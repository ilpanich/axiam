//! OAuth2 authorization and token endpoints.

use actix_web::{HttpResponse, web};
use axiam_db::{
    SurrealAuthorizationCodeRepository, SurrealOAuth2ClientRepository, SurrealTenantRepository,
};
use axiam_oauth2::authorize::{AuthorizeRequest, AuthorizeService};
use axiam_oauth2::error::OAuth2Error;
use axiam_oauth2::token::{TokenRequest, TokenResponse, TokenService};
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
        AuthorizeService<
            SurrealOAuth2ClientRepository<C>,
            SurrealAuthorizationCodeRepository<C>,
        >,
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
    };

    match authz_service.authorize(req).await {
        Ok(resp) => {
            let mut redirect_url = resp.redirect_uri;
            redirect_url.push_str("?code=");
            redirect_url.push_str(&resp.code);
            if let Some(ref state) = resp.state {
                redirect_url.push_str("&state=");
                redirect_url.push_str(state);
            }
            HttpResponse::Found()
                .append_header(("Location", redirect_url))
                .finish()
        }
        Err(e) => build_error_redirect(&q.redirect_uri, &e, q.state.as_deref()),
    }
}

/// `POST /oauth2/token` -- OAuth2 token endpoint.
///
/// Accepts form-encoded body per RFC 6749. The `tenant_id` is passed as a
/// query parameter since the token endpoint is unauthenticated (the client
/// is authenticating itself here).
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
    token_service: web::Data<
        TokenService<
            SurrealOAuth2ClientRepository<C>,
            SurrealAuthorizationCodeRepository<C>,
            SurrealTenantRepository<C>,
        >,
    >,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    match token_service.exchange_code(tenant_id, form.into_inner()).await {
        Ok(resp) => HttpResponse::Ok()
            .append_header(("Cache-Control", "no-store"))
            .append_header(("Pragma", "no-cache"))
            .json(resp),
        Err(e) => {
            let status = match &e {
                OAuth2Error::InvalidClient(_) => {
                    actix_web::http::StatusCode::UNAUTHORIZED
                }
                OAuth2Error::ServerError(_) => {
                    actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
                }
                _ => actix_web::http::StatusCode::BAD_REQUEST,
            };
            HttpResponse::build(status).json(OAuth2ErrorResponse {
                error: e.error_code().to_string(),
                error_description: e.error_description(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a redirect response with error parameters per RFC 6749 section 4.1.2.1.
fn build_error_redirect(
    redirect_uri: &str,
    error: &OAuth2Error,
    state: Option<&str>,
) -> HttpResponse {
    let mut url = format!(
        "{}?error={}&error_description={}",
        redirect_uri,
        error.error_code(),
        urlencoded(&error.error_description()),
    );
    if let Some(state) = state {
        url.push_str("&state=");
        url.push_str(state);
    }
    HttpResponse::Found()
        .append_header(("Location", url))
        .finish()
}

/// Minimal percent-encoding for query string values.
fn urlencoded(s: &str) -> String {
    s.replace(' ', "%20")
        .replace(':', "%3A")
        .replace('&', "%26")
        .replace('=', "%3D")
}

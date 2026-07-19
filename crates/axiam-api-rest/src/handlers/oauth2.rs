//! OAuth2 authorization and token endpoints.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::config::AuthConfig;
use axiam_core::repository::UserRepository;
use axiam_oauth2::authorize::AuthorizeRequest;
use axiam_oauth2::error::OAuth2Error;
use axiam_oauth2::jwks_cache::JwksCacheResponse;
use axiam_oauth2::oidc::{
    JwksDocument, OidcDiscoveryDocument, UserInfoResponse, build_discovery_document,
};
use axiam_oauth2::token::{
    IntrospectRequest, IntrospectionResponse, RevokeRequest, TokenRequest, TokenResponse,
};
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use crate::extractors::auth::AuthenticatedUser;
use crate::state::AppState;

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
pub async fn authorize<C: Connection + Clone>(
    user: AuthenticatedUser,
    query: web::Query<AuthorizeQuery>,
    state: web::Data<AppState<C>>,
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

    match state.authorize_service.authorize(req).await {
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
pub async fn token<C: Connection + Clone>(
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<TokenRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    match state
        .token_service
        .exchange(tenant_id, form.into_inner())
        .await
    {
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
pub async fn revoke<C: Connection + Clone>(
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<RevokeRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    match state
        .token_service
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
pub async fn introspect<C: Connection + Clone>(
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<IntrospectRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    match state
        .token_service
        .introspect_token(tenant_id, form.into_inner())
        .await
    {
        Ok(resp) => HttpResponse::Ok()
            .append_header(("Cache-Control", "no-store"))
            .append_header(("Pragma", "no-cache"))
            .json(resp),
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
///
/// B3: served from an in-process cache (`state.oauth2_jwks_cache`) keyed by
/// a hash of the source PEM, with a `Cache-Control: public, max-age=<n>`
/// header (configurable, default 300s) and a strong `ETag`. Clients that
/// send a matching `If-None-Match` get `304 Not Modified` with no body;
/// clients that ignore caching headers entirely still get the identical
/// `200 OK` + JWKS body they always did -- this is a pure additive change.
/// See `axiam_oauth2::jwks_cache` module docs for the cache design and the
/// documented limitations (no key-rotation mechanism exists yet; the
/// endpoint serves one global, not per-tenant, key set).
#[utoipa::path(
    get,
    path = "/oauth2/jwks",
    tag = "oidc",
    responses(
        (status = 200, description = "JWKS document", body = JwksDocument),
        (status = 304, description = "Not Modified -- ETag matches If-None-Match"),
        (status = 500, description = "Key parsing error"),
    ),
)]
pub async fn jwks<C: Connection + Clone>(
    req: HttpRequest,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let if_none_match = req
        .headers()
        .get(actix_web::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());

    let cache_control = state.oauth2_jwks_cache_config.cache_control_header();

    match state
        .oauth2_jwks_cache
        .get(&state.auth_config.jwt_public_key_pem, if_none_match)
    {
        Ok(JwksCacheResponse::Fresh { body, etag }) => HttpResponse::Ok()
            .content_type("application/json")
            .insert_header(("Cache-Control", cache_control))
            .insert_header(("ETag", etag))
            .body(body),
        Ok(JwksCacheResponse::NotModified { etag }) => HttpResponse::NotModified()
            .insert_header(("Cache-Control", cache_control))
            .insert_header(("ETag", etag))
            .finish(),
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
pub async fn userinfo<C: Connection + Clone>(
    user: AuthenticatedUser,
    state: web::Data<AppState<C>>,
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
        match state
            .user_repo
            .get_by_id(user.tenant_id, user.user_id)
            .await
        {
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
/// `invalid_client` returns 401 with a `WWW-Authenticate` header per
/// RFC 6749 §5.2.  Although the token endpoint uses `client_secret_post`,
/// RFC 6749 §5.2 still requires the 401 response to include
/// `WWW-Authenticate` indicating the authentication scheme.
fn build_oauth2_error_response(e: &OAuth2Error) -> HttpResponse {
    let status = match e {
        OAuth2Error::InvalidClient(_) => actix_web::http::StatusCode::UNAUTHORIZED,
        OAuth2Error::ServerError(_) => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        _ => actix_web::http::StatusCode::BAD_REQUEST,
    };
    let mut builder = HttpResponse::build(status);
    builder
        .append_header(("Cache-Control", "no-store"))
        .append_header(("Pragma", "no-cache"));
    // RFC 6749 §5.2: 401 responses MUST include WWW-Authenticate
    if status == actix_web::http::StatusCode::UNAUTHORIZED {
        builder.append_header(("WWW-Authenticate", "Bearer realm=\"axiam\""));
    }
    builder.json(OAuth2ErrorResponse {
        error: e.error_code().to_string(),
        error_description: e.error_description(),
    })
}

// ---------------------------------------------------------------------------
// Tests (B3: JWKS caching headers wired through the actix handler)
// ---------------------------------------------------------------------------
//
// The full RFC-conformance/e2e coverage for `/oauth2/jwks` lives in
// `tests/oauth2_*.rs`. These handler-level tests are deliberately narrow:
// they call `jwks::<C>` directly against `AppState::for_test` (no DB
// migrations, no running `App`/router) since the handler does not touch the
// database at all -- just enough actix machinery (`HttpRequest`,
// `web::Data`) to prove the `If-None-Match` -> 304 wiring and the
// `Cache-Control`/`ETag` headers actually reach the HTTP response. The
// cache/ETag/304 *logic itself* (RFC 7232 comparison, rotation, malformed
// keys, etc.) is exhaustively covered by `axiam_oauth2::jwks_cache`'s own
// unit tests -- this module does not re-test that logic, only the plumbing.
#[cfg(test)]
mod jwks_handler_tests {
    use actix_web::http::header::{CACHE_CONTROL, ETAG, IF_NONE_MATCH};
    use actix_web::test::TestRequest;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    use super::*;

    // Test-only Ed25519 keypair with no real-world value. nosemgrep
    const TEST_PUBLIC_KEY_PEM: &str = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );

    async fn test_state() -> AppState<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory db");
        let auth_config = AuthConfig {
            jwt_public_key_pem: TEST_PUBLIC_KEY_PEM.into(),
            ..AuthConfig::default()
        };
        AppState::for_test(db, auth_config)
    }

    #[actix_web::test]
    async fn jwks_returns_200_with_cache_control_and_etag_when_no_if_none_match() {
        let state = web::Data::new(test_state().await);
        let req = TestRequest::default().to_http_request();

        let resp = jwks(req, state).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap(),
            "public, max-age=300"
        );
        assert!(resp.headers().get(ETAG).is_some());
    }

    #[actix_web::test]
    async fn jwks_returns_304_when_if_none_match_echoes_current_etag() {
        let state = web::Data::new(test_state().await);

        // First request: discover the current ETag.
        let first_req = TestRequest::default().to_http_request();
        let first_resp = jwks(first_req, state.clone()).await;
        let etag = first_resp
            .headers()
            .get(ETAG)
            .expect("etag present")
            .to_str()
            .expect("etag is ascii")
            .to_string();

        // Second request: echo it back via If-None-Match.
        let second_req = TestRequest::default()
            .insert_header((IF_NONE_MATCH, etag.as_str()))
            .to_http_request();
        let second_resp = jwks(second_req, state).await;

        assert_eq!(
            second_resp.status(),
            actix_web::http::StatusCode::NOT_MODIFIED
        );
        assert_eq!(second_resp.headers().get(ETAG).unwrap(), etag.as_str());
        assert_eq!(
            second_resp.headers().get(CACHE_CONTROL).unwrap(),
            "public, max-age=300"
        );
    }

    #[actix_web::test]
    async fn jwks_returns_200_when_if_none_match_does_not_match() {
        let state = web::Data::new(test_state().await);
        let req = TestRequest::default()
            .insert_header((IF_NONE_MATCH, "\"stale-etag-from-before-rotation\""))
            .to_http_request();

        let resp = jwks(req, state).await;

        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }
}

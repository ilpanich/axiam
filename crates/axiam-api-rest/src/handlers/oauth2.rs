//! OAuth2 authorization and token endpoints.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::config::AuthConfig;
use axiam_core::repository::UserRepository;
use axiam_oauth2::authorize::AuthorizeRequest;
use axiam_oauth2::device_service::{
    DEVICE_CODE_GRANT_TYPE, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
};
use axiam_oauth2::error::OAuth2Error;
use axiam_oauth2::jwks_cache::JwksCacheResponse;
use axiam_oauth2::oidc::{
    JwksDocument, OidcDiscoveryDocument, UserInfoResponse, build_discovery_document,
};
use axiam_oauth2::token::{
    IntrospectRequest, IntrospectionResponse, RevokeRequest, TokenRequest, TokenResponse,
};
use axiam_oauth2::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE;
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogRepository, TenantRepository};
use axiam_db::{SurrealAuditLogRepository, SurrealTenantRepository};

use crate::extractors::auth::AuthenticatedUser;
use crate::extractors::client_info::{client_ip, peer_ip};
use crate::state::AppState;

/// Cap for the caller-supplied `client_id` recorded in a failed-client-auth
/// audit row (SEC-087). Server-generated ids are `oa_`/`sa_` + a 32-char
/// encoding, so this leaves generous headroom for a legitimate value while
/// bounding what an anonymous caller can push into the log.
const MAX_CLIENT_ID_LEN: usize = 128;

/// Truncate to at most [`MAX_CLIENT_ID_LEN`] **bytes**, cutting on a character
/// boundary so the result is still valid UTF-8.
///
/// §22.3 residual 3: the previous `chars().take(N)` capped code points, not
/// bytes, so a multibyte id could still store 4× the intended size. The cap
/// exists to bound what an anonymous caller can push into an append-only log,
/// and a bound expressed in the wrong unit is not the bound that was intended.
fn truncate_bytes_on_char_boundary(s: &str) -> String {
    if s.len() <= MAX_CLIENT_ID_LEN {
        return s.to_owned();
    }
    let mut end = MAX_CLIENT_ID_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

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
    req: HttpRequest,
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<TokenRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    let form = form.into_inner();
    // I5: keep the grant type for the stage-timing event below. The token
    // service moves `form`, so copy the (short) discriminator first.
    let grant_type = form.grant_type.clone();
    // §17.2 residual 3: same reason, for the failed-client-auth audit event
    // below. Never the secret — only the client id, which is the caller's own
    // input and is what an operator needs to correlate an attack.
    let attempted_client_id = form.client_id.clone();
    let started = std::time::Instant::now();

    // B2 / RFC 8628 §3.4: the device-code grant is served by its own service.
    // Dispatching here, before `TokenService::exchange`, is the single `match`
    // arm the device flow costs the rest of the codebase — `TokenService`
    // never learns that this grant exists.
    //
    // Note what is deliberately NOT done: no client authentication. RFC 8628
    // targets public clients (a television cannot keep a secret), so the
    // device presents only its `device_code`, which is a 256-bit CSPRNG value
    // stored as a hash. The device code IS the credential.
    if grant_type == DEVICE_CODE_GRANT_TYPE {
        let device_code = match form.device_code.as_deref() {
            Some(code) if !code.is_empty() => code.to_owned(),
            _ => {
                return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
                    "device_code is required for the device_code grant".into(),
                ));
            }
        };
        return match state
            .device_authorization_service
            .poll(tenant_id, &device_code)
            .await
        {
            Ok(resp) => HttpResponse::Ok()
                .append_header(("Cache-Control", "no-store"))
                .append_header(("Pragma", "no-cache"))
                .json(resp),
            // `authorization_pending` and `slow_down` are the NORMAL answers
            // here — a device polls for as long as the user takes to walk to
            // another screen — so they are not logged as failures. Treating
            // the expected path as an error condition would bury the real
            // ones under it.
            Err(e) => build_oauth2_error_response(&e),
        };
    }

    // B3 / RFC 8693. Like the device grant, its own service behind one match
    // arm. Unlike the device grant, the exchanging client DOES authenticate —
    // it is a confidential service, not a television, and an exchange is
    // precisely the operation that should be attributable.
    if grant_type == TOKEN_EXCHANGE_GRANT_TYPE {
        return handle_token_exchange(tenant_id, form, &state).await;
    }

    match state.token_service.exchange(tenant_id, form).await {
        Ok(resp) => {
            let exchange_us = started.elapsed().as_micros() as u64;

            // I5: serialize explicitly rather than via `.json()` so the
            // serialization cost and the exact response body size are
            // observable. Body size is the load-bearing number for the
            // Nagle/delayed-ACK hypothesis behind the TLS client-credentials
            // plateau: the pathology only fires when a response reaches the
            // socket as a full segment plus a small trailing fragment, so run 5
            // needs to know where this body sits relative to the path MSS
            // (1448 bytes on a standard 1500-byte-MTU docker veth) once TLS
            // record and HTTP/2 frame overhead are added.
            let t_serialize = std::time::Instant::now();
            let body = match serde_json::to_vec(&resp) {
                Ok(body) => body,
                Err(e) => {
                    tracing::error!(error = %e, "failed to serialize token response");
                    return HttpResponse::InternalServerError().finish();
                }
            };
            let serialize_us = t_serialize.elapsed().as_micros() as u64;

            tracing::debug!(
                target: "axiam::perf",
                stage = "oauth2.token_endpoint",
                %grant_type,
                exchange_us,
                serialize_us,
                response_body_bytes = body.len(),
                handler_total_us = started.elapsed().as_micros() as u64,
                "token endpoint stage timings (I5)"
            );

            HttpResponse::Ok()
                .append_header(("Cache-Control", "no-store"))
                .append_header(("Pragma", "no-cache"))
                .content_type("application/json")
                .body(body)
        }
        Err(e) => {
            if matches!(e, OAuth2Error::InvalidClient(_)) {
                // §22.3 residual 1: this used to be awaited, which put a tenant
                // read (and, when it succeeded, an insert) on the response path
                // — so a failed client auth returned measurably faster for a
                // NONEXISTENT tenant than a real one, on an unauthenticated
                // endpoint. Detaching it removes the differential at its source
                // rather than trying to balance the two branches, and makes the
                // "fire-and-forget" this function has always claimed actually
                // true. The response below no longer waits on the audit sink at
                // all.
                let tenant_repo = state.tenant_repo.clone();
                let audit_repo = state.audit_repo.clone();
                let attempted = attempted_client_id.clone();
                let grant = grant_type.clone();
                let peer = peer_ip(&req);
                let forwarded = client_ip(&req);
                actix_web::rt::spawn(async move {
                    append_client_auth_failure_audit(
                        &tenant_repo,
                        &audit_repo,
                        tenant_id,
                        attempted.as_deref(),
                        &grant,
                        peer,
                        forwarded,
                    )
                    .await;
                });
            }
            build_oauth2_error_response(&e)
        }
    }
}

/// Append an `oauth2.client_auth_failed` audit entry, fire-and-forget.
///
/// §17.2 residual 3: a failed client authentication at the token endpoint used
/// to accrue **nothing** — no counter, no lockout, no audit row, no metric —
/// and `/oauth2` is not covered by the audit middleware, so nothing else
/// filled the gap either. Contrast the interactive login path, which records
/// every failure and applies exponential backoff.
///
/// This closes the **detection** half only, which is the half that was
/// genuinely missing. Lockout is deliberately *not* added here: client
/// credentials are 256-bit CSPRNG values, so online guessing is not the threat
/// — and a lockout keyed on a caller-supplied `client_id` would hand any
/// unauthenticated party a denial-of-service against a known client. The
/// endpoint's existing rate limit remains the volumetric control.
///
/// Recorded with `actor_id = Uuid::nil()` and [`ActorType::System`] because
/// the caller is by definition unauthenticated: the presented `client_id`
/// either does not exist or did not prove possession of its secret, so it must
/// not be promoted into the actor field as though it had. It goes in the
/// metadata instead, where it is evidence rather than identity.
///
/// The secret is never recorded, in any form.
///
/// # SEC-087 — this endpoint is unauthenticated, so nothing here may be trusted
///
/// `/oauth2/token` takes its `tenant_id` from a **query parameter** and requires
/// no credential to reach. The first version of this function wrote the row
/// unconditionally, which let any anonymous caller append rows into an arbitrary
/// tenant's append-only log — or into a tenant id that never existed — at
/// request rate. Three separate controls apply here as a result:
///
/// 1. **The tenant is resolved before the write**, and a row that cannot be
///    attributed to a real tenant goes to the **system partition**
///    (`tenant_id = nil`, the one [`AuditLogRepository::list_system`] serves)
///    rather than to a caller-chosen id. This bounds what an anonymous caller
///    can steer: they may cause a row, but never choose which real tenant's
///    append-only log it lands in. It does *not* stop a caller from generating
///    failures against a real tenant they do not belong to — and deliberately
///    doesn't try to, because that event is **true**: a failed client
///    authentication did occur against that tenant, and suppressing it would
///    blind the operator to a real attack. The volumetric control is the
///    endpoint's rate limit, not the audit layer.
///
///    §22.3 residual 2: an earlier version *dropped* the row whenever the
///    tenant read failed for any reason other than `NotFound`. The reasoning
///    (a DB outage must not turn a 401 into a 500) was right, but the effect
///    was that a database fault cost exactly the telemetry this row exists to
///    provide — and a database fault is plausibly correlated with an incident.
///    Routing to the system partition keeps the signal in precisely the case
///    where losing it hurts most, while still refusing to guess a tenant.
/// 2. **The client id is truncated on a character boundary, by bytes.**
///    §22.3 residual 3: the cap was applied with `chars().take(N)`, so a
///    multibyte id still stored up to 4N bytes. It is caller-supplied and
///    otherwise unbounded, unlike the `client_ip`/`user_agent` helpers which
///    have always capped their inputs (and which share the same char-vs-byte
///    looseness, bounded there by much smaller limits).
/// 3. **The IP is recorded at two trust levels.** `ip_address` carries the
///    transport peer address, which a caller cannot forge. The
///    `X-Forwarded-For`-derived value goes to metadata under a name that says
///    it is untrusted: on an authenticated path behind a trusted proxy the
///    forwarded value is the useful one, but here anyone can assert it, and an
///    operator who blocks a forged IP has been made to act against the wrong
///    host.
async fn append_client_auth_failure_audit<C: Connection + Clone>(
    tenant_repo: &SurrealTenantRepository<C>,
    audit_repo: &SurrealAuditLogRepository<C>,
    tenant_id: Uuid,
    attempted_client_id: Option<&str>,
    grant_type: &str,
    peer_ip: Option<String>,
    forwarded_ip_untrusted: Option<String>,
) {
    // Control 1 — attribute the row to the request's tenant only when that
    // tenant demonstrably exists; otherwise fall back to the system partition.
    // `attributed_tenant` is nil in both the unknown and the indeterminate
    // case, so a caller can never place a row in a real tenant's log by naming
    // one.
    let (attributed_tenant, tenant_note) = match tenant_repo.get_by_id(tenant_id).await {
        Ok(_) => (tenant_id, None),
        Err(AxiamError::NotFound { .. }) => {
            tracing::warn!(
                claimed_tenant_id = %tenant_id,
                %grant_type,
                "oauth2: client-auth-failure audit routed to the system partition — unknown tenant (SEC-087)"
            );
            (Uuid::nil(), Some("unknown_tenant"))
        }
        Err(e) => {
            // A DB fault must not turn a 401 into a 500 (T-15-04), and must not
            // cost the telemetry either (§22.3 residual 2). Record it as
            // unattributed rather than dropping it.
            tracing::error!(
                error = %e,
                claimed_tenant_id = %tenant_id,
                "oauth2: tenant lookup failed for client-auth-failure audit; \
                 routing to the system partition"
            );
            (Uuid::nil(), Some("tenant_lookup_failed"))
        }
    };

    // Control 2 — bound the one remaining caller-controlled string, by BYTES,
    // truncating on a character boundary so the stored value stays valid UTF-8.
    let attempted_client_id: Option<String> =
        attempted_client_id.map(truncate_bytes_on_char_boundary);

    if let Err(e) = audit_repo
        .append(CreateAuditLogEntry {
            tenant_id: attributed_tenant,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "oauth2.client_auth_failed".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            // Control 3 — the unforgeable half.
            ip_address: peer_ip,
            metadata: Some(serde_json::json!({
                "client_id": attempted_client_id,
                "grant_type": grant_type,
                // Named so nobody downstream mistakes it for verified input.
                "forwarded_for_untrusted": forwarded_ip_untrusted,
                // Present only on a system-partition row: the tenant the caller
                // named, and why it could not be attributed. Also caller-supplied.
                "claimed_tenant_id_untrusted": tenant_note.map(|_| tenant_id.to_string()),
                "unattributed_reason": tenant_note,
            })),
        })
        .await
    {
        // Never propagated: a token-endpoint 401 must not become a 500 because
        // the audit sink is unavailable (T-15-04).
        tracing::error!(
            error = %e,
            tenant_id = %attributed_tenant,
            %grant_type,
            "oauth2: failed to write oauth2.client_auth_failed audit log"
        );
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
/// `POST /oauth2/device_authorization` — RFC 8628 §3.1–3.2 (B2).
///
/// Issues a `device_code` (the secret the device polls with), a short
/// `user_code` (the string a human reads off a screen and types elsewhere),
/// and the `verification_uri` to send them to.
///
/// **Unauthenticated by design.** RFC 8628 exists for input-constrained public
/// clients — a television, a CLI, an IoT sensor — none of which can keep a
/// client secret, so there is no secret to present. What is still verified is
/// that `client_id` names a real client in this tenant that is registered for
/// this grant; without that check any string could mint pending grants and
/// exhaust the user-code space, which is a denial of service against every
/// legitimate device at once.
///
/// The endpoint carries its own rate-limit bucket (see `server.rs`) rather
/// than sharing the generic token bucket: it is unauthenticated and it
/// allocates state, which is a different abuse profile from the token
/// endpoint's.
#[utoipa::path(
    post,
    path = "/oauth2/device_authorization",
    tag = "oauth2",
    params(TenantQuery),
    request_body(
        content_type = "application/x-www-form-urlencoded",
        content = DeviceAuthorizationRequest,
    ),
    responses(
        (status = 200, description = "Device and user codes",
         body = DeviceAuthorizationResponse),
        (status = 400, description = "OAuth2 error", body = OAuth2ErrorResponse),
    ),
)]
pub async fn device_authorization<C: Connection + Clone>(
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<DeviceAuthorizationRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;
    match state
        .device_authorization_service
        .authorize(tenant_id, form.into_inner())
        .await
    {
        Ok(resp) => HttpResponse::Ok()
            .append_header(("Cache-Control", "no-store"))
            .append_header(("Pragma", "no-cache"))
            .json(resp),
        Err(e) => build_oauth2_error_response(&e),
    }
}

/// The `urn:ietf:params:oauth:grant-type:token-exchange` arm of the token
/// endpoint (B3).
///
/// The form is re-read rather than typed at the route because RFC 8693's
/// parameters are disjoint from RFC 6749's and actix deserializes one body
/// once — so `TokenRequest` carries the shared fields and the
/// exchange-specific ones are pulled from the raw form here.
async fn handle_token_exchange<C: Connection + Clone>(
    tenant_id: Uuid,
    form: TokenRequest,
    state: &web::Data<AppState<C>>,
) -> HttpResponse {
    let (Some(client_id), Some(client_secret)) =
        (form.client_id.as_deref(), form.client_secret.as_deref())
    else {
        return build_oauth2_error_response(&OAuth2Error::InvalidClient(
            "the token-exchange grant requires client authentication".into(),
        ));
    };

    let client = match state
        .token_service
        .authenticate_client(tenant_id, client_id, client_secret)
        .await
    {
        Ok(client) => client,
        Err(e) => return build_oauth2_error_response(&e),
    };

    // B3: the exchange's own bucket, applied here rather than as route
    // middleware because `/oauth2/token` serves every grant and actix
    // deserializes the body once — the grant is not knowable until the form
    // has been read, which is after the middleware chain has run.
    //
    // Keyed by the authenticated client, deliberately: an exchange always
    // carries client credentials, so unlike the device endpoints there is a
    // real identity to key on, and per-IP would collapse a whole mesh behind
    // one NAT into a single bucket. Counted AFTER authentication so an
    // unauthenticated caller cannot consume a real client's allowance.
    //
    // `check_at` rather than `check`: it derives the window itself so it can
    // also see the OFFSET into it, which is the sliding-window bound the J1
    // fix added after run 5 measured boundary over-admission. Re-deriving a
    // truncated window here would quietly opt this endpoint out of that fix.
    if !state.shared_rate_limit.check_at(
        &format!("oauth2_token_exchange:{}:{}", tenant_id, client.client_id),
        chrono::Utc::now(),
        state.rate_limit_cfg.token_exchange_per_min,
    ) {
        return HttpResponse::TooManyRequests()
            .append_header(("Cache-Control", "no-store"))
            .json(OAuth2ErrorResponse {
                error: "slow_down".into(),
                error_description: "token-exchange rate limit exceeded for this client".into(),
            });
    }

    let Some(exchange_req) = form.exchange_request() else {
        return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
            "subject_token and subject_token_type are required for the \
             token-exchange grant"
                .into(),
        ));
    };

    match state
        .token_exchange_service
        .exchange(tenant_id, &client, exchange_req)
        .await
    {
        Ok(outcome) => {
            // Audited BEFORE the token is returned, not after. For an
            // impersonation this record is the only surviving evidence that
            // the acting party was not the subject — the token deliberately
            // carries no `act` claim — so it must not be lost to a crash
            // between issuing and logging.
            tracing::info!(
                target: "axiam::audit",
                event = "oauth2.token_exchange",
                tenant_id = %tenant_id,
                client_id = %client.client_id,
                kind = outcome.kind.as_str(),
                subject = %outcome.subject,
                actor = outcome.actor.as_deref().unwrap_or("-"),
                granted_scopes = %outcome.granted_scopes.join(" "),
                audience = %outcome.audience,
                "token exchange"
            );
            HttpResponse::Ok()
                .append_header(("Cache-Control", "no-store"))
                .append_header(("Pragma", "no-cache"))
                .json(outcome.response)
        }
        Err(e) => {
            tracing::info!(
                target: "axiam::audit",
                event = "oauth2.token_exchange",
                tenant_id = %tenant_id,
                client_id = %client.client_id,
                outcome = "refused",
                error = e.error_code(),
                "token exchange refused"
            );
            build_oauth2_error_response(&e)
        }
    }
}

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

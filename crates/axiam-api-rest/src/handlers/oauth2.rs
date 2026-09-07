//! OAuth2 authorization and token endpoints.

use actix_web::{HttpRequest, HttpResponse, web};
use axiam_auth::config::AuthConfig;
use axiam_core::models::uma::{UMA_CLAIM_TOKEN_FORMAT, UMA_TICKET_GRANT_TYPE};
use axiam_core::repository::{
    OAuth2ClientRepository, SessionClientRepository, SessionRepository, UserRepository,
};
use axiam_oauth2::authn_params::{AuthnRequestParams, RawAuthnParams};
use axiam_oauth2::authorize::{AuthorizeRequest, RequestObject, SessionEvidence};
use axiam_oauth2::device_service::{
    DEVICE_CODE_GRANT_TYPE, DeviceAuthorizationRequest, DeviceAuthorizationResponse,
};
use axiam_oauth2::error::OAuth2Error;
use axiam_oauth2::jwks_cache::JwksCacheResponse;
use axiam_oauth2::mtls::PresentedCertificate;
use axiam_oauth2::oidc::{
    JwksDocument, OidcDiscoveryDocument, UserInfoResponse, build_discovery_document,
};
use axiam_oauth2::token::{
    IntrospectRequest, IntrospectionResponse, RevokeRequest, TokenRequest, TokenRequestContext,
    TokenResponse,
};
use axiam_oauth2::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE;
use axiam_oauth2::uma::UmaError;
use serde::{Deserialize, Serialize};
use surrealdb::Connection;
use uuid::Uuid;

use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogRepository, TenantRepository};
use axiam_db::{SurrealAuditLogRepository, SurrealTenantRepository};

use crate::extractors::auth::{AuthenticatedUser, MaybeAuthenticatedUser};
use crate::extractors::cert_auth::VerifiedClientCert;
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
    /// Required unless `request_uri` is present (B5 / RFC 9126 §4).
    pub response_type: Option<String>,
    pub client_id: String,
    /// Required unless `request_uri` is present.
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    /// B5 — a `urn:ietf:params:oauth:request_uri:` value obtained from
    /// `/oauth2/par`. Mutually exclusive with the inline parameters above.
    pub request_uri: Option<String>,
    /// X7 G12 — RFC 9101 `request`, a request object by value. AXIAM does not
    /// accept one; the field exists so the refusal can name the right error
    /// code (`request_not_supported`) instead of the parameter being dropped
    /// by serde and the request quietly succeeding without it.
    pub request: Option<String>,
    // X7.1 — the nine OIDC authentication-request parameters (OIDC Core
    // §3.1.2.1, §5.2, §5.5). Declared so they can be *parsed*; whether any of
    // them is acted on is the client's `authn_request_params` registration,
    // and in this wave the answer is "none of them, for anybody".
    //
    // Adding them here is the one change in this file that alters what serde
    // accepts. It cannot change what a request *does*: previously they were
    // dropped as unknown parameters, and the golden-path tests (P1) assert
    // that a standard client sending all nine still gets a byte-identical
    // redirect, token response and ID token.
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub display: Option<String>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    /// W3 — which tenant this authorization request is for, read **only** when
    /// the request carries no authenticated principal (plan §4.0).
    ///
    /// Every session, client and code in AXIAM is tenant-scoped, and until this
    /// wave the tenant came exclusively from the caller's own access token. An
    /// anonymous browser has no token, so the login hop cannot even look up the
    /// client whose `browser_sso` field decides how to answer it — hence a
    /// parameter, the same way `/oauth2/end_session` and `/oauth2/token` already
    /// take one, and the same way the tenant-scoped discovery document is
    /// fetched.
    ///
    /// **Ignored whenever a principal was resolved from a token**, which is
    /// every request that works today: the token's tenant wins, unconditionally,
    /// exactly as before. A request that omits it and has no principal is
    /// answered with today's 401 — so a client registered today, which has never
    /// sent it, cannot observe that it exists.
    pub tenant_id: Option<Uuid>,
    /// W3 — the login hop's loop guard (`axiam_login_hop`).
    ///
    /// Set by this server inside the `return_to` it builds, and read here to
    /// recognise the return leg. See `axiam_oauth2::login_hop` for why its
    /// presence bounds the hop at one redirect, and for why a browser that
    /// strips it harms only itself.
    #[serde(rename = "axiam_login_hop")]
    pub login_hop: Option<String>,
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

/// Read the authentication behind this request's session (X7.2, plan §4.3).
///
/// The evidence is snapshotted onto the authorization code, so it has to be
/// read here, while the session still exists: refresh rotation replaces the
/// row, and by the time the code is redeemed the session it was minted from
/// may be a different row with a different id.
///
/// # It never fails the request
///
/// A session that cannot be read yields empty evidence and a `debug!` line,
/// not an error. Two reasons, and both are invariant 4: an authorization
/// request that works today must not start failing because of a column added
/// this wave, and the principal on this path is not always a browser session
/// at all (a bearer token minted for a service, a session already rotated
/// away). Empty evidence is also the strict reading — a code with no
/// `auth_time` can never present as fresh.
async fn resolve_session_evidence<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    session_id: Uuid,
) -> SessionEvidence {
    match state.session_repo.get_by_id(tenant_id, session_id).await {
        Ok(session) => SessionEvidence {
            auth_time: Some(session.authenticated_at),
            amr: session.amr,
        },
        Err(e) => {
            tracing::debug!(
                error = %e,
                %session_id,
                "no session row behind this authorization request; the code is issued \
                 without authentication evidence"
            );
            SessionEvidence::default()
        }
    }
}

/// Record the outcome of a `prompt=none` authorization request (W4, plan §4.2).
///
/// `prompt=none` is a **silent-authentication oracle**: a registered relying
/// party learns, without any interaction, whether this browser is signed in.
/// That is inherent to the parameter and it is accepted — it is bounded to
/// clients registered in this tenant with exact `redirect_uri` matching, and
/// nothing but one bit crosses — but "accepted" and "invisible" are different
/// things. One audit row per outcome is what makes abuse of it something an
/// operator can see and count rather than something they have to be told about
/// by the party doing it.
///
/// Two actions are emitted, `oauth2.prompt_none.code` and
/// `oauth2.prompt_none.login_required`. The plan names a third,
/// `oauth2.prompt_none.consent_required`, which **cannot** be emitted in W4:
/// it needs a consent-gated scope and there are none until W7 (plan §4.8). It
/// is not written here rather than written into a branch that can never run.
///
/// Never fails the request. An audit sink that is down costs a row, not a
/// login (T-15-04).
async fn audit_prompt_none<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    tenant_id: Uuid,
    client_id: &str,
    refusal: Option<&OAuth2Error>,
) {
    let (action, result) = match refusal {
        None => ("oauth2.prompt_none.code", AuditOutcome::Success),
        Some(e) => (
            match e.error_code() {
                "login_required" => "oauth2.prompt_none.login_required",
                _ => "oauth2.prompt_none.refused",
            },
            AuditOutcome::Failure,
        ),
    };
    if let Err(e) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: action.into(),
            resource_id: None,
            outcome: result,
            ip_address: peer_ip(http_req),
            metadata: Some(serde_json::json!({
                // The `client_id` is the point of the row: the oracle is
                // per-client, so counting it per client is what makes a
                // relying party polling every few seconds visible.
                "client_id": truncate_bytes_on_char_boundary(client_id),
                "error": refusal.map(OAuth2Error::error_code),
            })),
        })
        .await
    {
        tracing::error!(
            error = %e,
            %tenant_id,
            "could not record a prompt=none outcome; the authorization request is unaffected"
        );
    }
}

/// Decode an `id_token_hint` presented at the authorization endpoint (W4,
/// plan §4.2).
///
/// One decoder, shared with `/oauth2/end_session`
/// ([`axiam_oauth2::logout::decode_id_token_hint`]): the signature is checked,
/// the expiry deliberately is not — an `id_token_hint` has routinely expired,
/// which is exactly why an RP is sending one rather than a live token — and
/// `aud` is read out rather than validated against, because who the token was
/// for is part of what the caller wants to learn. A second decoder here would
/// be a second opinion about what a hint proves.
///
/// Returns `None` when no hint arrived and when one arrived and did not
/// verify. The caller distinguishes them by
/// [`AuthnRequestParams::id_token_hint`], and treats the second as a hint that
/// names somebody else rather than as an absent one — dropping an unverifiable
/// hint would let any string turn a `prompt=none` refusal into a code.
///
/// Run for every request carrying the parameter, not only for the honour lane.
/// It costs one Ed25519 verification of a value the request already carried,
/// it cannot change any response on the `ignore` lane (nothing reads the
/// result there), and making it conditional would put the lane decision in a
/// second place.
fn decode_authorize_id_token_hint<C: Connection + Clone>(
    state: &AppState<C>,
    params: &AuthnRequestParams,
) -> Option<axiam_oauth2::logout::IdTokenHint> {
    let raw = params.id_token_hint.as_deref()?;
    axiam_oauth2::logout::decode_id_token_hint(raw, &state.auth_config.jwt_public_key_pem)
}

/// Classify a request object on an authorization request (X7 G12, plan §4.10).
///
/// AXIAM accepts neither form. `request` is RFC 9101's request object by
/// value; a `request_uri` that is not a `urn:ietf:params:oauth:request_uri:`
/// handle is a request object by reference, which would have the authorization
/// server fetch an attacker-chosen URL — an SSRF primitive that PAR (RFC 9126
/// §1) made unnecessary and that FAPI 2.0 does not ask for.
///
/// `request` is checked first: when both arrive, the by-value object is the
/// one the server would have had to *read*, so it is the one the refusal
/// should name.
///
/// Returns `None` for a request carrying no request object at all, including
/// one whose `request_uri` is a genuine PAR handle — that path is untouched.
fn classify_request_object(
    request: Option<&str>,
    request_uri: Option<&str>,
) -> Option<RequestObject> {
    // A blank value is a client library filling in a template, not an object.
    // Refusing it would break a request that works today and carries nothing.
    fn present(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|s| !s.is_empty())
    }

    if present(request).is_some() {
        return Some(RequestObject::ByValue);
    }
    match present(request_uri) {
        Some(uri) if !uri.starts_with(axiam_oauth2::par::REQUEST_URI_PREFIX) => {
            Some(RequestObject::ByReference)
        }
        _ => None,
    }
}

/// What [`resolve_authorize_principal`] answers with when there is no principal
/// to return: a finished response, boxed.
///
/// Boxed because `HttpResponse` is a large value (well over
/// `clippy::result_large_err`'s 128-byte threshold), and a `Result` whose error
/// variant is large makes *every* caller pay that size on the success path too.
/// Do not unbox it back for tidiness — CI's clippy is the thing that notices.
type AuthorizeRefusal = Box<HttpResponse>;

/// The principal an authorization request is acting for (W3, plan §4.0).
///
/// Three fields rather than an [`AuthenticatedUser`] because the two ways of
/// arriving here produce different amounts of context and only these three are
/// used past this point: an access token carries an organization scope and an
/// active-tenant header, an `axiam_op_session` cookie carries a session row.
/// Modelling the union would invite a later reader to ask a question of the
/// cookie path that only the token path can answer.
struct AuthorizePrincipal {
    tenant_id: Uuid,
    user_id: Uuid,
    session_id: Uuid,
}

/// Is this `return_to` a path on an origin this deployment owns?
///
/// The second of the two server-side checks the plan asks for. The first is
/// [`axiam_oauth2::login_hop::validate_return_to`], which is syntactic and
/// demands the exact authorize path; this one *resolves* the candidate against
/// the issuer and hands the result to
/// [`require_deployment_spa_origin`](crate::handlers::federation_login::require_deployment_spa_origin)
/// — the rule that already decides where a federation SSO handoff code may be
/// sent, rather than a second rule that could come to disagree with it.
///
/// While the syntactic check demands `/oauth2/authorize?…` this is redundant,
/// and it is kept for the case that stops being true: `Url::join` is what turns
/// `//evil.example` into a different host and `/a/../../b` into `/b`, so it is
/// an independent opinion on the two attacks that are about *resolution*
/// rather than about spelling.
fn return_to_is_on_this_deployment<C: Connection + Clone>(
    state: &AppState<C>,
    return_to: &str,
) -> bool {
    let Ok(base) = url::Url::parse(state.auth_config.effective_issuer()) else {
        return false;
    };
    let Ok(resolved) = base.join(return_to) else {
        return false;
    };
    if resolved.path() != axiam_oauth2::login_hop::AUTHORIZE_PATH {
        return false;
    }
    crate::handlers::federation_login::require_deployment_spa_origin(state, resolved.as_str())
        .is_ok()
}

/// Resolve who this authorization request is acting for (W3, plan §4.0).
///
/// Two ways in, in this order:
///
/// 1. **An access token** — the `axiam_access` cookie or a `Bearer`/`DPoP`
///    header, via [`AuthenticatedUser`]. Unchanged, and it wins whenever it
///    succeeds. Every request that works today takes this path and cannot tell
///    that the other exists.
/// 2. **The `axiam_op_session` cookie**, and only for a client registered
///    `browser_sso`. This is the path that makes AXIAM usable as an OP for a
///    third-party relying party at all: `axiam_access` is `SameSite=Strict`, so
///    the cross-site top-level navigation an RP redirect *is* never carries it,
///    and until this wave a signed-in user arrived here anonymous.
///
/// # Order of operations, and why the client is loaded first
///
/// The client must be read before the cookie is, because the client's
/// registration is what decides whether the cookie is consulted. That is the
/// reordering plan §4.0 describes, and it is not a new trust decision — the
/// authorize service already loads this row before any redirectable error, so
/// the lookup moves one step earlier rather than appearing.
///
/// # Every anonymous refusal is today's refusal
///
/// No tenant, no such client, a client that did not opt in, a repository that
/// failed: all four return the **same** 401 the extractor would have produced,
/// byte for byte, by returning the extractor's own error object. That is
/// invariant 4 and it is also what keeps the endpoint from becoming an oracle:
/// an anonymous caller cannot learn from the response whether a `client_id`
/// exists in a tenant, only whether it opted into the hop.
///
/// # Errors
///
/// Returns a complete [`HttpResponse`] — the 401, the 302 into the login page,
/// or the loop guard's terminal `login_required` — because each of the three
/// is finished at the point it is decided and none is expressible as an
/// [`OAuth2Error`] the caller could usefully re-render. Boxed: see
/// [`AuthorizeRefusal`].
async fn resolve_authorize_principal<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    q: &AuthorizeQuery,
    maybe_user: MaybeAuthenticatedUser,
) -> Result<AuthorizePrincipal, AuthorizeRefusal> {
    use actix_web::ResponseError;

    let auth_error = match maybe_user.into_result() {
        Ok(user) => {
            // Path 1. `tenant_id` on the query is ignored here, deliberately:
            // the tenant a token was minted for is the tenant it acts in, and
            // letting a query parameter move that would be a tenant-crossing
            // primitive handed to whoever holds the browser.
            return Ok(AuthorizePrincipal {
                tenant_id: user.tenant_id,
                user_id: user.user_id,
                session_id: user.session_id,
            });
        }
        Err(e) => e,
    };

    // ---- Path 2: anonymous ------------------------------------------------
    let Some(tenant_id) = q.tenant_id else {
        return Err(Box::new(auth_error.error_response()));
    };
    let Ok(client) = state
        .oauth2_client_repo
        .get_by_client_id(tenant_id, &q.client_id)
        .await
    else {
        return Err(Box::new(auth_error.error_response()));
    };
    if !client.browser_sso {
        // **T0.1 / T0.5 / M7's I4 twin.** Every client registered today lands
        // here, including one whose browser happens to be carrying an
        // `axiam_op_session` cookie: the cookie is not read, because reading it
        // is what `browser_sso` opts into.
        return Err(Box::new(auth_error.error_response()));
    }

    // The cookie, and whether it still names a live session in this tenant.
    let presented = http_req.cookie(crate::middleware::csrf::COOKIE_OP_SESSION);
    let resolved = match presented.as_ref() {
        Some(cookie) => {
            let digest = axiam_auth::token::hash_browser_session_token(cookie.value());
            match state
                .session_repo
                .get_by_browser_token_hash(tenant_id, &digest)
                .await
            {
                Ok(found) => found,
                Err(e) => {
                    // A read failure is not a principal. Logged without the
                    // cookie value or its digest — the first is a credential and
                    // the second is enough to recognise one.
                    tracing::warn!(
                        error = %e,
                        %tenant_id,
                        "could not resolve the OP browser session; treating the \
                         request as anonymous"
                    );
                    None
                }
            }
        }
        None => None,
    };

    if let Some(session) = resolved {
        return Ok(AuthorizePrincipal {
            tenant_id,
            user_id: session.user_id,
            session_id: session.id,
        });
    }

    // ---- No principal: refuse silently, hop, or stop ---------------------
    //
    // W4 (plan §4.2, T1.1/T1.7). `prompt=none` says: answer without showing
    // the end user anything. There is nothing to answer with — no session
    // resolved — so the answer is `login_required`, **redirected to the
    // relying party** rather than to a sign-in page it forbade.
    //
    // Read from the query string only. A pushed request's `prompt` cannot be
    // seen here at all (the handle is consumed later, inside the handler), so
    // a PAR client's `prompt=none` takes the hop first and is refused on the
    // return leg instead, by the marker rule in `axiam_oauth2::honour` — the
    // interaction is never converted into a code either way.
    //
    // Honour lane only, and that is what keeps T0.1 exact: a `browser_sso`
    // client registered `ignore` — which is every client that exists — sending
    // `prompt=none` gets today's answer, byte for byte.
    //
    // W5 (plan §4.5/§4.6) reads the same bundle for the cosmetic four, which is
    // why it is parsed once here with every field rather than only `prompt`.
    // Query string only, as before: a pushed request's parameters cannot be
    // seen at this point (the handle is consumed inside the handler, after a
    // principal exists), so a PAR client's presentation reaches the page on the
    // *interaction* arm below instead. Both arms build their URL through the
    // one builder, so the two carriers cannot come to disagree about what a
    // `/login` URL looks like.
    let honour = client.authn_request_params.is_honour();
    let authn_params = honour.then(|| {
        AuthnRequestParams::parse(&RawAuthnParams {
            prompt: q.prompt.as_deref(),
            login_hint: q.login_hint.as_deref(),
            display: q.display.as_deref(),
            ui_locales: q.ui_locales.as_deref(),
            // `claims_locales` is deliberately not read: it selects the
            // language of *claim values*, which AXIAM does not localise, and
            // it must not reach the page's language. See
            // `axiam_oauth2::login_hop::Cosmetic::from_params`.
            ..Default::default()
        })
    });
    if let Some(params) = authn_params.as_ref()
        && params
            .prompt
            .contains(&axiam_oauth2::authn_params::Prompt::None)
    {
        let refusal = OAuth2Error::LoginRequired(
            "no end user is authenticated at this authorization server, and prompt=none \
                 forbids asking them to sign in"
                .into(),
        );
        audit_prompt_none(state, http_req, tenant_id, &q.client_id, Some(&refusal)).await;
        // RFC 6749 §4.1.2.1: an error is redirected only to a
        // `redirect_uri` this client registered. Exact match, the same
        // comparison `AuthorizeService::authorize` makes — an unregistered
        // or absent one is answered directly instead.
        return Err(Box::new(match q.redirect_uri.as_deref() {
            Some(uri) if client.redirect_uris.iter().any(|r| r == uri) => {
                build_error_redirect(uri, &refusal, q.state.as_deref(), &state.auth_config)
            }
            _ => build_oauth2_error_response(&refusal),
        }));
    }

    // The loop guard. A request that already carries the marker is one this
    // server sent to the login page and got back; sending it there a second
    // time is the non-terminating case, so it is answered instead. See
    // `axiam_oauth2::login_hop` for the full argument.
    if axiam_oauth2::login_hop::is_return_leg(q.login_hop.as_deref()) {
        tracing::warn!(
            %tenant_id,
            client_id = %q.client_id,
            "an authorization request returned from the login hop still \
             carrying no OP session; refusing to redirect again"
        );
        return Err(Box::new(build_oauth2_error_response(
            &OAuth2Error::LoginRequired(
                "the sign-in did not establish a session for this tenant at this \
                 origin; sign in again from the relying party, and check that the \
                 browser accepts the axiam_op_session cookie"
                    .into(),
            ),
        )));
    }

    let Some(return_to) = axiam_oauth2::login_hop::build_return_to(http_req.query_string()) else {
        // Nothing safe to come back to. Answer as if the request had been
        // anonymous with no `browser_sso` at all rather than send a browser
        // somewhere on a value that did not validate.
        return Err(Box::new(auth_error.error_response()));
    };
    if !return_to_is_on_this_deployment(state, &return_to) {
        return Err(Box::new(auth_error.error_response()));
    }

    // A cookie that was presented and did not resolve is stale: this browser
    // believes it is signed in and is not. `reauth` tells the SPA to say so and
    // to authenticate afresh instead of trusting what it already holds, and the
    // dead cookie is removed on the way out so the next attempt starts clean.
    let stale = presented.is_some();
    // W5. The presentation the relying party asked for, on the honour lane and
    // nowhere else: `authn_params` is `None` for every client registered
    // `ignore`, so `Cosmetic::NONE` is what they get and their `/login` URL is
    // byte-identical to the one W3 built. Invariant 4, as a type rather than as
    // a branch somebody has to remember to write.
    //
    // The tenant default is `None` here — see plan §4.6's W5 amendment for why
    // W5 ships the fallback chain without a tenant surface to configure it.
    let cosmetic = authn_params
        .as_ref()
        .map_or(axiam_oauth2::login_hop::Cosmetic::NONE, |params| {
            axiam_oauth2::login_hop::Cosmetic::from_params(params, None)
        });
    let location =
        axiam_oauth2::login_hop::build_login_redirect_for(&return_to, stale, None, &cosmetic);

    let mut builder = HttpResponse::Found();
    builder
        .append_header((actix_web::http::header::LOCATION, location))
        // The URL carries the whole authorization request; it must not be
        // cached, and it must not travel onward as a referrer.
        .append_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
        .append_header(("Referrer-Policy", "no-referrer"));
    if stale {
        builder.cookie(crate::middleware::csrf::clear_op_session_cookie());
    }
    Err(Box::new(builder.finish()))
}

/// `GET /oauth2/authorize` -- OAuth2 authorization endpoint.
///
/// A request carrying an access token authorizes as its subject. A request
/// carrying none is answered with a 401 JSON body — unless the client it names
/// is registered `browser_sso`, in which case it is either recognised by its
/// `axiam_op_session` cookie or redirected to the sign-in page and brought back
/// (W3, plan §4.0). See [`resolve_authorize_principal`].
///
/// On success, redirects to `redirect_uri?code=...&state=...`.
/// On error, redirects with `?error=...&error_description=...&state=...`.
#[utoipa::path(
    get,
    path = "/oauth2/authorize",
    tag = "oauth2",
    params(AuthorizeQuery),
    responses(
        (status = 302, description = "Redirect with authorization code, or to \
                                      the sign-in page for a browser_sso client"),
        (status = 400, description = "OAuth2 error", body = OAuth2ErrorResponse),
        (status = 401, description = "No authenticated principal, and the \
                                      client did not opt into the login hop"),
    ),
    security(("bearer" = []))
)]
pub async fn authorize<C: Connection + Clone>(
    http_req: HttpRequest,
    maybe_user: MaybeAuthenticatedUser,
    // W3: a `Result` rather than a plain extractor so that the **order** of
    // today's refusals is preserved. `AuthenticatedUser` used to be the first
    // extractor on this handler, so an unauthenticated request with an
    // unparseable query was answered 401 and never reached the body.
    // `MaybeAuthenticatedUser` cannot fail, which would have promoted the query
    // error to first place and turned that 401 into a 400 — a behaviour change
    // for nobody's benefit. Resolving both here keeps the precedence explicit.
    query: Result<web::Query<AuthorizeQuery>, actix_web::Error>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    use actix_web::ResponseError;

    let q = match query {
        Ok(q) => q.into_inner(),
        Err(query_error) => {
            return match maybe_user.into_result() {
                Err(auth_error) => auth_error.error_response(),
                Ok(_) => query_error.error_response(),
            };
        }
    };

    let user = match resolve_authorize_principal(&state, &http_req, &q, maybe_user).await {
        Ok(principal) => principal,
        Err(response) => return *response,
    };

    // X7 G12 (plan §4.10). Classify request objects FIRST, before the PAR
    // branch below, for two reasons. A `request_uri` that is not a PAR handle
    // would otherwise fall into `par_service.consume` and come back as a
    // generic `invalid_request`, losing the code OIDC Core §3.1.2.6 defines
    // and a conformance suite matches on; and a non-PAR `request_uri` sent
    // alongside inline parameters would earn the "must not be combined"
    // refusal, which describes a rule that is beside the point when the
    // parameter is not supported at all.
    //
    // Both forms are refused either way — this only decides *which* refusal.
    // The marker travels on the `AuthorizeRequest` rather than being answered
    // here so that the client and its `redirect_uri` are validated first: a
    // refusal is redirected only to a URI the client actually registered, and
    // otherwise answered directly.
    let request_object = classify_request_object(q.request.as_deref(), q.request_uri.as_deref());

    // X7.2 — resolved once, for both carriers: the evidence describes the
    // session this request arrives in, which is the same session whether the
    // parameters came inline or through PAR.
    let session_evidence = resolve_session_evidence(&state, user.tenant_id, user.session_id).await;

    // B5 / RFC 9126 §4. The two forms do not mix: a request carrying both a
    // `request_uri` and inline parameters is refused rather than merged.
    // Merging is exactly where parameter confusion lives — an attacker
    // supplies the inline value they want and lets the pushed copy satisfy
    // whatever check reads the other one.
    //
    // A refused request object takes the inline branch whatever it carried:
    // there is nothing to consume, and the branch exists only to reach the
    // validation that decides how the refusal is reported.
    let request_uri = match request_object {
        Some(_) => None,
        None => q.request_uri,
    };
    let req = match request_uri {
        Some(request_uri) => {
            if axiam_oauth2::par::has_inline_params(
                q.response_type.as_deref(),
                q.redirect_uri.as_deref(),
                q.scope.as_deref(),
                q.code_challenge.as_deref(),
            ) {
                return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
                    "request_uri must not be combined with inline \
                     authorization parameters"
                        .into(),
                ));
            }

            let params = match state
                .oauth2
                .par_service
                .consume(user.tenant_id, &q.client_id, &request_uri)
                .await
            {
                Ok(params) => params,
                // W3 (plan §4.0, F10). A pushed request lives 60 seconds. A
                // user who took longer than that to type a password comes back
                // here to a handle that no longer exists — and telling them
                // `invalid_request: request_uri is unknown, expired, or used`
                // describes a client bug that did not happen. On a return leg,
                // and only there, the recoverable code is used instead: the
                // relying party pushes again and restarts, which is RFC 9126
                // §2.2's own design rather than a workaround for it.
                //
                // Narrow on purpose. Only the "gone" refusal is remapped, only
                // when the marker says this request came back from the login
                // page, so an ordinary authorization request with a dead handle
                // gets exactly the answer it got before this wave.
                Err(e)
                    if axiam_oauth2::login_hop::is_return_leg(q.login_hop.as_deref())
                        && axiam_oauth2::par::is_request_uri_gone(&e) =>
                {
                    return build_oauth2_error_response(&OAuth2Error::InvalidRequestUri(
                        "the pushed authorization request expired while signing in \
                         (a request_uri lives 60 seconds); push it again and restart \
                         the authorization request"
                            .into(),
                    ));
                }
                Err(e) => return build_oauth2_error_response(&e),
            };

            // X7.1 — parsed from the *pushed* copy, never from the query
            // string. `state` and `nonce` already work this way and for the
            // same reason: a parameter the client chose at push time must not
            // be substitutable by the browser that carries the handle.
            let authn_params = AuthnRequestParams::parse(&RawAuthnParams::from(&params));

            // W4 (T1.3) — and this is the other half of that sentence: the
            // query string's copies are not merely ignored, they are grounds
            // to refuse the request on the honour lane. Parsed rather than
            // tested field by field so "an authentication-request parameter
            // arrived" means the same thing here as everywhere else, blank
            // template values included.
            let inline_authn_params_beside_request_uri =
                !AuthnRequestParams::parse(&RawAuthnParams {
                    prompt: q.prompt.as_deref(),
                    max_age: q.max_age.as_deref(),
                    acr_values: q.acr_values.as_deref(),
                    claims: q.claims.as_deref(),
                    id_token_hint: q.id_token_hint.as_deref(),
                    login_hint: q.login_hint.as_deref(),
                    display: q.display.as_deref(),
                    ui_locales: q.ui_locales.as_deref(),
                    claims_locales: q.claims_locales.as_deref(),
                })
                .is_empty();

            AuthorizeRequest {
                tenant_id: user.tenant_id,
                user_id: user.user_id,
                response_type: params.response_type,
                client_id: q.client_id,
                redirect_uri: params.redirect_uri,
                scope: params.scope,
                // `state` and `nonce` come from the pushed request too: they
                // were the client's to choose at push time, and honouring a
                // query-string copy would let the browser substitute its own.
                state: params.state,
                code_challenge: params.code_challenge,
                code_challenge_method: params.code_challenge_method,
                nonce: params.nonce,
                // B5: the browser session this authorization happens within.
                // It reaches the ID token as `sid`, which is what lets a
                // back-channel logout token name one session rather than the
                // subject's every session.
                session_id: Some(user.session_id),
                via_par: true,
                id_token_hint: decode_authorize_id_token_hint(&state, &authn_params),
                inline_authn_params_beside_request_uri,
                login_hop_return_leg: axiam_oauth2::login_hop::is_return_leg(
                    q.login_hop.as_deref(),
                ),
                authn_params,
                request_object,
                session_evidence,
            }
        }
        None => {
            let authn_params = AuthnRequestParams::parse(&RawAuthnParams {
                prompt: q.prompt.as_deref(),
                max_age: q.max_age.as_deref(),
                acr_values: q.acr_values.as_deref(),
                claims: q.claims.as_deref(),
                id_token_hint: q.id_token_hint.as_deref(),
                login_hint: q.login_hint.as_deref(),
                display: q.display.as_deref(),
                ui_locales: q.ui_locales.as_deref(),
                claims_locales: q.claims_locales.as_deref(),
            });
            let (Some(response_type), Some(redirect_uri)) = (q.response_type, q.redirect_uri)
            else {
                // A refused request object with no inline redirect_uri cannot
                // be reported by redirecting — there is no validated URI to
                // redirect to — so it is answered directly, with its own code
                // rather than the generic complaint about missing parameters.
                if let Some(object) = request_object {
                    return build_oauth2_error_response(&object.into_error());
                }
                return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
                    "response_type and redirect_uri are required unless \
                     request_uri is used"
                        .into(),
                ));
            };
            AuthorizeRequest {
                tenant_id: user.tenant_id,
                user_id: user.user_id,
                response_type,
                client_id: q.client_id,
                redirect_uri,
                scope: q.scope,
                state: q.state,
                code_challenge: q.code_challenge,
                code_challenge_method: q.code_challenge_method,
                nonce: q.nonce,
                session_id: Some(user.session_id),
                via_par: false,
                id_token_hint: decode_authorize_id_token_hint(&state, &authn_params),
                // Not a pushed request: there is no second copy to conflict
                // with.
                inline_authn_params_beside_request_uri: false,
                login_hop_return_leg: axiam_oauth2::login_hop::is_return_leg(
                    q.login_hop.as_deref(),
                ),
                authn_params,
                request_object,
                session_evidence,
            }
        }
    };

    // Captured before `req` moves: the error path needs the *resolved*
    // redirect_uri and state, which for a PAR request came from the pushed
    // parameters rather than the query string.
    let resolved_redirect_uri = req.redirect_uri.clone();
    let resolved_state = req.state.clone();
    let authorized_client_id = req.client_id.clone();

    // W4 — was this a `prompt=none` request? Captured before `req` moves so
    // the audit rows below can name the outcome of a silent authorization
    // (plan §4.2, "Threats and what remains"): the one-bit login-status oracle
    // `prompt=none` inherently gives a registered relying party is accepted,
    // and made visible.
    let silent = req
        .authn_params
        .prompt
        .contains(&axiam_oauth2::authn_params::Prompt::None);

    // W5 — the presentation the sign-in page will be asked for, if it is
    // shown. Captured before `req` moves, from the bundle whichever carrier
    // delivered it, and used **only** inside the interaction arm below.
    //
    // There is no honour-lane condition here and there does not need to be:
    // `AuthorizeOutcome::Interact` is produced at exactly one place
    // (`axiam_oauth2::authorize`, step 6b) and that place is inside
    // `if fapi::honours_authn_params(&client)`. A client on the `ignore` lane
    // never reaches the arm that reads this, so it never reaches a `/login`
    // URL carrying a presentation — invariant 4, held by the shape of the
    // outcome type rather than by a second copy of the lane check that could
    // come to disagree with the first.
    //
    // Assembled here rather than inside `honour::evaluate` because the cosmetic
    // four decide no `Outcome` — see that module's "W5's cosmetic four are not
    // here". The tenant default is `None`: plan §4.6's W5 amendment says why.
    let cosmetic_owned = {
        let c = axiam_oauth2::login_hop::Cosmetic::from_params(&req.authn_params, None);
        (c.login_hint.map(str::to_owned), c.display, c.ui_locale)
    };

    let outcome = match state.oauth2.authorize_service.authorize(req).await {
        Ok(axiam_oauth2::authorize::AuthorizeOutcome::Interact(interaction)) => {
            // W4 — the honour lane asked for an interaction. It rides W3's
            // login hop: same `return_to`, same validation on both sides, same
            // marker, so the chain is still bounded at one redirect.
            //
            // `reauth` is unconditional here, unlike W3's stale-cookie case.
            // Every reason the honour lane interacts — `prompt=login`, a
            // `max_age` this session cannot satisfy, a step-up, an
            // `id_token_hint` naming somebody else — is a reason not to trust
            // what the browser already holds; a sign-in page that silently
            // reused the current session would return the same unsatisfying
            // session and the loop guard would have to catch it.
            tracing::debug!(
                client_id = %authorized_client_id,
                reason = ?interaction.reason,
                required_acr = ?interaction.required_acr,
                "an authorization request on the honour lane needs an interaction"
            );
            let Some(return_to) = axiam_oauth2::login_hop::build_return_to(http_req.query_string())
            else {
                // Nothing safe to come back to, so there is nothing to send
                // the browser away for. The relying party is told what is
                // missing instead.
                return build_error_redirect(
                    &resolved_redirect_uri,
                    &OAuth2Error::LoginRequired(
                        "this authorization request needs the end user to authenticate, and \
                         could not be resumed after a sign-in"
                            .into(),
                    ),
                    resolved_state.as_deref(),
                    &state.auth_config,
                );
            };
            if !return_to_is_on_this_deployment(&state, &return_to) {
                return build_error_redirect(
                    &resolved_redirect_uri,
                    &OAuth2Error::LoginRequired(
                        "this authorization request needs the end user to authenticate, and \
                         could not be resumed after a sign-in"
                            .into(),
                    ),
                    resolved_state.as_deref(),
                    &state.auth_config,
                );
            }
            let (login_hint, display, ui_locale) = &cosmetic_owned;
            let cosmetic = axiam_oauth2::login_hop::Cosmetic {
                login_hint: login_hint.as_deref(),
                display: *display,
                ui_locale: *ui_locale,
            };
            let location = axiam_oauth2::login_hop::build_login_redirect_for(
                &return_to,
                true,
                interaction.required_acr,
                &cosmetic,
            );
            return HttpResponse::Found()
                .append_header((actix_web::http::header::LOCATION, location))
                .append_header((actix_web::http::header::CACHE_CONTROL, "no-store"))
                .append_header(("Referrer-Policy", "no-referrer"))
                .finish();
        }
        other => other.map(|o| match o {
            axiam_oauth2::authorize::AuthorizeOutcome::Code(resp) => resp,
            axiam_oauth2::authorize::AuthorizeOutcome::Interact(_) => {
                unreachable!("the interaction arm returned above")
            }
        }),
    };

    if silent {
        audit_prompt_none(
            &state,
            &http_req,
            user.tenant_id,
            &authorized_client_id,
            outcome.as_ref().err(),
        )
        .await;
    }

    match outcome {
        Ok(resp) => {
            // B5: the client has just joined this session. Recorded here —
            // the moment a code is issued — because that is when
            // participation becomes true, and back-channel logout iterates
            // exactly these rows. A failure is logged and swallowed: losing a
            // logout notification is bad, but failing the login that would
            // have created the session is worse.
            if let Err(e) = state
                .oauth2
                .session_client_repo
                .record(axiam_core::models::oauth2_client::CreateSessionClient {
                    tenant_id: user.tenant_id,
                    session_id: user.session_id,
                    client_id: authorized_client_id.clone(),
                    user_id: user.user_id,
                })
                .await
            {
                tracing::warn!(
                    error = %e,
                    "could not record session participation; back-channel \
                     logout will not reach this client"
                );
            }

            match url::Url::parse(&resp.redirect_uri) {
                Ok(mut url) => {
                    url.query_pairs_mut().append_pair("code", &resp.code);
                    if let Some(ref state) = resp.state {
                        url.query_pairs_mut().append_pair("state", state);
                    }
                    append_issuer(&mut url, &state.auth_config);
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
                // B5: `ParRequired` joins these two because it is raised
                // BEFORE redirect_uri validation — redirecting would bounce
                // the user agent to an unvalidated URI that arrived by the
                // very channel the setting forbids.
                OAuth2Error::InvalidClient(_)
                | OAuth2Error::InvalidRedirectUri(_)
                | OAuth2Error::ParRequired(_) => build_oauth2_error_response(&e),
                _ => {
                    // These errors occur after client+redirect_uri
                    // were validated — safe to redirect.
                    build_error_redirect(
                        &resolved_redirect_uri,
                        &e,
                        resolved_state.as_deref(),
                        &state.auth_config,
                    )
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
            .oauth2
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

    // SEC-096: ONE context construction and ONE DPoP verification, ahead of
    // every grant that authenticates a client. Before this, the
    // token-exchange and uma-ticket grants each `return`ed above this point,
    // so a DPoP proof on those requests was never verified, never recorded as
    // single-use, and never available to the binding decision — which meant a
    // client holding a `cnf`-bound token could exchange it for a plain bearer
    // one, and a `fapi2` client could obtain an unconstrained token from a
    // grant `fapi::enforce_token_request` never saw.
    //
    // The device-code grant stays above this line deliberately: RFC 8628
    // performs no client authentication at all, so there is no registration
    // in hand for the profile gate to enforce and no party for a proof to
    // bind to.
    let ctx = token_request_context(&req).with_assertion_from(&form);
    let ctx = match dpop_from_request(&req, &state, tenant_id, ctx).await {
        Ok(ctx) => ctx,
        Err(response) => return *response,
    };

    // B3 / RFC 8693. Like the device grant, its own service behind one match
    // arm. Unlike the device grant, the exchanging client DOES authenticate —
    // it is a confidential service, not a television, and an exchange is
    // precisely the operation that should be attributable.
    if grant_type == TOKEN_EXCHANGE_GRANT_TYPE {
        // SEC-093: the transport context travels with the grant, so a client
        // registered for `tls_client_auth` / `private_key_jwt` is
        // authenticated by the credential its registration names rather than
        // by the secret it was also, unavoidably, issued.
        return handle_token_exchange(tenant_id, form, &state, &ctx).await;
    }

    // X2 / UMA 2.0 §3.3.1. Third grant dispatched here for the same structural
    // reason as the other two: the body is deserialized once, so the grant is
    // only knowable after `grant_type` has been read out of it.
    if grant_type == UMA_TICKET_GRANT_TYPE {
        // The authz checker is pulled from the request here rather than taken
        // as a handler parameter on purpose. `/oauth2/token` serves five
        // grants, and only this one evaluates anything against the RBAC
        // engine; making it an extractor would make the checker a hard
        // requirement of the whole endpoint, so a deployment (or a test
        // harness) that never uses UMA would start answering 500 to ordinary
        // token requests because of a dependency none of them use.
        let Some(authz) = req.app_data::<crate::authz::AuthzData>().cloned() else {
            return build_oauth2_error_response(&OAuth2Error::ServerError(
                "the uma-ticket grant requires an authorization checker".into(),
            ));
        };
        // SEC-093, as for the token-exchange grant above.
        return handle_uma_ticket(tenant_id, form, &state, &authz, &ctx).await;
    }

    match state
        .oauth2
        .token_service
        .exchange(tenant_id, form, &ctx)
        .await
    {
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

/// Build the token endpoint's transport context from the connection (X5.1).
///
/// The certificate comes from [`VerifiedClientCert`], which `axiam-server`'s
/// `on_connect` hook populates from the peer chain **rustls verified during
/// the TLS 1.3 handshake**. Nothing else is consulted: in particular the
/// `X-Client-Certificate` header that `CertificateAuthenticated` accepts as a
/// proxy fallback is deliberately not read here, because an OAuth2 client
/// credential must not be assertable by anything that can set a header. See
/// `axiam_oauth2::mtls`'s module docs for the full argument.
///
/// Cost on the ordinary path — a connection with no client certificate, which
/// is every non-mTLS deployment — is one `conn_data` lookup that misses and no
/// allocation at all. On an mTLS connection it is one copy of the DER plus one
/// SHA-256 over it. The X.509 *parse* is deliberately not done here: it is
/// deferred to `PresentedCertificate::identity`, which only the
/// `tls_client_auth` branch calls, so a deployment running mTLS with ordinary
/// secret-authenticating clients does not pay for a DN nobody reads.
fn token_request_context(req: &HttpRequest) -> TokenRequestContext {
    let Some(verified) = req.conn_data::<VerifiedClientCert>() else {
        return TokenRequestContext::default();
    };
    TokenRequestContext {
        client_certificate: Some(PresentedCertificate::from_der(&verified.der)),
        ..TokenRequestContext::default()
    }
}

/// The `htu` a DPoP proof must name for this request (SEC-102, RFC 9449 §4.3
/// step 9).
///
/// Built from the **configured** issuer plus the request's path. RFC 9449 says
/// `htu` is compared against "the HTTP URI used for the request, without query
/// and fragment parts" — meaning the server's own view of its own endpoint.
/// `HttpRequest::full_url()` does not give that: it takes the authority from
/// `ConnectionInfo`, which prefers `Forwarded`, then `X-Forwarded-Host`, then
/// `Host`, and this deployment has no trusted-proxy layer that normalises any
/// of the three. With the authority sourced from the request, a caller chooses
/// *both* sides of the comparison and the check degrades to "the proof names
/// some authority consistently" — so a client phished into signing a proof for
/// `https://attacker.example/oauth2/token` could have it accepted here by
/// sending a matching `Host`.
///
/// The path still comes from the request, and must: it is what keeps a
/// `/oauth2/par` proof from being replayed at `/oauth2/token`. `req.path()` is
/// actix's already-normalised path and carries neither query nor fragment,
/// which is exactly the string the RFC compares.
///
/// `effective_issuer()` is trimmed of any trailing slash by `AuthConfig`, and
/// `req.path()` always begins with one, so the join never doubles it.
fn dpop_htu<C: Connection + Clone>(state: &AppState<C>, req: &HttpRequest) -> String {
    format!("{}{}", state.auth_config.effective_issuer(), req.path())
}

/// The header a DPoP proof arrives in (RFC 9449 §4).
const DPOP_HEADER: &str = "DPoP";

/// The response header carrying a nonce challenge (RFC 9449 §8).
const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";

/// Verify the `DPoP` header, if one is present, and fold the result into the
/// token-endpoint context (X5.1, RFC 9449 §4.3).
///
/// Two properties this function exists to hold, both of which are easy to lose
/// by writing the obvious thing instead:
///
/// 1. **A proof that fails verification is an error, not an absence.** Returning
///    a context with `dpop_proof: None` for a *bad* proof would be silently
///    equivalent to not sending one — so a client that sent a forged proof would
///    get whatever an unbound client gets. The `Err` arm is what stops that.
/// 2. **An absent header is not an error here.** Whether this particular client
///    needed a proof is `fapi::enforce_token_request`'s question and
///    `certificate_binding_for`'s, both of which read the *registration*. Making
///    the decision here would require loading the client twice, and would put
///    the "does this client need a proof" rule in two places.
///
/// The `jti` is recorded on success, through the same `UNIQUE`-index guard the
/// client-assertion path uses. A proof whose `jti` cannot be recorded is
/// refused rather than accepted: failing open would turn a database blip into
/// an unlimited replay window.
async fn dpop_from_request<C: Connection + Clone>(
    req: &HttpRequest,
    state: &AppState<C>,
    tenant_id: Uuid,
    mut ctx: TokenRequestContext,
) -> Result<TokenRequestContext, Box<HttpResponse>> {
    use axiam_core::repository::{ProofKind, ProofReplayRepository};
    use axiam_oauth2::dpop::{self, DpopExpectation};

    let Some(raw) = req
        .headers()
        .get(DPOP_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        return Ok(ctx);
    };

    // RFC 9449 §4.3 step 2: more than one DPoP header is a malformed request,
    // not a choice of proofs. Refusing rather than taking the first is what
    // stops a request-smuggling intermediary from deciding which proof counts.
    if req.headers().get_all(DPOP_HEADER).count() > 1 {
        return Err(dpop_error_response(
            "invalid_dpop_proof",
            "a request may carry at most one DPoP header",
            None,
        ));
    }

    // SEC-102: the authority comes from the CONFIGURED issuer, never from the
    // request. `HttpRequest::full_url()` builds it from `ConnectionInfo`,
    // which prefers `Forwarded`, then `X-Forwarded-Host`, then `Host` — all
    // three request-controlled. Sourcing it there let the caller choose both
    // sides of RFC 9449 §4.3 step 9's comparison, reducing the `htu` check to
    // "the proof names *some* authority consistently". Only the path is taken
    // from the request, and only `req.path()`, which actix has already
    // normalised and which carries no query or fragment — exactly what the
    // RFC compares against.
    let htu = dpop_htu(state, req);
    let expect = DpopExpectation {
        htm: req.method().as_str(),
        htu: &htu,
        // SEC-097: `expected_nonce` stays `None` because this deployment
        // stores no per-client nonce to compare against — see
        // `dpop_nonce_required_for`, which is what decides whether a nonce is
        // demanded at all, and `docs/security-profiles.md` for what v1's
        // nonce challenge does and does not prove.
        expected_nonce: None,
        require_nonce: false,
        access_token: None,
        now: chrono::Utc::now().timestamp(),
        max_age_secs: dpop::DEFAULT_PROOF_MAX_AGE_SECS,
    };

    let verified = match dpop::verify_dpop_proof(raw, &expect) {
        Ok(v) => v,
        Err(e) if e.is_nonce_challenge() => {
            return Err(dpop_error_response(
                e.error_code(),
                "a DPoP nonce is required",
                Some(dpop::new_nonce()),
            ));
        }
        Err(e) => {
            tracing::debug!(error = %e, "DPoP proof verification failed at the token endpoint");
            return Err(dpop_error_response(
                e.error_code(),
                "the DPoP proof could not be verified",
                None,
            ));
        }
    };

    match state
        .oauth2
        .proof_replay_repo
        .insert_proof_jti(
            tenant_id,
            ProofKind::DpopProof,
            &verified.jkt,
            &verified.jti,
            verified.replay_expiry(dpop::DEFAULT_PROOF_MAX_AGE_SECS),
        )
        .await
    {
        Ok(()) => {}
        Err(axiam_core::error::AxiamError::ReplayDetected) => {
            tracing::warn!(jkt = %verified.jkt, "a DPoP proof was replayed; refusing");
            return Err(dpop_error_response(
                "invalid_dpop_proof",
                "this DPoP proof has already been used",
                None,
            ));
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "could not record a DPoP proof's jti; refusing rather than accepting a proof \
                 that cannot be made single-use"
            );
            return Err(dpop_error_response(
                "invalid_dpop_proof",
                "the DPoP proof could not be verified",
                None,
            ));
        }
    }

    ctx.dpop_proof = Some(verified);
    Ok(ctx)
}

/// RFC 9449 §7.1 error response, optionally carrying a nonce challenge.
///
/// Boxed because it is only ever the `Err` of `dpop_from_request`, whose `Ok`
/// is a handful of words: an inline `HttpResponse` there makes every caller
/// carry the error's width on the success path (`clippy::result_large_err`).
fn dpop_error_response(error: &str, description: &str, nonce: Option<String>) -> Box<HttpResponse> {
    let mut builder = HttpResponse::BadRequest();
    builder
        .append_header(("Cache-Control", "no-store"))
        .append_header(("Pragma", "no-cache"));
    if let Some(nonce) = nonce {
        builder.append_header((DPOP_NONCE_HEADER, nonce));
    }
    Box::new(builder.json(serde_json::json!({
        "error": error,
        "error_description": description,
    })))
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
    http_req: HttpRequest,
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<RevokeRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    // SEC-093: carry the connection's client certificate through, so a client
    // registered for `tls_client_auth` can actually revoke. The assertion
    // parameters are folded in by `revoke_token` from the form.
    let ctx = token_request_context(&http_req);

    match state
        .oauth2
        .token_service
        .revoke_token(tenant_id, form.into_inner(), &ctx)
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
    http_req: HttpRequest,
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<IntrospectRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;

    // SEC-093 — as for `revoke`.
    let ctx = token_request_context(&http_req);

    match state
        .oauth2
        .token_service
        .introspect_token(tenant_id, form.into_inner(), &ctx)
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
///
/// RFC 8705 §5 `mtls_endpoint_aliases` is included when — and only when —
/// `AuthConfig::oauth2_mtls_base_url` names a separate mutual-TLS host.
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
    // A misconfigured mTLS base URL fails the request rather than dropping the
    // aliases. Serving the document without them would tell an mTLS client the
    // conventional endpoints are the ones to use — a silent downgrade to
    // exactly the topology RFC 8705 §5 exists to steer it away from — and it
    // would look, from the client's side, indistinguishable from a deployment
    // that has no mTLS host at all.
    let doc = match build_discovery_document(issuer, auth_config.mtls_base_url()) {
        Ok(doc) => doc,
        Err(e) => {
            tracing::error!(
                error = %e,
                "AXIAM__AUTH__OAUTH2_MTLS_BASE_URL is set but unusable; refusing to serve a \
                 discovery document without its RFC 8705 §5 mtls_endpoint_aliases"
            );
            return HttpResponse::InternalServerError().json(OAuth2ErrorResponse {
                error: "server_error".into(),
                error_description: "mTLS endpoint alias base URL is not configured as a \
                    valid URL"
                    .into(),
            });
        }
    };
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
//
// F3 note, deliberately NOT a doc comment: the field is `state.oauth2.
// oauth2_jwks_cache` since the sub-state split. The line above still says
// `state.oauth2_jwks_cache` because utoipa lifts this doc block verbatim into
// the OpenAPI `description`, which eleven SDK repos vendor byte-for-byte. An
// internal field rename is not a reason to churn a published API artifact and
// re-vendor it eleven times; that the description names an internal field at
// all is a separate (real) smell, and fixing it deserves its own change with a
// spec regeneration and a re-vendor round.
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

    let cache_control = state.oauth2.oauth2_jwks_cache_config.cache_control_header();

    match state
        .oauth2
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
    userinfo_claims(&user, &state).await
}

/// The UserInfo response itself, for a principal already authenticated.
///
/// Shared verbatim by [`userinfo`] (GET) and [`userinfo_post`] (POST), which is
/// the whole reason W6 could add a method without touching what the endpoint
/// answers. Nothing here reads the request: the response is a function of the
/// token's subject and its scopes, so the two methods cannot diverge except in
/// how the token was carried.
async fn userinfo_claims<C: Connection + Clone>(
    user: &AuthenticatedUser,
    state: &AppState<C>,
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
        // UserInfo describes the SUBJECT of the token, and that account lives in
        // the tenant the subject inhabits — never one it happens to be acting
        // on. The two differ only for an organization-level principal whose
        // request carried `X-Axiam-Tenant`; reading the acting tenant there
        // found no account and answered with `sub` alone.
        match state
            .user_repo
            .get_by_id(user.principal_tenant_id, user.user_id)
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
                    tenant_id = %user.principal_tenant_id,
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

/// The form body `POST /oauth2/userinfo` accepts (RFC 6750 §2.2).
///
/// Unknown fields are ignored, as serde does by default: RFC 6750 §2.2 defines
/// one parameter and says nothing about others, and a UserInfo request that
/// also carried, say, a `client_id` is not malformed.
#[derive(Deserialize)]
pub struct UserInfoPostForm {
    /// The access token, per RFC 6750 §2.2.
    access_token: Option<String>,
}

/// Hand-written so that the token cannot be logged by anyone who reaches for
/// `?form` — hazard 1 of plan §4.9's G10, and the same line the repository drew
/// in `e33977d` for a `Set-Cookie` header carrying a credential.
///
/// A derived `Debug` would print the bearer token verbatim into whichever
/// `tracing` field, panic message or `dbg!` picked it up. Deriving nothing at
/// all would make that a compile error, which is stronger — but it is also
/// undone by anyone who adds `#[derive(Debug)]` to make a borrow checker
/// message readable. This states the intent where it will be read.
impl std::fmt::Debug for UserInfoPostForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserInfoPostForm")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// `POST /oauth2/userinfo` — the same endpoint, the other method (W6, plan
/// §4.9 G10; OIDC Core §5.3, which says an OP MUST support both).
///
/// # Why a second handler rather than a second extractor
///
/// The access token may arrive in the `Authorization` header (RFC 6750 §2.1) or
/// — on POST only — in an `access_token` form field (§2.2). The second carrier
/// lives in the body, which [`AuthenticatedUser`]'s `FromRequest` impl does not
/// read and must not start reading: that impl is on the path `GET` takes, and
/// on the path every other authenticated route in the tree takes. Resolving the
/// token here instead leaves all of them untouched, which is what makes "GET
/// behaviour is unchanged" a property of the routing table rather than a claim
/// about a shared code path. Both arms then hand the same
/// [`AuthenticatedUser`] to the same [`userinfo_claims`].
///
/// # The refusals, and where each is decided
///
/// * **Two carriers, one request.** RFC 6750 §2: *"Clients MUST NOT use more
///   than one method to transmit the token in each request."* A form field
///   presented together with an `Authorization` header is refused here with
///   `400 invalid_request`, and the refusal names neither token — it does not
///   read them at all, so there is nothing to leak into the body or the log.
///   The `axiam_access` cookie is refused alongside the form field for the same
///   reason even though it is not one of RFC 6750's methods: it is a second
///   credential naming a possibly different subject, and the alternative to
///   refusing is choosing silently between two identities.
/// * **The cookie alone still authenticates, exactly as on GET.** That is
///   today's behaviour and invariant 4 keeps it. It is a CSRF surface in
///   principle — `/oauth2` is not wrapped in `CsrfMiddleware`, only `/api/v1`
///   is — and it fails closed in practice because `axiam_access` is
///   `SameSite=Strict` (`middleware::csrf::access_cookie`), so a cross-site
///   form POST carries no cookie and lands here unauthenticated. That is a
///   property of the cookie, not of this handler, so it is pinned by a test
///   rather than asserted by this comment
///   (`oauth2_userinfo_post_test.rs::the_access_cookie_is_strict_so_a_cross_site_post_cannot_be_authenticated_by_it`).
/// * **`access_token` in the query string is never read** — on either method.
///   RFC 6750 §2.3 deprecates that form because it puts a credential in a URL,
///   a `Referer` and every access log in the path. Refusing it would mean
///   reading it first, and the parameter's problem is that it exists at all,
///   not that a server honours it. So there is no code here that looks at the
///   query string, and a `GET /oauth2/userinfo?access_token=…` is simply an
///   unauthenticated request with an odd URL.
///
/// # An empty field is not a carrier
///
/// `access_token=` transmits no token, so it is treated as absent rather than
/// as a second method or as an invalid credential. A request carrying an empty
/// field and a real `Authorization` header is answered, not refused.
pub async fn userinfo_post<C: Connection + Clone>(
    req: HttpRequest,
    form: Option<web::Form<UserInfoPostForm>>,
    maybe_user: MaybeAuthenticatedUser,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    use actix_web::ResponseError as _;

    let body_token = form
        .as_ref()
        .and_then(|f| f.access_token.as_deref())
        .map(str::trim)
        .filter(|t| !t.is_empty());

    let Some(body_token) = body_token else {
        // No §2.2 carrier: this is a header- or cookie-authenticated request,
        // and `MaybeAuthenticatedUser` holds precisely what actix would have
        // handed a `AuthenticatedUser` handler — the same principal, or the
        // same 401.
        return match maybe_user.into_result() {
            Ok(user) => userinfo_claims(&user, &state).await,
            Err(e) => e.error_response(),
        };
    };

    let header_present = req
        .headers()
        .contains_key(actix_web::http::header::AUTHORIZATION);
    let cookie_present = req.cookie("axiam_access").is_some();
    if header_present || cookie_present {
        return HttpResponse::BadRequest().json(OAuth2ErrorResponse {
            error: "invalid_request".into(),
            error_description: "the access token was presented by more than one method; \
                 RFC 6750 section 2 permits exactly one per request"
                .into(),
        });
    }

    match crate::extractors::auth::authenticate_presented_token(&req, body_token).await {
        Ok(user) => userinfo_claims(&user, &state).await,
        Err(e) => e.error_response(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a redirect response with error parameters per RFC 6749
/// section 4.1.2.1.
/// Append the RFC 9207 `iss` authorization-response parameter (X5.1).
///
/// # Why this matters, and why it is unconditional
///
/// RFC 9207 exists because of the **mix-up attack**: a client that talks to
/// more than one authorization server, and receives an authorization response
/// on a shared redirect URI, cannot otherwise tell which server sent it. An
/// attacker who controls one of those servers can therefore have a code minted
/// by an honest server delivered to the attacker's own token endpoint — or the
/// reverse. `iss` names the sender, so the client can check that the response
/// came from the server it started the flow with.
///
/// Emitted for **every** client, not just FAPI ones. RFC 9207 §2.4 says an AS
/// that supports the parameter SHOULD include it in every authorization
/// response; a client that does not understand it ignores an unknown query
/// parameter, which is the behaviour RFC 6749 §4.1.2 already requires of it.
/// Making it conditional would mean a client only gets mix-up protection when
/// somebody remembered to switch it on — and mix-up is precisely the attack a
/// client does not know it is under.
///
/// It goes on the **error** redirect too. RFC 9207 §2.4 is explicit about
/// this, and it is not a formality: one variant of the mix-up attack works by
/// injecting an error response, so a client that validates `iss` on success
/// and skips it on failure has left the door it just closed ajar.
fn append_issuer(url: &mut url::Url, auth_config: &AuthConfig) {
    let issuer = auth_config.effective_issuer();
    if issuer.is_empty() {
        // Nothing sensible to assert. Emitting an empty `iss` would be worse
        // than omitting it: a client comparing it against its configured
        // issuer would fail every flow, and one comparing loosely might pass
        // anything.
        tracing::warn!(
            "no issuer is configured, so the RFC 9207 `iss` authorization-response              parameter cannot be emitted; clients cannot detect a mix-up attack"
        );
        return;
    }
    url.query_pairs_mut().append_pair("iss", issuer);
}

fn build_error_redirect(
    redirect_uri: &str,
    error: &OAuth2Error,
    state: Option<&str>,
    auth_config: &AuthConfig,
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
    // RFC 9207 §2.4 — see `append_issuer`. Error responses carry `iss` too,
    // because one form of the mix-up attack is an injected error response.
    append_issuer(&mut url, auth_config);
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
        .oauth2
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
/// X2 — `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket`.
///
/// Redeems a permission ticket for an RPT. Four things are worth naming.
///
/// **The client authenticates, and the ticket is bound to it.** A ticket is
/// minted by a resource server through the Protection API and redeemed by that
/// same resource server; `consume` matches on `client_id`, so a ticket leaked
/// to another client is not a usable credential — and a wrong-client attempt
/// changes nothing rather than burning the rightful holder's ticket.
///
/// **`claim_token` is required, though UMA 2.0 calls it optional.** The spec's
/// other two ways to name a requesting party — an RPT presented for
/// incremental authorization, and interactive claims-gathering — are both
/// deferred to v2, so this is the only channel that exists. Requiring it and
/// saying so beats resolving to some default subject, which would mint an RPT
/// for a party nobody named.
///
/// **The subject token is validated, not trusted.** It is a signed AXIAM access
/// token; its remaining life bounds the RPT's, which is what stops an RPT from
/// outliving the authorization it rests on.
///
/// **Refusals are uniform.** Every ticket rejection — unknown, consumed,
/// expired, wrong client — answers `invalid_grant` with one message, because a
/// caller that could tell them apart could probe for live ticket handles.
async fn handle_uma_ticket<C: Connection + Clone>(
    tenant_id: Uuid,
    form: TokenRequest,
    state: &web::Data<AppState<C>>,
    authz: &crate::authz::AuthzData,
    ctx: &TokenRequestContext,
) -> HttpResponse {
    // SEC-093: only `client_id` is required up front. Whether the credential
    // that must accompany it is a secret, a certificate or a signed assertion
    // is a property of the REGISTRATION, so it cannot be decided before the
    // lookup — `authenticate_client` decides it, and answers the same
    // `invalid_client` for "no credential" as for "wrong credential".
    let Some(client_id) = form.client_id.as_deref() else {
        return build_oauth2_error_response(&OAuth2Error::InvalidClient(
            "the uma-ticket grant requires client authentication".into(),
        ));
    };

    let client = match state
        .oauth2
        .token_service
        .authenticate_client(tenant_id, client_id, form.client_secret.as_deref(), ctx)
        .await
    {
        Ok(client) => client,
        Err(e) => return build_oauth2_error_response(&e),
    };

    // Counted after authentication, keyed by the authenticated client — the
    // same reasoning as the token-exchange bucket: an unauthenticated caller
    // must not be able to consume a real client's allowance, and per-IP would
    // collapse a whole mesh behind one NAT into a single bucket.
    if !state.shared_rate_limit.check_at(
        &format!("oauth2_uma_ticket:{}:{}", tenant_id, client.client_id),
        chrono::Utc::now(),
        state.rate_limit_cfg.uma_ticket_per_min,
    ) {
        return HttpResponse::TooManyRequests()
            .append_header(("Cache-Control", "no-store"))
            .json(OAuth2ErrorResponse {
                error: "slow_down".into(),
                error_description: "uma-ticket rate limit exceeded for this client".into(),
            });
    }

    // SEC-096: the same two gates the token-exchange grant now runs, for the
    // same reason — an RPT is an access token, and a `fapi2` client must not
    // be able to obtain an unconstrained one through the grant nobody wired
    // the profile gate into.
    if let Err(e) = axiam_oauth2::fapi::enforce_token_request(&client, ctx.evidence()) {
        return build_oauth2_error_response(&e);
    }
    let cnf = match state
        .oauth2
        .token_service
        .certificate_binding_for(&client, ctx)
    {
        Ok(cnf) => cnf,
        Err(e) => return build_oauth2_error_response(&e),
    };

    let Some(ticket) = form.ticket.as_deref().filter(|t| !t.is_empty()) else {
        return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
            "ticket is required for the uma-ticket grant".into(),
        ));
    };

    let Some(claim_token) = form.claim_token.as_deref().filter(|t| !t.is_empty()) else {
        return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
            "claim_token is required for the uma-ticket grant: it names the \
             requesting party, and v1 implements neither incremental \
             authorization nor claims-gathering"
                .into(),
        ));
    };

    // An unrecognised format is refused rather than assumed. Guessing would
    // mean validating a foreign token with the wrong verifier.
    if let Some(format) = form.claim_token_format.as_deref().filter(|f| !f.is_empty())
        && format != UMA_CLAIM_TOKEN_FORMAT
    {
        return build_oauth2_error_response(&OAuth2Error::InvalidRequest(format!(
            "unsupported claim_token_format '{format}'; v1 accepts only \
             '{UMA_CLAIM_TOKEN_FORMAT}'"
        )));
    }

    let claims = match axiam_auth::token::validate_access_token(claim_token, &state.auth_config) {
        Ok(validated) => validated.0,
        Err(_) => {
            return build_oauth2_error_response(&OAuth2Error::InvalidGrant(
                "claim_token is not a valid access token".into(),
            ));
        }
    };

    let Ok(subject_id) = claims.sub.parse::<Uuid>() else {
        return build_oauth2_error_response(&OAuth2Error::InvalidGrant(
            "claim_token does not name a user as its subject".into(),
        ));
    };

    // The requesting party must belong to the tenant the ticket was minted in.
    // Without this a token from tenant A could redeem a ticket in tenant B and
    // be evaluated against B's grants under A's subject id.
    if claims.tenant_id != tenant_id.to_string() {
        return build_oauth2_error_response(&OAuth2Error::InvalidGrant(
            "claim_token belongs to a different tenant".into(),
        ));
    }

    let subject_remaining_secs = claims.exp - chrono::Utc::now().timestamp();

    let granted = match state
        .uma_service(authz.get_ref().clone())
        .exchange_ticket(
            tenant_id,
            &client.client_id,
            ticket,
            subject_id,
            subject_remaining_secs,
        )
        .await
    {
        Ok(granted) => granted,
        Err(e) => {
            tracing::info!(
                target: "axiam::audit",
                event = "uma.rpt_refused",
                tenant_id = %tenant_id,
                client_id = %client.client_id,
                subject = %subject_id,
                error = e.wire_error(),
                "uma-ticket grant refused"
            );
            return uma_refusal_response(e);
        }
    };

    let org_id = match claims.org_id.parse::<Uuid>() {
        Ok(id) => id,
        Err(_) => {
            return build_oauth2_error_response(&OAuth2Error::ServerError(
                "claim_token carries an unparseable org_id".into(),
            ));
        }
    };

    let rpt = match axiam_auth::token::issue_rpt(
        subject_id,
        tenant_id,
        org_id,
        granted.permissions.clone(),
        granted.lifetime_secs,
        &state.auth_config,
        cnf.clone(),
    ) {
        Ok(token) => token,
        Err(e) => return build_oauth2_error_response(&OAuth2Error::ServerError(e.to_string())),
    };

    // Audited before the token is returned: the ticket is already consumed at
    // this point, so a crash between issuing and logging would leave a spent
    // ticket with no record of what it bought.
    tracing::info!(
        target: "axiam::audit",
        event = "uma.rpt_issued",
        tenant_id = %tenant_id,
        client_id = %client.client_id,
        subject = %subject_id,
        pairs = granted.permissions.len(),
        lifetime_secs = granted.lifetime_secs,
        "RPT issued"
    );

    HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .append_header(("Pragma", "no-cache"))
        .json(TokenResponse {
            access_token: rpt,
            // SEC-096 / RFC 9449 §5: `DPoP` when the RPT is DPoP-bound,
            // `Bearer` for everything else — which is every client that did
            // not register DPoP binding.
            token_type: axiam_oauth2::dpop::token_type_for(cnf.as_ref()),
            expires_in: granted.lifetime_secs as u64,
            refresh_token: None,
            scope: None,
            id_token: None,
        })
}

/// Render a [`UmaError`] as the token endpoint's error response.
///
/// # Why `access_denied` does not go through `build_oauth2_error_response`
///
/// That helper maps everything except `invalid_client` and `server_error` to
/// **400**, which is right for RFC 6749 and right for RFC 8628 — the device
/// grant's `access_denied` (the user said no) is a 400 and must stay one.
///
/// UMA 2.0 §3.3.6 specifies **403** for a request the authorization server
/// refuses on the merits, and a UMA-conforming resource server distinguishes
/// "you may not have this" from "your request was malformed" by exactly that
/// status. Routing the UMA refusal through the shared helper would answer 400
/// and quietly fail conformance, so this one status is built here. Every other
/// UMA error keeps the shared mapping.
fn uma_refusal_response(e: UmaError) -> HttpResponse {
    if matches!(e, UmaError::AccessDenied) {
        return HttpResponse::Forbidden()
            .append_header(("Cache-Control", "no-store"))
            .append_header(("Pragma", "no-cache"))
            .json(OAuth2ErrorResponse {
                // v1 sends no `need_info` alongside it: that field exists to
                // steer a client into claims-gathering, which is deferred, so
                // sending it would point at a flow that does not run.
                error: "access_denied".into(),
                error_description:
                    "the requesting party is not authorized for every requested permission".into(),
            });
    }
    build_oauth2_error_response(&uma_error_to_oauth2(e))
}

/// Map a [`UmaError`] onto the OAuth2 error shape the token endpoint answers.
fn uma_error_to_oauth2(e: UmaError) -> OAuth2Error {
    match e {
        UmaError::InvalidRequest(m) => OAuth2Error::InvalidRequest(m),
        UmaError::InvalidGrant(m) => OAuth2Error::InvalidGrant(m),
        UmaError::AccessDenied => OAuth2Error::AccessDenied(
            "the requesting party is not authorized for every requested permission".into(),
        ),
        UmaError::ExpiredSubjectToken => {
            OAuth2Error::InvalidGrant("the presented claim_token has expired".into())
        }
        UmaError::Server(m) => OAuth2Error::ServerError(m),
    }
}

async fn handle_token_exchange<C: Connection + Clone>(
    tenant_id: Uuid,
    form: TokenRequest,
    state: &web::Data<AppState<C>>,
    ctx: &TokenRequestContext,
) -> HttpResponse {
    // SEC-093 — see `handle_uma_ticket` for why only `client_id` is required
    // before the lookup.
    let Some(client_id) = form.client_id.as_deref() else {
        return build_oauth2_error_response(&OAuth2Error::InvalidClient(
            "the token-exchange grant requires client authentication".into(),
        ));
    };

    let client = match state
        .oauth2
        .token_service
        .authenticate_client(tenant_id, client_id, form.client_secret.as_deref(), ctx)
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

    // SEC-096, gate 1: the profile the REGISTRATION declares, re-checked at
    // the moment it matters — the same call the authorization_code,
    // client_credentials and refresh_token grants make. Without it a `fapi2`
    // client could obtain an unconstrained token through this grant while
    // being refused one through the other three, which is a conformance
    // failure and an authentication downgrade in the same request.
    if let Err(e) = axiam_oauth2::fapi::enforce_token_request(&client, ctx.evidence()) {
        return build_oauth2_error_response(&e);
    }

    // SEC-096, gate 2: the confirmation claim the EXCHANGING client earned on
    // this request. `None` for every client that registered no binding, so
    // this is byte-identical to the pre-SEC-096 response for them; for a
    // client that registered binding and presented nothing it refuses rather
    // than laundering a bound token into an unbound one.
    let cnf = match state
        .oauth2
        .token_service
        .certificate_binding_for(&client, ctx)
    {
        Ok(cnf) => cnf,
        Err(e) => return build_oauth2_error_response(&e),
    };

    let Some(exchange_req) = form.exchange_request() else {
        return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
            "subject_token and subject_token_type are required for the \
             token-exchange grant"
                .into(),
        ));
    };

    match state
        .oauth2
        .token_exchange_service
        .exchange(tenant_id, &client, exchange_req, cnf)
        .await
    {
        Ok(outcome) => {
            // Audited BEFORE the token is returned, not after. For an
            // impersonation this record is the only surviving evidence that
            // the acting party was not the subject — the token deliberately
            // carries no `act` claim — so it must not be lost to a crash
            // between issuing and logging.
            // X4: an external exchange's provenance is recorded in the same
            // entry, not a second one. A reader correlating two lines by
            // timestamp is a reader who can be made to correlate the wrong
            // two, and for a JIT provision this is the only record that a
            // partner's IdP created an AXIAM user.
            let ext = outcome.external.as_ref();
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
                external_issuer = ext.map(|e| e.issuer.as_str()).unwrap_or("-"),
                external_subject = ext.map(|e| e.external_subject.as_str()).unwrap_or("-"),
                federation_provider = ext.map(|e| e.provider_name.as_str()).unwrap_or("-"),
                federation_config_id = ext
                    .map(|e| e.provider_id.to_string())
                    .unwrap_or_else(|| "-".into()),
                jit_provisioned = ext.is_some_and(|e| e.newly_provisioned),
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

    /// **T0.3, server side.** The `return_to` check that resolves rather than
    /// parses.
    ///
    /// `login_hop::validate_return_to` refuses these on spelling; this one
    /// refuses them on where they *resolve to*, which is the property that
    /// survives an edit to the first. `Url::join` is what turns
    /// `//evil.example` into another host and normalises `..` away, so the two
    /// checks fail for genuinely independent reasons.
    #[actix_web::test]
    async fn t0_3_return_to_must_resolve_onto_an_origin_this_deployment_owns() {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory db");
        let state = AppState::for_test(
            db,
            AuthConfig {
                oauth2_issuer_url: "https://iam.example.com".into(),
                ..AuthConfig::default()
            },
        );

        assert!(return_to_is_on_this_deployment(
            &state,
            "/oauth2/authorize?client_id=oa_1&axiam_login_hop=1"
        ));

        for hostile in [
            "https://evil.example/oauth2/authorize?x=1",
            "//evil.example/oauth2/authorize?x=1",
            "/oauth2/authorize/../../admin/users?x=1",
            "/api/v1/users?x=1",
            "/login?return_to=%2F",
            // Resolves to the right path on the wrong host — the case only a
            // resolving check can see.
            "https://iam.example.com.evil.test/oauth2/authorize?x=1",
        ] {
            assert!(
                !return_to_is_on_this_deployment(&state, hostile),
                "must refuse {hostile}"
            );
        }
    }

    /// The two checks are applied in series and the builder is bound by both:
    /// what `build_return_to` emits is what this accepts.
    #[actix_web::test]
    async fn the_return_to_the_server_builds_passes_the_origin_check() {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory db");
        let state = AppState::for_test(
            db,
            AuthConfig {
                oauth2_issuer_url: "https://iam.example.com".into(),
                ..AuthConfig::default()
            },
        );
        let built = axiam_oauth2::login_hop::build_return_to(
            "response_type=code&client_id=oa_1&tenant_id=00000000-0000-0000-0000-000000000001",
        )
        .expect("a return_to");
        assert!(return_to_is_on_this_deployment(&state, &built));
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

// ---------------------------------------------------------------------------
// B5 — Pushed Authorization Requests (RFC 9126)
// ---------------------------------------------------------------------------

/// Form body accepted by `POST /oauth2/par`.
///
/// These are the ordinary authorization-request parameters, plus the client
/// credentials that make the push attributable. `request_uri` is deliberately
/// absent: RFC 9126 §2.1 forbids pushing one, because a chained push would let
/// the second request inherit the first's authentication.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct PushedAuthorizationRequest {
    pub client_id: String,
    /// Optional since SEC-093: a client registered for `tls_client_auth` or
    /// `private_key_jwt` has no secret to present here, and presenting one no
    /// longer authenticates it.
    pub client_secret: Option<String>,
    /// RFC 7521 §4.2 — `private_key_jwt` client authentication at PAR.
    pub client_assertion: Option<String>,
    pub client_assertion_type: Option<String>,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    // X7.1 — pushed alongside the original seven, because PAR is the only
    // carrier a `require_par` client has.
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub display: Option<String>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
}

/// `POST /oauth2/par` success body (RFC 9126 §2.2).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct PushedAuthorizationResponse {
    /// Opaque, single-use, `urn:ietf:params:oauth:request_uri:`-prefixed.
    pub request_uri: String,
    /// Seconds until the `request_uri` expires.
    pub expires_in: i64,
}

/// `POST /oauth2/par` — RFC 9126 (B5).
///
/// Accepts an authorization request over a direct, client-authenticated POST
/// and returns an opaque `request_uri` to put in the browser redirect instead
/// of the parameters. What travels through the user agent is then a random
/// string that cannot be edited into meaning something else.
///
/// **Authenticated, unlike `/oauth2/device_authorization`.** That is the whole
/// point: the parameters stop travelling through the browser, and the ones
/// that arrive are attributable to a client that proved it holds the secret.
///
/// Answers `201`, not `200` — RFC 9126 §2.2 specifies Created, and the
/// response names a resource that did not exist before the call.
#[utoipa::path(
    post,
    path = "/oauth2/par",
    tag = "oauth2",
    params(TenantQuery),
    request_body(
        content_type = "application/x-www-form-urlencoded",
        content = PushedAuthorizationRequest,
    ),
    responses(
        (status = 201, description = "Pushed authorization request stored",
         body = PushedAuthorizationResponse),
        (status = 400, description = "OAuth2 error", body = OAuth2ErrorResponse),
        (status = 401, description = "Client authentication failed",
         body = OAuth2ErrorResponse),
    ),
)]
pub async fn pushed_authorization_request<C: Connection + Clone>(
    http_req: HttpRequest,
    tenant_query: web::Query<TenantQuery>,
    form: web::Form<PushedAuthorizationRequest>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let tenant_id = tenant_query.into_inner().tenant_id;
    let req = form.into_inner();

    // One client-authentication path in the codebase, shared with the token
    // endpoint, rather than a second one to keep correct — and since SEC-093
    // that path honours the registered `token_endpoint_auth_method`. PAR is
    // the sharpest instance of the old bug: FAPI 2.0 §5.3.1.1 requires strong
    // client authentication AND requires PAR, so a FAPI deployment whose PAR
    // endpoint accepted a shared secret was both an authentication downgrade
    // and a conformance failure.
    let ctx = token_request_context(&http_req).with_assertion(
        req.client_assertion.as_deref(),
        req.client_assertion_type.as_deref(),
    );
    let client = match state
        .oauth2
        .token_service
        .authenticate_client(
            tenant_id,
            &req.client_id,
            req.client_secret.as_deref(),
            &ctx,
        )
        .await
    {
        Ok(client) => client,
        Err(e) => return build_oauth2_error_response(&e),
    };

    // Keyed by the authenticated client and counted AFTER authentication, for
    // the same reasons as the token exchange: PAR always carries credentials
    // so there is a real identity to key on, per-IP would collapse a whole
    // deployment behind one NAT into a single bucket, and counting before
    // authentication would let an unauthenticated caller burn a real client's
    // allowance.
    if !state.shared_rate_limit.check_at(
        &format!("oauth2_par:{}:{}", tenant_id, client.client_id),
        chrono::Utc::now(),
        state.rate_limit_cfg.par_per_min,
    ) {
        return HttpResponse::TooManyRequests()
            .append_header(("Cache-Control", "no-store"))
            .json(OAuth2ErrorResponse {
                error: "slow_down".into(),
                error_description: "PAR rate limit exceeded for this client".into(),
            });
    }

    match state
        .oauth2
        .par_service
        .push(axiam_oauth2::par::PushedRequest {
            tenant_id,
            client_id: client.client_id,
            response_type: req.response_type,
            redirect_uri: req.redirect_uri,
            scope: req.scope,
            state: req.state,
            code_challenge: req.code_challenge,
            code_challenge_method: req.code_challenge_method,
            nonce: req.nonce,
            prompt: req.prompt,
            max_age: req.max_age,
            acr_values: req.acr_values,
            claims: req.claims,
            id_token_hint: req.id_token_hint,
            login_hint: req.login_hint,
            display: req.display,
            ui_locales: req.ui_locales,
            claims_locales: req.claims_locales,
        })
        .await
    {
        Ok(resp) => HttpResponse::Created()
            .append_header(("Cache-Control", "no-store"))
            .append_header(("Pragma", "no-cache"))
            .json(PushedAuthorizationResponse {
                request_uri: resp.request_uri,
                expires_in: resp.expires_in,
            }),
        Err(e) => build_oauth2_error_response(&e),
    }
}

// ---------------------------------------------------------------------------
// B5 — RP-Initiated Logout 1.0
// ---------------------------------------------------------------------------

/// Query parameters accepted by `/oauth2/end_session`.
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct EndSessionQuery {
    pub tenant_id: Uuid,
    /// A previously-issued ID token identifying the session to end. The only
    /// *authenticated* statement of which session and client this is about.
    pub id_token_hint: Option<String>,
    /// Where to send the browser afterwards. Honoured only on the identified
    /// client's allow-list, by exact match.
    pub post_logout_redirect_uri: Option<String>,
    /// Echoed verbatim on a redirect that actually happens. Never interpreted.
    pub state: Option<String>,
    /// Fallback identification when no `id_token_hint` is supplied.
    pub client_id: Option<String>,
}

/// `GET`/`POST /oauth2/end_session` — OIDC RP-Initiated Logout 1.0 (B5).
///
/// Ends the session named by `id_token_hint` and notifies every client that
/// participated in it (Back-Channel Logout 1.0), then either redirects to an
/// allow-listed `post_logout_redirect_uri` or renders AXIAM's own logged-out
/// page.
///
/// # The redirect is the whole security surface
///
/// This endpoint is reachable without authentication by design — a user whose
/// session has already expired must still be able to complete a logout — so an
/// unvalidated `post_logout_redirect_uri` would be an open redirect on an
/// unauthenticated endpoint. It is honoured **only** on exact match against
/// the identified client's `post_logout_redirect_uris`.
///
/// A non-matching URI does not fail the request: the session is still ended
/// and AXIAM renders its own page. Refusing to log a user out because their RP
/// sent a bad parameter would be the wrong failure — they asked to log out.
///
/// # Why an unverifiable hint cannot end a session
///
/// Without a verifiable `id_token_hint` there is nothing to identify but the
/// browser's own AXIAM cookie, so the endpoint ends the cookie session if
/// there is one and does nothing otherwise. It deliberately does **not** fall
/// back to "end every session for the subject named in an unverified
/// parameter": that is a denial-of-service primitive handed to anyone who
/// knows a user id.
///
/// # No confirmation prompt
///
/// RP-Initiated Logout 1.0 §2 permits one, and a prompt is the mitigation for
/// logout CSRF. We take the other side deliberately: a forced logout is a
/// nuisance, not a privilege escalation, and a prompt shown on every logout is
/// trained away within a week.
#[utoipa::path(
    get,
    path = "/oauth2/end_session",
    tag = "oauth2",
    params(EndSessionQuery),
    responses(
        (status = 302, description = "Session ended; redirected to an allow-listed URI"),
        (status = 200, description = "Session ended; AXIAM's logged-out page"),
        (status = 400, description = "OAuth2 error", body = OAuth2ErrorResponse),
    ),
)]
pub async fn end_session<C: Connection + Clone>(
    query: web::Query<EndSessionQuery>,
    state: web::Data<AppState<C>>,
) -> HttpResponse {
    let q = query.into_inner();
    let tenant_id = q.tenant_id;

    // 1. Identify the session and client. The hint is a *signed* statement of
    //    both; `client_id` is an unauthenticated parameter and is only a
    //    fallback for choosing the redirect allow-list.
    let hinted = q.id_token_hint.as_deref().and_then(|t| {
        axiam_oauth2::logout::decode_id_token_hint(t, &state.auth_config.jwt_public_key_pem)
    });

    let (session_id, hint_client_id, subject_id) = match hinted {
        Some(h) => (h.session_id, Some(h.client_id), h.subject_id),
        None => (None, None, None),
    };

    // 2. When both are present and disagree, refuse rather than resolve in
    //    favour of either. Picking the signed one would silently ignore what
    //    the caller asked; picking the unsigned one would let a parameter
    //    override a signature.
    if let (Some(hint_client), Some(param_client)) =
        (hint_client_id.as_deref(), q.client_id.as_deref())
        && hint_client != param_client
    {
        return build_oauth2_error_response(&OAuth2Error::InvalidRequest(
            "id_token_hint and client_id identify different clients".into(),
        ));
    }

    let effective_client_id = hint_client_id.or_else(|| q.client_id.clone());

    // 3. End the session, and notify the clients that were in it.
    if let (Some(session_id), Some(subject_id)) = (session_id, subject_id) {
        dispatch_backchannel_logout(&state, tenant_id, session_id, subject_id).await;
        // Best-effort: a session that has already expired is not an error —
        // the user asked to be logged out and they are.
        let _ = state.auth_service.logout(tenant_id, session_id).await;
    }

    // 4. Resolve the redirect against the identified client's allow-list.
    let allow_list = match effective_client_id.as_deref() {
        Some(client_id) => state
            .oauth2_client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map(|c| c.post_logout_redirect_uris)
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let cookie_secure = state.auth_config.cookie_secure;

    match axiam_oauth2::logout::resolve_post_logout_redirect(
        q.post_logout_redirect_uri.as_deref(),
        &allow_list,
        q.state.as_deref(),
    ) {
        axiam_oauth2::logout::LogoutOutcome::Redirect { uri, state: st } => {
            let location = match (url::Url::parse(&uri), st) {
                (Ok(mut url), Some(st)) => {
                    url.query_pairs_mut().append_pair("state", &st);
                    url.to_string()
                }
                (Ok(url), None) => url.to_string(),
                // An allow-listed entry that will not parse is an operator
                // error, not a user-facing one; render rather than emit a
                // Location header we could not construct.
                (Err(_), _) => {
                    return logged_out_page(cookie_secure);
                }
            };
            HttpResponse::Found()
                .append_header(("Location", location))
                .append_header(("Cache-Control", "no-store"))
                .cookie(crate::middleware::csrf::clear_access_cookie(cookie_secure))
                .cookie(crate::middleware::csrf::clear_refresh_cookie(cookie_secure))
                .cookie(crate::middleware::csrf::clear_csrf_cookie(cookie_secure))
                // W3: RP-initiated logout clears the OP browser session too.
                // Leaving it would mean a user who logged out through one
                // relying party is still recognised, silently, by the next.
                .cookie(crate::middleware::csrf::clear_op_session_cookie())
                .finish()
        }
        axiam_oauth2::logout::LogoutOutcome::Rendered => logged_out_page(cookie_secure),
    }
}

/// AXIAM's own logged-out page.
///
/// Deliberately carries no RP-supplied content — not the `state`, not the
/// rejected URI. Echoing either would put an attacker-controlled string into
/// a page served from AXIAM's own origin.
///
/// `cookie_secure` is `AuthConfig::cookie_secure` (D-18): the removal cookies
/// must carry the same attributes as the ones they clear.
fn logged_out_page(cookie_secure: bool) -> HttpResponse {
    HttpResponse::Ok()
        .append_header(("Cache-Control", "no-store"))
        .content_type("text/html; charset=utf-8")
        .cookie(crate::middleware::csrf::clear_access_cookie(cookie_secure))
        .cookie(crate::middleware::csrf::clear_refresh_cookie(cookie_secure))
        .cookie(crate::middleware::csrf::clear_csrf_cookie(cookie_secure))
        .cookie(crate::middleware::csrf::clear_op_session_cookie())
        .body(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
             <title>Signed out</title></head><body><h1>You are signed out.</h1>\
             </body></html>",
        )
}

/// Build and dispatch logout tokens for a session's participants.
///
/// Spawned rather than awaited: the user's session is gone the moment this
/// request returns, and making logout wait on N external HTTP calls would make
/// it a hostage to the least reliable RP.
async fn dispatch_backchannel_logout<C: Connection + Clone>(
    state: &web::Data<AppState<C>>,
    tenant_id: Uuid,
    session_id: Uuid,
    subject_id: Uuid,
) {
    let participants = match state
        .oauth2
        .session_client_repo
        .list_for_session(tenant_id, session_id)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "could not list session participants for logout");
            return;
        }
    };
    if participants.is_empty() {
        return;
    }

    let mut clients = Vec::new();
    for client_id in participants
        .iter()
        .map(|p| p.client_id.clone())
        .collect::<std::collections::BTreeSet<_>>()
    {
        match state
            .oauth2_client_repo
            .get_by_client_id(tenant_id, &client_id)
            .await
        {
            Ok(c) => clients.push(c),
            // A participant whose registration cannot be loaded is dropped
            // from the fan-out — correct (a deleted client keeps its
            // participation rows), but silent until now. The RP that does not
            // get told sees nothing, and neither did anyone reading the logs.
            Err(e) => tracing::debug!(
                %client_id,
                error = %e,
                "back-channel logout: session participant is not a loadable client, skipping"
            ),
        }
    }

    let issuer = state.auth_config.effective_issuer().to_string();
    let auth_config = state.auth_config.clone();
    let participant_ids: Vec<String> = participants.into_iter().map(|p| p.client_id).collect();

    let deliveries = crate::backchannel_logout::select_targets(
        &participant_ids,
        &clients,
        |client_id| {
            match axiam_oauth2::logout::issue_logout_token(
                &issuer,
                client_id,
                session_id,
                subject_id,
                &auth_config,
            ) {
                Ok(token) => Some(token),
                // This used to be `.ok()`. A token that cannot be minted (a
                // misconfigured issuer, an unusable signing key) silently
                // removed the client from the fan-out, so a whole deployment
                // could stop notifying anyone with no signal anywhere — on a
                // session-termination path, where "nothing happened" is
                // exactly the outcome an attacker wants. WARN, not DEBUG: this
                // one is never routine.
                Err(e) => {
                    tracing::warn!(
                        %client_id,
                        error = %e,
                        "back-channel logout: could not issue a logout token, client will NOT be notified"
                    );
                    None
                }
            }
        },
    );

    // One line naming every stage of the funnel, so a delivery that never
    // happens can be localised without a code read: how many clients joined
    // the session, how many of those are still loadable registrations, and how
    // many of those actually got a token and a URI to send it to. Each drop
    // between those numbers has its own line above (or is the deliberate
    // "client registered no backchannel_logout_uri" skip in `select_targets`).
    tracing::debug!(
        participants = participant_ids.len(),
        clients = clients.len(),
        deliveries = deliveries.len(),
        "back-channel logout fan-out computed"
    );

    // Participation records are dropped after the fan-out list is built, not
    // before — the list is what the fan-out iterates.
    let _ = state
        .oauth2
        .session_client_repo
        .delete_for_session(tenant_id, session_id)
        .await;

    if !deliveries.is_empty() {
        actix_web::rt::spawn(crate::backchannel_logout::deliver_all(deliveries));
    }
}

#[cfg(test)]
mod dpop_htu_tests {
    use actix_web::test::TestRequest;
    use axiam_auth::config::AuthConfig;
    use surrealdb::Surreal;
    use surrealdb::engine::local::Mem;

    use super::*;

    async fn state_with_issuer(issuer: &str) -> AppState<surrealdb::engine::local::Db> {
        let db = Surreal::new::<Mem>(()).await.expect("in-memory db");
        let auth_config = AuthConfig {
            oauth2_issuer_url: issuer.to_string(),
            sso_spa_origins: Vec::new(),
            ..AuthConfig::default()
        };
        AppState::for_test(db, auth_config)
    }

    /// SEC-102. `htu` must be the server's own view of its endpoint, never the
    /// caller's.
    ///
    /// `HttpRequest::full_url()` — what this used to call — takes the
    /// authority from `ConnectionInfo`, which prefers `Forwarded`, then
    /// `X-Forwarded-Host`, then `Host`, and no trusted-proxy layer normalises
    /// any of the three here. With the authority sourced from the request, the
    /// caller chooses **both** sides of RFC 9449 §4.3 step 9's comparison, so
    /// a client phished into signing a proof for
    /// `https://attacker.example/oauth2/token` could have it accepted by
    /// sending a matching `Host`.
    #[actix_web::test]
    async fn htu_ignores_every_request_supplied_authority_header() {
        let state = state_with_issuer("https://id.example.test").await;

        for header in ["Host", "X-Forwarded-Host"] {
            let req = TestRequest::post()
                .uri("/oauth2/token?tenant_id=x")
                .insert_header((header, "attacker.example"))
                .to_http_request();
            assert_eq!(
                dpop_htu(&state, &req),
                "https://id.example.test/oauth2/token",
                "the {header} header must not reach htu"
            );
        }

        let req = TestRequest::post()
            .uri("/oauth2/token")
            .insert_header(("Forwarded", "host=attacker.example;proto=https"))
            .to_http_request();
        assert_eq!(
            dpop_htu(&state, &req),
            "https://id.example.test/oauth2/token"
        );
    }

    /// The path still comes from the request — that is what keeps a
    /// `/oauth2/par` proof from being replayed at `/oauth2/token` — and the
    /// query string is excluded, which is exactly what RFC 9449 compares.
    #[actix_web::test]
    async fn htu_keeps_the_path_and_drops_the_query() {
        let state = state_with_issuer("https://id.example.test/").await;

        let par = TestRequest::post()
            .uri("/oauth2/par?tenant_id=00000000-0000-0000-0000-000000000000")
            .to_http_request();
        assert_eq!(dpop_htu(&state, &par), "https://id.example.test/oauth2/par");

        let token = TestRequest::post().uri("/oauth2/token").to_http_request();
        assert_ne!(
            dpop_htu(&state, &par),
            dpop_htu(&state, &token),
            "cross-endpoint replay must still be refused by the htu comparison"
        );
    }
}

// ---------------------------------------------------------------------------
// X7 G12 — request-object classification (plan §4.10)
// ---------------------------------------------------------------------------
//
// T12.1-T12.3. Pure-function tests of the classifier, deliberately narrow:
// what a refusal *does* to the response (redirect vs 400) is the authorize
// service's business and is covered by `authorize`'s own tests and by the
// oauth2_conformance integration suite. What is pinned here is the
// classification itself, because the two error codes are what a conformance
// suite matches on and swapping them is invisible until a run fails.
#[cfg(test)]
mod request_object_tests {
    use super::*;
    use axiam_oauth2::par::REQUEST_URI_PREFIX;

    /// T12.1 — `request` present ⇒ `request_not_supported`.
    #[test]
    fn t12_1_a_request_object_by_value_is_classified() {
        assert_eq!(
            classify_request_object(Some("eyJhbGciOiJub25lIn0.e30."), None),
            Some(RequestObject::ByValue)
        );
        assert_eq!(
            RequestObject::ByValue.into_error().error_code(),
            "request_not_supported"
        );
    }

    /// T12.2 — a `request_uri` that is not a PAR handle ⇒
    /// `request_uri_not_supported`. This is the SSRF-shaped form: it would
    /// have the authorization server fetch a URL the request chose.
    #[test]
    fn t12_2_a_request_object_by_reference_is_classified() {
        for uri in [
            "https://attacker.example/request.jwt",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "urn:ietf:params:oauth:not-a-request-uri:abc",
            "not a uri at all",
        ] {
            assert_eq!(
                classify_request_object(None, Some(uri)),
                Some(RequestObject::ByReference),
                "{uri:?} is not a PAR handle and must be refused as one"
            );
        }
        assert_eq!(
            RequestObject::ByReference.into_error().error_code(),
            "request_uri_not_supported"
        );
    }

    /// T12.3 — a genuine PAR handle is **not** a request object. This is the
    /// regression that matters: classifying before the consume path must not
    /// break PAR, which FAPI 2.0 requires of every client.
    #[test]
    fn t12_3_a_par_handle_is_not_a_request_object() {
        let handle = format!("{REQUEST_URI_PREFIX}p6nS1_A2b3C4d5E6f7G8h9");
        assert_eq!(classify_request_object(None, Some(&handle)), None);
        assert_eq!(classify_request_object(None, None), None);
    }

    /// When both arrive, the by-value object is the one named: it is the one
    /// the server would have had to read.
    #[test]
    fn a_by_value_object_is_named_before_a_by_reference_one() {
        assert_eq!(
            classify_request_object(Some("ey.jwt"), Some("https://attacker.example/r.jwt")),
            Some(RequestObject::ByValue)
        );
        // ...including alongside a PAR handle, which is otherwise untouched.
        let handle = format!("{REQUEST_URI_PREFIX}abc");
        assert_eq!(
            classify_request_object(Some("ey.jwt"), Some(&handle)),
            Some(RequestObject::ByValue)
        );
    }

    /// A blank value is a client library filling in a template, not a request
    /// object. Refusing it would break a request that works today and carries
    /// nothing — the same emptiness rule the rest of this server applies.
    #[test]
    fn a_blank_parameter_is_not_a_request_object() {
        assert_eq!(classify_request_object(Some(""), None), None);
        assert_eq!(classify_request_object(Some("   "), None), None);
        assert_eq!(classify_request_object(None, Some("")), None);
        assert_eq!(classify_request_object(None, Some("  ")), None);
    }

    /// The two codes are distinct and are the ones OIDC Core §3.1.2.6 spells.
    /// A test rather than a comment because the whole value of the change is
    /// that a relying party can tell the two apart.
    #[test]
    fn the_two_refusals_do_not_share_an_error_code() {
        let by_value = RequestObject::ByValue.into_error();
        let by_reference = RequestObject::ByReference.into_error();
        assert_ne!(by_value.error_code(), by_reference.error_code());
        assert_eq!(by_value.error_code(), "request_not_supported");
        assert_eq!(by_reference.error_code(), "request_uri_not_supported");
        // Neither is reported as a generic invalid_request, which is what the
        // pre-X7 code path produced and what the suite does not match on.
        for e in [by_value, by_reference] {
            assert_ne!(e.error_code(), "invalid_request");
        }
    }
}

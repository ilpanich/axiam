//! The SAML 2.0 identity provider's SSO endpoint (G-2, T23.2.3).
//!
//! Four routes under `/saml/v2/{tenant_id}`, behind the `saml` feature:
//!
//! | Route | What it does |
//! |---|---|
//! | `GET /sso` | HTTP-Redirect binding: an SP-initiated `AuthnRequest` |
//! | `POST /sso` | HTTP-POST binding: the same, as a form post |
//! | `GET /sso/idp-initiated?sp=…[&RelayState=…]` | IdP-initiated sign-on, for an SP that opted in (D-3) |
//! | `GET /sso/continue?handle=…` | the second leg: resolve the browser's session, hop to sign in if needed, issue |
//! | `GET`/`HEAD /metadata` | the tenant's IdP metadata (T23.2.5, D-40), unauthenticated |
//!
//! # Two legs, and why
//!
//! A SAML `AuthnRequest` is an authorization request with a different wire
//! format, and it signs the user in through the same login hop and OP-session
//! cookie as `/oauth2/authorize` (X7.3, D-11): MFA, OPAQUE and passkeys apply
//! unchanged because the session is the same session. But the HTTP-POST binding
//! arrives as a **cross-site form post**: a `SameSite=Lax` cookie is not sent
//! on it, and the browser cannot be sent to the sign-in page and then re-post
//! it. So the first leg checks the request and stores what it decided (the
//! `saml_authn_request` row, schema v73) under an opaque handle, and answers
//! `303` to the second leg, a top-level `GET` that carries the cookie. Both
//! bindings and IdP-initiated sign-on take the same path from there.
//!
//! # What the first leg refuses, before anyone is asked to sign in
//!
//! Everything decidable without a principal (the #524 / P23W2-03 lesson): an
//! undecodable, oversized or DTD-bearing message, anything but a SAML 2.0
//! `AuthnRequest`, a bad `ID`, a stale `IssueInstant`, an unknown issuer, a
//! missing, misplaced or failing signature for an SP that signs, a
//! `Destination` other than this tenant's SSO URL, an ACS URL or index outside
//! the registration, a `ProtocolBinding` other than HTTP-POST, an over-long
//! `RelayState`, a replayed request `ID` — each answered with an error page
//! that posts nowhere — and a disabled SP, encryption requested, or a
//! `NameIDPolicy` that conflicts with the SP's, each answered with a SAML
//! failure response posted to the (already checked) ACS URL. None of them
//! writes a pending row, and none redirects to `/login`.
//!
//! # The second leg
//!
//! It requires the browser-binding cookie the first leg set (so a handle copied
//! to another browser is worthless), resolves the session from the OP cookie
//! through the tenant-keyed digest lookup alone, and applies `account_may_act`.
//! `ForceAuthn` is **bound**, not marker-based (it does not inherit
//! P23W1-08): the session must have authenticated *after* the first leg
//! accepted the request, so a forged hop marker cannot skip the sign-in.
//! `IsPassive` never shows the sign-in page. The pending row is consumed on the
//! X6 arbiter immediately before issuing, so one handle yields at most one
//! response.
//!
//! # D-20
//!
//! Every route answers [`not_found`] — an empty `404`, the answer for a path
//! nothing is mounted at — when the tenant does not exist, its path segment is
//! not the canonical UUID spelling, or its effective `saml_idp_enabled` is off;
//! that check runs before the body is read. A build without `saml` mounts no
//! route, which answers the same `404`.
//!
//! # What is never logged
//!
//! `SAMLRequest`, `SAMLResponse`, `RelayState`, the handle, the binding value
//! and the OP cookie. Refusals are logged as the fixed reason and the tenant
//! (and the SP's record id once known).

use actix_web::cookie::{Cookie, SameSite};
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::saml_authn_request::{
    NewPendingSamlRequest, PENDING_SAML_REQUEST_TTL_SECS, PendingSamlRequest,
};
use axiam_core::models::saml_sp::SamlServiceProvider;
use axiam_core::models::session::Session;
use axiam_core::models::user::User;
use axiam_core::repository::{
    AuditLogRepository, GroupRepository, PendingSamlRequestRepository, RoleRepository,
    SamlServiceProviderRepository, SessionRepository, SettingsRepository, TenantRepository,
    UserRepository,
};
use axiam_federation::saml_idp::request::{
    self as saml_request, BINDING_HTTP_POST, ParsedAuthnRequest, RedirectQuery, RequestError,
};
use axiam_federation::saml_idp::{
    PostBinding, SamlIdpError, SamlStatus, SsoIssuance, check_acs_url, check_relay_state,
    idp_sso_url,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use futures::StreamExt;
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use surrealdb::Connection;
use uuid::Uuid;

use crate::extractors::client_info::peer_ip;
use crate::state::AppState;

/// The largest HTTP-POST body read, in bytes. A signed `AuthnRequest` with a
/// certificate in `KeyInfo`, base64 and form-encoded, is a few kilobytes; the
/// decoded document is bounded separately
/// ([`saml_request::MAX_REQUEST_XML_BYTES`]).
pub const MAX_POST_BODY_BYTES: usize = 192 * 1024;

/// The browser-binding cookie's name prefix. The full name is the prefix and
/// sixteen hex digits of the handle's digest, so concurrent sign-ons in one
/// browser (two tabs, two SPs) each keep their own binding.
pub const BINDING_COOKIE_PREFIX: &str = "axiam_saml_req_";

/// The opaque handle's length: 32 CSPRNG bytes, base64url without padding.
const HANDLE_LEN: usize = 43;

// ---------------------------------------------------------------------------
// D-20
// ---------------------------------------------------------------------------

/// The `404` every SAML route answers when the tenant does not serve SAML, and
/// what an unmounted path answers: empty body, no headers of its own.
pub async fn not_found() -> HttpResponse {
    HttpResponse::NotFound().finish()
}

/// `(tenant_id, organization_id)` when the path names, in canonical form, a
/// tenant whose effective `saml_idp_enabled` is on; `None` otherwise — and the
/// caller answers [`not_found`] without saying which.
async fn tenant_serving_saml<C: Connection + Clone>(
    state: &AppState<C>,
    raw_tenant: &str,
) -> Option<(Uuid, Uuid)> {
    let tenant_id = Uuid::parse_str(raw_tenant).ok()?;
    // Canonical spelling only: the OP cookie's path is byte-for-byte the
    // canonical form, so any other spelling would route here carrying no
    // cookie (the P23W2-08 (c) class); it is simply not a SAML path.
    if tenant_id.to_string() != raw_tenant {
        return None;
    }
    let tenant = state.tenant_repo.get_by_id(tenant_id).await.ok()?;
    let settings = state
        .settings_repo
        .get_effective_settings(tenant.organization_id, tenant_id)
        .await
        .ok()?;
    settings
        .oidc
        .saml_idp_enabled
        .then_some((tenant_id, tenant.organization_id))
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// Why a request was refused, as a fixed string for the log and the audit row.
type Reason = &'static str;

/// An error page that posts nowhere. Generic text: nothing from the request is
/// reflected, and the reason is in the log, not on the page.
fn refusal_page(status: StatusCode, reason: Reason, tenant_id: Uuid) -> HttpResponse {
    tracing::info!(%tenant_id, reason, "SAML SSO: request refused with an error page");
    let body = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
                <title>Sign-in request refused</title></head><body>\
                <h1>This sign-in request cannot be completed</h1>\
                <p>Return to the application you came from and try again. If this \
                keeps happening, contact its administrator.</p></body></html>";
    HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .body(body)
}

fn request_refused(error: RequestError, tenant_id: Uuid) -> HttpResponse {
    let reason: Reason = match error {
        RequestError::TooLarge => "too_large",
        RequestError::Encoding => "encoding",
        RequestError::Inflate => "inflate",
        RequestError::Dtd => "markup_declaration",
        RequestError::Malformed => "malformed",
        RequestError::NotAnAuthnRequest => "not_an_authn_request",
        RequestError::InvalidId => "invalid_id",
        RequestError::InvalidField => "invalid_field",
        RequestError::Stale => "stale_issue_instant",
        RequestError::SubjectUnsupported => "subject_unsupported",
        RequestError::DuplicateParameter => "duplicate_parameter",
        RequestError::SignaturePlacement => "signature_placement",
        RequestError::SignatureMissing => "signature_missing",
        RequestError::SignatureAlgorithm => "signature_algorithm",
        RequestError::SignatureInvalid => "signature_invalid",
    };
    let status = if error == RequestError::TooLarge {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    refusal_page(status, reason, tenant_id)
}

/// HTML-escape a value for an attribute or text node.
fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// The CSP origin of the ACS URL: `scheme://host[:port]`.
fn acs_origin(acs_url: &str) -> Option<String> {
    let url = url::Url::parse(acs_url).ok()?;
    let origin = url.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The auto-submitting HTTP-POST binding page (SAML Bindings §3.5.4).
///
/// Every value is HTML-escaped. Its own `Content-Security-Policy`, stricter
/// than the global one: nothing loads, the one inline script runs under a
/// per-response nonce, the form may post only to the ACS URL's origin, and the
/// page cannot be framed. `no-store`, so a back button cannot re-post it.
fn post_page(
    binding: &PostBinding,
    clear: Option<Cookie<'static>>,
    tenant_id: Uuid,
) -> HttpResponse {
    let Some(origin) = acs_origin(&binding.acs_url) else {
        return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "acs_origin", tenant_id);
    };
    let mut nonce = [0u8; 16];
    rand::rng().fill_bytes(&mut nonce);
    let nonce = URL_SAFE_NO_PAD.encode(nonce);

    let relay = binding
        .relay_state
        .as_deref()
        .map(|r| {
            format!(
                "<input type=\"hidden\" name=\"RelayState\" value=\"{}\">",
                html_escape(r)
            )
        })
        .unwrap_or_default();
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Signing in</title></head><body>\
         <form method=\"post\" action=\"{action}\">\
         <input type=\"hidden\" name=\"SAMLResponse\" value=\"{response}\">{relay}\
         <noscript><p>Press Continue to finish signing in.</p>\
         <button type=\"submit\">Continue</button></noscript></form>\
         <script nonce=\"{nonce}\">document.forms[0].submit();</script>\
         </body></html>",
        action = html_escape(&binding.acs_url),
        response = html_escape(&binding.saml_response),
    );
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; form-action {origin}; \
         frame-ancestors 'none'; base-uri 'none'"
    );
    let mut builder = HttpResponse::Ok();
    builder
        .content_type("text/html; charset=utf-8")
        .insert_header(("Content-Security-Policy", csp))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"));
    if let Some(cookie) = clear {
        builder.cookie(cookie);
    }
    builder.body(body)
}

// ---------------------------------------------------------------------------
// Handles and the browser binding
// ---------------------------------------------------------------------------

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// A well-formed handle: exactly what [`random_token`] mints.
fn is_handle(value: &str) -> bool {
    value.len() == HANDLE_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn binding_cookie_name(handle_hash: &str) -> String {
    format!("{BINDING_COOKIE_PREFIX}{}", &handle_hash[..16])
}

/// The browser-binding cookie: `HttpOnly; Secure; SameSite=Lax`, scoped to the
/// tenant's SSO path (so it reaches `/continue`), living as long as the row.
fn binding_cookie(
    tenant_id: Uuid,
    name: String,
    value: String,
    max_age_secs: i64,
) -> Cookie<'static> {
    Cookie::build(name, value)
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path(axiam_oauth2::login_hop::saml_sso_path(tenant_id))
        .max_age(actix_web::cookie::time::Duration::seconds(max_age_secs))
        .finish()
}

fn clear_binding_cookie(tenant_id: Uuid, handle_hash: &str) -> Cookie<'static> {
    let mut c = binding_cookie(
        tenant_id,
        binding_cookie_name(handle_hash),
        String::new(),
        0,
    );
    c.make_removal();
    c
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async fn audit<C: Connection + Clone>(
    state: &AppState<C>,
    req: &HttpRequest,
    tenant_id: Uuid,
    actor: Option<Uuid>,
    sp_id: Uuid,
    outcome: Result<&str, SamlStatus>,
) {
    let (action, result, detail) = match outcome {
        Ok(response_id) => (
            "saml_idp.sso.issued",
            AuditOutcome::Success,
            serde_json::json!({ "sp_id": sp_id, "response_id": response_id }),
        ),
        Err(status) => (
            "saml_idp.sso.refused",
            AuditOutcome::Failure,
            serde_json::json!({
                "sp_id": sp_id,
                "status": status.second_level().unwrap_or(status.top_level()),
            }),
        ),
    };
    if let Err(e) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: actor.unwrap_or(Uuid::nil()),
            actor_type: if actor.is_some() {
                ActorType::User
            } else {
                ActorType::System
            },
            action: action.into(),
            resource_id: Some(sp_id),
            outcome: result,
            ip_address: peer_ip(req),
            metadata: Some(detail),
        })
        .await
    {
        tracing::error!(error = %e, %tenant_id, "SAML SSO: could not record the outcome");
    }
}

/// A status-only failure posted to the (registered) ACS URL, or an error page
/// when it cannot be.
#[allow(clippy::too_many_arguments)]
async fn post_failure<C: Connection + Clone>(
    state: &AppState<C>,
    req: &HttpRequest,
    tenant_id: Uuid,
    sp: &SamlServiceProvider,
    acs_url: &str,
    in_response_to: Option<&str>,
    relay_state: Option<&str>,
    status: SamlStatus,
    actor: Option<Uuid>,
    clear: Option<Cookie<'static>>,
) -> HttpResponse {
    tracing::info!(%tenant_id, sp_id = %sp.id, ?status, "SAML SSO: answering the SP with a failure");
    audit(state, req, tenant_id, actor, sp.id, Err(status)).await;
    match state.saml_idp.issuer.failure(
        tenant_id,
        sp,
        acs_url,
        in_response_to,
        relay_state,
        status,
        Utc::now(),
    ) {
        Ok(binding) => post_page(&binding, clear, tenant_id),
        Err(_) => refusal_page(StatusCode::BAD_REQUEST, "acs_not_registered", tenant_id),
    }
}

// ---------------------------------------------------------------------------
// First leg: SP-initiated, both bindings
// ---------------------------------------------------------------------------

/// `GET`/`HEAD /saml/v2/{tenant_id}/metadata` — the tenant's IdP metadata
/// (T23.2.5, D-40).
///
/// Unauthenticated, `application/samlmetadata+xml`, one `EntityDescriptor` from
/// a fixed template carrying the signing certificates of the `active` credential
/// and then the `next` one (so an SP has the successor before any assertion is
/// signed with it), and nothing else that varies. **Unsigned**, on purpose:
/// signing it with the key it publishes would anchor nothing.
///
/// **D-20.** The tenant check runs before anything else and every way of having
/// nothing to say — a build without SAML (no route at all), an unknown tenant, a
/// non-canonical id, the setting off, no publishable credential — is the same
/// empty [`not_found`]: a `503` for a missing credential would tell anyone that
/// the tenant exists and serves SAML (T-368). The administrator sees readiness
/// through `get_idp`.
///
/// `Cache-Control: public, max-age=3600` and a strong `ETag`; `If-None-Match`
/// answers `304`. It reads the keyless credential list only, never the sealed
/// key.
pub async fn metadata<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    use axiam_federation::saml_idp::idp_metadata::{
        IDP_METADATA_CACHE_CONTROL, IDP_METADATA_MEDIA_TYPE, build_idp_metadata,
        if_none_match_matches,
    };
    use axiam_federation::saml_idp::{idp_entity_id, idp_sso_url};

    let Some((tenant_id, _org)) = tenant_serving_saml(&state, &path).await else {
        return not_found().await;
    };
    let Ok(credentials) = state.saml_idp.credential_service.list(tenant_id).await else {
        return not_found().await;
    };
    let base = state.auth_config.root_issuer();
    let Some(document) = build_idp_metadata(
        &idp_entity_id(base, tenant_id),
        &idp_sso_url(base, tenant_id),
        &credentials,
    ) else {
        return not_found().await;
    };

    let revalidated = req
        .headers()
        .get(actix_web::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| if_none_match_matches(v, &document.etag));
    let mut response = if revalidated {
        HttpResponse::NotModified()
    } else {
        HttpResponse::Ok()
    };
    response
        .insert_header(("Cache-Control", IDP_METADATA_CACHE_CONTROL))
        .insert_header(("ETag", document.etag.clone()));
    if revalidated {
        return response.finish();
    }
    response
        .content_type(IDP_METADATA_MEDIA_TYPE)
        .body(document.xml)
}

/// `GET /saml/v2/{tenant_id}/sso` — the HTTP-Redirect binding.
pub async fn sso_redirect<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let Some((tenant_id, _org)) = tenant_serving_saml(&state, &path).await else {
        return not_found().await;
    };
    let query = match RedirectQuery::parse(req.query_string()) {
        Ok(q) => q,
        Err(e) => return request_refused(e, tenant_id),
    };
    let document = match saml_request::decode_redirect(&query.saml_request()) {
        Ok(d) => d,
        Err(e) => return request_refused(e, tenant_id),
    };
    accept(
        &state,
        &req,
        tenant_id,
        Incoming {
            document,
            relay_state: query.relay_state(),
            redirect: Some(query),
        },
    )
    .await
}

/// `POST /saml/v2/{tenant_id}/sso` — the HTTP-POST binding.
pub async fn sso_post<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
    mut payload: web::Payload,
) -> HttpResponse {
    let Some((tenant_id, _org)) = tenant_serving_saml(&state, &path).await else {
        return not_found().await;
    };
    // Read the body only now, after D-20, and only up to the cap.
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let Ok(chunk) = chunk else {
            return request_refused(RequestError::Encoding, tenant_id);
        };
        if body.len() + chunk.len() > MAX_POST_BODY_BYTES {
            return request_refused(RequestError::TooLarge, tenant_id);
        }
        body.extend_from_slice(&chunk);
    }
    let (mut saml, mut relay) = (None, None);
    for (name, value) in url::form_urlencoded::parse(&body) {
        let slot = match name.as_ref() {
            "SAMLRequest" => &mut saml,
            "RelayState" => &mut relay,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return request_refused(RequestError::DuplicateParameter, tenant_id);
        }
    }
    let Some(saml) = saml else {
        return request_refused(RequestError::Encoding, tenant_id);
    };
    let document = match saml_request::decode_post(&saml) {
        Ok(d) => d,
        Err(e) => return request_refused(e, tenant_id),
    };
    accept(
        &state,
        &req,
        tenant_id,
        Incoming {
            document,
            relay_state: relay,
            redirect: None,
        },
    )
    .await
}

struct Incoming<'q> {
    document: String,
    relay_state: Option<String>,
    /// The Redirect binding's query (its signature is over the query); `None`
    /// for the POST binding.
    redirect: Option<RedirectQuery<'q>>,
}

/// Everything the first leg decides, in the order the module docs give.
async fn accept<C: Connection + Clone>(
    state: &AppState<C>,
    req: &HttpRequest,
    tenant_id: Uuid,
    incoming: Incoming<'_>,
) -> HttpResponse {
    let now = Utc::now();
    let parsed = match saml_request::parse_authn_request(&incoming.document, now) {
        Ok(p) => p,
        Err(e) => return request_refused(e, tenant_id),
    };
    // A signature inside a Redirect-binding document is not that binding's
    // signature (Bindings §3.4.4.1); nothing checks it, so it is refused.
    if incoming.redirect.is_some() && parsed.enveloped_signature {
        return request_refused(RequestError::SignaturePlacement, tenant_id);
    }

    // The SP, by issuer, within the path's tenant only.
    let sp = match state
        .saml_idp
        .sp_repo
        .get_by_entity_id(tenant_id, &parsed.issuer)
        .await
    {
        Ok(Some(sp)) => sp,
        Ok(None) => return refusal_page(StatusCode::BAD_REQUEST, "unknown_sp", tenant_id),
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not read the SP registry");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "registry", tenant_id);
        }
    };

    // The signature, before anything the request names is trusted.
    let signed = match &incoming.redirect {
        Some(query) => query.is_signed(),
        None => parsed.enveloped_signature,
    };
    let sp_cert = match sp.sp_signing_cert_pem.as_deref() {
        Some(pem) => match axiam_federation::cert::pem_cert_to_der(pem) {
            Ok(der) => Some(der),
            Err(_) => {
                return refusal_page(StatusCode::BAD_REQUEST, "sp_certificate", tenant_id);
            }
        },
        None => None,
    };
    let verified = match (&sp_cert, signed) {
        (Some(cert), true) => {
            let outcome = match &incoming.redirect {
                Some(query) => query.verify_signature(cert),
                None => saml_request::verify_post_signature(&incoming.document, cert),
            };
            if let Err(e) = outcome {
                return request_refused(e, tenant_id);
            }
            true
        }
        // Signed, but the SP registered no certificate to check it with: the
        // signature cannot be evaluated, and is not relied on.
        (None, true) | (_, false) => false,
    };
    if sp.want_authn_requests_signed && !verified {
        return request_refused(RequestError::SignatureMissing, tenant_id);
    }

    // `Destination`: when present it must be this tenant's SSO URL, and a
    // signed request must carry it (Bindings §3.4.5.2, §3.5.5.2).
    let sso_url = idp_sso_url(state.auth_config.root_issuer(), tenant_id);
    match parsed.destination.as_deref() {
        Some(destination) if destination != sso_url => {
            return refusal_page(StatusCode::BAD_REQUEST, "destination", tenant_id);
        }
        None if verified => {
            return refusal_page(StatusCode::BAD_REQUEST, "destination_missing", tenant_id);
        }
        _ => {}
    }

    // The ACS URL, resolved against the registration only.
    let Some(acs_url) = resolve_acs(&sp, &parsed) else {
        return refusal_page(StatusCode::BAD_REQUEST, "acs_not_registered", tenant_id);
    };
    if check_acs_url(&sp, &acs_url).is_err() {
        return refusal_page(StatusCode::BAD_REQUEST, "acs_not_registered", tenant_id);
    }
    if parsed
        .protocol_binding
        .as_deref()
        .is_some_and(|b| b != BINDING_HTTP_POST)
    {
        return refusal_page(StatusCode::BAD_REQUEST, "protocol_binding", tenant_id);
    }
    if check_relay_state(incoming.relay_state.as_deref()).is_err() {
        return refusal_page(StatusCode::BAD_REQUEST, "relay_state", tenant_id);
    }

    // From here the ACS URL is one the SP registered: policy refusals are
    // answered to it as SAML failures.
    let respond = |status| {
        post_failure(
            state,
            req,
            tenant_id,
            &sp,
            &acs_url,
            Some(&parsed.id),
            incoming.relay_state.as_deref(),
            status,
            None,
            None,
        )
    };
    if !sp.enabled {
        return respond(SamlStatus::RequestDenied).await;
    }
    if sp.encrypt_assertions {
        return respond(SamlIdpError::EncryptionUnsupported.status()).await;
    }
    if !saml_request::name_id_format_compatible(parsed.name_id_format.as_deref(), sp.name_id_format)
    {
        return respond(SamlStatus::InvalidNameIdPolicy).await;
    }

    hold(
        state,
        tenant_id,
        &sp,
        Some(parsed.id.clone()),
        acs_url.clone(),
        incoming.relay_state.clone(),
        parsed.force_authn,
        parsed.is_passive,
    )
    .await
}

/// The registered ACS URL a request names: by URL (exact), by index, or the
/// SP's default. A request naming both is malformed (SAML Core §3.4.1).
fn resolve_acs(sp: &SamlServiceProvider, parsed: &ParsedAuthnRequest) -> Option<String> {
    let endpoint = match (parsed.acs_url.as_deref(), parsed.acs_index) {
        (Some(_), Some(_)) => return None,
        (Some(url), None) => sp.acs_by_url(url),
        (None, Some(index)) => sp.acs_by_index(index),
        (None, None) => sp.default_acs(),
    }?;
    Some(endpoint.url.clone())
}

/// Store the pending request and send the browser to the second leg, bound to
/// it by a cookie.
#[allow(clippy::too_many_arguments)]
async fn hold<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    sp: &SamlServiceProvider,
    request_id: Option<String>,
    acs_url: String,
    relay_state: Option<String>,
    force_authn: bool,
    is_passive: bool,
) -> HttpResponse {
    let handle = random_token();
    let binding = random_token();
    let handle_hash = sha256_hex(&handle);
    let created_at = Utc::now();
    let row = NewPendingSamlRequest {
        tenant_id,
        sp_id: sp.id,
        request_id,
        acs_url,
        relay_state,
        force_authn,
        is_passive,
        handle_hash: handle_hash.clone(),
        binding_hash: sha256_hex(&binding),
        created_at,
        expires_at: created_at + Duration::seconds(PENDING_SAML_REQUEST_TTL_SECS),
    };
    match state.saml_idp.pending_repo.create(row).await {
        Ok(()) => {}
        Err(axiam_core::error::AxiamError::ReplayDetected) => {
            tracing::warn!(%tenant_id, sp_id = %sp.id, "SAML SSO: a request ID was replayed");
            return refusal_page(StatusCode::BAD_REQUEST, "replayed_request_id", tenant_id);
        }
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not store the request");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "store", tenant_id);
        }
    }
    let location = format!(
        "{}?handle={handle}",
        axiam_oauth2::login_hop::saml_sso_continue_path(tenant_id)
    );
    HttpResponse::SeeOther()
        .insert_header((actix_web::http::header::LOCATION, location))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Referrer-Policy", "no-referrer"))
        .cookie(binding_cookie(
            tenant_id,
            binding_cookie_name(&handle_hash),
            binding,
            PENDING_SAML_REQUEST_TTL_SECS,
        ))
        .finish()
}

// ---------------------------------------------------------------------------
// First leg: IdP-initiated (D-3)
// ---------------------------------------------------------------------------

/// `GET /saml/v2/{tenant_id}/sso/idp-initiated?sp=<entity id>[&RelayState=…]`.
///
/// For an SP that opted in (`allow_idp_initiated`), and refused before the hop
/// for any other. A cross-site trigger is refused (`Sec-Fetch-Site:
/// cross-site`): the link is meant for AXIAM's own pages and bookmarks, and a
/// third-party page that could start it could sign a visitor in to an SP with a
/// `RelayState` of its choosing. Every refusal is an error page: an unsolicited
/// failure response is no use to an SP.
pub async fn sso_idp_initiated<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let Some((tenant_id, _org)) = tenant_serving_saml(&state, &path).await else {
        return not_found().await;
    };
    if req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return refusal_page(StatusCode::FORBIDDEN, "idp_initiated_cross_site", tenant_id);
    }
    let (mut entity, mut relay) = (None, None);
    for (name, value) in url::form_urlencoded::parse(req.query_string().as_bytes()) {
        let slot = match name.as_ref() {
            "sp" => &mut entity,
            "RelayState" => &mut relay,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return request_refused(RequestError::DuplicateParameter, tenant_id);
        }
    }
    let Some(entity) = entity.filter(|e| !e.is_empty()) else {
        return refusal_page(StatusCode::BAD_REQUEST, "idp_initiated_no_sp", tenant_id);
    };
    let sp = match state
        .saml_idp
        .sp_repo
        .get_by_entity_id(tenant_id, &entity)
        .await
    {
        Ok(Some(sp)) => sp,
        Ok(None) => return refusal_page(StatusCode::BAD_REQUEST, "unknown_sp", tenant_id),
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not read the SP registry");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "registry", tenant_id);
        }
    };
    if !sp.allow_idp_initiated {
        return refusal_page(
            StatusCode::FORBIDDEN,
            "idp_initiated_not_allowed",
            tenant_id,
        );
    }
    if !sp.enabled {
        return refusal_page(StatusCode::FORBIDDEN, "sp_disabled", tenant_id);
    }
    if sp.encrypt_assertions {
        return refusal_page(StatusCode::BAD_REQUEST, "encryption_unsupported", tenant_id);
    }
    let Some(acs_url) = sp.default_acs().map(|e| e.url.clone()) else {
        return refusal_page(StatusCode::BAD_REQUEST, "acs_not_registered", tenant_id);
    };
    if check_acs_url(&sp, &acs_url).is_err() {
        return refusal_page(StatusCode::BAD_REQUEST, "acs_not_registered", tenant_id);
    }
    if check_relay_state(relay.as_deref()).is_err() {
        return refusal_page(StatusCode::BAD_REQUEST, "relay_state", tenant_id);
    }
    hold(&state, tenant_id, &sp, None, acs_url, relay, false, false).await
}

// ---------------------------------------------------------------------------
// Second leg
// ---------------------------------------------------------------------------

/// `GET /saml/v2/{tenant_id}/sso/continue?handle=…[&axiam_login_hop=1]`.
pub async fn sso_continue<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let Some((tenant_id, org_id)) = tenant_serving_saml(&state, &path).await else {
        return not_found().await;
    };
    let (mut handle, mut marker) = (None, None);
    for (name, value) in url::form_urlencoded::parse(req.query_string().as_bytes()) {
        let slot = match name.as_ref() {
            "handle" => &mut handle,
            axiam_oauth2::login_hop::LOGIN_HOP_MARKER => &mut marker,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return request_refused(RequestError::DuplicateParameter, tenant_id);
        }
    }
    let Some(handle) = handle.filter(|h| is_handle(h)) else {
        return refusal_page(StatusCode::BAD_REQUEST, "handle", tenant_id);
    };
    let handle_hash = sha256_hex(&handle);

    let pending = match state
        .saml_idp
        .pending_repo
        .get_pending(tenant_id, &handle_hash)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => return refusal_page(StatusCode::BAD_REQUEST, "handle_unknown", tenant_id),
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not read the request");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "store", tenant_id);
        }
    };

    // The browser that started this request, and no other.
    let bound = req
        .cookie(&binding_cookie_name(&handle_hash))
        .map(|c| sha256_hex(c.value()))
        .is_some_and(|h| bool::from(h.as_bytes().ct_eq(pending.binding_hash.as_bytes())));
    if !bound {
        return refusal_page(StatusCode::BAD_REQUEST, "binding", tenant_id);
    }
    let clear = || Some(clear_binding_cookie(tenant_id, &handle_hash));

    // The SP as it is now: deleted or disabled since the first leg ends it.
    let sp = match state.saml_idp.sp_repo.get(tenant_id, pending.sp_id).await {
        Ok(sp) => sp,
        Err(_) => {
            let _ = state
                .saml_idp
                .pending_repo
                .consume(tenant_id, &handle_hash)
                .await;
            return refusal_page(StatusCode::BAD_REQUEST, "sp_gone", tenant_id);
        }
    };
    let fail = |status, actor| {
        let state = &state;
        let req = &req;
        let sp = &sp;
        let pending = &pending;
        let handle_hash = &handle_hash;
        async move {
            if state
                .saml_idp
                .pending_repo
                .consume(tenant_id, handle_hash)
                .await
                .ok()
                .flatten()
                .is_none()
            {
                return refusal_page(StatusCode::BAD_REQUEST, "handle_consumed", tenant_id);
            }
            post_failure(
                state,
                req,
                tenant_id,
                sp,
                &pending.acs_url,
                pending.request_id.as_deref(),
                pending.relay_state.as_deref(),
                status,
                actor,
                clear(),
            )
            .await
        }
    };
    if !sp.enabled {
        return fail(SamlStatus::RequestDenied, None).await;
    }

    // The session, from the OP cookie, through the tenant-keyed lookup only.
    let presented = req
        .cookie(crate::middleware::csrf::COOKIE_OP_SESSION)
        .is_some();
    let resolved = resolve_session(&state, &req, tenant_id).await;
    let fresh = resolved
        .as_ref()
        .is_some_and(|(session, _)| satisfies_force_authn(&pending, session));

    if let (true, Some((session, user))) = (fresh, resolved.as_ref()) {
        return issue(
            &state,
            &req,
            tenant_id,
            org_id,
            &sp,
            &handle_hash,
            session.clone(),
            user.clone(),
        )
        .await;
    }
    let actor = resolved.as_ref().map(|(_, user)| user.id);
    if pending.is_passive {
        return fail(SamlStatus::NoPassive, actor).await;
    }
    if axiam_oauth2::login_hop::is_return_leg(marker.as_deref()) {
        // Back from the sign-in page with no session — or, under ForceAuthn,
        // with none newer than the request. Answered, never hopped again; and
        // a forged marker on a first visit lands here too, with no assertion.
        return fail(SamlStatus::AuthnFailed, actor).await;
    }

    // The hop. `reauth` when the browser holds a session that does not count:
    // a stale cookie, or one older than a ForceAuthn request.
    let Some(return_to) = axiam_oauth2::login_hop::build_saml_return_to(tenant_id, &handle) else {
        return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "return_to", tenant_id);
    };
    let continue_path = axiam_oauth2::login_hop::saml_sso_continue_path(tenant_id);
    if !crate::handlers::oauth2::return_to_is_on_this_deployment(&state, &return_to, &continue_path)
    {
        return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "return_to", tenant_id);
    }
    let stale = presented && resolved.is_none();
    let reauth = stale || resolved.is_some();
    let location = axiam_oauth2::login_hop::build_login_redirect(&return_to, reauth);
    let mut builder = HttpResponse::Found();
    builder
        .insert_header((actix_web::http::header::LOCATION, location))
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Referrer-Policy", "no-referrer"));
    if stale {
        builder.cookie(crate::middleware::csrf::clear_presented_saml_op_session_cookie(tenant_id));
    }
    builder.finish()
}

/// `ForceAuthn` bound to the request: the session must have authenticated
/// strictly after the first leg accepted it (P23W1-08 not inherited).
fn satisfies_force_authn(pending: &PendingSamlRequest, session: &Session) -> bool {
    !pending.force_authn || session.authenticated_at > pending.created_at
}

/// The session the OP cookie names in this tenant, and its account, when that
/// account may act — the rule `/oauth2/authorize` applies
/// (`check_session_holder`, i.e. `account_may_act`: `PendingVerification` is
/// served). A failed read is no session.
async fn resolve_session<C: Connection + Clone>(
    state: &AppState<C>,
    req: &HttpRequest,
    tenant_id: Uuid,
) -> Option<(Session, User)> {
    let cookie = req.cookie(crate::middleware::csrf::COOKIE_OP_SESSION)?;
    let digest = axiam_auth::token::hash_browser_session_token(cookie.value());
    let session = match state
        .session_repo
        .get_by_browser_token_hash(tenant_id, &digest)
        .await
    {
        Ok(found) => found?,
        Err(e) => {
            tracing::warn!(error = %e, %tenant_id, "SAML SSO: could not resolve the OP session");
            return None;
        }
    };
    let user = match state.user_repo.get_by_id(tenant_id, session.user_id).await {
        Ok(user) => user,
        Err(e) => {
            tracing::warn!(error = %e, %tenant_id, "SAML SSO: could not read the session's account");
            return None;
        }
    };
    match state.auth_service.check_session_holder(&user) {
        Ok(()) => Some((session, user)),
        Err(reason) => {
            tracing::info!(%tenant_id, session_id = %session.id, reason = %reason,
                "SAML SSO: the OP session's account may not act");
            None
        }
    }
}

/// Consume the pending request and issue the signed response.
#[allow(clippy::too_many_arguments)]
async fn issue<C: Connection + Clone>(
    state: &AppState<C>,
    req: &HttpRequest,
    tenant_id: Uuid,
    org_id: Uuid,
    sp: &SamlServiceProvider,
    handle_hash: &str,
    session: Session,
    user: User,
) -> HttpResponse {
    // Single use, decided here and nowhere else: of any number of concurrent
    // continues, one gets the row.
    let pending = match state
        .saml_idp
        .pending_repo
        .consume(tenant_id, handle_hash)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => return refusal_page(StatusCode::BAD_REQUEST, "handle_consumed", tenant_id),
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not consume the request");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "store", tenant_id);
        }
    };
    let clear = Some(clear_binding_cookie(tenant_id, handle_hash));
    let fail = |status: SamlStatus| {
        post_failure(
            state,
            req,
            tenant_id,
            sp,
            &pending.acs_url,
            pending.request_id.as_deref(),
            pending.relay_state.as_deref(),
            status,
            Some(user.id),
            clear.clone(),
        )
    };

    let groups = match state.group_repo.get_user_groups(tenant_id, user.id).await {
        Ok(g) => g,
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not read the user's groups");
            return fail(SamlStatus::Responder).await;
        }
    };
    if let Err(e) = axiam_federation::saml_idp::check_allowed_groups(sp, &groups) {
        return fail(e.status()).await;
    }
    let roles = match state.role_repo.get_user_roles(tenant_id, user.id).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not read the user's roles");
            return fail(SamlStatus::Responder).await;
        }
    };
    let key = match state
        .saml_idp
        .credential_service
        .get_active_signing_key(org_id, tenant_id)
        .await
    {
        Ok(Some(key)) => key,
        Ok(None) => {
            tracing::warn!(%tenant_id, "SAML SSO: the tenant has no active signing credential");
            return fail(SamlIdpError::NoActiveCredential.status()).await;
        }
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SSO: could not open the signing credential");
            return fail(SamlStatus::Responder).await;
        }
    };

    // RSA-4096 signing and the self-check, off the async workers, under the
    // same gate that bounds the other CPU-heavy work.
    let permit = state.crypto_semaphore.clone().acquire_owned().await;
    let issuer = std::sync::Arc::clone(&state.saml_idp.issuer);
    let sp_owned = sp.clone();
    let user_owned = user.clone();
    let acs_url = pending.acs_url.clone();
    let request_id = pending.request_id.clone();
    let relay_state = pending.relay_state.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        issuer.issue(
            &SsoIssuance {
                tenant_id,
                sp: &sp_owned,
                acs_url: &acs_url,
                in_response_to: request_id.as_deref(),
                relay_state: relay_state.as_deref(),
                session: &session,
                user: &user_owned,
                groups: &groups,
                roles: &roles,
            },
            &key,
            Utc::now(),
        )
    })
    .await;
    match outcome {
        Ok(Ok(issued)) => {
            tracing::info!(%tenant_id, sp_id = %sp.id, user_id = %user.id,
                "SAML SSO: assertion issued");
            audit(
                state,
                req,
                tenant_id,
                Some(user.id),
                sp.id,
                Ok(&issued.response_id),
            )
            .await;
            post_page(&issued.binding, clear, tenant_id)
        }
        Ok(Err(e @ (SamlIdpError::AcsNotRegistered | SamlIdpError::AcsBindingUnsupported))) => {
            refusal_page(StatusCode::BAD_REQUEST, error_reason(e), tenant_id)
        }
        Ok(Err(e)) => {
            tracing::info!(%tenant_id, sp_id = %sp.id, error = %e, "SAML SSO: not issued");
            fail(e.status()).await
        }
        Err(_) => fail(SamlStatus::Responder).await,
    }
}

fn error_reason(e: SamlIdpError) -> Reason {
    match e {
        SamlIdpError::AcsNotRegistered => "acs_not_registered",
        SamlIdpError::AcsBindingUnsupported => "acs_binding",
        _ => "issuance",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_escape_escapes_every_markup_character() {
        assert_eq!(
            html_escape(r#"<a href="x">'&'</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;"
        );
    }

    #[test]
    fn the_csp_origin_is_the_acs_origin_alone() {
        assert_eq!(
            acs_origin("https://sp.example.test/saml/acs?x=1").as_deref(),
            Some("https://sp.example.test")
        );
        assert_eq!(
            acs_origin("https://sp.example.test:8443/acs").as_deref(),
            Some("https://sp.example.test:8443")
        );
        assert_eq!(acs_origin("not a url"), None);
    }

    /// F4 (W3 review, D-27): the auto-post page's own policy is narrower than
    /// the global one everywhere but `script-src` (a per-response nonce) and
    /// `form-action` (the ACS origin alone) — nothing may be loaded, framed or
    /// re-based, and no directive is a wildcard or an `unsafe-` keyword.
    #[test]
    fn the_auto_post_policy_is_narrower_than_the_global_one() {
        let binding = PostBinding {
            acs_url: "https://sp.example.test/saml/acs?x=1".into(),
            saml_response: "PHNhbWxwOlJlc3BvbnNlLz4=".into(),
            relay_state: Some("rs-1".into()),
        };
        let page = post_page(&binding, None, Uuid::new_v4());
        let csp = page
            .headers()
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .expect("the page sets its own policy")
            .to_owned();
        let directives: Vec<&str> = csp.split(';').map(str::trim).collect();
        for required in [
            "default-src 'none'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action https://sp.example.test",
        ] {
            assert!(directives.contains(&required), "missing {required}");
        }
        assert!(
            directives
                .iter()
                .any(|d| d.starts_with("script-src 'nonce-") && d.split(' ').count() == 2),
            "script-src is one nonce and nothing else"
        );
        assert_eq!(directives.len(), 5, "no other directive widens the page");
        assert!(!csp.contains('*') && !csp.contains("unsafe-"));
    }

    #[test]
    fn a_handle_is_exactly_what_is_minted() {
        let minted = random_token();
        assert!(is_handle(&minted));
        assert!(!is_handle(&format!("{minted}a")));
        assert!(!is_handle(&minted.replacen(|_: char| true, "+", 1)));
        assert!(!is_handle(""));
        assert_ne!(random_token(), random_token());
    }
}

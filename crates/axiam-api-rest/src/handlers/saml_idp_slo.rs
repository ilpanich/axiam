//! The SAML 2.0 identity provider's single-logout endpoint (G-2, T23.2.4, D-37,
//! D-38, D-39).
//!
//! Three routes under `/saml/v2/{tenant_id}`, behind the `saml` feature:
//!
//! | Route | What it does |
//! |---|---|
//! | `GET /slo` | HTTP-Redirect binding: an SP's `LogoutRequest`, or its `LogoutResponse` to one of ours |
//! | `POST /slo` | HTTP-POST binding: the same, as a form post |
//! | `GET /sso/logout` | the IdP-initiated trigger: end the browser's own session and tell its SPs |
//!
//! # What a verified `LogoutRequest` ends
//!
//! **Whole AXIAM sessions** — the ones `saml_sp_session` maps the request to, by
//! (path tenant, the verified issuer's SP, `SessionIndex`), and only when the
//! request's `NameID` value and format equal the row's (T-379). With no
//! `SessionIndex`: everything that SP holds for that `NameID`. For each session,
//! in order: OIDC back-channel logout to the clients bound to it, then
//! `AuthService::logout` — `SessionRepository::invalidate`, which publishes to the
//! revocation feed when it is on — so SLO and the revocation feed revoke the same
//! thing. No match is `Success`: the end state the SP asked for already holds.
//!
//! # Revoke first, then propagate
//!
//! The sessions are gone before any other SP is told, so a chain that breaks
//! never leaves an AXIAM session alive. Propagation is front-channel and
//! sequential, through the browser, in a `saml_logout_run`: each other SP of those
//! sessions that registered an `slo_url` is sent a signed `LogoutRequest` on its
//! registered binding, one at a time, and its `LogoutResponse` here advances the
//! chain. The chain ends with a signed `LogoutResponse` (`Success`, or
//! `PartialLogout`) to the initiating SP's registered `slo_url`, or AXIAM's
//! logged-out page.
//!
//! # What is verified before anything happens
//!
//! Every message from an SP is signed by its registered certificate, always —
//! the Redirect binding over the exact query octets, the POST binding as the
//! root's one enveloped signature — and `verify_signed_xml`, which checks only
//! the first signature, is **never** called (D-23, D-38). An SP with no
//! certificate cannot start a logout. Its `LogoutResponse` to a request of ours is
//! accepted unsigned only to advance the chain, and is never counted as a
//! confirmed logout. Anything refused before verification gets an error page that
//! posts nowhere, and AXIAM **never signs anything for an unverified request**: a
//! party with no session and no SP key cannot make the tenant's key sign.
//!
//! # The browser's cookies
//!
//! `/slo` never reads the OP cookie (its path is the SSO path, and a cross-site
//! post carries no `Lax` cookie) and never decides anything by it. Every answer to
//! a **verified** message clears every OP-cookie copy for the tenant and the API
//! cookies, so the browser that carried the logout is signed out whichever
//! session its cookie named.
//!
//! # D-20, and what is never logged
//!
//! The tenant check — canonical id, tenant exists, effective `saml_idp_enabled`
//! — runs before the body is read and answers the same empty `404` as an
//! unmounted path. `SAMLRequest`, `SAMLResponse`, `RelayState`, `Signature`, a
//! `NameID`, a `SessionIndex` and the OP cookie are never logged; refusals are the
//! fixed reason and the tenant.

use actix_web::cookie::Cookie;
use actix_web::http::StatusCode;
use actix_web::{HttpRequest, HttpResponse, web};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::saml_slo::{
    MAX_LOGOUT_RUN_PARTICIPANTS, NewSamlLogoutRun, SamlLogoutInitiator, SamlLogoutPlan,
    SamlLogoutProgress, SamlLogoutRun, SamlSpSession,
};
use axiam_core::models::saml_sp::SamlServiceProvider;
use axiam_core::repository::{
    AuditLogRepository, SamlLogoutRunRepository, SamlServiceProviderRepository,
    SamlSpSessionRepository, SessionRepository,
};
use axiam_federation::saml_idp::logout::{
    LogoutDelivery, LogoutStatus, LogoutSubject, OutboundLogout, ParsedLogoutMessage,
    ParsedLogoutRequest, ParsedLogoutResponse, parse_logout_message,
};
use axiam_federation::saml_idp::request::{
    self as saml_request, MessageParam, RedirectQuery, RequestError,
};
use axiam_federation::saml_idp::{SamlIdpError, check_relay_state, idp_slo_url};
use chrono::Utc;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use surrealdb::Connection;
use uuid::Uuid;

use crate::extractors::client_info::peer_ip;
use crate::handlers::saml_idp::{
    MAX_POST_BODY_BYTES, not_found, post_form_page, request_reason, request_status,
    tenant_serving_saml,
};
use crate::state::AppState;

/// Why a request was refused, as a fixed string for the log.
type Reason = &'static str;

/// What every step of one request needs, so none carries five arguments.
struct Ctx<'a, C: Connection + Clone> {
    state: &'a web::Data<AppState<C>>,
    req: &'a HttpRequest,
    tenant_id: Uuid,
    /// The tenant's organization, for the signing credential's custody.
    org_id: Uuid,
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

/// An error page that posts nowhere. Generic text: nothing from the request is
/// reflected, and the reason is in the log, not on the page. Sets no cookie: a
/// message that was not verified changes nothing about the browser's sign-in
/// (T-378).
fn refusal_page(status: StatusCode, reason: Reason, tenant_id: Uuid) -> HttpResponse {
    tracing::info!(%tenant_id, reason, "SAML SLO: request refused with an error page");
    let body = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
                <title>Sign-out request refused</title></head><body>\
                <h1>This sign-out request cannot be completed</h1>\
                <p>Return to the application you came from. If this keeps happening, \
                contact its administrator.</p></body></html>";
    HttpResponse::build(status)
        .content_type("text/html; charset=utf-8")
        .insert_header(("Cache-Control", "no-store"))
        .insert_header(("Pragma", "no-cache"))
        .body(body)
}

fn request_refused(error: RequestError, tenant_id: Uuid) -> HttpResponse {
    refusal_page(request_status(error), request_reason(error), tenant_id)
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// What every answer to a verified message carries: the three API cookies and
/// every OP-session copy for the tenant, cleared (D-39).
fn clear_cookies<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
) -> Vec<Cookie<'static>> {
    crate::handlers::oauth2::logout_cookies(&state.auth_config, tenant_id)
}

/// AXIAM's own logged-out page, with the cookies cleared (it does both).
fn logged_out<C: Connection + Clone>(state: &AppState<C>, tenant_id: Uuid) -> HttpResponse {
    crate::handlers::oauth2::logged_out_page(&state.auth_config, tenant_id)
}

/// Deliver one signed logout message through the browser: a redirect to the SP's
/// registered endpoint, or the shared auto-post page, with the cookies cleared.
fn deliver<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    outbound: OutboundLogout,
) -> HttpResponse {
    let cookies = clear_cookies(state, tenant_id);
    match outbound.delivery {
        LogoutDelivery::Redirect { location } => {
            let mut builder = HttpResponse::Found();
            builder
                .insert_header((actix_web::http::header::LOCATION, location))
                .insert_header(("Cache-Control", "no-store"))
                .insert_header(("Referrer-Policy", "no-referrer"));
            for cookie in cookies {
                builder.cookie(cookie);
            }
            builder.finish()
        }
        LogoutDelivery::Post {
            destination,
            field,
            value,
            relay_state,
        } => post_form_page(
            &destination,
            field,
            &value,
            relay_state.as_deref(),
            cookies,
            tenant_id,
        ),
    }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/// `saml_idp.logout` — never containing a `NameID` (T-376): who started it, which
/// SP, how far it got.
async fn audit<C: Connection + Clone>(
    state: &AppState<C>,
    req: &HttpRequest,
    tenant_id: Uuid,
    actor: Option<Uuid>,
    sp_id: Option<Uuid>,
    outcome: AuditOutcome,
    detail: serde_json::Value,
) {
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
            action: "saml_idp.logout".into(),
            resource_id: sp_id,
            outcome,
            ip_address: peer_ip(req),
            metadata: Some(detail),
        })
        .await
    {
        tracing::error!(error = %e, %tenant_id, "SAML SLO: could not record the outcome");
    }
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

struct Incoming<'q> {
    document: String,
    param: MessageParam,
    relay_state: Option<String>,
    /// The Redirect binding's query (its signature is over the query); `None`
    /// for the POST binding.
    redirect: Option<RedirectQuery<'q>>,
}

/// `GET /saml/v2/{tenant_id}/slo` — the HTTP-Redirect binding.
pub async fn slo_redirect<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let Some((tenant_id, org_id)) = tenant_serving_saml(&state, &path).await else {
        return not_found().await;
    };
    let query = match RedirectQuery::parse_logout(req.query_string()) {
        Ok(q) => q,
        Err(e) => return request_refused(e, tenant_id),
    };
    let document = match saml_request::decode_redirect(&query.message()) {
        Ok(d) => d,
        Err(e) => return request_refused(e, tenant_id),
    };
    receive(
        &Ctx {
            state: &state,
            req: &req,
            tenant_id,
            org_id,
        },
        Incoming {
            document,
            param: query.param,
            relay_state: query.relay_state(),
            redirect: Some(query),
        },
    )
    .await
}

/// `POST /saml/v2/{tenant_id}/slo` — the HTTP-POST binding.
pub async fn slo_post<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
    mut payload: web::Payload,
) -> HttpResponse {
    let Some((tenant_id, org_id)) = tenant_serving_saml(&state, &path).await else {
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
    let (mut request, mut response, mut relay) = (None, None, None);
    for (name, value) in url::form_urlencoded::parse(&body) {
        let slot = match name.as_ref() {
            "SAMLRequest" => &mut request,
            "SAMLResponse" => &mut response,
            "RelayState" => &mut relay,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return request_refused(RequestError::DuplicateParameter, tenant_id);
        }
    }
    let (param, encoded) = match (request, response) {
        (Some(m), None) => (MessageParam::Request, m),
        (None, Some(m)) => (MessageParam::Response, m),
        (Some(_), Some(_)) => {
            return request_refused(RequestError::DuplicateParameter, tenant_id);
        }
        (None, None) => return request_refused(RequestError::Encoding, tenant_id),
    };
    let document = match saml_request::decode_post(&encoded) {
        Ok(d) => d,
        Err(e) => return request_refused(e, tenant_id),
    };
    receive(
        &Ctx {
            state: &state,
            req: &req,
            tenant_id,
            org_id,
        },
        Incoming {
            document,
            param,
            relay_state: relay,
            redirect: None,
        },
    )
    .await
}

/// What the endpoint decides about a received message, in the order the module
/// docs give.
async fn receive<C: Connection + Clone>(cx: &Ctx<'_, C>, incoming: Incoming<'_>) -> HttpResponse {
    let (state, tenant_id) = (cx.state, cx.tenant_id);
    let parsed = match parse_logout_message(&incoming.document, Utc::now()) {
        Ok(p) => p,
        Err(e) => return request_refused(e, tenant_id),
    };
    // The parameter or form field the message arrived in must be its kind: the
    // Redirect signature covers the parameter's name.
    let kind_matches = matches!(
        (incoming.param, &parsed),
        (MessageParam::Request, ParsedLogoutMessage::Request(_))
            | (MessageParam::Response, ParsedLogoutMessage::Response(_))
    );
    if !kind_matches {
        return request_refused(RequestError::NotALogoutMessage, tenant_id);
    }
    // A signature inside a Redirect-binding document is not that binding's
    // signature (Bindings §3.4.4.1); nothing checks it, so it is refused.
    if incoming.redirect.is_some() && parsed.enveloped_signature() {
        return request_refused(RequestError::SignaturePlacement, tenant_id);
    }
    if check_relay_state(incoming.relay_state.as_deref()).is_err() {
        return refusal_page(StatusCode::BAD_REQUEST, "relay_state", tenant_id);
    }
    // `Destination` is this tenant's SLO URL, always present (D-38).
    let slo_url = idp_slo_url(state.auth_config.root_issuer(), tenant_id);
    match parsed.destination() {
        Some(destination) if destination == slo_url => {}
        Some(_) => return refusal_page(StatusCode::BAD_REQUEST, "destination", tenant_id),
        None => return request_refused(RequestError::DestinationMissing, tenant_id),
    }

    // The SP, by issuer, within the path's tenant only.
    let sp = match state
        .saml_idp
        .sp_repo
        .get_by_entity_id(tenant_id, parsed.issuer())
        .await
    {
        Ok(Some(sp)) => sp,
        Ok(None) => return refusal_page(StatusCode::BAD_REQUEST, "unknown_sp", tenant_id),
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SLO: could not read the SP registry");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "registry", tenant_id);
        }
    };
    // An administrator who disabled an SP expects it to have no effect, a
    // logout included: a disabled SP's key ends nothing.
    if !sp.enabled {
        return refusal_page(StatusCode::FORBIDDEN, "sp_disabled", tenant_id);
    }

    // The signature, before anything the message names is trusted.
    let verified = match verify(&incoming, &parsed, &sp) {
        Ok(verified) => verified,
        Err(refusal) => return refusal.page(tenant_id),
    };

    match parsed {
        ParsedLogoutMessage::Request(request) => {
            handle_request(cx, &sp, request, incoming.relay_state).await
        }
        ParsedLogoutMessage::Response(response) => {
            handle_response(cx, &sp, response, verified).await
        }
    }
}

/// Why verification refused a message.
enum Refusal {
    /// A [`RequestError`] from the receiver's verifiers.
    Request(RequestError),
    /// A fixed reason of this endpoint's own.
    Reason(Reason),
}

impl Refusal {
    fn page(self, tenant_id: Uuid) -> HttpResponse {
        match self {
            Self::Request(e) => request_refused(e, tenant_id),
            Self::Reason(reason) => refusal_page(StatusCode::BAD_REQUEST, reason, tenant_id),
        }
    }
}

/// Verify a message against the SP's registered certificate.
///
/// * A **request** must be signed, by that certificate, and an SP with none
///   cannot start a logout.
/// * A **response** from an SP that registered a certificate must be signed by
///   it too. One from an SP with none is accepted unsigned only to advance the
///   chain, and is reported unverified: it is never counted as a confirmed
///   logout.
///
/// `Ok(true)` when a signature was checked and held. **`verify_signed_xml` is
/// never called**: the POST signature is the one placement allowed
/// (`parse_logout_message` established it) checked on that node by xmlsec, and
/// the Redirect signature is over the exact octets received.
fn verify(
    incoming: &Incoming<'_>,
    parsed: &ParsedLogoutMessage,
    sp: &SamlServiceProvider,
) -> Result<bool, Refusal> {
    let cert = match sp.sp_signing_cert_pem.as_deref() {
        Some(pem) => Some(
            axiam_federation::cert::pem_cert_to_der(pem)
                .map_err(|_| Refusal::Reason("sp_certificate"))?,
        ),
        None => None,
    };
    let signed = match &incoming.redirect {
        Some(query) => query.is_signed(),
        None => parsed.enveloped_signature(),
    };
    let is_request = matches!(parsed, ParsedLogoutMessage::Request(_));
    let Some(cert) = cert else {
        if is_request {
            return Err(Refusal::Reason("sp_has_no_certificate"));
        }
        return Ok(false);
    };
    if !signed {
        return Err(Refusal::Request(RequestError::SignatureMissing));
    }
    let outcome = match &incoming.redirect {
        Some(query) => query.verify_signature(&cert),
        None => saml_request::verify_post_signature(&incoming.document, &cert),
    };
    outcome.map(|()| true).map_err(Refusal::Request)
}

// ---------------------------------------------------------------------------
// A verified LogoutRequest
// ---------------------------------------------------------------------------

async fn handle_request<C: Connection + Clone>(
    cx: &Ctx<'_, C>,
    sp: &SamlServiceProvider,
    request: ParsedLogoutRequest,
    relay_state: Option<String>,
) -> HttpResponse {
    let (state, tenant_id) = (cx.state, cx.tenant_id);
    // The replay guard, claimed before anything is resolved or revoked: a
    // replayed request ends nothing (T-371).
    let run = match state
        .saml_idp
        .logout_run_repo
        .claim(NewSamlLogoutRun {
            tenant_id,
            initiator: SamlLogoutInitiator::ServiceProvider(sp.id),
            initiator_request_id: Some(request.id.clone()),
            initiator_relay_state: relay_state,
        })
        .await
    {
        Ok(run) => run,
        Err(AxiamError::ReplayDetected) => {
            return refusal_page(StatusCode::BAD_REQUEST, "replayed_request_id", tenant_id);
        }
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SLO: could not claim the run");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "store", tenant_id);
        }
    };

    // The sessions this SP may name: its own rows, by index or by `NameID`, whose
    // `NameID` value and format are the request's (T-379).
    let rows = match resolve_participants(state, tenant_id, sp, &request).await {
        Ok(rows) => rows,
        Err(()) => return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "store", tenant_id),
    };
    let mut sessions: Vec<(Uuid, Uuid)> = Vec::new();
    for row in &rows {
        if !sessions
            .iter()
            .any(|(session, _)| *session == row.session_id)
        {
            sessions.push((row.session_id, row.user_id));
        }
    }

    let run = match end_sessions(cx, run, &sessions, Some(sp.id)).await {
        Ok(run) => run,
        Err(page) => return *page,
    };
    next_hop(cx, run).await
}

/// The participant rows a request names, and only those its `NameID` matches.
async fn resolve_participants<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    sp: &SamlServiceProvider,
    request: &ParsedLogoutRequest,
) -> Result<Vec<SamlSpSession>, ()> {
    let repo = &state.saml_idp.participant_repo;
    let mut rows: Vec<SamlSpSession> = Vec::new();
    if request.session_indexes.is_empty() {
        match repo
            .list_for_sp_name_id(tenant_id, sp.id, &request.name_id)
            .await
        {
            Ok(found) => rows = found,
            Err(e) => {
                tracing::error!(error = %e, %tenant_id, "SAML SLO: could not read participants");
                return Err(());
            }
        }
    } else {
        for index in &request.session_indexes {
            match repo.get_by_index(tenant_id, sp.id, index).await {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => {}
                Err(e) => {
                    tracing::error!(error = %e, %tenant_id,
                        "SAML SLO: could not read participants");
                    return Err(());
                }
            }
        }
    }
    // The index alone ends nothing: the request must also name the principal the
    // SP was given, in the format it was given.
    rows.retain(|row| {
        row.sp_id == sp.id
            && row.tenant_id == tenant_id
            && row.name_id == request.name_id
            && Some(row.name_id_format.as_str()) == request.name_id_format.as_deref()
    });
    Ok(rows)
}

/// End `sessions` — back-channel logout to their OIDC clients, then
/// `AuthService::logout`, which feeds the revocation feed — and plan the chain
/// that tells every **other** SP of those sessions (D-39). Revokes first.
///
/// `Err` is the page to answer with when a session could not be revoked —
/// boxed, since `HttpResponse` is past `clippy::result_large_err`'s threshold
/// and the success path should not carry its width.
async fn end_sessions<C: Connection + Clone>(
    cx: &Ctx<'_, C>,
    run: SamlLogoutRun,
    sessions: &[(Uuid, Uuid)],
    initiator_sp: Option<Uuid>,
) -> Result<SamlLogoutRun, Box<HttpResponse>> {
    let (state, tenant_id) = (cx.state, cx.tenant_id);
    let mut failed = false;
    for (session_id, user_id) in sessions {
        crate::handlers::oauth2::dispatch_backchannel_logout(
            state,
            tenant_id,
            *session_id,
            *user_id,
            None,
        )
        .await;
        if let Err(e) = state.auth_service.logout(tenant_id, *session_id).await {
            tracing::error!(error = %e, %tenant_id, session_id = %session_id,
                "SAML SLO: could not revoke the session");
            failed = true;
        }
    }
    if failed {
        // Not `Success`: a session is still alive. Nothing is signed; the
        // cookies are cleared all the same (this answers a verified request).
        let mut page = refusal_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "revocation_failed",
            tenant_id,
        );
        for cookie in clear_cookies(state, tenant_id) {
            let _ = page.add_cookie(&cookie);
        }
        return Err(Box::new(page));
    }

    let session_ids: Vec<Uuid> = sessions.iter().map(|(session, _)| *session).collect();
    let mut queue: Vec<Uuid> = Vec::new();
    for session_id in &session_ids {
        match state
            .saml_idp
            .participant_repo
            .list_for_session(tenant_id, *session_id)
            .await
        {
            Ok(rows) => queue.extend(
                rows.into_iter()
                    .filter(|row| Some(row.sp_id) != initiator_sp)
                    .map(|row| row.id),
            ),
            Err(e) => {
                tracing::error!(error = %e, %tenant_id, "SAML SLO: could not list participants");
                // The sessions are gone; the other SPs cannot be told.
                return Ok(
                    planned_without_chain(state, tenant_id, run, &session_ids, sessions).await,
                );
            }
        }
    }
    // Rows are kept for one run lifetime while the chain needs them.
    if let Err(e) = state
        .saml_idp
        .participant_repo
        .mark_ended(tenant_id, &session_ids)
        .await
    {
        tracing::error!(error = %e, %tenant_id, "SAML SLO: could not mark the participants");
    }
    let over_cap = queue.len() > MAX_LOGOUT_RUN_PARTICIPANTS;
    queue.truncate(MAX_LOGOUT_RUN_PARTICIPANTS);

    let user_id = sessions.first().map(|(_, user)| *user);
    let planned = match user_id {
        Some(user_id) => {
            state
                .saml_idp
                .logout_run_repo
                .plan(
                    tenant_id,
                    run.id,
                    SamlLogoutPlan {
                        user_id,
                        queue: queue.clone(),
                        session_ids: session_ids.clone(),
                        partial: over_cap,
                    },
                )
                .await
        }
        // No session matched: nothing was ended and nobody is told.
        None => Ok(run.clone()),
    };
    let planned = match planned {
        Ok(planned) => planned,
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SLO: could not plan the run");
            let mut degraded = run;
            degraded.session_ids = session_ids.clone();
            degraded.sessions_ended = u32::try_from(session_ids.len()).unwrap_or(u32::MAX);
            degraded.partial = true;
            degraded
        }
    };
    audit(
        state,
        cx.req,
        tenant_id,
        user_id,
        planned.initiator_sp_id,
        AuditOutcome::Success,
        serde_json::json!({
            "phase": "sessions_ended",
            "initiator": if planned.initiator_sp_id.is_some() { "sp" } else { "idp" },
            "sessions_ended": session_ids.len(),
            "sps_queued": planned.queue.len(),
            "partial": planned.partial,
        }),
    )
    .await;
    Ok(planned)
}

/// The sessions are revoked but the participants could not be read: a run with
/// nothing to tell, marked partial.
async fn planned_without_chain<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    mut run: SamlLogoutRun,
    session_ids: &[Uuid],
    sessions: &[(Uuid, Uuid)],
) -> SamlLogoutRun {
    run.partial = true;
    run.session_ids = session_ids.to_vec();
    run.sessions_ended = u32::try_from(session_ids.len()).unwrap_or(u32::MAX);
    run.user_id = sessions.first().map(|(_, user)| *user);
    run.queue = Vec::new();
    if let Some(user_id) = run.user_id {
        let _ = state
            .saml_idp
            .logout_run_repo
            .plan(
                tenant_id,
                run.id,
                SamlLogoutPlan {
                    user_id,
                    queue: Vec::new(),
                    session_ids: session_ids.to_vec(),
                    partial: true,
                },
            )
            .await;
    }
    run
}

// ---------------------------------------------------------------------------
// The chain
// ---------------------------------------------------------------------------

/// Sign with the tenant's active credential, off the async workers and under the
/// gate that bounds the other CPU-heavy work.
async fn sign_with_active_key<C, F, T>(cx: &Ctx<'_, C>, sign: F) -> Result<T, Reason>
where
    C: Connection + Clone,
    F: FnOnce(
            &axiam_federation::saml_idp::SamlIdpIssuer,
            &axiam_federation::saml_idp::SamlIdpSigningKey,
        ) -> Result<T, SamlIdpError>
        + Send
        + 'static,
    T: Send + 'static,
{
    let (state, tenant_id, org_id) = (cx.state, cx.tenant_id, cx.org_id);
    let key = match state
        .saml_idp
        .credential_service
        .get_active_signing_key(org_id, tenant_id)
        .await
    {
        Ok(Some(key)) => key,
        Ok(None) => return Err("no_credential"),
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SLO: could not open the signing credential");
            return Err("credential");
        }
    };
    let permit = state.crypto_semaphore.clone().acquire_owned().await;
    let issuer = std::sync::Arc::clone(&state.saml_idp.issuer);
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        sign(&issuer, &key)
    })
    .await
    {
        Ok(Ok(signed)) => Ok(signed),
        Ok(Err(e)) => {
            tracing::warn!(%tenant_id, error = %e, "SAML SLO: a logout message was not signed");
            Err("signing")
        }
        Err(_) => Err("signing"),
    }
}

/// Tell the next other SP, or end the chain.
///
/// Pops the queue until a participant can be sent a request — its row and SP
/// still exist, the SP registered an `slo_url`, and a message can be signed —
/// marking the run partial for every one that cannot. A request goes out only
/// once the run holds the SHA-256 of its `ID`, so no response can arrive for a
/// request the run does not know. When the queue is empty the chain ends.
async fn next_hop<C: Connection + Clone>(cx: &Ctx<'_, C>, mut run: SamlLogoutRun) -> HttpResponse {
    let (state, tenant_id) = (cx.state, cx.tenant_id);
    let mut queue: std::collections::VecDeque<Uuid> = run.queue.iter().copied().collect();
    while let Some(row_id) = queue.pop_front() {
        let row = match state.saml_idp.participant_repo.get(tenant_id, row_id).await {
            Ok(Some(row)) => row,
            _ => {
                run.partial = true;
                continue;
            }
        };
        let sp = match state.saml_idp.sp_repo.get(tenant_id, row.sp_id).await {
            Ok(sp) if sp.slo_url.is_some() && sp.slo_binding.is_some() => sp,
            // Deleted since, or it registered no single-logout endpoint: it is
            // not told, and the logout is partial.
            _ => {
                run.partial = true;
                continue;
            }
        };
        let (sp_for_sign, row_for_sign) = (sp.clone(), row.clone());
        let outbound = sign_with_active_key(cx, move |issuer, key| {
            issuer.logout_request(
                tenant_id,
                &sp_for_sign,
                &LogoutSubject {
                    name_id: &row_for_sign.name_id,
                    name_id_format: &row_for_sign.name_id_format,
                    session_index: &row_for_sign.session_index,
                },
                key,
                Utc::now(),
            )
        })
        .await;
        let outbound = match outbound {
            Ok(outbound) => outbound,
            Err(_) => {
                run.partial = true;
                continue;
            }
        };
        let told = run.sps_told + 1;
        let progress = SamlLogoutProgress {
            queue: queue.iter().copied().collect(),
            outbound: Some((sp.id, sha256_hex(&outbound.id))),
            partial: run.partial,
            sps_told: told,
        };
        if let Err(e) = state
            .saml_idp
            .logout_run_repo
            .progress(tenant_id, run.id, progress)
            .await
        {
            // The chain cannot be followed; nothing has been sent. End it here.
            tracing::error!(error = %e, %tenant_id, "SAML SLO: could not advance the run");
            run.partial = true;
            break;
        }
        tracing::info!(%tenant_id, run_id = %run.id, sp_id = %sp.id,
            "SAML SLO: telling the next service provider");
        return deliver(state, tenant_id, outbound);
    }
    finish(cx, run).await
}

/// End the chain: delete the participant rows of the sessions it ended, record
/// the outcome and answer — a signed `LogoutResponse` to the initiating SP at its
/// registered `slo_url`, or AXIAM's logged-out page.
async fn finish<C: Connection + Clone>(cx: &Ctx<'_, C>, run: SamlLogoutRun) -> HttpResponse {
    let (state, tenant_id) = (cx.state, cx.tenant_id);
    if let Err(e) = state
        .saml_idp
        .participant_repo
        .delete_for_sessions(tenant_id, &run.session_ids)
        .await
    {
        tracing::warn!(error = %e, %tenant_id, "SAML SLO: could not delete the participant rows");
    }
    if let Err(e) = state
        .saml_idp
        .logout_run_repo
        .finish(tenant_id, run.id, run.partial, run.sps_told)
        .await
    {
        tracing::warn!(error = %e, %tenant_id, "SAML SLO: could not finish the run");
    }
    audit(
        state,
        cx.req,
        tenant_id,
        run.user_id,
        run.initiator_sp_id,
        if run.partial {
            AuditOutcome::Failure
        } else {
            AuditOutcome::Success
        },
        serde_json::json!({
            "phase": "completed",
            "initiator": if run.initiator_sp_id.is_some() { "sp" } else { "idp" },
            "sessions_ended": run.sessions_ended,
            "sps_told": run.sps_told,
            "partial": run.partial,
            "outcome": if run.partial { "partial_logout" } else { "success" },
        }),
    )
    .await;

    // The IdP-initiated trigger, or an initiator that cannot be answered: our own
    // page. Nothing is signed for it.
    let Some(initiator_id) = run.initiator_sp_id else {
        return logged_out(state, tenant_id);
    };
    let Some(request_id) = run.initiator_request_id.clone() else {
        return logged_out(state, tenant_id);
    };
    let initiator = match state.saml_idp.sp_repo.get(tenant_id, initiator_id).await {
        Ok(sp) if sp.slo_url.is_some() && sp.slo_binding.is_some() => sp,
        _ => return logged_out(state, tenant_id),
    };
    let (relay_state, partial) = (run.initiator_relay_state.clone(), run.partial);
    let response = sign_with_active_key(cx, move |issuer, key| {
        issuer.logout_response(
            tenant_id,
            &initiator,
            &request_id,
            relay_state.as_deref(),
            partial,
            key,
            Utc::now(),
        )
    })
    .await;
    match response {
        Ok(outbound) => deliver(state, tenant_id, outbound),
        Err(_) => logged_out(state, tenant_id),
    }
}

// ---------------------------------------------------------------------------
// A LogoutResponse to one of ours
// ---------------------------------------------------------------------------

async fn handle_response<C: Connection + Clone>(
    cx: &Ctx<'_, C>,
    sp: &SamlServiceProvider,
    response: ParsedLogoutResponse,
    verified: bool,
) -> HttpResponse {
    let (state, tenant_id) = (cx.state, cx.tenant_id);
    // Consumed once on the X6 arbiter, and only by the SP the request went to: a
    // replayed, unknown or foreign `InResponseTo` matches no run and consumes
    // nothing (T-371, T-383).
    let consumed = state
        .saml_idp
        .logout_run_repo
        .consume_response(tenant_id, &sha256_hex(&response.in_response_to), sp.id)
        .await;
    let mut run = match consumed {
        Ok(Some(run)) => run,
        Ok(None) => {
            return refusal_page(StatusCode::BAD_REQUEST, "unknown_in_response_to", tenant_id);
        }
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SLO: could not consume the response");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "store", tenant_id);
        }
    };
    // Confirmed only by a signed `Success`. An unsigned answer (from an SP with
    // no certificate), `PartialLogout` or any failure advances the chain and makes
    // the logout partial.
    if !(verified && response.status == LogoutStatus::Success) {
        run.partial = true;
    }
    next_hop(cx, run).await
}

// ---------------------------------------------------------------------------
// The IdP-initiated trigger
// ---------------------------------------------------------------------------

/// `GET /saml/v2/{tenant_id}/sso/logout` — end the browser's own session and tell
/// the SPs that hold it (D-39).
///
/// Under the SSO path, so the OP cookie reaches it (as `/oauth2/authorize/logout`
/// sits under the authorization endpoint). A cross-site trigger is refused
/// (`Sec-Fetch-Site: cross-site`, D-26's rule): a third-party page that could
/// navigate a visitor here would sign them out of AXIAM and every SP (T-378). The
/// cookie is resolved through the tenant-keyed digest lookup alone; with no
/// cookie or no live session the cookies are cleared and the logged-out page is
/// shown.
pub async fn sso_logout<C: Connection + Clone>(
    state: web::Data<AppState<C>>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let Some((tenant_id, org_id)) = tenant_serving_saml(&state, &path).await else {
        return not_found().await;
    };
    let cx = Ctx {
        state: &state,
        req: &req,
        tenant_id,
        org_id,
    };
    if req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("cross-site"))
    {
        return refusal_page(StatusCode::FORBIDDEN, "idp_logout_cross_site", tenant_id);
    }

    let session = match req.cookie(crate::middleware::csrf::COOKIE_OP_SESSION) {
        Some(cookie) => {
            let digest = axiam_auth::token::hash_browser_session_token(cookie.value());
            match state
                .session_repo
                .get_by_browser_token_hash(tenant_id, &digest)
                .await
            {
                Ok(found) => found,
                Err(e) => {
                    tracing::warn!(error = %e, %tenant_id,
                        "SAML SLO: could not resolve the OP session; clearing the cookies");
                    None
                }
            }
        }
        None => None,
    };
    let Some(session) = session else {
        return logged_out(&state, tenant_id);
    };

    let run = match state
        .saml_idp
        .logout_run_repo
        .claim(NewSamlLogoutRun {
            tenant_id,
            initiator: SamlLogoutInitiator::Idp,
            initiator_request_id: None,
            initiator_relay_state: None,
        })
        .await
    {
        Ok(run) => run,
        Err(e) => {
            tracing::error!(error = %e, %tenant_id, "SAML SLO: could not claim the run");
            return refusal_page(StatusCode::INTERNAL_SERVER_ERROR, "store", tenant_id);
        }
    };
    let run = match end_sessions(&cx, run, &[(session.id, session.user_id)], None).await {
        Ok(run) => run,
        Err(page) => return *page,
    };
    next_hop(&cx, run).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_is_the_sha256_hex_of_the_value() {
        assert_eq!(sha256_hex("").len(), 64);
        assert_ne!(sha256_hex("_a"), sha256_hex("_b"));
        assert_eq!(sha256_hex("_a"), sha256_hex("_a"));
    }
}

//! `POST /api/v1/network/decide` — the RADIUS placement decision (RADIUS Live profile,
//! W6.4; `claude_dev/radius-reply-profile-design.md` §4.3, §6.3, §7, §8; threat
//! T-468).
//!
//! FreeRADIUS's `rlm_rest`, in `post-auth` after EAP-TLS succeeded, posts the
//! presented certificate (or its fingerprint) and the **site key from its own
//! client configuration**; AXIAM answers `{ "allow": false }` with **no
//! reason**, or `{ "allow": true, "reply": … }` with the attributes of the
//! segment the device is placed on, rendered from its typed reply profile.
//!
//! # The caller (T-468)
//!
//! An authenticated oracle on "is this certificate good here", so its caller is
//! held to more than an ordinary machine route's:
//!
//! * a **service account** (`aud = axiam:m2m`, `sub_kind = service_account`);
//!   a user's token, an OAuth2 client's and a user token narrowed to the machine
//!   audience are `401`;
//! * its token **bound to its own certificate**: `cnf.x5t#S256` present (a
//!   plain bearer token, or one bound only by DPoP, is `401`), presented over a
//!   connection whose TLS-verified client certificate is that one (the
//!   extractor's sender-constraint check), and that certificate resolves —
//!   through [`DeviceAuthService::authenticate_der`](axiam_pki::DeviceAuthService::authenticate_der),
//!   now, so a revoked caller certificate stops at the next request — to **this**
//!   service account in this tenant, which is `Active`;
//! * holding `network:decide` on every site node the decision reads (§4.2: "a
//!   site"), so a FreeRADIUS credential for HQ answers nothing about a branch
//!   office: `403`, audited;
//! * metered per **caller** (`network_decide_per_min`, D-6), not per address.
//!
//! The `network` permission family stays human-only
//! ([`HUMAN_ONLY_FAMILIES`](crate::permissions::HUMAN_ONLY_FAMILIES)); this one
//! route is the named exception,
//! [`CERTIFICATE_BOUND_MACHINE_ROUTES`](crate::permissions::CERTIFICATE_BOUND_MACHINE_ROUTES).
//!
//! # The decision (§4.3), at one cost (T-457)
//!
//! Every request that gets past the caller's checks runs the same steps, in the
//! same order, whatever the certificate turns out to be:
//!
//! 1. the certificate row by fingerprint (global), then `authenticate_der` —
//!    over the caller's own certificate, as a decoy whose result is discarded,
//!    when no row of this tenant resolved (#706); **another tenant's
//!    certificate is refused** (§7), with the reject every other failure gets;
//! 2. the subject's account (the device's service account, or — when no
//!    certificate of this tenant resolved — the caller's own, as a decoy of the
//!    same shape) — `Active` or no placement;
//! 3. the site's segments, their stored profiles and the tenant's cap, each one
//!    query; every profile is re-validated and rendered (§3.4), and a profile
//!    that no longer validates makes its segment no candidate and is audited once
//!    per window;
//! 4. **one** `check_access_batch` of `network:join` over every enabled segment of
//!    the site, for the subject (the decoy included), through the decision cache,
//!    deny-override in force — which is what makes quarantine by deny work (§4.4);
//! 5. the lowest-ranked `access` candidate, else a `quarantine` one, else none;
//! 6. one audit row (T-463, §8), and the answer.
//!
//! "No candidate", "another tenant's certificate", "an unknown certificate or
//! fingerprint", "an inactive account" and a placement therefore cost the same
//! reads, one full verification and the same batch; only the answer differs.
//! What remains is recorded for the threat model (T-457), not hidden:
//! `authenticate_der`'s own early refusals for a row of **this** tenant (a
//! revoked, expired or server certificate stops before the chain is verified),
//! the engine's answer for a subject with no role assignment, and the **global
//! fingerprint read** of step 1: a hit deserialises the row of another tenant's
//! certificate and a miss is `NotFound`, so a caller can tell, by one indexed
//! read against a verification, whether a certificate with that fingerprint
//! exists in any tenant (T-457, residual (f); Informational, not closed).
//!
//! # What is never on the wire, and never in the row
//!
//! The deny carries no reason. The audit row carries the internal reason, the
//! site, the certificate's SHA-256 fingerprint, and — for a certificate of this
//! tenant — its id and the service account it is bound to; **never** the
//! certificate's subject or alternative names, and the request accepts no
//! `Calling-Station-Id` or `User-Name` (an unknown key is a `400`), so none can
//! reach the trail (§8, T-464). A certificate of another tenant is recorded by
//! its fingerprint alone: the caller's tenant learns nothing about the other's.

use std::collections::BTreeSet;

use actix_web::error::JsonPayloadError;
use actix_web::{FromRequest, HttpRequest, HttpResponse, web};
use axiam_auth::token::SubjectKind;
use axiam_authz::types::{AccessDecision, AccessRequest, SubjectScope};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::certificate::{Certificate, CertificateStatus};
use axiam_core::models::network::{
    NETWORK_DECIDE, NETWORK_JOIN, NetworkSegment, NetworkSegmentKind, ProfileDefect,
    select_placement, site_node_id,
};
use axiam_core::models::radius_reply::{RenderedReply, is_valid_identifier};
use axiam_core::models::user::UserStatus;
use axiam_core::repository::{
    AuditLogRepository, CertificateRepository, NetworkPolicyRepository, NetworkSegmentRepository,
    ReplyProfileRepository, ServiceAccountRepository,
};
use axiam_db::repository::{
    SurrealNetworkPolicyRepository, SurrealNetworkSegmentRepository, SurrealReplyProfileRepository,
};
use base64::Engine as _;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use surrealdb::Connection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::authz::AuthzData;
use crate::error::AxiamApiError;
use crate::extractors::auth::AuthenticatedServiceAccount;
use crate::extractors::cert_auth::VerifiedClientCert;
use crate::extractors::client_info::client_ip;
use crate::state::AppState;

/// Audit action: a decision placed a device.
pub const AUDIT_DECISION_ALLOWED: &str = "network_decision.allowed";
/// Audit action: a decision refused a device (no placement).
pub const AUDIT_DECISION_DENIED: &str = "network_decision.denied";
/// Audit action: a caller without `network:decide` on the site asked.
pub const AUDIT_DECISION_REFUSED: &str = "network_decision.refused";
/// Audit action: a stored reply profile no longer validates (design note §3.4,
/// §5.4); one row per profile per window.
pub const AUDIT_PROFILE_INVALID: &str = "reply_profile.invalid";
/// The shared-counter bucket name of the route (D-6).
pub const BUCKET: &str = "network_decide";

/// The body limit: a DER certificate in base64 is a few kilobytes.
const BODY_LIMIT: usize = 32_768;

/// The 401 a token that is not bound to its own certificate gets.
pub const CERTIFICATE_BOUND_REFUSAL: &str = "the network decision route requires a service \
    account token bound to the caller's own certificate (cnf x5t#S256), presented over mTLS \
    with that certificate";

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

/// The body of `POST /api/v1/network/decide`. Closed: an unknown key — a MAC
/// address, a user name — is a `400` naming it, so nothing the design note's
/// §8 keeps out of the audit trail can be posted into it.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkDecisionRequest {
    /// The site key, from FreeRADIUS's own client configuration
    /// (`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`). Never taken from the packet.
    pub site: String,
    /// The certificate the device presented in EAP-TLS, DER, standard base64.
    /// Exactly one of `certificate` and `fingerprint`.
    #[serde(default)]
    pub certificate: Option<String>,
    /// The SHA-256 of that certificate's DER, 64 hexadecimal digits. Exactly
    /// one of `certificate` and `fingerprint`.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// The decision: `{ "allow": false }` with **no reason**, or
/// `{ "allow": true, "reply": … }`.
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkDecisionResponse {
    /// Whether the device is placed. `false` carries nothing else, whatever
    /// the reason (T-457, T-468).
    pub allow: bool,
    /// The Access-Accept attributes of the segment the device is placed on:
    /// its tunnel triple (RFC 3580 §3.31) and its reply profile's fields, with
    /// `Session-Timeout` clamped to the tenant's cap. Only on an allow.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<RenderedReply>,
}

/// The JSON extractor of the route: a body limit and a `400` that names the
/// offending key.
pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default().limit(BODY_LIMIT).error_handler(
        |err: JsonPayloadError, _req: &HttpRequest| {
            let message = match err {
                JsonPayloadError::Deserialize(inner) => {
                    format!("the request body is not a valid decision request: {inner}")
                }
                JsonPayloadError::ContentType => {
                    "the request body must be application/json".to_string()
                }
                JsonPayloadError::Overflow { .. }
                | JsonPayloadError::OverflowKnownLength { .. } => {
                    "the request body is too large".to_string()
                }
                _ => "the request body could not be read".to_string(),
            };
            AxiamApiError(AxiamError::Validation { message }).into()
        },
    )
}

/// How the request named the certificate.
enum Presented {
    Certificate(Vec<u8>),
    Fingerprint,
}

impl Presented {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Certificate(_) => "certificate",
            Self::Fingerprint => "fingerprint",
        }
    }
}

fn invalid(message: &str) -> AxiamApiError {
    AxiamApiError(AxiamError::Validation {
        message: message.to_owned(),
    })
}

/// The body's site key, the presented certificate, and its fingerprint.
fn parse_body(body: NetworkDecisionRequest) -> Result<(String, Presented, String), AxiamApiError> {
    if !is_valid_identifier(&body.site) {
        return Err(invalid("site is not a valid site key"));
    }
    match (body.certificate, body.fingerprint) {
        (Some(b64), None) => {
            let der = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|_| invalid("certificate is not standard base64"))?;
            if der.is_empty() {
                return Err(invalid("certificate is empty"));
            }
            let fingerprint = hex::encode(Sha256::digest(&der));
            Ok((body.site, Presented::Certificate(der), fingerprint))
        }
        (None, Some(fp)) => {
            let fp = fp.trim().to_ascii_lowercase();
            if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(
                    "fingerprint must be the SHA-256 of the certificate's DER, 64 hex digits",
                ));
            }
            Ok((body.site, Presented::Fingerprint, fp))
        }
        _ => Err(invalid(
            "exactly one of certificate and fingerprint is required",
        )),
    }
}

// ---------------------------------------------------------------------------
// The caller
// ---------------------------------------------------------------------------

fn unauthenticated(reason: &str) -> AxiamApiError {
    AxiamApiError(AxiamError::AuthenticationFailed {
        reason: reason.to_owned(),
    })
}

/// A service-account caller whose token is bound to a certificate this
/// connection presented — the synchronous half of T-468's caller binding, run as
/// an extractor so that it answers before the body is read: a plain bearer
/// token is `401` whatever it posts.
///
/// The asynchronous half — that the certificate is still the caller's own and
/// valid, and the account active — is [`certificate_bound_caller`], the
/// handler's first step.
pub struct CertificateBoundServiceAccount {
    /// The authenticated machine token.
    pub account: AuthenticatedServiceAccount,
    /// The service account's id (the token's `sub`).
    pub subject: Uuid,
    /// The TLS-verified certificate the token is bound to, DER.
    pub der: Vec<u8>,
}

impl FromRequest for CertificateBoundServiceAccount {
    type Error = AxiamApiError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        let account = AuthenticatedServiceAccount::from_request(req, payload);
        let req = req.clone();
        Box::pin(async move {
            let account = account.await?;
            let claims = &account.claims.0;
            if claims.sub_kind != SubjectKind::ServiceAccount {
                return Err(unauthenticated(
                    "the network decision route is a service account's; this machine token \
                     is not one",
                ));
            }
            let subject = Uuid::parse_str(&account.subject)
                .map_err(|_| unauthenticated("invalid sub claim"))?;
            // A bearer token, or one bound only by DPoP, is not what T-468
            // asks for: the binding must be to the caller's own certificate.
            let Some(bound_to) = claims
                .cnf
                .as_ref()
                .and_then(|cnf| cnf.certificate_thumbprint())
            else {
                return Err(unauthenticated(CERTIFICATE_BOUND_REFUSAL));
            };
            // The extractor has already refused a bound token whose certificate
            // is not on this connection (`enforce_sender_constraint`); this
            // restates it here, where the rest of the rule needs the
            // certificate itself.
            let Some(verified) = req.conn_data::<VerifiedClientCert>() else {
                return Err(unauthenticated(CERTIFICATE_BOUND_REFUSAL));
            };
            verified
                .check_usable_for_device_auth()
                .map_err(AxiamApiError::from)?;
            if axiam_oauth2::mtls::thumbprint_s256(&verified.der) != bound_to {
                return Err(unauthenticated(CERTIFICATE_BOUND_REFUSAL));
            }
            let der = verified.der.clone();
            Ok(Self {
                account,
                subject,
                der,
            })
        })
    }
}

/// The asynchronous half of the caller binding: the certificate the token is
/// bound to is the caller's own **now** — revoked, expired, rebound to another
/// account or another tenant's, it stops here at the next request rather than
/// when the token expires — and the account is `Active`.
async fn certificate_bound_caller<C: Connection + Clone>(
    caller: &CertificateBoundServiceAccount,
    state: &AppState<C>,
) -> Result<Uuid, AxiamApiError> {
    let tenant_id = caller.account.tenant_id;
    let identity = state
        .pki
        .device_auth_service
        .authenticate_der(&caller.der)
        .await
        .map_err(|_| unauthenticated(CERTIFICATE_BOUND_REFUSAL))?;
    if identity.service_account_id != caller.subject || identity.tenant_id != tenant_id {
        return Err(unauthenticated(CERTIFICATE_BOUND_REFUSAL));
    }
    let account = state
        .service_account_repo
        .get_by_id(tenant_id, caller.subject)
        .await
        .map_err(|_| unauthenticated("the calling service account is not active"))?;
    if account.status != UserStatus::Active {
        return Err(unauthenticated("the calling service account is not active"));
    }
    Ok(caller.subject)
}

/// Spend one decision of the caller's bucket (D-6): the shared counter when it
/// is on, the in-process keyed limiter when it is off.
fn admit<C: Connection + Clone>(state: &AppState<C>, tenant_id: Uuid, caller: Uuid) -> bool {
    let per_min = state.rate_limit_cfg.network_decide_per_min;
    if state.shared_rate_limit.is_enabled() {
        state
            .shared_rate_limit
            .check_at(&bucket_key(tenant_id, caller), Utc::now(), per_min)
    } else {
        state.network_decide.admit(tenant_id, caller, per_min)
    }
}

/// The caller's bucket in the shared counter.
pub fn bucket_key(tenant_id: Uuid, caller: Uuid) -> String {
    format!("{BUCKET}:{tenant_id}:{caller}")
}

fn too_many_requests() -> HttpResponse {
    HttpResponse::TooManyRequests()
        .content_type(actix_web::http::header::ContentType::json())
        .insert_header((actix_web::http::header::RETRY_AFTER, "60"))
        .body(r#"{"error":"rate_limit_exceeded"}"#)
}

// ---------------------------------------------------------------------------
// The certificate
// ---------------------------------------------------------------------------

/// What the presented certificate resolved to.
enum Resolved {
    /// A certificate of the caller's tenant, bound to `service_account_id`.
    Device {
        service_account_id: Uuid,
        certificate_id: Uuid,
    },
    /// Refused, with the internal reason. `certificate_id` is set only for a
    /// certificate of the caller's tenant.
    Refused {
        reason: &'static str,
        certificate_id: Option<Uuid>,
    },
}

/// The one certificate a decision verifies.
#[derive(Debug, PartialEq, Eq)]
enum VerificationTarget<'a> {
    /// A certificate of the caller's tenant: the DER presented, or — for the
    /// fingerprint form — the row's own.
    Presented(std::borrow::Cow<'a, [u8]>),
    /// No row of the caller's tenant — unknown anywhere, or another tenant's:
    /// the caller's own certificate, verified as a decoy and the result
    /// discarded, so the refusal pays the full verification a certificate of
    /// this tenant pays (T-457, #706).
    Decoy(&'a [u8]),
    /// A row of the caller's tenant whose stored PEM does not parse.
    Nothing,
}

/// Which certificate `resolve_certificate` verifies. Every path but a stored
/// PEM that does not parse verifies exactly one, and which one depends on the
/// caller's own tenant alone: whether a fingerprint is registered in another
/// tenant, and in what state, never decides whether a verification runs.
fn verification_target<'a>(
    presented: &'a Presented,
    row: Option<&Certificate>,
    tenant_id: Uuid,
    caller_der: &'a [u8],
) -> VerificationTarget<'a> {
    match (presented, row.filter(|r| r.tenant_id == tenant_id)) {
        (_, None) => VerificationTarget::Decoy(caller_der),
        (Presented::Certificate(der), Some(_)) => VerificationTarget::Presented(der.into()),
        (Presented::Fingerprint, Some(row)) => match pem_to_der(&row.public_cert_pem) {
            Some(der) => VerificationTarget::Presented(der.into()),
            None => VerificationTarget::Nothing,
        },
    }
}

/// Resolve the presented certificate through `authenticate_der`, refusing one
/// of another tenant (§7). The row is read first, by fingerprint, for two
/// reasons: the fingerprint form has no DER without it, and a refusal of this
/// tenant's certificate can then be named from the row (revoked, expired)
/// rather than from the wording of an error message. When no row of this
/// tenant resolves, the caller's own certificate is verified instead and the
/// result discarded ([`VerificationTarget::Decoy`]).
async fn resolve_certificate<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    presented: &Presented,
    fingerprint: &str,
    caller_der: &[u8],
) -> Result<Resolved, AxiamApiError> {
    let row: Option<Certificate> = match state
        .pki
        .cert_repo
        .get_by_fingerprint_global(fingerprint)
        .await
    {
        Ok(row) => Some(row),
        Err(AxiamError::NotFound { .. }) => None,
        Err(e) => return Err(e.into()),
    };
    let device_auth = &state.pki.device_auth_service;
    let authenticated = match verification_target(presented, row.as_ref(), tenant_id, caller_der) {
        VerificationTarget::Presented(der) => match device_auth.authenticate_der(&der).await {
            Ok(identity) => Some(identity),
            Err(AxiamError::Certificate(_) | AxiamError::NotFound { .. }) => None,
            Err(e) => return Err(e.into()),
        },
        VerificationTarget::Decoy(der) => {
            // Discarded whole, an error included: the decoy never changes the
            // answer, the row or the status (the precedent is
            // `equalising_dummy_verify`).
            let _ = device_auth.authenticate_der(der).await;
            None
        }
        VerificationTarget::Nothing => None,
    };

    let Some(row) = row.filter(|r| r.tenant_id == tenant_id) else {
        // Unknown anywhere, or another tenant's: one reason, so the caller's
        // tenant does not learn that the certificate exists elsewhere.
        return Ok(Resolved::Refused {
            reason: "certificate:not_in_tenant",
            certificate_id: None,
        });
    };
    match authenticated {
        Some(identity) if identity.tenant_id == tenant_id && identity.certificate_id == row.id => {
            Ok(Resolved::Device {
                service_account_id: identity.service_account_id,
                certificate_id: row.id,
            })
        }
        _ => {
            let now = Utc::now();
            let reason = if row.status == CertificateStatus::Revoked {
                "certificate:revoked"
            } else if row.status != CertificateStatus::Active
                || now < row.not_before
                || now > row.not_after
            {
                "certificate:expired"
            } else {
                // Unbound, not a client certificate type, or its chain does
                // not reach a trusted anchor.
                "certificate:refused"
            };
            Ok(Resolved::Refused {
                reason,
                certificate_id: Some(row.id),
            })
        }
    }
}

fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .ok()
        .map(|(_, p)| p.contents)
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

async fn append<C: Connection + Clone>(state: &AppState<C>, entry: CreateAuditLogEntry) {
    let (tenant_id, action) = (entry.tenant_id, entry.action.clone());
    if let Err(error) = state.audit_repo.append(entry).await {
        tracing::error!(
            target: "axiam::network_decide",
            %tenant_id,
            action,
            %error,
            "a network decision audit row could not be written"
        );
    }
}

/// One `reply_profile.invalid` row per profile per window (§3.4).
async fn audit_defect<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &HttpRequest,
    tenant_id: Uuid,
    caller: Uuid,
    segment: &NetworkSegment,
    version: u64,
    dictionary: &str,
    defect: &ProfileDefect,
) {
    if !state
        .network_decide
        .first_in_window(tenant_id, segment.id, version, defect.rule)
    {
        return;
    }
    append(
        state,
        CreateAuditLogEntry {
            tenant_id,
            actor_id: caller,
            actor_type: ActorType::ServiceAccount,
            action: AUDIT_PROFILE_INVALID.to_owned(),
            resource_id: Some(segment.id),
            outcome: AuditOutcome::Failure,
            ip_address: client_ip(http_req),
            metadata: Some(json!({
                "segment_id": segment.id,
                "path": segment.path(),
                "profile_version": version,
                "dictionary": dictionary,
                "rule": defect.rule,
                "reason": defect.reason,
                "window_secs": crate::network_decide_guard::INVALID_PROFILE_AUDIT_WINDOW.as_secs(),
            })),
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// The route
// ---------------------------------------------------------------------------

/// `POST /api/v1/network/decide`
///
/// The RADIUS placement decision FreeRADIUS asks for once per EAP-TLS
/// authentication (RADIUS Live profile). Not SDK surface: its caller is FreeRADIUS's
/// service account, over mTLS with a token bound to its own certificate.
#[utoipa::path(
    post,
    operation_id = "network_decide",
    path = "/api/v1/network/decide",
    tag = "network",
    request_body = NetworkDecisionRequest,
    responses(
        (status = 200, description = "The decision. `{\"allow\": false}` carries no reason, \
                                      whatever it was; `{\"allow\": true, \"reply\": …}` carries \
                                      the placed segment's tunnel attributes and its reply \
                                      profile's, `Session-Timeout` clamped to the tenant's cap. \
                                      `Tunnel-Type` and `Tunnel-Medium-Type` carry tag 0 on the \
                                      wire; `Tunnel-Private-Group-Id` carries no tag octet",
         body = NetworkDecisionResponse),
        (status = 400, description = "The body: an unknown key (named), a site key outside the \
                                      pattern, not exactly one of `certificate` and \
                                      `fingerprint`, or one that does not decode"),
        (status = 401, description = "Not a service account, or its token is not bound \
                                      (`cnf.x5t#S256`) to the certificate this mTLS connection \
                                      presented, or that certificate is no longer the caller's \
                                      own and valid, or the account is not active"),
        (status = 403, description = "The caller lacks `network:decide` on the site"),
        (status = 429, description = "The caller's `network_decide_per_min` allowance is spent"),
    ),
    security(("service_account" = []))
)]
pub async fn decide<C: Connection + Clone>(
    http_req: HttpRequest,
    caller: CertificateBoundServiceAccount,
    authz: AuthzData,
    state: web::Data<AppState<C>>,
    body: web::Json<NetworkDecisionRequest>,
) -> Result<HttpResponse, AxiamApiError> {
    // The bucket is the caller's own (D-6), spent as soon as the token is known
    // to be its — signed by AXIAM, and bound to the certificate whose key this
    // connection proved — and before anything is read for it.
    let tenant_id = caller.account.tenant_id;
    if !admit(&state, tenant_id, caller.subject) {
        return Ok(too_many_requests());
    }
    let caller_id = certificate_bound_caller(&caller, &state).await?;
    let (site, presented, fingerprint) = parse_body(body.into_inner())?;
    let authz = authz.get_ref().as_ref();

    // The site: every segment of it, both branches, one query.
    let segments = SurrealNetworkSegmentRepository::new(state.db.clone())
        .list_site(tenant_id, &site)
        .await?;

    // The caller holds `network:decide` on every site node the decision reads
    // (a site with no segment yet: on its `zones` node).
    let mut site_nodes: BTreeSet<Uuid> = segments
        .iter()
        .map(|s| site_node_id(tenant_id, s.kind, &site))
        .collect();
    if site_nodes.is_empty() {
        site_nodes.insert(site_node_id(tenant_id, NetworkSegmentKind::Access, &site));
    }
    let site_nodes: Vec<Uuid> = site_nodes.into_iter().collect();
    let decide_checks: Vec<AccessRequest> = site_nodes
        .iter()
        .map(|node| AccessRequest {
            tenant_id,
            subject_scope: SubjectScope::Tenant,
            subject_id: caller_id,
            action: NETWORK_DECIDE.to_owned(),
            resource_id: *node,
            scope: None,
        })
        .collect();
    let answers = authz.check_access_batch(&decide_checks).await?;
    if let Some((node, decision)) = site_nodes
        .iter()
        .zip(&answers)
        .find(|(_, d)| !matches!(d, AccessDecision::Allow))
    {
        let reason = match decision {
            AccessDecision::Deny(r) | AccessDecision::DeniedByRule(r) => r.clone(),
            AccessDecision::Allow => String::new(),
        };
        append(
            &state,
            CreateAuditLogEntry {
                tenant_id,
                actor_id: caller_id,
                actor_type: ActorType::ServiceAccount,
                action: AUDIT_DECISION_REFUSED.to_owned(),
                resource_id: Some(*node),
                outcome: AuditOutcome::Denied,
                ip_address: client_ip(&http_req),
                metadata: Some(json!({
                    "site": site,
                    "rule": "4.2:decide",
                    "missing_permission": NETWORK_DECIDE,
                    "node": node,
                    "reason": reason,
                    "status": 403,
                })),
            },
        )
        .await;
        return Err(AxiamApiError(AxiamError::AuthorizationDenied {
            reason,
            action: Some(NETWORK_DECIDE.to_owned()),
            resource_id: Some(node.to_string()),
        }));
    }

    // 1. The certificate, then 2. the subject's account. When no certificate
    // of this tenant resolved, the caller's own account stands in as the
    // subject: an account that exists and holds role assignments, so the reads
    // and the batch below cost what a real device's do. Its answers are
    // discarded.
    let resolved =
        resolve_certificate(&state, tenant_id, &presented, &fingerprint, &caller.der).await?;
    let (subject, device) = match &resolved {
        Resolved::Device {
            service_account_id, ..
        } => (*service_account_id, true),
        Resolved::Refused { .. } => (caller_id, false),
    };
    let account_active = match state
        .service_account_repo
        .get_by_id(tenant_id, subject)
        .await
    {
        Ok(account) => account.status == UserStatus::Active,
        Err(AxiamError::NotFound { .. }) => false,
        Err(e) => return Err(e.into()),
    };

    // 3. The profiles and the cap, each one query, every profile re-validated.
    let segment_ids: Vec<Uuid> = segments.iter().map(|s| s.id).collect();
    let stored = SurrealReplyProfileRepository::new(state.db.clone())
        .list_stored(tenant_id, &segment_ids)
        .await?;
    let cap = SurrealNetworkPolicyRepository::new(state.db.clone())
        .get(tenant_id)
        .await?
        .session_timeout_max_secs;
    let mut rendered: Vec<Option<(RenderedReply, Value)>> = Vec::with_capacity(segments.len());
    for segment in &segments {
        let Some(profile) = stored.iter().find(|p| p.segment_id == segment.id) else {
            // No profile: no candidate, which only narrows (§5.2).
            rendered.push(None);
            continue;
        };
        match profile.revalidate(segment, cap) {
            Ok((effective, reply)) => rendered.push(Some((
                reply,
                json!({
                    "profile_version": profile.version,
                    "session_timeout_secs": effective.session_timeout_secs,
                    "session_timeout_clamped": effective.session_timeout_clamped,
                }),
            ))),
            Err(defect) => {
                audit_defect(
                    &state,
                    &http_req,
                    tenant_id,
                    caller_id,
                    segment,
                    profile.version,
                    &profile.dictionary,
                    &defect,
                )
                .await;
                rendered.push(None);
            }
        }
    }

    // 4. One batch of `network:join`, over every enabled segment of the site,
    // through the decision cache, deny-override in force.
    let enabled: Vec<usize> = (0..segments.len())
        .filter(|i| segments[*i].enabled)
        .collect();
    let join_checks: Vec<AccessRequest> = enabled
        .iter()
        .map(|i| AccessRequest {
            tenant_id,
            subject_scope: SubjectScope::Tenant,
            subject_id: subject,
            action: NETWORK_JOIN.to_owned(),
            resource_id: segments[*i].id,
            scope: None,
        })
        .collect();
    let join_answers = authz.check_access_batch(&join_checks).await?;
    let mut joinable = vec![false; segments.len()];
    for (i, answer) in enabled.iter().zip(&join_answers) {
        joinable[*i] = matches!(answer, AccessDecision::Allow);
    }
    let usable: Vec<bool> = rendered.iter().map(Option::is_some).collect();

    // 5. The placement — counted only for a device of this tenant whose
    // account may act.
    let placed = select_placement(&segments, &joinable, &usable);
    let placement = placed
        .filter(|_| device && account_active)
        .and_then(|i| rendered[i].take().map(|r| (i, r)));

    // 6. One row, and the answer.
    let mut metadata = json!({
        "site": site,
        "presented": presented.as_str(),
        "certificate_fingerprint": fingerprint,
        "method": "eap_tls",
        "transport": "rlm_rest",
        "candidates": segments.len(),
    });
    if let Resolved::Device {
        service_account_id,
        certificate_id,
    } = &resolved
    {
        metadata["subject_id"] = json!(service_account_id);
        metadata["certificate_id"] = json!(certificate_id);
    }
    if let Resolved::Refused {
        certificate_id: Some(id),
        ..
    } = &resolved
    {
        metadata["certificate_id"] = json!(id);
    }
    let response = match placement {
        Some((i, (reply, values))) => {
            let segment = &segments[i];
            metadata["reason"] = json!(match segment.kind {
                NetworkSegmentKind::Access => "placement:access",
                NetworkSegmentKind::Quarantine => "placement:quarantine",
            });
            metadata["segment_id"] = json!(segment.id);
            metadata["segment_kind"] = json!(segment.kind.as_str());
            metadata["vlan_id"] = json!(segment.vlan_id);
            if let Value::Object(extra) = values {
                for (k, v) in extra {
                    metadata[k] = v;
                }
            }
            append(
                &state,
                CreateAuditLogEntry {
                    tenant_id,
                    actor_id: caller_id,
                    actor_type: ActorType::ServiceAccount,
                    action: AUDIT_DECISION_ALLOWED.to_owned(),
                    resource_id: Some(segment.id),
                    outcome: AuditOutcome::Success,
                    ip_address: client_ip(&http_req),
                    metadata: Some(metadata),
                },
            )
            .await;
            NetworkDecisionResponse {
                allow: true,
                reply: Some(reply),
            }
        }
        None => {
            let reason = match &resolved {
                Resolved::Refused { reason, .. } => *reason,
                Resolved::Device { .. } if !account_active => "account:inactive",
                Resolved::Device { .. } => "placement:no_candidate",
            };
            metadata["reason"] = json!(reason);
            append(
                &state,
                CreateAuditLogEntry {
                    tenant_id,
                    actor_id: caller_id,
                    actor_type: ActorType::ServiceAccount,
                    action: AUDIT_DECISION_DENIED.to_owned(),
                    resource_id: None,
                    outcome: AuditOutcome::Denied,
                    ip_address: client_ip(&http_req),
                    metadata: Some(metadata),
                },
            )
            .await;
            NetworkDecisionResponse {
                allow: false,
                reply: None,
            }
        }
    };
    Ok(HttpResponse::Ok().json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::certificate::{CertificateType, KeyAlgorithm};

    const CALLER: &[u8] = b"the caller's own certificate";
    const PRESENTED: &[u8] = b"the device's certificate";
    // The envelope alone: `pem_to_der` reads the base64, not the X.509 inside.
    const ROW_PEM: &str = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";

    fn row(tenant_id: Uuid, pem: &str) -> Certificate {
        Certificate {
            id: Uuid::new_v4(),
            tenant_id,
            issuer_ca_id: Uuid::new_v4(),
            subject: "device-001".into(),
            public_cert_pem: pem.into(),
            fingerprint: "00".repeat(32),
            cert_type: CertificateType::Device,
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now(),
            not_after: Utc::now(),
            status: CertificateStatus::Active,
            metadata: Value::Null,
            user_id: None,
            created_at: Utc::now(),
        }
    }

    /// The structural half of T-457 for the verification (#706): every path
    /// verifies exactly one certificate, and every refusal before a row of this
    /// tenant — an unknown certificate or fingerprint, another tenant's —
    /// verifies the caller's own, whatever the other tenant holds.
    #[test]
    fn every_path_verifies_one_certificate_and_every_refusal_the_callers() {
        let tenant = Uuid::new_v4();
        let mine = row(tenant, ROW_PEM);
        let theirs = row(Uuid::new_v4(), ROW_PEM);
        let unparsable = row(tenant, "not a PEM");
        let by_der = Presented::Certificate(PRESENTED.to_vec());
        let by_fingerprint = Presented::Fingerprint;
        let cases: [(&str, &Presented, Option<&Certificate>, VerificationTarget); 7] = [
            (
                "unknown certificate",
                &by_der,
                None,
                VerificationTarget::Decoy(CALLER),
            ),
            (
                "another tenant's certificate",
                &by_der,
                Some(&theirs),
                VerificationTarget::Decoy(CALLER),
            ),
            (
                "this tenant's certificate",
                &by_der,
                Some(&mine),
                VerificationTarget::Presented(PRESENTED.into()),
            ),
            (
                "unknown fingerprint",
                &by_fingerprint,
                None,
                VerificationTarget::Decoy(CALLER),
            ),
            (
                "another tenant's fingerprint",
                &by_fingerprint,
                Some(&theirs),
                VerificationTarget::Decoy(CALLER),
            ),
            (
                "this tenant's fingerprint",
                &by_fingerprint,
                Some(&mine),
                VerificationTarget::Presented(vec![1, 2, 3].into()),
            ),
            (
                "this tenant's row, PEM unparsable",
                &by_fingerprint,
                Some(&unparsable),
                VerificationTarget::Nothing,
            ),
        ];
        for (name, presented, row, expected) in cases {
            assert_eq!(
                verification_target(presented, row, tenant, CALLER),
                expected,
                "{name}"
            );
        }
    }
}

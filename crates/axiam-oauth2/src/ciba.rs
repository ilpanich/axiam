//! OpenID Connect Client-Initiated Backchannel Authentication — G-7.
//!
//! CIBA Core 1.0, poll and ping modes. This module owns everything about the
//! grant that is not the token endpoint's issuance (that is
//! `TokenService::exchange_ciba`, beside the other grants, so the CIBA grant
//! cannot mint differently from them):
//!
//! * what a CIBA **client registration** must say ([`validate_client_registration`]),
//! * what a `POST /oauth2/bc-authorize` **request** may carry and how its hint
//!   resolves to a user ([`CibaService::initiate`]),
//! * the **approval service API** the identity pages call
//!   ([`CibaService::lookup_for_approval`], [`CibaService::approve`],
//!   [`CibaService::deny`]),
//! * the **poll back-off** ([`poll_backoff`]).
//!
//! # What AXIAM requires of a CIBA client (D-61)
//!
//! | requirement | why |
//! |---|---|
//! | a confidential client (any method but `none`) | CIBA Core §7.1: the client authenticates at `bc-authorize` exactly as at the token endpoint |
//! | `backchannel_token_delivery_mode` = `poll` or `ping` | §4; `push` is not offered (FAPI-CIBA forbids it) |
//! | ping ⇒ an `https` notification endpoint under the webhook URL policy | §4; the endpoint is an outbound target |
//! | `backchannel_authentication_request_signing_alg`, if registered, is `PS256`, `ES256` or `EdDSA`, with exactly one key source (`jwks` or `jwks_uri`) and, inline, a key of that algorithm | §7.1.1; the three algorithms AXIAM verifies on any client-signed JWT |
//! | a registered signing algorithm ⇒ **every** request is a signed `request` JWT under it; no algorithm ⇒ a `request` is refused | §4 "when omitted, the Client will not send signed authentication requests"; a registered switch that accepted unsigned requests anyway would be the SEC-097 shape |
//! | `fapi2` ⇒ the signing algorithm is registered | FAPI-CIBA §5.2.2: signed authentication requests are required |
//! | `fapi2` ⇒ `tls_client_auth`, `self_signed_tls_client_auth` or `private_key_jwt`, and sender-constrained tokens | the `fapi2` profile's own rules (`fapi::validate_registration`), which already apply to every grant a `fapi2` client holds |
//! | no `backchannel_user_code_parameter` | AXIAM has no per-user secret to check a user code against that is not the password |
//!
//! At request time a `fapi2` client must also send a `binding_message`
//! (FAPI-CIBA §5.2.2: a unique authorization context, which AXIAM has no other
//! carrier for) and, in ping mode, a `client_notification_token` of at least
//! [`MIN_FAPI_NOTIFICATION_TOKEN_BYTES`] characters.
//!
//! Sender-constraining follows the client's registration exactly as for every
//! other grant (`certificate_binding_for`, and `fapi::enforce_token_request` at
//! the token endpoint), and a row edited in the datastore past these gates
//! still meets D-17's request-time rule and the signed-request rule at
//! `bc-authorize`. Signed requests themselves are
//! [`crate::ciba_signed_request`].
//!
//! # Not a user oracle (D-63)
//!
//! A hint that names nobody, names a user who may not sign in, or names a user
//! under brute-force lockout is answered **exactly like a real one**: a stored
//! request, an `auth_req_id`, `expires_in` and `interval`. Such a request has
//! no user, nobody is notified, nothing can approve it, and the client polls
//! `authorization_pending` until `expired_token`. `unknown_user_id` is never
//! sent: answering it would let any registered CIBA client enumerate the
//! tenant's usernames and e-mail addresses at the endpoint's rate limit.
//!
//! The per-(client, hint) cap (#599, T-424, [`DEFAULT_REQUESTS_PER_CLIENT_HINT`])
//! keeps to this. It counts the client's `bc-authorize` calls for the hint as
//! the request carried it — a `login_hint` as sent, a verified
//! `id_token_hint`'s subject — in a shared counter, before the hint is looked
//! up, so a hint that names nobody is refused at exactly the call a real
//! user's would be. (From 2026-10-13 until its correction the same day the cap
//! counted the resolved user's open requests, and a request for nobody was
//! never refused: the fourth call told the client whether the hint named a
//! user who may sign in.)

use axiam_core::models::ciba::{
    CIBA_GRANT_TYPE, CibaApprovalEvidence, CibaClientMetadata, CibaDeliveryMode,
    CibaPingCredentials, CibaRequest, CibaRequestSigningAlg, CibaRequestStatus,
    CibaUserNotification, CreateCibaRequest,
};
use axiam_core::models::oauth2_client::{ClientAuthMethod, ClientProfile, OAuth2Client};
use axiam_core::models::session::Amr;
use axiam_core::models::user::User;
use axiam_core::repository::{CibaRequestRepository, UserRepository};
use axiam_db::helpers::retry_on_write_conflict;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::acr::{Acr, acr_for};
use crate::error::OAuth2Error;

pub use axiam_core::models::ciba::CIBA_GRANT_TYPE as GRANT_TYPE;

/// Default lifetime of a request when the client names none (`expires_in`).
pub const DEFAULT_EXPIRES_IN_SECS: u64 = 300;

/// The bounds a `requested_expiry` must fall within.
///
/// Ten minutes at most, which is the device grant's lifetime: a request is a
/// push notification on a user's phone, and one that waits longer than that is
/// an invitation to approve something the user no longer remembers starting.
pub const MIN_REQUESTED_EXPIRY_SECS: u64 = 30;
/// See [`MIN_REQUESTED_EXPIRY_SECS`].
pub const MAX_REQUESTED_EXPIRY_SECS: u64 = 600;

/// Minimum seconds between token requests (`interval`); CIBA Core §7.3's
/// default.
pub const DEFAULT_INTERVAL_SECS: u64 = 5;

/// How much each `slow_down` raises the interval — RFC 8628 §3.5's step, which
/// CIBA Core §11 adopts.
pub const SLOW_DOWN_STEP_SECS: u64 = 5;

/// Ceiling on the interval `slow_down` may raise a request to (the device
/// grant's ceiling, for the same reason: past it, "slow down" would silently
/// become "never succeed").
pub const MAX_INTERVAL_SECS: u64 = 60;

/// Longest `binding_message`, in characters. CIBA Core §7.1 asks for one
/// "relatively short" enough to show on both devices; FAPI-CIBA clients send a
/// handful of characters.
pub const MAX_BINDING_MESSAGE_CHARS: usize = 64;

/// Longest `client_notification_token`, in bytes (CIBA Core §7.1 suggests
/// 1024 as the minimum an OP accepts).
pub const MAX_NOTIFICATION_TOKEN_BYTES: usize = 1024;

/// Shortest `client_notification_token` a `fapi2` client may send, in bytes.
///
/// The token is the bearer credential AXIAM presents at the client's
/// notification endpoint, so a guessable one lets anybody forge a ping. The
/// authorization server cannot measure entropy; it can refuse a token too
/// short to carry 128 bits in base64url, which is the floor FAPI-CIBA's
/// security considerations ask of it. A `standard` client keeps CIBA Core's
/// rule (any non-empty token).
pub const MIN_FAPI_NOTIFICATION_TOKEN_BYTES: usize = 22;

/// Longest `login_hint`, in bytes.
pub const MAX_LOGIN_HINT_BYTES: usize = 256;

/// How many `acr_values` a request may name, and how long each may be.
pub const MAX_ACR_VALUES: usize = 8;
/// See [`MAX_ACR_VALUES`].
pub const MAX_ACR_VALUE_BYTES: usize = 128;

/// How long an expired request is kept before the sweep deletes it, so that a
/// client still polling is told `expired_token` rather than `invalid_grant`.
pub const EXPIRED_RETENTION_SECS: i64 = 600;

/// Generate an `auth_req_id`: 256 bits of CSPRNG, base64url, unpadded — the
/// device code's shape (CIBA Core §7.3 asks for at least 128 bits).
#[must_use]
pub fn generate_auth_req_id() -> String {
    crate::device::generate_device_code()
}

/// SHA-256 of an `auth_req_id`, hex — what is stored and looked up.
#[must_use]
pub fn hash_auth_req_id(raw: &str) -> String {
    crate::device::hash_device_code(raw)
}

/// Whether a client is registered for the CIBA grant.
#[must_use]
pub fn holds_ciba_grant(grant_types: &[String]) -> bool {
    grant_types.iter().any(|g| g.trim() == CIBA_GRANT_TYPE)
}

// ---------------------------------------------------------------------------
// Client registration
// ---------------------------------------------------------------------------

/// Why a CIBA registration is refused. One variant per rule in the module
/// documentation's table, so a test asserts which rule fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibaRegistrationError {
    /// The client holds the grant but registered no delivery mode.
    DeliveryModeRequired,
    /// A delivery mode other than `poll` or `ping` (including `push`).
    UnsupportedDeliveryMode {
        /// What was asked for.
        mode: String,
    },
    /// Ping mode without a notification endpoint.
    NotificationEndpointRequired,
    /// A notification endpoint outside ping mode.
    NotificationEndpointWithoutPing,
    /// The notification endpoint fails the outbound URL policy.
    InvalidNotificationEndpoint {
        /// The policy rule that failed — never the URL.
        reason: String,
    },
    /// CIBA metadata on a client that does not hold the grant.
    MetadataWithoutGrant,
    /// A public client asked for the grant.
    PublicClient,
    /// `backchannel_authentication_request_signing_alg` names an algorithm
    /// AXIAM does not verify.
    UnsupportedSigningAlg {
        /// What was asked for.
        alg: String,
    },
    /// A `fapi2` client asked for the grant without registering a signing
    /// algorithm (FAPI-CIBA requires signed authentication requests).
    FapiRequiresSignedRequests,
    /// A signing algorithm without exactly one key source.
    SigningKeysRequired {
        /// How many of `jwks` and `jwks_uri` were registered.
        registered: usize,
    },
    /// An inline `jwks` holding no key of the registered algorithm.
    NoKeyForSigningAlg {
        /// The registered algorithm.
        alg: &'static str,
    },
    /// `backchannel_user_code_parameter: true` was registered.
    UserCodeUnsupported,
}

impl std::fmt::Display for CibaRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DeliveryModeRequired => write!(
                f,
                "a client holding the {CIBA_GRANT_TYPE} grant must register \
                 backchannel_token_delivery_mode (poll or ping)"
            ),
            Self::UnsupportedDeliveryMode { mode } => write!(
                f,
                "backchannel_token_delivery_mode {mode:?} is not supported: AXIAM offers poll and \
                 ping (push is not offered)"
            ),
            Self::NotificationEndpointRequired => write!(
                f,
                "ping mode requires backchannel_client_notification_endpoint"
            ),
            Self::NotificationEndpointWithoutPing => write!(
                f,
                "backchannel_client_notification_endpoint is used only in ping mode; remove it or \
                 register ping"
            ),
            Self::InvalidNotificationEndpoint { reason } => {
                write!(f, "backchannel_client_notification_endpoint: {reason}")
            }
            Self::MetadataWithoutGrant => write!(
                f,
                "backchannel_* metadata requires the {CIBA_GRANT_TYPE} grant in grant_types"
            ),
            Self::PublicClient => write!(
                f,
                "the CIBA grant requires a confidential client: a client registered with \
                 token_endpoint_auth_method none cannot authenticate at the backchannel \
                 authentication endpoint"
            ),
            Self::UnsupportedSigningAlg { alg } => write!(
                f,
                "backchannel_authentication_request_signing_alg {alg:?} is not supported: this \
                 server verifies PS256, ES256 and EdDSA"
            ),
            Self::FapiRequiresSignedRequests => write!(
                f,
                "a fapi2 client holding the CIBA grant must register \
                 backchannel_authentication_request_signing_alg: the FAPI-CIBA profile requires \
                 signed authentication requests"
            ),
            Self::SigningKeysRequired { registered } => write!(
                f,
                "backchannel_authentication_request_signing_alg requires exactly one of jwks and \
                 jwks_uri, to verify the signed requests against (registered: {registered})"
            ),
            Self::NoKeyForSigningAlg { alg } => write!(
                f,
                "the registered jwks holds no {alg} key, so no request signed with \
                 backchannel_authentication_request_signing_alg {alg} could be verified"
            ),
            Self::UserCodeUnsupported => write!(
                f,
                "backchannel_user_code_parameter is not supported: this server holds no user code \
                 to verify"
            ),
        }
    }
}

impl std::error::Error for CibaRegistrationError {}

/// What a registration said about CIBA, borrowed from whichever input carries
/// it (the admin API, RFC 7591, a merged update).
#[derive(Debug, Clone, Copy)]
pub struct CibaRegistrationView<'a> {
    /// The registered grants.
    pub grant_types: &'a [String],
    /// The registered client-authentication method.
    pub token_endpoint_auth_method: ClientAuthMethod,
    /// The registered profile.
    pub profile: ClientProfile,
    /// The delivery mode as sent — a string, so `push` and typos are named in
    /// the refusal rather than lost in deserialization.
    pub delivery_mode: Option<&'a str>,
    /// The notification endpoint as sent.
    pub notification_endpoint: Option<&'a str>,
    /// `backchannel_authentication_request_signing_alg` as sent.
    pub signing_alg: Option<&'a str>,
    /// `backchannel_user_code_parameter` as sent.
    pub user_code_parameter: Option<bool>,
    /// The registered inline `jwks`, as the row will hold it.
    pub jwks: Option<&'a str>,
    /// The registered `jwks_uri`, as the row will hold it.
    pub jwks_uri: Option<&'a str>,
}

/// Validate a registration's CIBA metadata and resolve what is stored.
///
/// Runs for every registration, CIBA or not: stray `backchannel_*` metadata on
/// a client without the grant is refused rather than stored unread.
///
/// # Errors
///
/// The rule that failed.
pub fn validate_client_registration(
    reg: CibaRegistrationView<'_>,
) -> Result<CibaClientMetadata, CibaRegistrationError> {
    fn blank(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|s| !s.is_empty())
    }
    let mode_raw = blank(reg.delivery_mode);
    let endpoint = blank(reg.notification_endpoint);

    // The member AXIAM does not implement, first: whatever else the
    // registration says, it asked for something it will not get.
    if reg.user_code_parameter == Some(true) {
        return Err(CibaRegistrationError::UserCodeUnsupported);
    }
    let signing_alg = match blank(reg.signing_alg) {
        None => None,
        Some(raw) => Some(CibaRequestSigningAlg::from_wire(raw).ok_or_else(|| {
            CibaRegistrationError::UnsupportedSigningAlg {
                alg: raw.to_owned(),
            }
        })?),
    };

    if !holds_ciba_grant(reg.grant_types) {
        if mode_raw.is_some() || endpoint.is_some() || signing_alg.is_some() {
            return Err(CibaRegistrationError::MetadataWithoutGrant);
        }
        return Ok(CibaClientMetadata::default());
    }

    if reg.token_endpoint_auth_method.is_public() {
        return Err(CibaRegistrationError::PublicClient);
    }
    // FAPI-CIBA §5.2.2. The profile's client-authentication and
    // sender-constraining rules are `fapi::validate_registration`'s, which
    // every registration path runs as well: one statement of them.
    if reg.profile.is_fapi2() && signing_alg.is_none() {
        return Err(CibaRegistrationError::FapiRequiresSignedRequests);
    }
    if let Some(alg) = signing_alg {
        let inline = blank(reg.jwks);
        let sources = usize::from(inline.is_some()) + usize::from(blank(reg.jwks_uri).is_some());
        if sources != 1 {
            return Err(CibaRegistrationError::SigningKeysRequired {
                registered: sources,
            });
        }
        // An inline set is checked now; a `jwks_uri` can only be checked when
        // it is fetched, and a request whose key cannot be found is refused
        // then. An unparseable inline set is reported by
        // `fapi::validate_registration` with the parser's detail; here it
        // simply holds no usable key.
        if let Some(raw) = inline {
            let usable = serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(raw)
                .is_ok_and(|set| crate::ciba_signed_request::key_set_supports(&set, alg));
            if !usable {
                return Err(CibaRegistrationError::NoKeyForSigningAlg { alg: alg.as_str() });
            }
        }
    }
    let Some(mode_raw) = mode_raw else {
        return Err(CibaRegistrationError::DeliveryModeRequired);
    };
    let mode = CibaDeliveryMode::from_wire(mode_raw).ok_or_else(|| {
        CibaRegistrationError::UnsupportedDeliveryMode {
            mode: mode_raw.to_owned(),
        }
    })?;
    let endpoint = match (mode, endpoint) {
        (CibaDeliveryMode::Ping, None) => {
            return Err(CibaRegistrationError::NotificationEndpointRequired);
        }
        (CibaDeliveryMode::Poll, Some(_)) => {
            return Err(CibaRegistrationError::NotificationEndpointWithoutPing);
        }
        (CibaDeliveryMode::Poll, None) => None,
        (CibaDeliveryMode::Ping, Some(raw)) => {
            // The webhook write-time policy (D-49); the delivery-time guard is
            // the deliverer's, through `guarded_fetch_no_redirect`.
            crate::ssf::validate_push_endpoint(raw).map_err(|reason| {
                CibaRegistrationError::InvalidNotificationEndpoint {
                    reason: reason.replace("endpoint_url", "the endpoint"),
                }
            })?;
            Some(raw.to_owned())
        }
    };
    Ok(CibaClientMetadata {
        backchannel_token_delivery_mode: Some(mode),
        backchannel_client_notification_endpoint: endpoint,
        backchannel_authentication_request_signing_alg: signing_alg,
    })
}

// ---------------------------------------------------------------------------
// The backchannel authentication request
// ---------------------------------------------------------------------------

/// `POST /oauth2/bc-authorize` (CIBA Core §7.1), form-encoded.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct BackchannelAuthenticationRequest {
    /// The client, unless it authenticates with HTTP Basic or an assertion
    /// that names it.
    pub client_id: Option<String>,
    /// `client_secret_post` credential.
    pub client_secret: Option<String>,
    /// `private_key_jwt` credential.
    pub client_assertion: Option<String>,
    /// Must be `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`.
    pub client_assertion_type: Option<String>,
    /// Space-delimited; must include `openid`.
    pub scope: Option<String>,
    /// Bearer token for the ping notification. Required in ping mode.
    pub client_notification_token: Option<String>,
    /// Requested authentication context classes, space-delimited.
    pub acr_values: Option<String>,
    /// Not supported; refused.
    pub login_hint_token: Option<String>,
    /// An ID token AXIAM issued to this client.
    pub id_token_hint: Option<String>,
    /// A username or e-mail address in the tenant.
    pub login_hint: Option<String>,
    /// Shown to the user on both devices.
    pub binding_message: Option<String>,
    /// Not supported; refused.
    pub user_code: Option<String>,
    /// Requested lifetime in seconds.
    pub requested_expiry: Option<String>,
    /// A signed authentication request (CIBA Core §7.1.1): a JWT whose claims
    /// are this request's parameters, signed with the client's registered
    /// `backchannel_authentication_request_signing_alg`. Required from a
    /// client that registered one, refused from a client that did not; sent
    /// alone, with no authentication-request parameter beside it.
    pub request: Option<String>,
    /// Not part of CIBA; refused.
    pub request_uri: Option<String>,
    /// RFC 8707 target service.
    pub resource: Option<String>,
}

/// `POST /oauth2/bc-authorize` success body (CIBA Core §7.3).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct BackchannelAuthenticationResponse {
    /// The identifier the client redeems at the token endpoint. Returned once.
    pub auth_req_id: String,
    /// Seconds until the request expires.
    pub expires_in: u64,
    /// Minimum seconds between token requests.
    pub interval: u64,
}

/// Refusals decidable from the request alone, before the client is
/// authenticated: each names a parameter the caller sent and nothing about the
/// client, so none is an oracle, and a request that cannot be served whoever
/// sent it should not first cost an authentication.
///
/// # Errors
///
/// `invalid_request` naming the parameter.
pub fn refuse_unsupported_parameters(
    req: &BackchannelAuthenticationRequest,
) -> Result<(), OAuth2Error> {
    let present = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.trim().is_empty());
    if present(&req.request_uri) {
        return Err(OAuth2Error::InvalidRequest(
            "request_uri is not supported: CIBA Core section 7.1.1 defines the signed \
             authentication request by value, in the request parameter"
                .into(),
        ));
    }
    if present(&req.request) {
        // CIBA Core §7.1.1: the parameters "MUST NOT be present outside of the
        // JWT, in particular they MUST NOT appear as HTTP request parameters".
        // Refused rather than ignored: a parameter the client believes it sent
        // and the server silently dropped is a request the two read
        // differently.
        let outside: Vec<&str> = [
            ("scope", &req.scope),
            ("client_notification_token", &req.client_notification_token),
            ("acr_values", &req.acr_values),
            ("login_hint_token", &req.login_hint_token),
            ("id_token_hint", &req.id_token_hint),
            ("login_hint", &req.login_hint),
            ("binding_message", &req.binding_message),
            ("user_code", &req.user_code),
            ("requested_expiry", &req.requested_expiry),
            ("resource", &req.resource),
        ]
        .into_iter()
        .filter(|(_, v)| v.is_some())
        .map(|(name, _)| name)
        .collect();
        if !outside.is_empty() {
            return Err(OAuth2Error::InvalidRequest(format!(
                "a signed authentication request carries every parameter inside the request JWT; \
                 these were also sent outside it: {}",
                outside.join(", ")
            )));
        }
        return Ok(());
    }
    if present(&req.login_hint_token) {
        return Err(OAuth2Error::InvalidRequest(
            "login_hint_token is not supported; identify the user with login_hint or \
             id_token_hint"
                .into(),
        ));
    }
    if present(&req.user_code) {
        return Err(OAuth2Error::InvalidRequest(
            "user_code is not supported by this server".into(),
        ));
    }
    Ok(())
}

/// Validate a `binding_message`: at most [`MAX_BINDING_MESSAGE_CHARS`]
/// characters, no control characters, not blank.
///
/// # Errors
///
/// `invalid_binding_message`.
pub fn validate_binding_message(raw: Option<&str>) -> Result<Option<String>, OAuth2Error> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(OAuth2Error::InvalidBindingMessage(
            "binding_message must not be blank".into(),
        ));
    }
    if trimmed.chars().count() > MAX_BINDING_MESSAGE_CHARS {
        return Err(OAuth2Error::InvalidBindingMessage(format!(
            "binding_message must be at most {MAX_BINDING_MESSAGE_CHARS} characters"
        )));
    }
    // Printable: shown verbatim on two screens and in an e-mail, so a control
    // character (a newline, a bidi override) could make the two disagree.
    if trimmed
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
    {
        return Err(OAuth2Error::InvalidBindingMessage(
            "binding_message must contain printable characters only".into(),
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

/// Resolve `requested_expiry` to the request's lifetime.
///
/// # Errors
///
/// `invalid_request` for a value that is not an integer in
/// `[MIN_REQUESTED_EXPIRY_SECS, MAX_REQUESTED_EXPIRY_SECS]`.
pub fn resolve_expiry(raw: Option<&str>) -> Result<u64, OAuth2Error> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_EXPIRES_IN_SECS);
    };
    let secs: u64 = raw.parse().map_err(|_| {
        OAuth2Error::InvalidRequest("requested_expiry must be a positive integer".into())
    })?;
    if !(MIN_REQUESTED_EXPIRY_SECS..=MAX_REQUESTED_EXPIRY_SECS).contains(&secs) {
        return Err(OAuth2Error::InvalidRequest(format!(
            "requested_expiry must be between {MIN_REQUESTED_EXPIRY_SECS} and \
             {MAX_REQUESTED_EXPIRY_SECS} seconds"
        )));
    }
    Ok(secs)
}

/// Parse `acr_values`, bounded.
///
/// # Errors
///
/// `invalid_request` past [`MAX_ACR_VALUES`] or [`MAX_ACR_VALUE_BYTES`].
pub fn parse_acr_values(raw: Option<&str>) -> Result<Vec<String>, OAuth2Error> {
    let values: Vec<String> = raw
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if values.len() > MAX_ACR_VALUES || values.iter().any(|v| v.len() > MAX_ACR_VALUE_BYTES) {
        return Err(OAuth2Error::InvalidRequest(format!(
            "acr_values may name at most {MAX_ACR_VALUES} values of at most \
             {MAX_ACR_VALUE_BYTES} bytes each"
        )));
    }
    Ok(values)
}

/// Resolve the requested scopes: `openid` is required (CIBA Core §7.1), and
/// every value must be one the client is registered for.
///
/// # Errors
///
/// `invalid_request` without `openid`; `invalid_scope` for an unregistered
/// value.
pub fn resolve_scopes(
    raw: Option<&str>,
    registered: &[String],
) -> Result<Vec<String>, OAuth2Error> {
    let mut scopes: Vec<String> = Vec::new();
    for s in raw.unwrap_or("").split_whitespace() {
        if !scopes.iter().any(|seen| seen == s) {
            scopes.push(s.to_owned());
        }
    }
    if !scopes.iter().any(|s| s == "openid") {
        return Err(OAuth2Error::InvalidRequest(
            "scope is required and must include openid (CIBA Core section 7.1)".into(),
        ));
    }
    if let Some(bad) = scopes.iter().find(|s| !registered.iter().any(|r| r == *s)) {
        return Err(OAuth2Error::InvalidScope(format!(
            "scope {bad:?} is not registered for this client"
        )));
    }
    Ok(scopes)
}

/// The hint a request named — exactly one of the two AXIAM accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibaHint {
    /// A username or e-mail address.
    LoginHint(String),
    /// An ID token, still encoded.
    IdTokenHint(String),
}

/// Select the request's hint (CIBA Core §7.1: exactly one).
///
/// # Errors
///
/// `invalid_request` for none or more than one, or an oversized `login_hint`.
pub fn select_hint(req: &BackchannelAuthenticationRequest) -> Result<CibaHint, OAuth2Error> {
    let login = req
        .login_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let id_token = req
        .id_token_hint
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    match (login, id_token) {
        (Some(_), Some(_)) => Err(OAuth2Error::InvalidRequest(
            "exactly one of login_hint, id_token_hint and login_hint_token may be sent".into(),
        )),
        (None, None) => Err(OAuth2Error::InvalidRequest(
            "one of login_hint or id_token_hint is required".into(),
        )),
        (Some(hint), None) => {
            if hint.len() > MAX_LOGIN_HINT_BYTES {
                return Err(OAuth2Error::InvalidRequest(format!(
                    "login_hint must be at most {MAX_LOGIN_HINT_BYTES} bytes"
                )));
            }
            Ok(CibaHint::LoginHint(hint.to_owned()))
        }
        (None, Some(token)) => Ok(CibaHint::IdTokenHint(token.to_owned())),
    }
}

/// Verify an `id_token_hint` and return its subject.
///
/// The hint must be an ID token **this deployment** signed (its EdDSA key),
/// issued **to this client** (`aud`) under **one of the issuers this request
/// may name** (`iss`: the deployment's, or the tenant path's the request
/// arrived under). Expiry is not checked: CIBA Core §7.1 describes the hint as
/// a token "previously issued", and the hint authenticates nothing — it only
/// names the user to ask. What it may not do is name a user of another tenant
/// or another client's relying party, which `aud` and the tenant-scoped user
/// lookup that follows both prevent.
///
/// # Errors
///
/// `invalid_request` for anything that fails; the message does not say which.
pub fn verify_id_token_hint(
    token: &str,
    public_key_pem: &str,
    client_id: &str,
    acceptable_issuers: &[String],
) -> Result<Uuid, OAuth2Error> {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation};

    let invalid = || {
        OAuth2Error::InvalidRequest(
            "id_token_hint is not an ID token this server issued to this client".into(),
        )
    };
    let key = DecodingKey::from_ed_pem(public_key_pem.as_bytes()).map_err(|_| invalid())?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims = jsonwebtoken::decode::<axiam_auth::token::IdTokenClaims>(token, &key, &validation)
        .map_err(|_| invalid())?
        .claims;
    if claims.aud != client_id {
        return Err(invalid());
    }
    if !acceptable_issuers.iter().any(|i| i == &claims.iss) {
        return Err(invalid());
    }
    Uuid::parse_str(&claims.sub).map_err(|_| invalid())
}

/// Whether a user may be the subject of a CIBA grant right now: the account
/// may act (`axiam_auth::service::account_may_act`, what `/oauth2/authorize`
/// and refresh use) **and** is not under brute-force lockout. The second half
/// is the Keycloak 26.7.x lesson: a lockout that only the password path reads
/// is a lockout a backchannel grant walks around.
#[must_use]
pub fn user_may_be_subject(user: &User) -> bool {
    axiam_auth::service::account_may_act(user).is_ok() && !axiam_auth::lockout::is_locked_out(user)
}

/// Decide a token request's back-off: `(too_fast, interval to store)`.
///
/// RFC 8628 §3.5's rule, which CIBA Core §11 adopts: a request inside the
/// current interval is `slow_down` and raises the interval by
/// [`SLOW_DOWN_STEP_SECS`], capped at [`MAX_INTERVAL_SECS`].
#[must_use]
pub fn poll_backoff(
    interval_secs: u64,
    last_polled_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> (bool, u64) {
    let too_fast = last_polled_at
        .is_some_and(|last| (now - last).num_milliseconds() < (interval_secs as i64) * 1000);
    let next = if too_fast {
        (interval_secs + SLOW_DOWN_STEP_SECS).min(MAX_INTERVAL_SECS)
    } else {
        interval_secs
    };
    (too_fast, next)
}

// ---------------------------------------------------------------------------
// The service
// ---------------------------------------------------------------------------

/// What `bc-authorize` produced: the response, and — only for a request whose
/// hint named a user who may sign in — the notification the caller hands to
/// the [`axiam_core::models::ciba::CibaUserNotifier`] port, detached.
#[derive(Debug, Clone)]
pub struct CibaInitiation {
    /// The `200` body.
    pub response: BackchannelAuthenticationResponse,
    /// The stored request.
    pub request: CibaRequest,
    /// `None` for a request nobody can approve.
    pub notification: Option<CibaUserNotification>,
}

/// The authentication the approving user performed, as the identity pages
/// know it (their `AuthenticatedUser` and its session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaApproval {
    /// The signed-in user. Must be the request's user.
    pub user_id: Uuid,
    /// Their session.
    pub session_id: Uuid,
    /// When they authenticated.
    pub auth_time: DateTime<Utc>,
    /// How they authenticated. The `acr` is derived from this, never taken
    /// from the caller.
    pub amr: Vec<Amr>,
}

/// The most pending requests one user's list returns. A user with more than
/// this many open requests is being flooded (T-424); the oldest are shown, in
/// the order they were made, and the list says how many more there are
/// ([`CibaPendingPage::total_pending`]).
pub const MAX_PENDING_LIST: u32 = 50;

/// The shipped allowance of `bc-authorize` calls one client may have admitted
/// for one hint in any [`HINT_CAP_WINDOW_SECS`] (#599, T-424). The deployment
/// sets its own with `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_HINT` (#639,
/// [`CibaHintCap::with_per_hint`]); a call past the allowance is refused before
/// the hint is looked up, stored or mailed, with the `slow_down` the
/// per-client limiter answers.
///
/// `requested_expiry` is the client's to choose, so without a per-client bound
/// a client that may address a user could keep the whole list full of
/// short-lived requests of its own. Three is room for a retry or two while the
/// first is still on the user's phone; a client that needs more is waiting on
/// a user who has not answered. A conformance suite or an SDK's integration
/// suite, which runs many flows for one test user from one client within
/// minutes, needs more, and sets the knob for the deployment it tests.
///
/// **What is counted is admitted calls, not open requests.** The count is keyed
/// on (tenant, client, a keyed digest of the hint) — never on the user the hint
/// resolves to — so a hint that names nobody, a user who may not sign in and a
/// real user are refused at the same call, and the refusal says nothing about
/// the hint (D-63, T-422). A request that has been approved, denied or has
/// expired therefore still counts until its window has passed. A **refused**
/// call does not count (#639; until 1.1.0 it did, so a client that kept
/// retrying stayed refused): a client that stops for the rest of the window
/// after the one in which it used its allowance is admitted again. The hint is
/// the one the request carried, as hint resolution normalises it (a
/// `login_hint` trimmed and otherwise exact, as the username and e-mail lookups
/// match it; an `id_token_hint` reduced to its verified subject), so one user
/// named by username, by e-mail address and by ID token is three hints — three
/// allowances a window from one client.
///
/// Admission requires the admitted calls in this window and the one before it,
/// this call included, to come to at most the allowance, so any
/// [`HINT_CAP_WINDOW_SECS`]-long stretch admits at most the allowance; as no
/// request outlives that, one client never holds more open requests for one
/// hint than the allowance. The price is coarseness: a client that has used the
/// allowance in one window is refused for the whole of the next, so it waits
/// between one and two windows. The count is the shared rate-limit table,
/// written atomically in the datastore, so the bound holds across replicas and
/// under concurrent calls (see [`CibaHintCap`] for the protocol and the
/// argument).
pub const DEFAULT_REQUESTS_PER_CLIENT_HINT: u32 = 3;

/// The window of the per-hint allowance ([`DEFAULT_REQUESTS_PER_CLIENT_HINT`]):
/// the longest a request may live ([`MAX_REQUESTED_EXPIRY_SECS`]), not the
/// default ([`DEFAULT_EXPIRES_IN_SECS`]), so a client that asks for the longest
/// expiry still cannot hold more open requests for one hint than the allowance.
pub const HINT_CAP_WINDOW_SECS: u64 = MAX_REQUESTED_EXPIRY_SECS;

/// What a hint names, as the cap counts it and the lookup reads it: a
/// `login_hint` as sent (already trimmed), or a verified `id_token_hint`'s
/// subject. Computed without looking anyone up.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HintName {
    /// A username or e-mail address.
    Login(String),
    /// The subject of an ID token this deployment signed for this client.
    Subject(Uuid),
}

/// The per-(client, hint) cap on `bc-authorize` (#599, T-424): see
/// [`DEFAULT_REQUESTS_PER_CLIENT_HINT`].
///
/// Counted in the deployment's shared rate-limit table (`rate_limit_bucket`)
/// through [`axiam_db::SharedRateLimitStore`] — not through the write-behind
/// [`axiam_db::SharedRateLimitCounter`], whose window is the limiters' minute
/// and whose local buckets are pruned after two of them. Two buckets per
/// (tenant, client, hint), one for even and one for odd windows, so the table
/// holds at most two rows per hint a client has named, however long it keeps
/// naming it.
///
/// The bucket key is `ciba_hint_cap:{tenant}:` followed by an HMAC-SHA256,
/// under a key only the deployment holds, of the client and the hint: the
/// table is not a dictionary of hashes of the usernames and addresses clients
/// have tried.
///
/// # The protocol, and the bound it guarantees (#639)
///
/// A call stamped in window `s` (its own clock) does three things, each one
/// statement on one record:
///
/// 1. **counts itself**: an atomic increment of window `s`'s bucket, which
///    answers the count after it, `v`;
/// 2. **reads** window `s − 1`'s bucket (a `SELECT`, which writes nothing): its
///    count when the bucket still holds `s − 1`, zero when it holds an older
///    window or does not exist, and **overtaken** when it already holds
///    `s + 1` — a call stamped in the next window has written, so this one is
///    late;
/// 3. is **admitted** when it was not overtaken and `v` plus the previous
///    window's count is at most the allowance; otherwise it is refused and
///    **takes its count back** with a conditional decrement (which only
///    touches the bucket while it still holds window `s`).
///
/// *The bound.* For every two consecutive windows the admitted calls stamped
/// in them come to at most the allowance, so any window-long stretch admits at
/// most the allowance — exactly, under concurrent calls and across replicas,
/// with no overshoot. Within one window: the admitted call whose increment
/// came last counted every admitted call of its window before it (admitted
/// counts are never taken back; a refused call's count is taken back only
/// after it was made, so it can only inflate `v`), so `v` is at least the
/// window's admissions. Across a boundary: a call stamped `s − 1` that is
/// admitted read window `s`'s bucket (its "previous" bucket by parity) before
/// any call stamped `s` had counted itself — had one done so, the bucket would
/// hold `s` and the call would be overtaken and refused. So every call stamped
/// `s − 1` that is admitted counted itself before any call stamped `s` read
/// window `s − 1`'s bucket, and the last admitted call of window `s` saw all of
/// them. Two calls racing across a boundary can both be refused (each sees the
/// other); they cannot both be admitted past the allowance.
///
/// *What it assumes.* No call stays in flight — from its clock read to its
/// last statement — while a call stamped two windows later writes; that is,
/// a call's latency plus the replicas' clock skew stays under one window (ten
/// minutes). Beyond that the error is still on the strict side: a call whose
/// own bucket has been taken over adds to the newer window's count and its
/// previous bucket reads as overtaken.
///
/// *What it costs.* A refusal may be spurious only while another call for the
/// same hint is between its count and its take-back, or when a call is
/// overtaken at a window boundary (or by a replica whose clock runs ahead).
/// A store error after the count leaves the count in place (strict: the
/// allowance is one smaller until the window passes) and the call fails with
/// `server_error`; a take-back that fails leaves it in place too, and the call
/// is refused as decided.
///
/// A row is read until the end of the window after the one it was written in,
/// so the server's `rate_limit_bucket` sweep deletes a row once it is more
/// than twice [`HINT_CAP_WINDOW_SECS`] old (with a margin), which bounds the
/// table by the hints named in that stretch instead of every hint ever named.
///
/// *Assumption (#676).* The sweep compares `updated_at` with the datastore's
/// own clock (`time::now() - retention`, in the selection and in the
/// `DELETE`), so the sweeping replica's clock is not an input. The "exactly"
/// above still assumes that the replicas serving the cap agree with the
/// datastore to within the sweep's margin (one minute): a reader whose clock
/// runs further ahead may find the previous window's row already swept and read
/// it as zero, and the stretch may then admit up to twice the allowance.
#[derive(Clone)]
pub struct CibaHintCap {
    store: std::sync::Arc<dyn axiam_db::SharedRateLimitStore>,
    key: [u8; 32],
    per_hint: u64,
}

impl std::fmt::Debug for CibaHintCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CibaHintCap")
            .field("per_hint", &self.per_hint)
            .finish_non_exhaustive()
    }
}

/// What [`CibaHintCap`] read in the previous window's bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreviousWindow {
    /// The admitted (and not yet taken back) calls of the previous window.
    Counted(u64),
    /// The bucket already holds the window after this call's: this call is
    /// late, and the previous window's count is gone.
    Overtaken,
}

impl CibaHintCap {
    /// The domain label of [`Self::derived_from`]'s derivation.
    const KEY_LABEL: &'static [u8] = b"axiam/ciba/hint-cap/v1";

    /// A cap over `store`, keying its buckets with `key`, with the shipped
    /// allowance ([`DEFAULT_REQUESTS_PER_CLIENT_HINT`]).
    pub fn new(store: std::sync::Arc<dyn axiam_db::SharedRateLimitStore>, key: [u8; 32]) -> Self {
        Self {
            store,
            key,
            per_hint: u64::from(DEFAULT_REQUESTS_PER_CLIENT_HINT),
        }
    }

    /// A cap whose bucket key is derived from a secret every replica already
    /// shares — the deployment's token signing key, PEM-encoded — as
    /// HMAC-SHA256(secret, a fixed label). One-way, so the derived key tells
    /// nothing about the signing key; a new signing key starts every hint's
    /// count afresh, which errs lenient for one window and no further.
    pub fn derived_from(
        store: std::sync::Arc<dyn axiam_db::SharedRateLimitStore>,
        deployment_secret: &[u8],
    ) -> Self {
        Self::new(store, hmac_sha256(deployment_secret, &[Self::KEY_LABEL]))
    }

    /// The allowance per (client, hint) per [`HINT_CAP_WINDOW_SECS`] (#639):
    /// `RateLimitConfig::bc_authorize_per_hint`,
    /// `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_HINT`. At least one by type; the
    /// configuration refuses `0` at startup. Every replica sharing the table
    /// must be given the same allowance (each enforces its own against the
    /// shared counts). Builder-style.
    #[must_use]
    pub fn with_per_hint(mut self, per_hint: std::num::NonZeroU32) -> Self {
        self.per_hint = u64::from(per_hint.get());
        self
    }

    /// The bucket base for (tenant, client, hint); the window's parity is
    /// appended.
    fn bucket(&self, tenant_id: Uuid, client_id: &str, hint: &HintName) -> String {
        let tenant = tenant_id.to_string();
        let (kind, value): (&[u8], String) = match hint {
            HintName::Login(v) => (b"login", v.clone()),
            HintName::Subject(sub) => (b"sub", sub.to_string()),
        };
        // Length-prefixed parts, so no two (tenant, client, kind, value)
        // tuples encode alike.
        let mac = hmac_sha256(
            &self.key,
            &[
                tenant.as_bytes(),
                client_id.as_bytes(),
                kind,
                value.as_bytes(),
            ],
        );
        format!("ciba_hint_cap:{tenant_id}:{}", hex::encode(mac))
    }

    /// Count this call, decide, and take the count back if it is refused: the
    /// protocol in [`CibaHintCap`]'s documentation. A hint's first call
    /// creates one row, its window's; the read of the previous window writes
    /// nothing, and a take-back never creates a row.
    async fn admit(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        hint: &HintName,
        now: DateTime<Utc>,
    ) -> Result<bool, OAuth2Error> {
        let window = HINT_CAP_WINDOW_SECS as i64;
        let index = now.timestamp().div_euclid(window);
        let start = |i: i64| DateTime::<Utc>::from_timestamp(i * window, 0).unwrap_or(now);
        let base = self.bucket(tenant_id, client_id, hint);
        let slot = |i: i64| format!("{base}:{}", i.rem_euclid(2));
        let failed = |e: axiam_db::DbError| OAuth2Error::ServerError(e.to_string());
        let own = slot(index);
        // Concurrent calls for one hint write one record: the datastore
        // aborts all but one with a retryable write conflict, and an aborted
        // statement wrote nothing, so it is replayed (not counted twice).
        let current = retry_on_write_conflict(|| self.store.increment_by(&own, start(index), 1))
            .await
            .map_err(failed)?;
        let previous = match self.store.peek_bucket(&slot(index - 1)).await {
            Ok(None) => PreviousWindow::Counted(0),
            Ok(Some((stored, count))) => match stored.cmp(&start(index - 1)) {
                std::cmp::Ordering::Less => PreviousWindow::Counted(0),
                std::cmp::Ordering::Equal => PreviousWindow::Counted(count),
                std::cmp::Ordering::Greater => PreviousWindow::Overtaken,
            },
            // The count stays: strict, never lenient.
            Err(e) => return Err(failed(e)),
        };
        let admitted = match previous {
            PreviousWindow::Counted(count) => current.saturating_add(count) <= self.per_hint,
            PreviousWindow::Overtaken => false,
        };
        if !admitted {
            // A refused call does not consume the allowance (#639). A failed
            // take-back leaves the count in place, which is strict; the call
            // is refused either way.
            if let Err(e) =
                retry_on_write_conflict(|| self.store.decrement(&own, start(index))).await
            {
                tracing::warn!(error = %e, "the CIBA hint cap could not take back a refused call's count");
            }
        }
        Ok(admitted)
    }
}

/// HMAC-SHA256 of the length-prefixed `parts` under `key`.
fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    use hmac::{KeyInit, Mac};
    let mut mac = <hmac::Hmac<sha2::Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC accepts a key of any length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// What the approval page may show (nothing the user's own request does not
/// already say).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaApprovalView {
    /// The request's id.
    pub request_id: Uuid,
    /// The version to pass back to [`CibaService::approve`] /
    /// [`CibaService::deny`].
    pub version: u64,
    /// The client that asked.
    pub client_id: String,
    /// The scopes it asked for.
    pub scopes: Vec<String>,
    /// The binding message, to compare with the client's device.
    pub binding_message: Option<String>,
    /// The requested `acr_values`.
    pub acr_values: Vec<String>,
    /// When it expires.
    pub expires_at: DateTime<Utc>,
}

/// A user's pending requests as the console lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CibaPendingPage {
    /// Oldest first, at most [`MAX_PENDING_LIST`].
    pub requests: Vec<CibaApprovalView>,
    /// Every `pending`, unexpired request addressed to the user, the ones not
    /// in `requests` included; never less than `requests.len()`.
    pub total_pending: u64,
}

impl CibaPendingPage {
    /// Whether `requests` leaves some open requests out.
    pub fn truncated(&self) -> bool {
        self.total_pending > self.requests.len() as u64
    }
}

/// The class a request's `acr_values` still need, given the authentication the
/// approving session performed — `None` when the request asked for no class
/// AXIAM implements, or when the session already achieved one of them.
///
/// The one place the rule lives: [`CibaService::approve`] refuses with it, and
/// the approval page asks for it beforehand so that it can offer the step-up
/// before the user presses Approve. The class a session achieved is derived
/// from its `amr` ([`acr_for`]); nothing the caller says moves it.
#[must_use]
pub fn step_up_required(acr_values: &[String], amr: &[Amr]) -> Option<Acr> {
    let achieved = acr_for(amr);
    let requested: Vec<Acr> = acr_values
        .iter()
        .filter_map(|v| Acr::from_wire(v))
        .collect();
    if requested.is_empty() || requested.iter().any(|wanted| achieved.satisfies(*wanted)) {
        return None;
    }
    Some(requested.iter().copied().min().unwrap_or(Acr::MultiFactor))
}

/// The result of a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CibaDecisionOutcome {
    /// Recorded. Carries the request as it now is (T23.7.2's ping deliverer
    /// needs its mode and id).
    Recorded(Box<CibaRequest>),
    /// Unknown, another user's, expired, already decided, or decided by
    /// someone else since the page read it. One answer for all five: the page
    /// must not become an oracle for which request ids exist.
    NotDecidable,
    /// The request asked for an authentication class the approving session
    /// did not achieve; the page should ask the user to step up to `required`.
    StepUpRequired {
        /// The weakest requested class AXIAM implements.
        required: Acr,
    },
}

/// The CIBA service: `bc-authorize` and the approval API.
#[derive(Clone)]
pub struct CibaService<CR, UR> {
    requests: CR,
    users: UR,
    /// The deployment's ID-token verification key, for `id_token_hint`.
    public_key_pem: String,
    /// Verifies signed authentication requests (CIBA Core §7.1.1). `None`
    /// refuses every signed request with `server_error` — never accepts one
    /// unverified, and never lets a client that registered a signing
    /// algorithm fall back to plain requests.
    signed_requests: Option<std::sync::Arc<dyn crate::ciba_signed_request::SignedRequestVerifier>>,
    /// Where a decided ping-mode request's notification is queued (T23.7.2,
    /// D-65). `None` queues nothing: a deployment with no dispatcher wired
    /// (T23.8.1 supplies the in-process one) still records the decision, and
    /// the client — which may poll in either mode — still collects the result.
    ping: Option<crate::ciba_ping::PingPublisher>,
    /// The per-(client, hint) cap on `bc-authorize` (#599, T-424).
    hint_cap: CibaHintCap,
}

impl<CR, UR> CibaService<CR, UR>
where
    CR: CibaRequestRepository,
    UR: UserRepository,
{
    /// Build the service. `hint_cap` is required, not a builder option: a
    /// deployment that forgot it would have no cap on one client's requests
    /// for one person (T-424).
    pub fn new(requests: CR, users: UR, public_key_pem: String, hint_cap: CibaHintCap) -> Self {
        Self {
            requests,
            users,
            public_key_pem,
            signed_requests: None,
            ping: None,
            hint_cap,
        }
    }

    /// Wire the ping-mode notification queue (T23.7.2, D-65). Builder-style.
    ///
    /// Once set, [`Self::approve`] and [`Self::deny`] enqueue one
    /// `OutboundKind::CibaPing` message — the request's record id and tenant,
    /// nothing secret — for a ping-mode request they have just recorded. The
    /// enqueue is best effort: a broker that is down is logged and never turns
    /// a recorded decision into an error.
    #[must_use]
    pub fn with_ping_publisher(mut self, publisher: crate::ciba_ping::PingPublisher) -> Self {
        self.ping = Some(publisher);
        self
    }

    /// Wire the signed-request verifier (D-61). Builder-style, like
    /// `TokenService::with_assertion_verifier`.
    #[must_use]
    pub fn with_signed_request_verifier(
        mut self,
        verifier: std::sync::Arc<dyn crate::ciba_signed_request::SignedRequestVerifier>,
    ) -> Self {
        self.signed_requests = Some(verifier);
        self
    }

    /// Resolve the parameters this request is made of: the signed `request`
    /// JWT's claims for a client that registered a signing algorithm, the
    /// form for one that did not — never a mixture, and never the other form.
    async fn effective_request<'r>(
        &self,
        client: &OAuth2Client,
        req: &'r BackchannelAuthenticationRequest,
        acceptable_issuers: &[String],
    ) -> Result<std::borrow::Cow<'r, BackchannelAuthenticationRequest>, OAuth2Error> {
        use std::borrow::Cow;
        let signed = req
            .request
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        match (
            client.ciba.backchannel_authentication_request_signing_alg,
            signed,
        ) {
            (None, None) => {
                // A `fapi2` row reaches here only if edited past the
                // registration gate (`FapiRequiresSignedRequests`).
                if client.profile.is_fapi2() {
                    tracing::error!(
                        client_id = %client.client_id,
                        "a fapi2 CIBA client has no backchannel_authentication_request_signing_alg; \
                         this registration cannot have passed validate_client_registration"
                    );
                    return Err(OAuth2Error::UnauthorizedClient(
                        "a fapi2 client must send signed authentication requests".into(),
                    ));
                }
                Ok(Cow::Borrowed(req))
            }
            (Some(alg), None) => Err(OAuth2Error::InvalidRequest(format!(
                "this client registered backchannel_authentication_request_signing_alg {}: send \
                 the authentication request as a signed request JWT (CIBA Core section 7.1.1)",
                alg.as_str()
            ))),
            (None, Some(_)) => Err(OAuth2Error::InvalidRequest(
                "this client has not registered backchannel_authentication_request_signing_alg, \
                 so it cannot send a signed request; register the algorithm it signs with"
                    .into(),
            )),
            (Some(_), Some(jwt)) => {
                let Some(verifier) = self.signed_requests.as_ref() else {
                    tracing::error!(
                        client_id = %client.client_id,
                        "a signed CIBA request arrived and no signed-request verifier is wired"
                    );
                    return Err(OAuth2Error::ServerError(
                        "signed authentication requests are not available on this deployment"
                            .into(),
                    ));
                };
                Ok(Cow::Owned(
                    verifier.verify(client, jwt, acceptable_issuers).await?,
                ))
            }
        }
    }

    /// The request store, for the token endpoint's redemption.
    pub fn requests(&self) -> &CR {
        &self.requests
    }

    /// What a hint names, without looking anyone up: a `login_hint` as sent,
    /// or the subject of a verified `id_token_hint` (a signature check, no
    /// datastore read). The cap counts this, and [`Self::resolve_subject`]
    /// looks it up.
    fn name_in_hint(
        &self,
        hint: &CibaHint,
        client_id: &str,
        acceptable_issuers: &[String],
    ) -> Result<HintName, OAuth2Error> {
        Ok(match hint {
            CibaHint::LoginHint(value) => HintName::Login(value.clone()),
            CibaHint::IdTokenHint(token) => HintName::Subject(verify_id_token_hint(
                token,
                &self.public_key_pem,
                client_id,
                acceptable_issuers,
            )?),
        })
    }

    /// Resolve what a hint names to a user who may be the grant's subject, or
    /// `None`.
    async fn resolve_subject(
        &self,
        tenant_id: Uuid,
        name: &HintName,
    ) -> Result<Option<User>, OAuth2Error> {
        use axiam_core::error::AxiamError;
        let found = match name {
            HintName::Login(value) => match self.users.get_by_username(tenant_id, value).await {
                Ok(user) => Some(user),
                Err(AxiamError::NotFound { .. }) => {
                    match self.users.get_by_email(tenant_id, value).await {
                        Ok(user) => Some(user),
                        Err(AxiamError::NotFound { .. }) => None,
                        Err(e) => return Err(OAuth2Error::ServerError(e.to_string())),
                    }
                }
                Err(e) => return Err(OAuth2Error::ServerError(e.to_string())),
            },
            HintName::Subject(sub) => match self.users.get_by_id(tenant_id, *sub).await {
                Ok(user) => Some(user),
                Err(AxiamError::NotFound { .. }) => None,
                Err(e) => return Err(OAuth2Error::ServerError(e.to_string())),
            },
        };
        // Defence in depth: the lookups are tenant-scoped in SQL.
        Ok(found.filter(|u| u.tenant_id == tenant_id && user_may_be_subject(u)))
    }

    /// `POST /oauth2/bc-authorize` after client authentication (CIBA Core
    /// §7). The caller has authenticated `client`, applied D-17, checked the
    /// grant and counted the request; this validates and stores it.
    ///
    /// `acceptable_issuers` are the `iss` values an `id_token_hint` may carry
    /// for this request.
    ///
    /// # Errors
    ///
    /// CIBA Core §13's codes for a malformed request; `slow_down` when the
    /// client has already been admitted its allowance for this hint
    /// ([`CibaHintCap::with_per_hint`], default
    /// [`DEFAULT_REQUESTS_PER_CLIENT_HINT`]) in the cap's window (#599, #639),
    /// whoever the hint names;
    /// `server_error` for a datastore failure (or a
    /// ping request with no sealing key).
    pub async fn initiate(
        &self,
        client: &OAuth2Client,
        req: &BackchannelAuthenticationRequest,
        acceptable_issuers: &[String],
    ) -> Result<CibaInitiation, OAuth2Error> {
        let tenant_id = client.tenant_id;
        let mode = client.ciba.backchannel_token_delivery_mode.ok_or_else(|| {
            OAuth2Error::UnauthorizedClient(
                "this client has no backchannel_token_delivery_mode registered".into(),
            )
        })?;

        // D-61: a signed request is verified (and its `jti` spent) before
        // anything it carries is read; from here on `req` is what the client
        // signed, or the form of a client that signs nothing.
        let req = self
            .effective_request(client, req, acceptable_issuers)
            .await?;
        let req: &BackchannelAuthenticationRequest = &req;
        // The parameters AXIAM does not implement, again: inside a signed
        // request they could not be seen before it was verified.
        refuse_unsupported_parameters(req)?;
        let fapi = client.profile.is_fapi2();
        if fapi
            && req
                .binding_message
                .as_deref()
                .is_none_or(|m| m.trim().is_empty())
        {
            // FAPI-CIBA §5.2.2: a unique authorization context or a binding
            // message. AXIAM has no other carrier for the former.
            return Err(OAuth2Error::InvalidRequest(
                "a fapi2 client must send a binding_message (FAPI-CIBA)".into(),
            ));
        }

        let scopes = resolve_scopes(req.scope.as_deref(), &client.scopes)?;
        let hint = select_hint(req)?;
        let binding_message = validate_binding_message(req.binding_message.as_deref())?;
        let expires_in = resolve_expiry(req.requested_expiry.as_deref())?;
        let acr_values = parse_acr_values(req.acr_values.as_deref())?;
        let resource =
            crate::resource::resolve_requested(&client.allowed_resources, req.resource.as_deref())?;

        let auth_req_id = generate_auth_req_id();
        let ping = match mode {
            CibaDeliveryMode::Poll => None,
            CibaDeliveryMode::Ping => {
                let token = req
                    .client_notification_token
                    .as_deref()
                    .filter(|t| !t.is_empty())
                    .ok_or_else(|| {
                        OAuth2Error::InvalidRequest(
                            "client_notification_token is required in ping mode".into(),
                        )
                    })?;
                if token.len() > MAX_NOTIFICATION_TOKEN_BYTES
                    || !token.bytes().all(|b| b.is_ascii_graphic())
                {
                    return Err(OAuth2Error::InvalidRequest(format!(
                        "client_notification_token must be at most {MAX_NOTIFICATION_TOKEN_BYTES} \
                         visible ASCII characters"
                    )));
                }
                if fapi && token.len() < MIN_FAPI_NOTIFICATION_TOKEN_BYTES {
                    return Err(OAuth2Error::InvalidRequest(format!(
                        "a fapi2 client's client_notification_token must be at least \
                         {MIN_FAPI_NOTIFICATION_TOKEN_BYTES} characters (128 bits of entropy)"
                    )));
                }
                Some(CibaPingCredentials {
                    auth_req_id: auth_req_id.clone(),
                    client_notification_token: token.to_owned(),
                })
            }
        };

        // Validation is complete; only now is the hint read, so a malformed
        // request is refused identically whoever it names.
        let named = self.name_in_hint(&hint, &client.client_id, acceptable_issuers)?;

        // #599 (T-424): the per-(client, hint) cap, before the hint is looked
        // up and before anything is stored or mailed. It counts the hint, not
        // the user it names, so it refuses a hint naming nobody at the same
        // call as a real user's and its answer — and its cost, a count and a
        // read, and a take-back when refused, whoever the hint names — says
        // nothing about the hint (D-63).
        // `slow_down` is the answer the per-client limiter gives; the handler
        // renders it as that limiter's 429.
        if !self
            .hint_cap
            .admit(tenant_id, &client.client_id, &named, Utc::now())
            .await?
        {
            return Err(OAuth2Error::SlowDown);
        }

        let subject = self.resolve_subject(tenant_id, &named).await?;

        let expires_at = Utc::now() + Duration::seconds(expires_in as i64);
        let stored = self
            .requests
            .create(CreateCibaRequest {
                tenant_id,
                client_id: client.client_id.clone(),
                auth_req_id_hash: hash_auth_req_id(&auth_req_id),
                user_id: subject.as_ref().map(|u| u.id),
                scopes: scopes.clone(),
                binding_message: binding_message.clone(),
                acr_values,
                resource,
                delivery_mode: mode,
                ping,
                interval_secs: DEFAULT_INTERVAL_SECS,
                expires_at,
            })
            .await
            .map_err(|e| match e {
                axiam_core::error::AxiamError::ServiceUnavailable(detail) => {
                    tracing::error!(%detail, "a ping-mode CIBA request could not be stored");
                    OAuth2Error::ServerError("ping mode is not available on this deployment".into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        let notification = subject.map(|user| CibaUserNotification {
            tenant_id,
            request_id: stored.id,
            user_id: user.id,
            client_id: client.client_id.clone(),
            client_name: client.name.clone(),
            binding_message,
            scopes,
            expires_at,
        });

        Ok(CibaInitiation {
            response: BackchannelAuthenticationResponse {
                auth_req_id,
                expires_in,
                interval: DEFAULT_INTERVAL_SECS,
            },
            request: stored,
            notification,
        })
    }

    /// Load a request for the approval page: only the request's own user,
    /// only while it is pending and unexpired. `None` otherwise — one answer
    /// for every reason.
    ///
    /// # Errors
    ///
    /// `server_error` for a datastore failure.
    pub async fn lookup_for_approval(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<CibaApprovalView>, OAuth2Error> {
        let Some(req) = self
            .requests
            .get_by_id(tenant_id, request_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
        else {
            return Ok(None);
        };
        if req.user_id != Some(user_id)
            || req.status != CibaRequestStatus::Pending
            || req.is_expired_at(Utc::now())
        {
            return Ok(None);
        }
        Ok(Some(CibaApprovalView {
            request_id: req.id,
            version: req.version,
            client_id: req.client_id,
            scopes: req.scopes,
            binding_message: req.binding_message,
            acr_values: req.acr_values,
            expires_at: req.expires_at,
        }))
    }

    /// The signed-in user's own pending requests, oldest first, at most
    /// [`MAX_PENDING_LIST`] — what the console lists for an account the
    /// approval mail never reached (D-74) — with the number of open requests
    /// there are in all. Each entry is what [`Self::lookup_for_approval`] would
    /// return for it.
    ///
    /// # Errors
    ///
    /// `server_error` for a datastore failure.
    pub async fn list_pending_for_approval(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<CibaPendingPage, OAuth2Error> {
        let rows = self
            .requests
            .list_pending_for_user(tenant_id, user_id, MAX_PENDING_LIST)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        let counted = self
            .requests
            .count_pending_for_user(tenant_id, user_id, None)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        let requests: Vec<CibaApprovalView> = rows
            .into_iter()
            .map(|req| CibaApprovalView {
                request_id: req.id,
                version: req.version,
                client_id: req.client_id,
                scopes: req.scopes,
                binding_message: req.binding_message,
                acr_values: req.acr_values,
                expires_at: req.expires_at,
            })
            .collect();
        // The two reads are not one snapshot: a request decided between them
        // must not make the total smaller than what was just listed.
        let total_pending = counted.max(requests.len() as u64);
        Ok(CibaPendingPage {
            requests,
            total_pending,
        })
    }

    /// The user approves (T23.7.2's page, after full authentication).
    ///
    /// Conditional on `expected_version` (what the page read), on the request
    /// being the approving user's, pending and unexpired, and on the user still
    /// being allowed to be a grant's subject (status and lockout, re-read
    /// here). The `acr` recorded is derived from `approval.amr`; a request that
    /// asked for a class this authentication did not achieve is not approved —
    /// the page is told which class to step up to.
    ///
    /// # Errors
    ///
    /// `server_error` for a datastore failure.
    pub async fn approve(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        expected_version: u64,
        approval: CibaApproval,
    ) -> Result<CibaDecisionOutcome, OAuth2Error> {
        let Some(view) = self
            .lookup_for_approval(tenant_id, request_id, approval.user_id)
            .await?
        else {
            return Ok(CibaDecisionOutcome::NotDecidable);
        };
        if view.version != expected_version {
            return Ok(CibaDecisionOutcome::NotDecidable);
        }
        if !self.subject_may_act(tenant_id, approval.user_id).await? {
            return Ok(CibaDecisionOutcome::NotDecidable);
        }

        let achieved = acr_for(&approval.amr);
        if let Some(required) = step_up_required(&view.acr_values, &approval.amr) {
            return Ok(CibaDecisionOutcome::StepUpRequired { required });
        }

        let recorded = self
            .requests
            .approve(
                tenant_id,
                request_id,
                expected_version,
                approval.user_id,
                CibaApprovalEvidence {
                    session_id: approval.session_id,
                    auth_time: approval.auth_time,
                    acr: achieved.as_str().to_owned(),
                    amr: approval.amr,
                },
            )
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        self.after_decision(tenant_id, request_id, recorded).await
    }

    /// The user refuses. Same preconditions as [`Self::approve`], minus the
    /// authentication class (refusing needs no step-up).
    ///
    /// # Errors
    ///
    /// `server_error` for a datastore failure.
    pub async fn deny(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        expected_version: u64,
        user_id: Uuid,
    ) -> Result<CibaDecisionOutcome, OAuth2Error> {
        let recorded = self
            .requests
            .deny(tenant_id, request_id, expected_version, user_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        self.after_decision(tenant_id, request_id, recorded).await
    }

    async fn after_decision(
        &self,
        tenant_id: Uuid,
        request_id: Uuid,
        recorded: bool,
    ) -> Result<CibaDecisionOutcome, OAuth2Error> {
        if !recorded {
            return Ok(CibaDecisionOutcome::NotDecidable);
        }
        match self
            .requests
            .get_by_id(tenant_id, request_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
        {
            Some(req) => {
                self.enqueue_ping(&req).await;
                Ok(CibaDecisionOutcome::Recorded(Box::new(req)))
            }
            // Swept between the write and the read: decided, but gone.
            None => Ok(CibaDecisionOutcome::NotDecidable),
        }
    }

    /// Queue the ping of a just-decided ping-mode request (D-65). After an
    /// approval **and** after a denial: the client learns that the request was
    /// decided, never how — it asks the token endpoint, where it authenticates.
    async fn enqueue_ping(&self, request: &CibaRequest) {
        let Some(publisher) = &self.ping else {
            return;
        };
        if request.delivery_mode != CibaDeliveryMode::Ping {
            return;
        }
        let message = crate::ciba_ping::ping_message(request.tenant_id, request.id);
        if let Err(e) = publisher.enqueue(&message).await {
            tracing::error!(
                error = %e,
                request_id = %request.id,
                "a decided CIBA request's ping could not be queued; the client can still \
                 collect the result from the token endpoint"
            );
        }
    }

    async fn subject_may_act(&self, tenant_id: Uuid, user_id: Uuid) -> Result<bool, OAuth2Error> {
        match self.users.get_by_id(tenant_id, user_id).await {
            Ok(user) => Ok(user_may_be_subject(&user)),
            Err(axiam_core::error::AxiamError::NotFound { .. }) => Ok(false),
            Err(e) => Err(OAuth2Error::ServerError(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(
        grants: &'a [String],
        mode: Option<&'a str>,
        endpoint: Option<&'a str>,
    ) -> CibaRegistrationView<'a> {
        CibaRegistrationView {
            grant_types: grants,
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretBasic,
            profile: ClientProfile::Standard,
            delivery_mode: mode,
            notification_endpoint: endpoint,
            signing_alg: None,
            user_code_parameter: None,
            jwks: None,
            jwks_uri: None,
        }
    }

    /// A one-key inline JWK Set with an Ed25519 key, as a registration holds it.
    fn ed25519_jwks() -> String {
        use base64::Engine as _;
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let raw = kp.public_key_raw();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw[raw.len() - 32..]);
        serde_json::json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": x}]}).to_string()
    }

    fn ciba_grants() -> Vec<String> {
        vec![CIBA_GRANT_TYPE.to_owned(), "refresh_token".to_owned()]
    }

    /// T23.7.2 — the rule the page asks and `approve` enforces is one function:
    /// a step-up is needed only when the request asked for a class AXIAM
    /// implements and the session's evidence achieved none of them.
    #[test]
    fn a_step_up_is_required_only_for_a_class_the_session_did_not_achieve() {
        let mfa = vec![Acr::MultiFactor.as_str().to_owned()];
        let single = vec![Acr::SingleFactor.as_str().to_owned()];
        let pwd_only = [Amr::Pwd];
        let second_factor = [Amr::Pwd, Amr::Otp, Amr::Mfa];

        assert_eq!(
            step_up_required(&mfa, &pwd_only),
            Some(Acr::MultiFactor),
            "a password session has not achieved multi-factor"
        );
        assert_eq!(step_up_required(&mfa, &second_factor), None);
        assert_eq!(step_up_required(&single, &pwd_only), None);
        assert_eq!(step_up_required(&[], &pwd_only), None, "asked for nothing");
        assert_eq!(
            step_up_required(&["urn:other:acr".to_owned()], &pwd_only),
            None,
            "a value AXIAM does not implement can never be satisfied, so is never asked for"
        );
        // Any satisfiable value in the list is enough.
        let either = vec![mfa[0].clone(), single[0].clone()];
        assert_eq!(step_up_required(&either, &pwd_only), None);
        // And no evidence at all is single-factor, the strict reading.
        assert_eq!(step_up_required(&mfa, &[]), Some(Acr::MultiFactor));
    }

    #[test]
    fn a_pending_page_is_truncated_only_when_open_requests_are_left_out() {
        let view = |n: u8| CibaApprovalView {
            request_id: Uuid::from_u128(u128::from(n)),
            version: 0,
            client_id: "oa_x".into(),
            scopes: vec!["openid".into()],
            binding_message: None,
            acr_values: Vec::new(),
            expires_at: Utc::now(),
        };
        let page = |held: u8, total: u64| CibaPendingPage {
            requests: (0..held).map(view).collect(),
            total_pending: total,
        };
        assert!(!page(0, 0).truncated());
        assert!(!page(3, 3).truncated());
        assert!(page(3, 4).truncated());
        assert_eq!(DEFAULT_REQUESTS_PER_CLIENT_HINT, 3);
    }

    #[test]
    fn a_poll_registration_resolves_to_poll() {
        let grants = ciba_grants();
        let meta = validate_client_registration(view(&grants, Some("poll"), None)).unwrap();
        assert_eq!(
            meta.backchannel_token_delivery_mode,
            Some(CibaDeliveryMode::Poll)
        );
        assert_eq!(meta.backchannel_client_notification_endpoint, None);
    }

    #[test]
    fn a_ping_registration_needs_a_public_https_endpoint() {
        let grants = ciba_grants();
        assert_eq!(
            validate_client_registration(view(&grants, Some("ping"), None)),
            Err(CibaRegistrationError::NotificationEndpointRequired)
        );
        for bad in [
            "http://rp.example.com/cb",
            "https://127.0.0.1/cb",
            "https://10.0.0.8/cb",
            "https://localhost/cb",
            "https://svc.internal/cb",
            "https://user:pw@rp.example.com/cb",
        ] {
            assert!(
                matches!(
                    validate_client_registration(view(&grants, Some("ping"), Some(bad))),
                    Err(CibaRegistrationError::InvalidNotificationEndpoint { .. })
                ),
                "{bad} must fail the outbound URL policy"
            );
        }
        let meta = validate_client_registration(view(
            &grants,
            Some("ping"),
            Some("https://rp.example.com/ciba/notify"),
        ))
        .unwrap();
        assert_eq!(
            meta.backchannel_token_delivery_mode,
            Some(CibaDeliveryMode::Ping)
        );
        assert_eq!(
            meta.backchannel_client_notification_endpoint.as_deref(),
            Some("https://rp.example.com/ciba/notify")
        );
    }

    #[test]
    fn push_and_unknown_modes_and_missing_modes_are_refused() {
        let grants = ciba_grants();
        assert_eq!(
            validate_client_registration(view(&grants, None, None)),
            Err(CibaRegistrationError::DeliveryModeRequired)
        );
        assert!(matches!(
            validate_client_registration(view(&grants, Some("push"), None)),
            Err(CibaRegistrationError::UnsupportedDeliveryMode { .. })
        ));
        assert_eq!(
            validate_client_registration(view(
                &grants,
                Some("poll"),
                Some("https://rp.example.com/cb")
            )),
            Err(CibaRegistrationError::NotificationEndpointWithoutPing)
        );
    }

    #[test]
    fn stray_metadata_public_clients_and_unimplemented_members_are_refused() {
        let none: Vec<String> = vec!["authorization_code".into()];
        assert_eq!(
            validate_client_registration(view(&none, Some("poll"), None)),
            Err(CibaRegistrationError::MetadataWithoutGrant)
        );
        assert_eq!(
            validate_client_registration(view(&none, None, None)),
            Ok(CibaClientMetadata::default())
        );

        let grants = ciba_grants();
        let mut public = view(&grants, Some("poll"), None);
        public.token_endpoint_auth_method = ClientAuthMethod::None;
        assert_eq!(
            validate_client_registration(public),
            Err(CibaRegistrationError::PublicClient)
        );
        let mut user_code = view(&grants, Some("poll"), None);
        user_code.user_code_parameter = Some(true);
        assert_eq!(
            validate_client_registration(user_code),
            Err(CibaRegistrationError::UserCodeUnsupported)
        );
        // `false` is what the default means and is accepted.
        let mut no_user_code = view(&grants, Some("poll"), None);
        no_user_code.user_code_parameter = Some(false);
        assert!(validate_client_registration(no_user_code).is_ok());
    }

    /// D-61 — a signing algorithm is one AXIAM verifies, comes with exactly
    /// one key source holding a key of that algorithm, needs the grant, and is
    /// stored when accepted.
    #[test]
    fn a_signing_algorithm_is_verified_keyed_and_stored() {
        let grants = ciba_grants();
        let jwks = ed25519_jwks();

        let mut signed = view(&grants, Some("poll"), None);
        signed.signing_alg = Some("EdDSA");
        signed.jwks = Some(&jwks);
        assert_eq!(
            validate_client_registration(signed)
                .unwrap()
                .backchannel_authentication_request_signing_alg,
            Some(CibaRequestSigningAlg::EdDsa)
        );
        // A published key set is accepted unread; it is checked when fetched.
        let mut remote = view(&grants, Some("poll"), None);
        remote.signing_alg = Some("PS256");
        remote.jwks_uri = Some("https://rp.example.com/jwks.json");
        assert!(validate_client_registration(remote).is_ok());

        for bad in ["RS256", "HS256", "none", "eddsa"] {
            let mut v = view(&grants, Some("poll"), None);
            v.signing_alg = Some(bad);
            v.jwks = Some(&jwks);
            assert_eq!(
                validate_client_registration(v),
                Err(CibaRegistrationError::UnsupportedSigningAlg { alg: bad.into() }),
                "{bad}"
            );
        }
        let mut keyless = view(&grants, Some("poll"), None);
        keyless.signing_alg = Some("EdDSA");
        assert_eq!(
            validate_client_registration(keyless),
            Err(CibaRegistrationError::SigningKeysRequired { registered: 0 })
        );
        let mut both = view(&grants, Some("poll"), None);
        both.signing_alg = Some("EdDSA");
        both.jwks = Some(&jwks);
        both.jwks_uri = Some("https://rp.example.com/jwks.json");
        assert_eq!(
            validate_client_registration(both),
            Err(CibaRegistrationError::SigningKeysRequired { registered: 2 })
        );
        let mut wrong_key = view(&grants, Some("poll"), None);
        wrong_key.signing_alg = Some("ES256");
        wrong_key.jwks = Some(&jwks);
        assert_eq!(
            validate_client_registration(wrong_key),
            Err(CibaRegistrationError::NoKeyForSigningAlg { alg: "ES256" })
        );
        let none: Vec<String> = vec!["client_credentials".into()];
        let mut stray = view(&none, None, None);
        stray.signing_alg = Some("EdDSA");
        stray.jwks = Some(&jwks);
        assert_eq!(
            validate_client_registration(stray),
            Err(CibaRegistrationError::MetadataWithoutGrant)
        );
    }

    /// D-61 / FAPI-CIBA §5.2.2 — a `fapi2` client may hold the grant only
    /// with signed requests. (Its client-authentication method and
    /// sender-constraining are `fapi::validate_registration`'s rules, run on
    /// every registration path beside this one.)
    #[test]
    fn a_fapi2_client_holds_the_grant_only_with_signed_requests() {
        let grants = ciba_grants();
        let jwks = ed25519_jwks();
        let mut unsigned = view(&grants, Some("poll"), None);
        unsigned.profile = ClientProfile::Fapi2;
        unsigned.token_endpoint_auth_method = ClientAuthMethod::PrivateKeyJwt;
        unsigned.jwks = Some(&jwks);
        assert_eq!(
            validate_client_registration(unsigned),
            Err(CibaRegistrationError::FapiRequiresSignedRequests)
        );
        let mut signed = unsigned;
        signed.signing_alg = Some("EdDSA");
        assert!(validate_client_registration(signed).is_ok());
        // Ping is offered to a fapi2 client too (FAPI-CIBA permits it).
        let mut ping = signed;
        ping.delivery_mode = Some("ping");
        ping.notification_endpoint = Some("https://rp.example.com/ciba/notify");
        assert!(validate_client_registration(ping).is_ok());
    }

    #[test]
    fn binding_messages_are_bounded_and_printable() {
        assert_eq!(validate_binding_message(None).unwrap(), None);
        assert_eq!(
            validate_binding_message(Some(" W4SCT "))
                .unwrap()
                .as_deref(),
            Some("W4SCT")
        );
        for bad in [
            "".to_owned(),
            "   ".to_owned(),
            "x".repeat(MAX_BINDING_MESSAGE_CHARS + 1),
            "two\nlines".to_owned(),
            "evil\u{202E}txt".to_owned(),
        ] {
            assert!(
                matches!(
                    validate_binding_message(Some(&bad)),
                    Err(OAuth2Error::InvalidBindingMessage(_))
                ),
                "{bad:?}"
            );
        }
        // Non-ASCII letters are printable and allowed.
        assert!(validate_binding_message(Some("Zahlung 42 € an Müller")).is_ok());
    }

    #[test]
    fn requested_expiry_is_bounded() {
        assert_eq!(resolve_expiry(None).unwrap(), DEFAULT_EXPIRES_IN_SECS);
        assert_eq!(resolve_expiry(Some("120")).unwrap(), 120);
        for bad in ["0", "-5", "abc", "29", "601", "1e3"] {
            assert!(resolve_expiry(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn scope_must_carry_openid_and_stay_registered() {
        let registered = vec!["openid".to_owned(), "profile".to_owned()];
        assert!(matches!(
            resolve_scopes(Some("profile"), &registered),
            Err(OAuth2Error::InvalidRequest(_))
        ));
        assert!(matches!(
            resolve_scopes(None, &registered),
            Err(OAuth2Error::InvalidRequest(_))
        ));
        assert!(matches!(
            resolve_scopes(Some("openid admin"), &registered),
            Err(OAuth2Error::InvalidScope(_))
        ));
        assert_eq!(
            resolve_scopes(Some("openid profile openid"), &registered).unwrap(),
            ["openid", "profile"]
        );
    }

    #[test]
    fn exactly_one_hint_is_required() {
        let mut req = BackchannelAuthenticationRequest::default();
        assert!(select_hint(&req).is_err());
        req.login_hint = Some("alice".into());
        assert_eq!(
            select_hint(&req).unwrap(),
            CibaHint::LoginHint("alice".into())
        );
        req.id_token_hint = Some("eyJ".into());
        assert!(select_hint(&req).is_err());
        req.login_hint = None;
        assert_eq!(
            select_hint(&req).unwrap(),
            CibaHint::IdTokenHint("eyJ".into())
        );
        req.id_token_hint = None;
        req.login_hint = Some("a".repeat(MAX_LOGIN_HINT_BYTES + 1));
        assert!(select_hint(&req).is_err());
    }

    #[test]
    fn unsupported_parameters_are_refused_before_anything_else() {
        let mut req = BackchannelAuthenticationRequest::default();
        assert!(refuse_unsupported_parameters(&req).is_ok());
        // A signed request alone passes this gate (it is verified later).
        req.request = Some("eyJ".into());
        assert!(refuse_unsupported_parameters(&req).is_ok());
        // Beside any authentication-request parameter it is refused, naming it
        // (CIBA Core §7.1.1: they "MUST NOT be present outside of the JWT").
        req.login_hint = Some("alice".into());
        req.binding_message = Some("W4SCT".into());
        match refuse_unsupported_parameters(&req) {
            Err(OAuth2Error::InvalidRequest(msg)) => {
                assert!(msg.contains("login_hint, binding_message"), "{msg}");
            }
            other => panic!("expected invalid_request, got {other:?}"),
        }
        // The client-authentication members are not request parameters.
        req = BackchannelAuthenticationRequest {
            request: Some("eyJ".into()),
            client_id: Some("c".into()),
            client_secret: Some("s".into()),
            ..Default::default()
        };
        assert!(refuse_unsupported_parameters(&req).is_ok());
        for setter in [
            |r: &mut BackchannelAuthenticationRequest| r.request_uri = Some("urn:x".into()),
            |r: &mut BackchannelAuthenticationRequest| r.login_hint_token = Some("t".into()),
            |r: &mut BackchannelAuthenticationRequest| r.user_code = Some("1234".into()),
        ] {
            req = BackchannelAuthenticationRequest::default();
            setter(&mut req);
            assert!(matches!(
                refuse_unsupported_parameters(&req),
                Err(OAuth2Error::InvalidRequest(_))
            ));
        }
    }

    #[test]
    fn acr_values_are_bounded() {
        assert_eq!(
            parse_acr_values(Some("urn:axiam:acr:mfa urn:axiam:acr:1fa")).unwrap(),
            ["urn:axiam:acr:mfa", "urn:axiam:acr:1fa"]
        );
        let many = ["a"; MAX_ACR_VALUES + 1].join(" ");
        assert!(parse_acr_values(Some(&many)).is_err());
        assert!(parse_acr_values(Some(&"x".repeat(MAX_ACR_VALUE_BYTES + 1))).is_err());
    }

    /// The device grant's back-off, applied per request.
    #[test]
    fn polling_inside_the_interval_slows_down_and_the_interval_grows_to_a_cap() {
        let t0 = Utc::now();
        assert_eq!(poll_backoff(5, None, t0), (false, 5));
        assert_eq!(
            poll_backoff(5, Some(t0), t0 + Duration::seconds(6)),
            (false, 5)
        );
        assert_eq!(
            poll_backoff(5, Some(t0), t0 + Duration::seconds(1)),
            (true, 10)
        );
        assert_eq!(
            poll_backoff(10, Some(t0), t0 + Duration::seconds(9)),
            (true, 15)
        );
        assert_eq!(
            poll_backoff(MAX_INTERVAL_SECS, Some(t0), t0),
            (true, MAX_INTERVAL_SECS)
        );
    }

    #[test]
    fn auth_req_ids_are_high_entropy_and_hashed() {
        let a = generate_auth_req_id();
        let b = generate_auth_req_id();
        // `assert!` rather than `assert_ne!`: a failure must not print an
        // `auth_req_id` (CodeQL hygiene, W5 F4 review).
        assert!(a != b, "two ids are distinct");
        assert_eq!(a.len(), 43, "256 bits, base64url unpadded");
        assert_eq!(hash_auth_req_id(&a).len(), 64);
        assert!(hash_auth_req_id(&a) != a, "the digest is not the id");
    }

    /// The rate-limit table's three statements, in memory, with the
    /// datastore's semantics: the windowed upsert (a newer window resets the
    /// bucket, an older one adds to the stored window), the plain read, and
    /// the conditional take-back (only while the bucket holds the window
    /// named, never below zero, never creating a bucket). Each statement
    /// yields first, so concurrent calls interleave between statements as
    /// they do against the datastore; each is atomic, as one statement on one
    /// record is.
    #[derive(Default)]
    struct MemStore(std::sync::Mutex<std::collections::HashMap<String, (DateTime<Utc>, u64)>>);

    impl axiam_db::SharedRateLimitStore for MemStore {
        fn increment_by<'a>(
            &'a self,
            key: &'a str,
            window_start: DateTime<Utc>,
            delta: u64,
        ) -> axiam_db::StoreIncrementFuture<'a> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                let mut map = self.0.lock().unwrap();
                let entry = map.entry(key.to_owned()).or_insert((window_start, 0));
                if entry.0 < window_start {
                    *entry = (window_start, 0);
                }
                entry.1 += delta;
                Ok(entry.1)
            })
        }

        fn peek_bucket<'a>(&'a self, key: &'a str) -> axiam_db::StorePeekFuture<'a> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(self.0.lock().unwrap().get(key).copied())
            })
        }

        fn decrement<'a>(
            &'a self,
            key: &'a str,
            window_start: DateTime<Utc>,
        ) -> axiam_db::StoreDecrementFuture<'a> {
            Box::pin(async move {
                tokio::task::yield_now().await;
                match self.0.lock().unwrap().get_mut(key) {
                    Some((stored, count)) if *stored == window_start && *count > 0 => {
                        *count -= 1;
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            })
        }
    }

    /// The "deployment secret" every replica in a test shares: random per
    /// process, stable within one, so no key-shaped literal sits in the source.
    fn deployment_secret() -> &'static [u8] {
        static SECRET: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
        SECRET.get_or_init(|| {
            let mut secret = [0u8; 32];
            secret[..16].copy_from_slice(Uuid::new_v4().as_bytes());
            secret[16..].copy_from_slice(Uuid::new_v4().as_bytes());
            secret
        })
    }

    fn cap() -> (CibaHintCap, std::sync::Arc<MemStore>) {
        let store = std::sync::Arc::new(MemStore::default());
        (
            CibaHintCap::derived_from(store.clone(), deployment_secret()),
            store,
        )
    }

    /// A window's start, `offset` seconds into window `index`.
    fn at(index: i64, offset: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(index * HINT_CAP_WINDOW_SECS as i64 + offset, 0).unwrap()
    }

    /// #599: the cap counts calls per (tenant, client, hint), whatever the
    /// hint names, and the fourth in a window is refused.
    #[tokio::test]
    async fn the_hint_cap_refuses_the_fourth_call_for_one_hint() {
        let (cap, _) = cap();
        let tenant = Uuid::new_v4();
        let hint = HintName::Login("nobody-at-all".into());
        let t = at(1000, 10);
        for _ in 0..3 {
            assert!(cap.admit(tenant, "oa_a", &hint, t).await.unwrap());
        }
        assert!(!cap.admit(tenant, "oa_a", &hint, t).await.unwrap());
        // Another client, another hint, another tenant: their own counts.
        assert!(cap.admit(tenant, "oa_b", &hint, t).await.unwrap());
        let other = HintName::Login("someone-else".into());
        assert!(cap.admit(tenant, "oa_a", &other, t).await.unwrap());
        assert!(cap.admit(Uuid::new_v4(), "oa_a", &hint, t).await.unwrap());
        // An ID token's subject is a hint of its own, whatever token carries it.
        let sub = HintName::Subject(Uuid::new_v4());
        for _ in 0..3 {
            assert!(cap.admit(tenant, "oa_a", &sub, t).await.unwrap());
        }
        assert!(!cap.admit(tenant, "oa_a", &sub, t).await.unwrap());
    }

    /// The window before counts too, so no window-long stretch admits more
    /// than three; the window after that starts afresh.
    #[tokio::test]
    async fn the_hint_cap_bounds_every_window_long_stretch() {
        let (cap, _) = cap();
        let tenant = Uuid::new_v4();
        let hint = HintName::Login("alice".into());
        let late = HINT_CAP_WINDOW_SECS as i64 - 1;
        for _ in 0..3 {
            assert!(cap.admit(tenant, "oa_a", &hint, at(7, late)).await.unwrap());
        }
        // One second later is the next window, but the stretch holds three.
        assert!(!cap.admit(tenant, "oa_a", &hint, at(8, 0)).await.unwrap());
        assert!(!cap.admit(tenant, "oa_a", &hint, at(8, late)).await.unwrap());
        // Window 9's odd bucket held window 7 and starts over; window 8 is the
        // window before it, and its two refused calls were taken back (#639),
        // so window 9 has the whole allowance.
        for offset in 0..3 {
            assert!(
                cap.admit(tenant, "oa_a", &hint, at(9, offset))
                    .await
                    .unwrap()
            );
        }
        assert!(!cap.admit(tenant, "oa_a", &hint, at(9, 5)).await.unwrap());
        // A hint left alone for a whole window starts afresh.
        for _ in 0..3 {
            assert!(cap.admit(tenant, "oa_a", &hint, at(11, 0)).await.unwrap());
        }
        assert!(!cap.admit(tenant, "oa_a", &hint, at(11, 1)).await.unwrap());

        // A quiet hint: three in one window, three again two windows on.
        let quiet = HintName::Login("bob".into());
        for _ in 0..3 {
            assert!(cap.admit(tenant, "oa_a", &quiet, at(20, 5)).await.unwrap());
        }
        for _ in 0..3 {
            assert!(cap.admit(tenant, "oa_a", &quiet, at(22, 5)).await.unwrap());
        }
    }

    /// The buckets name neither the hint nor the client, and a different
    /// deployment secret gives different buckets; two per hint, by parity.
    #[tokio::test]
    async fn the_hint_cap_buckets_are_keyed_digests() {
        let (cap, store) = cap();
        let tenant = Uuid::new_v4();
        let hint = HintName::Login("alice@example.com".into());
        let bucket = cap.bucket(tenant, "oa_client", &hint);
        assert!(bucket.starts_with(&format!("ciba_hint_cap:{tenant}:")));
        assert!(!bucket.contains("alice") && !bucket.contains("oa_client"));
        let other = CibaHintCap::derived_from(
            std::sync::Arc::new(MemStore::default()),
            // A secret that is not the shared one, so the buckets must differ.
            Uuid::new_v4().as_bytes(),
        );
        assert!(other.bucket(tenant, "oa_client", &hint) != bucket);
        // "login" "x" and "sub" "x" never share a bucket.
        let sub = Uuid::new_v4();
        assert!(
            cap.bucket(tenant, "c", &HintName::Login(sub.to_string()))
                != cap.bucket(tenant, "c", &HintName::Subject(sub))
        );
        for i in 0..5 {
            cap.admit(tenant, "oa_client", &hint, at(i, 0))
                .await
                .unwrap();
        }
        let keys: Vec<String> = store.0.lock().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 2, "{keys:?}");
    }

    /// #638: the first call for a hint writes one bucket, the current
    /// window's; reading the previous window's creates none. The second
    /// bucket exists only once a later window has counted a call.
    #[tokio::test]
    async fn a_new_hint_writes_one_bucket() {
        let (cap, store) = cap();
        let tenant = Uuid::new_v4();
        let hint = HintName::Login("carol".into());
        assert!(cap.admit(tenant, "oa_a", &hint, at(40, 3)).await.unwrap());
        assert_eq!(store.0.lock().unwrap().len(), 1);
        assert!(cap.admit(tenant, "oa_a", &hint, at(40, 4)).await.unwrap());
        assert_eq!(store.0.lock().unwrap().len(), 1, "same window, same row");
        assert!(cap.admit(tenant, "oa_a", &hint, at(41, 0)).await.unwrap());
        assert_eq!(store.0.lock().unwrap().len(), 2, "the next window's own");
    }
    /// #639: the allowance is the configured one. With the knob at four, a
    /// fourth call is admitted and a fifth refused; at one, a second is.
    #[tokio::test]
    async fn the_allowance_is_the_configured_one() {
        let (cap, store) = cap();
        let four = cap.with_per_hint(std::num::NonZeroU32::new(4).unwrap());
        let tenant = Uuid::new_v4();
        let hint = HintName::Login("conformance-user".into());
        for _ in 0..4 {
            assert!(four.admit(tenant, "oa_a", &hint, at(60, 1)).await.unwrap());
        }
        assert!(!four.admit(tenant, "oa_a", &hint, at(60, 2)).await.unwrap());

        let one = CibaHintCap::derived_from(store, deployment_secret())
            .with_per_hint(std::num::NonZeroU32::new(1).unwrap());
        let other = HintName::Login("someone".into());
        assert!(one.admit(tenant, "oa_a", &other, at(60, 1)).await.unwrap());
        assert!(!one.admit(tenant, "oa_a", &other, at(60, 2)).await.unwrap());
        // The shipped allowance is the default.
        let shipped = CibaHintCap::new(std::sync::Arc::new(MemStore::default()), [0; 32]);
        assert_eq!(
            shipped.per_hint,
            u64::from(DEFAULT_REQUESTS_PER_CLIENT_HINT)
        );
    }

    /// #639: a refused call does not consume the allowance. Retrying through
    /// the window after a used allowance (when every call is refused) leaves
    /// that window's count at zero, so the window after it is admitted in
    /// full; under the old rule those refusals counted, and the retrying
    /// client stayed refused.
    #[tokio::test]
    async fn refused_calls_do_not_consume_the_allowance() {
        let (cap, store) = cap();
        let tenant = Uuid::new_v4();
        let hint = HintName::Login("retrying".into());
        for _ in 0..3 {
            assert!(cap.admit(tenant, "oa_a", &hint, at(50, 0)).await.unwrap());
        }
        for offset in 1..6 {
            assert!(
                !cap.admit(tenant, "oa_a", &hint, at(50, offset))
                    .await
                    .unwrap()
            );
        }
        let bucket = cap.bucket(tenant, "oa_a", &hint);
        let count = |parity: u8| store.0.lock().unwrap()[&format!("{bucket}:{parity}")].1;
        assert_eq!(count(0), 3, "refusals in the window took their count back");
        // Window 51 has window 50's three behind it: every call is refused.
        for offset in 0..10 {
            assert!(
                !cap.admit(tenant, "oa_a", &hint, at(51, offset * 50))
                    .await
                    .unwrap()
            );
        }
        assert_eq!(count(1), 0, "window 51's refusals are not counted");
        // Window 52: window 51 is the one before it and holds nothing, so the
        // first call is admitted at once, and the allowance is whole.
        for offset in 0..3 {
            assert!(
                cap.admit(tenant, "oa_a", &hint, at(52, offset))
                    .await
                    .unwrap()
            );
        }
        assert!(!cap.admit(tenant, "oa_a", &hint, at(52, 9)).await.unwrap());
    }

    /// Runs `stamps.len()` concurrent calls for one hint, alternating between
    /// two replicas' caps over one store (each with the allowance `per_hint`),
    /// and answers which were admitted, by stamp.
    async fn concurrent_calls(
        store: std::sync::Arc<dyn axiam_db::SharedRateLimitStore>,
        per_hint: u32,
        stamps: &[DateTime<Utc>],
    ) -> Vec<(DateTime<Utc>, Result<bool, String>)> {
        let per_hint = std::num::NonZeroU32::new(per_hint).unwrap();
        let replicas = [
            CibaHintCap::derived_from(store.clone(), deployment_secret()).with_per_hint(per_hint),
            CibaHintCap::derived_from(store, deployment_secret()).with_per_hint(per_hint),
        ];
        let tenant = Uuid::from_u128(7);
        let hint = HintName::Login("contended".into());
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(stamps.len()));
        let tasks: Vec<_> = stamps
            .iter()
            .enumerate()
            .map(|(i, stamp)| {
                let cap = replicas[i % 2].clone();
                let hint = hint.clone();
                let barrier = barrier.clone();
                let stamp = *stamp;
                tokio::spawn(async move {
                    barrier.wait().await;
                    let admitted = cap.admit(tenant, "oa_a", &hint, stamp).await;
                    (stamp, admitted.map_err(|e| e.to_string()))
                })
            })
            .collect();
        let mut out = Vec::new();
        for task in tasks {
            out.push(task.await.unwrap());
        }
        out
    }

    /// #639: N concurrent calls in one window, on two replicas, against an
    /// allowance of k admit exactly k — never more (two calls that both see
    /// k − 1 cannot both be admitted) and, with nothing else in flight, no
    /// fewer — and leave the count at k. Repeated, so that many interleavings
    /// are tried.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_calls_admit_at_most_the_allowance() {
        for round in 0..200 {
            let store = std::sync::Arc::new(MemStore::default());
            let stamps = vec![at(70, 3); 12];
            let admitted = concurrent_calls(store.clone(), 4, &stamps).await;
            let n = admitted.iter().filter(|(_, ok)| *ok == Ok(true)).count();
            assert_eq!(n, 4, "round {round}: {admitted:?}");
            let counts: Vec<u64> = store.0.lock().unwrap().values().map(|v| v.1).collect();
            assert_eq!(counts, [4], "round {round}: refusals took their count back");
        }
    }

    /// #639: concurrent calls straddling a window boundary — a third stamped
    /// at the start of window 81, the rest at the end of window 80, on two
    /// replicas, with two calls already admitted at the end of window 79 —
    /// keep both pairs of windows within k, whatever the interleaving. The
    /// pair (79, 80) is the one a late call could break: a call of window 80
    /// reads window 79 in the bucket window 81 takes over, so once a call of
    /// window 81 has counted itself, a call of window 80 that comes to read is
    /// overtaken and refused rather than admitted against window 81's count.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_calls_across_a_boundary_admit_at_most_the_allowance() {
        let late = HINT_CAP_WINDOW_SECS as i64 - 1;
        for round in 0..300 {
            let store = std::sync::Arc::new(MemStore::default());
            let before = concurrent_calls(store.clone(), 4, &[at(79, late); 2]).await;
            assert!(before.iter().all(|(_, ok)| *ok == Ok(true)));
            let stamps: Vec<DateTime<Utc>> = (0..12)
                .map(|i| if i % 3 == 0 { at(81, 0) } else { at(80, late) })
                .collect();
            let admitted = concurrent_calls(store.clone(), 4, &stamps).await;
            let in_window = |stamp: DateTime<Utc>| {
                admitted
                    .iter()
                    .filter(|(s, ok)| *ok == Ok(true) && *s == stamp)
                    .count()
            };
            let (w80, w81) = (in_window(at(80, late)), in_window(at(81, 0)));
            assert!(2 + w80 <= 4, "round {round}: (79, 80): {admitted:?}");
            assert!(w80 + w81 <= 4, "round {round}: (80, 81): {admitted:?}");
            // Window 81 took over window 79's bucket; what is left counted is
            // exactly what windows 80 and 81 admitted.
            let counted: u64 = store.0.lock().unwrap().values().map(|v| v.1).sum();
            assert_eq!(counted, (w80 + w81) as u64, "round {round}");
        }
    }

    /// #639: the same bound against the datastore's own statements — the
    /// in-memory engine, two replicas' repositories over one database.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_bound_holds_against_the_datastore_under_concurrency() {
        let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
            .await
            .unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let late = HINT_CAP_WINDOW_SECS as i64 - 1;
        for round in 0..20 {
            let store: std::sync::Arc<dyn axiam_db::SharedRateLimitStore> =
                std::sync::Arc::new(axiam_db::SurrealRateLimitBucketRepository::new(db.clone()));
            // A window of its own per round, so rounds do not see each other.
            let stamps = vec![at(1000 + 4 * round, 3); 10];
            let admitted = concurrent_calls(store.clone(), 4, &stamps).await;
            let n = admitted.iter().filter(|(_, ok)| *ok == Ok(true)).count();
            assert!(n <= 4, "round {round}: {admitted:?}");
            // A call whose write conflict outlived its retries fails with
            // `server_error` and admits nothing; with none, exactly four.
            if admitted.iter().all(|(_, ok)| ok.is_ok()) {
                assert_eq!(n, 4, "round {round}: {admitted:?}");
            }

            let stamps: Vec<DateTime<Utc>> = (0..10)
                .map(|i| {
                    if i % 2 == 0 {
                        at(1002 + 4 * round, 0)
                    } else {
                        at(1001 + 4 * round, late)
                    }
                })
                .collect();
            let admitted = concurrent_calls(store, 4, &stamps).await;
            let n = admitted.iter().filter(|(_, ok)| *ok == Ok(true)).count();
            // Window 1001's previous is window 1000, which holds four: none of
            // its calls can be admitted, and window 1002's may take up to four.
            assert!(n <= 4, "round {round}: {admitted:?}");
            assert!(
                admitted
                    .iter()
                    .all(|(stamp, ok)| *ok != Ok(true) || *stamp == at(1002 + 4 * round, 0)),
                "round {round}: {admitted:?}"
            );
        }
    }
}

//! The FAPI 2.0 profile switch (X5.1).
//!
//! FAPI 2.0 Security Profile (Final) is not one feature. It is a bundle of
//! constraints, and a client that satisfies eleven of twelve is not
//! "mostly FAPI" — it is a client with a hole. This module is where the bundle
//! is defined once, so that:
//!
//! - an operator turns the whole posture on with **one field**
//!   (`profile: "fapi2"`), exactly as the rate-limit postures work; and
//! - **ordinary clients are untouched.** Every function here is a no-op for
//!   [`ClientProfile::Standard`], which is the serde default and what every
//!   row written before schema v38 decodes to. There is no behaviour change
//!   for a deployment that never sets the flag — that is a property the tests
//!   at the bottom of this file assert directly, not an aspiration.
//!
//! # What the switch actually requires
//!
//! | Constraint | Where enforced | FAPI 2.0 §|
//! |---|---|---|
//! | PAR mandatory | `require_par` forced true at registration; `authorize` refuses a direct request | 5.3.1.2 |
//! | PKCE with `S256` mandatory | [`enforce_authorization_request`]; `S256`-only is already global | 5.3.1.2 |
//! | `response_type=code` only | already global in `authorize` — no other value is accepted for any client | 5.3.1.1 |
//! | Strong client authentication | [`validate_registration`] requires an mTLS method **or** `private_key_jwt` | 5.3.1.1 |
//! | Sender-constrained tokens | [`validate_registration`] requires certificate binding **or** DPoP | 5.3.1.1 |
//! | Strict `redirect_uri` equality | already global — `redirect_uris.contains()`, no prefix or wildcard matching anywhere | 5.3.1.2 |
//! | Authorization code single-use | already global, and since #318/schema v37 guaranteed by a transaction plus a post-commit nonce read-back | 5.3.1.2 |
//! | No token in any URL | already global — `response_type=token` does not exist in this server | 5.3.1.1 |
//! | EdDSA/PS256/ES256, never `none` | already global — `Algorithm::EdDSA` is hard-coded at both encode and decode | 5.3.1.1 |
//!
//! Four of those nine rows say "already global". That is the honest reading of
//! the tree and the reason X5.1's gap table listed them as *audit* items
//! rather than *work* items: AXIAM never implemented the relaxations FAPI
//! forbids. What this module adds is the machinery for the five that were
//! genuinely absent, plus tests that pin the four so a later convenience
//! change cannot quietly reintroduce one.
//!
//! # Registration-time, not just request-time
//!
//! The heavy lifting is [`validate_registration`], which refuses to *create* a
//! FAPI client that could not satisfy the profile. Enforcing only at request
//! time would leave a registered client that answers `invalid_request` to
//! every request it ever makes — a configuration error discovered by the
//! client's users rather than by the operator who made it. Request-time checks
//! remain as defence in depth, because a row edited directly in the database
//! never passes through registration validation.
//!
//! # Two families, two mechanisms, and the pairing rule
//!
//! FAPI 2.0 §5.3.1.1 asks two independent questions, and each has two
//! acceptable answers:
//!
//! | | mutual TLS | asymmetric JWT |
//! |---|---|---|
//! | **Client authentication** | `tls_client_auth`, `self_signed_tls_client_auth` (RFC 8705 §2) | `private_key_jwt` (RFC 7523 §2.2) |
//! | **Sender-constraining** | `tls_client_certificate_bound_access_tokens` (RFC 8705 §3) | `dpop_bound_access_tokens` (RFC 9449) |
//!
//! All four pairings are legitimate, and the gate accepts all four. The profile
//! does **not** require the two columns to match: a client may authenticate
//! with `private_key_jwt` and bind its tokens to a certificate, or authenticate
//! with mTLS and bind with DPoP. What it requires is one answer from each *row*,
//! and [`validate_registration`] refuses a client that has authentication from
//! one family and sender-constraining from neither — which is the shape a
//! half-finished migration produces and the one an operator is most likely to
//! create by accident.
//!
//! # The second lane, and why its gates live here too (X7.1)
//!
//! AXIAM now has two profiles that answer the same question differently: FAPI
//! 2.0, and the OpenID Connect "Basic OP" lane that reads the authentication-
//! request parameters (`prompt`, `max_age`, `acr_values`, `claims`,
//! `id_token_hint`, and the four display hints). Its opt-in is one per-client
//! field, [`AuthnRequestParamsMode`], for the same reason `profile` is one
//! field: a client that honours `max_age` but ignores `prompt=none` is not
//! "mostly conformant", it is a client a relying party cannot reason about.
//!
//! Its gates are **here**, not in a module of their own, because they are the
//! same two-layer mechanism enforcing a mutual exclusion between the two
//! lanes, and splitting them would leave two places that each believe they
//! decide what a `fapi2` client may send:
//!
//! | Constraint | Registration | Request time |
//! |---|---|---|
//! | `fapi2` may not say `honour` | [`FapiRegistrationError::AuthnParamsOnFapiClient`] | refused + `error!`, as the row must have been edited in the database |
//! | `fapi2` may not send the five *security-bearing* parameters | — (they are per-request) | `invalid_request`, naming each |
//! | `fapi2` may not register `address`/`phone` | [`FapiRegistrationError::SensitiveScopesOnFapiClient`] | (userinfo release, a later wave) |
//!
//! Two asymmetries in that table are deliberate. The four *cosmetic*
//! parameters are not refused on an honest `fapi2` row — client libraries send
//! `login_hint` by reflex, and refusing it would break working clients for no
//! security property. And `browser_sso` is not refused on any profile: it
//! decides how an *anonymous* browser is answered and relaxes nothing.
//!
//! As everywhere else in this module, all of it is a no-op for a `standard`
//! client, which is every client registered today. That is invariant 4 of
//! `claude_dev/basic-op-gap-plan.md`, and like the X5.1 properties above it is
//! asserted by tests at the bottom of this file rather than hoped for.

use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, OAuth2Client,
};

use crate::authn_params::AuthnRequestParams;
use crate::error::OAuth2Error;

/// Why a client registration cannot satisfy the profile it asked for.
///
/// A typed error rather than a string so the REST layer can render it as a
/// 400 with a field-specific message, and so a test can assert *which*
/// constraint failed rather than pattern-matching prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FapiRegistrationError {
    /// FAPI 2.0 requires PAR for every authorization request.
    ParNotRequired,
    /// FAPI 2.0 requires `private_key_jwt` or mTLS client authentication.
    /// AXIAM implements both families; this is a client registered with
    /// neither — that is, with a shared secret.
    WeakClientAuth { method: ClientAuthMethod },
    /// FAPI 2.0 requires sender-constrained access tokens.
    TokensNotSenderConstrained,
    /// `tls_client_auth` needs exactly one registered subject DN or SAN
    /// (RFC 8705 §2.1.2).
    MtlsBindingCount { registered: usize },
    /// `self_signed_tls_client_auth` needs at least one registered thumbprint.
    NoSelfSignedThumbprint,
    /// A registered thumbprint is not a base64url-unpadded SHA-256 digest, so
    /// it can never match a real certificate.
    MalformedThumbprint { value: String },
    /// `private_key_jwt` needs exactly one key source: an inline `jwks` or a
    /// `jwks_uri` (RFC 7591 §2), never both and never neither.
    JwksSourceCount { registered: usize },
    /// A registered `jwks` document is not a parseable JWK Set, so no assertion
    /// signed by the client could ever be verified against it.
    MalformedJwks { detail: String },
    /// A registered `jwks_uri` is not an absolute `https` URL.
    InsecureJwksUri { value: String },
    /// X7.1 — a `fapi2` client asked to honour the OIDC
    /// authentication-request parameters.
    ///
    /// The bundle is the Basic-OP lane's mechanism, and FAPI 2.0 clients do
    /// not send its parameters (the FAPI conformance plans run
    /// `openid: plain_oauth`). Permitting it on a `fapi2` row would mean a
    /// client whose posture answers two different questions depending on
    /// which parameter arrived.
    AuthnParamsOnFapiClient,
    /// X7 G8 — a `fapi2` client registered a GDPR-sensitive scope.
    ///
    /// `address` and `phone` release personal data AXIAM has no consent
    /// record for on the FAPI lane, and FAPI 2.0's whole argument is that the
    /// data a token reaches is the data the client was authorised for.
    SensitiveScopesOnFapiClient { scopes: Vec<String> },
}

/// The scopes X7 G8 treats as GDPR-sensitive, refused on a `fapi2` row.
///
/// OIDC Core §5.4 defines both; each releases a category of personal data
/// (a postal address, a telephone number) that is not derivable from anything
/// AXIAM already discloses under `profile` or `email`.
pub const SENSITIVE_SCOPES: [&str; 2] = ["address", "phone"];

impl std::fmt::Display for FapiRegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParNotRequired => write!(
                f,
                "a fapi2 client must set require_par: FAPI 2.0 §5.3.1.2 requires pushed \
                 authorization requests"
            ),
            Self::WeakClientAuth { method } => write!(
                f,
                "a fapi2 client may not authenticate with {}: FAPI 2.0 §5.3.1.1 requires \
                 private_key_jwt or mutual-TLS client authentication (use tls_client_auth or \
                 self_signed_tls_client_auth)",
                method.as_str()
            ),
            Self::TokensNotSenderConstrained => write!(
                f,
                "a fapi2 client must set tls_client_certificate_bound_access_tokens: FAPI 2.0 \
                 §5.3.1.1 requires sender-constrained access tokens"
            ),
            Self::MtlsBindingCount { registered } => write!(
                f,
                "tls_client_auth requires exactly one of tls_client_auth_subject_dn, \
                 tls_client_auth_san_dns or tls_client_auth_san_uri (RFC 8705 §2.1.2); \
                 {registered} were registered"
            ),
            Self::NoSelfSignedThumbprint => write!(
                f,
                "self_signed_tls_client_auth requires at least one registered certificate \
                 thumbprint in self_signed_tls_client_auth_thumbprints"
            ),
            Self::MalformedThumbprint { value } => write!(
                f,
                "{value:?} is not a valid x5t#S256 thumbprint: expected 43 base64url \
                 characters (an unpadded SHA-256 digest, RFC 8705 §3.1)"
            ),
            Self::JwksSourceCount { registered } => write!(
                f,
                "private_key_jwt requires exactly one of jwks or jwks_uri (RFC 7591 §2); \
                 {registered} were registered"
            ),
            Self::MalformedJwks { detail } => write!(
                f,
                "the registered jwks is not a parseable JWK Set ({detail}); no client assertion \
                 could ever be verified against it"
            ),
            Self::InsecureJwksUri { value } => write!(
                f,
                "jwks_uri {value:?} must be an absolute https URL: AXIAM fetches it to obtain \
                 the keys that authenticate this client, and a plaintext or relative URL makes \
                 that credential rewritable in transit"
            ),
            Self::AuthnParamsOnFapiClient => write!(
                f,
                "a fapi2 client may not set authn_request_params: honour: the OpenID Connect \
                 authentication-request parameters (prompt, max_age, acr_values, claims, \
                 id_token_hint and the display hints) belong to the standard lane, and a \
                 fapi2 client is refused them at the authorization endpoint as well"
            ),
            Self::SensitiveScopesOnFapiClient { scopes } => write!(
                f,
                "a fapi2 client may not register the scope(s) {}: address and phone release \
                 personal data under a consent record the fapi2 lane does not collect",
                scopes.join(", ")
            ),
        }
    }
}

impl std::error::Error for FapiRegistrationError {}

impl From<FapiRegistrationError> for OAuth2Error {
    fn from(e: FapiRegistrationError) -> Self {
        OAuth2Error::InvalidRequest(e.to_string())
    }
}

/// Length of a base64url-unpadded SHA-256 digest: ceil(32 * 4 / 3) = 43.
const THUMBPRINT_LEN: usize = 43;

/// Whether a string could be an `x5t#S256` value at all.
///
/// Checked at registration rather than at authentication, because a
/// thumbprint that can never match is a typo an operator wants to hear about
/// while they are onboarding the client — not six weeks later as an
/// unexplained `invalid_client`. A padded or standard-base64 value is the
/// common form of this mistake, and both are rejected here by construction:
/// `=`, `+` and `/` are not in the base64url alphabet.
fn is_wellformed_thumbprint(value: &str) -> bool {
    value.len() == THUMBPRINT_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The registration fields the profile rules actually look at.
///
/// A borrowed view rather than an `OAuth2Client`, so the **same** rules run
/// against a pending `CreateOAuth2Client` (before anything is written), a
/// merged `UpdateOAuth2Client` (before the write lands), and a stored
/// `OAuth2Client` (as a runtime audit). Validating only the stored form would
/// mean creating an impossible client and then telling the operator about it —
/// or worse, leaving it created.
#[derive(Debug, Clone, Copy)]
pub struct RegistrationView<'a> {
    pub profile: ClientProfile,
    pub token_endpoint_auth_method: ClientAuthMethod,
    pub require_par: bool,
    pub tls_client_certificate_bound_access_tokens: bool,
    /// Result of `axiam_core::models::oauth2_client::count_mtls_bindings`.
    pub mtls_binding_count: usize,
    pub self_signed_thumbprints: &'a [String],
    /// Result of `axiam_core::models::oauth2_client::count_jwks_sources`.
    pub jwks_source_count: usize,
    pub jwks: Option<&'a str>,
    pub jwks_uri: Option<&'a str>,
    pub dpop_bound_access_tokens: bool,
    /// X7.1 — whether this client asked to honour the OIDC
    /// authentication-request parameters.
    pub authn_request_params: AuthnRequestParamsMode,
    /// X7 G8 — the registered scopes, read only for the sensitive-scope arm.
    pub scopes: &'a [String],
}

impl<'a> From<&'a OAuth2Client> for RegistrationView<'a> {
    fn from(c: &'a OAuth2Client) -> Self {
        Self {
            profile: c.profile,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            require_par: c.require_par,
            tls_client_certificate_bound_access_tokens: c
                .tls_client_certificate_bound_access_tokens,
            mtls_binding_count: c.mtls_binding_count(),
            self_signed_thumbprints: &c.self_signed_tls_client_auth_thumbprints,
            jwks_source_count: c.jwks_source_count(),
            jwks: c.jwks.as_deref(),
            jwks_uri: c.jwks_uri.as_deref(),
            dpop_bound_access_tokens: c.dpop_bound_access_tokens,
            authn_request_params: c.authn_request_params,
            scopes: &c.scopes,
        }
    }
}

impl<'a> From<&'a CreateOAuth2Client> for RegistrationView<'a> {
    fn from(c: &'a CreateOAuth2Client) -> Self {
        Self {
            profile: c.profile,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            require_par: c.require_par,
            tls_client_certificate_bound_access_tokens: c
                .tls_client_certificate_bound_access_tokens,
            mtls_binding_count: c.mtls_binding_count(),
            self_signed_thumbprints: &c.self_signed_tls_client_auth_thumbprints,
            jwks_source_count: c.jwks_source_count(),
            jwks: c.jwks.as_deref(),
            jwks_uri: c.jwks_uri.as_deref(),
            dpop_bound_access_tokens: c.dpop_bound_access_tokens,
            authn_request_params: c.authn_request_params,
            scopes: &c.scopes,
        }
    }
}

/// Validate a client registration against the profile it declares.
///
/// Runs for **every** registration, not only FAPI ones: the RFC 8705 checks
/// (exactly one `tls_client_auth_*` parameter, well-formed thumbprints) apply
/// to any client using an mTLS method, whatever its profile. The FAPI-specific
/// requirements are gated on [`ClientProfile::Fapi2`].
///
/// A `standard` client registered with `client_secret_post` — that is, every
/// client that existed before X5.1 — passes without a single check running
/// against it.
pub fn validate_registration<'a>(
    reg: impl Into<RegistrationView<'a>>,
) -> Result<(), FapiRegistrationError> {
    let reg = reg.into();

    // --- RFC 8705 / RFC 7591 consistency, for any client using a strong
    //     method, whatever its profile ---------------------------------------
    match reg.token_endpoint_auth_method {
        ClientAuthMethod::TlsClientAuth => {
            if reg.mtls_binding_count != 1 {
                return Err(FapiRegistrationError::MtlsBindingCount {
                    registered: reg.mtls_binding_count,
                });
            }
        }
        ClientAuthMethod::SelfSignedTlsClientAuth => {
            if reg.self_signed_thumbprints.is_empty() {
                return Err(FapiRegistrationError::NoSelfSignedThumbprint);
            }
        }
        ClientAuthMethod::PrivateKeyJwt => {
            // RFC 7591 §2 permits `jwks` **or** `jwks_uri`. Neither leaves a
            // client that can authenticate nothing; both leaves a client whose
            // credential is the union of a document it controls and one it
            // publishes, which is two answers to a question that has one.
            if reg.jwks_source_count != 1 {
                return Err(FapiRegistrationError::JwksSourceCount {
                    registered: reg.jwks_source_count,
                });
            }
        }
        ClientAuthMethod::ClientSecretPost => {}
    }

    // Thumbprints are validated whenever any are registered, even under
    // `tls_client_auth` where they are unused: a malformed value sitting in
    // the row is a landmine for the day somebody switches the method.
    for t in reg.self_signed_thumbprints {
        if !is_wellformed_thumbprint(t) {
            return Err(FapiRegistrationError::MalformedThumbprint { value: t.clone() });
        }
    }

    // Key material is validated on the same principle, and for the same reason
    // the thumbprint check exists: an operator wants to hear about an unparseable
    // JWKS while they are onboarding the client, not six weeks later as an
    // unexplained `invalid_client` that the wire response is deliberately unable
    // to explain.
    if let Some(raw) = non_blank(reg.jwks)
        && let Err(e) = serde_json::from_str::<jsonwebtoken::jwk::JwkSet>(raw)
    {
        return Err(FapiRegistrationError::MalformedJwks {
            detail: e.to_string(),
        });
    }
    if let Some(uri) = non_blank(reg.jwks_uri)
        && !is_https_absolute(uri)
    {
        return Err(FapiRegistrationError::InsecureJwksUri {
            value: uri.to_owned(),
        });
    }

    // --- the profile bundle -----------------------------------------------
    if !reg.profile.is_fapi2() {
        return Ok(());
    }

    if !reg.require_par {
        return Err(FapiRegistrationError::ParNotRequired);
    }
    // Either family satisfies §5.3.1.1. `is_strong` is asked rather than the
    // two methods enumerated, so a future third strong method joins the profile
    // by answering one question rather than by being added at every gate.
    if !reg.token_endpoint_auth_method.is_strong() {
        return Err(FapiRegistrationError::WeakClientAuth {
            method: reg.token_endpoint_auth_method,
        });
    }
    // Likewise either sender-constraining mechanism. A client with strong
    // authentication and *neither* constraint is the shape a half-finished
    // migration produces, and it is refused rather than served: the profile's
    // whole security argument is that a stolen token is inert.
    if !reg.tls_client_certificate_bound_access_tokens && !reg.dpop_bound_access_tokens {
        return Err(FapiRegistrationError::TokensNotSenderConstrained);
    }
    // X7.1. The Basic-OP lane's opt-in and the FAPI posture are two answers to
    // the same question — what does an authorization request from this client
    // mean — so a row may hold at most one of them. Refusing here rather than
    // only at request time is the same argument the whole module rests on: a
    // registration that could never be served is a configuration error the
    // operator should hear about now, not one the client's users discover.
    if reg.authn_request_params.is_honour() {
        return Err(FapiRegistrationError::AuthnParamsOnFapiClient);
    }
    // X7 G8. Checked last of the bundle because it is the only arm that names
    // values rather than a flag, and an operator fixing several problems at
    // once is better served by hearing about the structural ones first.
    let sensitive: Vec<String> = reg
        .scopes
        .iter()
        .filter(|s| SENSITIVE_SCOPES.contains(&s.trim()))
        .map(|s| s.trim().to_owned())
        .collect();
    if !sensitive.is_empty() {
        return Err(FapiRegistrationError::SensitiveScopesOnFapiClient { scopes: sensitive });
    }

    Ok(())
}

/// A registered value counts only when it is present and non-blank — the same
/// emptiness rule `count_jwks_sources` applies, so the counter and the
/// validators cannot disagree about whether `Some("  ")` is registered.
fn non_blank(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Whether a `jwks_uri` is an absolute `https` URL.
///
/// Deliberately a prefix check rather than a URL parse. This is a registration
/// guard, not the fetch guard: the fetch goes through
/// `axiam_federation::jwks_cache`, which resolves, applies the SEC-054
/// private-network classifier, and pins the validated IP into the connection.
/// Duplicating a URL parser here would add a second, weaker opinion about what
/// a URL means, and the failure mode of the two disagreeing is the interesting
/// one. What this catches is the operator mistake — `http://`, or a relative
/// path — at the moment it is made.
fn is_https_absolute(uri: &str) -> bool {
    uri.len() > "https://".len() && uri[.."https://".len()].eq_ignore_ascii_case("https://")
}

/// Request-time gate on the authorization endpoint (X5.1, X7.1).
///
/// Three things, in the order the plan's §3.3 sets out, all of them before any
/// redirectable error the authorization service would otherwise raise:
///
/// 1. **PKCE** is mandatory under the FAPI profile. AXIAM requires PKCE for
///    *public* clients (SEC-025) and accepts only `S256` from anybody, so the
///    remaining gap is a confidential client omitting `code_challenge`.
/// 2. **A `fapi2` client is refused the security-bearing authentication-request
///    parameters** (X7.1) — `prompt`, `max_age`, `acr_values`, `claims`,
///    `id_token_hint`. Refusing rather than ignoring is the point: ignoring
///    `max_age` tells a relying party it got a freshness guarantee it did not
///    get, and *that* silent downgrade is what this whole gate exists to
///    prevent. A conforming FAPI 2.0 relying party sends none of the five (the
///    FAPI conformance plans run `openid: plain_oauth`), so no client that
///    passes the FAPI plan today observes this.
/// 3. **A `fapi2` row that says `honour`** cannot have passed
///    [`validate_registration`], so it was edited in the database. Refused and
///    logged at `error!`, mirroring [`enforce_token_request`]'s existing
///    defence-in-depth branch.
///
/// The four *cosmetic* parameters (`login_hint`, `display`, `ui_locales`,
/// `claims_locales`) are **not** refused on an honest `fapi2` row. Client
/// libraries send `login_hint` by reflex; refusing it would break working FAPI
/// clients for no security property, and their mechanism — a prefilled form, a
/// locale, a layout — is reached only through a redirect the server builds on
/// the honour lane and therefore never builds for a `fapi2` client.
///
/// # For a `standard` client this remains a no-op
///
/// Every parameter is ignored exactly as it is today, including the
/// security-bearing five, because invariant 4 says no client registered today
/// changes behaviour — and it outranks the general preference for the stricter
/// reading. What is added is a `warn!`, rate-limited per client, so an operator
/// can see which of their clients are sending parameters that would do
/// something under `authn_request_params: honour`.
pub fn enforce_authorization_request(
    client: &OAuth2Client,
    code_challenge: Option<&str>,
    params: &AuthnRequestParams,
) -> Result<(), OAuth2Error> {
    if !client.profile.is_fapi2() {
        // Rule 3. Nothing is refused, nothing is honoured; the request
        // proceeds byte-for-byte as it did before X7.1 existed.
        if !params.is_empty() && client.authn_request_params == AuthnRequestParamsMode::Ignore {
            warn_ignored_params(client, params);
            return Ok(());
        }
        // Rule 4 (W4) — the honour lane. The only thing decided here is that a
        // value nobody can interpret is refused rather than acted on: from
        // this point the parameters *mean* something, so `max_age=tomorrow`
        // can no longer be quietly dropped the way an `ignore` client's is.
        //
        // Deliberately the whole of rule 4 that lives in this module. What the
        // parameters then *do* is `crate::honour`, evaluated inside the
        // authorization service where the client, the `redirect_uri` and the
        // session are all in hand — this gate runs before the request is known
        // to be redirectable, and an interaction decision made here could not
        // be reported to the relying party.
        if client.authn_request_params.is_honour()
            && let Some(detail) = params.parse_error()
        {
            return Err(OAuth2Error::InvalidRequest(detail.to_owned()));
        }
        return Ok(());
    }

    if code_challenge.is_none_or(str::is_empty) {
        return Err(OAuth2Error::InvalidRequest(
            "PKCE (code_challenge) is required for clients on the fapi2 profile".into(),
        ));
    }

    // Rule 2. Presence is what is refused, not validity: a `fapi2` client that
    // sent `max_age=tomorrow` is refused for having sent `max_age` at all,
    // which is why the parse records presence separately from meaning.
    let refused = params.security_bearing_present();
    if !refused.is_empty() {
        return Err(OAuth2Error::InvalidRequest(format!(
            "the parameter(s) {} are not supported for clients on the fapi2 profile",
            refused.join(", ")
        )));
    }

    // Rule 3's `fapi2` half. `validate_registration` refuses this combination
    // on create and on update, so a row holding it did not come through either.
    if client.authn_request_params.is_honour() {
        tracing::error!(
            client_id = %client.client_id,
            "a client on the fapi2 profile is registered with authn_request_params: honour; \
             this registration cannot have passed validate_registration and the row should be \
             investigated"
        );
        return Err(OAuth2Error::InvalidRequest(
            "this client's registration is inconsistent: the fapi2 profile does not permit \
             authn_request_params: honour"
                .into(),
        ));
    }

    Ok(())
}

/// Whether this client's ID tokens carry session evidence (X7.2/W4, plan §4.3).
///
/// **True for the honour lane and for nothing else.** W2 recorded the evidence
/// — `auth_time`, `acr`, `amr` — on every session and snapshotted it onto every
/// authorization code, and emitted it for nobody. W4 opens the one door: a
/// client registered `authn_request_params: honour` receives the three claims;
/// every client registered today is `ignore` and its ID token is byte-for-byte
/// what it has always been (invariant 4, pinned by
/// `oauth2_flow_test::t2_6_…` and `…::p1_…`).
///
/// A `fapi2` client can never reach `honour`: [`validate_registration`] refuses
/// the combination on create and on update, and
/// [`enforce_authorization_request`] refuses it again at request time on a row
/// that was edited past both. The profile is nevertheless asked here — a third
/// time, for a row those two could only have refused — because this function
/// is read by the token endpoint, where no authorization request is in hand and
/// so neither of the other two gates has run. `acr`/`amr`/`auth_time` on a
/// `fapi2` ID token is a claim the FAPI lane has never emitted and this
/// function is the last place that could start.
///
/// It is a function rather than a field read at the two mint sites because the
/// code-exchange and refresh paths must agree: OIDC Core §12.2 requires a
/// refreshed ID token's `auth_time` to equal the original's, and two
/// expressions are two places for that to drift.
///
/// Plan §11 D5 keeps this per-client. Emitting `auth_time` for *every* client
/// is additive and truthful, and it is also a visible change to every relying
/// party's ID token; it is left to the maintainer, and it is one line here.
pub fn emits_session_evidence(client: &OAuth2Client) -> bool {
    honours_authn_params(client)
}

/// Is this client on the honour lane (W4)?
///
/// The one predicate every honour-lane decision asks, so that "on the lane"
/// cannot come to mean one thing at the authorization endpoint and another at
/// the token endpoint. Both halves matter: the client opted in **and** it is
/// not on the FAPI profile, which the two registration gates already
/// guarantee and which is asserted here anyway because this is the last place
/// that could start honouring a parameter for a `fapi2` row.
pub fn honours_authn_params(client: &OAuth2Client) -> bool {
    !client.profile.is_fapi2() && client.authn_request_params.is_honour()
}

/// How long a client stays quiet after one "parameters ignored" warning.
///
/// The event is per authorization request, so an unthrottled log line would be
/// emitted once per login for every relying party in a deployment that sends
/// `login_hint` — which is most of them. Ten minutes is long enough that the
/// line is a signal an operator notices and short enough that it reappears
/// while they are still looking.
const IGNORED_PARAMS_WARN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// The largest number of clients tracked for rate limiting at once.
///
/// The key is a `client_id`, which is server-generated and therefore bounded by
/// the number of registered clients — but a map that only ever grows is still a
/// slow leak in a long-lived process, and the *purpose* here is a log line.
/// When the bound is reached the whole map is dropped: the cost of that is a
/// duplicate warning per client, which is exactly the thing this is not very
/// worried about.
const IGNORED_PARAMS_WARN_MAX_TRACKED: usize = 1024;

/// Emit the rate-limited "these parameters were ignored" warning (rule 3).
///
/// Deliberately never fails and never blocks the request: a poisoned mutex or
/// a full table costs a log line, not a login. Extracted so the gate above
/// reads as three rules rather than three rules and a cache.
fn warn_ignored_params(client: &OAuth2Client, params: &AuthnRequestParams) {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;

    static LAST_WARNED: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    let table = LAST_WARNED.get_or_init(|| Mutex::new(HashMap::new()));

    let Ok(mut seen) = table.lock() else {
        return;
    };
    let now = Instant::now();
    if let Some(last) = seen.get(&client.client_id)
        && now.duration_since(*last) < IGNORED_PARAMS_WARN_INTERVAL
    {
        return;
    }
    if seen.len() >= IGNORED_PARAMS_WARN_MAX_TRACKED {
        seen.clear();
    }
    seen.insert(client.client_id.clone(), now);
    drop(seen);

    tracing::warn!(
        client_id = %client.client_id,
        parameters = %params.present().join(", "),
        "authorization request carried OpenID Connect authentication-request parameters that \
         this client is registered to ignore (authn_request_params: ignore); the request was \
         served exactly as before. Set authn_request_params: honour to act on them"
    );
}

/// Request-time gate on the token endpoint (X5.1).
///
/// Defence in depth behind [`validate_registration`]. A FAPI client whose row
/// was edited directly in the database — bypassing registration validation —
/// must not be able to authenticate with a secret or receive an unbound
/// token, so the invariants are re-checked at the moment they matter.
///
/// `evidence` is what the request actually carried: a verified client
/// certificate on the connection, a verified DPoP proof, or neither. The FAPI
/// profile requires whatever the client's own registration says it requires, so
/// the absence of the *relevant* evidence is refused here even though the
/// authentication and binding paths would also refuse it — this way the refusal
/// names the profile, which is what an operator needs to see.
///
/// A no-op for a `standard` client.
pub fn enforce_token_request(
    client: &OAuth2Client,
    evidence: TokenRequestEvidence,
) -> Result<(), OAuth2Error> {
    if !client.profile.is_fapi2() {
        return Ok(());
    }

    if !client.token_endpoint_auth_method.is_strong() {
        tracing::error!(
            client_id = %client.client_id,
            method = client.token_endpoint_auth_method.as_str(),
            "a client on the fapi2 profile is registered with a shared-secret authentication \
             method; this registration cannot have passed validate_registration and the row \
             should be investigated"
        );
        return Err(OAuth2Error::InvalidClient(
            crate::mtls::MTLS_AUTH_FAILED.into(),
        ));
    }

    if !client.is_sender_constrained() {
        tracing::error!(
            client_id = %client.client_id,
            "a client on the fapi2 profile is registered with neither certificate-bound nor \
             DPoP-bound access tokens; refusing to issue an unconstrained token under a FAPI \
             profile"
        );
        return Err(OAuth2Error::InvalidClient(
            crate::mtls::MTLS_AUTH_FAILED.into(),
        ));
    }

    // A certificate is required when the client authenticates by one, or binds
    // its tokens to one. The two are independent (RFC 8705 §3.4), so this is an
    // OR over reasons rather than a single flag.
    let needs_certificate = client.token_endpoint_auth_method.is_mtls()
        || client.tls_client_certificate_bound_access_tokens;
    if needs_certificate && !evidence.presented_certificate {
        return Err(OAuth2Error::InvalidClient(
            crate::mtls::MTLS_AUTH_FAILED.into(),
        ));
    }

    if client.dpop_bound_access_tokens && !evidence.verified_dpop_proof {
        return Err(OAuth2Error::InvalidClient(
            crate::mtls::MTLS_AUTH_FAILED.into(),
        ));
    }

    Ok(())
}

/// What a token request actually carried, as opposed to what its body claimed.
///
/// A named struct rather than two `bool` parameters: `enforce_token_request(c,
/// true, false)` and `enforce_token_request(c, false, true)` both compile and
/// mean opposite things.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenRequestEvidence {
    /// A client certificate rustls verified on this connection.
    pub presented_certificate: bool,
    /// A DPoP proof that **already verified** — not merely one that was
    /// present. A caller that sets this from the presence of a `DPoP` header
    /// has turned the proof into a self-signed permission slip.
    pub verified_dpop_proof: bool,
}

/// Whether a token issued to this client must carry a `cnf.x5t#S256`
/// certificate confirmation.
///
/// Driven by the client's own `tls_client_certificate_bound_access_tokens`
/// flag rather than by its profile, because RFC 8705 §3.4 makes binding
/// independent of the authentication method: a deployment may want bound
/// tokens for a client that still authenticates with a secret over an mTLS
/// connection. The FAPI profile forces at least one constraint on; it is not
/// the only thing that can.
pub const fn wants_certificate_binding(client: &OAuth2Client) -> bool {
    client.tls_client_certificate_bound_access_tokens
}

/// Whether a token issued to this client must carry a `cnf.jkt` DPoP
/// confirmation (RFC 9449 §5).
///
/// Independent of [`wants_certificate_binding`] on purpose — a client may ask
/// for both, and a token that carries both confirmations must satisfy both at
/// the resource server (`axiam_auth::token::verify_token_binding`).
pub const fn wants_dpop_binding(client: &OAuth2Client) -> bool {
    client.dpop_bound_access_tokens
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn base_client() -> OAuth2Client {
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "oa_test".into(),
            client_secret_hash: "hash".into(),
            name: "test".into(),
            redirect_uris: vec!["https://rp.example/cb".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into()],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// A registration that satisfies the whole bundle.
    fn fapi_client() -> OAuth2Client {
        let mut c = base_client();
        c.profile = ClientProfile::Fapi2;
        c.require_par = true;
        c.token_endpoint_auth_method = ClientAuthMethod::TlsClientAuth;
        c.tls_client_auth_san_dns = Some("rp.example".into());
        c.tls_client_certificate_bound_access_tokens = true;
        c
    }

    /// A valid `S256` challenge, so a FAPI request under test fails for the
    /// reason the test is about rather than for missing PKCE.
    const PKCE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    /// The bundle every request carried before X7.1: nothing.
    fn no_params() -> AuthnRequestParams {
        AuthnRequestParams::default()
    }

    /// Parse one named parameter, the way a request carrying only it would.
    fn one_param(name: &str, value: &str) -> AuthnRequestParams {
        let mut raw = crate::authn_params::RawAuthnParams::default();
        match name {
            "prompt" => raw.prompt = Some(value),
            "max_age" => raw.max_age = Some(value),
            "acr_values" => raw.acr_values = Some(value),
            "claims" => raw.claims = Some(value),
            "id_token_hint" => raw.id_token_hint = Some(value),
            "login_hint" => raw.login_hint = Some(value),
            "display" => raw.display = Some(value),
            "ui_locales" => raw.ui_locales = Some(value),
            "claims_locales" => raw.claims_locales = Some(value),
            other => panic!("unknown parameter {other:?}"),
        }
        AuthnRequestParams::parse(&raw)
    }

    // -- ordinary clients are untouched ----------------------------------
    //
    // This is the load-bearing property of the whole design, so it is asserted
    // three times over rather than assumed: registration, authorization and
    // token issuance must all behave for a `standard` client exactly as they
    // did before X5.1 existed.

    #[test]
    fn a_pre_x5_client_registration_still_validates() {
        assert_eq!(validate_registration(&base_client()), Ok(()));
    }

    #[test]
    fn a_standard_client_needs_no_pkce_from_this_gate() {
        // SEC-025 still requires PKCE of public clients; this gate adds
        // nothing for a standard confidential client.
        assert!(enforce_authorization_request(&base_client(), None, &no_params()).is_ok());
    }

    /// The positive regression test the whole design rests on: a client that
    /// has never heard of mTLS *or* DPoP must pass this gate with no evidence
    /// at all. Asserted against every combination, because the failure mode
    /// worth catching is a gate that starts demanding a proof from everybody.
    #[test]
    fn a_standard_client_needs_no_certificate_and_no_proof() {
        for evidence in [
            TokenRequestEvidence::default(),
            TokenRequestEvidence {
                presented_certificate: true,
                verified_dpop_proof: false,
            },
            TokenRequestEvidence {
                presented_certificate: false,
                verified_dpop_proof: true,
            },
        ] {
            assert!(
                enforce_token_request(&base_client(), evidence).is_ok(),
                "a standard client must be untouched by the profile gate: {evidence:?}"
            );
        }
    }

    #[test]
    fn a_standard_client_gets_unbound_tokens() {
        assert!(!wants_certificate_binding(&base_client()));
    }

    // -- the bundle is all-or-nothing ------------------------------------

    #[test]
    fn a_complete_fapi_registration_validates() {
        assert_eq!(validate_registration(&fapi_client()), Ok(()));
    }

    #[test]
    fn fapi_without_par_is_refused() {
        let mut c = fapi_client();
        c.require_par = false;
        assert_eq!(
            validate_registration(&c),
            Err(FapiRegistrationError::ParNotRequired)
        );
    }

    #[test]
    fn fapi_with_secret_auth_is_refused() {
        let mut c = fapi_client();
        c.token_endpoint_auth_method = ClientAuthMethod::ClientSecretPost;
        c.tls_client_auth_san_dns = None;
        assert_eq!(
            validate_registration(&c),
            Err(FapiRegistrationError::WeakClientAuth {
                method: ClientAuthMethod::ClientSecretPost
            })
        );
    }

    #[test]
    fn fapi_without_sender_constraining_is_refused() {
        let mut c = fapi_client();
        c.tls_client_certificate_bound_access_tokens = false;
        assert_eq!(
            validate_registration(&c),
            Err(FapiRegistrationError::TokensNotSenderConstrained)
        );
    }

    #[test]
    fn fapi_requires_pkce_at_the_authorization_endpoint() {
        let c = fapi_client();
        assert!(enforce_authorization_request(&c, None, &no_params()).is_err());
        assert!(enforce_authorization_request(&c, Some(""), &no_params()).is_err());
        assert!(enforce_authorization_request(&c, Some(PKCE), &no_params()).is_ok());
    }

    #[test]
    fn fapi_token_request_requires_a_certificate() {
        let c = fapi_client();
        assert!(enforce_token_request(&c, TokenRequestEvidence::default()).is_err());
        assert!(
            enforce_token_request(
                &c,
                TokenRequestEvidence {
                    presented_certificate: true,
                    verified_dpop_proof: false,
                }
            )
            .is_ok()
        );
    }

    /// Defence in depth: a row that bypassed registration validation must
    /// still be refused at request time rather than served.
    #[test]
    fn fapi_token_request_refuses_a_tampered_row() {
        let mut weak_auth = fapi_client();
        weak_auth.token_endpoint_auth_method = ClientAuthMethod::ClientSecretPost;
        assert!(
            enforce_token_request(
                &weak_auth,
                TokenRequestEvidence {
                    presented_certificate: true,
                    verified_dpop_proof: false,
                }
            )
            .is_err()
        );

        let mut unbound = fapi_client();
        unbound.tls_client_certificate_bound_access_tokens = false;
        assert!(
            enforce_token_request(
                &unbound,
                TokenRequestEvidence {
                    presented_certificate: true,
                    verified_dpop_proof: false,
                }
            )
            .is_err()
        );
    }

    // -- the second family: private_key_jwt + DPoP ------------------------

    /// A minimal, valid inline key set. The key itself never signs anything in
    /// these tests — registration validation only asks whether the document
    /// parses as a JWK Set.
    const INLINE_JWKS: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;

    /// A FAPI client on the *other* diagonal: asymmetric client authentication
    /// and DPoP sender-constraining, with no certificate anywhere.
    fn fapi_private_key_jwt_client() -> OAuth2Client {
        let mut c = base_client();
        c.profile = ClientProfile::Fapi2;
        c.require_par = true;
        c.token_endpoint_auth_method = ClientAuthMethod::PrivateKeyJwt;
        c.jwks = Some(INLINE_JWKS.into());
        c.dpop_bound_access_tokens = true;
        c
    }

    #[test]
    fn a_private_key_jwt_plus_dpop_registration_validates() {
        assert_eq!(
            validate_registration(&fapi_private_key_jwt_client()),
            Ok(())
        );
    }

    /// All four pairings of the two families are legitimate. The profile asks
    /// one question of each row, not that the two rows agree.
    #[test]
    fn every_pairing_of_the_two_families_is_accepted() {
        // mTLS auth + DPoP binding.
        let mut mtls_dpop = fapi_client();
        mtls_dpop.tls_client_certificate_bound_access_tokens = false;
        mtls_dpop.dpop_bound_access_tokens = true;
        assert_eq!(validate_registration(&mtls_dpop), Ok(()));

        // private_key_jwt auth + certificate binding.
        let mut jwt_cert = fapi_private_key_jwt_client();
        jwt_cert.dpop_bound_access_tokens = false;
        jwt_cert.tls_client_certificate_bound_access_tokens = true;
        assert_eq!(validate_registration(&jwt_cert), Ok(()));

        // Both constraints at once is also fine — and means the token must
        // satisfy both at the resource server.
        let mut both = fapi_private_key_jwt_client();
        both.tls_client_certificate_bound_access_tokens = true;
        assert_eq!(validate_registration(&both), Ok(()));
    }

    /// The shape the gate exists to refuse: strong authentication from one
    /// family, sender-constraining from neither.
    #[test]
    fn strong_auth_with_neither_constraint_is_refused() {
        for mut c in [fapi_client(), fapi_private_key_jwt_client()] {
            c.tls_client_certificate_bound_access_tokens = false;
            c.dpop_bound_access_tokens = false;
            assert_eq!(
                validate_registration(&c),
                Err(FapiRegistrationError::TokensNotSenderConstrained),
                "method {} with no sender-constraining must be refused",
                c.token_endpoint_auth_method.as_str()
            );
        }
    }

    /// RFC 7591 §2: exactly one key source. Neither leaves a client that can
    /// authenticate nothing; both leaves one whose credential is a union
    /// nobody registered.
    #[test]
    fn private_key_jwt_needs_exactly_one_key_source() {
        let mut neither = fapi_private_key_jwt_client();
        neither.jwks = None;
        assert_eq!(
            validate_registration(&neither),
            Err(FapiRegistrationError::JwksSourceCount { registered: 0 })
        );

        let mut both = fapi_private_key_jwt_client();
        both.jwks_uri = Some("https://rp.example/jwks.json".into());
        assert_eq!(
            validate_registration(&both),
            Err(FapiRegistrationError::JwksSourceCount { registered: 2 })
        );

        // A blank value is not a source — the same emptiness rule
        // `count_jwks_sources` applies.
        let mut blank = fapi_private_key_jwt_client();
        blank.jwks_uri = Some("   ".into());
        assert_eq!(validate_registration(&blank), Ok(()));
    }

    /// This check applies to any client with a key source, whatever its
    /// profile — the same way the RFC 8705 thumbprint check does. An operator
    /// should hear about an unparseable JWKS while onboarding, not six weeks
    /// later as an `invalid_client` the wire deliberately cannot explain.
    #[test]
    fn a_malformed_jwks_is_refused_at_registration() {
        let mut c = fapi_private_key_jwt_client();
        c.jwks = Some("{not json".into());
        assert!(matches!(
            validate_registration(&c),
            Err(FapiRegistrationError::MalformedJwks { .. })
        ));

        // ...including on a standard client, which never reaches the profile
        // bundle at all.
        let mut standard = base_client();
        standard.jwks = Some(r#"{"keys": "not an array"}"#.into());
        assert!(matches!(
            validate_registration(&standard),
            Err(FapiRegistrationError::MalformedJwks { .. })
        ));
    }

    #[test]
    fn a_plaintext_or_relative_jwks_uri_is_refused() {
        for bad in [
            "http://rp.example/jwks.json",
            "/jwks.json",
            "rp.example/jwks.json",
            "https://",
        ] {
            let mut c = fapi_private_key_jwt_client();
            c.jwks = None;
            c.jwks_uri = Some(bad.into());
            assert!(
                matches!(
                    validate_registration(&c),
                    Err(FapiRegistrationError::InsecureJwksUri { .. })
                ),
                "{bad:?} should be refused"
            );
        }

        let mut good = fapi_private_key_jwt_client();
        good.jwks = None;
        good.jwks_uri = Some("HTTPS://rp.example/jwks.json".into());
        assert_eq!(validate_registration(&good), Ok(()));
    }

    /// A secret is still not strong authentication, whichever constraint the
    /// client pairs it with.
    #[test]
    fn dpop_does_not_make_a_secret_client_fapi() {
        let mut c = base_client();
        c.profile = ClientProfile::Fapi2;
        c.require_par = true;
        c.dpop_bound_access_tokens = true;
        assert_eq!(
            validate_registration(&c),
            Err(FapiRegistrationError::WeakClientAuth {
                method: ClientAuthMethod::ClientSecretPost
            })
        );
    }

    /// The request-time gate must ask for the evidence the *registration* says
    /// it needs, and no more. A private_key_jwt + DPoP client has no
    /// certificate and must not be asked for one.
    #[test]
    fn the_token_gate_asks_only_for_the_evidence_the_registration_implies() {
        let c = fapi_private_key_jwt_client();

        assert!(
            enforce_token_request(
                &c,
                TokenRequestEvidence {
                    presented_certificate: false,
                    verified_dpop_proof: true,
                }
            )
            .is_ok(),
            "a DPoP-bound client with no mTLS anywhere must not be asked for a certificate"
        );

        assert!(
            enforce_token_request(
                &c,
                TokenRequestEvidence {
                    presented_certificate: true,
                    verified_dpop_proof: false,
                }
            )
            .is_err(),
            "a certificate is not a substitute for the proof this client's tokens bind to"
        );

        assert!(enforce_token_request(&c, TokenRequestEvidence::default()).is_err());
    }

    /// A client asking for both constraints must supply both.
    #[test]
    fn a_doubly_constrained_client_must_supply_both_proofs() {
        let mut c = fapi_private_key_jwt_client();
        c.tls_client_certificate_bound_access_tokens = true;

        assert!(
            enforce_token_request(
                &c,
                TokenRequestEvidence {
                    presented_certificate: true,
                    verified_dpop_proof: true,
                }
            )
            .is_ok()
        );
        for partial in [
            TokenRequestEvidence {
                presented_certificate: true,
                verified_dpop_proof: false,
            },
            TokenRequestEvidence {
                presented_certificate: false,
                verified_dpop_proof: true,
            },
        ] {
            assert!(enforce_token_request(&c, partial).is_err(), "{partial:?}");
        }
    }

    #[test]
    fn the_two_binding_questions_are_asked_independently() {
        let mut c = base_client();
        assert!(!wants_certificate_binding(&c));
        assert!(!wants_dpop_binding(&c));

        c.dpop_bound_access_tokens = true;
        assert!(!wants_certificate_binding(&c));
        assert!(wants_dpop_binding(&c));
        assert!(c.is_sender_constrained());
    }

    // -- RFC 8705 consistency, independent of profile ---------------------

    #[test]
    fn tls_client_auth_needs_exactly_one_binding() {
        let mut none = base_client();
        none.token_endpoint_auth_method = ClientAuthMethod::TlsClientAuth;
        assert_eq!(
            validate_registration(&none),
            Err(FapiRegistrationError::MtlsBindingCount { registered: 0 })
        );

        let mut two = base_client();
        two.token_endpoint_auth_method = ClientAuthMethod::TlsClientAuth;
        two.tls_client_auth_san_dns = Some("rp.example".into());
        two.tls_client_auth_subject_dn = Some("CN=rp".into());
        assert_eq!(
            validate_registration(&two),
            Err(FapiRegistrationError::MtlsBindingCount { registered: 2 })
        );
    }

    #[test]
    fn self_signed_needs_a_thumbprint() {
        let mut c = base_client();
        c.token_endpoint_auth_method = ClientAuthMethod::SelfSignedTlsClientAuth;
        assert_eq!(
            validate_registration(&c),
            Err(FapiRegistrationError::NoSelfSignedThumbprint)
        );
    }

    #[test]
    fn malformed_thumbprints_are_refused_at_registration() {
        let good = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(is_wellformed_thumbprint(good));

        for bad in [
            // standard base64 rather than base64url
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM",
            // padded
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=",
            // a hex digest — the most likely operator mistake, since the
            // device-auth path fingerprints in hex
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "",
        ] {
            assert!(!is_wellformed_thumbprint(bad), "{bad:?} should be rejected");
            let mut c = base_client();
            c.token_endpoint_auth_method = ClientAuthMethod::SelfSignedTlsClientAuth;
            c.self_signed_tls_client_auth_thumbprints = vec![bad.to_owned()];
            assert!(matches!(
                validate_registration(&c),
                Err(FapiRegistrationError::NoSelfSignedThumbprint)
                    | Err(FapiRegistrationError::MalformedThumbprint { .. })
            ));
        }
    }

    // -- X7.1: the profile-confusion matrix, registration halves ----------
    //
    // Plan §7 rows M1-M6 and M8. Every row asserts the *same* refusal on
    // create and on update, because the update path is a different call site
    // (`handlers::oauth2_clients` validates the merged row) and a gate that
    // holds on one is not a gate.

    /// The merged-update equivalent of `validate_registration(&create)`: what
    /// the REST layer does at `oauth2_clients.rs`'s update handler.
    fn validate_update(
        stored: &OAuth2Client,
        patch: &axiam_core::models::oauth2_client::UpdateOAuth2Client,
    ) -> Result<(), FapiRegistrationError> {
        let merged = stored.clone().with_update_applied(patch);
        validate_registration(&merged)
    }

    fn patch() -> axiam_core::models::oauth2_client::UpdateOAuth2Client {
        axiam_core::models::oauth2_client::UpdateOAuth2Client::default()
    }

    /// M1-M6 registration half, create. One field governs the whole bundle, so
    /// one arm refuses all six mechanisms at once — which is the reason it is
    /// one field.
    #[test]
    fn m1_m6_fapi_plus_honour_is_refused_at_creation() {
        let mut c = fapi_client();
        c.authn_request_params = AuthnRequestParamsMode::Honour;
        assert_eq!(
            validate_registration(&c),
            Err(FapiRegistrationError::AuthnParamsOnFapiClient)
        );
    }

    /// M1-M6 registration half, update. Flipping the field on a stored `fapi2`
    /// row is a well-formed patch and a refused one.
    #[test]
    fn m1_m6_fapi_plus_honour_is_refused_on_update() {
        let stored = fapi_client();
        let mut p = patch();
        p.authn_request_params = Some(AuthnRequestParamsMode::Honour);
        assert_eq!(
            validate_update(&stored, &p),
            Err(FapiRegistrationError::AuthnParamsOnFapiClient)
        );

        // ...and the mirror image: flipping a *standard* honour client to
        // `fapi2` is the same collision arriving from the other side, and must
        // be refused just as firmly.
        let mut standard_honour = base_client();
        standard_honour.authn_request_params = AuthnRequestParamsMode::Honour;
        standard_honour.require_par = true;
        standard_honour.token_endpoint_auth_method = ClientAuthMethod::TlsClientAuth;
        standard_honour.tls_client_auth_san_dns = Some("rp.example".into());
        standard_honour.tls_client_certificate_bound_access_tokens = true;
        let mut to_fapi = patch();
        to_fapi.profile = Some(ClientProfile::Fapi2);
        assert_eq!(
            validate_update(&standard_honour, &to_fapi),
            Err(FapiRegistrationError::AuthnParamsOnFapiClient)
        );
    }

    /// The I4 twin of M1-M6: a `standard` client may hold either value, and
    /// `ignore` — what every existing row decodes to — is untouched.
    #[test]
    fn a_standard_client_may_honour_or_ignore() {
        for mode in [
            AuthnRequestParamsMode::Ignore,
            AuthnRequestParamsMode::Honour,
        ] {
            let mut c = base_client();
            c.authn_request_params = mode;
            assert_eq!(validate_registration(&c), Ok(()), "{mode:?}");
        }
    }

    /// M8 registration half, create.
    #[test]
    fn m8_fapi_plus_sensitive_scopes_is_refused_at_creation() {
        for scope in SENSITIVE_SCOPES {
            let mut c = fapi_client();
            c.scopes = vec!["openid".into(), scope.to_owned()];
            assert_eq!(
                validate_registration(&c),
                Err(FapiRegistrationError::SensitiveScopesOnFapiClient {
                    scopes: vec![scope.to_owned()]
                }),
                "scope {scope:?} must be refused on a fapi2 client"
            );
        }

        // Both at once are both named, so an operator fixes one registration
        // rather than discovering the second scope on the next attempt.
        let mut both = fapi_client();
        both.scopes = vec!["openid".into(), "address".into(), "phone".into()];
        assert_eq!(
            validate_registration(&both),
            Err(FapiRegistrationError::SensitiveScopesOnFapiClient {
                scopes: vec!["address".into(), "phone".into()]
            })
        );
    }

    /// M8 registration half, update. The patch replaces the scope list, so the
    /// gate must read the merged list rather than the stored one.
    #[test]
    fn m8_fapi_plus_sensitive_scopes_is_refused_on_update() {
        let stored = fapi_client();
        let mut p = patch();
        p.scopes = Some(vec!["openid".into(), "address".into()]);
        assert_eq!(
            validate_update(&stored, &p),
            Err(FapiRegistrationError::SensitiveScopesOnFapiClient {
                scopes: vec!["address".into()]
            })
        );
    }

    /// The I4 twin of M8: the scopes are ordinary on the standard lane, and a
    /// scope that merely *contains* a sensitive name is not one.
    #[test]
    fn sensitive_scopes_are_ordinary_for_a_standard_client() {
        let mut c = base_client();
        c.scopes = vec!["openid".into(), "address".into(), "phone".into()];
        assert_eq!(validate_registration(&c), Ok(()));

        // Substring, not scope. `phone_number` is a *claim*; refusing a scope
        // for containing the letters of another is how a gate acquires a
        // reputation for being wrong.
        let mut lookalike = fapi_client();
        lookalike.scopes = vec!["openid".into(), "phone_number".into(), "addressbook".into()];
        assert_eq!(validate_registration(&lookalike), Ok(()));
    }

    /// A patch that touches only a rename must not pay for the stored read —
    /// but every field the gates now read must force one, or an update could
    /// be validated against a row it is not about to write.
    #[test]
    fn the_new_fields_force_the_merged_validation() {
        let mut rename = patch();
        rename.name = Some("new name".into());
        assert!(!rename.touches_security_profile());

        let mut honour = patch();
        honour.authn_request_params = Some(AuthnRequestParamsMode::Honour);
        assert!(honour.touches_security_profile());

        let mut scopes = patch();
        scopes.scopes = Some(vec!["openid".into(), "address".into()]);
        assert!(
            scopes.touches_security_profile(),
            "the sensitive-scope arm reads `scopes`, so a scope patch must be merged first"
        );

        let mut sso = patch();
        sso.browser_sso = Some(true);
        assert!(sso.touches_security_profile());
    }

    /// D2: `browser_sso` is permitted on a `fapi2` client, deliberately. It
    /// relaxes nothing — it decides how an *anonymous* browser is answered —
    /// and refusing it would keep the FAPI harness's interactive modules
    /// manual forever for no security property.
    #[test]
    fn browser_sso_is_permitted_on_every_profile() {
        for mut c in [base_client(), fapi_client()] {
            c.browser_sso = true;
            assert_eq!(
                validate_registration(&c),
                Ok(()),
                "browser_sso must not be refused on {}",
                c.profile.as_str()
            );
        }
    }

    /// **M7 request half (W3).** `browser_sso` changes nothing about what an
    /// authorization request is *allowed to contain*, on either profile.
    ///
    /// It is the one field in the two-layer gate that is permitted on `fapi2`
    /// (D2), so the obvious worry is that permitting it smuggled a relaxation
    /// in with it. It did not, and cannot: the flag decides how a request with
    /// **no principal** is answered — a 401 or a redirect to a sign-in page —
    /// and every gate this function applies runs afterwards, on the return leg,
    /// exactly as it runs on a request that never hopped. Here that is asserted
    /// as an equality rather than a description: for every combination of
    /// profile and parameter, the answer with `browser_sso` set is the answer
    /// without it.
    ///
    /// The end-to-end half — a `require_par` client that cannot smuggle inline
    /// parameters through the hop, and PKCE still required on the way back —
    /// is `axiam-api-rest`'s `oauth2_login_hop_test`, which has an HTTP
    /// listener to hop through.
    #[test]
    fn m7_browser_sso_does_not_change_what_a_request_may_contain() {
        for base in [base_client(), fapi_client()] {
            for (name, value) in [
                ("prompt", "none"),
                ("max_age", "0"),
                ("acr_values", "urn:axiam:acr:mfa"),
                ("id_token_hint", "ey.header.payload"),
                ("login_hint", "someone@example.com"),
                ("display", "page"),
            ] {
                let mut with = base.clone();
                with.browser_sso = true;
                let params = one_param(name, value);

                let without_pkce = enforce_authorization_request(&base, None, &params).is_err();
                let with_pkce = enforce_authorization_request(&base, Some(PKCE), &params).is_err();

                assert_eq!(
                    enforce_authorization_request(&with, None, &params).is_err(),
                    without_pkce,
                    "browser_sso changed the answer for {name}={value} on {} (no PKCE)",
                    base.profile.as_str()
                );
                assert_eq!(
                    enforce_authorization_request(&with, Some(PKCE), &params).is_err(),
                    with_pkce,
                    "browser_sso changed the answer for {name}={value} on {}",
                    base.profile.as_str()
                );
            }
        }
    }

    // -- X7.1: the matrix, request-time halves ----------------------------

    /// M1-M4 request half. The five security-bearing parameters are refused on
    /// a `fapi2` client, one at a time, whichever it is.
    #[test]
    fn m1_m4_security_bearing_parameters_are_refused_for_a_fapi_client() {
        let c = fapi_client();
        for (name, value) in [
            ("prompt", "none"),
            ("prompt", "login"),
            ("max_age", "0"),
            ("max_age", "3600"),
            ("acr_values", "urn:axiam:acr:mfa"),
            ("claims", r#"{"id_token":{"acr":{"essential":true}}}"#),
            ("id_token_hint", "ey.header.payload"),
        ] {
            let err = enforce_authorization_request(&c, Some(PKCE), &one_param(name, value))
                .expect_err("{name} must be refused for a fapi2 client");
            assert_eq!(err.error_code(), "invalid_request", "{name}");
            assert!(
                err.to_string().contains(name),
                "the refusal must name {name}: {err}"
            );
        }
    }

    /// A `fapi2` client that sent a *malformed* security-bearing parameter is
    /// refused for having sent it, not excused for spelling it wrongly. This
    /// is why the parse records presence separately from meaning.
    #[test]
    fn a_malformed_security_bearing_parameter_is_still_refused_for_fapi() {
        let c = fapi_client();
        for (name, bad) in [
            ("max_age", "tomorrow"),
            ("prompt", "teleport"),
            ("claims", "{not json"),
        ] {
            assert!(
                enforce_authorization_request(&c, Some(PKCE), &one_param(name, bad)).is_err(),
                "a fapi2 client sending a malformed {name} must still be refused"
            );
        }
    }

    /// All five at once are all named, so one refusal tells an operator the
    /// whole story.
    #[test]
    fn the_refusal_names_every_offending_parameter() {
        let params = AuthnRequestParams::parse(&crate::authn_params::RawAuthnParams {
            prompt: Some("login"),
            max_age: Some("60"),
            acr_values: Some("urn:axiam:acr:mfa"),
            claims: Some(r#"{"id_token":{"acr":{"essential":true}}}"#),
            id_token_hint: Some("ey.hint"),
            ..Default::default()
        });
        let err = enforce_authorization_request(&fapi_client(), Some(PKCE), &params)
            .expect_err("a fapi2 client sending all five must be refused");
        for name in ["prompt", "max_age", "acr_values", "claims", "id_token_hint"] {
            assert!(err.to_string().contains(name), "{name} missing from: {err}");
        }
    }

    /// M5-M6 request half. The cosmetic four are **not** refused on an honest
    /// `fapi2` row: client libraries send `login_hint` by reflex, and refusing
    /// it would break working FAPI clients for no security property. Their
    /// mechanism is unreachable because the server only builds the redirect
    /// that carries it on the honour lane.
    #[test]
    fn m5_m6_the_cosmetic_four_are_not_refused_for_an_honest_fapi_client() {
        let c = fapi_client();
        for (name, value) in [
            ("login_hint", "ada@example.com"),
            ("display", "page"),
            ("ui_locales", "en-GB en"),
            ("claims_locales", "en"),
        ] {
            assert!(
                enforce_authorization_request(&c, Some(PKCE), &one_param(name, value)).is_ok(),
                "{name} must be ignored, not refused, on an honest fapi2 row"
            );
        }
    }

    /// M1-M6 request half, the tampered-row case (rule 2). A `fapi2` row that
    /// says `honour` cannot have passed `validate_registration`, so it was
    /// edited in the database — refused even when it carries no parameter at
    /// all, and even when the only parameter is a cosmetic one.
    #[test]
    fn a_fapi_row_edited_to_honour_is_refused_at_request_time() {
        let mut c = fapi_client();
        c.authn_request_params = AuthnRequestParamsMode::Honour;

        for params in [
            no_params(),
            one_param("login_hint", "ada@example.com"),
            one_param("display", "page"),
        ] {
            let err = enforce_authorization_request(&c, Some(PKCE), &params)
                .expect_err("a tampered fapi2 row must be refused");
            assert_eq!(err.error_code(), "invalid_request");
        }
    }

    // -- invariant 4, at this layer ---------------------------------------
    //
    // The integration tests P1/P2 prove it end to end; these prove the gate
    // itself cannot be the thing that breaks it.

    /// The I4 twin of every request-time row: a `standard`/`ignore` client —
    /// which is every client registered today — sends all nine parameters and
    /// the gate does exactly what it did before X7.1, namely nothing.
    #[test]
    fn a_standard_ignore_client_is_refused_nothing() {
        let c = base_client();
        assert_eq!(c.authn_request_params, AuthnRequestParamsMode::Ignore);

        let everything = AuthnRequestParams::parse(&crate::authn_params::RawAuthnParams {
            prompt: Some("none"),
            max_age: Some("0"),
            acr_values: Some("urn:axiam:acr:mfa"),
            claims: Some(r#"{"id_token":{"acr":{"essential":true}}}"#),
            id_token_hint: Some("ey.hint"),
            login_hint: Some("ada@example.com"),
            display: Some("page"),
            ui_locales: Some("en-GB"),
            claims_locales: Some("en"),
        });
        assert!(
            enforce_authorization_request(&c, None, &everything).is_ok(),
            "a standard client must be untouched by the parameter gate, PKCE included"
        );

        // Malformed values change nothing either: they were dropped before
        // X7.1 and they are dropped now.
        let malformed = AuthnRequestParams::parse(&crate::authn_params::RawAuthnParams {
            prompt: Some("teleport"),
            max_age: Some("tomorrow"),
            ..Default::default()
        });
        assert!(malformed.parse_error().is_some());
        assert!(
            enforce_authorization_request(&c, None, &malformed).is_ok(),
            "a parse error must not surface on the ignore lane"
        );
    }

    /// A `standard` client on the **honour** lane is not refused either — the
    /// honour lane is a later wave, and until it exists an opted-in client
    /// behaves exactly like an opted-out one. Pinned so that landing W4 is a
    /// deliberate change to this test rather than an accident.
    #[test]
    fn the_honour_lane_does_nothing_yet() {
        let mut c = base_client();
        c.authn_request_params = AuthnRequestParamsMode::Honour;
        assert!(enforce_authorization_request(&c, None, &one_param("max_age", "0")).is_ok());
    }

    /// P2's unit-level half: a `fapi2` client sending none of the nine is
    /// affected by nothing this wave added. The whole X7.1 gate is invisible
    /// to the FAPI lane, which is what lets conformance run #1 equal the
    /// baseline.
    #[test]
    fn p2_a_fapi_client_sending_none_of_them_is_unaffected() {
        let c = fapi_client();
        assert!(enforce_authorization_request(&c, Some(PKCE), &no_params()).is_ok());
        assert_eq!(validate_registration(&c), Ok(()));
    }

    /// **W4, the wave's central claim**: session evidence reaches the honour
    /// lane and nothing else.
    ///
    /// This test replaces X7.2's `session_evidence_is_emitted_for_nobody`, and
    /// the replacement is the change getting noticed — which is exactly what
    /// that test was for. The half that must not move is the `ignore` half:
    /// every client registered today is `standard` + `ignore`, and its ID
    /// token still carries no `auth_time`, no `acr` and no `amr`.
    ///
    /// The `fapi2` + `honour` row cannot be registered — both layers of the
    /// gate refuse it — and is asserted here anyway, because "cannot be
    /// registered" is a property of two other functions and this one should
    /// not depend on either of them being right.
    #[test]
    fn session_evidence_reaches_the_honour_lane_and_nobody_else() {
        for mode in [
            AuthnRequestParamsMode::Ignore,
            AuthnRequestParamsMode::Honour,
        ] {
            let mut standard = base_client();
            standard.authn_request_params = mode;
            assert_eq!(
                emits_session_evidence(&standard),
                mode.is_honour(),
                "a standard client receives session evidence exactly when it opted in ({mode:?})"
            );

            let mut fapi = fapi_client();
            fapi.authn_request_params = mode;
            assert!(
                !emits_session_evidence(&fapi),
                "a fapi2 client with {mode:?} must receive no session evidence, ever"
            );
        }
    }

    /// **M1–M4's request halves, and the I4 twin of each.**
    ///
    /// One table rather than four tests because the rows differ only in which
    /// parameter arrives: a `fapi2` client is refused every security-bearing
    /// one, and the same input against the `standard`/`ignore` client every
    /// deployment actually holds is served exactly as it was before X7.1 —
    /// which is the half of the matrix a negative test alone does not prove.
    #[test]
    fn m1_to_m4_every_security_bearing_parameter_is_refused_on_fapi2_and_ignored_on_the_default_lane()
     {
        for (row, name, value) in [
            ("M1", "prompt", "none"),
            ("M1", "prompt", "login"),
            ("M2", "max_age", "0"),
            ("M2", "max_age", "3600"),
            ("M3", "acr_values", "urn:axiam:acr:mfa"),
            ("M3", "claims", r#"{"id_token":{"acr":{"essential":true}}}"#),
            ("M4", "id_token_hint", "ey.header.payload"),
        ] {
            let params = one_param(name, value);

            // Layer 2, the refusal.
            let refusal = enforce_authorization_request(&fapi_client(), Some(PKCE), &params)
                .expect_err(&format!("{row}: a fapi2 client must be refused {name}"));
            let message = refusal.to_string();
            assert!(
                message.contains(name) && message.contains("fapi2"),
                "{row}: the refusal must name the parameter and the profile: {message}"
            );

            // The I4 twin: the client every deployment holds today.
            assert!(
                enforce_authorization_request(&base_client(), None, &params).is_ok(),
                "{row} (I4): a standard/ignore client must be served exactly as before, \
                 whatever it sends"
            );
        }
    }

    /// Rule 4's one refusal: a value that has no meaning is refused **on the
    /// honour lane only**, because there it would otherwise have to be acted
    /// on, and there is nothing to act on.
    ///
    /// The `ignore` twin is the point. `max_age=tomorrow` from a client
    /// registered today has always produced a code, and still does.
    #[test]
    fn t2_7_a_malformed_value_is_invalid_request_on_the_honour_lane_and_dropped_on_the_ignore_one()
    {
        for (name, value) in [
            ("max_age", "-1"),
            ("max_age", "abc"),
            ("prompt", "teleport"),
            ("prompt", "none login"),
            ("claims", "{not json"),
        ] {
            let params = one_param(name, value);
            assert!(
                params.parse_error().is_some(),
                "{name}={value} must parse as malformed"
            );

            let mut honour = base_client();
            honour.authn_request_params = AuthnRequestParamsMode::Honour;
            let refusal = enforce_authorization_request(&honour, None, &params).expect_err(
                &format!("{name}={value} must be refused on the honour lane"),
            );
            assert_eq!(refusal.error_code(), "invalid_request");

            assert!(
                enforce_authorization_request(&base_client(), None, &params).is_ok(),
                "{name}={value} must still be dropped for an ignore-lane client"
            );
        }
    }

    /// A well-formed bundle passes rule 4 untouched: the gate decides nothing
    /// else about it, and everything it *does* decide lives in
    /// `crate::honour`.
    #[test]
    fn rule_four_refuses_nothing_a_client_spelled_correctly() {
        let mut honour = base_client();
        honour.authn_request_params = AuthnRequestParamsMode::Honour;
        for (name, value) in [
            ("prompt", "none"),
            ("max_age", "0"),
            ("acr_values", "urn:axiam:acr:mfa"),
            ("login_hint", "ada@example.com"),
        ] {
            assert!(
                enforce_authorization_request(&honour, None, &one_param(name, value)).is_ok(),
                "{name}={value}"
            );
        }
    }
}

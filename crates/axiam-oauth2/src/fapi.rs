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

use axiam_core::models::oauth2_client::{
    ClientAuthMethod, ClientProfile, CreateOAuth2Client, OAuth2Client,
};

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
}

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

/// Request-time gate on the authorization endpoint (X5.1).
///
/// One check that `authorize` does not already make for every client: PKCE is
/// mandatory. AXIAM requires PKCE for *public* clients (SEC-025) and accepts
/// only `S256` from anybody, so under the FAPI profile the remaining gap is a
/// confidential client omitting `code_challenge` entirely.
///
/// A no-op for a `standard` client — see the module docs.
pub fn enforce_authorization_request(
    client: &OAuth2Client,
    code_challenge: Option<&str>,
) -> Result<(), OAuth2Error> {
    if !client.profile.is_fapi2() {
        return Ok(());
    }
    if code_challenge.is_none_or(str::is_empty) {
        return Err(OAuth2Error::InvalidRequest(
            "PKCE (code_challenge) is required for clients on the fapi2 profile".into(),
        ));
    }
    Ok(())
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
        assert!(enforce_authorization_request(&base_client(), None).is_ok());
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
        assert!(enforce_authorization_request(&c, None).is_err());
        assert!(enforce_authorization_request(&c, Some("")).is_err());
        assert!(
            enforce_authorization_request(&c, Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"))
                .is_ok()
        );
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
}

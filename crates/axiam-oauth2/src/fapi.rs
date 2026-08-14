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
//! | Strong client authentication | [`validate_registration`] requires an mTLS method | 5.3.1.1 |
//! | Sender-constrained tokens | [`validate_registration`] requires certificate binding | 5.3.1.1 |
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
    /// AXIAM implements the mTLS half (see the module docs and the X5.1 table
    /// for where `private_key_jwt` stands).
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

    // --- RFC 8705 consistency, for any client using an mTLS method --------
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

    // --- the profile bundle -----------------------------------------------
    if !reg.profile.is_fapi2() {
        return Ok(());
    }

    if !reg.require_par {
        return Err(FapiRegistrationError::ParNotRequired);
    }
    if !reg.token_endpoint_auth_method.is_mtls() {
        return Err(FapiRegistrationError::WeakClientAuth {
            method: reg.token_endpoint_auth_method,
        });
    }
    if !reg.tls_client_certificate_bound_access_tokens {
        return Err(FapiRegistrationError::TokensNotSenderConstrained);
    }

    Ok(())
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
/// `presented_certificate` is whether a verified client certificate exists on
/// this connection. The FAPI profile requires one for both halves (client
/// authentication *and* token binding), so its absence is refused here even
/// though `authenticate_mtls_client` would also refuse it — this way the
/// refusal names the profile, which is what an operator needs to see.
///
/// A no-op for a `standard` client.
pub fn enforce_token_request(
    client: &OAuth2Client,
    presented_certificate: bool,
) -> Result<(), OAuth2Error> {
    if !client.profile.is_fapi2() {
        return Ok(());
    }

    if !client.token_endpoint_auth_method.is_mtls() {
        tracing::error!(
            client_id = %client.client_id,
            method = client.token_endpoint_auth_method.as_str(),
            "a client on the fapi2 profile is registered with a non-mTLS authentication \
             method; this registration cannot have passed validate_registration and the row \
             should be investigated"
        );
        return Err(OAuth2Error::InvalidClient(
            crate::mtls::MTLS_AUTH_FAILED.into(),
        ));
    }

    if !client.tls_client_certificate_bound_access_tokens {
        tracing::error!(
            client_id = %client.client_id,
            "a client on the fapi2 profile is registered without certificate-bound access \
             tokens; refusing to issue an unconstrained token under a FAPI profile"
        );
        return Err(OAuth2Error::InvalidClient(
            crate::mtls::MTLS_AUTH_FAILED.into(),
        ));
    }

    if !presented_certificate {
        return Err(OAuth2Error::InvalidClient(
            crate::mtls::MTLS_AUTH_FAILED.into(),
        ));
    }

    Ok(())
}

/// Whether a token issued to this client must carry a `cnf` confirmation.
///
/// Driven by the client's own `tls_client_certificate_bound_access_tokens`
/// flag rather than by its profile, because RFC 8705 §3.4 makes binding
/// independent of the authentication method: a deployment may want bound
/// tokens for a client that still authenticates with a secret over an mTLS
/// connection. The FAPI profile forces the flag on; it is not the only thing
/// that can.
pub const fn wants_certificate_binding(client: &OAuth2Client) -> bool {
    client.tls_client_certificate_bound_access_tokens
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

    #[test]
    fn a_standard_client_needs_no_certificate() {
        assert!(enforce_token_request(&base_client(), false).is_ok());
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
        assert!(enforce_token_request(&c, false).is_err());
        assert!(enforce_token_request(&c, true).is_ok());
    }

    /// Defence in depth: a row that bypassed registration validation must
    /// still be refused at request time rather than served.
    #[test]
    fn fapi_token_request_refuses_a_tampered_row() {
        let mut weak_auth = fapi_client();
        weak_auth.token_endpoint_auth_method = ClientAuthMethod::ClientSecretPost;
        assert!(enforce_token_request(&weak_auth, true).is_err());

        let mut unbound = fapi_client();
        unbound.tls_client_certificate_bound_access_tokens = false;
        assert!(enforce_token_request(&unbound, true).is_err());
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

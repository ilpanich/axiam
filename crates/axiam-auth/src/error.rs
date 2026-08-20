//! Authentication error types.

use axiam_core::error::AxiamError;
use axiam_core::models::webauthn_policy::AttestationDenyReason;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("account is locked")]
    AccountLocked,

    #[error("account is inactive")]
    AccountInactive,

    #[error("account is pending verification")]
    AccountPendingVerification,

    #[error("MFA is required")]
    MfaRequired,

    #[error("invalid MFA code")]
    MfaInvalidCode,

    #[error("MFA is not enrolled for this user")]
    MfaNotEnrolled,

    #[error("token has expired")]
    TokenExpired,

    #[error("invalid token: {0}")]
    TokenInvalid(String),

    #[error("email verification token expired or invalid")]
    VerificationTokenInvalid,

    #[error("email already verified")]
    EmailAlreadyVerified,

    #[error("password reset token expired or invalid")]
    ResetTokenInvalid,

    #[error("federated users cannot reset passwords")]
    FederatedUserPasswordReset,

    #[error("MFA setup token expired or invalid")]
    MfaSetupTokenInvalid,

    #[error("MFA is already configured for this user")]
    MfaAlreadyConfigured,

    #[error("WebAuthn registration failed: {0}")]
    WebauthnRegistration(String),

    #[error("WebAuthn authentication failed: {0}")]
    WebauthnAuthentication(String),

    #[error("WebAuthn state token invalid or expired")]
    WebauthnStateInvalid,

    #[error("no WebAuthn credentials registered for this user")]
    WebauthnNoCredentials,

    #[error("cannot remove the last MFA method while MFA is enabled")]
    MfaCannotRemoveLastMethod,

    /// Generic cryptography failure (use typed sub-variants for new call sites).
    #[error("cryptography error: {0}")]
    Crypto(String),
    /// A client-supplied OPAQUE protocol message was not well formed.
    ///
    /// Distinct from [`Self::Crypto`] because the two have different owners
    /// and therefore different HTTP statuses. A malformed `KE1` is the
    /// caller's mistake and must be a `400`; a stored record that will not
    /// parse is AXIAM's own corruption and must be a `500`. Collapsing them —
    /// which this originally did — meant a client sending junk got a `500`,
    /// which reads as "the server is broken" in every dashboard and pager rule
    /// an operator has.
    ///
    /// It carries no detail about *why* beyond the field name, because a
    /// caller that could distinguish "bad point encoding" from "wrong length"
    /// learns something about the server's parser and nothing it needs.
    #[error("malformed OPAQUE message: {0}")]
    OpaqueMalformed(String),

    /// Key material could not be parsed or decoded (e.g. PEM/DER parse failure).
    #[error("key parse error: {0}")]
    CryptoKeyParse(String),

    /// AES-GCM decryption failure (authentication tag mismatch or wrong key).
    #[error("AES decryption error: {0}")]
    CryptoAesDecrypt(String),

    /// HMAC signature verification failed.
    #[error("HMAC verification failed: {0}")]
    CryptoHmacInvalid(String),

    #[error("new password must differ from the current password")]
    PasswordReusedCurrent,

    /// X3 D7/D11/W2-D1: the registration ceremony completed but the
    /// tenant's attestation policy (`axiam_core::models::webauthn_policy::evaluate`)
    /// denied it, or `webauthn-rs` itself rejected the attestation as
    /// unverifiable (W2-D1 point 3 — a `none`/self-attested credential
    /// presented to the attested ceremony). `reason` is the machine-readable
    /// [`AttestationDenyReason`] for the audit record; the `Display` text is
    /// deliberately the fixed, non-specific message a user is shown — never
    /// a raw library error string (D11).
    #[error("this security key model is not permitted by your organization")]
    WebauthnAttestationDenied { reason: AttestationDenyReason },

    /// X1: a registered reactor refused this login on `login.post_auth`, or a
    /// `fail_closed` reactor could not be reached.
    ///
    /// `reason` is the reactor's own text (or the failure that stood in for
    /// it), carried for the audit record; the `Display` text is deliberately
    /// the fixed, non-specific message the end user is shown — the same D11
    /// split [`AuthError::WebauthnAttestationDenied`] makes. A reactor is
    /// third-party code, and echoing its string to an unauthenticated caller
    /// would let an extension author turn the login endpoint into an oracle
    /// (or an XSS sink) without touching AXIAM.
    #[error("login refused by policy")]
    ReactorDenied { reason: String },

    /// W2-D3: the tenant's policy requires attestation (`mode != none`) but
    /// no attestation CA list could be built — MDS has never been ingested,
    /// or no allowed AAGUID has a known root. Distinct from
    /// [`AuthError::WebauthnAttestationDenied`] (a per-credential policy
    /// decision): this is an operator-facing configuration problem that
    /// blocks *every* attested registration for the tenant, and registration
    /// MUST fail closed here rather than silently falling back to the
    /// unattested ceremony.
    #[error("attestation policy is enabled but no FIDO metadata is available")]
    WebauthnAttestationUnavailable,
}

impl From<AuthError> for AxiamError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::InvalidCredentials
            | AuthError::AccountLocked
            | AuthError::AccountInactive
            | AuthError::AccountPendingVerification
            | AuthError::MfaRequired
            | AuthError::MfaInvalidCode
            | AuthError::MfaNotEnrolled
            | AuthError::WebauthnRegistration(_)
            | AuthError::WebauthnAuthentication(_)
            | AuthError::WebauthnStateInvalid
            | AuthError::WebauthnNoCredentials => AxiamError::AuthenticationFailed {
                reason: err.to_string(),
            },
            AuthError::TokenExpired | AuthError::TokenInvalid(_) => {
                AxiamError::AuthenticationFailed {
                    reason: err.to_string(),
                }
            }
            AuthError::VerificationTokenInvalid
            | AuthError::EmailAlreadyVerified
            | AuthError::ResetTokenInvalid
            | AuthError::FederatedUserPasswordReset
            | AuthError::MfaAlreadyConfigured
            | AuthError::MfaCannotRemoveLastMethod => AxiamError::Validation {
                message: err.to_string(),
            },
            AuthError::MfaSetupTokenInvalid => AxiamError::AuthenticationFailed {
                reason: err.to_string(),
            },
            AuthError::Crypto(msg)
            | AuthError::CryptoKeyParse(msg)
            | AuthError::CryptoAesDecrypt(msg)
            | AuthError::CryptoHmacInvalid(msg) => AxiamError::Crypto(msg),
            AuthError::OpaqueMalformed(msg) => AxiamError::Validation { message: msg },
            AuthError::PasswordReusedCurrent => AxiamError::Validation {
                message: err.to_string(),
            },
            // D11: the end user sees the fixed `Display` text (never the raw
            // `reason`); the raw `AttestationDenyReason` is for the caller to
            // log/audit *before* this conversion happens (see
            // `axiam_auth::webauthn`'s attested-registration path, which logs
            // it at the point of denial).
            AuthError::WebauthnAttestationDenied { .. } => AxiamError::AuthorizationDenied {
                reason: err.to_string(),
                action: Some("webauthn:register".into()),
                resource_id: None,
            },
            AuthError::WebauthnAttestationUnavailable => {
                AxiamError::ServiceUnavailable(err.to_string())
            }
            // The user sees the fixed `Display` text; the reactor's own reason
            // was already written to the audit trail by the gate.
            AuthError::ReactorDenied { .. } => AxiamError::AuthenticationFailed {
                reason: err.to_string(),
            },
        }
    }
}

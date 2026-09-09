//! OAuth2 error types per RFC 6749.

use thiserror::Error;

/// OAuth2-specific errors following RFC 6749 error codes.
#[derive(Debug, Error)]
pub enum OAuth2Error {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),
    #[error("access_denied: {0}")]
    AccessDenied(String),
    #[error("unsupported_response_type: only 'code' response type is supported")]
    UnsupportedResponseType,
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    /// RFC 9449 §5 — a DPoP proof was required and was missing or unusable.
    ///
    /// # Why this is not `invalid_client`
    ///
    /// It was, and it was wrong in both directions. A `private_key_jwt` client
    /// that presented a perfectly valid assertion and no proof was told
    /// `invalid_client: invalid client credentials`, which names the one thing
    /// that was not the problem — so the client cannot tell what to fix, and an
    /// operator reading logs sees an authentication failure that did not
    /// happen. RFC 9449 §5 gives the code for exactly this case, and §7.1 gives
    /// the same code for a proof that fails verification at a resource.
    ///
    /// The OIDF FAPI 2.0 DPoP lane checks it by name:
    /// `CheckTokenEndpointReturnedInvalidRequestGrantOrDPopProofError` accepts
    /// `invalid_request`, `invalid_grant` or `invalid_dpop_proof` and rejects
    /// anything else, `invalid_client` included.
    ///
    /// Carries HTTP **400**, not 401: 401 is for a failure to authenticate the
    /// client (RFC 6749 §5.2), and this is a client that authenticated.
    #[error("invalid_dpop_proof: {0}")]
    InvalidDpopProof(String),
    #[error("invalid_request: {0}")]
    InvalidRedirectUri(String),
    /// B5 — the client is registered `require_par` and sent its parameters
    /// through the browser anyway.
    ///
    /// A distinct variant rather than a plain `InvalidRequest` because of how
    /// the authorize handler decides whether to redirect: `InvalidRequest`
    /// means "we got past client and redirect_uri validation", and is
    /// therefore safe to report by redirecting. This refusal happens
    /// *before* the redirect_uri is validated — deliberately, since the whole
    /// point is that this client's parameters must not travel through the
    /// browser — so redirecting would bounce the user agent to an unvalidated
    /// URI supplied by the very channel the setting forbids. On the wire it
    /// is still `invalid_request` per RFC 9126 §5; the variant exists to keep
    /// the response non-redirecting.
    #[error("invalid_request: {0}")]
    ParRequired(String),
    #[error("unsupported_grant_type: grant type is not supported")]
    UnsupportedGrantType,
    #[error("server_error: {0}")]
    ServerError(String),

    // --- RFC 8628 device-flow polling errors (B2) --------------------------
    //
    // These are NOT failures in the usual sense: `authorization_pending` is
    // the *expected* answer to almost every poll, and `slow_down` is
    // corrective rather than terminal. They are modelled as errors because
    // that is what RFC 8628 §3.5 puts on the wire — a 400 with an `error`
    // field — and because keeping them in one type is what stops the token
    // endpoint growing a second, parallel response path.
    /// The user has not yet approved or denied. The device keeps polling.
    #[error("authorization_pending: the user has not yet completed authorization")]
    AuthorizationPending,
    /// The device is polling faster than the interval it was given. The
    /// interval has been raised; the device must honour the new one.
    #[error("slow_down: polling faster than the permitted interval")]
    SlowDown,
    /// The device code expired before the user acted.
    #[error("expired_token: the device code has expired; restart the flow")]
    ExpiredToken,

    // --- RFC 8693 token exchange (B3) --------------------------------------
    /// RFC 8693 §2.2.2 — the requested `audience`/`resource` is not one the
    /// exchanging client may address. Its own error code rather than
    /// `invalid_request` because a caller can act on it: the target is
    /// well-formed, it is simply not theirs to address.
    #[error("invalid_target: {0}")]
    InvalidTarget(String),

    // --- OIDC Core §3.1.2.6 request objects (X7 G12) -----------------------
    //
    // Their own variants rather than `InvalidRequest` because the codes are
    // the whole point: OIDC Core defines `request_not_supported` and
    // `request_uri_not_supported` precisely so a relying party can tell "I
    // sent a malformed request" from "this server does not do request
    // objects", and a conformance suite matches on the distinction. AXIAM
    // implements neither form — see `authorize::RequestObject` for why.
    /// OIDC Core §3.1.2.6 — `login_required`: the authorization server needs
    /// the end user to authenticate and cannot ask again (W3, plan §4.0).
    ///
    /// The **terminal state of the login hop's loop guard**. A `browser_sso`
    /// client's anonymous authorization request is redirected to the login page
    /// once; if the request that redirect produces comes back still carrying no
    /// principal, this is the answer, and it is deliberately not another
    /// redirect. See `crate::login_hop` for the argument that this bounds the
    /// chain at two authorization requests.
    ///
    /// Answered **directly**, not by redirecting to the relying party. W3
    /// honours no authentication-request parameter, so it builds no
    /// parameter-driven redirect error; the loop guard is a server-side safety
    /// valve for a deployment that is misconfigured or a browser that is
    /// refusing cookies, and neither is something the relying party can act on
    /// by being told in a query string.
    #[error("login_required: {0}")]
    LoginRequired(String),

    /// OIDC Core §3.1.2.6 — `consent_required`: the end user has not consented
    /// to something this request needs, and `prompt=none` forbids asking.
    ///
    /// **Unreachable in W4, deliberately and stated rather than hidden.** The
    /// only thing that could require consent is a consent-gated scope, and
    /// there are none until W7 defines `address` and `phone` (plan §4.8). The
    /// variant exists because the four OIDC interaction errors are one
    /// vocabulary and splitting it across two waves is how an error code comes
    /// to be spelled twice; the honour lane raises it nowhere, and
    /// `crate::honour` has no branch that could.
    #[error("consent_required: {0}")]
    ConsentRequired(String),

    /// OIDC Core §3.1.2.6 — `interaction_required`: some interaction other
    /// than authentication or consent is needed, and `prompt=none` forbids it.
    ///
    /// **Also unreachable in W4.** Every `prompt=none` refusal the honour lane
    /// can produce has a more specific name — `login_required` for a missing,
    /// stale or mismatched authentication, `account_selection_required` when a
    /// hint mismatch is the cause, `unmet_authentication_requirements` for an
    /// essential `acr` — and OIDC Core asks for the most specific code that
    /// applies. It is declared with its siblings for the same reason
    /// [`Self::ConsentRequired`] is.
    #[error("interaction_required: {0}")]
    InteractionRequired(String),

    /// OIDC Core §3.1.2.6 — `account_selection_required`: the end user needs
    /// to choose a session, and this request could not choose for them.
    ///
    /// Raised on the return leg of a login hop when `prompt=select_account`
    /// was asked and the `id_token_hint` still names somebody other than
    /// whoever signed in (plan §4.2). Without `select_account` the same state
    /// is `login_required`: the relying party did not ask about accounts, so
    /// naming accounts in the answer would tell it something it did not ask.
    #[error("account_selection_required: {0}")]
    AccountSelectionRequired(String),

    /// OpenID Connect Core Error Code `unmet_authentication_requirements` 1.0
    /// — an **essential** authentication context class the end user did not
    /// reach.
    ///
    /// Distinct from `login_required` because the two ask the relying party
    /// for different things: `login_required` says "send them back and they
    /// can sign in", and this says "they signed in, and this deployment cannot
    /// give you the assurance level you require of them" — commonly a user
    /// with no second factor enrolled against a request for
    /// [`crate::acr::Acr::MultiFactor`]. Answering `login_required` there
    /// invites a loop the relying party drives.
    ///
    /// Never accompanied by a token, at any point. That is the whole
    /// difference between an essential and a voluntary `acr` request.
    #[error("unmet_authentication_requirements: {0}")]
    UnmetAuthenticationRequirements(String),

    /// OIDC Core §3.1.2.6 — `invalid_request_uri`, raised on the **return leg
    /// of a login hop** when the pushed request the browser left with is gone
    /// (W3, plan §4.0 and F10).
    ///
    /// A PAR `request_uri` lives 60 seconds (RFC 9126 §2.2, and `par.rs`'s own
    /// constant). A user who takes longer than that to type a password comes
    /// back to an authorization endpoint that has nothing to consume — and
    /// telling them `invalid_request: request_uri is unknown, expired, or used`
    /// describes a client bug that did not happen. This code says the recoverable
    /// thing instead, which is what OIDC Core defines it for: the relying party
    /// pushes again and restarts.
    ///
    /// Raised **only** on a request carrying `axiam_login_hop`; an ordinary
    /// authorization request with a dead `request_uri` gets the same
    /// `invalid_request` it has always got, because changing that would change
    /// behaviour for a client registered today.
    #[error("invalid_request_uri: {0}")]
    InvalidRequestUri(String),

    /// OIDC Core §3.1.2.6 — a `request` parameter (a request object by value).
    #[error(
        "request_not_supported: this server does not accept request objects; send the \
             authorization parameters directly, or push them to /oauth2/par"
    )]
    RequestNotSupported,
    /// OIDC Core §3.1.2.6 — a `request_uri` that is not a PAR handle.
    #[error(
        "request_uri_not_supported: request_uri accepts only a \
             urn:ietf:params:oauth:request_uri: value obtained from /oauth2/par (RFC 9126); \
             this server does not fetch request objects by reference"
    )]
    RequestUriNotSupported,
}

impl OAuth2Error {
    /// RFC 6749 error code string.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::UnauthorizedClient(_) => "unauthorized_client",
            Self::AccessDenied(_) => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope(_) => "invalid_scope",
            Self::InvalidGrant(_) => "invalid_grant",
            Self::InvalidClient(_) => "invalid_client",
            Self::InvalidDpopProof(_) => "invalid_dpop_proof",
            Self::InvalidRedirectUri(_) => "invalid_request",
            Self::ParRequired(_) => "invalid_request",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::ServerError(_) => "server_error",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::InvalidTarget(_) => "invalid_target",
            Self::LoginRequired(_) => "login_required",
            Self::ConsentRequired(_) => "consent_required",
            Self::InteractionRequired(_) => "interaction_required",
            Self::AccountSelectionRequired(_) => "account_selection_required",
            Self::UnmetAuthenticationRequirements(_) => "unmet_authentication_requirements",
            Self::InvalidRequestUri(_) => "invalid_request_uri",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
        }
    }

    /// Human-readable error description for the `error_description` field.
    ///
    /// Strips the RFC error-code prefix from the Display output so that
    /// `error_description` contains only the message (the code goes in
    /// the separate `error` field per RFC 6749 §5.2).
    pub fn error_description(&self) -> String {
        let full = self.to_string();
        // Display format is "error_code: message"; extract the message part.
        match full.split_once(": ") {
            Some((_, msg)) => msg.to_string(),
            None => full,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OIDC interaction vocabulary, pinned as strings.
    ///
    /// These five codes are what a relying party matches on and what the
    /// conformance suite's
    /// `CheckErrorFromAuthorizationEndpointIsOneThatRequiredAUserInterface`
    /// accepts; a typo in one of them is invisible to every type in the
    /// codebase and visible to every client. Two of the five are unreachable
    /// in W4 — see their doc comments — and are pinned anyway so the wave that
    /// reaches them inherits the spelling rather than choosing it again.
    #[test]
    fn the_oidc_interaction_error_codes_are_spelled_as_the_specification_spells_them() {
        for (error, code) in [
            (OAuth2Error::LoginRequired(String::new()), "login_required"),
            (
                OAuth2Error::ConsentRequired(String::new()),
                "consent_required",
            ),
            (
                OAuth2Error::InteractionRequired(String::new()),
                "interaction_required",
            ),
            (
                OAuth2Error::AccountSelectionRequired(String::new()),
                "account_selection_required",
            ),
            (
                OAuth2Error::UnmetAuthenticationRequirements(String::new()),
                "unmet_authentication_requirements",
            ),
        ] {
            assert_eq!(error.error_code(), code);
        }
    }

    /// The description carries the message and not the code — the two travel
    /// in separate members of the RFC 6749 §5.2 body.
    #[test]
    fn the_description_does_not_repeat_the_code() {
        let e = OAuth2Error::UnmetAuthenticationRequirements("no second factor enrolled".into());
        assert_eq!(e.error_description(), "no second factor enrolled");
        assert!(!e.error_description().contains("unmet_authentication"));
    }
}

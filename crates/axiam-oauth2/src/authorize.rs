//! OAuth2 authorization code grant — authorization endpoint logic.

use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::CreateAuthorizationCode;
use axiam_core::models::session::Amr;
use axiam_core::repository::{AuthorizationCodeRepository, OAuth2ClientRepository};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::authn_params::AuthnRequestParams;
use crate::error::OAuth2Error;

/// Authorization request parameters (from query string).
#[derive(Debug)]
pub struct AuthorizeRequest {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// OIDC nonce — passed through to the authorization code for
    /// inclusion in the ID token.
    pub nonce: Option<String>,
    /// B5 — the AXIAM session this authorization is happening within, stored
    /// on the code so the ID token minted from it can assert `sid`.
    pub session_id: Option<Uuid>,
    /// B5 — whether these parameters arrived via `/oauth2/par` rather than on
    /// the query string.
    ///
    /// Carried here rather than checked in the handler because the
    /// `require_par` decision needs the client registration, which this
    /// service already fetches; doing it in the handler would mean a second
    /// lookup of the same row and a second place for the policy to drift.
    pub via_par: bool,
    /// X7.1 — the OIDC authentication-request parameters, parsed once from
    /// whichever carrier delivered them.
    ///
    /// Here for the same reason `via_par` is: the decision they feed needs the
    /// client registration this service already loaded. The gate
    /// (`crate::fapi`) reads which of them arrived and refuses a `fapi2`
    /// client the five that carry security; W4's honour lane
    /// (`crate::honour`) is what reads their *meaning*, and only for a client
    /// registered `authn_request_params: honour`.
    pub authn_params: AuthnRequestParams,
    /// X7 G12 — a request-object parameter the server refuses (plan §4.10).
    ///
    /// Carried rather than answered in the handler so that the refusal is
    /// reported only *after* the client and its `redirect_uri` have been
    /// validated. A request object is refused whatever happens; what this
    /// buys is that the refusal is never redirected to a URI the request
    /// itself supplied.
    pub request_object: Option<RequestObject>,
    /// X7.2 — the authentication behind [`Self::session_id`], as it stood when
    /// this request arrived (plan §4.3).
    ///
    /// Resolved by the handler, which owns the session repository, and
    /// snapshotted onto the authorization code below. It is a snapshot and not
    /// a join because the session may be gone by the time the code is
    /// redeemed — refresh rotation replaces the row — and evidence that cannot
    /// be resolved at redemption is evidence that quietly becomes `None`.
    ///
    /// Empty when the session could not be read at all. That is the strict
    /// direction and never an error: an authorization request must not start
    /// failing because of a column this wave added.
    pub session_evidence: SessionEvidence,
    /// W4 — the decoded `id_token_hint`, when one arrived and verified
    /// (plan §4.2).
    ///
    /// Decoded by the handler, which holds the signing key, and decoded
    /// unconditionally rather than only for the honour lane: the decode is a
    /// signature check over a value the request already carried, it changes no
    /// response, and making it conditional would put the lane decision in two
    /// places. Only [`crate::honour`] reads it, and only on the honour lane.
    ///
    /// `None` when no hint arrived **and** when one arrived and did not verify.
    /// The two are distinguished by [`AuthnRequestParams::id_token_hint`], and
    /// the second is treated as a hint naming somebody else — never as an
    /// absent hint, which would let an unsigned string turn a `prompt=none`
    /// refusal into a code.
    pub id_token_hint: Option<crate::logout::IdTokenHint>,
    /// W4 — whether the query string carried an authentication-request
    /// parameter alongside a `request_uri` (plan §4.1, test T1.3).
    ///
    /// The seven original parameters (`response_type`, `redirect_uri`,
    /// `scope`, `code_challenge` and friends) are **ignored** when duplicated
    /// beside a `request_uri`, which is what RFC 9101 §6.3 requires and what
    /// RFC 9126 §4 adopts by reference. The nine OIDC authentication-request
    /// parameters are refused **only on the honour lane**,
    /// which is where the refusal is worth anything: there a browser adding
    /// `prompt=none` to somebody's pushed request would be changing what the
    /// request means, and on the `ignore` lane it would be adding a parameter
    /// that is dropped either way. Refusing it for every client would change
    /// the answer given to a client registered today, which is the one thing
    /// this plan does not do.
    pub inline_authn_params_beside_request_uri: bool,
    /// W7 — what the handler resolved about this request's GDPR-sensitive
    /// scopes (X7 G8, plan §4.8).
    ///
    /// Carried rather than looked up here for the reason
    /// [`Self::session_evidence`] is: deciding needs the tenant's effective
    /// settings and the user's consent records, and this service owns neither
    /// repository. What it owns is the *order* — the decision has to be taken
    /// after the client, the `redirect_uri` and the scopes are validated and
    /// before a code exists, and this is the only place that is true.
    ///
    /// [`crate::sensitive::Requested::None`] for every request that asks for
    /// no sensitive scope, which is every request in every deployment today.
    pub sensitive_scopes: crate::sensitive::Requested,
    /// W7 — whether the tenant's effective settings have the sensitive scopes
    /// switched off.
    ///
    /// Separate from [`Self::sensitive_scopes`] so that the two facts, which
    /// arrive from two different reads, are checked against each other rather
    /// than collapsed by the caller into one that could be wrong. See
    /// `crate::sensitive::decide`.
    pub sensitive_scopes_switch_is_off: bool,
    /// T21.4 / D4 — what the handler resolved about this request's
    /// external-client consent.
    ///
    /// Carried rather than looked up here for the reason
    /// [`Self::sensitive_scopes`] is: deciding needs the user's consent
    /// records and this service owns no such repository. What it owns is the
    /// order — after the client and its `redirect_uri` are known good, before
    /// a code exists.
    ///
    /// [`crate::external_consent::Requested::NotApplicable`] for every client
    /// an administrator created, which is every client in every deployment
    /// today (I1).
    pub external_consent: crate::external_consent::Requested,
    /// W7 — whether this request carries
    /// [`crate::login_hop::CONSENT_HOP_MARKER`], i.e. has already been through
    /// the **consent** page once.
    ///
    /// Distinct from [`Self::login_hop_return_leg`] on purpose: that one says
    /// the browser has been to a first-party page, and this one says the end
    /// user has been asked about consent and did not give it. A request
    /// carrying `prompt=consent` and `address` needs both ceremonies, in that
    /// order, and conflating the markers would answer the second question with
    /// the first one's evidence — `access_denied` for somebody who was never
    /// shown the question.
    pub consent_hop_return_leg: bool,
    /// W4 — whether this request carries
    /// [`crate::login_hop::LOGIN_HOP_MARKER`], i.e. has already been through
    /// the sign-in page once.
    ///
    /// The honour lane's termination argument rests on it: a requirement that
    /// survives one interaction is answered rather than retried. See
    /// [`crate::honour`].
    pub login_hop_return_leg: bool,
    /// RFC 9449 §10 — the DPoP key this authorization is pinned to, if any.
    ///
    /// Resolved by the handler, which is the only layer holding both of
    /// §10's carriers: the `dpop_jkt` request parameter and the thumbprint of
    /// a `DPoP` proof presented at the PAR endpoint. Snapshotted onto the
    /// authorization code below and compared at redemption — the comparison
    /// is the whole of §10.1, and it can only happen at the token endpoint,
    /// which is why the value has to survive the round trip through the
    /// browser rather than be re-derived there.
    ///
    /// Read from the *pushed* copy when there is one, never from the query
    /// string beside a `request_uri`, for the reason `state` and `nonce` are:
    /// a key the client pinned under client authentication must not be
    /// substitutable by the browser that merely carries the handle.
    pub dpop_jkt: Option<String>,
    /// OIDC Core §5.5 — the UserInfo claims this request asked for by name.
    ///
    /// Resolved by the handler through [`crate::claims_request::userinfo_claims`],
    /// which is where the raw `claims` parameter is parsed and filtered to what
    /// AXIAM will release on a request alone. Snapshotted onto the
    /// authorization code for the same reason `dpop_jkt` is: UserInfo runs on
    /// a later request that holds nothing but an access token, so anything it
    /// must honour has to survive the round trip rather than be re-derived.
    pub requested_userinfo_claims: Vec<String>,
    /// T21.3 / RFC 8707 §2 — the target service this authorization is for.
    ///
    /// Read from the *pushed* copy when there is one, never from the query
    /// string beside a `request_uri`, for the reason `state`, `nonce` and
    /// `dpop_jkt` are: a target the client named under client authentication
    /// must not be substitutable by the browser that merely carries the
    /// handle.
    ///
    /// Validated below against the client's `allowed_resources` and
    /// snapshotted onto the authorization code, which is what makes the token
    /// minted at redemption carry it as `aud`. `None` for every request that
    /// sends no `resource`, which is every request in every deployment today
    /// — and such a request mints `axiam:user` exactly as it always did (I2).
    pub resource: Option<String>,
}

/// What an authorization request earned (W4, plan §4.2).
///
/// Before W4 the answer was a code or an error. The honour lane adds a third:
/// *the end user has to do something first*. It is modelled here rather than
/// as an `OAuth2Error` variant because it is not an error and must not be
/// reported like one — it produces a redirect to this deployment's own sign-in
/// page, not a redirect to the relying party — and because the service is the
/// only place that can decide it: the decision needs the client registration,
/// the validated `redirect_uri` and the session evidence at once.
#[derive(Debug)]
pub enum AuthorizeOutcome {
    /// A code was issued. Redirect to the relying party.
    Code(AuthorizeResponse),
    /// The end user must authenticate before this request can be answered.
    /// Send the browser through the login hop (`crate::login_hop`).
    Interact(crate::honour::Interaction),
}

/// The authentication evidence snapshotted onto an authorization code.
///
/// A distinct type from [`axiam_core::models::session::AuthenticationEvidence`]
/// (which is an *input* to session creation, and whose `authenticated_at` is
/// therefore not optional) because here the absence of evidence is a real and
/// expected state: a session row this build cannot read, or a grant with no
/// browser session behind it at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionEvidence {
    /// When the end user authenticated, from `session.authenticated_at`.
    pub auth_time: Option<chrono::DateTime<Utc>>,
    /// The methods that authentication used.
    pub amr: Vec<Amr>,
}

/// Which form of request object arrived (X7 G12, plan §4.10).
///
/// AXIAM implements neither, and §9 of the plan records why nobody should
/// "helpfully" implement them later: JAR by value duplicates PAR's purpose
/// with a weaker integrity story, and `request_uri` by reference is an SSRF
/// primitive — the authorization server fetches an attacker-chosen URL — which
/// PAR (RFC 9126 §1) made unnecessary. FAPI 2.0 requires PAR and does not
/// require JAR.
///
/// Modelled as a type rather than answered with a bare string so the two
/// distinct OIDC error codes cannot be swapped: the suite matches on them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestObject {
    /// A `request` parameter — a request object by value (RFC 9101).
    ByValue,
    /// A `request_uri` that is not a `urn:ietf:params:oauth:request_uri:`
    /// value, i.e. a request object by reference rather than a PAR handle.
    ByReference,
}

impl RequestObject {
    /// The OIDC Core §3.1.2.6 error this refusal answers with.
    pub fn into_error(self) -> OAuth2Error {
        match self {
            Self::ByValue => OAuth2Error::RequestNotSupported,
            Self::ByReference => OAuth2Error::RequestUriNotSupported,
        }
    }
}

/// Authorization response -- contains the code to return to the client.
#[derive(Debug)]
pub struct AuthorizeResponse {
    pub code: String,
    pub state: Option<String>,
    pub redirect_uri: String,
}

/// OAuth2 authorization service -- handles the authorization code grant.
#[derive(Clone)]
pub struct AuthorizeService<OC, AC> {
    client_repo: OC,
    code_repo: AC,
    code_lifetime_secs: u64,
}

impl<OC, AC> AuthorizeService<OC, AC>
where
    OC: OAuth2ClientRepository,
    AC: AuthorizationCodeRepository,
{
    pub fn new(client_repo: OC, code_repo: AC, code_lifetime_secs: u64) -> Self {
        Self {
            client_repo,
            code_repo,
            code_lifetime_secs,
        }
    }

    /// Process an authorization request.
    ///
    /// Answers with a code, with a request for an interaction (W4's honour
    /// lane — see [`AuthorizeOutcome`]), or with an error. Everything a
    /// relying party may be *redirected* an error about happens after step 2,
    /// where the client and its `redirect_uri` have been validated.
    pub async fn authorize(&self, req: AuthorizeRequest) -> Result<AuthorizeOutcome, OAuth2Error> {
        // 1. Look up client — must happen BEFORE any redirectable
        //    errors to avoid open-redirect to unvalidated URIs.
        let client = self
            .client_repo
            .get_by_client_id(req.tenant_id, &req.client_id)
            .await
            .map_err(|e| match e {
                // QUAL-03/D-11: only a genuinely-unknown client maps to
                // invalid_client. Any other error (e.g. a DB outage) must
                // surface as a distinct server error, never masquerade as
                // bad client credentials (error-oracle).
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient("client not found".into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        // 1b. B5 / RFC 9126 §5: a client registered as PAR-only may not send
        //     its parameters through the browser. Checked before the redirect
        //     is validated, and answered as a non-redirecting error, because
        //     bouncing the user agent to a redirect_uri that arrived by the
        //     very channel the client forbade would defeat the setting.
        if client.require_par && !req.via_par {
            return Err(OAuth2Error::ParRequired(
                "this client must use pushed authorization requests \
                 (RFC 9126); send parameters to /oauth2/par first"
                    .into(),
            ));
        }

        // 2. Validate redirect_uri — also before any redirectable
        //    errors per RFC 6749 §4.1.2.1.
        //
        // T21.2: `contains()` became `any_redirect_uri_matches`, which IS
        // `contains()` for every URI that is not a registered `http` loopback
        // one — see `crate::redirect_uri` for why the non-loopback path
        // compares strings rather than parsed URLs, and for the RFC 8252 §7.3
        // allowance that is the whole of the difference.
        if !crate::redirect_uri::any_redirect_uri_matches(&client.redirect_uris, &req.redirect_uri)
        {
            return Err(OAuth2Error::InvalidRedirectUri(
                "redirect_uri not registered".into(),
            ));
        }

        // 2b. SEC-025: Enforce PKCE for public clients.
        // Per OAuth 2.0 Security BCP §7.6 and RFC 7636, public clients MUST use PKCE.
        //
        // T21.2: publicness is what the REGISTRATION says
        // (`token_endpoint_auth_method: none`), not what the stored hash looks
        // like. The empty-hash arm is kept beside it rather than replaced by
        // it: before T21.2 it was the whole test, and a deployment that
        // reached that state some other way — a half-finished migration, a
        // hand-edited row — has had PKCE required of it ever since SEC-025.
        // Dropping the arm would quietly stop requiring it there, which is a
        // weakening no part of this task asked for. The union is fail-closed
        // and identical to today's answer for every client that exists.
        let is_public_client =
            client.token_endpoint_auth_method.is_public() || client.client_secret_hash.is_empty();
        if is_public_client && req.code_challenge.is_none() {
            return Err(OAuth2Error::InvalidRequest(
                "PKCE (code_challenge) is required for public clients".into(),
            ));
        }

        // Parsed here rather than at step 5 because the FAPI gate below reads
        // it: W7's rule 4 refuses a `fapi2` request that asks for a sensitive
        // scope, and it has to ask what the *request* wanted. Pure and
        // allocation-cheap, and step 5 uses the same vector, so nothing is
        // parsed twice and the two cannot come to disagree about what
        // `scope=openid  profile` means.
        let scopes = parse_scopes(req.scope.as_deref());

        // 2c. X5.1: under the FAPI 2.0 profile PKCE is required of *every*
        //     client, confidential ones included (FAPI 2.0 §5.3.1.2). A no-op
        //     for a `standard` client, which is every client that predates
        //     X5.1. `S256`-only is already enforced for everybody at step 6,
        //     so this is the whole of the remaining gap.
        crate::fapi::enforce_authorization_request(
            &client,
            req.code_challenge.as_deref(),
            &req.authn_params,
            &scopes,
        )?;

        // 2d. X7 G12: request objects are refused, with the error code OIDC
        //     Core §3.1.2.6 defines for each form. Placed *after* redirect_uri
        //     validation so the refusal redirects only to a URI this client
        //     registered, and *before* every other redirectable error so the
        //     suite sees `request_not_supported` rather than whichever
        //     complaint the rest of the request happens to earn first.
        if let Some(object) = req.request_object {
            return Err(object.into_error());
        }

        // 3. Validate response_type (now safe to redirect errors)
        if req.response_type != "code" {
            return Err(OAuth2Error::UnsupportedResponseType);
        }

        // 4. Validate grant type
        if !client.grant_types.iter().any(|s| s == "authorization_code") {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for authorization_code grant".into(),
            ));
        }

        // 5. Validate the scopes (parsed above) against the client's
        //    registered set.
        if req.scope.is_some() {
            let invalid: Vec<&str> = scopes
                .iter()
                .filter(|s| !client.scopes.contains(s))
                .map(String::as_str)
                .collect();
            if !invalid.is_empty() {
                return Err(OAuth2Error::InvalidScope(format!(
                    "unregistered scopes: {}",
                    invalid.join(", ")
                )));
            }
        }

        // 6. Validate PKCE parameters
        if req.code_challenge.is_some() {
            match req.code_challenge_method.as_deref() {
                None => {
                    return Err(OAuth2Error::InvalidRequest(
                        "code_challenge_method required when \
                         code_challenge is present"
                            .into(),
                    ));
                }
                Some("S256") => {}
                Some(_) => {
                    return Err(OAuth2Error::InvalidRequest(
                        "only S256 code_challenge_method is supported".into(),
                    ));
                }
            }
        } else if req.code_challenge_method.is_some() {
            return Err(OAuth2Error::InvalidRequest(
                "code_challenge required with code_challenge_method".into(),
            ));
        }

        // 6a. W4 — a pushed request may not be topped up through the browser
        //     (plan §4.1, T1.3). Honour lane only; see the field's docs.
        if crate::fapi::honours_authn_params(&client) && req.inline_authn_params_beside_request_uri
        {
            return Err(OAuth2Error::InvalidRequest(
                "request_uri must not be combined with inline authorization parameters".into(),
            ));
        }

        // 6b. W4 — the honour lane (plan §4.2/§4.3/§4.4).
        //
        // Placed here, and this is the whole of why: every gate above has run,
        // so the client is known, the `redirect_uri` is one this client
        // registered, and any error raised from now on is safe to report by
        // redirecting; and no code has been generated, so a request that needs
        // an interaction has not already minted the thing the interaction was
        // supposed to gate.
        //
        // For a client on the `ignore` lane — which is every client registered
        // today — this block does nothing at all: `honour_lane` is false, no
        // parameter is read, and no `acr` is recorded. That is invariant 4.
        let acr = if crate::fapi::honours_authn_params(&client) {
            match crate::honour::evaluate(crate::honour::Request {
                params: &req.authn_params,
                auth_time: req.session_evidence.auth_time,
                amr: &req.session_evidence.amr,
                subject: req.user_id,
                client_id: &req.client_id,
                id_token_hint: req.id_token_hint.as_ref(),
                return_leg: req.login_hop_return_leg,
                now: Utc::now(),
            }) {
                crate::honour::Outcome::Proceed { acr } => acr.map(str::to_owned),
                crate::honour::Outcome::Interact(interaction) => {
                    return Ok(AuthorizeOutcome::Interact(interaction));
                }
                crate::honour::Outcome::Refuse(error) => return Err(error),
            }
        } else {
            None
        };

        // 6c. W7 — the sensitive-scope consent gate (plan §4.8).
        //
        // **After** the honour lane, deliberately: a consent screen asks a
        // person a question, and there is no person to ask until
        // authentication has been settled. If W4's evaluation wanted an
        // interaction it has already returned above, and the consent question
        // is put on the leg that comes back.
        //
        // **Before** the code, for the reason the whole of 6b is placed where
        // it is: an interaction that gates a release must not be asked for
        // after the thing it gates has been minted.
        //
        // `prompt=none` is read only on the honour lane. A client registered
        // `ignore` has the parameter dropped everywhere else in this server,
        // and a wave that started reading it here would be breaking
        // invariant 4 to do it.
        let prompt_none = crate::fapi::honours_authn_params(&client)
            && req
                .authn_params
                .prompt
                .contains(&crate::authn_params::Prompt::None);
        match crate::sensitive::decide(
            req.sensitive_scopes,
            req.sensitive_scopes_switch_is_off,
            req.consent_hop_return_leg,
            prompt_none,
        ) {
            crate::sensitive::Decision::Proceed => {}
            crate::sensitive::Decision::AskForConsent => {
                return Ok(AuthorizeOutcome::Interact(crate::honour::Interaction {
                    required_acr: None,
                    reason: crate::honour::Reason::ConsentRequired,
                }));
            }
            crate::sensitive::Decision::Refuse(refusal) => {
                return Err(match refusal {
                    crate::sensitive::Refusal::Disabled => OAuth2Error::InvalidScope(
                        "the address and phone scopes are not enabled for this tenant".into(),
                    ),
                    crate::sensitive::Refusal::ConsentRequired => OAuth2Error::ConsentRequired(
                        "releasing the requested scopes needs the end user's consent, and \
                         prompt=none forbids asking for it"
                            .into(),
                    ),
                    crate::sensitive::Refusal::Declined => OAuth2Error::AccessDenied(
                        "the end user did not consent to releasing the requested scopes".into(),
                    ),
                });
            }
        }

        // 6d. T21.3 / RFC 8707 §2 — the resource indicator.
        //
        // Placed with the other per-request validations and **after** the
        // client and its `redirect_uri` are known good, so an `invalid_target`
        // is reported by redirecting to a URI this client registered rather
        // than rendered at AXIAM's own origin (T-255). Placed **before** the
        // code exists, so a request naming a resource this client may not
        // address never mints the credential it was going to be refused for.
        //
        // A request that sends no `resource` gets `Ok(None)` and nothing
        // below it changes: the code stores no resource, the token endpoint
        // mints `axiam:user`, and the whole of this block is invisible (I2).
        let resource =
            crate::resource::resolve_requested(&client.allowed_resources, req.resource.as_deref())?;

        // 6e. T21.4 / D4 — the external-client consent gate.
        //
        // **Beside** 6c rather than folded into it, because the two ask
        // different questions about different things: W7 asks whether the end
        // user agreed to release a postal address, and this asks whether they
        // agreed to this application acting as them at all. They share a
        // consent record namespace (see `crate::external_consent`) and nothing
        // else, and a request can only ever be in one of them — a
        // self-registered client cannot hold `address` or `phone`, because the
        // settings layer refuses those scopes in `dcr_allowed_scopes`.
        //
        // **After 6d**, the resource check, and that placement is the whole
        // reason this block is here rather than beside 6c. Asking a person to
        // approve a request that cannot succeed is the failure T-270 is about:
        // a request naming a resource this client may not address is refused
        // whatever the user says, so refusing it first means nobody is
        // interrupted for nothing. Moving 6d in front of 6c instead would have
        // been the same improvement for W7 — and would have changed the answer
        // an existing client gets, which is what I1 forbids. This gate is new,
        // so it can simply be placed correctly.
        //
        // **Before the code**, for the reason the whole 6b-6e run is ordered
        // this way: an interaction that gates a credential must not be asked
        // for after the credential exists.
        //
        // For a client an administrator created — every client in every
        // deployment today — `req.external_consent` is `NotApplicable` and
        // this block compiles down to one comparison and no branch taken (I1).
        match crate::external_consent::decide(
            req.external_consent,
            req.consent_hop_return_leg,
            prompt_none,
        ) {
            crate::external_consent::Decision::Proceed => {}
            crate::external_consent::Decision::AskForConsent => {
                return Ok(AuthorizeOutcome::Interact(crate::honour::Interaction {
                    required_acr: None,
                    reason: crate::honour::Reason::ConsentRequired,
                }));
            }
            crate::external_consent::Decision::Refuse(refusal) => {
                return Err(match refusal {
                    crate::external_consent::Refusal::ConsentRequired => {
                        OAuth2Error::ConsentRequired(
                            "this client was not registered by an administrator of this tenant, \
                             so the end user must be asked before it may act as them, and \
                             prompt=none forbids asking"
                                .into(),
                        )
                    }
                    crate::external_consent::Refusal::Declined => OAuth2Error::AccessDenied(
                        "the end user did not consent to this client acting as them".into(),
                    ),
                });
            }
        }

        // 7. Generate random authorization code
        let raw_code = generate_auth_code();
        let code_hash = hash_code(&raw_code);

        // 8. Store authorization code
        //
        // The lifetime is the deployment's, capped by the client's profile:
        // FAPI 2.0 §5.3.2.1 caps an authorization code at 60 seconds, and
        // AXIAM's default is 600. See `crate::fapi::auth_code_lifetime_secs`
        // for why this is a per-client cap rather than a lower global default.
        let lifetime = i64::try_from(crate::fapi::auth_code_lifetime_secs(
            &client,
            self.code_lifetime_secs,
        ))
        .expect("code_lifetime_secs exceeds i64::MAX");
        let expires_at = Utc::now() + chrono::Duration::seconds(lifetime);
        let _stored = self
            .code_repo
            .create(CreateAuthorizationCode {
                tenant_id: req.tenant_id,
                client_id: req.client_id,
                user_id: req.user_id,
                code_hash,
                redirect_uri: req.redirect_uri.clone(),
                scopes,
                code_challenge: req.code_challenge,
                code_challenge_method: req.code_challenge_method,
                nonce: req.nonce,
                session_id: req.session_id,
                // X7.2: snapshotted here, at issuance, because this is the
                // last moment the session behind the code is known to exist.
                auth_time: req.session_evidence.auth_time,
                // W4 — derived from the session's evidence by
                // `crate::acr::acr_for`, which cannot see this request, and
                // then filtered through `report_acr`, which can only select
                // among values that evidence already satisfies. `None` for
                // every client on the `ignore` lane and for any request with
                // no session to speak for.
                acr,
                amr: req.session_evidence.amr,
                // RFC 9449 §10.1 — snapshotted for the same reason
                // `code_challenge` is: it is a commitment the client made
                // under client authentication, and the token request that
                // redeems this code has to be checked against the commitment
                // as it stood then, not against anything it sends now.
                dpop_jkt: req.dpop_jkt,
                requested_userinfo_claims: req.requested_userinfo_claims,
                // RFC 8707 — snapshotted in its normalised form, for the
                // reason `code_challenge` is: the client committed to this
                // target here, and the token request that redeems the code is
                // answered against the commitment as it stood now.
                resource,
                expires_at,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // 9. T21.4 — stamp the sweeper's "last used" marker, for an externally
        //    registered client and for nothing else.
        //
        // The `if` is invariant I1 kept exact rather than an optimisation: an
        // administrator's client reaches the end of this function having made
        // exactly the repository calls it made before this task, and a second
        // write on the hot path of every authorization in every deployment
        // would be a behaviour change even though no response would differ.
        // The repository statement carries the same condition, so the
        // restriction does not depend on this line staying written.
        //
        // Best effort, deliberately: the code has already been created and the
        // user has already consented, so failing the authorization now would
        // turn a bookkeeping error into a sign-in the end user has to repeat.
        // The cost of a lost stamp is a client swept one cycle early, which is
        // recoverable by registering again — the cost of a failed
        // authorization is not.
        if client.managed_by.is_external()
            && let Err(e) = self
                .client_repo
                .touch_last_authorized(req.tenant_id, &client.client_id, Utc::now())
                .await
        {
            tracing::warn!(
                error = %e,
                client_id = %client.client_id,
                "could not stamp last_authorized_at on an externally registered client; it may \
                 be swept as unused earlier than its tenant's TTL intends"
            );
        }

        Ok(AuthorizeOutcome::Code(AuthorizeResponse {
            code: raw_code,
            state: req.state,
            redirect_uri: req.redirect_uri,
        }))
    }
}

/// Generate a cryptographically random authorization code (32 bytes, base64url).
fn generate_auth_code() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rand::RngExt::random(&mut rng);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 hash of an authorization code, hex-encoded.
pub fn hash_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

/// Parse the `scope` parameter into a vec.
///
/// When the request omits `scope`, an empty set is returned rather
/// than the client's full registered scopes. This prevents implicit
/// granting of `openid` (and the associated ID token issuance) when
/// the client didn't explicitly request it.
fn parse_scopes(scope: Option<&str>) -> Vec<String> {
    match scope {
        Some(s) => s.split_whitespace().map(String::from).collect(),
        None => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests — SEC-025 PKCE enforcement
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::oauth2_client::AuthnRequestParamsMode;
    use axiam_core::models::oauth2_client::{
        AuthorizationCode, CreateAuthorizationCode, CreateOAuth2Client, OAuth2Client,
        UpdateOAuth2Client,
    };
    use axiam_core::repository::{
        AuthorizationCodeRepository, OAuth2ClientRepository, PaginatedResult, Pagination,
    };
    use chrono::Utc;
    use uuid::Uuid;

    // ---- Mock repositories ----

    #[derive(Clone)]
    struct MockClientRepo {
        client: OAuth2Client,
    }

    impl OAuth2ClientRepository for MockClientRepo {
        async fn create(&self, _input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
            unimplemented!()
        }
        async fn upsert_cimd_client(
            &self,
            _client_id: &str,
            _input: CreateOAuth2Client,
        ) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn get_by_id(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn get_by_client_id(
            &self,
            _tenant_id: Uuid,
            _client_id: &str,
        ) -> AxiamResult<OAuth2Client> {
            Ok(self.client.clone())
        }
        async fn update(
            &self,
            _tid: Uuid,
            _id: Uuid,
            _input: UpdateOAuth2Client,
        ) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn delete(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }
        async fn list(
            &self,
            _tid: Uuid,
            _page: Pagination,
        ) -> AxiamResult<PaginatedResult<OAuth2Client>> {
            unimplemented!()
        }
        async fn upgrade_client_secret_hash(
            &self,
            _tid: Uuid,
            _client_id: &str,
            _expected_hash: &str,
            _new_hash: &str,
        ) -> AxiamResult<bool> {
            unimplemented!()
        }
        async fn count_by_managed_by(
            &self,
            _tid: Uuid,
            _managed_by: axiam_core::models::oauth2_client::ManagedBy,
        ) -> AxiamResult<u64> {
            unimplemented!()
        }

        async fn list_all_by_managed_by(
            &self,
            _managed_by: axiam_core::models::oauth2_client::ManagedBy,
        ) -> AxiamResult<Vec<OAuth2Client>> {
            unimplemented!()
        }

        async fn touch_last_authorized(
            &self,
            _tid: Uuid,
            _client_id: &str,
            _at: chrono::DateTime<chrono::Utc>,
        ) -> AxiamResult<()> {
            // T21.4 — a no-op rather than `unimplemented!()`: the
            // authorization path calls this for an external client, so a
            // panic here would fail a test about something else entirely.
            Ok(())
        }
    }

    /// QUAL-03/D-11: a client-repo that always fails with a DB-outage-shaped
    /// error (not `AxiamError::NotFound`), used to prove `authenticate_client`
    /// (and its callers) distinguish a DB outage from a genuinely-unknown
    /// client.
    #[derive(Clone)]
    struct MockClientRepoDbOutage;

    impl OAuth2ClientRepository for MockClientRepoDbOutage {
        async fn create(&self, _input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
            unimplemented!()
        }
        async fn upsert_cimd_client(
            &self,
            _client_id: &str,
            _input: CreateOAuth2Client,
        ) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn get_by_id(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn get_by_client_id(
            &self,
            _tenant_id: Uuid,
            _client_id: &str,
        ) -> AxiamResult<OAuth2Client> {
            Err(AxiamError::Database("simulated DB outage".into()))
        }
        async fn update(
            &self,
            _tid: Uuid,
            _id: Uuid,
            _input: UpdateOAuth2Client,
        ) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn delete(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }
        async fn list(
            &self,
            _tid: Uuid,
            _page: Pagination,
        ) -> AxiamResult<PaginatedResult<OAuth2Client>> {
            unimplemented!()
        }
        async fn upgrade_client_secret_hash(
            &self,
            _tid: Uuid,
            _client_id: &str,
            _expected_hash: &str,
            _new_hash: &str,
        ) -> AxiamResult<bool> {
            unimplemented!()
        }
        async fn count_by_managed_by(
            &self,
            _tid: Uuid,
            _managed_by: axiam_core::models::oauth2_client::ManagedBy,
        ) -> AxiamResult<u64> {
            unimplemented!()
        }

        async fn list_all_by_managed_by(
            &self,
            _managed_by: axiam_core::models::oauth2_client::ManagedBy,
        ) -> AxiamResult<Vec<OAuth2Client>> {
            unimplemented!()
        }

        async fn touch_last_authorized(
            &self,
            _tid: Uuid,
            _client_id: &str,
            _at: chrono::DateTime<chrono::Utc>,
        ) -> AxiamResult<()> {
            // T21.4 — a no-op rather than `unimplemented!()`: the
            // authorization path calls this for an external client, so a
            // panic here would fail a test about something else entirely.
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockCodeRepo;

    impl AuthorizationCodeRepository for MockCodeRepo {
        async fn create(&self, input: CreateAuthorizationCode) -> AxiamResult<AuthorizationCode> {
            Ok(AuthorizationCode {
                id: Uuid::new_v4(),
                tenant_id: input.tenant_id,
                client_id: input.client_id,
                user_id: input.user_id,
                code_hash: input.code_hash,
                redirect_uri: input.redirect_uri,
                scopes: input.scopes,
                code_challenge: input.code_challenge,
                code_challenge_method: input.code_challenge_method,
                nonce: input.nonce,
                session_id: None,
                auth_time: input.auth_time,
                acr: input.acr,
                amr: input.amr,
                dpop_jkt: input.dpop_jkt,
                requested_userinfo_claims: input.requested_userinfo_claims,
                resource: input.resource,
                expires_at: input.expires_at,
                used: false,
                created_at: Utc::now(),
            })
        }
        async fn get_by_hash(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<AuthorizationCode> {
            unimplemented!()
        }
        async fn consume(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<AuthorizationCode> {
            unimplemented!()
        }
        async fn replayed_session(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<Option<Uuid>> {
            // These mocks exercise `authorize`, which never redeems a code and
            // so never reaches the replay path.
            unimplemented!()
        }
        async fn delete_expired(&self) -> AxiamResult<u64> {
            Ok(0)
        }
    }

    /// A client repo that always reports the client as genuinely unknown
    /// (`AxiamError::NotFound`), used to prove `authorize` maps that specific
    /// case to `OAuth2Error::InvalidClient`.
    #[derive(Clone)]
    struct MockClientRepoNotFound;

    impl OAuth2ClientRepository for MockClientRepoNotFound {
        async fn create(&self, _input: CreateOAuth2Client) -> AxiamResult<(OAuth2Client, String)> {
            unimplemented!()
        }
        async fn upsert_cimd_client(
            &self,
            _client_id: &str,
            _input: CreateOAuth2Client,
        ) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn get_by_id(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn get_by_client_id(
            &self,
            _tenant_id: Uuid,
            _client_id: &str,
        ) -> AxiamResult<OAuth2Client> {
            Err(AxiamError::NotFound {
                entity: "oauth2_client".into(),
                id: _client_id.to_string(),
            })
        }
        async fn update(
            &self,
            _tid: Uuid,
            _id: Uuid,
            _input: UpdateOAuth2Client,
        ) -> AxiamResult<OAuth2Client> {
            unimplemented!()
        }
        async fn delete(&self, _tid: Uuid, _id: Uuid) -> AxiamResult<()> {
            unimplemented!()
        }
        async fn list(
            &self,
            _tid: Uuid,
            _page: Pagination,
        ) -> AxiamResult<PaginatedResult<OAuth2Client>> {
            unimplemented!()
        }
        async fn upgrade_client_secret_hash(
            &self,
            _tid: Uuid,
            _client_id: &str,
            _expected_hash: &str,
            _new_hash: &str,
        ) -> AxiamResult<bool> {
            unimplemented!()
        }
        async fn count_by_managed_by(
            &self,
            _tid: Uuid,
            _managed_by: axiam_core::models::oauth2_client::ManagedBy,
        ) -> AxiamResult<u64> {
            unimplemented!()
        }

        async fn list_all_by_managed_by(
            &self,
            _managed_by: axiam_core::models::oauth2_client::ManagedBy,
        ) -> AxiamResult<Vec<OAuth2Client>> {
            unimplemented!()
        }

        async fn touch_last_authorized(
            &self,
            _tid: Uuid,
            _client_id: &str,
            _at: chrono::DateTime<chrono::Utc>,
        ) -> AxiamResult<()> {
            // T21.4 — a no-op rather than `unimplemented!()`: the
            // authorization path calls this for an external client, so a
            // panic here would fail a test about something else entirely.
            Ok(())
        }
    }

    /// A code repo whose `create` always fails with a DB-outage-shaped
    /// error, used to prove step 8 (code persistence) maps failures to
    /// `OAuth2Error::ServerError` rather than panicking or masking them.
    #[derive(Clone)]
    struct MockCodeRepoFailing;

    impl AuthorizationCodeRepository for MockCodeRepoFailing {
        async fn create(&self, _input: CreateAuthorizationCode) -> AxiamResult<AuthorizationCode> {
            Err(AxiamError::Database("simulated code-store outage".into()))
        }
        async fn get_by_hash(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<AuthorizationCode> {
            unimplemented!()
        }
        async fn consume(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<AuthorizationCode> {
            unimplemented!()
        }
        async fn replayed_session(
            &self,
            _tid: Uuid,
            _hash: &str,
            _client_id: &str,
            _redirect_uri: &str,
        ) -> AxiamResult<Option<Uuid>> {
            // These mocks exercise `authorize`, which never redeems a code and
            // so never reaches the replay path.
            unimplemented!()
        }
        async fn delete_expired(&self) -> AxiamResult<u64> {
            Ok(0)
        }
    }

    fn make_client(is_public: bool) -> OAuth2Client {
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "test-client".into(),
            // T21.2: a public client is one registered for `none`, and holds
            // no secret to hash. Before T21.2 the empty hash WAS the test, so
            // the fixture set only that; it now sets both halves of what a
            // public registration actually looks like, and
            // `a_none_client_is_public_however_its_hash_looks` covers the case
            // where the two disagree.
            client_secret_hash: if is_public {
                String::new()
            } else {
                "some-hash".into()
            },
            name: "Test Client".into(),
            redirect_uris: vec!["https://app.example.com/callback".into()],
            grant_types: vec!["authorization_code".into()],
            scopes: vec!["openid".into(), "profile".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method: if is_public {
                axiam_core::models::oauth2_client::ClientAuthMethod::None
            } else {
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost
            },
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
            allowed_resources: Vec::new(),
            managed_by: axiam_core::models::oauth2_client::ManagedBy::Admin,
            last_authorized_at: None,
        }
    }

    fn make_authorize_request(
        tenant_id: Uuid,
        client: &OAuth2Client,
        code_challenge: Option<&str>,
    ) -> AuthorizeRequest {
        AuthorizeRequest {
            tenant_id,
            user_id: Uuid::new_v4(),
            response_type: "code".into(),
            client_id: client.client_id.clone(),
            redirect_uri: client.redirect_uris[0].clone(),
            scope: Some("openid".into()),
            state: Some("state-xyz".into()),
            code_challenge: code_challenge.map(String::from),
            code_challenge_method: code_challenge.map(|_| "S256".into()),
            nonce: None,
            session_id: None,
            via_par: false,
            authn_params: AuthnRequestParams::default(),
            request_object: None,
            session_evidence: SessionEvidence::default(),
            sensitive_scopes: crate::sensitive::Requested::None,
            sensitive_scopes_switch_is_off: false,
            external_consent: crate::external_consent::Requested::NotApplicable,
            consent_hop_return_leg: false,
            id_token_hint: None,
            inline_authn_params_beside_request_uri: false,
            login_hop_return_leg: false,
            dpop_jkt: None,
            requested_userinfo_claims: Vec::new(),
            resource: None,
        }
    }

    // SEC-025 Case 1: public client WITHOUT code_challenge → InvalidRequest
    #[tokio::test]
    async fn authorize_public_client_without_pkce_returns_invalid_request() {
        let client = make_client(true); // public
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let req = make_authorize_request(tenant_id, &client, None);
        let result = svc.authorize(req).await;

        assert!(
            result.is_err(),
            "public client without PKCE must be rejected"
        );
        assert!(
            matches!(result.unwrap_err(), OAuth2Error::InvalidRequest(_)),
            "error must be InvalidRequest"
        );
    }

    // SEC-025 Case 2: public client WITH valid S256 code_challenge → success
    #[tokio::test]
    async fn authorize_public_client_with_s256_pkce_succeeds() {
        let client = make_client(true); // public
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        // Provide a valid S256 code_challenge (any base64url string is syntactically valid here)
        let req = make_authorize_request(
            tenant_id,
            &client,
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        );
        let result = svc.authorize(req).await;

        assert!(
            result.is_ok(),
            "public client with S256 PKCE must succeed, got: {:?}",
            result
        );
    }

    // SEC-025 Case 3: confidential client WITHOUT PKCE → success (unchanged)
    #[tokio::test]
    async fn authorize_confidential_client_without_pkce_succeeds() {
        let client = make_client(false); // confidential
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let req = make_authorize_request(tenant_id, &client, None);
        let result = svc.authorize(req).await;

        assert!(
            result.is_ok(),
            "confidential client without PKCE must still succeed, got: {:?}",
            result
        );
    }

    // T21.2: publicness is the registration's answer, not the hash's.
    #[tokio::test]
    async fn a_none_client_is_public_however_its_hash_looks() {
        // A row registered for `none` that nonetheless carries a secret hash —
        // the shape a client would have if it were ever allowed to switch
        // method in place (the admin API refuses that, and this is what makes
        // the refusal unnecessary for correctness here). PKCE is still
        // required of it, because the METHOD says it is public.
        let mut client = make_client(true);
        client.client_secret_hash = "a-stale-hash".into();
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let result = svc
            .authorize(make_authorize_request(tenant_id, &client, None))
            .await;
        assert!(
            matches!(result, Err(OAuth2Error::InvalidRequest(_))),
            "a client registered for `none` is public whatever its stored hash says, \
             so PKCE is required; got {result:?}"
        );
    }

    // SEC-025 has required PKCE of an empty-hash client since long before
    // `none` existed. T21.2 must not quietly stop: the union in step 2b is
    // what keeps this true.
    #[tokio::test]
    async fn a_confidential_client_with_an_empty_hash_still_needs_pkce() {
        let mut client = make_client(false);
        client.client_secret_hash = String::new();
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let result = svc
            .authorize(make_authorize_request(tenant_id, &client, None))
            .await;
        assert!(
            matches!(result, Err(OAuth2Error::InvalidRequest(_))),
            "SEC-025's empty-hash rule must survive T21.2; got {result:?}"
        );
    }

    // T21.2 / RFC 8252 §7.3 — the loopback allowance, at the endpoint rather
    // than in the matcher's own unit tests: what matters here is that
    // `authorize` consults the matcher at all.
    #[tokio::test]
    async fn a_loopback_client_may_present_any_port() {
        let mut client = make_client(true);
        client.redirect_uris = vec!["http://127.0.0.1/callback".into()];
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );

        let mut req = make_authorize_request(
            tenant_id,
            &client,
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        );
        req.redirect_uri = "http://127.0.0.1:51703/callback".into();
        assert!(
            svc.authorize(req).await.is_ok(),
            "an ephemeral loopback port must be accepted (RFC 8252 §7.3)"
        );

        // And a different loopback spelling is still a different host.
        let mut req = make_authorize_request(
            tenant_id,
            &client,
            Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
        );
        req.redirect_uri = "http://localhost:51703/callback".into();
        assert!(
            matches!(
                svc.authorize(req).await,
                Err(OAuth2Error::InvalidRedirectUri(_))
            ),
            "`localhost` and `127.0.0.1` are not interchangeable"
        );
    }

    // I6 — an `https` registration keeps exact matching at the endpoint too.
    #[tokio::test]
    async fn an_https_client_may_not_vary_its_port() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.redirect_uri = "https://app.example.com:8443/callback".into();
        assert!(
            matches!(
                svc.authorize(req).await,
                Err(OAuth2Error::InvalidRedirectUri(_))
            ),
            "the port allowance must not reach an https registration (I6)"
        );
    }

    // QUAL-03/D-11: a DB outage at client lookup must surface as a 5xx
    // ServerError, never masquerade as invalid_client (error-oracle).
    #[tokio::test]
    async fn authorize_client_lookup_db_outage_returns_server_error_not_invalid_client() {
        let svc = AuthorizeService::new(MockClientRepoDbOutage, MockCodeRepo, 300);
        let req = make_authorize_request(
            Uuid::new_v4(),
            &make_client(false),
            None, // confidential client path, PKCE irrelevant here
        );
        let result = svc.authorize(req).await;

        assert!(result.is_err(), "a DB outage must be a hard error");
        match result.unwrap_err() {
            OAuth2Error::ServerError(_) => {}
            other => panic!(
                "expected OAuth2Error::ServerError on a DB outage, got: {other:?} \
                 (a DB outage must never be reported as invalid_client)"
            ),
        }
    }

    // A genuinely-unknown client_id (AxiamError::NotFound) must map to
    // OAuth2Error::InvalidClient (bad client_id case).
    #[tokio::test]
    async fn authorize_unknown_client_id_returns_invalid_client() {
        let svc = AuthorizeService::new(MockClientRepoNotFound, MockCodeRepo, 300);
        let req = make_authorize_request(Uuid::new_v4(), &make_client(false), None);
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), OAuth2Error::InvalidClient(_)),
            "unknown client_id must map to InvalidClient"
        );
    }

    // redirect_uri not in the client's registered set must be rejected
    // before any other validation (RFC 6749 §4.1.2.1).
    #[tokio::test]
    async fn authorize_redirect_uri_mismatch_returns_invalid_redirect_uri() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.redirect_uri = "https://evil.example.com/callback".into();
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, OAuth2Error::InvalidRedirectUri(_)),
            "unregistered redirect_uri must map to InvalidRedirectUri, got: {:?}",
            err
        );
    }

    // Only response_type=code is supported; anything else is rejected
    // (only reachable once client + redirect_uri are known-good).
    #[tokio::test]
    async fn authorize_unsupported_response_type_returns_error() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.response_type = "token".into();
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OAuth2Error::UnsupportedResponseType
        ));
    }

    // A client not registered for the authorization_code grant type must
    // be rejected with unauthorized_client.
    #[tokio::test]
    async fn authorize_client_without_grant_type_returns_unauthorized_client() {
        let mut client = make_client(false);
        client.grant_types = vec!["client_credentials".into()];
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let req = make_authorize_request(tenant_id, &client, None);
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OAuth2Error::UnauthorizedClient(_)
        ));
    }

    // Requesting a scope not in the client's registered scope set must
    // be rejected with invalid_scope.
    #[tokio::test]
    async fn authorize_unregistered_scope_returns_invalid_scope() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.scope = Some("openid super-admin".into());
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OAuth2Error::InvalidScope(_)));
    }

    // Omitting `scope` entirely must succeed with an empty scope set
    // (no implicit grant of the client's full registered scopes).
    #[tokio::test]
    async fn authorize_without_scope_succeeds_with_empty_scopes() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.scope = None;
        let result = svc.authorize(req).await;

        assert!(result.is_ok(), "omitted scope must still succeed");
    }

    // code_challenge present without code_challenge_method is invalid_request.
    #[tokio::test]
    async fn authorize_pkce_challenge_without_method_returns_invalid_request() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.code_challenge = Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into());
        req.code_challenge_method = None;
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OAuth2Error::InvalidRequest(_)
        ));
    }

    // code_challenge_method present without code_challenge is invalid_request.
    #[tokio::test]
    async fn authorize_pkce_method_without_challenge_returns_invalid_request() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.code_challenge = None;
        req.code_challenge_method = Some("S256".into());
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OAuth2Error::InvalidRequest(_)
        ));
    }

    // Only S256 is a supported code_challenge_method; e.g. "plain" is rejected.
    #[tokio::test]
    async fn authorize_pkce_unsupported_method_returns_invalid_request() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepo,
            300,
        );
        let mut req = make_authorize_request(tenant_id, &client, None);
        req.code_challenge = Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into());
        req.code_challenge_method = Some("plain".into());
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            OAuth2Error::InvalidRequest(_)
        ));
    }

    // A failure while persisting the authorization code must surface as a
    // ServerError, not panic or silently drop the request.
    #[tokio::test]
    async fn authorize_code_store_failure_returns_server_error() {
        let client = make_client(false);
        let tenant_id = client.tenant_id;
        let svc = AuthorizeService::new(
            MockClientRepo {
                client: client.clone(),
            },
            MockCodeRepoFailing,
            300,
        );
        let req = make_authorize_request(tenant_id, &client, None);
        let result = svc.authorize(req).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OAuth2Error::ServerError(_)));
    }

    // hash_code must be deterministic and distinct for distinct inputs
    // (used by consumers to look codes up by hash).
    #[test]
    fn hash_code_is_deterministic_and_distinguishes_inputs() {
        let a1 = hash_code("code-a");
        let a2 = hash_code("code-a");
        let b = hash_code("code-b");

        assert_eq!(a1, a2, "hashing the same code twice must be stable");
        assert_ne!(a1, b, "different codes must hash differently");
        assert_eq!(a1.len(), 64, "SHA-256 hex digest must be 64 chars");
    }

    // parse_scopes: whitespace-separated parsing and the None => empty rule.
    #[test]
    fn parse_scopes_splits_on_whitespace_and_handles_none() {
        assert_eq!(parse_scopes(None), Vec::<String>::new());
        assert_eq!(parse_scopes(Some("")), Vec::<String>::new());
        assert_eq!(
            parse_scopes(Some("openid  profile   email")),
            vec!["openid", "profile", "email"]
        );
    }
}

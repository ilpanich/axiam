//! Pushed Authorization Requests (RFC 9126) — B5.
//!
//! The client POSTs its authorization parameters to `/oauth2/par`, where it
//! **authenticates**, and gets back an opaque `request_uri` to put in the
//! browser redirect instead of the parameters themselves.
//!
//! # What this actually buys
//!
//! In a plain authorization-code redirect, every parameter travels through the
//! user agent: it lands in browser history, in `Referer` headers, in any proxy
//! access log along the way, and — the part that matters — it is trivially
//! modifiable by whoever controls the browser. PKCE closes the code-injection
//! half of that, but nothing stops a tampered `scope` or `redirect_uri` from
//! reaching the authorization endpoint attributable to nobody.
//!
//! With PAR the parameters arrive over a direct, client-authenticated,
//! server-to-server POST. What travels through the browser is a random string
//! that means nothing to anyone who intercepts it and cannot be edited into
//! meaning something else. This is why FAPI 2.0 requires it, and why X5 needs
//! it before a conformance run is possible.
//!
//! # The two rules that carry the security
//!
//! 1. **Single-use.** Enforced in the repository's `consume`, in one
//!    statement. A replayable `request_uri` is a replayable authorization
//!    request.
//! 2. **Parameters do not mix.** An authorize request carrying both a
//!    `request_uri` and inline parameters is refused rather than merged.
//!    Merging is exactly where parameter confusion lives: the attacker
//!    supplies the inline value they want and lets the pushed one satisfy
//!    whatever check reads the other copy.

use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::{CreatePushedAuthRequest, PushedAuthParams};
use axiam_core::repository::{OAuth2ClientRepository, PushedAuthRequestRepository};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use rand::RngExt;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::OAuth2Error;

/// The `request_uri` scheme RFC 9126 §2.2 mandates.
pub const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// How long a pushed request stays usable.
///
/// RFC 9126 §2.2 suggests "in the order of seconds to a few minutes", and the
/// window only has to cover one browser redirect. There is deliberately no
/// configuration knob in v1: every value an operator might pick is either this
/// or worse, and a tunable that only trends longer is a tunable that only
/// widens a replay window.
pub const REQUEST_URI_LIFETIME_SECS: i64 = 60;

/// Generate a `request_uri`: 256 bits of CSPRNG behind the RFC's URN prefix.
pub fn generate_request_uri() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 32] = rng.random();
    format!("{REQUEST_URI_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

/// SHA-256 of a `request_uri`'s random component, hex-encoded — what is stored.
///
/// Hashed at rest for the same reason device codes are: for the 60 s it lives,
/// the `request_uri` is a bearer credential, and a database read should not
/// hand an attacker a usable one. SHA-256 rather than a KDF because the value
/// is a 256-bit CSPRNG string with no offline-guessing threat to defend
/// against.
pub fn hash_request_uri(raw: &str) -> String {
    let component = raw.strip_prefix(REQUEST_URI_PREFIX).unwrap_or(raw);
    let mut hasher = Sha256::new();
    hasher.update(component.as_bytes());
    hex::encode(hasher.finalize())
}

/// What a client pushes.
///
/// X7.1 — the nine OIDC authentication-request parameters are pushed
/// alongside the original seven. PAR and the inline query string are two
/// carriers of one request, and for a `require_par` client PAR is the only
/// carrier there is: a parameter added to only one of them is silently lost by
/// exactly the clients the FAPI profile insists on.
#[derive(Debug, Clone, Default)]
pub struct PushedRequest {
    pub tenant_id: Uuid,
    pub client_id: String,
    pub response_type: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub acr_values: Option<String>,
    pub claims: Option<String>,
    pub id_token_hint: Option<String>,
    pub login_hint: Option<String>,
    pub display: Option<String>,
    pub ui_locales: Option<String>,
    pub claims_locales: Option<String>,
    /// RFC 9449 §10 — the DPoP key this request binds its authorization to.
    ///
    /// Already *resolved* by the caller: the handler is where both inputs
    /// exist (the `dpop_jkt` form parameter and the `DPoP` header's verified
    /// thumbprint), and §10.1's rule that the two must agree is a refusal the
    /// endpoint owes the client before anything is stored. What arrives here
    /// is the single key the authorization is bound to, or `None`.
    pub dpop_jkt: Option<String>,
}

/// What `/oauth2/par` answers with (RFC 9126 §2.2).
#[derive(Debug, Clone)]
pub struct PushedAuthResponse {
    pub request_uri: String,
    pub expires_in: i64,
}

/// The PAR endpoint's logic.
#[derive(Clone)]
pub struct ParService<OC, PR> {
    client_repo: OC,
    par_repo: PR,
}

impl<OC, PR> ParService<OC, PR>
where
    OC: OAuth2ClientRepository,
    PR: PushedAuthRequestRepository,
{
    pub fn new(client_repo: OC, par_repo: PR) -> Self {
        Self {
            client_repo,
            par_repo,
        }
    }

    /// Store a pushed authorization request and mint its `request_uri`.
    ///
    /// The caller must already have authenticated the client — that is the
    /// point of the endpoint, and doing it here as well would duplicate the
    /// one secret-verification path the token endpoint shares.
    pub async fn push(&self, req: PushedRequest) -> Result<PushedAuthResponse, OAuth2Error> {
        let client = self
            .client_repo
            .get_by_client_id(req.tenant_id, &req.client_id)
            .await
            .map_err(|e| match e {
                // Same QUAL-03/D-11 discipline as the authorize endpoint: only
                // a genuinely-unknown client is `invalid_client`. A DB outage
                // must not masquerade as bad client credentials.
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient("client not found".into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;

        // The redirect_uri is validated here, not deferred to the authorize
        // step. Validating at push time is the whole benefit: the client is
        // authenticated *now*, so a rejection is attributable, and the browser
        // never gets a request_uri standing for a request that was going to
        // fail anyway.
        if !client.redirect_uris.iter().any(|u| u == &req.redirect_uri) {
            return Err(OAuth2Error::InvalidRedirectUri(
                "redirect_uri is not registered for this client".into(),
            ));
        }

        if req.response_type != "code" {
            return Err(OAuth2Error::UnsupportedResponseType);
        }

        // RFC 9126 §2.1: `request_uri` is not a parameter a client may push.
        // Accepting one would let a client chain pushed requests, and the
        // second would inherit the first's authentication.
        let request_uri = generate_request_uri();
        let expires_at = Utc::now() + Duration::seconds(REQUEST_URI_LIFETIME_SECS);

        self.par_repo
            .create(CreatePushedAuthRequest {
                tenant_id: req.tenant_id,
                client_id: req.client_id,
                request_uri_hash: hash_request_uri(&request_uri),
                params: PushedAuthParams {
                    response_type: req.response_type,
                    redirect_uri: req.redirect_uri,
                    scope: req.scope,
                    state: req.state,
                    code_challenge: req.code_challenge,
                    code_challenge_method: req.code_challenge_method,
                    nonce: req.nonce,
                    prompt: req.prompt,
                    max_age: req.max_age,
                    acr_values: req.acr_values,
                    claims: req.claims,
                    id_token_hint: req.id_token_hint,
                    login_hint: req.login_hint,
                    display: req.display,
                    ui_locales: req.ui_locales,
                    claims_locales: req.claims_locales,
                    dpop_jkt: req.dpop_jkt,
                },
                expires_at,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(PushedAuthResponse {
            request_uri,
            expires_in: REQUEST_URI_LIFETIME_SECS,
        })
    }

    /// Resolve and consume a `request_uri` on the authorize path.
    ///
    /// The returned parameters are the ones the client pushed; the caller must
    /// use them *instead of* anything on the authorize query string, never
    /// merged with it.
    pub async fn consume(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        request_uri: &str,
    ) -> Result<PushedAuthParams, OAuth2Error> {
        if !request_uri.starts_with(REQUEST_URI_PREFIX) {
            return Err(OAuth2Error::InvalidRequest(
                "request_uri is not a pushed authorization request URI".into(),
            ));
        }

        let stored = self
            .par_repo
            .consume(tenant_id, &hash_request_uri(request_uri))
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            .ok_or_else(|| {
                // Unknown, expired and already-consumed all answer identically,
                // deliberately: distinguishing them tells an attacker holding a
                // stolen request_uri whether it is worth racing for, and none of
                // the three is recoverable by the client anyway.
                OAuth2Error::InvalidRequest(REQUEST_URI_GONE.into())
            })?;

        // The pushed request belongs to the client that pushed it. Without
        // this, a second client could spend another client's request_uri and
        // receive a code minted against the first client's registration.
        if stored.client_id != client_id {
            return Err(OAuth2Error::InvalidRequest(
                "request_uri was not issued to this client".into(),
            ));
        }

        Ok(stored.params)
    }
}

/// The single answer given for a `request_uri` that is unknown, expired or
/// already consumed.
///
/// A constant because two places need to agree on it: [`ParService::consume`]
/// produces it, and the authorization endpoint recognises it to tell a
/// **login-hop return leg** whose 60-second window closed (W3, plan §4.0 and
/// F10) apart from a client that sent nonsense. See [`is_request_uri_gone`].
pub const REQUEST_URI_GONE: &str = "request_uri is unknown, expired, or used";

/// Is this the "the pushed request is gone" refusal?
///
/// The recogniser lives here, next to the producer, so the two cannot drift:
/// a caller matching on the message itself would keep compiling after the
/// wording changed and would silently stop recognising the case.
///
/// Deliberately narrow. `request_uri was not issued to this client` is a
/// different failure — a client spending someone else's handle — and must keep
/// its own answer even on a return leg.
pub fn is_request_uri_gone(e: &OAuth2Error) -> bool {
    matches!(e, OAuth2Error::InvalidRequest(msg) if msg == REQUEST_URI_GONE)
}

// `has_inline_params` used to live here: it reported whether an authorize
// request carried `response_type`/`redirect_uri`/`scope`/`code_challenge`
// alongside a `request_uri`, and the authorization endpoint refused such a
// request as "the two forms do not mix".
//
// It is gone rather than merely unused, because the rule it encoded is not the
// one the specifications state. RFC 9126 §4 delegates the shape of the
// authorization request to RFC 9101, whose §5 says a client MAY duplicate the
// pushed parameters in the query string and whose §6.3 says the authorization
// server MUST only *use* the ones from the pushed request. Ignore, not refuse
// — and the endpoint reads every field from the pushed copy already, so
// ignoring is what it now does. See the comment at the `request_uri` branch in
// `axiam_api_rest::handlers::oauth2`.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_request_uri_carries_the_rfc_prefix() {
        assert!(generate_request_uri().starts_with(REQUEST_URI_PREFIX));
    }

    #[test]
    fn generated_request_uris_are_distinct() {
        let a = generate_request_uri();
        let b = generate_request_uri();
        assert_ne!(a, b, "request_uri must be CSPRNG, not a counter");
    }

    #[test]
    fn hash_ignores_the_prefix() {
        // The prefix is constant, so hashing it adds nothing; what matters is
        // that a caller passing the full URI and one passing the bare
        // component resolve to the same stored row.
        let uri = generate_request_uri();
        let bare = uri.strip_prefix(REQUEST_URI_PREFIX).unwrap();
        assert_eq!(hash_request_uri(&uri), hash_request_uri(bare));
    }

    #[test]
    fn hash_is_not_the_plaintext() {
        let uri = generate_request_uri();
        let h = hash_request_uri(&uri);
        assert!(!uri.contains(&h));
        assert_eq!(h.len(), 64, "hex-encoded SHA-256");
    }

    #[test]
    fn lifetime_is_short_enough_to_bound_replay() {
        // Guards the constant against a well-meaning future edit: RFC 9126
        // §2.2 wants seconds-to-minutes, and the window only has to cover one
        // browser redirect. In a `const` block so a bad edit fails to compile
        // rather than waiting for someone to run the suite.
        const {
            assert!(REQUEST_URI_LIFETIME_SECS <= 120);
            assert!(REQUEST_URI_LIFETIME_SECS >= 30);
        }
    }
}

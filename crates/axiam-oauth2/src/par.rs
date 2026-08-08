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
#[derive(Debug, Clone)]
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
                OAuth2Error::InvalidRequest("request_uri is unknown, expired, or used".into())
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

/// Whether an authorize request is carrying inline parameters alongside a
/// `request_uri`.
///
/// RFC 9126 §4: the two forms do not mix. Rather than merging (where parameter
/// confusion lives), a request carrying both is refused.
pub fn has_inline_params(
    response_type: Option<&str>,
    redirect_uri: Option<&str>,
    scope: Option<&str>,
    code_challenge: Option<&str>,
) -> bool {
    response_type.is_some() || redirect_uri.is_some() || scope.is_some() || code_challenge.is_some()
}

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
    fn inline_params_are_detected_individually() {
        assert!(!has_inline_params(None, None, None, None));
        assert!(has_inline_params(Some("code"), None, None, None));
        assert!(has_inline_params(None, Some("https://rp/cb"), None, None));
        assert!(has_inline_params(None, None, Some("openid"), None));
        assert!(has_inline_params(None, None, None, Some("chal")));
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

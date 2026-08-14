//! `private_key_jwt` client authentication (RFC 7523 §2.2, OIDC Core §9) —
//! X5.1.
//!
//! The second of the two client-authentication families FAPI 2.0 §5.3.1.1
//! permits, and the counterpart to [`crate::mtls`]'s §2. Both replace the shared
//! secret with proof of possession of a private key; they differ only in where
//! the proof happens:
//!
//! | | Proof carried by | Needs from the deployment |
//! |---|---|---|
//! | mTLS (RFC 8705 §2) | the TLS handshake | an mTLS listener the client can reach *directly* |
//! | `private_key_jwt` (RFC 7523 §2.2) | a signed assertion in the request body | nothing at the transport layer |
//!
//! That second column is the whole reason this family exists. A client behind a
//! TLS-terminating load balancer, an API gateway, or a CDN cannot present a
//! client certificate to AXIAM — the connection AXIAM sees is the proxy's. Such
//! a client had no route to strong authentication here before X5.1's second
//! half, which the conformance runbook recorded as a gap and which this module
//! closes. mTLS remains AXIAM's differentiator and the cheaper option; this is
//! the one that works everywhere.
//!
//! # What is checked, and in what order
//!
//! RFC 7523 §3, with OIDC Core §9's tightening of `iss`/`sub`:
//!
//! 1. **The signature**, under a key the *client registered* — inline `jwks` or
//!    a fetched `jwks_uri`, never a key the assertion supplies. This is the
//!    difference between an assertion and a DPoP proof, and it is not
//!    cosmetic: a DPoP proof names a key that only has to be *consistent*
//!    across a token's life, whereas a client assertion names an identity, and
//!    an identity that can supply its own key is not authenticated.
//! 2. **`alg` from the registered key, never the header.** See [`crate::jose`].
//! 3. `iss` and `sub` are both exactly the `client_id` (OIDC Core §9). RFC 7523
//!    alone would permit an `iss` that merely identifies the issuer of the
//!    assertion; OIDC pins both to the client, and pinning both is what stops
//!    one registered client minting an assertion that authenticates as another.
//! 4. `aud` names this authorization server. An assertion is a bearer
//!    credential for whoever holds it, so an assertion minted for *another* AS
//!    must not authenticate here — that is the cross-AS replay RFC 7523 §3's
//!    audience requirement exists for.
//! 5. `exp` is in the future and the assertion's total life is bounded
//!    ([`MAX_ASSERTION_LIFETIME_SECS`]).
//! 6. `jti` is present, and **single-use**. The caller records it; see below.
//!
//! # `jti` replay is the caller's, and it is not optional
//!
//! This module returns the `jti` and refuses to pretend it has recorded it.
//! Recording is `axiam_core::repository::ProofReplayRepository`'s job, and that
//! repository decides replay by a `UNIQUE` index violation rather than by
//! reading first — the same mechanism `saml_replay` and `amqp_nonce_replay` use,
//! and for the same reason. A read-then-write check leaves a window in which two
//! concurrent copies of one assertion both authenticate, which is the race
//! X6 (#316) and #318 closed for authorization codes.
//!
//! Freshness alone is not enough. `exp` bounds how long a captured assertion
//! stays interesting; the `jti` guard is what makes that window unusable.

use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

use crate::jose;

/// RFC 7521 §4.2 `client_assertion_type` — the only value AXIAM accepts.
pub const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The longest total life an assertion may claim, in seconds.
///
/// One hour, matching FAPI 2.0's bound. The value is not really about the
/// legitimate client — a well-behaved one mints an assertion valid for seconds —
/// it is about the size of the replay table and the window a captured assertion
/// is useful in if the replay guard is ever unavailable. An assertion claiming a
/// year is refused rather than trimmed, because trimming would silently accept a
/// credential the client believes has different semantics.
pub const MAX_ASSERTION_LIFETIME_SECS: i64 = 3600;

/// Tolerance for clock disagreement between the client and AXIAM, in seconds.
///
/// Applied to `exp`, `nbf` and `iat` alike. Sixty seconds is enough for the
/// NTP-adjacent drift real deployments have and short enough that it does not
/// meaningfully extend an assertion's usable life.
pub const CLOCK_SKEW_SECS: i64 = 60;

/// `aud` is a string or an array of strings (RFC 7519 §4.1.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains_any(&self, acceptable: &[String]) -> bool {
        match self {
            Self::One(a) => acceptable.iter().any(|x| x == a),
            Self::Many(list) => list.iter().any(|a| acceptable.iter().any(|x| x == a)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AssertionClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    jti: String,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
}

/// Why a client assertion did not authenticate.
///
/// Typed rather than stringly so a test can assert *which* constraint failed.
/// The wire never sees the distinction: every variant is reported to the client
/// as `invalid_client` with [`ASSERTION_AUTH_FAILED`], for exactly the reason
/// [`crate::mtls::MTLS_AUTH_FAILED`] gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionError {
    /// `client_assertion_type` was absent or was not the JWT-bearer URN.
    WrongAssertionType { got: Option<String> },
    /// Not a JWT, or missing a claim RFC 7523 requires.
    Malformed(String),
    /// The client registered no usable key material.
    NoRegisteredKeys,
    /// The registered keys could not supply a verifier for this assertion.
    Key(jose::JoseKeyError),
    /// The signature did not verify under any registered key.
    Signature,
    /// `iss` or `sub` is not this client.
    SubjectMismatch { claim: &'static str, got: String },
    /// `aud` does not name this authorization server.
    AudienceMismatch,
    /// `exp` has passed, `nbf` has not arrived, or `iat` is in the future.
    NotCurrentlyValid(&'static str),
    /// The assertion claims a longer life than the profile permits.
    LifetimeTooLong { seconds: i64 },
    /// `jti` is absent or blank, so the assertion cannot be made single-use.
    UnusableJti,
    /// This `jti` has already authenticated once.
    Replayed,
}

/// The single `error_description` every `private_key_jwt` failure returns.
///
/// Word for word the same as [`crate::mtls::MTLS_AUTH_FAILED`] and
/// `token::CLIENT_AUTH_FAILED`, deliberately: an unauthenticated caller must not
/// be able to tell "no such client" from "wrong key" from "assertion expired"
/// from "already used", because each of those is a fact about a `client_id` they
/// have not authenticated as. The distinctions go to the tracing log.
pub const ASSERTION_AUTH_FAILED: &str = "invalid client credentials";

impl std::fmt::Display for AssertionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongAssertionType { got } => write!(
                f,
                "client_assertion_type must be {CLIENT_ASSERTION_TYPE:?}, got {got:?}"
            ),
            Self::Malformed(d) => write!(f, "malformed client assertion: {d}"),
            Self::NoRegisteredKeys => write!(
                f,
                "the client registered no jwks or jwks_uri, so no assertion of its can be verified"
            ),
            Self::Key(e) => write!(f, "client assertion key: {e}"),
            Self::Signature => {
                write!(
                    f,
                    "the client assertion does not verify under any registered key"
                )
            }
            Self::SubjectMismatch { claim, got } => write!(
                f,
                "the assertion's {claim} is {got:?}, which is not the client it authenticates as \
                 (OIDC Core §9 requires iss = sub = client_id)"
            ),
            Self::AudienceMismatch => write!(
                f,
                "the assertion's aud does not name this authorization server; an assertion minted \
                 for another server must not authenticate here"
            ),
            Self::NotCurrentlyValid(which) => {
                write!(f, "the assertion is not currently valid: {which}")
            }
            Self::LifetimeTooLong { seconds } => write!(
                f,
                "the assertion claims a life of {seconds}s, longer than the \
                 {MAX_ASSERTION_LIFETIME_SECS}s this profile permits"
            ),
            Self::UnusableJti => write!(
                f,
                "the assertion carries no usable jti, so it cannot be made single-use"
            ),
            Self::Replayed => write!(f, "this client assertion has already been used"),
        }
    }
}

impl std::error::Error for AssertionError {}

impl From<jose::JoseKeyError> for AssertionError {
    fn from(e: jose::JoseKeyError) -> Self {
        Self::Key(e)
    }
}

impl From<AssertionError> for crate::error::OAuth2Error {
    fn from(_: AssertionError) -> Self {
        crate::error::OAuth2Error::InvalidClient(ASSERTION_AUTH_FAILED.into())
    }
}

/// An assertion that authenticated, and what the caller must still do with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAssertion {
    /// The `jti` the caller records to make this assertion single-use.
    pub jti: String,
    /// When the assertion expires — the natural lifetime of its replay row,
    /// because past `exp` a replay is refused without the table being read.
    pub exp: i64,
}

impl VerifiedAssertion {
    /// When a replay row for this assertion stops being useful.
    pub fn replay_expiry(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(self.exp + CLOCK_SKEW_SECS, 0)
            .unwrap_or_else(chrono::Utc::now)
    }
}

/// Check the `client_assertion_type` form parameter (RFC 7521 §4.2).
///
/// A separate function because it is checked before anything is parsed: an
/// assertion of an unrecognised type is not something to attempt to verify.
pub fn check_assertion_type(presented: Option<&str>) -> Result<(), AssertionError> {
    match presented {
        Some(t) if t == CLIENT_ASSERTION_TYPE => Ok(()),
        other => Err(AssertionError::WrongAssertionType {
            got: other.map(str::to_owned),
        }),
    }
}

/// Verify a `client_assertion` against the keys a client registered.
///
/// `acceptable_audiences` is the set of values RFC 7523 §3 permits in `aud`:
/// AXIAM's issuer and its token-endpoint URL. Both are accepted because the
/// specifications disagree about which one a client should use — OIDC Core §9
/// says the token endpoint URL, RFC 7523 says an identifier of the
/// authorization server — and refusing a client for following the other
/// specification would be an interop failure with no security content.
///
/// Returns the `jti` for the caller to record. **A caller that drops it has not
/// implemented replay protection**, which is why the return type carries it
/// rather than the function answering `Ok(())`.
pub fn verify_client_assertion(
    assertion: &str,
    client_id: &str,
    acceptable_audiences: &[String],
    keys: &JwkSet,
    now: i64,
) -> Result<VerifiedAssertion, AssertionError> {
    if keys.keys.is_empty() {
        return Err(AssertionError::NoRegisteredKeys);
    }

    let header = decode_header(assertion)
        .map_err(|e| AssertionError::Malformed(format!("bad JWS header: {e}")))?;

    // Every candidate is a key the client registered. The header's `kid`
    // narrows the set; it can never widen it, and it can never introduce a key
    // from the assertion itself — which is the difference between this and a
    // DPoP proof.
    let candidates: Vec<(&Jwk, jsonwebtoken::Algorithm)> =
        jose::candidate_keys(&keys.keys, header.kid.as_deref())?;

    let mut claims: Option<AssertionClaims> = None;
    for (jwk, key_alg) in &candidates {
        // The algorithm is the key's. A header naming something else is not a
        // request to verify differently, it is a refusal — and it is a refusal
        // for *this key*, not for the whole set, because a client publishing an
        // Ed25519 and a P-256 key legitimately signs with either.
        let Ok(alg) = jose::verify_permitted_header(header.alg, *key_alg) else {
            continue;
        };
        let Ok(decoding_key) = jose::decoding_key_for(jwk) else {
            continue;
        };
        let mut validation = Validation::new(alg);
        // Every temporal and audience rule is applied below with RFC 7523's
        // semantics and AXIAM's error vocabulary. Leaving jsonwebtoken's
        // checks on as well would mean two definitions of "expired" that could
        // drift, and would collapse four distinct refusals into one opaque one.
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        match decode::<AssertionClaims>(assertion, &decoding_key, &validation) {
            Ok(data) => {
                claims = Some(data.claims);
                break;
            }
            Err(e) => match e.kind() {
                // A signature that does not verify under *this* key says
                // nothing about the next one.
                jsonwebtoken::errors::ErrorKind::InvalidSignature => continue,
                // A payload that is not a well-formed assertion will not become
                // one under another key.
                _ => return Err(AssertionError::Malformed(e.to_string())),
            },
        }
    }

    let Some(claims) = claims else {
        return Err(AssertionError::Signature);
    };

    // --- RFC 7523 §3 / OIDC Core §9 --------------------------------------
    if claims.iss != client_id {
        return Err(AssertionError::SubjectMismatch {
            claim: "iss",
            got: claims.iss,
        });
    }
    if claims.sub != client_id {
        return Err(AssertionError::SubjectMismatch {
            claim: "sub",
            got: claims.sub,
        });
    }
    if !claims.aud.contains_any(acceptable_audiences) {
        return Err(AssertionError::AudienceMismatch);
    }

    if claims.exp <= now - CLOCK_SKEW_SECS {
        return Err(AssertionError::NotCurrentlyValid("exp has passed"));
    }
    if let Some(nbf) = claims.nbf
        && nbf > now + CLOCK_SKEW_SECS
    {
        return Err(AssertionError::NotCurrentlyValid("nbf is in the future"));
    }
    if let Some(iat) = claims.iat {
        if iat > now + CLOCK_SKEW_SECS {
            return Err(AssertionError::NotCurrentlyValid("iat is in the future"));
        }
        let life = claims.exp - iat;
        if life > MAX_ASSERTION_LIFETIME_SECS {
            return Err(AssertionError::LifetimeTooLong { seconds: life });
        }
    }
    // Bound the life even when the client omitted `iat`, which RFC 7523 makes
    // optional. Without this, omitting one optional claim would buy an
    // unbounded assertion — the kind of asymmetry an attacker looks for.
    let remaining = claims.exp - now;
    if remaining > MAX_ASSERTION_LIFETIME_SECS {
        return Err(AssertionError::LifetimeTooLong { seconds: remaining });
    }

    if claims.jti.trim().is_empty() {
        return Err(AssertionError::UnusableJti);
    }

    Ok(VerifiedAssertion {
        jti: claims.jti,
        exp: claims.exp,
    })
}

/// Where a client's verification keys come from.
///
/// RFC 7591 §2 permits `jwks` **or** `jwks_uri`, never both, and AXIAM enforces
/// that at registration (`fapi::validate_registration`). This enum is the
/// runtime consequence of that rule: there is one source, and which one it is
/// determines whether resolving it touches the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientKeySource {
    /// An inline `jwks` document, already parsed.
    Inline(Box<JwkSet>),
    /// A `jwks_uri` to fetch — through `axiam_federation::jwks_cache`, which
    /// carries the SSRF guard and the TTL/stale-while-revalidate policy. Never
    /// through a bare HTTP client.
    Remote(String),
    /// The client registered neither, so nothing it signs can be verified.
    None,
}

/// Read a client's registered key source.
///
/// A malformed inline `jwks` resolves to [`ClientKeySource::None`] rather than
/// an error, and the caller reports the ordinary authentication failure. The
/// alternative — surfacing a parse error — would let an unauthenticated caller
/// distinguish "this client has a broken key document" from "this client does
/// not exist", which is precisely the probe [`ASSERTION_AUTH_FAILED`] exists to
/// prevent. The parse failure is logged.
pub fn key_source_of(client: &axiam_core::models::oauth2_client::OAuth2Client) -> ClientKeySource {
    if let Some(raw) = client
        .jwks
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return match serde_json::from_str::<JwkSet>(raw) {
            Ok(set) => ClientKeySource::Inline(Box::new(set)),
            Err(e) => {
                tracing::warn!(
                    client_id = %client.client_id,
                    error = %e,
                    "client has a registered jwks that is not a parseable JWK Set; it cannot \
                     authenticate with private_key_jwt until the document is fixed"
                );
                ClientKeySource::None
            }
        };
    }
    if let Some(uri) = client
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return ClientKeySource::Remote(uri.to_owned());
    }
    ClientKeySource::None
}

// ---------------------------------------------------------------------------
// The authenticator seam
// ---------------------------------------------------------------------------

/// A future returned by [`ClientAssertionVerifier`].
pub type VerifyFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), crate::error::OAuth2Error>> + Send + 'a>,
>;

/// Resolve a client's keys, verify its assertion, and record the `jti` — the
/// three steps `crate::token::TokenService` cannot do itself.
///
/// A trait object rather than two more generic parameters on `TokenService`,
/// which already carries six. It is also the seam that keeps the *pure* half of
/// this module — [`verify_client_assertion`], which is where every RFC 7523
/// rule lives — free of the database and the network, so it can be tested
/// against vectors and benchmarked.
///
/// `None` on a `TokenService` means no client may authenticate with
/// `private_key_jwt` in that deployment. That is a refusal, not a bypass: a
/// client registered for the method is refused outright rather than falling
/// back to a secret.
pub trait ClientAssertionVerifier: Send + Sync {
    fn verify<'a>(
        &'a self,
        tenant_id: uuid::Uuid,
        client: &'a axiam_core::models::oauth2_client::OAuth2Client,
        assertion: &'a str,
    ) -> VerifyFuture<'a>;
}

/// The production [`ClientAssertionVerifier`].
///
/// Composed of the two things the pure verifier deliberately does not know
/// about, and nothing else:
///
/// * `jwks` — `axiam_federation::jwks_cache::JwksCache`, so a client's
///   `jwks_uri` is fetched through the **same** TTL, stale-while-revalidate and
///   SEC-054 SSRF-guarded path a federated IdP's JWKS goes through. A
///   client-supplied URL the server will fetch on demand is the same threat
///   surface whichever feature asked for it, and giving it a second, weaker
///   guard is how one of the two ends up missing a fix.
/// * `replay` — `ProofReplayRepository`, which decides replay by a `UNIQUE`
///   index violation rather than by reading first.
pub struct JwksAssertionVerifier<R> {
    jwks: axiam_federation::jwks_cache::JwksCache,
    http: reqwest::Client,
    replay: R,
    /// The `aud` values an assertion may name: AXIAM's issuer and its
    /// token-endpoint URL. See [`verify_client_assertion`] for why both.
    acceptable_audiences: Vec<String>,
}

impl<R> JwksAssertionVerifier<R> {
    pub fn new(
        jwks: axiam_federation::jwks_cache::JwksCache,
        http: reqwest::Client,
        replay: R,
        acceptable_audiences: Vec<String>,
    ) -> Self {
        Self {
            jwks,
            http,
            replay,
            acceptable_audiences,
        }
    }
}

impl<R> ClientAssertionVerifier for JwksAssertionVerifier<R>
where
    R: axiam_core::repository::ProofReplayRepository,
{
    fn verify<'a>(
        &'a self,
        tenant_id: uuid::Uuid,
        client: &'a axiam_core::models::oauth2_client::OAuth2Client,
        assertion: &'a str,
    ) -> VerifyFuture<'a> {
        Box::pin(async move {
            use crate::error::OAuth2Error;
            use axiam_core::repository::ProofKind;

            let failed = || OAuth2Error::InvalidClient(ASSERTION_AUTH_FAILED.into());

            let keys: JwkSet = match key_source_of(client) {
                ClientKeySource::Inline(set) => *set,
                ClientKeySource::Remote(uri) => {
                    // The cache is keyed by `(tenant_id, client.id)`, which is
                    // the natural unit here: two clients that happen to publish
                    // the same URI still get independent entries, so one
                    // client's rotation cannot serve another client a stale
                    // key set.
                    match self
                        .jwks
                        .get_or_fetch(&self.http, (tenant_id, client.id), &uri)
                        .await
                    {
                        Ok(set) => set,
                        Err(e) => {
                            tracing::warn!(
                                client_id = %client.client_id,
                                error = %e,
                                "could not obtain the client's jwks_uri key set; refusing the \
                                 assertion rather than authenticating without checking it"
                            );
                            return Err(failed());
                        }
                    }
                }
                ClientKeySource::None => {
                    tracing::warn!(
                        client_id = %client.client_id,
                        "client is registered for private_key_jwt but has no usable key source"
                    );
                    return Err(failed());
                }
            };

            let now = chrono::Utc::now().timestamp();
            let verified = verify_client_assertion(
                assertion,
                &client.client_id,
                &self.acceptable_audiences,
                &keys,
                now,
            )
            .map_err(|e| {
                tracing::debug!(
                    client_id = %client.client_id,
                    reason = %e,
                    "private_key_jwt client authentication failed"
                );
                failed()
            })?;

            // The signature proved possession of the key. This is what makes
            // the assertion single-*use* rather than merely single-*purpose*,
            // and it happens after verification so a garbage assertion cannot
            // fill the table.
            match self
                .replay
                .insert_proof_jti(
                    tenant_id,
                    ProofKind::ClientAssertion,
                    &client.client_id,
                    &verified.jti,
                    verified.replay_expiry(),
                )
                .await
            {
                Ok(()) => Ok(()),
                Err(axiam_core::error::AxiamError::ReplayDetected) => {
                    tracing::warn!(
                        client_id = %client.client_id,
                        "a client assertion was replayed; refusing"
                    );
                    Err(failed())
                }
                Err(e) => {
                    // A replay guard that cannot record must not authenticate.
                    // Failing open here would turn a database blip into an
                    // unlimited replay window, which is the one failure mode
                    // this whole mechanism exists to prevent.
                    tracing::error!(
                        client_id = %client.client_id,
                        error = %e,
                        "could not record a client assertion's jti; refusing the authentication \
                         rather than accepting an assertion that cannot be made single-use"
                    );
                    Err(failed())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::oauth2_client::{ClientAuthMethod, ClientProfile, OAuth2Client};
    use chrono::Utc;
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::json;
    use uuid::Uuid;

    const NOW: i64 = 1_800_000_000;
    const CLIENT: &str = "oa_client";
    const TOKEN_ENDPOINT: &str = "https://as.example/oauth2/token";

    fn audiences() -> Vec<String> {
        vec!["https://as.example".into(), TOKEN_ENDPOINT.into()]
    }

    struct TestKey {
        encoding: EncodingKey,
        jwk: serde_json::Value,
        alg: &'static str,
    }

    fn ed25519_key(kid: Option<&str>) -> TestKey {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("generate Ed25519");
        let encoding =
            EncodingKey::from_ed_pem(kp.serialize_pem().as_bytes()).expect("encoding key");
        let spki = kp.public_key_raw();
        use base64::Engine as _;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&spki[spki.len() - 32..]);
        let mut jwk = json!({"kty": "OKP", "crv": "Ed25519", "x": x});
        if let Some(kid) = kid {
            jwk["kid"] = json!(kid);
        }
        TestKey {
            encoding,
            jwk,
            alg: "EdDSA",
        }
    }

    fn jwks(keys: &[&TestKey]) -> JwkSet {
        let value = json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()});
        serde_json::from_value(value).expect("build JWK Set")
    }

    fn claims(now: i64) -> serde_json::Value {
        json!({
            "iss": CLIENT,
            "sub": CLIENT,
            "aud": TOKEN_ENDPOINT,
            "exp": now + 120,
            "iat": now,
            "jti": "assertion-0001",
        })
    }

    fn sign(key: &TestKey, claims: &serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::from_str_alg(key.alg));
        header.kid = key
            .jwk
            .get("kid")
            .and_then(|k| k.as_str())
            .map(str::to_owned);
        jsonwebtoken::encode(&header, claims, &key.encoding).expect("sign assertion")
    }

    // A tiny helper so the tests can name algorithms as strings.
    trait FromStrAlg {
        fn from_str_alg(s: &str) -> Algorithm;
    }
    impl FromStrAlg for Algorithm {
        fn from_str_alg(s: &str) -> Algorithm {
            match s {
                "EdDSA" => Algorithm::EdDSA,
                "ES256" => Algorithm::ES256,
                "PS256" => Algorithm::PS256,
                other => panic!("unhandled test algorithm {other}"),
            }
        }
    }

    fn verify(assertion: &str, keys: &JwkSet) -> Result<VerifiedAssertion, AssertionError> {
        verify_client_assertion(assertion, CLIENT, &audiences(), keys, NOW)
    }

    // -- the happy path ---------------------------------------------------

    #[test]
    fn a_well_formed_assertion_authenticates_and_yields_its_jti() {
        let key = ed25519_key(None);
        let assertion = sign(&key, &claims(NOW));
        let verified = verify(&assertion, &jwks(&[&key])).expect("should authenticate");
        assert_eq!(verified.jti, "assertion-0001");
        assert_eq!(verified.exp, NOW + 120);
    }

    #[test]
    fn either_acceptable_audience_is_honoured() {
        let key = ed25519_key(None);
        for aud in ["https://as.example", TOKEN_ENDPOINT] {
            let mut c = claims(NOW);
            c["aud"] = json!(aud);
            assert!(verify(&sign(&key, &c), &jwks(&[&key])).is_ok(), "aud {aud}");
        }
        // ...as is an array containing one of them (RFC 7519 §4.1.3).
        let mut c = claims(NOW);
        c["aud"] = json!(["https://elsewhere.example", TOKEN_ENDPOINT]);
        assert!(verify(&sign(&key, &c), &jwks(&[&key])).is_ok());
    }

    /// Key rotation: a client publishes two keys and signs with either.
    #[test]
    fn any_registered_key_may_sign() {
        let old = ed25519_key(Some("old"));
        let new = ed25519_key(Some("new"));
        let set = jwks(&[&old, &new]);
        assert!(verify(&sign(&old, &claims(NOW)), &set).is_ok());
        assert!(verify(&sign(&new, &claims(NOW)), &set).is_ok());
    }

    /// ...but a `kid` naming one key must not be satisfied by another. A client
    /// that says which key it used is held to it.
    #[test]
    fn a_kid_selects_and_does_not_merely_hint() {
        let old = ed25519_key(Some("old"));
        let new = ed25519_key(Some("new"));
        // Sign with `old`'s private key but claim `new`'s kid.
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some("new".into());
        let forged =
            jsonwebtoken::encode(&header, &claims(NOW), &old.encoding).expect("sign assertion");
        assert_eq!(
            verify(&forged, &jwks(&[&old, &new])),
            Err(AssertionError::Signature)
        );
    }

    // -- the rejected-algorithm vectors (X5.5) ----------------------------

    /// `none` cannot even be expressed: `jsonwebtoken::Algorithm` has no such
    /// variant, so a header claiming it fails to parse. Asserted directly
    /// rather than assumed, because "unreachable" is a claim the tree should be
    /// able to demonstrate.
    #[test]
    fn alg_none_is_unreachable() {
        use base64::Engine as _;
        let b64 = |v: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
        };
        let unsigned = format!(
            "{}.{}.",
            b64(&json!({"alg": "none", "typ": "JWT"})),
            b64(&claims(NOW))
        );
        let key = ed25519_key(None);
        assert!(matches!(
            verify(&unsigned, &jwks(&[&key])),
            Err(AssertionError::Malformed(_))
        ));
    }

    /// The header does not choose the algorithm. Substituting `ES256` into the
    /// header of an EdDSA-signed assertion must not select a different
    /// verification path.
    #[test]
    fn a_header_alg_that_disagrees_with_the_registered_key_is_refused() {
        use base64::Engine as _;
        let key = ed25519_key(None);
        let honest = sign(&key, &claims(NOW));
        let mut parts = honest.split('.');
        let (_, payload, signature) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        let forged_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg": "ES256", "typ": "JWT"})).unwrap());
        let forged = format!("{forged_header}.{payload}.{signature}");
        assert!(matches!(
            verify(&forged, &jwks(&[&key])),
            Err(AssertionError::Key(
                jose::JoseKeyError::AlgorithmMismatch { .. }
            )) | Err(AssertionError::Signature)
        ));
    }

    /// An HMAC header against an asymmetric registered key is the classic
    /// algorithm-confusion forgery. The registered key set contains no
    /// symmetric key, so there is nothing for it to select.
    #[test]
    fn an_hmac_header_finds_no_key_to_confuse() {
        use base64::Engine as _;
        let key = ed25519_key(None);
        let honest = sign(&key, &claims(NOW));
        let payload = honest.split('.').nth(1).unwrap();
        let forged_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg": "HS256", "typ": "JWT"})).unwrap());
        let forged = format!("{forged_header}.{payload}.c2lnbmF0dXJl");
        assert!(verify(&forged, &jwks(&[&key])).is_err());
    }

    /// A registered key whose declared `alg` is outside the profile is not
    /// usable, and a set containing only such keys authenticates nothing.
    #[test]
    fn a_registered_key_outside_the_profile_authenticates_nothing() {
        let set: JwkSet =
            serde_json::from_str(r#"{"keys":[{"kty":"EC","crv":"P-521","x":"AA","y":"AA"}]}"#)
                .unwrap();
        let key = ed25519_key(None);
        assert_eq!(
            verify(&sign(&key, &claims(NOW)), &set),
            Err(AssertionError::Key(jose::JoseKeyError::NoUsableKey))
        );
    }

    #[test]
    fn a_client_with_no_registered_keys_authenticates_nothing() {
        let key = ed25519_key(None);
        let empty = JwkSet { keys: vec![] };
        assert_eq!(
            verify(&sign(&key, &claims(NOW)), &empty),
            Err(AssertionError::NoRegisteredKeys)
        );
    }

    // -- RFC 7523 §3 constraints ------------------------------------------

    #[test]
    fn iss_and_sub_must_both_be_this_client() {
        let key = ed25519_key(None);
        for claim in ["iss", "sub"] {
            let mut c = claims(NOW);
            c[claim] = json!("oa_somebody_else");
            assert_eq!(
                verify(&sign(&key, &c), &jwks(&[&key])),
                Err(AssertionError::SubjectMismatch {
                    claim: if claim == "iss" { "iss" } else { "sub" },
                    got: "oa_somebody_else".into()
                })
            );
        }
    }

    /// An assertion minted for another authorization server must not
    /// authenticate here. This is the cross-AS replay RFC 7523's audience
    /// requirement exists for, and it is the reason `aud` is not merely
    /// advisory.
    #[test]
    fn an_assertion_for_another_server_is_refused() {
        let key = ed25519_key(None);
        let mut c = claims(NOW);
        c["aud"] = json!("https://someone-elses-as.example/token");
        assert_eq!(
            verify(&sign(&key, &c), &jwks(&[&key])),
            Err(AssertionError::AudienceMismatch)
        );
    }

    #[test]
    fn an_expired_assertion_is_refused_and_the_skew_is_bounded() {
        let key = ed25519_key(None);

        let mut expired = claims(NOW);
        expired["exp"] = json!(NOW - CLOCK_SKEW_SECS - 1);
        assert_eq!(
            verify(&sign(&key, &expired), &jwks(&[&key])),
            Err(AssertionError::NotCurrentlyValid("exp has passed"))
        );

        // Just inside the skew allowance still authenticates — a client whose
        // clock is a few seconds slow is not an attacker.
        let mut just_inside = claims(NOW);
        just_inside["exp"] = json!(NOW - CLOCK_SKEW_SECS + 1);
        assert!(verify(&sign(&key, &just_inside), &jwks(&[&key])).is_ok());
    }

    #[test]
    fn nbf_and_a_future_iat_are_honoured() {
        let key = ed25519_key(None);

        let mut not_yet = claims(NOW);
        not_yet["nbf"] = json!(NOW + CLOCK_SKEW_SECS + 10);
        assert!(matches!(
            verify(&sign(&key, &not_yet), &jwks(&[&key])),
            Err(AssertionError::NotCurrentlyValid(_))
        ));

        let mut from_the_future = claims(NOW);
        from_the_future["iat"] = json!(NOW + CLOCK_SKEW_SECS + 10);
        from_the_future["exp"] = json!(NOW + CLOCK_SKEW_SECS + 20);
        assert!(matches!(
            verify(&sign(&key, &from_the_future), &jwks(&[&key])),
            Err(AssertionError::NotCurrentlyValid(_))
        ));
    }

    /// A long-lived assertion is a bearer credential with a long life. The
    /// bound applies whether or not the client supplied `iat` — omitting an
    /// optional claim must not buy an unbounded credential.
    #[test]
    fn an_over_long_assertion_is_refused_with_or_without_iat() {
        let key = ed25519_key(None);

        let mut with_iat = claims(NOW);
        with_iat["exp"] = json!(NOW + MAX_ASSERTION_LIFETIME_SECS + 60);
        assert!(matches!(
            verify(&sign(&key, &with_iat), &jwks(&[&key])),
            Err(AssertionError::LifetimeTooLong { .. })
        ));

        let mut without_iat = with_iat.clone();
        without_iat.as_object_mut().unwrap().remove("iat");
        assert!(matches!(
            verify(&sign(&key, &without_iat), &jwks(&[&key])),
            Err(AssertionError::LifetimeTooLong { .. })
        ));
    }

    #[test]
    fn an_assertion_without_a_usable_jti_is_refused() {
        let key = ed25519_key(None);
        for jti in ["", "  "] {
            let mut c = claims(NOW);
            c["jti"] = json!(jti);
            assert_eq!(
                verify(&sign(&key, &c), &jwks(&[&key])),
                Err(AssertionError::UnusableJti)
            );
        }
        // An absent jti fails deserialization, which is also a refusal — RFC
        // 7523 §3 makes it mandatory.
        let mut c = claims(NOW);
        c.as_object_mut().unwrap().remove("jti");
        assert!(matches!(
            verify(&sign(&key, &c), &jwks(&[&key])),
            Err(AssertionError::Malformed(_))
        ));
    }

    #[test]
    fn the_replay_row_outlives_the_assertion_by_the_skew_allowance() {
        let key = ed25519_key(None);
        let verified = verify(&sign(&key, &claims(NOW)), &jwks(&[&key])).unwrap();
        assert_eq!(
            verified.replay_expiry().timestamp(),
            NOW + 120 + CLOCK_SKEW_SECS
        );
    }

    // -- assertion type ---------------------------------------------------

    #[test]
    fn only_the_jwt_bearer_assertion_type_is_accepted() {
        assert!(check_assertion_type(Some(CLIENT_ASSERTION_TYPE)).is_ok());
        for wrong in [
            None,
            Some(""),
            Some("urn:ietf:params:oauth:client-assertion-type:saml2-bearer"),
        ] {
            assert!(matches!(
                check_assertion_type(wrong),
                Err(AssertionError::WrongAssertionType { .. })
            ));
        }
    }

    // -- key source -------------------------------------------------------

    fn client_with(jwks_doc: Option<&str>, jwks_uri: Option<&str>) -> OAuth2Client {
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: CLIENT.into(),
            client_secret_hash: String::new(),
            name: "test".into(),
            redirect_uris: vec![],
            grant_types: vec![],
            scopes: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::PrivateKeyJwt,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: jwks_doc.map(str::to_owned),
            jwks_uri: jwks_uri.map(str::to_owned),
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn an_inline_jwks_resolves_to_its_keys() {
        let key = ed25519_key(Some("k1"));
        let doc = serde_json::to_string(&jwks(&[&key])).unwrap();
        match key_source_of(&client_with(Some(&doc), None)) {
            ClientKeySource::Inline(set) => assert_eq!(set.keys.len(), 1),
            other => panic!("expected an inline key set, got {other:?}"),
        }
    }

    #[test]
    fn a_jwks_uri_resolves_to_a_remote_source() {
        assert_eq!(
            key_source_of(&client_with(None, Some("https://rp.example/jwks.json"))),
            ClientKeySource::Remote("https://rp.example/jwks.json".into())
        );
    }

    /// A broken key document is an ordinary authentication failure, not a
    /// distinguishable one — see [`key_source_of`]'s docs.
    #[test]
    fn a_malformed_inline_jwks_is_no_keys_rather_than_an_error() {
        assert_eq!(
            key_source_of(&client_with(Some("{not json"), None)),
            ClientKeySource::None
        );
        assert_eq!(
            key_source_of(&client_with(None, None)),
            ClientKeySource::None
        );
        // Blank is absent, matching `count_jwks_sources`'s emptiness rule.
        assert_eq!(
            key_source_of(&client_with(Some("   "), Some("  "))),
            ClientKeySource::None
        );
    }
}

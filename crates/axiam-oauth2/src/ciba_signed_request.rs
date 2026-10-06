//! Signed CIBA authentication requests — CIBA Core 1.0 §7.1.1 and the
//! FAPI-CIBA profile (G-7, D-61).
//!
//! A client that registered `backchannel_authentication_request_signing_alg`
//! sends its backchannel authentication request as **one signed JWT**, the
//! `request` form parameter, whose claims are the request's parameters. The
//! signature binds the request to the client's key, so a request captured in
//! transit (or replayed from a log) cannot be edited — a different
//! `login_hint`, a wider `scope`, a softer `binding_message` — without the edit
//! being detected.
//!
//! # What is checked, and in what order
//!
//! 1. **Size and shape**: at most [`MAX_REQUEST_BYTES`], a JWS.
//! 2. **The algorithm is the registered one.** The header's `alg` must equal
//!    the client's `backchannel_authentication_request_signing_alg` — never
//!    merely "some algorithm AXIAM supports" — and must agree with the key
//!    (`crate::jose`: the key decides, the header only confirms).
//! 3. **The signature**, under a key the client *registered* (`jwks` or
//!    `jwks_uri`, resolved by `private_key_jwt::resolve_registered_keys`, the
//!    one path every client-signed JWT's keys come through). Never a key the
//!    request supplies.
//! 4. `iss` is the `client_id` (§7.1.1); a `client_id` claim, if present, too.
//! 5. `aud` names this authorization server — its issuer identifier, in either
//!    of the two forms AXIAM serves (the deployment's and the tenant path's),
//!    as a string or inside an array.
//! 6. `exp`, `nbf`, `iat` and `jti` are all present (§7.1.1 requires each).
//!    `exp` is in the future, `nbf` and `iat` are not, and FAPI-CIBA §5.2.2's
//!    bounds hold for **every** client: `exp - nbf` at most sixty minutes and
//!    `nbf` no more than sixty minutes in the past.
//! 7. The parameters are read **from the claims only**. The handler has
//!    already refused a form that carried any authentication-request
//!    parameter beside `request` (§7.1.1: they "MUST NOT be present outside of
//!    the JWT"), so nothing outside the JWT can supplement or override it.
//! 8. The `jti` is recorded, **after** everything above, in the proof-replay
//!    table (`ProofKind::CibaRequestObject`, scoped by `client_id`) — the
//!    UNIQUE-index arbiter client assertions and DPoP proofs already use. A
//!    second use is refused, and a guard that cannot record refuses too.
//!
//! # Refusal code
//!
//! Every failure is `invalid_request` (CIBA Core §13: "includes an invalid
//! parameter value … or is otherwise malformed"). §13 defines no
//! request-object code, and RFC 9101's `invalid_request_object` belongs to the
//! authorization endpoint. Unlike a client-authentication failure the
//! description **does** say what failed: the caller has already authenticated
//! as the client whose request it is, so the detail is about its own request
//! and is no oracle about anyone else's.
//!
//! # `request_uri` is not part of CIBA
//!
//! CIBA Core §7.1.1 defines the signed request by value only. A `request_uri`
//! at `bc-authorize` is refused before client authentication, as an
//! unsupported parameter: fetching a client-chosen URL to obtain the request
//! would be the SSRF primitive X7 G12 refused at the authorization endpoint,
//! for no gain the by-value form does not already give.

use axiam_core::models::ciba::CibaRequestSigningAlg;
use axiam_core::models::oauth2_client::OAuth2Client;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::{Map, Value};

use crate::ciba::BackchannelAuthenticationRequest;
use crate::error::OAuth2Error;
use crate::jose;

/// Clock tolerance, the same sixty seconds every client-signed JWT gets.
pub use crate::private_key_jwt::CLOCK_SKEW_SECS;

/// The longest life a signed request may claim, `exp - nbf`, in seconds —
/// FAPI-CIBA §5.2.2's sixty minutes, applied to every client.
pub const MAX_SIGNED_REQUEST_LIFETIME_SECS: i64 = 3600;

/// How far in the past `nbf` may lie, in seconds — FAPI 1.0 Advanced
/// §5.2.2-17's sixty minutes, which FAPI-CIBA inherits.
pub const MAX_NBF_AGE_SECS: i64 = 3600;

/// Longest accepted `request`, in bytes. Generous for a dozen short claims
/// and a PS256 signature; it bounds the work an authenticated client can ask
/// the verifier to do.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Longest accepted `jti`, in bytes — it becomes a key in the replay index.
pub const MAX_JTI_BYTES: usize = 256;

/// The `jsonwebtoken` algorithm a registered value names.
#[must_use]
pub const fn jose_algorithm(alg: CibaRequestSigningAlg) -> Algorithm {
    match alg {
        CibaRequestSigningAlg::Ps256 => Algorithm::PS256,
        CibaRequestSigningAlg::Es256 => Algorithm::ES256,
        CibaRequestSigningAlg::EdDsa => Algorithm::EdDSA,
    }
}

/// The algorithms advertised as
/// `backchannel_authentication_request_signing_alg_values_supported`.
///
/// Derived from [`CibaRequestSigningAlg::ALL`] — the set registration
/// accepts — and asserted in this module's tests to equal
/// `jose::permitted_algorithm_names()`, the set the verifier honours, so the
/// three can never disagree.
#[must_use]
pub fn supported_algorithm_names() -> Vec<String> {
    CibaRequestSigningAlg::ALL
        .iter()
        .map(|a| a.as_str().to_owned())
        .collect()
}

/// Whether a key set holds at least one key the registered algorithm can
/// verify with — the registration-time check that an inline `jwks` can serve
/// the algorithm the client says it signs with.
#[must_use]
pub fn key_set_supports(keys: &JwkSet, alg: CibaRequestSigningAlg) -> bool {
    let wanted = jose_algorithm(alg);
    keys.keys
        .iter()
        .any(|k| jose::algorithm_for_key(k).is_ok_and(|a| a == wanted))
}

/// Why a signed authentication request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedRequestError {
    /// Not a JWS, too large, or a claim of the wrong JSON type.
    Malformed(String),
    /// The header names an algorithm other than the registered one.
    AlgorithmNotRegistered {
        /// What the header named.
        header: String,
        /// What the client registered.
        registered: CibaRequestSigningAlg,
    },
    /// No registered key can verify the registered algorithm (or a `kid`
    /// named none).
    NoKey(String),
    /// The signature did not verify under any candidate key.
    Signature,
    /// `iss` (or `client_id`) is not this client.
    ClaimMismatch {
        /// The claim.
        claim: &'static str,
    },
    /// `aud` does not name this authorization server.
    AudienceMismatch,
    /// A claim §7.1.1 requires is absent.
    MissingClaim(&'static str),
    /// `exp` has passed, `nbf` or `iat` has not arrived, or `nbf` is too old.
    NotCurrentlyValid(&'static str),
    /// `exp - nbf` exceeds [`MAX_SIGNED_REQUEST_LIFETIME_SECS`].
    LifetimeTooLong {
        /// The claimed life.
        seconds: i64,
    },
    /// `jti` is blank or longer than [`MAX_JTI_BYTES`].
    UnusableJti,
    /// This `jti` was already used by this client.
    Replayed,
}

impl std::fmt::Display for SignedRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "malformed: {detail}"),
            Self::AlgorithmNotRegistered { header, registered } => write!(
                f,
                "signed with {header}, but this client registered {} as its \
                 backchannel_authentication_request_signing_alg",
                registered.as_str()
            ),
            Self::NoKey(detail) => write!(f, "no registered key can verify it: {detail}"),
            Self::Signature => write!(f, "the signature does not verify under a registered key"),
            Self::ClaimMismatch { claim } => write!(f, "{claim} must be this client's client_id"),
            Self::AudienceMismatch => write!(f, "aud must be this server's issuer identifier"),
            Self::MissingClaim(claim) => write!(f, "the {claim} claim is required"),
            Self::NotCurrentlyValid(why) => write!(f, "not currently valid: {why}"),
            Self::LifetimeTooLong { seconds } => write!(
                f,
                "exp - nbf is {seconds} seconds; at most {MAX_SIGNED_REQUEST_LIFETIME_SECS} \
                 is accepted"
            ),
            Self::UnusableJti => write!(
                f,
                "jti must be a non-blank string of at most {MAX_JTI_BYTES} bytes"
            ),
            Self::Replayed => write!(f, "this jti has already been used"),
        }
    }
}

impl std::error::Error for SignedRequestError {}

impl From<SignedRequestError> for OAuth2Error {
    fn from(e: SignedRequestError) -> Self {
        OAuth2Error::InvalidRequest(format!("the signed authentication request is invalid: {e}"))
    }
}

/// A signed request that verified: the parameters it carries, and the `jti`
/// the caller must still record.
#[derive(Debug)]
pub struct VerifiedSignedRequest {
    /// The authentication-request parameters, from the claims only. The
    /// client-authentication members are `None`: they are not request
    /// parameters, and authentication has already happened.
    pub params: BackchannelAuthenticationRequest,
    /// The `jti` to record.
    pub jti: String,
    /// The request's `exp`.
    pub exp: i64,
}

impl VerifiedSignedRequest {
    /// When the replay row stops being useful: past `exp` plus the skew, the
    /// request is refused on `exp` without the table being read.
    #[must_use]
    pub fn replay_expiry(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(self.exp + CLOCK_SKEW_SECS, 0)
            .unwrap_or_else(chrono::Utc::now)
    }
}

fn string_claim(
    claims: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, SignedRequestError> {
    match claims.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(SignedRequestError::Malformed(format!(
            "the {name} claim must be a string"
        ))),
    }
}

fn time_claim(claims: &Map<String, Value>, name: &'static str) -> Result<i64, SignedRequestError> {
    match claims.get(name) {
        None | Some(Value::Null) => Err(SignedRequestError::MissingClaim(name)),
        Some(Value::Number(n)) => n
            .as_i64()
            .or_else(|| n.as_f64().map(|f| f as i64))
            .ok_or_else(|| SignedRequestError::Malformed(format!("{name} is not a NumericDate"))),
        Some(_) => Err(SignedRequestError::Malformed(format!(
            "{name} must be a NumericDate"
        ))),
    }
}

/// Verify a signed authentication request against the keys a client
/// registered, and return its parameters.
///
/// Pure — no clock, no datastore, no network — so every rule is testable
/// against vectors. **The caller must record the returned `jti`**; that is the
/// single-use half, and it is not optional.
///
/// `acceptable_audiences` are the issuer identifiers this request may name:
/// the deployment's and, for a tenant-path request, the tenant's.
///
/// # Errors
///
/// The first rule that failed.
pub fn verify_signed_request(
    request: &str,
    client_id: &str,
    registered: CibaRequestSigningAlg,
    acceptable_audiences: &[String],
    keys: &JwkSet,
    now: i64,
) -> Result<VerifiedSignedRequest, SignedRequestError> {
    if request.len() > MAX_REQUEST_BYTES {
        return Err(SignedRequestError::Malformed(format!(
            "request exceeds {MAX_REQUEST_BYTES} bytes"
        )));
    }
    let header = decode_header(request)
        .map_err(|e| SignedRequestError::Malformed(format!("not a JWS: {e}")))?;
    let wanted = jose_algorithm(registered);
    if header.alg != wanted {
        return Err(SignedRequestError::AlgorithmNotRegistered {
            header: format!("{:?}", header.alg),
            registered,
        });
    }

    let candidates: Vec<(&Jwk, Algorithm)> =
        jose::candidate_keys(&keys.keys, header.kid.as_deref())
            .map_err(|e| SignedRequestError::NoKey(e.to_string()))?
            .into_iter()
            .filter(|(_, key_alg)| *key_alg == wanted)
            .collect();
    if candidates.is_empty() {
        return Err(SignedRequestError::NoKey(format!(
            "no registered key is a {} key",
            registered.as_str()
        )));
    }

    let mut verified: Option<Map<String, Value>> = None;
    for (jwk, key_alg) in &candidates {
        let Ok(alg) = jose::verify_permitted_header(header.alg, *key_alg) else {
            continue;
        };
        let Ok(decoding_key) = jose::decoding_key_for(jwk) else {
            continue;
        };
        let mut validation = Validation::new(alg);
        // Every temporal and audience rule is applied below, once, with
        // §7.1.1's and FAPI-CIBA's semantics.
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims.clear();
        match decode::<Map<String, Value>>(request, &decoding_key, &validation) {
            Ok(data) => {
                verified = Some(data.claims);
                break;
            }
            Err(e) => match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => continue,
                _ => return Err(SignedRequestError::Malformed(e.to_string())),
            },
        }
    }
    let Some(claims) = verified else {
        return Err(SignedRequestError::Signature);
    };

    // --- who sent it, and to whom ----------------------------------------
    match claims.get("iss") {
        None | Some(Value::Null) => return Err(SignedRequestError::MissingClaim("iss")),
        Some(Value::String(iss)) if iss == client_id => {}
        Some(_) => return Err(SignedRequestError::ClaimMismatch { claim: "iss" }),
    }
    if let Some(cid) = claims.get("client_id")
        && cid.as_str() != Some(client_id)
    {
        return Err(SignedRequestError::ClaimMismatch { claim: "client_id" });
    }
    let aud_ok = match claims.get("aud") {
        None | Some(Value::Null) => return Err(SignedRequestError::MissingClaim("aud")),
        Some(Value::String(a)) => acceptable_audiences.iter().any(|x| x == a),
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(Value::as_str)
            .any(|a| acceptable_audiences.iter().any(|x| x == a)),
        Some(_) => false,
    };
    if !aud_ok {
        return Err(SignedRequestError::AudienceMismatch);
    }

    // --- when --------------------------------------------------------------
    let exp = time_claim(&claims, "exp")?;
    let nbf = time_claim(&claims, "nbf")?;
    let iat = time_claim(&claims, "iat")?;
    let jti = match claims.get("jti") {
        None | Some(Value::Null) => return Err(SignedRequestError::MissingClaim("jti")),
        Some(Value::String(j)) if !j.trim().is_empty() && j.len() <= MAX_JTI_BYTES => j.clone(),
        Some(_) => return Err(SignedRequestError::UnusableJti),
    };
    if exp <= now - CLOCK_SKEW_SECS {
        return Err(SignedRequestError::NotCurrentlyValid("exp has passed"));
    }
    if nbf > now + CLOCK_SKEW_SECS {
        return Err(SignedRequestError::NotCurrentlyValid(
            "nbf is in the future",
        ));
    }
    if iat > now + CLOCK_SKEW_SECS {
        return Err(SignedRequestError::NotCurrentlyValid(
            "iat is in the future",
        ));
    }
    if nbf < now - MAX_NBF_AGE_SECS {
        return Err(SignedRequestError::NotCurrentlyValid(
            "nbf is more than 60 minutes in the past",
        ));
    }
    if exp - nbf > MAX_SIGNED_REQUEST_LIFETIME_SECS {
        return Err(SignedRequestError::LifetimeTooLong { seconds: exp - nbf });
    }

    // --- what it asks for: from the claims, and only from them -------------
    for nested in ["request", "request_uri"] {
        if claims.contains_key(nested) {
            return Err(SignedRequestError::Malformed(format!(
                "a signed request must not carry a {nested} claim"
            )));
        }
    }
    let requested_expiry = match claims.get("requested_expiry") {
        None | Some(Value::Null) => None,
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => {
            return Err(SignedRequestError::Malformed(
                "the requested_expiry claim must be a number".into(),
            ));
        }
    };
    let params = BackchannelAuthenticationRequest {
        scope: string_claim(&claims, "scope")?,
        client_notification_token: string_claim(&claims, "client_notification_token")?,
        acr_values: string_claim(&claims, "acr_values")?,
        login_hint_token: string_claim(&claims, "login_hint_token")?,
        id_token_hint: string_claim(&claims, "id_token_hint")?,
        login_hint: string_claim(&claims, "login_hint")?,
        binding_message: string_claim(&claims, "binding_message")?,
        user_code: string_claim(&claims, "user_code")?,
        requested_expiry,
        resource: string_claim(&claims, "resource")?,
        ..Default::default()
    };

    Ok(VerifiedSignedRequest { params, jti, exp })
}

// ---------------------------------------------------------------------------
// The verifier seam
// ---------------------------------------------------------------------------

/// A future returned by [`SignedRequestVerifier`].
pub type SignedRequestFuture<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<BackchannelAuthenticationRequest, OAuth2Error>>
            + Send
            + 'a,
    >,
>;

/// Resolve a client's keys, verify its signed request and record the `jti`.
///
/// A trait object for the reason `private_key_jwt::ClientAssertionVerifier`
/// is one: it keeps [`verify_signed_request`] free of the database and the
/// network, and keeps `CibaService`'s generic parameters to its two stores.
pub trait SignedRequestVerifier: Send + Sync {
    /// Verify `request` for `client` (which has authenticated and registered
    /// a signing algorithm) and return the parameters it carries.
    fn verify<'a>(
        &'a self,
        client: &'a OAuth2Client,
        request: &'a str,
        acceptable_audiences: &'a [String],
    ) -> SignedRequestFuture<'a>;
}

/// The production [`SignedRequestVerifier`]: the federation JWKS cache (the
/// same SSRF-guarded path, and the same cache entries, as client assertions)
/// and the proof-replay table.
pub struct JwksSignedRequestVerifier<R> {
    jwks: axiam_federation::jwks_cache::JwksCache,
    http: reqwest::Client,
    replay: R,
}

impl<R> JwksSignedRequestVerifier<R> {
    /// Compose the verifier. Pass the deployment's shared JWKS cache.
    pub fn new(
        jwks: axiam_federation::jwks_cache::JwksCache,
        http: reqwest::Client,
        replay: R,
    ) -> Self {
        Self { jwks, http, replay }
    }
}

impl<R> SignedRequestVerifier for JwksSignedRequestVerifier<R>
where
    R: axiam_core::repository::ProofReplayRepository,
{
    fn verify<'a>(
        &'a self,
        client: &'a OAuth2Client,
        request: &'a str,
        acceptable_audiences: &'a [String],
    ) -> SignedRequestFuture<'a> {
        Box::pin(async move {
            use axiam_core::repository::ProofKind;

            let Some(registered) = client.ciba.backchannel_authentication_request_signing_alg
            else {
                return Err(OAuth2Error::InvalidRequest(
                    "this client has not registered backchannel_authentication_request_signing_alg"
                        .into(),
                ));
            };
            let Some(keys) = crate::private_key_jwt::resolve_registered_keys(
                &self.jwks,
                &self.http,
                client.tenant_id,
                client,
            )
            .await
            else {
                return Err(SignedRequestError::NoKey(
                    "the client's registered key set could not be obtained".into(),
                )
                .into());
            };
            let now = chrono::Utc::now().timestamp();
            let verified = verify_signed_request(
                request,
                &client.client_id,
                registered,
                acceptable_audiences,
                &keys,
                now,
            )
            .inspect_err(|e| {
                tracing::debug!(
                    client_id = %client.client_id,
                    reason = %e,
                    "a signed CIBA authentication request was refused"
                );
            })?;

            // After verification, so a garbage request cannot fill the table.
            match self
                .replay
                .insert_proof_jti(
                    client.tenant_id,
                    ProofKind::CibaRequestObject,
                    &client.client_id,
                    &verified.jti,
                    verified.replay_expiry(),
                )
                .await
            {
                Ok(()) => Ok(verified.params),
                Err(axiam_core::error::AxiamError::ReplayDetected) => {
                    tracing::warn!(
                        client_id = %client.client_id,
                        "a signed CIBA authentication request was replayed; refusing"
                    );
                    Err(SignedRequestError::Replayed.into())
                }
                Err(e) => {
                    // A replay guard that cannot record must not accept: the
                    // request would be single-use only while the database is up.
                    tracing::error!(
                        client_id = %client.client_id,
                        error = %e,
                        "could not record a signed CIBA request's jti; refusing it"
                    );
                    Err(OAuth2Error::ServerError(
                        "the signed request could not be made single-use".into(),
                    ))
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    const NOW: i64 = 1_800_000_000;
    const CLIENT: &str = "oa_ciba";
    const ISSUER: &str = "https://as.example";
    const TENANT_ISSUER: &str = "https://as.example/t/acme";

    fn audiences() -> Vec<String> {
        vec![ISSUER.into(), TENANT_ISSUER.into()]
    }

    struct TestKey {
        encoding: EncodingKey,
        jwk: Value,
        alg: Algorithm,
    }

    fn ed25519(kid: Option<&str>) -> TestKey {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let raw = kp.public_key_raw();
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw[raw.len() - 32..]);
        let mut jwk = json!({"kty": "OKP", "crv": "Ed25519", "x": x});
        if let Some(kid) = kid {
            jwk["kid"] = json!(kid);
        }
        TestKey {
            encoding: EncodingKey::from_ed_pem(kp.serialize_pem().as_bytes()).unwrap(),
            jwk,
            alg: Algorithm::EdDSA,
        }
    }

    fn p256() -> TestKey {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let raw = kp.public_key_raw(); // 0x04 || x || y
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        TestKey {
            encoding: EncodingKey::from_ec_pem(kp.serialize_pem().as_bytes()).unwrap(),
            jwk: json!({"kty": "EC", "crv": "P-256", "x": b64(&raw[1..33]), "y": b64(&raw[33..65])}),
            alg: Algorithm::ES256,
        }
    }

    fn set(keys: &[&TestKey]) -> JwkSet {
        serde_json::from_value(
            json!({"keys": keys.iter().map(|k| k.jwk.clone()).collect::<Vec<_>>()}),
        )
        .unwrap()
    }

    fn claims() -> Value {
        json!({
            "iss": CLIENT,
            "aud": ISSUER,
            "exp": NOW + 300,
            "nbf": NOW,
            "iat": NOW,
            "jti": "req-0001",
            "scope": "openid profile",
            "login_hint": "alice",
            "binding_message": "W4SCT",
            "requested_expiry": 120,
        })
    }

    fn sign(key: &TestKey, claims: &Value) -> String {
        let mut header = Header::new(key.alg);
        header.kid = key
            .jwk
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_owned);
        jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
    }

    fn verify(jwt: &str, keys: &JwkSet) -> Result<VerifiedSignedRequest, SignedRequestError> {
        verify_signed_request(
            jwt,
            CLIENT,
            CibaRequestSigningAlg::EdDsa,
            &audiences(),
            keys,
            NOW,
        )
    }

    #[test]
    fn a_well_formed_request_yields_its_parameters_and_jti() {
        let key = ed25519(None);
        let v = verify(&sign(&key, &claims()), &set(&[&key])).unwrap();
        assert_eq!(v.jti, "req-0001");
        assert_eq!(v.params.scope.as_deref(), Some("openid profile"));
        assert_eq!(v.params.login_hint.as_deref(), Some("alice"));
        assert_eq!(v.params.binding_message.as_deref(), Some("W4SCT"));
        assert_eq!(v.params.requested_expiry.as_deref(), Some("120"));
        assert!(v.params.client_id.is_none() && v.params.request.is_none());
        assert_eq!(v.replay_expiry().timestamp(), NOW + 300 + CLOCK_SKEW_SECS);
    }

    #[test]
    fn both_issuer_forms_are_an_audience_as_a_string_or_in_an_array() {
        let key = ed25519(None);
        for aud in [
            json!(ISSUER),
            json!(TENANT_ISSUER),
            json!([ISSUER]),
            json!(["https://other.example", TENANT_ISSUER]),
        ] {
            let mut c = claims();
            c["aud"] = aud.clone();
            assert!(verify(&sign(&key, &c), &set(&[&key])).is_ok(), "{aud}");
        }
        for aud in [
            json!("https://other.example"),
            json!(format!("{ISSUER}/oauth2/bc-authorize")),
            json!([]),
            json!(42),
        ] {
            let mut c = claims();
            c["aud"] = aud.clone();
            assert_eq!(
                verify(&sign(&key, &c), &set(&[&key])).unwrap_err(),
                SignedRequestError::AudienceMismatch,
                "{aud}"
            );
        }
    }

    #[test]
    fn a_signature_by_an_unregistered_key_is_refused() {
        let registered = ed25519(None);
        let stranger = ed25519(None);
        assert_eq!(
            verify(&sign(&stranger, &claims()), &set(&[&registered])).unwrap_err(),
            SignedRequestError::Signature
        );
        // A tampered payload under the right key fails the same way.
        let jwt = sign(&registered, &claims());
        let mut parts: Vec<String> = jwt.split('.').map(str::to_owned).collect();
        let mut c = claims();
        c["login_hint"] = json!("mallory");
        parts[1] = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&c).unwrap());
        assert_eq!(
            verify(&parts.join("."), &set(&[&registered])).unwrap_err(),
            SignedRequestError::Signature
        );
    }

    #[test]
    fn only_the_registered_algorithm_is_accepted() {
        // The client registered EdDSA and publishes an Ed25519 and a P-256
        // key: an ES256 signature by its own P-256 key is still refused.
        let ed = ed25519(None);
        let ec = p256();
        let keys = set(&[&ed, &ec]);
        assert!(matches!(
            verify(&sign(&ec, &claims()), &keys).unwrap_err(),
            SignedRequestError::AlgorithmNotRegistered {
                registered: CibaRequestSigningAlg::EdDsa,
                ..
            }
        ));
        // Registered ES256, it verifies.
        assert!(
            verify_signed_request(
                &sign(&ec, &claims()),
                CLIENT,
                CibaRequestSigningAlg::Es256,
                &audiences(),
                &keys,
                NOW,
            )
            .is_ok()
        );
        // Registered ES256 with only an Ed25519 key: nothing can verify it.
        assert!(matches!(
            verify_signed_request(
                &sign(&ec, &claims()),
                CLIENT,
                CibaRequestSigningAlg::Es256,
                &audiences(),
                &set(&[&ed]),
                NOW,
            )
            .unwrap_err(),
            SignedRequestError::NoKey(_)
        ));
        // An HS256 token with the key's own bytes as the secret never reaches
        // a verifier.
        let hs = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(b"public-key-bytes"),
        )
        .unwrap();
        assert!(matches!(
            verify(&hs, &set(&[&ed])).unwrap_err(),
            SignedRequestError::AlgorithmNotRegistered { .. }
        ));
    }

    #[test]
    fn a_kid_selects_among_registered_keys_and_an_unknown_one_is_refused() {
        let a = ed25519(Some("a"));
        let b = ed25519(Some("b"));
        assert!(verify(&sign(&b, &claims()), &set(&[&a, &b])).is_ok());
        assert!(matches!(
            verify(&sign(&b, &claims()), &set(&[&a])).unwrap_err(),
            SignedRequestError::NoKey(_)
        ));
    }

    #[test]
    fn iss_and_a_client_id_claim_must_be_this_client() {
        let key = ed25519(None);
        let mut c = claims();
        c["iss"] = json!("someone-else");
        assert_eq!(
            verify(&sign(&key, &c), &set(&[&key])).unwrap_err(),
            SignedRequestError::ClaimMismatch { claim: "iss" }
        );
        let mut c = claims();
        c["client_id"] = json!("someone-else");
        assert_eq!(
            verify(&sign(&key, &c), &set(&[&key])).unwrap_err(),
            SignedRequestError::ClaimMismatch { claim: "client_id" }
        );
        let mut c = claims();
        c["client_id"] = json!(CLIENT);
        assert!(verify(&sign(&key, &c), &set(&[&key])).is_ok());
    }

    #[test]
    fn every_claim_section_7_1_1_requires_is_required() {
        let key = ed25519(None);
        for claim in ["iss", "aud", "exp", "nbf", "iat", "jti"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(claim);
            assert_eq!(
                verify(&sign(&key, &c), &set(&[&key])).unwrap_err(),
                SignedRequestError::MissingClaim(claim),
                "{claim}"
            );
        }
    }

    #[test]
    fn the_fapi_ciba_lifetime_bounds_hold() {
        let key = ed25519(None);
        let check = |exp: i64, nbf: i64, iat: i64| {
            let mut c = claims();
            c["exp"] = json!(exp);
            c["nbf"] = json!(nbf);
            c["iat"] = json!(iat);
            verify(&sign(&key, &c), &set(&[&key]))
        };
        // Expired, beyond the skew.
        assert!(matches!(
            check(NOW - CLOCK_SKEW_SECS - 1, NOW - 120, NOW - 120).unwrap_err(),
            SignedRequestError::NotCurrentlyValid("exp has passed")
        ));
        // Not yet valid.
        assert!(matches!(
            check(NOW + 600, NOW + CLOCK_SKEW_SECS + 1, NOW).unwrap_err(),
            SignedRequestError::NotCurrentlyValid("nbf is in the future")
        ));
        assert!(matches!(
            check(NOW + 600, NOW, NOW + CLOCK_SKEW_SECS + 1).unwrap_err(),
            SignedRequestError::NotCurrentlyValid("iat is in the future")
        ));
        // Sixty minutes exactly is accepted; one second more is not.
        assert!(check(NOW + 3000, NOW - 600, NOW - 600).is_ok());
        assert_eq!(
            check(NOW + 3001, NOW - 600, NOW - 600).unwrap_err(),
            SignedRequestError::LifetimeTooLong { seconds: 3601 }
        );
        // An nbf more than sixty minutes old.
        assert!(matches!(
            check(
                NOW + 10,
                NOW - MAX_NBF_AGE_SECS - 1,
                NOW - MAX_NBF_AGE_SECS - 1
            )
            .unwrap_err(),
            SignedRequestError::NotCurrentlyValid(_)
        ));
    }

    #[test]
    fn a_blank_or_oversized_jti_is_unusable() {
        let key = ed25519(None);
        for jti in [
            json!(""),
            json!("   "),
            json!(7),
            json!("j".repeat(MAX_JTI_BYTES + 1)),
        ] {
            let mut c = claims();
            c["jti"] = jti.clone();
            assert_eq!(
                verify(&sign(&key, &c), &set(&[&key])).unwrap_err(),
                SignedRequestError::UnusableJti,
                "{jti}"
            );
        }
    }

    #[test]
    fn parameters_of_the_wrong_type_or_nested_requests_are_malformed() {
        let key = ed25519(None);
        for (name, value) in [
            ("login_hint", json!(["alice"])),
            ("scope", json!(1)),
            ("requested_expiry", json!(true)),
            ("request", json!("x.y.z")),
            ("request_uri", json!("https://rp.example/r")),
        ] {
            let mut c = claims();
            c[name] = value;
            assert!(
                matches!(
                    verify(&sign(&key, &c), &set(&[&key])).unwrap_err(),
                    SignedRequestError::Malformed(_)
                ),
                "{name}"
            );
        }
        // A string requested_expiry is accepted as sent.
        let mut c = claims();
        c["requested_expiry"] = json!("90");
        assert_eq!(
            verify(&sign(&key, &c), &set(&[&key]))
                .unwrap()
                .params
                .requested_expiry
                .as_deref(),
            Some("90")
        );
    }

    #[test]
    fn an_oversized_or_non_jws_request_is_malformed() {
        let key = ed25519(None);
        assert!(matches!(
            verify("not-a-jwt", &set(&[&key])).unwrap_err(),
            SignedRequestError::Malformed(_)
        ));
        assert!(matches!(
            verify(&"a".repeat(MAX_REQUEST_BYTES + 1), &set(&[&key])).unwrap_err(),
            SignedRequestError::Malformed(_)
        ));
    }

    #[test]
    fn the_advertised_registered_and_verified_sets_agree() {
        assert_eq!(
            supported_algorithm_names(),
            jose::permitted_algorithm_names()
        );
        for alg in CibaRequestSigningAlg::ALL {
            assert!(jose::is_permitted(jose_algorithm(alg)));
        }
    }

    #[test]
    fn a_key_set_supports_exactly_the_algorithms_of_its_keys() {
        let ed = ed25519(None);
        let ec = p256();
        assert!(key_set_supports(&set(&[&ed]), CibaRequestSigningAlg::EdDsa));
        assert!(!key_set_supports(
            &set(&[&ed]),
            CibaRequestSigningAlg::Es256
        ));
        assert!(key_set_supports(
            &set(&[&ed, &ec]),
            CibaRequestSigningAlg::Es256
        ));
        assert!(!key_set_supports(&set(&[]), CibaRequestSigningAlg::Ps256));
    }

    #[test]
    fn every_refusal_is_invalid_request_naming_the_failure() {
        let e: OAuth2Error = SignedRequestError::Replayed.into();
        assert_eq!(e.error_code(), "invalid_request");
        assert!(e.to_string().contains("already been used"));
    }
}

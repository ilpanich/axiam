//! DPoP — Demonstrating Proof of Possession (RFC 9449) — X5.1.
//!
//! The second half of X5.1's sender-constraining row, and the counterpart to
//! [`crate::mtls`]'s §3. Both answer the same question — *may this bearer use
//! this token?* — and they differ in what the holder must possess:
//!
//! | | Possession proved by | Cost per request |
//! |---|---|---|
//! | mTLS binding (RFC 8705 §3) | a TLS handshake the transport already performed | one SHA-256 |
//! | DPoP (RFC 9449) | a freshly signed proof JWT, per request | **one asymmetric signature verification** |
//!
//! That second row is the reason DPoP exists and the reason it is not free.
//! mTLS binding is cheap because the expensive part — proving possession of the
//! certificate's private key — happened during the handshake and is amortised
//! over every request on the connection. DPoP has no connection to amortise
//! over, so it pays a public-key verification *per request*. `bench_dpop_proof`
//! in `axiam-auth`'s benchmark measures it, and §X5.1's write-up publishes the
//! number rather than an adjective. A client that can do mTLS should.
//!
//! What DPoP buys for that cost is the deployment it fits: a client behind a
//! TLS-terminating load balancer it does not control cannot present a client
//! certificate to AXIAM at all. Before this module, such a client had no route
//! to a sender-constrained token — which the conformance runbook recorded as a
//! coverage gap. It is now closed.
//!
//! # What a proof is checked against
//!
//! RFC 9449 §4.3. Every one of these is a refusal, never a warning:
//!
//! 1. `typ` is exactly `dpop+jwt`. A proof that is not typed as one is not one —
//!    this is the header confusion the `typ` member exists to prevent, and it is
//!    what stops an access token or an ID token being replayed as a proof.
//! 2. `alg` is an asymmetric algorithm this profile permits, **taken from the
//!    embedded key** (see [`crate::jose`]) rather than believed from the header.
//! 3. The header carries a public `jwk`, and the signature verifies under it.
//!    A `jwk` carrying private key material is refused outright (§4.3 step 4):
//!    a client that leaks its private key in a proof has already lost, and
//!    accepting it would make the leak silent.
//! 4. `htm` matches the HTTP method and `htu` the request URI, compared after
//!    stripping query and fragment (§4.3 step 9).
//! 5. `iat` is within [`DEFAULT_PROOF_MAX_AGE_SECS`] of now, in both directions.
//! 6. `jti` is present and, at the caller's discretion, single-use. **Freshness
//!    is not replay protection**: `iat` bounds the window, and the `jti` guard
//!    is what makes the window unusable. See [`crate::private_key_jwt`] for the
//!    storage mechanism both share.
//! 7. When the server requires one, `nonce` matches the nonce the server
//!    issued — otherwise the caller answers `use_dpop_nonce` with a fresh one.
//! 8. When a proof accompanies an access token, `ath` is the base64url SHA-256
//!    of that token, so a proof captured on one request cannot be re-aimed at
//!    another token held by the same key.
//!
//! # What this module deliberately does not do
//!
//! It does not touch the database and it does not know what a client is. Replay
//! recording is the caller's, because the caller is the one that knows the
//! tenant and holds the repository — and because keeping the signature check
//! synchronous and pure is what makes it benchmarkable and unit-testable
//! against RFC 9449's own vectors.

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

use crate::jose;

/// RFC 9449 §4.2: the `typ` every DPoP proof must carry.
pub const DPOP_TYP: &str = "dpop+jwt";

/// RFC 9449 §5: the `token_type` of a DPoP-bound access token.
///
/// Case matters on the way out (`DPoP`, as the RFC spells it) and does not on
/// the way in — see [`is_dpop_scheme`].
pub const TOKEN_TYPE_DPOP: &str = "DPoP";

/// RFC 6749 §7.1: the `token_type` of everything AXIAM issued before X5.1, and
/// of every unbound token it will ever issue.
pub const TOKEN_TYPE_BEARER: &str = "Bearer";

/// How far `iat` may be from now, in either direction, for a proof to be fresh
/// (RFC 9449 §4.3 step 12 leaves the window to the server).
///
/// Sixty seconds both ways. Forwards because a client's clock can legitimately
/// run fast and refusing those proofs is an outage with no attacker in it;
/// backwards because the window is the *only* thing bounding how long a
/// captured proof stays interesting to somebody who cannot reach the replay
/// table. Sixty is the value RFC 9449's own security considerations use as the
/// illustrative "relatively brief period".
pub const DEFAULT_PROOF_MAX_AGE_SECS: i64 = 60;

/// The claims RFC 9449 §4.2 defines on a proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProofClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

/// Why a DPoP proof was refused.
///
/// RFC 9449 §7.1 gives the wire mapping: everything here is `invalid_dpop_proof`
/// except [`DpopError::NonceRequired`] and [`DpopError::NonceMismatch`], which
/// are `use_dpop_nonce` — a *challenge*, not a rejection, and the one case where
/// the client is expected to retry rather than give up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopError {
    /// Not a JWT, or not one carrying the claims a proof must carry.
    Malformed(String),
    /// `typ` was absent or was not `dpop+jwt`.
    WrongTyp { got: Option<String> },
    /// The header carried no `jwk`, or one that cannot be used.
    Key(jose::JoseKeyError),
    /// The header's `jwk` contained private key material.
    PrivateKeyInProof,
    /// The signature did not verify under the embedded key.
    Signature,
    /// `iat` is outside the freshness window.
    Stale { iat: i64, now: i64 },
    /// `htm` does not name the method this request used.
    MethodMismatch { expected: String, got: String },
    /// `htu` does not name the URI this request targeted.
    UriMismatch { expected: String, got: String },
    /// The server requires a nonce and the proof carried none.
    NonceRequired,
    /// The proof carried a nonce that is not the one the server issued.
    NonceMismatch,
    /// `ath` does not hash the access token presented alongside the proof.
    AccessTokenHashMismatch,
    /// A proof accompanied an access token but carried no `ath`.
    AccessTokenHashMissing,
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(d) => write!(f, "malformed DPoP proof: {d}"),
            Self::WrongTyp { got } => write!(
                f,
                "a DPoP proof must be typed {DPOP_TYP:?}, got {got:?}; an untyped JWT is not a \
                 proof"
            ),
            Self::Key(e) => write!(f, "DPoP proof key: {e}"),
            Self::PrivateKeyInProof => write!(
                f,
                "the DPoP proof's jwk carries private key material, which RFC 9449 §4.3 forbids"
            ),
            Self::Signature => write!(f, "the DPoP proof signature does not verify"),
            Self::Stale { iat, now } => write!(
                f,
                "the DPoP proof's iat ({iat}) is outside the {DEFAULT_PROOF_MAX_AGE_SECS}s \
                 freshness window around {now}"
            ),
            Self::MethodMismatch { expected, got } => {
                write!(f, "the DPoP proof's htm is {got:?}, not {expected:?}")
            }
            Self::UriMismatch { expected, got } => {
                write!(f, "the DPoP proof's htu is {got:?}, not {expected:?}")
            }
            Self::NonceRequired => write!(f, "a DPoP nonce is required and the proof carried none"),
            Self::NonceMismatch => write!(f, "the DPoP proof carries a stale or unknown nonce"),
            Self::AccessTokenHashMismatch => write!(
                f,
                "the DPoP proof's ath does not hash the access token it was presented with"
            ),
            Self::AccessTokenHashMissing => write!(
                f,
                "a DPoP proof presented with an access token must carry ath (RFC 9449 §4.2)"
            ),
        }
    }
}

impl std::error::Error for DpopError {}

impl DpopError {
    /// The RFC 9449 §7.1 error code this refusal is reported as.
    ///
    /// `use_dpop_nonce` is not a failure the client should give up on — it is
    /// the server saying "retry with this". Everything else is.
    pub const fn error_code(&self) -> &'static str {
        match self {
            Self::NonceRequired | Self::NonceMismatch => "use_dpop_nonce",
            _ => "invalid_dpop_proof",
        }
    }

    /// Whether the client is expected to retry with a server-supplied nonce.
    pub const fn is_nonce_challenge(&self) -> bool {
        matches!(self, Self::NonceRequired | Self::NonceMismatch)
    }
}

impl From<jose::JoseKeyError> for DpopError {
    fn from(e: jose::JoseKeyError) -> Self {
        Self::Key(e)
    }
}

/// What the verifier checks a proof against.
///
/// A struct rather than eight positional parameters because two of them are
/// `Option<&str>` and swapping them would compile — and would mean checking the
/// nonce against the access token.
#[derive(Debug, Clone, Copy)]
pub struct DpopExpectation<'a> {
    /// The HTTP method of the request the proof accompanies.
    pub htm: &'a str,
    /// The full request URI, which the verifier strips of query and fragment
    /// before comparing (RFC 9449 §4.3 step 9).
    pub htu: &'a str,
    /// The nonce the server most recently issued to this client, if any.
    pub expected_nonce: Option<&'a str>,
    /// Whether a nonce is mandatory for this client. When true and the proof
    /// carries none, the answer is [`DpopError::NonceRequired`] — a challenge.
    pub require_nonce: bool,
    /// The access token the proof was presented with, at a resource server.
    /// `None` at the token endpoint, where no access token exists yet.
    pub access_token: Option<&'a str>,
    /// Unix seconds. Passed in rather than read from the clock so a test can
    /// pin it and the benchmark can exclude it.
    pub now: i64,
    /// Freshness window in seconds; [`DEFAULT_PROOF_MAX_AGE_SECS`] unless a
    /// deployment has a reason.
    pub max_age_secs: i64,
}

impl<'a> DpopExpectation<'a> {
    /// A token-endpoint expectation: no access token, no nonce.
    pub fn at_token_endpoint(htm: &'a str, htu: &'a str, now: i64) -> Self {
        Self {
            htm,
            htu,
            expected_nonce: None,
            require_nonce: false,
            access_token: None,
            now,
            max_age_secs: DEFAULT_PROOF_MAX_AGE_SECS,
        }
    }

    /// A resource-server expectation: the proof must hash the token it
    /// accompanies.
    pub fn at_resource_server(htm: &'a str, htu: &'a str, access_token: &'a str, now: i64) -> Self {
        Self {
            htm,
            htu,
            expected_nonce: None,
            require_nonce: false,
            access_token: Some(access_token),
            now,
            max_age_secs: DEFAULT_PROOF_MAX_AGE_SECS,
        }
    }
}

/// A proof that verified, and the facts a caller needs from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDpopProof {
    /// RFC 7638 thumbprint of the proof key — the `cnf.jkt` a token issued
    /// against this proof will carry, and the replay scope of [`Self::jti`].
    pub jkt: String,
    /// The proof's unique identifier. The caller records it against `jkt` to
    /// make the proof single-use.
    pub jti: String,
    /// `iat`, so the caller can size the replay row's lifetime to the
    /// freshness window rather than guessing.
    pub iat: i64,
}

impl VerifiedDpopProof {
    /// When a replay row for this proof stops being useful.
    ///
    /// Exactly the end of the freshness window: past it, a replay is refused by
    /// [`DpopError::Stale`] without the table being consulted, so keeping the
    /// row longer costs storage and buys nothing.
    pub fn replay_expiry(&self, max_age_secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(self.iat + max_age_secs, 0)
            .unwrap_or_else(chrono::Utc::now)
    }
}

/// Whether an `Authorization` scheme names DPoP.
///
/// Case-insensitive because RFC 9110 §11.1 makes auth schemes
/// case-insensitive, and a client that sends `dpop` is not making a mistake
/// worth an outage over.
pub fn is_dpop_scheme(scheme: &str) -> bool {
    scheme.eq_ignore_ascii_case(TOKEN_TYPE_DPOP)
}

/// RFC 9449 §4.3 step 9: compare `htu` with query and fragment removed.
///
/// Kept as a plain string operation rather than a URL parse. A parser would
/// normalise — default ports, percent-encoding, case in the host — and every
/// one of those normalisations is a place where two strings that are not equal
/// become equal. The direction of the risk matters: an over-strict comparison
/// fails an onboarding, an over-lenient one accepts a proof minted for a
/// different endpoint.
fn strip_query_and_fragment(uri: &str) -> &str {
    let end = uri.find(['?', '#']).unwrap_or(uri.len());
    &uri[..end]
}

/// A JWK is public if it carries none of the private members RFC 7518 defines.
///
/// Enumerated positively — the members that make a key private — rather than
/// trusting `serde` to have dropped them, because `jsonwebtoken`'s `Jwk` types
/// simply have no fields for `d`, `p`, `q` and friends, so a private key
/// deserializes into a *public* `Jwk` with the private half silently discarded.
/// That is a safe outcome for verification and a terrible one for the client
/// whose key just travelled over the wire, so the check is made against the raw
/// JSON the proof actually carried.
fn contains_private_key_material(raw_header: &serde_json::Value) -> bool {
    const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    raw_header
        .get("jwk")
        .and_then(|j| j.as_object())
        .is_some_and(|o| PRIVATE_MEMBERS.iter().any(|m| o.contains_key(*m)))
}

/// Decode a JWS header as raw JSON, for the checks the typed `Header` cannot
/// make.
fn raw_header_of(proof: &str) -> Result<serde_json::Value, DpopError> {
    use base64::Engine as _;
    let encoded = proof
        .split('.')
        .next()
        .ok_or_else(|| DpopError::Malformed("not a JWT".into()))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| DpopError::Malformed(format!("header is not base64url: {e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| DpopError::Malformed(format!("header is not JSON: {e}")))
}

/// Verify a DPoP proof against what the request actually was (RFC 9449 §4.3).
///
/// Returns the proof's `jkt` and `jti` on success. **The caller must still
/// record the `jti`** — see the module docs on why freshness alone is not
/// replay protection.
pub fn verify_dpop_proof(
    proof: &str,
    expect: &DpopExpectation<'_>,
) -> Result<VerifiedDpopProof, DpopError> {
    // --- header: typ, and the embedded key -------------------------------
    let header =
        decode_header(proof).map_err(|e| DpopError::Malformed(format!("bad JWS header: {e}")))?;

    // RFC 9449 §4.3 step 3. Checked before anything expensive, and before the
    // key is even looked at: a JWT that does not claim to be a proof must not
    // be able to reach the verification path at all, or an access token signed
    // by a client's own key becomes a proof.
    match header.typ.as_deref() {
        Some(t) if t.eq_ignore_ascii_case(DPOP_TYP) => {}
        other => {
            return Err(DpopError::WrongTyp {
                got: other.map(str::to_owned),
            });
        }
    }

    let raw_header = raw_header_of(proof)?;
    if contains_private_key_material(&raw_header) {
        return Err(DpopError::PrivateKeyInProof);
    }

    let jwk: Jwk = header
        .jwk
        .ok_or_else(|| DpopError::Malformed("the proof header carries no jwk".into()))?;

    // Belt and braces on the same property: `AlgorithmParameters::OctetKey` is
    // the one variant that *is* private key material by construction, and it
    // has a typed home in `Jwk` rather than being dropped.
    if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_)) {
        return Err(DpopError::PrivateKeyInProof);
    }

    // The algorithm comes from the key. See `crate::jose`'s module docs.
    let key_alg = jose::algorithm_for_key(&jwk)?;
    let alg = jose::verify_permitted_header(header.alg, key_alg)?;
    let jkt = jose::jwk_thumbprint(&jwk)?;
    let decoding_key: DecodingKey = jose::decoding_key_for(&jwk)?;

    // --- signature and claims --------------------------------------------
    let mut validation = Validation::new(alg);
    // A proof has no audience and no issuer, and its `iat` is checked against
    // this module's own window rather than jsonwebtoken's `exp` machinery —
    // proofs have no `exp` at all. Turning these off is what lets the freshness
    // rule be the one in RFC 9449 rather than the one in RFC 7519.
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let claims = decode::<ProofClaims>(proof, &decoding_key, &validation)
        .map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::InvalidSignature => DpopError::Signature,
            _ => DpopError::Malformed(e.to_string()),
        })?
        .claims;

    // --- freshness --------------------------------------------------------
    if (claims.iat - expect.now).abs() > expect.max_age_secs {
        return Err(DpopError::Stale {
            iat: claims.iat,
            now: expect.now,
        });
    }

    // --- binding to *this* request ---------------------------------------
    if !claims.htm.eq_ignore_ascii_case(expect.htm) {
        return Err(DpopError::MethodMismatch {
            expected: expect.htm.to_owned(),
            got: claims.htm,
        });
    }
    let expected_htu = strip_query_and_fragment(expect.htu);
    let presented_htu = strip_query_and_fragment(&claims.htu);
    if presented_htu != expected_htu {
        return Err(DpopError::UriMismatch {
            expected: expected_htu.to_owned(),
            got: presented_htu.to_owned(),
        });
    }

    // --- nonce (RFC 9449 §4.3 step 11, §8) --------------------------------
    //
    // Two independent conditions, in this order:
    //
    // 1. If the server *requires* a nonce, an absent one is a **challenge**
    //    (`use_dpop_nonce`), not a rejection — the client is expected to retry
    //    with the value the response supplies.
    // 2. If the server *provided* a nonce, the proof must carry that one.
    //
    // A nonce the server never issued, on a request where none is required, is
    // not checked. That is deliberately the RFC's rule rather than a stricter
    // one: the server decides whether the mechanism is in force, so an
    // unsolicited value cannot weaken anything, and refusing it would fail a
    // client that is merely still sending a nonce from a window that has since
    // been turned off.
    if expect.require_nonce && claims.nonce.is_none() {
        return Err(DpopError::NonceRequired);
    }
    if let Some(expected) = expect.expected_nonce
        && claims.nonce.as_deref() != Some(expected)
    {
        return Err(DpopError::NonceMismatch);
    }

    // --- ath --------------------------------------------------------------
    if let Some(token) = expect.access_token {
        let Some(ath) = claims.ath.as_deref() else {
            return Err(DpopError::AccessTokenHashMissing);
        };
        // Constant-time for the same reason the thumbprint comparison in
        // `crate::mtls` is: cheap, and the one scenario where it matters is an
        // attacker holding a stolen token probing what a proof must contain.
        let matches: bool = {
            use subtle::ConstantTimeEq;
            ath.as_bytes()
                .ct_eq(jose::access_token_hash(token).as_bytes())
                .into()
        };
        if !matches {
            return Err(DpopError::AccessTokenHashMismatch);
        }
    }

    if claims.jti.trim().is_empty() {
        return Err(DpopError::Malformed(
            "a DPoP proof must carry a non-empty jti; without one it cannot be made single-use"
                .into(),
        ));
    }

    Ok(VerifiedDpopProof {
        jkt,
        jti: claims.jti,
        iat: claims.iat,
    })
}

/// Mint a `DPoP-Nonce` value.
///
/// Opaque and random, with no structure a client could predict or forge. RFC
/// 9449 §8 leaves the format entirely to the server; what it must be is
/// unguessable, because the whole point is that the client cannot have
/// pre-computed a proof carrying it.
pub fn new_nonce() -> String {
    use base64::Engine as _;
    use rand::RngExt as _;
    let bytes: [u8; 24] = rand::rng().random();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    /// An Ed25519 keypair and the JWK for its public half.
    struct TestKey {
        encoding: EncodingKey,
        jwk: serde_json::Value,
    }

    fn ed25519_key() -> TestKey {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("generate Ed25519");
        let encoding =
            EncodingKey::from_ed_pem(kp.serialize_pem().as_bytes()).expect("encoding key");
        // The raw 32-byte public key sits at the end of the SPKI DER.
        // `public_key_raw` is the SPKI DER; the raw 32-byte Ed25519 public key
        // is its tail.
        let spki = kp.public_key_raw();
        use base64::Engine as _;
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&spki[spki.len() - 32..]);
        TestKey {
            encoding,
            jwk: json!({"kty": "OKP", "crv": "Ed25519", "x": x}),
        }
    }

    /// Sign a proof with an arbitrary header and claim object, so a test can
    /// produce malformed proofs a well-behaved client never would.
    fn sign(key: &TestKey, header: serde_json::Value, claims: serde_json::Value) -> String {
        let header: Header = serde_json::from_value(header).expect("header");
        jsonwebtoken::encode(&header, &claims, &key.encoding).expect("sign proof")
    }

    fn proof_header(key: &TestKey) -> serde_json::Value {
        json!({"typ": DPOP_TYP, "alg": "EdDSA", "jwk": key.jwk})
    }

    fn claims(now: i64) -> serde_json::Value {
        json!({
            "jti": "01HW-unique",
            "htm": "POST",
            "htu": "https://as.example/oauth2/token",
            "iat": now,
        })
    }

    fn expectation(now: i64) -> DpopExpectation<'static> {
        DpopExpectation::at_token_endpoint("POST", "https://as.example/oauth2/token", now)
    }

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn a_well_formed_proof_verifies_and_yields_its_thumbprint() {
        let key = ed25519_key();
        let proof = sign(&key, proof_header(&key), claims(NOW));
        let verified = verify_dpop_proof(&proof, &expectation(NOW)).expect("proof should verify");
        assert_eq!(verified.jti, "01HW-unique");
        assert_eq!(verified.iat, NOW);
        // base64url-unpadded SHA-256 → 43 characters, exactly like x5t#S256.
        assert_eq!(verified.jkt.len(), 43);
        assert!(!verified.jkt.contains('='));
    }

    /// The thumbprint must be stable across proofs from the same key, because
    /// it is what a `cnf.jkt` is compared against on every later request.
    #[test]
    fn the_thumbprint_is_a_property_of_the_key_not_the_proof() {
        let key = ed25519_key();
        let a = sign(&key, proof_header(&key), claims(NOW));
        let b = sign(&key, proof_header(&key), claims(NOW + 1));
        assert_eq!(
            verify_dpop_proof(&a, &expectation(NOW)).unwrap().jkt,
            verify_dpop_proof(&b, &expectation(NOW + 1)).unwrap().jkt
        );

        let other = ed25519_key();
        let c = sign(&other, proof_header(&other), claims(NOW));
        assert_ne!(
            verify_dpop_proof(&a, &expectation(NOW)).unwrap().jkt,
            verify_dpop_proof(&c, &expectation(NOW)).unwrap().jkt
        );
    }

    // -- typ confusion ----------------------------------------------------

    #[test]
    fn a_jwt_that_is_not_typed_as_a_proof_is_refused() {
        let key = ed25519_key();
        for typ in [json!("JWT"), json!("at+jwt"), serde_json::Value::Null] {
            let mut header = proof_header(&key);
            if typ.is_null() {
                header.as_object_mut().unwrap().remove("typ");
            } else {
                header["typ"] = typ;
            }
            let proof = sign(&key, header, claims(NOW));
            assert!(matches!(
                verify_dpop_proof(&proof, &expectation(NOW)),
                Err(DpopError::WrongTyp { .. })
            ));
        }
    }

    // -- algorithm --------------------------------------------------------

    /// The `alg` in the header cannot select a different algorithm from the one
    /// the embedded key implies. This is the check `crate::jose` exists for.
    #[test]
    fn a_header_alg_that_disagrees_with_the_key_is_refused() {
        let key = ed25519_key();
        let mut header = proof_header(&key);
        header["alg"] = json!("ES256");
        // Signing with a header the encoder disagrees with fails outright in
        // jsonwebtoken, so build the proof by hand from the honest signature.
        let honest = sign(&key, proof_header(&key), claims(NOW));
        let mut parts = honest.split('.');
        let (_, payload, signature) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );
        use base64::Engine as _;
        let forged_header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());
        let forged = format!("{forged_header}.{payload}.{signature}");
        assert!(matches!(
            verify_dpop_proof(&forged, &expectation(NOW)),
            Err(DpopError::Key(jose::JoseKeyError::AlgorithmMismatch { .. }))
        ));
    }

    /// A proof whose `jwk` leaks the private half is refused outright.
    ///
    /// The proof has to be assembled by hand: `jsonwebtoken`'s typed `Header`
    /// has no field for `d`, so signing through it would silently drop the very
    /// member under test and the assertion would pass for the wrong reason.
    /// That silent drop is also exactly why `contains_private_key_material`
    /// inspects the **raw** header JSON rather than the parsed `Jwk`.
    #[test]
    fn a_proof_carrying_private_key_material_is_refused() {
        use base64::Engine as _;
        let key = ed25519_key();
        let honest = sign(&key, proof_header(&key), claims(NOW));
        let mut parts = honest.split('.');
        let (_, payload, signature) = (
            parts.next().unwrap(),
            parts.next().unwrap(),
            parts.next().unwrap(),
        );

        let mut header = proof_header(&key);
        header["jwk"]["d"] = json!("cGxlYXNlLWRvLW5vdC1zZW5kLXRoaXM");
        let leaky = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&header).unwrap());

        assert_eq!(
            verify_dpop_proof(&format!("{leaky}.{payload}.{signature}"), &expectation(NOW)),
            Err(DpopError::PrivateKeyInProof)
        );
    }

    #[test]
    fn a_proof_signed_by_a_different_key_than_it_advertises_is_refused() {
        let signer = ed25519_key();
        let advertised = ed25519_key();
        // Header advertises `advertised`'s key; the signature is `signer`'s.
        let header = json!({"typ": DPOP_TYP, "alg": "EdDSA", "jwk": advertised.jwk});
        let proof = sign(&signer, header, claims(NOW));
        assert_eq!(
            verify_dpop_proof(&proof, &expectation(NOW)),
            Err(DpopError::Signature)
        );
    }

    // -- freshness --------------------------------------------------------

    #[test]
    fn a_stale_proof_is_refused_in_both_directions() {
        let key = ed25519_key();
        for skew in [
            -(DEFAULT_PROOF_MAX_AGE_SECS + 1),
            DEFAULT_PROOF_MAX_AGE_SECS + 1,
        ] {
            let proof = sign(&key, proof_header(&key), claims(NOW + skew));
            assert!(
                matches!(
                    verify_dpop_proof(&proof, &expectation(NOW)),
                    Err(DpopError::Stale { .. })
                ),
                "skew {skew} should be refused"
            );
        }
        // ...and the boundary itself is accepted, so a client whose clock is
        // exactly at the edge is not randomly refused.
        for skew in [-DEFAULT_PROOF_MAX_AGE_SECS, DEFAULT_PROOF_MAX_AGE_SECS] {
            let proof = sign(&key, proof_header(&key), claims(NOW + skew));
            assert!(verify_dpop_proof(&proof, &expectation(NOW)).is_ok());
        }
    }

    // -- request binding --------------------------------------------------

    #[test]
    fn a_proof_minted_for_another_method_or_uri_is_refused() {
        let key = ed25519_key();
        let proof = sign(&key, proof_header(&key), claims(NOW));

        let wrong_method =
            DpopExpectation::at_token_endpoint("GET", "https://as.example/oauth2/token", NOW);
        assert!(matches!(
            verify_dpop_proof(&proof, &wrong_method),
            Err(DpopError::MethodMismatch { .. })
        ));

        let wrong_uri =
            DpopExpectation::at_token_endpoint("POST", "https://as.example/oauth2/par", NOW);
        assert!(matches!(
            verify_dpop_proof(&proof, &wrong_uri),
            Err(DpopError::UriMismatch { .. })
        ));
    }

    /// RFC 9449 §4.3 step 9: the comparison ignores query and fragment, so a
    /// client that signed the bare endpoint still matches a request carrying
    /// parameters.
    #[test]
    fn htu_comparison_ignores_query_and_fragment() {
        let key = ed25519_key();
        let proof = sign(&key, proof_header(&key), claims(NOW));
        let with_query = DpopExpectation::at_token_endpoint(
            "POST",
            "https://as.example/oauth2/token?x=1#frag",
            NOW,
        );
        assert!(verify_dpop_proof(&proof, &with_query).is_ok());
    }

    /// ...but it must not ignore anything else. A proof for `/oauth2/token`
    /// must not satisfy a request to `/oauth2/token/../revoke`.
    #[test]
    fn htu_comparison_does_not_normalise_paths() {
        let key = ed25519_key();
        let mut c = claims(NOW);
        c["htu"] = json!("https://as.example/oauth2/token/../revoke");
        let proof = sign(&key, proof_header(&key), c);
        let expect =
            DpopExpectation::at_token_endpoint("POST", "https://as.example/oauth2/revoke", NOW);
        assert!(matches!(
            verify_dpop_proof(&proof, &expect),
            Err(DpopError::UriMismatch { .. })
        ));
    }

    // -- nonce ------------------------------------------------------------

    #[test]
    fn a_required_nonce_that_is_absent_is_a_challenge_not_a_rejection() {
        let key = ed25519_key();
        let proof = sign(&key, proof_header(&key), claims(NOW));
        let mut expect = expectation(NOW);
        expect.require_nonce = true;
        let err = verify_dpop_proof(&proof, &expect).unwrap_err();
        assert_eq!(err, DpopError::NonceRequired);
        assert_eq!(err.error_code(), "use_dpop_nonce");
        assert!(err.is_nonce_challenge());
    }

    #[test]
    fn the_right_nonce_verifies_and_a_stale_one_does_not() {
        let key = ed25519_key();
        let mut c = claims(NOW);
        c["nonce"] = json!("n-1");
        let proof = sign(&key, proof_header(&key), c);

        let mut good = expectation(NOW);
        good.require_nonce = true;
        good.expected_nonce = Some("n-1");
        assert!(verify_dpop_proof(&proof, &good).is_ok());

        let mut stale = expectation(NOW);
        stale.require_nonce = true;
        stale.expected_nonce = Some("n-2");
        assert_eq!(
            verify_dpop_proof(&proof, &stale),
            Err(DpopError::NonceMismatch)
        );
    }

    /// A nonce the server never issued, on a request where none is required, is
    /// not checked (RFC 9449 §4.3 step 11 conditions the check on the server
    /// having provided one). The client cannot weaken anything by sending it —
    /// the server decides whether the mechanism is in force — and refusing it
    /// would fail a client still sending a value from a window since turned
    /// off.
    #[test]
    fn an_unsolicited_nonce_is_ignored_when_none_was_issued() {
        let key = ed25519_key();
        let mut c = claims(NOW);
        c["nonce"] = json!("left over from an earlier window");
        let proof = sign(&key, proof_header(&key), c);
        assert!(verify_dpop_proof(&proof, &expectation(NOW)).is_ok());
    }

    /// ...but the moment the server *has* issued one, the proof must carry that
    /// one. Both the wrong value and no value at all are refused.
    #[test]
    fn once_a_nonce_is_issued_the_proof_must_carry_it() {
        let key = ed25519_key();
        let mut expect = expectation(NOW);
        expect.expected_nonce = Some("n-1");

        let without = sign(&key, proof_header(&key), claims(NOW));
        assert_eq!(
            verify_dpop_proof(&without, &expect),
            Err(DpopError::NonceMismatch)
        );

        let mut c = claims(NOW);
        c["nonce"] = json!("n-0");
        let stale = sign(&key, proof_header(&key), c);
        assert_eq!(
            verify_dpop_proof(&stale, &expect),
            Err(DpopError::NonceMismatch)
        );
    }

    // -- ath --------------------------------------------------------------

    #[test]
    fn a_resource_server_proof_must_hash_the_token_it_accompanies() {
        let key = ed25519_key();
        let token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";

        let mut c = claims(NOW);
        c["htm"] = json!("GET");
        c["htu"] = json!("https://rs.example/resource");
        c["ath"] = json!(jose::access_token_hash(token));
        let proof = sign(&key, proof_header(&key), c.clone());
        let expect =
            DpopExpectation::at_resource_server("GET", "https://rs.example/resource", token, NOW);
        assert!(verify_dpop_proof(&proof, &expect).is_ok());

        // The same proof re-aimed at a different token held by the same key.
        let other = DpopExpectation::at_resource_server(
            "GET",
            "https://rs.example/resource",
            "a-different-token",
            NOW,
        );
        assert_eq!(
            verify_dpop_proof(&proof, &other),
            Err(DpopError::AccessTokenHashMismatch)
        );

        // ...and a proof with no `ath` at all cannot be used with a token.
        c.as_object_mut().unwrap().remove("ath");
        let no_ath = sign(&key, proof_header(&key), c);
        assert_eq!(
            verify_dpop_proof(&no_ath, &expect),
            Err(DpopError::AccessTokenHashMissing)
        );
    }

    // -- jti --------------------------------------------------------------

    #[test]
    fn a_proof_without_a_usable_jti_is_refused() {
        let key = ed25519_key();
        for jti in ["", "   "] {
            let mut c = claims(NOW);
            c["jti"] = json!(jti);
            let proof = sign(&key, proof_header(&key), c);
            assert!(matches!(
                verify_dpop_proof(&proof, &expectation(NOW)),
                Err(DpopError::Malformed(_))
            ));
        }
        // An absent jti fails to deserialize, which is also a refusal.
        let mut c = claims(NOW);
        c.as_object_mut().unwrap().remove("jti");
        let proof = sign(&key, proof_header(&key), c);
        assert!(verify_dpop_proof(&proof, &expectation(NOW)).is_err());
    }

    #[test]
    fn the_replay_row_expires_with_the_freshness_window() {
        let key = ed25519_key();
        let proof = sign(&key, proof_header(&key), claims(NOW));
        let verified = verify_dpop_proof(&proof, &expectation(NOW)).unwrap();
        assert_eq!(
            verified
                .replay_expiry(DEFAULT_PROOF_MAX_AGE_SECS)
                .timestamp(),
            NOW + DEFAULT_PROOF_MAX_AGE_SECS
        );
    }

    // -- miscellany -------------------------------------------------------

    #[test]
    fn nonces_are_unpredictable_and_url_safe() {
        let a = new_nonce();
        let b = new_nonce();
        assert_ne!(a, b);
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
    }

    #[test]
    fn the_dpop_scheme_is_matched_case_insensitively() {
        for s in ["DPoP", "dpop", "DPOP"] {
            assert!(is_dpop_scheme(s));
        }
        assert!(!is_dpop_scheme("Bearer"));
    }

    #[test]
    fn garbage_is_refused_rather_than_panicking() {
        for junk in ["", "not.a.jwt", "a.b", "....."] {
            assert!(verify_dpop_proof(junk, &expectation(NOW)).is_err());
        }
    }
}

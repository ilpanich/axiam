//! The JOSE rules both asymmetric proof-of-possession mechanisms share (X5.1).
//!
//! `private_key_jwt` (RFC 7523 §2.2) and DPoP (RFC 9449) are different
//! protocols solving different problems, but they make the *same* three
//! decisions about a JWT signed by a key AXIAM did not mint:
//!
//! 1. which algorithms are permitted at all,
//! 2. **which key decides the algorithm** — and it is never the header, and
//! 3. how a public key reduces to the `jkt` thumbprint that names it.
//!
//! Those decisions live here once. Two copies would be two chances to fix one
//! and not the other, and the thing being decided is which signatures the
//! server accepts.
//!
//! # `alg` comes from the key, not from the assertion
//!
//! This is the load-bearing rule of the whole module. An attacker who can
//! choose the algorithm a verifier uses does not need to break the signature:
//! the classic failures — `alg: none`, and RSA-public-key-as-HMAC-secret —
//! are both "the token told the verifier how to check the token". So
//! [`algorithm_for_key`] derives the algorithm from the **key material**, and
//! [`verify_permitted_header`] then requires the header to agree with what the
//! key already decided. A header naming anything else is refused rather than
//! honoured.
//!
//! `none` is unreachable twice over: [`jsonwebtoken::Algorithm`] has no such
//! variant, so a proof carrying it fails to parse before any of this runs, and
//! [`PERMITTED_ALGORITHMS`] would not contain it if it did.
//!
//! # Why only three algorithms
//!
//! FAPI 2.0 §5.3.1.1 permits `PS256`, `ES256` and `EdDSA`. AXIAM implements
//! exactly those and refuses the rest — including `RS256`, which is the one an
//! operator is most likely to be surprised by, and which the profile excludes
//! deliberately (PKCS#1 v1.5 padding). A P-384 or P-521 key is likewise
//! refused: it is a perfectly good key, but it is not on the profile's list,
//! and quietly accepting `ES384` here would mean AXIAM's answer to "which
//! algorithms do you accept?" differed from the profile's.

use base64::Engine as _;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash};
use jsonwebtoken::{Algorithm, DecodingKey};
use sha2::{Digest, Sha256};

/// The signature algorithms AXIAM accepts on a client assertion or a DPoP
/// proof (FAPI 2.0 §5.3.1.1).
pub const PERMITTED_ALGORITHMS: [Algorithm; 3] =
    [Algorithm::PS256, Algorithm::ES256, Algorithm::EdDSA];

/// Why a key or a header could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoseKeyError {
    /// The key set contained no key usable under the permitted algorithms.
    NoUsableKey,
    /// A `kid` was named and no registered key carries it.
    UnknownKid { kid: String },
    /// The key's own type or curve is outside the profile.
    UnsupportedKeyType { detail: String },
    /// The header named an algorithm the selected key does not use.
    AlgorithmMismatch { header: Algorithm, key: Algorithm },
    /// The key's own `alg` member disagrees with its key material, or names an
    /// algorithm outside the profile.
    DeclaredAlgorithmMismatch { declared: String, key: Algorithm },
    /// The header named an algorithm outside the profile.
    AlgorithmNotPermitted { header: Algorithm },
    /// The key could not be turned into a verifier.
    Unusable { detail: String },
}

impl std::fmt::Display for JoseKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoUsableKey => write!(
                f,
                "no registered key uses an algorithm this profile permits (PS256, ES256, EdDSA)"
            ),
            Self::UnknownKid { kid } => {
                write!(f, "no registered key carries the key id {kid:?}")
            }
            Self::UnsupportedKeyType { detail } => write!(f, "unsupported key: {detail}"),
            Self::AlgorithmMismatch { header, key } => write!(
                f,
                "the JWS header names {header:?} but the registered key is a {key:?} key; the \
                 algorithm is decided by the key, never by the header"
            ),
            Self::DeclaredAlgorithmMismatch { declared, key } => write!(
                f,
                "the registered key declares alg {declared:?} but its key material is a {key:?} \
                 key; this profile permits PS256, ES256 and EdDSA, and a key that declares \
                 anything else is refused rather than reinterpreted"
            ),
            Self::AlgorithmNotPermitted { header } => write!(
                f,
                "{header:?} is not permitted by this profile (PS256, ES256, EdDSA)"
            ),
            Self::Unusable { detail } => write!(f, "key cannot be used for verification: {detail}"),
        }
    }
}

impl std::error::Error for JoseKeyError {}

/// Whether `alg` is one of the three the profile permits.
pub fn is_permitted(alg: Algorithm) -> bool {
    PERMITTED_ALGORITHMS.contains(&alg)
}

/// The one algorithm this key may be used with.
///
/// Derived from the key material — `kty` and, for the curve families, `crv` —
/// so that the answer does not depend on anything the presenter controls. A
/// `alg` member on the JWK itself is honoured only as a *consistency check*: if
/// the key declares one, it must equal what the material implies. A JWK saying
/// `{"kty":"RSA","alg":"ES256"}` is not a request to verify an RSA signature
/// with ECDSA; it is a malformed key, and it is refused.
pub fn algorithm_for_key(jwk: &Jwk) -> Result<Algorithm, JoseKeyError> {
    let intrinsic = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Algorithm::PS256,
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Algorithm::ES256,
            ref other => {
                return Err(JoseKeyError::UnsupportedKeyType {
                    detail: format!(
                        "EC curve {other:?} is outside this profile, which permits ES256 (P-256) \
                         only"
                    ),
                });
            }
        },
        AlgorithmParameters::OctetKeyPair(okp) => match okp.curve {
            EllipticCurve::Ed25519 => Algorithm::EdDSA,
            ref other => {
                return Err(JoseKeyError::UnsupportedKeyType {
                    detail: format!(
                        "OKP curve {other:?} is outside this profile, which permits EdDSA over \
                         Ed25519 only"
                    ),
                });
            }
        },
        // A symmetric key is not a proof of possession of anything the server
        // does not already hold, and accepting one here is how "verify this
        // RSA public key as an HMAC secret" becomes a signature forgery.
        AlgorithmParameters::OctetKey(_) => {
            return Err(JoseKeyError::UnsupportedKeyType {
                detail: "symmetric (oct) keys cannot authenticate a client asymmetrically".into(),
            });
        }
        // `Other`, and any variant a future jsonwebtoken adds. Both are
        // "a key type this profile does not list", and the catch-all is
        // deliberate: a new key type must arrive as a refusal until somebody
        // decides it belongs, not as a silently accepted credential.
        _ => {
            return Err(JoseKeyError::UnsupportedKeyType {
                detail: "unrecognised key type".into(),
            });
        }
    };

    // A declared `alg` on the key is honoured only as a consistency check.
    // `KeyAlgorithm` covers algorithms `Algorithm` does not (RSA-OAEP and
    // friends), so the comparison is made on the declared value's own terms:
    // anything that is not the intrinsic algorithm's name is a disagreement,
    // whether it is a *different signature* algorithm or not a signature
    // algorithm at all.
    if let Some(declared) = jwk.common.key_algorithm
        && !declares(declared, intrinsic)
    {
        return Err(JoseKeyError::DeclaredAlgorithmMismatch {
            declared: format!("{declared:?}"),
            key: intrinsic,
        });
    }

    Ok(intrinsic)
}

/// Whether a JWK's declared `alg` member names `expected`.
///
/// Compared by name rather than by converting `KeyAlgorithm` into `Algorithm`:
/// the conversion is private to `jsonwebtoken`, and more importantly it is
/// partial — `RSA-OAEP` has no `Algorithm` — so a key declaring an encryption
/// algorithm would otherwise fall through the check it is most important not to
/// fall through.
fn declares(declared: jsonwebtoken::jwk::KeyAlgorithm, expected: Algorithm) -> bool {
    use jsonwebtoken::jwk::KeyAlgorithm;
    matches!(
        (declared, expected),
        (KeyAlgorithm::PS256, Algorithm::PS256)
            | (KeyAlgorithm::ES256, Algorithm::ES256)
            | (KeyAlgorithm::EdDSA, Algorithm::EdDSA)
    )
}

/// Check a JWS header against the algorithm the key already decided.
///
/// Returns the algorithm to verify with — always the key's, never the
/// header's. The header is only ever an assertion to be *contradicted*.
pub fn verify_permitted_header(
    header_alg: Algorithm,
    key_alg: Algorithm,
) -> Result<Algorithm, JoseKeyError> {
    if !is_permitted(key_alg) {
        return Err(JoseKeyError::AlgorithmNotPermitted { header: key_alg });
    }
    if !is_permitted(header_alg) {
        return Err(JoseKeyError::AlgorithmNotPermitted { header: header_alg });
    }
    if header_alg != key_alg {
        return Err(JoseKeyError::AlgorithmMismatch {
            header: header_alg,
            key: key_alg,
        });
    }
    Ok(key_alg)
}

/// Build a verifier from a public JWK.
pub fn decoding_key_for(jwk: &Jwk) -> Result<DecodingKey, JoseKeyError> {
    DecodingKey::from_jwk(jwk).map_err(|e| JoseKeyError::Unusable {
        detail: e.to_string(),
    })
}

/// RFC 7638 JWK thumbprint, SHA-256, base64url-unpadded — the `jkt` of
/// RFC 9449 §6.1 and the `cnf.jkt` of §6.
///
/// Delegated to `jsonwebtoken`'s implementation rather than hand-rolled: the
/// canonicalisation (required members only, lexicographic order, no
/// whitespace) is the entire security property, and a second implementation of
/// it would be a second chance to canonicalise differently from every other
/// participant — which shows up as a `jkt` that never matches, or worse, one
/// that matches a key it should not.
pub fn jwk_thumbprint(jwk: &Jwk) -> Result<String, JoseKeyError> {
    jwk.thumbprint(ThumbprintHash::SHA256)
        .map_err(|e| JoseKeyError::Unusable {
            detail: format!("cannot compute a JWK thumbprint: {e}"),
        })
}

/// RFC 9449 §4.2 `ath`: base64url-unpadded SHA-256 of the access token's
/// ASCII form.
///
/// Unpadded for the same reason `x5t#S256` is: the value travels in a JWT
/// claim, and RFC 7515 §2 defines JOSE base64url as omitting the padding. A
/// padded value would not compare equal at a conforming peer.
pub fn access_token_hash(access_token: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()))
}

/// Select the key a JWS was signed with from a registered key set.
///
/// `kid` is honoured when the header carries one, because that is what a `kid`
/// is for and because a client rotating keys publishes both. When the header
/// carries none, every key in the set is a candidate — which is correct and
/// not a weakening: each candidate is a key the *client registered*, so
/// verifying against all of them proves possession of one of them, which is
/// exactly the claim being made.
///
/// Keys the profile cannot use are skipped rather than failing the whole set. A
/// client that publishes one Ed25519 key and one P-521 key has published one
/// key AXIAM can use, and refusing the set would make an unrelated key an
/// outage.
pub fn candidate_keys<'a>(
    keys: &'a [Jwk],
    kid: Option<&str>,
) -> Result<Vec<(&'a Jwk, Algorithm)>, JoseKeyError> {
    let scoped: Vec<&Jwk> = match kid {
        Some(kid) => {
            let matched: Vec<&Jwk> = keys
                .iter()
                .filter(|k| k.common.key_id.as_deref() == Some(kid))
                .collect();
            if matched.is_empty() {
                return Err(JoseKeyError::UnknownKid {
                    kid: kid.to_owned(),
                });
            }
            matched
        }
        None => keys.iter().collect(),
    };

    let usable: Vec<(&Jwk, Algorithm)> = scoped
        .into_iter()
        .filter_map(|k| algorithm_for_key(k).ok().map(|alg| (k, alg)))
        .collect();

    if usable.is_empty() {
        return Err(JoseKeyError::NoUsableKey);
    }
    Ok(usable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::JwkSet;

    /// The RFC 7638 §3.1 worked example, verbatim. If this thumbprint ever
    /// changes, every `cnf.jkt` AXIAM has ever issued is wrong.
    const RFC7638_KEY: &str = r#"{
      "kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e":"AQAB",
      "alg":"RS256",
      "kid":"2011-04-29"
    }"#;

    fn jwk(json: &str) -> Jwk {
        serde_json::from_str(json).expect("parse test JWK")
    }

    #[test]
    fn rfc7638_thumbprint_matches_the_published_vector() {
        let key = jwk(RFC7638_KEY);
        assert_eq!(
            jwk_thumbprint(&key).unwrap(),
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        );
    }

    /// An RSA key is a PS256 key here, whatever it says. RFC 7638's example
    /// declares `RS256`, which this profile does not permit — so the key is
    /// refused rather than downgraded to a permitted algorithm it did not ask
    /// for.
    #[test]
    fn rs256_is_refused_rather_than_reinterpreted() {
        let key = jwk(RFC7638_KEY);
        assert!(matches!(
            algorithm_for_key(&key),
            Err(JoseKeyError::DeclaredAlgorithmMismatch { .. })
        ));
    }

    #[test]
    fn an_undeclared_rsa_key_is_a_ps256_key() {
        let key = jwk(
            r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#,
        );
        assert_eq!(algorithm_for_key(&key).unwrap(), Algorithm::PS256);
    }

    #[test]
    fn p256_is_es256_and_ed25519_is_eddsa() {
        let ec = jwk(
            r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#,
        );
        assert_eq!(algorithm_for_key(&ec).unwrap(), Algorithm::ES256);

        let okp = jwk(
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        );
        assert_eq!(algorithm_for_key(&okp).unwrap(), Algorithm::EdDSA);
    }

    /// A perfectly good key that the profile does not list. Refused, not
    /// promoted to ES384.
    #[test]
    fn a_p384_key_is_outside_the_profile() {
        let key = jwk(
            r#"{"kty":"EC","crv":"P-384","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        );
        assert!(matches!(
            algorithm_for_key(&key),
            Err(JoseKeyError::UnsupportedKeyType { .. })
        ));
    }

    /// The header does not get to pick. This is the whole point of the module.
    #[test]
    fn a_header_that_disagrees_with_the_key_is_refused() {
        assert_eq!(
            verify_permitted_header(Algorithm::ES256, Algorithm::EdDSA),
            Err(JoseKeyError::AlgorithmMismatch {
                header: Algorithm::ES256,
                key: Algorithm::EdDSA
            })
        );
        assert_eq!(
            verify_permitted_header(Algorithm::RS256, Algorithm::PS256),
            Err(JoseKeyError::AlgorithmNotPermitted {
                header: Algorithm::RS256
            })
        );
        assert_eq!(
            verify_permitted_header(Algorithm::EdDSA, Algorithm::EdDSA),
            Ok(Algorithm::EdDSA)
        );
    }

    #[test]
    fn hmac_algorithms_are_not_permitted() {
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            assert!(!is_permitted(alg), "{alg:?} must not be permitted");
        }
        let oct = jwk(r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr8"}"#);
        assert!(matches!(
            algorithm_for_key(&oct),
            Err(JoseKeyError::UnsupportedKeyType { .. })
        ));
    }

    /// A key set mixing a usable key with one outside the profile yields the
    /// usable one, rather than failing because of a key nobody was asking to
    /// use.
    #[test]
    fn unusable_keys_are_skipped_not_fatal() {
        let set: JwkSet = serde_json::from_str(
            r#"{"keys":[
                {"kty":"EC","crv":"P-521","x":"AA","y":"AA","kid":"old"},
                {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"new"}
            ]}"#,
        )
        .unwrap();
        let candidates = candidate_keys(&set.keys, None).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].1, Algorithm::EdDSA);
    }

    #[test]
    fn a_named_kid_that_is_absent_is_an_error_not_a_fallback_to_every_key() {
        let set: JwkSet = serde_json::from_str(
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"new"}]}"#,
        )
        .unwrap();
        assert_eq!(
            candidate_keys(&set.keys, Some("missing")),
            Err(JoseKeyError::UnknownKid {
                kid: "missing".into()
            })
        );
    }

    /// RFC 9449 §4.2's worked `ath` example.
    #[test]
    fn ath_matches_the_rfc_9449_vector() {
        assert_eq!(
            access_token_hash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"),
            "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
        );
    }
}

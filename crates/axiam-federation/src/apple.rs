//! Sign in with Apple's client secret.
//!
//! Apple's `client_secret` is not a string an operator pastes once. It is an
//! ES256-signed JWT with `iss` = Team ID, `sub` = Services ID (the `client_id`),
//! `aud` = `https://appleid.apple.com`, and `exp` at most 15 777 000 seconds
//! (six months) after `iat`, signed with a `.p8` key whose 10-character Key ID
//! goes in the JOSE header `kid`.
//!
//! # Why AXIAM mints it rather than storing it
//!
//! *A secret that silently expires in six months is an outage nobody diagnoses
//! quickly.* It lapses on a Tuesday, "Sign in with Apple" starts answering
//! `invalid_client`, and the person who generated it left. Minting a fresh
//! five-minute JWT per token exchange removes the failure mode rather than
//! scheduling a warning about it.
//!
//! What the operator stores is the `.p8` private key, in the existing
//! `client_secret_ciphertext` / `client_secret_nonce` /
//! `client_secret_key_version` columns — it *is* the secret, so it gets the
//! AES-256-GCM-at-rest treatment SEC-045 already provides, unchanged. The Team
//! ID and Key ID are not secret and live in their own plain columns.
//!
//! A config with no `apple_team_id`/`apple_key_id` keeps the stored secret and
//! sends it verbatim, which is the escape hatch for an operator who prefers to
//! manage the JWT themselves.
//!
//! # Why the signature is `ring`'s and not `jsonwebtoken`'s
//!
//! This is the one place AXIAM performs an ECDSA *secret-key* operation, and an
//! unauthenticated caller can make it happen: every OIDC callback for an Apple
//! config mints a secret before the code exchange. `jsonwebtoken`'s
//! `rust_crypto` backend signs ES256 with `p256` 0.13, whose scalar arithmetic
//! (`add_mod`, `sub_mod`, `sbb`, `mul_wide`) is `crypto-bigint` 0.5.5 —
//! RUSTSEC-2026-0387, timing variability in operations meant to be constant
//! time, fixed only in 0.7.6, which no `p256` 0.13 release can take. So the JWS
//! is assembled here and signed by `ring`'s P-256 (already the TLS stack's
//! provider), which owes nothing to `crypto-bigint`. The advisory's `deny.toml`
//! entry rests on this: do not route this signature back through
//! `jsonwebtoken::encode`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use jsonwebtoken::{Algorithm, Header};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::FederationError;

/// The audience Apple requires on the client secret.
pub const APPLE_AUDIENCE: &str = "https://appleid.apple.com";

/// Lifetime of a minted client secret.
///
/// Apple's ceiling is six months. Five minutes is used instead because the JWT
/// is consumed by exactly one token exchange, seconds after it is minted, and a
/// credential's lifetime should match its job rather than its permitted
/// maximum. Clock skew between AXIAM and Apple is the only reason it is not
/// shorter still.
pub const CLIENT_SECRET_TTL_SECS: i64 = 300;

/// Apple's Team and Key identifiers are both exactly ten characters.
const APPLE_ID_LEN: usize = 10;

#[derive(Debug, Serialize)]
struct AppleClientSecretClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
    aud: &'a str,
    sub: &'a str,
}

/// Validate an Apple Team ID or Key ID.
///
/// Ten alphanumerics. Checked at config-write time so an operator
/// learns about a mistyped identifier while they are looking at the form,
/// rather than from an `invalid_client` at the first sign-in attempt.
pub fn validate_apple_identifier(kind: &str, value: &str) -> Result<(), String> {
    if value.len() != APPLE_ID_LEN || !value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(format!(
            "{kind} must be Apple's 10-character alphanumeric identifier"
        ));
    }
    Ok(())
}

/// Mint an Apple client secret.
///
/// `private_key_pem` is the contents of the `.p8` file Apple issues — a PKCS#8
/// `PRIVATE KEY` PEM over the P-256 curve.
pub fn mint_client_secret(
    team_id: &str,
    key_id: &str,
    client_id: &str,
    private_key_pem: &str,
) -> Result<String, FederationError> {
    validate_apple_identifier("apple_team_id", team_id).map_err(FederationError::ConfigInvalid)?;
    validate_apple_identifier("apple_key_id", key_id).map_err(FederationError::ConfigInvalid)?;

    let now = Utc::now().timestamp();
    let claims = AppleClientSecretClaims {
        iss: team_id,
        iat: now,
        exp: now + CLIENT_SECRET_TTL_SECS,
        aud: APPLE_AUDIENCE,
        sub: client_id,
    };

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.to_string());

    let signing_input = format!(
        "{}.{}",
        b64_json(&header, "header")?,
        b64_json(&claims, "claims")?
    );
    let signature = sign_es256(signing_input.as_bytes(), private_key_pem)?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn b64_json<T: Serialize>(part: &T, what: &str) -> Result<String, FederationError> {
    let json = serde_json::to_vec(part).map_err(|e| {
        FederationError::ConfigInvalid(format!(
            "failed to encode the Apple client secret {what}: {e}"
        ))
    })?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

/// ES256 over `message` with the `.p8` key, as the JWS `r || s` octets.
///
/// Only PKCS#8 (`PRIVATE KEY`) is accepted — what Apple issues. A wrong key
/// type fails here rather than producing a JWT Apple rejects for reasons the
/// operator cannot see.
fn sign_es256(message: &[u8], private_key_pem: &str) -> Result<Vec<u8>, FederationError> {
    let unusable = |why: String| {
        FederationError::ConfigInvalid(format!(
            "the Apple signing key is not a usable EC private key: {why}"
        ))
    };
    let pem = ::pem::parse(private_key_pem).map_err(|e| unusable(e.to_string()))?;
    if pem.tag() != "PRIVATE KEY" {
        return Err(unusable(format!(
            "expected a PKCS#8 PRIVATE KEY PEM (Apple's .p8), got {}",
            pem.tag()
        )));
    }
    let der = Zeroizing::new(pem.into_contents());

    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng)
        .map_err(|e| unusable(e.to_string()))?;
    let signature = key.sign(&rng, message).map_err(|_| {
        FederationError::ConfigInvalid("failed to sign the Apple client secret".into())
    })?;
    Ok(signature.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation, decode, decode_header};

    /// A throwaway P-256 keypair, PKCS#8 PEM for signing and SPKI PEM for
    /// verification — the same shape Apple's `.p8` has.
    fn ec_keypair() -> (String, String) {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        (key.serialize_pem(), key.public_key_pem())
    }

    #[test]
    fn a_minted_secret_carries_exactly_the_claims_apple_requires() {
        let (private_pem, public_pem) = ec_keypair();
        let token = mint_client_secret("ABCDE12345", "KEYID67890", "com.example.svc", &private_pem)
            .expect("minting must succeed");

        // The kid header is how Apple finds the key; without it the JWT is
        // unverifiable and the failure is a bare invalid_client.
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEYID67890"));

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[APPLE_AUDIENCE]);
        validation.set_issuer(&["ABCDE12345"]);
        let key = DecodingKey::from_ec_pem(public_pem.as_bytes()).expect("verification key");
        let data =
            decode::<serde_json::Value>(&token, &key, &validation).expect("signature must verify");

        assert_eq!(data.claims["iss"], "ABCDE12345");
        assert_eq!(data.claims["sub"], "com.example.svc");
        assert_eq!(data.claims["aud"], APPLE_AUDIENCE);

        let iat = data.claims["iat"].as_i64().unwrap();
        let exp = data.claims["exp"].as_i64().unwrap();
        assert_eq!(exp - iat, CLIENT_SECRET_TTL_SECS);
        // The point of minting per exchange: nowhere near Apple's six-month
        // ceiling, so there is no expiry for an operator to be surprised by.
        assert!(exp - iat < 15_777_000);
    }

    /// The property that makes storing the JWT unnecessary: every call stamps
    /// the current time, so the secret in flight is always minutes old.
    ///
    /// Deliberately not `assert_ne!(a, b)` on two same-second mints: token
    /// inequality would be asserting the signature backend (see
    /// `the_signature_is_rings_not_rust_cryptos`) rather than the freshness
    /// this test is about.
    #[test]
    fn each_mint_stamps_the_current_time() {
        let (private_pem, public_pem) = ec_keypair();
        let before = Utc::now().timestamp();
        let token = mint_client_secret("ABCDE12345", "KEYID67890", "svc", &private_pem).unwrap();
        let after = Utc::now().timestamp();

        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[APPLE_AUDIENCE]);
        validation.set_issuer(&["ABCDE12345"]);
        let key = DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap();
        let data = decode::<serde_json::Value>(&token, &key, &validation).unwrap();

        let iat = data.claims["iat"].as_i64().unwrap();
        assert!(
            (before..=after).contains(&iat),
            "iat {iat} must be minted now, not read from storage"
        );
    }

    #[test]
    fn a_mistyped_identifier_is_refused_at_the_form_not_at_the_idp() {
        let (private_pem, _) = ec_keypair();
        for (team, key) in [
            ("SHORT", "KEYID67890"),
            ("ABCDE12345", "SHORT"),
            ("ABCDE-2345", "KEYID67890"),
            ("", ""),
        ] {
            assert!(
                mint_client_secret(team, key, "svc", &private_pem).is_err(),
                "({team}, {key}) must be refused"
            );
        }
    }

    #[test]
    fn a_key_that_is_not_an_ec_private_key_fails_here() {
        let err =
            mint_client_secret("ABCDE12345", "KEYID67890", "svc", "not a pem at all").unwrap_err();
        assert!(
            err.to_string().contains("EC private key"),
            "the message must point at the key, not at Apple: {err}"
        );
    }

    /// Pins the RUSTSEC-2026-0387 mitigation. `jsonwebtoken`'s `rust_crypto`
    /// backend (`p256` on `crypto-bigint` 0.5.5) signs ES256 deterministically
    /// per RFC 6979, so the same message under the same key always yields the
    /// same bytes; `ring` mixes fresh randomness into every nonce. Two distinct
    /// signatures that both verify therefore show the secret key is not being
    /// handled by the affected backend.
    #[test]
    fn the_signature_is_rings_not_rust_cryptos() {
        let (private_pem, public_pem) = ec_keypair();
        let split = |t: &str| {
            let (input, sig) = t.rsplit_once('.').unwrap();
            (input.to_string(), sig.to_string())
        };
        // Two mints in the same second carry identical header and claims; retry
        // on the rare pair that straddles a second boundary.
        let (a, b) = (0..5)
            .map(|_| {
                let mint =
                    || mint_client_secret("ABCDE12345", "KEYID67890", "svc", &private_pem).unwrap();
                (mint(), mint())
            })
            .find(|(a, b)| split(a).0 == split(b).0)
            .expect("two mints within one second");
        assert_ne!(
            split(&a).1,
            split(&b).1,
            "a deterministic (RFC 6979) signer is back on this path"
        );

        let key = DecodingKey::from_ec_pem(public_pem.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_audience(&[APPLE_AUDIENCE]);
        validation.set_issuer(&["ABCDE12345"]);
        for token in [a, b] {
            decode::<serde_json::Value>(&token, &key, &validation).expect("must verify");
        }
    }

    #[test]
    fn a_sec1_key_is_refused_with_a_message_naming_pkcs8() {
        let sec1 = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
        let err = mint_client_secret("ABCDE12345", "KEYID67890", "svc", sec1).unwrap_err();
        assert!(err.to_string().contains("PKCS#8"), "{err}");
    }
}

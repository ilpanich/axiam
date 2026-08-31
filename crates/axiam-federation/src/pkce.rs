//! PKCE (RFC 7636) for the outbound federation flows.
//!
//! AXIAM is the *relying party* here, so this is PKCE from the client side: a
//! high-entropy verifier generated at authorize time, its `S256` challenge sent
//! to the IdP, and the verifier itself echoed at the token exchange.
//!
//! # Where it is mandatory, and why
//!
//! On the [`OAuth2`](axiam_core::models::federation::FederationProtocol::OAuth2)
//! variant it is not optional. That path has no ID token, so it has no `nonce`,
//! no `aud` and no signature — PKCE is the only thing left that binds the
//! authorization code to the browser session that started the flow.
//!
//! The honest caveat, stated here because it is easy to mistake sending PKCE
//! for having PKCE: a provider that *ignores* `code_challenge` gives us nothing
//! for it, and we cannot make a remote server verify something. GitHub has
//! supported `S256` since July 2025. Where a provider does not, the residual
//! protections are the single-use 256-bit server-side `state` and the
//! confidential-client secret at the token endpoint, and that is what an
//! operator is relying on.
//!
//! On the OIDC path PKCE is opt-in (`require_pkce`), because a server-side
//! `nonce` the client never sees already provides the binding, and because
//! making it mandatory would break every config written before the column
//! existed.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

/// Length in bytes of the random material behind a verifier.
///
/// 32 bytes → 43 base64url characters, the RFC 7636 §4.1 minimum, and the
/// length every major provider is tested against. The RFC permits up to 128
/// characters; more entropy than 256 bits buys nothing here.
const VERIFIER_BYTES: usize = 32;

/// A PKCE verifier and the challenge derived from it.
///
/// They are produced together and never separately: a challenge without its
/// verifier cannot complete a flow, and a verifier whose challenge was computed
/// somewhere else is how the two drift apart.
#[derive(Debug, Clone)]
pub struct PkcePair {
    /// The secret. Stored server-side in `federation_login_state` and echoed at
    /// the token endpoint. It must never reach the browser.
    pub verifier: String,
    /// `BASE64URL(SHA256(verifier))`, sent to the IdP as `code_challenge`.
    pub challenge: String,
}

/// The only challenge method AXIAM sends.
///
/// `plain` is deliberately absent. RFC 7636 §7.2 permits it and it protects
/// against nothing an attacker who can read the authorization request cannot
/// defeat, which is exactly the attacker PKCE exists for. Every provider AXIAM
/// federates to supports `S256`.
pub const CHALLENGE_METHOD: &str = "S256";

/// Generate a fresh verifier and its `S256` challenge.
pub fn generate() -> PkcePair {
    use rand::Rng;
    let mut bytes = [0u8; VERIFIER_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = challenge_for(&verifier);
    PkcePair {
        verifier,
        challenge,
    }
}

/// Derive the `S256` challenge for a verifier.
///
/// Split out so a test can pin the RFC 7636 Appendix B vector against the same
/// function the flow uses, rather than against a second copy of it.
pub fn challenge_for(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7636 Appendix B, verbatim. The one test that proves this is PKCE
    /// and not merely a hash of a random string.
    #[test]
    fn the_rfc_7636_appendix_b_vector_holds() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn a_verifier_meets_the_rfc_length_floor_and_is_url_safe() {
        let p = generate();
        // RFC 7636 §4.1: 43..=128 characters, from the unreserved set.
        assert!(
            (43..=128).contains(&p.verifier.len()),
            "{}",
            p.verifier.len()
        );
        assert!(
            p.verifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)),
            "verifier must be URL-safe without escaping: {}",
            p.verifier
        );
    }

    #[test]
    fn each_pair_is_fresh_and_internally_consistent() {
        let a = generate();
        let b = generate();
        assert_ne!(a.verifier, b.verifier, "verifiers must not repeat");
        assert_ne!(a.challenge, b.challenge);
        // The property that makes the pair usable at all.
        assert_eq!(challenge_for(&a.verifier), a.challenge);
    }

    /// The challenge must not be reversible to the verifier by construction —
    /// restated as the property that actually matters: they are different
    /// values, and only the verifier is ever stored as the secret.
    #[test]
    fn the_challenge_is_not_the_verifier() {
        let p = generate();
        assert_ne!(p.verifier, p.challenge);
    }
}

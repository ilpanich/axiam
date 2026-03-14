//! PKCE (Proof Key for Code Exchange) verification per RFC 7636.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Verify a PKCE code verifier against a stored code challenge (S256).
///
/// Validates the verifier format per RFC 7636 §4.1 (43–128 chars from
/// `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`) and uses
/// constant-time comparison to prevent timing side-channels.
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> bool {
    // RFC 7636 §4.1: code_verifier must be 43–128 characters
    if !(43..=128).contains(&code_verifier.len()) {
        return false;
    }

    // RFC 7636 §4.1: restricted character set
    let valid_chars = code_verifier
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_' || b == b'~');
    if !valid_chars {
        return false;
    }

    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let computed = URL_SAFE_NO_PAD.encode(hasher.finalize());

    // Constant-time comparison to prevent timing attacks
    computed.as_bytes().ct_eq(code_challenge.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_rfc7636_example() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(verify_pkce(verifier, challenge));
    }

    #[test]
    fn pkce_s256_mismatch() {
        // Use a verifier that meets the 43-char minimum
        let verifier = "wrong-verifier-padded-to-forty-three-chars1";
        assert!(!verify_pkce(
            verifier,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn pkce_s256_roundtrip() {
        let verifier = "my-custom-code-verifier-12345-padded-to-min";
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert!(verify_pkce(verifier, &challenge));
    }

    #[test]
    fn pkce_rejects_short_verifier() {
        assert!(!verify_pkce("too-short", "anything"));
    }

    #[test]
    fn pkce_rejects_long_verifier() {
        let long = "a".repeat(129);
        assert!(!verify_pkce(&long, "anything"));
    }

    #[test]
    fn pkce_rejects_invalid_chars() {
        // Space is not in the allowed set
        let verifier = "has spaces in it padded to forty three char";
        assert!(!verify_pkce(verifier, "anything"));
    }
}

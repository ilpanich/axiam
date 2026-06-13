//! PEM ↔ DER conversion helpers and X.509 certificate validation.
//!
//! Used by the SAML ACS handler to convert the stored IdP signing certificate
//! from PEM (admin-friendly) to DER (required by `samael::crypto::verify_signed_xml`).
//! Also called at federation config create/update time to reject garbage PEMs early.

use crate::error::FederationError;

/// Decode a PEM-encoded X.509 certificate to raw DER bytes.
///
/// Uses the `pem` crate's parser to correctly handle multi-block PEM files,
/// line endings, and label validation (must be `CERTIFICATE`).
///
/// Returns `Err(FederationError::InvalidIdpCert)` on any decode failure.
pub fn pem_cert_to_der(pem_str: &str) -> Result<Vec<u8>, FederationError> {
    let parsed = ::pem::parse(pem_str)
        .map_err(|e| FederationError::InvalidIdpCert(format!("PEM parse failed: {e}")))?;

    if parsed.tag() != "CERTIFICATE" {
        return Err(FederationError::InvalidIdpCert(format!(
            "expected PEM label CERTIFICATE, got {}",
            parsed.tag()
        )));
    }

    Ok(parsed.contents().to_vec())
}

/// Validate that a PEM string contains a syntactically valid X.509 certificate.
///
/// Calls [`pem_cert_to_der`] then parses the DER bytes with `x509_parser`.
/// Returns `Err(FederationError::InvalidIdpCert)` if the PEM is not a valid certificate.
///
/// Call this at admin federation-config create/update time so garbage PEMs are
/// rejected at upload rather than at assertion-verification time.
pub fn validate_pem_cert(pem: &str) -> Result<(), FederationError> {
    let der = pem_cert_to_der(pem)?;
    x509_parser::parse_x509_certificate(&der)
        .map_err(|e| FederationError::InvalidIdpCert(format!("x509 parse failed: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal self-signed test certificate (generated with rcgen for test use only).
    /// This is a CERTIFICATE PEM; it is a test vector only — the private key is not
    /// present and never used in production.
    ///
    /// Generated via:
    ///   rcgen::generate_simple_self_signed(["test.local".to_string()]).unwrap()
    fn test_cert_pem() -> String {
        // A real DER-encoded certificate in PEM wrapper so x509_parser can parse it.
        // We generate one at test time using rcgen.
        use rcgen::generate_simple_self_signed;
        let cert = generate_simple_self_signed(vec!["test.local".to_string()]).unwrap();
        cert.cert.pem()
    }

    #[test]
    fn valid_pem_round_trip() {
        let pem = test_cert_pem();
        let der = pem_cert_to_der(&pem).expect("should decode");
        assert!(!der.is_empty());
        // Should parse cleanly as an x509 certificate.
        x509_parser::parse_x509_certificate(&der).expect("should be valid x509");
    }

    #[test]
    fn garbage_pem_rejected() {
        let err = pem_cert_to_der("not a pem").expect_err("should fail");
        assert!(
            matches!(err, FederationError::InvalidIdpCert(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn non_cert_pem_rejected() {
        use base64::Engine;
        // Valid base64 of random bytes — not a certificate.
        let fake_pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
            base64::engine::general_purpose::STANDARD.encode(b"this is not a certificate at all")
        );
        let err = validate_pem_cert(&fake_pem).expect_err("random bytes are not a certificate");
        assert!(
            matches!(err, FederationError::InvalidIdpCert(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn validate_pem_cert_accepts_valid() {
        let pem = test_cert_pem();
        validate_pem_cert(&pem).expect("valid cert should pass validate_pem_cert");
    }
}

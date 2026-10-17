//! Certificate serial numbers: how AXIAM mints one, and how it spells one
//! it stores (#653).
//!
//! # Why AXIAM sets the serial itself
//!
//! Left unset, rcgen 0.14 writes the first 20 bytes of SHA-256 over the subject
//! public key (`rcgen-0.14.10/src/certificate.rs:458-472`). The serial is then a
//! function of the key alone, so two certificates one CA issues on the same key
//! — a CSR signed twice, a re-issue on a retained key — carry the same serial.
//! RFC 5280 §4.1.2.2 requires the serial to be unique per certificate the CA
//! issues, and a CRL entry names a serial, so revoking one of the two revoked
//! both on every relying party's list.
//!
//! [`random_serial`] is the one place a serial is minted. Every issuance that
//! signs locally (a generated leaf, a CSR-signed leaf, a root CA, an
//! intermediate CA) reads it. Certificates signed by Vault's PKI engine carry
//! the serial Vault chose, which is random in the same way.
//!
//! # The stored spelling
//!
//! [`certificate_serial_hex`] is lower-case hex of the serial's big-endian
//! magnitude, no separators, no sign byte — the bytes
//! `crl::list_identity` puts in a CRL entry
//! (`cert.serial.to_bytes_be()`), so a value in the database and an entry on the
//! list for the same certificate are the same string once the list's bytes are
//! hex-encoded. (Vault's own spelling, `aa:bb:…`, is [`crate::cert`]'s
//! `serial_hex`; it is for Vault's API and is not stored.)

use rand_core::{OsRng, RngCore};
use rcgen::SerialNumber;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

/// The length of a serial AXIAM issues: the 20 octets RFC 5280 §4.1.2.2 allows.
pub const SERIAL_LEN: usize = 20;

/// The bytes of a fresh serial: [`SERIAL_LEN`] octets from the operating
/// system's CSPRNG, the top bit cleared so the DER INTEGER is positive and stays
/// within 20 octets without a sign byte, and never all zero (zero is not a
/// positive integer).
#[must_use]
pub(crate) fn random_serial_bytes() -> [u8; SERIAL_LEN] {
    loop {
        let mut bytes = [0u8; SERIAL_LEN];
        OsRng.fill_bytes(&mut bytes);
        bytes[0] &= 0x7f;
        if bytes.iter().any(|b| *b != 0) {
            return bytes;
        }
    }
}

/// A fresh serial for `CertificateParams::serial_number`.
#[must_use]
pub(crate) fn random_serial() -> SerialNumber {
    SerialNumber::from_slice(&random_serial_bytes())
}

/// The serial of a PEM certificate, as lower-case hex of its big-endian
/// magnitude; `None` when the text is not a certificate that parses.
///
/// The stored column is `option<string>`: a row whose certificate cannot be
/// read (a fixture, or a value written before this column existed) carries no
/// serial and is not indexed by it.
#[must_use]
pub fn certificate_serial_hex(public_cert_pem: &str) -> Option<String> {
    let (_, block) = x509_parser::pem::parse_x509_pem(public_cert_pem.as_bytes()).ok()?;
    let (_, cert) = X509Certificate::from_der(&block.contents).ok()?;
    Some(hex::encode(cert.serial.to_bytes_be()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, KeyPair};

    /// #653 — at most 20 octets, positive (top bit clear), non-zero.
    #[test]
    fn a_serial_is_twenty_octets_positive_and_non_zero() {
        for _ in 0..256 {
            let bytes = random_serial_bytes();
            assert_eq!(bytes.len(), SERIAL_LEN);
            assert!(bytes.len() <= 20, "RFC 5280 §4.1.2.2: at most 20 octets");
            assert_eq!(bytes[0] & 0x80, 0, "the top bit must be clear");
            assert!(bytes.iter().any(|b| *b != 0), "zero is not positive");
        }
    }

    /// Two draws differ (2^-159 chance of a false failure), and the draw is not
    /// a function of anything the caller holds.
    #[test]
    fn two_serials_differ() {
        assert_ne!(random_serial_bytes(), random_serial_bytes());
    }

    /// The stored spelling is the certificate's serial as written, in the form
    /// the CRL encodes.
    #[test]
    fn the_stored_spelling_is_the_serial_the_certificate_carries() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, "serial");
        let bytes = random_serial_bytes();
        params.serial_number = Some(SerialNumber::from_slice(&bytes));
        let cert = params.self_signed(&key).unwrap();

        let (_, parsed) = X509Certificate::from_der(cert.der()).unwrap();
        let magnitude = parsed.serial.to_bytes_be();
        assert_eq!(
            certificate_serial_hex(&cert.pem()).as_deref(),
            Some(hex::encode(&magnitude).as_str())
        );
        // No leading zero octet is added or lost beyond the integer's own
        // minimal encoding.
        let trimmed: Vec<u8> = bytes.iter().copied().skip_while(|b| *b == 0).collect();
        assert_eq!(magnitude, trimmed);
    }

    #[test]
    fn text_that_is_not_a_certificate_has_no_serial() {
        assert_eq!(certificate_serial_hex("not pem"), None);
        assert_eq!(
            certificate_serial_hex(
                "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
            ),
            None
        );
    }
}

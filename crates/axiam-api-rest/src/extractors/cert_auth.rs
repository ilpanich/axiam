//! Certificate-based authentication extractor for mTLS device auth.
//!
//! Two identity sources are supported, in order of trust:
//!
//! 1. **Native mTLS (D3):** when the server terminates TLS in-process with
//!    client-cert auth enabled (`AXIAM__SERVER__TLS__CLIENT_AUTH`), rustls
//!    cryptographically verifies the client certificate against the configured
//!    CA bundle *during the handshake*. `axiam-server`'s `on_connect` hook then
//!    stores the verified leaf certificate as a [`VerifiedClientCert`] in the
//!    connection extensions. This extractor consumes that verified certificate —
//!    it cannot be forged by a request header.
//! 2. **Legacy proxy path:** the `X-Client-Certificate` header (URL-encoded PEM
//!    forwarded by a TLS-terminating reverse proxy). Used only when no verified
//!    certificate is present on the connection (i.e. TLS terminated upstream).
//!
//! Both paths validate the certificate via [`DeviceAuthService`].

use actix_web::HttpRequest;
use actix_web::web;
use axiam_core::error::AxiamError;
use axiam_core::models::certificate::{CertTrust, DeviceIdentity};
use sha2::{Digest, Sha256};
use surrealdb::Connection;
use uuid::Uuid;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::parse_x509_certificate;

use crate::error::AxiamApiError;
use crate::state::AppState;

/// A client certificate that rustls **verified** against the configured client
/// CA bundle during the TLS 1.3 handshake (D3).
///
/// `axiam-server`'s `HttpServer::on_connect` hook builds this from the rustls
/// connection's `peer_certificates()` and inserts it into the per-connection
/// [`actix_web::dev::Extensions`]; handlers read it back with
/// `HttpRequest::conn_data::<VerifiedClientCert>()`. Because it originates from
/// the verified peer chain — not a header — it is a trusted identity assertion.
#[derive(Debug, Clone)]
pub struct VerifiedClientCert {
    /// What the TLS layer was able to say about this certificate: whether it
    /// chained to a configured trust anchor, or was accepted self-asserted
    /// under [`ClientAuth::OptionalSelfSigned`][cauth] (RFC 8705 §2.2).
    ///
    /// Every consumer must decide what it does with a
    /// [`CertTrust::SelfAsserted`] certificate. Device authentication, in this
    /// very module, refuses it.
    ///
    /// [cauth]: crate::config::ClientAuth::OptionalSelfSigned
    pub trust: CertTrust,
    /// DER encoding of the verified leaf certificate.
    pub der: Vec<u8>,
    /// Subject Alternative Names (DNS/URI/RFC822/IP) parsed from the leaf, in
    /// certificate order. Empty if the leaf carries no SAN extension.
    pub sans: Vec<String>,
    /// Lowercase hex SHA-256 of the leaf's SubjectPublicKeyInfo (the SPKI
    /// fingerprint) — a stable key-identity handle for cert-mapped identities.
    pub spki_sha256: String,
}

impl VerifiedClientCert {
    /// Parse SAN entries and the SPKI fingerprint from a DER-encoded leaf
    /// certificate. Returns an error string only if the DER cannot be parsed as
    /// an X.509 certificate (rustls has already accepted the same bytes by this
    /// point, so this parse is expected to succeed).
    ///
    /// `trust` is not inferred, and there is no default: it is the caller's
    /// statement of what the *handshake* established, and the only caller in a
    /// position to know is `axiam-server`'s `on_connect` hook, which asks
    /// `axiam_server::tls::peer_certificate_trust`. A defaulted parameter here
    /// would have made [`CertTrust::ChainedToAnchor`] — the privileged value —
    /// what a future call site gets by saying nothing.
    pub fn from_der(der: &[u8], trust: CertTrust) -> Result<Self, String> {
        let (_, cert) =
            parse_x509_certificate(der).map_err(|e| format!("parse client cert DER: {e}"))?;

        let mut sans = Vec::new();
        if let Ok(Some(ext)) = cert.subject_alternative_name() {
            for name in &ext.value.general_names {
                match name {
                    GeneralName::DNSName(s) => sans.push(format!("DNS:{s}")),
                    GeneralName::RFC822Name(s) => sans.push(format!("email:{s}")),
                    GeneralName::URI(s) => sans.push(format!("URI:{s}")),
                    GeneralName::IPAddress(b) => sans.push(format!("IP:{}", fmt_ip(b))),
                    _ => {}
                }
            }
        }

        // The `.raw` field of SubjectPublicKeyInfo is the DER of the full SPKI
        // structure (RFC 5280 §4.1) — the standard input for an SPKI fingerprint.
        let spki_sha256 = hex::encode(Sha256::digest(cert.public_key().raw));

        Ok(Self {
            trust,
            der: der.to_vec(),
            sans,
            spki_sha256,
        })
    }

    /// Refuse this certificate for device/IoT authentication unless it chained
    /// to a configured mTLS trust anchor.
    ///
    /// # Why this exists at all (B-06)
    ///
    /// Device authentication's entire trust model is that the certificate was
    /// issued by a CA an administrator flagged as an `mtls_trust_anchor`; the
    /// lookup it performs resolves the certificate against the tenant's issued
    /// certificates. A [`CertTrust::SelfAsserted`] certificate carries no such
    /// issuance — it is admitted to the handshake only under
    /// [`ClientAuth::OptionalSelfSigned`][cauth], and only so that an RFC 8705
    /// §2.2 OAuth2 client can present a credential whose SHA-256 an
    /// administrator registered. Letting one through here would be the
    /// native-listener twin of **B-06**, where a certificate under a
    /// never-flagged CA authenticated through the proxy header, reopened on the
    /// listener that was supposed to be the trustworthy one.
    ///
    /// # Why it is a separate method
    ///
    /// [`CertificateAuthenticated::extract`] needs an `AppState<C>` and a live
    /// `DeviceAuthService`, so it is reachable only from an integration test —
    /// and the native-mTLS branch is not reachable even from there, because
    /// `actix_web::test` performs no TLS handshake and offers no way to
    /// populate the connection extensions this branch reads. Pulling the
    /// decision out gives it somewhere to be tested at all.
    ///
    /// [cauth]: crate::config::ClientAuth::OptionalSelfSigned
    ///
    /// # Errors
    ///
    /// [`AxiamError::AuthenticationFailed`] for a self-asserted certificate.
    /// The message names the actual problem — no trusted issuer — rather than
    /// falling through to the proxy-header branch's message, which would tell
    /// an operator to go and set `TRUST_FORWARDED_CLIENT_CERT`: advice that
    /// would not help here and would, if taken, make the deployment worse.
    pub fn check_usable_for_device_auth(&self) -> Result<(), AxiamError> {
        if self.trust.is_chained_to_anchor() {
            return Ok(());
        }
        tracing::warn!(
            "refusing device certificate authentication: the peer certificate chains to \
             no configured mTLS trust anchor. Self-asserted certificates are accepted by \
             the listener only for RFC 8705 §2.2 OAuth2 client authentication \
             (self_signed_tls_client_auth)"
        );
        Err(AxiamError::AuthenticationFailed {
            reason: "client certificate authentication requires a certificate issued by a \
                     trusted mTLS certificate authority"
                .into(),
        })
    }
}

/// Best-effort textual rendering of a SAN IP address (4-byte v4 / 16-byte v6).
fn fmt_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        16 => bytes
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":"),
        _ => hex::encode(bytes),
    }
}

/// Authenticated device context extracted from a client certificate.
///
/// Use this as a handler parameter to require certificate-based auth.
#[derive(Debug, Clone)]
pub struct CertificateAuthenticated {
    pub service_account_id: Uuid,
    pub tenant_id: Uuid,
    pub certificate_id: Uuid,
}

impl CertificateAuthenticated {
    /// Extract and validate the client certificate from the request.
    ///
    /// This is called manually from the handler rather than via
    /// `FromRequest`, because the concrete `DeviceAuthService` type
    /// depends on the DB connection generic `C`.
    pub async fn extract<C: Connection + Clone>(req: &HttpRequest) -> Result<Self, AxiamApiError> {
        let state = req
            .app_data::<web::Data<AppState<C>>>()
            .ok_or(AxiamError::Internal("missing AppState".into()))?;
        let service = &state.pki.device_auth_service;

        // Prefer the VERIFIED client certificate captured at TLS handshake time
        // (D3 native mTLS): rustls has already checked it against the client-CA
        // bundle, so it is authoritative and cannot be spoofed by a header. Only
        // fall back to the `X-Client-Certificate` proxy header when TLS was
        // terminated upstream (no verified cert on this connection) AND the
        // operator has said that upstream is trusted to set the header.
        let identity_result = if let Some(verified) = req.conn_data::<VerifiedClientCert>() {
            // A certificate that chains to nothing must not authenticate a
            // device, however well-formed it is and whatever it says about
            // itself. See `check_usable_for_device_auth` for why (B-06).
            verified.check_usable_for_device_auth()?;
            service.authenticate_der(&verified.der).await
        } else {
            // A certificate is public data, and every check on the header path
            // — fingerprint, status, expiry, chain to the CA — is satisfied by a
            // *copy* of an enrolled device's certificate. Only the TLS handshake
            // proves possession of the private key, and on this path there was
            // no handshake to prove it in. So the header is worth exactly as
            // much as the guarantee that a client could not have set it, and
            // that guarantee is a property of the deployment, not of the
            // request. Off by default; see
            // `axiam_auth::AuthConfig::trust_forwarded_client_cert`.
            if !state.auth_config.trust_forwarded_client_cert {
                return Err(AxiamError::AuthenticationFailed {
                    reason: "client certificate authentication requires a TLS-verified \
                             peer certificate on this connection. The X-Client-Certificate \
                             header is not trusted unless \
                             AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT is set, which is \
                             only safe when a proxy terminates mTLS and overwrites that \
                             header on every request"
                        .into(),
                }
                .into());
            }
            let header = req
                .headers()
                .get("X-Client-Certificate")
                .and_then(|v| v.to_str().ok())
                .ok_or(AxiamError::AuthenticationFailed {
                    reason: "missing client certificate (no native mTLS peer cert and no \
                             X-Client-Certificate header)"
                        .into(),
                })?;

            // URL-decode the PEM (reverse proxy URL-encodes it)
            let pem = urldecode(header).map_err(|_| AxiamError::AuthenticationFailed {
                reason: "invalid URL encoding in X-Client-Certificate".into(),
            })?;

            service.authenticate(&pem).await
        };

        let identity: DeviceIdentity = identity_result.map_err(|e| match &e {
            // Map certificate/NotFound errors to proper 401/403 status codes
            AxiamError::Certificate(msg) if msg.contains("not bound to a service account") => {
                AxiamError::AuthorizationDenied {
                    reason: msg.clone(),
                    action: None,
                    resource_id: None,
                }
            }
            AxiamError::Certificate(msg) => AxiamError::AuthenticationFailed {
                reason: msg.clone(),
            },
            AxiamError::NotFound { .. } => AxiamError::AuthenticationFailed {
                reason: "unknown client certificate".into(),
            },
            _ => e,
        })?;

        Ok(CertificateAuthenticated {
            service_account_id: identity.service_account_id,
            tenant_id: identity.tenant_id,
            certificate_id: identity.certificate_id,
        })
    }
}

/// Simple percent-decoding for the `X-Client-Certificate` header.
fn urldecode(input: &str) -> Result<String, ()> {
    let mut result = Vec::with_capacity(input.len());
    let mut bytes = input.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().ok_or(())?;
            let lo = bytes.next().ok_or(())?;
            let hi = hex_val(hi)?;
            let lo = hex_val(lo)?;
            result.push((hi << 4) | lo);
        } else {
            result.push(b);
        }
    }
    String::from_utf8(result).map_err(|_| ())
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // urldecode / hex_val (R4) — these private helpers are only reachable
    // indirectly through the HTTP `X-Client-Certificate` header path in
    // integration tests, which only exercise the happy path plus one
    // malformed-input case; test the pure logic directly here.
    // -----------------------------------------------------------------------

    #[test]
    fn urldecode_plain_string_round_trips() {
        assert_eq!(urldecode("hello-world_1.2~3").unwrap(), "hello-world_1.2~3");
    }

    #[test]
    fn urldecode_decodes_percent_sequences() {
        // "%0A" -> newline, "%2B" -> '+'.
        assert_eq!(urldecode("a%0Ab%2Bc").unwrap(), "a\nb+c");
    }

    #[test]
    fn urldecode_rejects_truncated_percent_sequence() {
        // Only one hex digit follows '%' before the string ends.
        assert!(urldecode("abc%2").is_err());
    }

    #[test]
    fn urldecode_rejects_invalid_hex_digit() {
        assert!(urldecode("abc%zz").is_err());
        assert!(urldecode("abc%2z").is_err());
    }

    #[test]
    fn hex_val_accepts_all_case_variants() {
        assert_eq!(hex_val(b'0').unwrap(), 0);
        assert_eq!(hex_val(b'9').unwrap(), 9);
        assert_eq!(hex_val(b'a').unwrap(), 10);
        assert_eq!(hex_val(b'f').unwrap(), 15);
        assert_eq!(hex_val(b'A').unwrap(), 10);
        assert_eq!(hex_val(b'F').unwrap(), 15);
    }

    #[test]
    fn hex_val_rejects_non_hex_byte() {
        assert!(hex_val(b'g').is_err());
        assert!(hex_val(b'Z').is_err());
        assert!(hex_val(b' ').is_err());
    }

    // -----------------------------------------------------------------------
    // fmt_ip (R4) — pure formatting helper for SAN IP entries.
    // -----------------------------------------------------------------------

    #[test]
    fn fmt_ip_formats_ipv4() {
        assert_eq!(fmt_ip(&[192, 168, 1, 1]), "192.168.1.1");
    }

    #[test]
    fn fmt_ip_formats_ipv6() {
        // ::1 (loopback), 16 bytes, all zero except the last byte.
        let mut bytes = [0u8; 16];
        bytes[15] = 1;
        assert_eq!(fmt_ip(&bytes), "0000:0000:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn fmt_ip_falls_back_to_hex_for_unexpected_length() {
        // Neither 4 nor 16 bytes -> hex fallback (defensive branch).
        assert_eq!(fmt_ip(&[1, 2, 3]), "010203");
    }

    // -----------------------------------------------------------------------
    // VerifiedClientCert::from_der (R4) — the native-mTLS path, unreachable
    // from `actix_web::test` (no real TLS handshake), so it is entirely
    // untested by any HTTP integration test. Exercise it directly against a
    // real self-signed certificate's DER encoding.
    // -----------------------------------------------------------------------

    #[test]
    fn from_der_parses_dns_san_and_spki_fingerprint() {
        let cert = rcgen::generate_simple_self_signed(vec!["device.example.com".to_string()])
            .expect("generate self-signed cert");
        let der = cert.cert.der().to_vec();

        let parsed =
            VerifiedClientCert::from_der(&der, CertTrust::ChainedToAnchor).expect("parse DER");
        assert!(
            parsed.sans.iter().any(|s| s == "DNS:device.example.com"),
            "expected a DNS SAN entry, got: {:?}",
            parsed.sans
        );
        assert_eq!(
            parsed.spki_sha256.len(),
            64,
            "SPKI fingerprint must be a 32-byte hex string (64 hex chars)"
        );
        assert!(
            parsed.spki_sha256.chars().all(|c| c.is_ascii_hexdigit()),
            "SPKI fingerprint must be lowercase hex"
        );
        assert_eq!(parsed.der, der);
    }

    #[test]
    fn from_der_rejects_garbage_bytes() {
        let result =
            VerifiedClientCert::from_der(b"not a real certificate", CertTrust::SelfAsserted);
        assert!(result.is_err(), "garbage DER must fail to parse");
    }

    // -----------------------------------------------------------------------
    // The B-06 guard: device authentication and self-asserted certificates.
    //
    // `client_auth = optional_self_signed` lets a certificate that chains to
    // nothing complete a TLS handshake, so that an RFC 8705 §2.2 OAuth2 client
    // can present the credential its registration is built around. Device
    // authentication must be unaffected by that: its model is issuance by a
    // flagged mTLS trust anchor, and a self-signed certificate has no issuer
    // anybody flagged.
    // -----------------------------------------------------------------------

    fn device_cert(trust: CertTrust) -> VerifiedClientCert {
        let cert = rcgen::generate_simple_self_signed(vec!["device.example.com".to_string()])
            .expect("generate self-signed cert");
        VerifiedClientCert::from_der(cert.cert.der().as_ref(), trust).expect("parse DER")
    }

    /// A self-asserted certificate cannot authenticate a device; a chained one
    /// can.
    ///
    /// The certificates in both halves are generated the same way, so the only
    /// difference between "refused" and "permitted" is what the TLS layer said
    /// about the connection — which is the contract.
    #[test]
    fn device_auth_refuses_a_self_asserted_certificate() {
        assert!(
            device_cert(CertTrust::ChainedToAnchor)
                .check_usable_for_device_auth()
                .is_ok(),
            "control: a certificate that chained to a configured anchor is device auth's \
             normal case and must still pass"
        );

        let err = device_cert(CertTrust::SelfAsserted)
            .check_usable_for_device_auth()
            .expect_err("a certificate that chains to nothing must not authenticate a device");
        assert!(
            matches!(err, AxiamError::AuthenticationFailed { .. }),
            "must fail authentication (401), not authorization or anything softer; got {err:?}"
        );
    }

    /// The refusal must not send an operator to the wrong knob.
    ///
    /// Falling through to the proxy-header branch would have produced its error
    /// text, which tells an operator to set
    /// `AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT`. That would not fix this —
    /// there is no forwarded header on a native mTLS connection — and an
    /// operator who took the advice would have widened a *different* trust
    /// boundary while chasing this one. So the message is asserted, not just
    /// the variant.
    #[test]
    fn the_device_auth_refusal_names_the_issuer_problem_not_the_header_knob() {
        let AxiamError::AuthenticationFailed { reason } = device_cert(CertTrust::SelfAsserted)
            .check_usable_for_device_auth()
            .expect_err("must be refused")
        else {
            panic!("expected AuthenticationFailed");
        };
        assert!(
            !reason.contains("TRUST_FORWARDED_CLIENT_CERT")
                && !reason.contains("X-Client-Certificate"),
            "the refusal must not point at the proxy-header configuration; got {reason:?}"
        );
        assert!(
            reason.contains("certificate authority"),
            "the refusal must say what is actually wrong — no trusted issuer; got {reason:?}"
        );
    }
}

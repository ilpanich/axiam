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
use axiam_core::models::certificate::DeviceIdentity;
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
    /// an X.509 certificate (rustls has already verified the chain by this
    /// point, so this parse is expected to succeed).
    pub fn from_der(der: &[u8]) -> Result<Self, String> {
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
            der: der.to_vec(),
            sans,
            spki_sha256,
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
        let service = &state.device_auth_service;

        // Prefer the VERIFIED client certificate captured at TLS handshake time
        // (D3 native mTLS): rustls has already checked it against the client-CA
        // bundle, so it is authoritative and cannot be spoofed by a header. Only
        // fall back to the `X-Client-Certificate` proxy header when TLS was
        // terminated upstream (no verified cert on this connection).
        let identity_result = if let Some(verified) = req.conn_data::<VerifiedClientCert>() {
            service.authenticate_der(&verified.der).await
        } else {
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

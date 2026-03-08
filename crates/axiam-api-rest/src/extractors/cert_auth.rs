//! Certificate-based authentication extractor for mTLS device auth.
//!
//! Reads the `X-Client-Certificate` header (URL-encoded PEM forwarded
//! by the TLS-terminating reverse proxy) and validates it via
//! [`DeviceAuthService`].

use actix_web::HttpRequest;
use actix_web::web;
use axiam_core::error::AxiamError;
use axiam_core::models::certificate::DeviceIdentity;
use axiam_db::SurrealCertificateRepository;
use axiam_pki::DeviceAuthService;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;

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
    pub async fn extract<C: Connection>(req: &HttpRequest) -> Result<Self, AxiamApiError> {
        let service = req
            .app_data::<web::Data<DeviceAuthService<SurrealCertificateRepository<C>>>>()
            .ok_or(AxiamError::Internal("missing DeviceAuthService".into()))?;

        let header = req
            .headers()
            .get("X-Client-Certificate")
            .and_then(|v| v.to_str().ok())
            .ok_or(AxiamError::AuthenticationFailed {
                reason: "missing X-Client-Certificate header".into(),
            })?;

        // URL-decode the PEM (reverse proxy URL-encodes it)
        let pem = urldecode(header).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid URL encoding in X-Client-Certificate".into(),
        })?;

        let identity: DeviceIdentity = service.authenticate(&pem).await.map_err(|e| match &e {
            // Map certificate/NotFound errors to proper 401/403 status codes
            AxiamError::Certificate(msg) if msg.contains("not bound to a service account") => {
                AxiamError::AuthorizationDenied {
                    reason: msg.clone(),
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

//! The TLS client configuration every directory connection uses.
//!
//! # Mandatory, and verified
//!
//! There is no code path in this crate that opens an LDAP connection without
//! TLS, and none that turns verification off: `ldap3`'s `no_tls_verify` switch
//! is never set, and the [`rustls::ClientConfig`] built here uses rustls' own
//! WebPKI verifier over the tenant's anchors. The server name checked is the
//! host of the configured URL — `ldap3` derives it from the same URL it dials —
//! so a certificate for another host is refused even when it chains to a
//! trusted anchor.
//!
//! # Whose anchors
//!
//! A tenant's `trust_anchors_pem` (validated at configuration time to be CA
//! certificates) is the **whole** trust store for that tenant's directory: a
//! private corporate CA — the organisation's own AXIAM CA included — is the
//! common case, and adding the public roots beside it would let any public CA
//! vouch for the directory's name. An empty list means the Mozilla bundle in
//! `webpki-roots`, which is what the rest of the workspace's outbound TLS
//! (`reqwest`'s `rustls-tls`, `lettre`) already trusts.
//!
//! # TLS 1.2 minimum, not 1.3 only
//!
//! The protocol floor toward a directory is **TLS 1.2**, with 1.3 preferred
//! when the server offers it. AXIAM's own listeners pin 1.3, but a directory is
//! somebody else's server: Active Directory domain controllers on Windows
//! Server 2019 and earlier do not speak TLS 1.3 on LDAPS at all, and many
//! OpenLDAP builds in the field are linked against TLS stacks that stop at 1.2.
//! A 1.3-only client would make the feature unusable against exactly the
//! directories it exists to federate. TLS 1.2 under rustls is still restricted
//! to AEAD suites with forward secrecy (no RSA key exchange, no CBC, no RC4),
//! so the floor is 1.2-done-well rather than anything older.
//!
//! # Crypto provider
//!
//! The configuration names the `ring` provider explicitly rather than reading
//! the process default. The workspace links both `ring` and `aws-lc-rs`, so a
//! process that never installed a default (a test binary, an embedder) would
//! otherwise panic at the first handshake; `ring` matches the REST listener and
//! the AMQP client.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};

/// Why a TLS client configuration could not be built from a tenant's anchors.
///
/// Configuration-time validation refuses every one of these, so reaching one
/// means the stored row was not validated. The bind path treats it as a
/// misconfigured directory and fails closed — it never falls back to another
/// trust store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TlsSetupError {
    /// An anchor entry held no PEM certificate.
    #[error("directory trust anchor #{0} holds no certificate")]
    NoCertificate(usize),
    /// An anchor was refused by rustls as a trust anchor.
    #[error("directory trust anchor #{0} is not usable as a trust anchor")]
    Unusable(usize),
    /// The protocol versions could not be applied (a rustls build without
    /// TLS 1.2 or 1.3 support; not reachable with this workspace's features).
    #[error("directory TLS configuration could not be built")]
    Protocol,
}

/// Build the client configuration for a tenant's directory from its trust
/// anchors.
///
/// # Errors
///
/// [`TlsSetupError`] when an anchor cannot be used. An empty list is not an
/// error: it selects the `webpki-roots` bundle.
pub fn client_config(trust_anchors_pem: &[String]) -> Result<Arc<ClientConfig>, TlsSetupError> {
    let roots = root_store(trust_anchors_pem)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| TlsSetupError::Protocol)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The trust store for one tenant: its anchors, or the public bundle when it
/// configured none. Never both.
fn root_store(trust_anchors_pem: &[String]) -> Result<RootCertStore, TlsSetupError> {
    let mut roots = RootCertStore::empty();
    if trust_anchors_pem.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        return Ok(roots);
    }
    for (index, pem) in trust_anchors_pem.iter().enumerate() {
        let mut found = false;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let cert = cert.map_err(|_| TlsSetupError::NoCertificate(index))?;
            roots
                .add(cert)
                .map_err(|_| TlsSetupError::Unusable(index))?;
            found = true;
        }
        if !found {
            return Err(TlsSetupError::NoCertificate(index));
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    fn ca_pem() -> String {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn an_empty_anchor_list_selects_the_public_bundle() {
        let roots = root_store(&[]).unwrap();
        assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(client_config(&[]).is_ok());
    }

    /// Configured anchors replace the public bundle rather than joining it: a
    /// tenant that pinned its corporate CA must not also trust every public CA
    /// to vouch for its directory's name.
    #[test]
    fn configured_anchors_are_the_whole_trust_store() {
        let roots = root_store(&[ca_pem(), ca_pem()]).unwrap();
        assert_eq!(roots.len(), 2);
    }

    #[test]
    fn an_entry_with_no_certificate_fails_closed() {
        assert_eq!(
            root_store(&[ca_pem(), "not pem".into()]).unwrap_err(),
            TlsSetupError::NoCertificate(1)
        );
        assert!(client_config(&["".into()]).is_err());
    }

    #[test]
    fn a_corrupt_certificate_fails_closed() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n";
        assert!(root_store(&[pem.into()]).is_err());
    }

    /// No client certificate is ever presented to a directory: AXIAM
    /// authenticates to it with the bind DN over the verified channel, and a
    /// configuration that could present one would be a credential this crate
    /// does not manage. (That TLS 1.2 is accepted and verification is enforced
    /// is pinned end to end in `tests/client_test.rs`, against a live server.)
    #[test]
    fn no_client_certificate_is_configured() {
        let config = client_config(&[]).unwrap();
        assert!(!config.client_auth_cert_resolver.has_certs());
        assert!(!config.key_log.will_log("CLIENT_RANDOM"));
    }
}

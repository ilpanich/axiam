//! Building the mTLS client trust store out of the organization CAs an operator
//! flagged in the admin UI.
//!
//! # What this is for
//!
//! `AXIAM__SERVER__TLS__CLIENT_AUTH` and `AXIAM__SERVER__TLS__CLIENT_CA_PATH`
//! are how the rustls listener is told to verify client certificates. Setting
//! them by hand means an operator has to get a copy of their organization CA's
//! certificate onto the server volume themselves, keep it in step with the CA
//! they actually issue from, and remember to remove it when they rotate — for a
//! CA that AXIAM generated, holds, and already shows them on a page.
//!
//! Flagging a CA
//! ([`axiam_core::models::certificate::CaCertificate::mtls_trust_anchor`]) does
//! that work instead: the certificate is exported at startup and the listener is
//! pointed at it.
//!
//! # The private key is not involved
//!
//! Only `public_cert_pem` is written. The signing key stays wherever its
//! custodian put it — Vault, under the deployment's own policy — and never
//! reaches the volume. Nothing is weakened by the copy: a trust anchor is
//! public by construction. It is what the server offers every client during the
//! handshake, and every device that validates an AXIAM-issued chain already
//! holds it.
//!
//! # Applying a change without a restart
//!
//! rustls builds its `RootCertStore` once, when the `ServerConfig` is
//! constructed, and actix-web binds that config for the life of the process —
//! so flagging a CA used to change what the *next* boot trusted, and the API
//! said so.
//!
//! What rustls does consult per handshake is the **verifier**. A verifier that
//! delegates to a swappable anchor set therefore gives the config something
//! permanent to hold while what it trusts changes underneath;
//! [`crate::tls::ReloadableClientCertVerifier`] is that, and
//! [`TrustAnchorReload`] here is what drives it from the handler that flags a
//! CA. The bundle on disk is still written and still read at every boot, so a
//! restart reaches the same state by the same path.
//!
//! Connections already established keep the verifier they handshook with. That
//! is correct rather than a limitation: a certificate accepted a moment ago
//! does not become invalid mid-connection, and ending a session that is already
//! authenticated is what session revocation is for.

use std::path::{Path, PathBuf};

use axiam_api_rest::config::{ClientAuth, TlsConfig};
use axiam_core::models::certificate::CaCertificate;

/// The bundle filename used when only [`TlsConfig::cert_path`] is known.
const DEFAULT_BUNDLE_FILENAME: &str = "client-ca-bundle.pem";

/// What [`plan`] decided to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorPlan {
    /// Nothing to do. No CA is flagged, so the deployment's TLS posture is
    /// untouched — the case every existing deployment is in.
    NoAnchors,
    /// CAs are flagged but there is nowhere to put the bundle: neither
    /// `client_ca_bundle_path` nor `cert_path` is set, so no path can be
    /// derived. Reported to the operator rather than guessed at.
    NoBundlePath,
    /// Write `pem` to `path`, and apply `client_auth` / `client_ca_path` as
    /// described by the two booleans.
    Write {
        /// Where the bundle goes.
        path: PathBuf,
        /// The concatenated PEM certificates.
        pem: String,
        /// How many CAs went in, for the startup log line.
        anchor_count: usize,
        /// Whether to turn `client_auth` on. False when the operator already
        /// chose a mode, which is never overridden.
        set_client_auth: bool,
        /// Whether to point `client_ca_path` at the bundle. False when the
        /// operator named their own bundle, which is never overridden.
        set_client_ca_path: bool,
    },
}

/// Where the bundle should be written, given the TLS configuration.
///
/// An explicit `client_ca_bundle_path` wins. Otherwise the bundle goes beside
/// the server's certificate, which is the directory an operator has already had
/// to make readable-and-writable for TLS material — inventing a path under
/// `/var/lib` would work on one packaging and not another.
pub fn bundle_path(tls: &TlsConfig) -> Option<PathBuf> {
    if let Some(ref explicit) = tls.client_ca_bundle_path {
        return Some(explicit.clone());
    }
    tls.cert_path
        .as_ref()
        .and_then(|p| p.parent())
        .map(|dir| dir.join(DEFAULT_BUNDLE_FILENAME))
}

/// Concatenate the anchors' public certificates into one PEM bundle.
///
/// Each certificate is newline-terminated so two PEMs cannot run together —
/// `-----END CERTIFICATE----------BEGIN CERTIFICATE-----` parses as neither,
/// and the resulting trust store would silently be empty.
///
/// A CA's `chain_pem` is **not** included. Under `vault_pki` custody
/// `public_cert_pem` is the signing intermediate and `chain_pem` carries the
/// root above it; adding the root to a *client* trust store would extend trust
/// to everything else that root ever signs, which is broader than the operator
/// flagged.
fn bundle_pem(anchors: &[CaCertificate]) -> String {
    let mut out = String::new();
    for anchor in anchors {
        let pem = anchor.public_cert_pem.trim_end();
        if pem.is_empty() {
            continue;
        }
        out.push_str(pem);
        out.push('\n');
    }
    out
}

/// Decide what to do with the flagged CAs, without touching the filesystem.
///
/// Split from the doing so the decision — especially "does an operator's
/// explicit setting survive?" — is testable without a disk or a database.
///
/// # Examples
///
/// ```
/// use axiam_api_rest::config::{ClientAuth, TlsConfig};
/// use axiam_server::mtls_anchors::{plan, AnchorPlan};
///
/// // No flagged CAs: nothing changes, which is every existing deployment.
/// let tls = TlsConfig::default();
/// assert_eq!(plan(&tls, &[]), AnchorPlan::NoAnchors);
/// ```
pub fn plan(tls: &TlsConfig, anchors: &[CaCertificate]) -> AnchorPlan {
    if anchors.is_empty() {
        return AnchorPlan::NoAnchors;
    }
    let Some(path) = bundle_path(tls) else {
        return AnchorPlan::NoBundlePath;
    };
    AnchorPlan::Write {
        path,
        pem: bundle_pem(anchors),
        anchor_count: anchors.len(),
        // An operator who set `client_auth` made a decision — including the
        // decision to leave it `off` while keeping a CA flagged for a later
        // change. `Off` is the default, so "still Off" is the only reading
        // available here that does not override a deliberate `required`.
        set_client_auth: tls.client_auth == ClientAuth::Off,
        // Likewise: a bundle the operator named is theirs. Pointing at ours
        // instead would replace a trust store they curated with one assembled
        // from database rows.
        set_client_ca_path: tls.client_ca_path.is_none(),
    }
}

/// Apply a [`AnchorPlan::Write`] to `tls`, writing the bundle to disk.
///
/// Returns the path written on success.
///
/// # Errors
///
/// Any I/O failure creating the directory or writing the file.
pub fn apply(tls: &mut TlsConfig, plan: &AnchorPlan) -> std::io::Result<Option<PathBuf>> {
    let AnchorPlan::Write {
        path,
        pem,
        set_client_auth,
        set_client_ca_path,
        ..
    } = plan
    else {
        return Ok(None);
    };

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_bundle(path, pem)?;

    if *set_client_auth {
        // `Optional`, never `Required`. A server that suddenly refuses every
        // client without a certificate would lock every browser out of the
        // admin UI the moment an operator flagged a CA — including the operator
        // who flagged it. `Optional` verifies a certificate when one is offered
        // and lets password and passkey logins carry on working, which is the
        // posture an IoT deployment actually wants: devices authenticate by
        // certificate, humans do not.
        tls.client_auth = ClientAuth::Optional;
    }
    if *set_client_ca_path {
        tls.client_ca_path = Some(path.clone());
    }
    Ok(Some(path.clone()))
}

/// Write `pem` to `path`, replacing whatever was there.
///
/// The bundle is rebuilt from the database on every boot, so a partial write
/// from a previous crash is not something to preserve. It is also not secret —
/// these are the certificates the server hands to every client — so no special
/// permissions are set beyond the process umask.
fn write_bundle(path: &Path, pem: &str) -> std::io::Result<()> {
    std::fs::write(path, pem)
}

// ---------------------------------------------------------------------------
// Live reload
// ---------------------------------------------------------------------------

/// Rebuilds the trust anchor bundle from the database and installs it on the
/// running listener.
///
/// Registered in `AppState` at startup as the implementation of
/// [`axiam_api_rest::TrustAnchorReloader`]. It holds the CA repository and the
/// resolved bundle path — the same path the boot sequence wrote, so a reload
/// and a restart converge on the same file.
pub struct TrustAnchorReload<C: surrealdb::Connection> {
    ca_repo: axiam_db::SurrealCaCertificateRepository<C>,
    /// Where the bundle is written. `None` when no path could be derived, in
    /// which case there is nothing on disk for a restart to read and the reload
    /// reports that a restart is required.
    bundle_path: Option<PathBuf>,
}

impl<C: surrealdb::Connection> TrustAnchorReload<C> {
    pub fn new(
        ca_repo: axiam_db::SurrealCaCertificateRepository<C>,
        bundle_path: Option<PathBuf>,
    ) -> Self {
        Self {
            ca_repo,
            bundle_path,
        }
    }
}

impl<C: surrealdb::Connection> axiam_api_rest::TrustAnchorReloader for TrustAnchorReload<C> {
    fn reload<'a>(
        &'a self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = axiam_core::error::AxiamResult<Option<usize>>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            use axiam_core::repository::CaCertificateRepository as _;

            // Re-read rather than accept a delta from the caller. The listener's
            // trust store is a whole set, the database is what a restart would
            // read, and rebuilding from it is what keeps the two from drifting
            // — including when two administrators toggle two CAs at once.
            let anchors = self.ca_repo.list_mtls_trust_anchors().await?;
            let pem = bundle_pem(&anchors);

            // Write the bundle first. If the process dies between the write and
            // the swap, the next boot reads the file and reaches the same state;
            // the other order would leave a listener trusting a set that no
            // restart could reproduce.
            if let Some(path) = self.bundle_path.as_ref() {
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| {
                        axiam_core::error::AxiamError::Internal(format!(
                            "failed to create the trust anchor bundle directory {}: {e}",
                            dir.display()
                        ))
                    })?;
                }
                write_bundle(path, &pem).map_err(|e| {
                    axiam_core::error::AxiamError::Internal(format!(
                        "failed to write the trust anchor bundle {}: {e}",
                        path.display()
                    ))
                })?;
            }

            crate::tls::reload_trust_anchors(&pem).map_err(|e| {
                axiam_core::error::AxiamError::Internal(format!(
                    "failed to install the trust anchor bundle on the listener: {e}"
                ))
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::ca_keys::CaKeyCustody;
    use axiam_core::models::certificate::{CertificateStatus, KeyAlgorithm};
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    fn anchor(pem: &str) -> CaCertificate {
        CaCertificate {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            tenant_id: None,
            parent_ca_id: None,
            subject: "CN=Test Root".into(),
            public_cert_pem: pem.into(),
            chain_pem: None,
            fingerprint: "ff".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: Utc::now() - Duration::days(1),
            not_after: Utc::now() + Duration::days(365),
            status: CertificateStatus::Active,
            encrypted_private_key: None,
            key_custody: CaKeyCustody::Vault,
            key_locator: Some("axiam/ca/x".into()),
            mtls_trust_anchor: true,
            created_at: Utc::now(),
        }
    }

    fn tls_with_cert(dir: &Path) -> TlsConfig {
        TlsConfig {
            enabled: true,
            cert_path: Some(dir.join("server.pem")),
            key_path: Some(dir.join("server.key")),
            ..TlsConfig::default()
        }
    }

    #[test]
    fn no_flagged_cas_changes_nothing() {
        // The property every existing deployment depends on.
        assert_eq!(plan(&TlsConfig::default(), &[]), AnchorPlan::NoAnchors);
    }

    #[test]
    fn flagged_cas_with_nowhere_to_write_are_reported_not_guessed() {
        let tls = TlsConfig::default(); // no cert_path, no bundle path
        assert_eq!(plan(&tls, &[anchor("PEM")]), AnchorPlan::NoBundlePath);
    }

    #[test]
    fn the_bundle_lands_beside_the_servers_own_certificate_by_default() {
        let tls = tls_with_cert(Path::new("/etc/axiam/tls"));
        match plan(&tls, &[anchor("PEM")]) {
            AnchorPlan::Write { path, .. } => {
                assert_eq!(path, Path::new("/etc/axiam/tls/client-ca-bundle.pem"));
            }
            other => panic!("expected a write plan, got {other:?}"),
        }
    }

    #[test]
    fn an_explicit_bundle_path_wins_over_the_derived_one() {
        let mut tls = tls_with_cert(Path::new("/etc/axiam/tls"));
        tls.client_ca_bundle_path = Some(PathBuf::from("/srv/anchors.pem"));
        match plan(&tls, &[anchor("PEM")]) {
            AnchorPlan::Write { path, .. } => assert_eq!(path, Path::new("/srv/anchors.pem")),
            other => panic!("expected a write plan, got {other:?}"),
        }
    }

    #[test]
    fn an_operators_explicit_client_auth_is_never_overridden() {
        // The important one. Someone who set `required` chose a stricter posture
        // than this feature would install, and silently relaxing it to
        // `optional` would be a security regression performed by a convenience.
        let mut tls = tls_with_cert(Path::new("/etc/axiam/tls"));
        tls.client_auth = ClientAuth::Required;
        match plan(&tls, &[anchor("PEM")]) {
            AnchorPlan::Write {
                set_client_auth, ..
            } => assert!(!set_client_auth),
            other => panic!("expected a write plan, got {other:?}"),
        }
    }

    #[test]
    fn an_operators_own_ca_bundle_is_never_replaced() {
        let mut tls = tls_with_cert(Path::new("/etc/axiam/tls"));
        tls.client_ca_path = Some(PathBuf::from("/etc/pki/corporate-roots.pem"));
        match plan(&tls, &[anchor("PEM")]) {
            AnchorPlan::Write {
                set_client_ca_path, ..
            } => assert!(!set_client_ca_path),
            other => panic!("expected a write plan, got {other:?}"),
        }
    }

    #[test]
    fn certificates_are_newline_separated_so_they_cannot_run_together() {
        // Without the separator the concatenation reads
        // `-----END CERTIFICATE----------BEGIN CERTIFICATE-----`, which parses
        // as neither certificate and yields a silently empty trust store.
        let pem = bundle_pem(&[anchor("-----A-----"), anchor("-----B-----")]);
        assert_eq!(pem, "-----A-----\n-----B-----\n");
    }

    #[test]
    fn a_certificate_already_ending_in_a_newline_does_not_get_a_second() {
        let pem = bundle_pem(&[anchor("-----A-----\n")]);
        assert_eq!(pem, "-----A-----\n");
    }

    #[test]
    fn an_empty_certificate_is_skipped_rather_than_writing_a_blank_line() {
        let pem = bundle_pem(&[anchor(""), anchor("-----B-----")]);
        assert_eq!(pem, "-----B-----\n");
    }

    #[test]
    fn apply_writes_the_bundle_and_points_the_listener_at_it() {
        let dir = std::env::temp_dir().join(format!("axiam-mtls-{}", Uuid::new_v4()));
        let mut tls = tls_with_cert(&dir);
        let p = plan(&tls, &[anchor("-----A-----")]);
        let written = apply(&mut tls, &p).expect("write must succeed");

        let path = written.expect("a write plan returns its path");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "-----A-----\n");
        // Optional, not Required — see `apply`.
        assert_eq!(tls.client_auth, ClientAuth::Optional);
        assert_eq!(tls.client_ca_path, Some(path));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn apply_is_a_no_op_for_a_plan_that_is_not_a_write() {
        let mut tls = TlsConfig::default();
        assert_eq!(apply(&mut tls, &AnchorPlan::NoAnchors).unwrap(), None);
        assert_eq!(apply(&mut tls, &AnchorPlan::NoBundlePath).unwrap(), None);
        assert_eq!(tls.client_auth, ClientAuth::Off);
        assert!(tls.client_ca_path.is_none());
    }
}

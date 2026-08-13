//! Adapter implementing `axiam_core::repository::AttestationMetadataSource`
//! over any [`MdsRepository`] (X3 wave 2, W2-D4).
//!
//! This is the "implemented over the repositories" half of W2-D4: it exists
//! so `axiam-auth` can depend on the small, data-only
//! [`axiam_core::repository::AttestationMetadataSource`] trait instead of a
//! hard `axiam-pki`/`axiam-db` dependency, while the real lookup still goes
//! through the same `mds_entry` table `MdsRepository` reads.

use axiam_core::error::AxiamResult;
use axiam_core::models::mds::MdsEntry;
use axiam_core::repository::{AttestationMetadataSource, AttestationRootMaterial, MdsRepository};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use uuid::Uuid;

/// Wraps any [`MdsRepository`] to serve [`AttestationMetadataSource`].
///
/// `attestation_roots` decodes each entry's `attestation_root_certificates`
/// (base64 DER, as MDS ships them — see `axiam_core::models::mds::MdsEntry`
/// docs) into raw DER bytes, flattened to one `AttestationRootMaterial` per
/// `(aaguid, root certificate)` pair. A cert that fails to base64-decode is
/// skipped and logged rather than failing the whole lookup — one malformed
/// MDS entry must not take down attestation for every other authenticator.
#[derive(Clone)]
pub struct MdsAttestationMetadataSource<M: MdsRepository> {
    mds: M,
}

impl<M: MdsRepository> MdsAttestationMetadataSource<M> {
    pub fn new(mds: M) -> Self {
        Self { mds }
    }
}

impl<M: MdsRepository + Send + Sync> AttestationMetadataSource for MdsAttestationMetadataSource<M> {
    async fn get_entry(&self, aaguid: Uuid) -> AxiamResult<Option<MdsEntry>> {
        self.mds.get_by_aaguid(aaguid).await
    }

    async fn attestation_roots(
        &self,
        allowed_aaguids: Option<&[Uuid]>,
    ) -> AxiamResult<Vec<AttestationRootMaterial>> {
        let entries: Vec<MdsEntry> = match allowed_aaguids {
            Some(allowed) => {
                let mut out = Vec::with_capacity(allowed.len());
                for &aaguid in allowed {
                    if let Some(entry) = self.mds.get_by_aaguid(aaguid).await? {
                        out.push(entry);
                    }
                }
                out
            }
            None => self.mds.list_all().await?,
        };

        let mut roots = Vec::new();
        for entry in entries {
            for cert_b64 in &entry.attestation_root_certificates {
                match STANDARD.decode(cert_b64) {
                    Ok(der) => roots.push(AttestationRootMaterial {
                        aaguid: entry.aaguid,
                        der,
                        description: entry
                            .description
                            .clone()
                            .unwrap_or_else(|| entry.aaguid.to_string()),
                    }),
                    Err(e) => {
                        tracing::warn!(
                            aaguid = %entry.aaguid,
                            error = %e,
                            "skipping unparsable MDS attestation root certificate"
                        );
                    }
                }
            }
        }
        Ok(roots)
    }
}

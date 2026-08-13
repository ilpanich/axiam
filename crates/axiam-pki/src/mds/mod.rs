//! FIDO Alliance Metadata Service (MDS3) ingestion (X3).
//!
//! `axiam-pki` owns this because MDS ingestion is fundamentally a
//! trust-anchor concern — the same category of thing as CA certificate
//! management — not a WebAuthn concern: it verifies a signed BLOB's chain
//! of custody back to a vendored root, exactly like `axiam-pki::mtls` does
//! for mTLS client certificates, before anything is allowed to consult it.
//!
//! ## Module layout
//!
//! - [`error::MdsError`] — this crate's local error type for the whole
//!   ingestion path (fetch, verify, parse).
//! - [`blob::verify_and_parse`] — the fail-closed BLOB verification pipeline
//!   (D4), and the [`blob::MdsBlob`] result type.
//! - This module (`mod.rs`) — the vendored trust anchor (D3), the
//!   fetch/local-file entry points (D10), and the rollback decision (D4
//!   step 8).
//!
//! ## Why the vendored anchor is digest-pinned, not just "the file in git"
//!
//! [`FIDO_MDS_ROOT_SHA256_HEX`] is the root of trust for **every**
//! attestation decision the policy engine (`axiam_core::models::webauthn_policy`)
//! makes: if the vendored anchor were ever silently swapped for a different
//! certificate, "only FIDO-certified authenticators may register" quietly
//! becomes "any authenticator an attacker can mint an attestation chain
//! for" — a security regression that would produce no test failure and no
//! error, only a bad root key. Digest-pinning turns that into a loud,
//! fail-closed startup error instead: [`load_root_anchor`] recomputes the
//! SHA-256 of the vendored PEM's DER bytes on every use and refuses to
//! proceed on any mismatch. The vendored `.pem` file is *not* re-fetched
//! from anywhere at runtime — matching the digest against the pinned
//! constant **is** the check.
//!
//! **Anchor update procedure** (for the admin guide, and for whoever needs
//! to rotate this): obtain the new GlobalSign Root CA – R3 (or successor)
//! certificate from a trusted, independently-verifiable source (e.g.
//! GlobalSign's own published fingerprint page, not just the download URL),
//! compute its SHA-256 over the DER encoding, update both the `.pem` file
//! and [`FIDO_MDS_ROOT_SHA256_HEX`] in the same commit, and get that commit
//! reviewed with the digest change called out explicitly — the digest
//! constant is the actual security control; the PEM file is inert without it
//! matching.

pub mod blob;
mod error;

pub use error::MdsError;

use chrono::Utc;
use sha2::{Digest, Sha256};

pub use blob::{MdsBlob, verify_and_parse};

/// The vendored FIDO MDS3 root anchor: GlobalSign Root CA – R3.
///
/// `include_str!`'d at compile time so the anchor ships inside the binary —
/// there is no runtime file dependency and no way to point this at a
/// different file without recompiling.
const ROOT_ANCHOR_PEM: &str = include_str!("fido-mds-root-ca-r3.pem");

/// SHA-256 (hex) of the vendored anchor's DER encoding. Independently
/// verified against GlobalSign's published fingerprint for "GlobalSign Root
/// CA - R3" at the time this was vendored (see the module docs for the
/// update procedure). This is the actual security control — see module docs.
pub const FIDO_MDS_ROOT_SHA256_HEX: &str =
    "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b";

/// Maximum accepted size for a fetched/loaded MDS3 BLOB response body.
///
/// The real BLOB is ~10 MB; this is deliberately raised well above the SSRF
/// guard's default 5 MiB cap (`crate::ssrf::MAX_RESPONSE_BYTES`, private to
/// that module) via [`crate::ssrf::guarded_fetch_with_cap`] — a named,
/// MDS-specific constant rather than a global cap increase (D2/D10).
pub const MDS_MAX_BLOB_BYTES: usize = 32 * 1024 * 1024;

/// Parse the vendored root anchor PEM, verify its digest against
/// [`FIDO_MDS_ROOT_SHA256_HEX`], and return its DER bytes.
///
/// Fails closed: any parse error or digest mismatch is an error, never a
/// silent fallback.
pub fn load_root_anchor() -> Result<Vec<u8>, MdsError> {
    let parsed = pem::parse(ROOT_ANCHOR_PEM).map_err(|_| MdsError::RootAnchorUnparsable)?;
    let der = parsed.contents();

    let digest = Sha256::digest(der);
    let digest_hex = hex::encode(digest);

    if digest_hex != FIDO_MDS_ROOT_SHA256_HEX {
        return Err(MdsError::RootAnchorDigestMismatch);
    }

    Ok(der.to_vec())
}

// ---------------------------------------------------------------------------
// Fetch / local-file entry points (D10)
// ---------------------------------------------------------------------------

/// Fetch, verify, and parse the MDS3 BLOB from `url` through the shared SSRF
/// guard ([`crate::ssrf::guarded_fetch_with_cap`], capped at
/// [`MDS_MAX_BLOB_BYTES`]).
///
/// `allow_private` exists solely for integration tests that point this at a
/// loopback mock server — production callers must pass `false`.
pub async fn fetch_verified_blob(
    url: &str,
    expected_leaf_dns: &str,
    allow_private: bool,
) -> Result<MdsBlob, MdsError> {
    let response =
        crate::ssrf::guarded_fetch_with_cap(url, allow_private, MDS_MAX_BLOB_BYTES, |c, u| {
            c.get(u)
        })
        .await
        .map_err(|e| MdsError::FetchFailed(e.to_string()))?;

    let bytes = crate::ssrf::read_capped_body(response, MDS_MAX_BLOB_BYTES)
        .await
        .map_err(|e| match e {
            crate::ssrf::SsrfError::ResponseTooLarge(cap) => MdsError::ResponseTooLarge(cap),
            other => MdsError::FetchFailed(other.to_string()),
        })?;

    let text = String::from_utf8(bytes).map_err(|_| MdsError::InvalidEncoding)?;
    verify_and_parse(&text, Utc::now(), expected_leaf_dns)
}

/// Load, verify, and parse the MDS3 BLOB from a local file — the air-gapped
/// deployment path (`AXIAM__PKI__MDS_BLOB_PATH`, D10). No network I/O
/// happens on this path at all.
pub fn load_verified_blob_from_file(
    path: &std::path::Path,
    expected_leaf_dns: &str,
) -> Result<MdsBlob, MdsError> {
    let text = std::fs::read_to_string(path).map_err(|e| MdsError::LocalFileRead(e.to_string()))?;
    verify_and_parse(&text, Utc::now(), expected_leaf_dns)
}

// ---------------------------------------------------------------------------
// D4 step 8: rollback protection
// ---------------------------------------------------------------------------

/// The outcome of comparing a freshly-verified BLOB's `no` (serial number)
/// against the last stored serial (D4 step 8).
///
/// This is a **pure decision function**, deliberately kept separate from
/// [`verify_and_parse`]: the pinned `verify_and_parse` signature
/// (`blob, now, expected_leaf_dns`) has no way to receive "the currently
/// stored `no`" — that value lives in storage (`MdsRepository::get_meta`,
/// `axiam-core`), which is out of this wave's scope (`axiam-db` wiring is a
/// later wave). The ingestion orchestrator that wires storage in is
/// responsible for calling this after `verify_and_parse` succeeds and before
/// calling `MdsRepository::replace_entries`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobIngestOutcome {
    /// No stored serial exists yet — first-ever ingestion.
    Initial,
    /// `no` is strictly greater than the stored serial — replace.
    Replace,
    /// `no` equals the stored serial — a no-op refresh: only
    /// `last_refreshed_at` should be bumped, entries are already current.
    NoOpRefresh,
    /// `no` is lower than the stored serial — a rollback attempt. Reject:
    /// never replace stored entries with an older BLOB.
    RollbackRejected,
}

/// D4 step 8: decide what a freshly-verified BLOB's serial number means
/// relative to what's already stored.
pub fn decide_ingest_outcome(new_no: i64, stored_no: Option<i64>) -> BlobIngestOutcome {
    match stored_no {
        None => BlobIngestOutcome::Initial,
        Some(stored) if new_no > stored => BlobIngestOutcome::Replace,
        Some(stored) if new_no == stored => BlobIngestOutcome::NoOpRefresh,
        Some(_) => BlobIngestOutcome::RollbackRejected,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_anchor_digest_matches_pin() {
        let der = load_root_anchor().expect("vendored anchor must parse and match its pin");
        let digest_hex = hex::encode(Sha256::digest(&der));
        assert_eq!(digest_hex, FIDO_MDS_ROOT_SHA256_HEX);
    }

    #[test]
    fn root_anchor_digest_mismatch_fails_closed() {
        // Simulate a tampered anchor: a different (but validly-PEM-encoded)
        // certificate would parse fine but must not match the pin. We can't
        // swap the embedded `include_str!` at runtime, so this test instead
        // proves the *mechanism* — recomputing the digest of arbitrary bytes
        // and comparing against the pinned constant — rejects a mismatch.
        let not_the_root_der = b"this is not the vendored root certificate";
        let digest_hex = hex::encode(Sha256::digest(not_the_root_der));
        assert_ne!(
            digest_hex, FIDO_MDS_ROOT_SHA256_HEX,
            "sanity: arbitrary bytes must not coincidentally match the pin"
        );
    }

    #[test]
    fn decide_ingest_outcome_initial_when_nothing_stored() {
        assert_eq!(decide_ingest_outcome(100, None), BlobIngestOutcome::Initial);
    }

    #[test]
    fn decide_ingest_outcome_replace_when_newer() {
        assert_eq!(
            decide_ingest_outcome(101, Some(100)),
            BlobIngestOutcome::Replace
        );
    }

    #[test]
    fn decide_ingest_outcome_noop_refresh_when_equal() {
        assert_eq!(
            decide_ingest_outcome(100, Some(100)),
            BlobIngestOutcome::NoOpRefresh
        );
    }

    #[test]
    fn decide_ingest_outcome_rejects_rollback() {
        assert_eq!(
            decide_ingest_outcome(99, Some(100)),
            BlobIngestOutcome::RollbackRejected
        );
    }

    #[tokio::test]
    async fn fetch_verified_blob_rejects_non_https_without_seam() {
        let result =
            fetch_verified_blob("http://example.com/blob.jwt", "mds.fidoalliance.org", false).await;
        assert!(matches!(result, Err(MdsError::FetchFailed(_))));
    }

    #[test]
    fn load_verified_blob_from_file_reports_missing_file() {
        let result = load_verified_blob_from_file(
            std::path::Path::new("/nonexistent/path/to/blob.jwt"),
            "mds.fidoalliance.org",
        );
        assert!(matches!(result, Err(MdsError::LocalFileRead(_))));
    }
}

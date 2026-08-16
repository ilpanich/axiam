//! Error type for FIDO MDS3 BLOB ingestion (X3).

/// Errors from fetching, verifying, and parsing a FIDO MDS3 BLOB.
///
/// Every variant here corresponds to a fail-closed rejection point in
/// [`crate::mds::blob::verify_and_parse`] or the fetch/load wrappers around
/// it — there is no variant that means "trust this anyway".
#[derive(Debug, thiserror::Error)]
pub enum MdsError {
    // -----------------------------------------------------------------
    // D3: vendored root anchor
    // -----------------------------------------------------------------
    #[error("vendored FIDO MDS root anchor PEM could not be parsed")]
    RootAnchorUnparsable,

    /// The vendored anchor's SHA-256 digest does not match the pinned
    /// constant. This must never happen for an untampered checkout — if it
    /// does, treat the build as compromised (see the module docs on
    /// `FIDO_MDS_ROOT_SHA256_HEX`).
    #[error(
        "vendored FIDO MDS root anchor digest mismatch — the anchor file may have been tampered with"
    )]
    RootAnchorDigestMismatch,

    // -----------------------------------------------------------------
    // D4 steps 1-3: JWT structure / header
    // -----------------------------------------------------------------
    #[error("malformed JWT: expected exactly 3 dot-separated segments")]
    MalformedJwt,

    #[error("JWT header is not valid base64url")]
    InvalidHeaderEncoding,

    #[error("JWT header is not valid JSON")]
    InvalidHeaderJson,

    /// The header's `alg` is not exactly `RS256`. Carries the rejected
    /// value (or `"none"`/absent) for diagnostics — never used to decide
    /// anything, only to report.
    #[error("unsupported JWT algorithm {0:?} — only RS256 is accepted")]
    UnsupportedAlgorithm(String),

    #[error("JWT header x5c claim is missing or empty")]
    MissingX5c,

    #[error("JWT header x5c claim has more than 8 entries")]
    X5cTooLong,

    #[error("JWT header x5c entry is not valid base64")]
    InvalidX5cEncoding,

    #[error("x5c certificate entry could not be parsed as DER: {0}")]
    InvalidCertificate(String),

    // -----------------------------------------------------------------
    // D4 step 4: chain build
    // -----------------------------------------------------------------
    #[error("a certificate in the x5c chain is outside its validity window")]
    CertificateExpired,

    #[error("x5c certificate chain signature verification failed")]
    ChainVerifyFailed,

    /// A certificate used as an issuer in the chain is not permitted to issue
    /// certificates (`basicConstraints` absent or `CA=false`, or `keyUsage`
    /// present without `keyCertSign`).
    ///
    /// This is the check that keeps the vendored anchor meaningful: without
    /// it, any holder of an ordinary end-entity certificate issued under the
    /// same public root could splice a self-minted leaf beneath their own
    /// certificate and produce a chain that verifies. See
    /// `blob::assert_is_issuer`.
    #[error("a certificate used as an issuer in the x5c chain is not a CA")]
    IssuerNotCa,

    #[error("x5c chain is deeper than an issuing certificate's pathLenConstraint permits")]
    PathLenExceeded,

    #[error("the x5c leaf certificate is itself a CA certificate")]
    LeafIsCa,

    // -----------------------------------------------------------------
    // D4 step 5: leaf identity pinning
    // -----------------------------------------------------------------
    #[error(
        "leaf certificate identity does not match the expected MDS hostname (checked SAN DNS names, falling back to CN only when no SAN extension is present)"
    )]
    LeafIdentityMismatch,

    // -----------------------------------------------------------------
    // D4 step 6: JWT signature
    // -----------------------------------------------------------------
    #[error("JWT signature verification failed")]
    SignatureInvalid,

    // -----------------------------------------------------------------
    // D4 steps 7-9: payload
    // -----------------------------------------------------------------
    #[error("BLOB payload is not valid JSON matching the expected MDS schema: {0}")]
    InvalidPayload(String),

    #[error("nextUpdate field could not be parsed as YYYY-MM-DD: {0}")]
    InvalidNextUpdate(String),

    // -----------------------------------------------------------------
    // Fetch / local-file paths (D10)
    // -----------------------------------------------------------------
    #[error("MDS BLOB fetch failed: {0}")]
    FetchFailed(String),

    #[error("MDS BLOB response exceeded the {0}-byte cap")]
    ResponseTooLarge(usize),

    #[error("MDS BLOB response was not valid UTF-8")]
    InvalidEncoding,

    #[error("local MDS BLOB file could not be read: {0}")]
    LocalFileRead(String),

    #[error("MDS ingestion is disabled (AXIAM__PKI__MDS_ENABLED=false)")]
    IngestionDisabled,
}

impl From<MdsError> for axiam_core::error::AxiamError {
    fn from(err: MdsError) -> Self {
        use axiam_core::error::AxiamError;
        match err {
            // Upstream/network problems — not our bug, mirrors
            // axiam-federation's FederationError -> AxiamError mapping for
            // the same class of failure.
            MdsError::FetchFailed(msg) => AxiamError::ServiceUnavailable(msg),
            MdsError::IngestionDisabled => AxiamError::Validation {
                message: err.to_string(),
            },
            // Everything else is a verification/parsing failure: the BLOB
            // (or its vendored anchor) failed a security-relevant check.
            // None of these should ever be shown to an end user verbatim —
            // callers log/audit the specific variant and surface a fixed
            // message, same posture as WebauthnAttestationDenied (D11).
            other => AxiamError::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamError;

    /// The mapping's security posture, not its plumbing: every verification
    /// failure must land on `Internal`, because those messages name which
    /// security-relevant check the BLOB failed and are for the audit log rather
    /// than for an end user. Only the two genuinely operational variants are
    /// allowed out of that bucket.
    #[test]
    fn only_operational_variants_escape_the_internal_bucket() {
        assert!(matches!(
            AxiamError::from(MdsError::FetchFailed("connection reset".into())),
            AxiamError::ServiceUnavailable(_)
        ));
        assert!(matches!(
            AxiamError::from(MdsError::IngestionDisabled),
            AxiamError::Validation { .. }
        ));

        // A representative from each verification stage — anchor, JWT shape,
        // chain, identity, signature and payload. Each is a failure an operator
        // investigates from the log, never a message a caller should act on.
        let verification_failures = vec![
            MdsError::RootAnchorUnparsable,
            MdsError::RootAnchorDigestMismatch,
            MdsError::MalformedJwt,
            MdsError::InvalidHeaderEncoding,
            MdsError::InvalidHeaderJson,
            MdsError::UnsupportedAlgorithm("HS256".into()),
            MdsError::MissingX5c,
            MdsError::X5cTooLong,
            MdsError::InvalidX5cEncoding,
            MdsError::InvalidCertificate("bad der".into()),
            MdsError::CertificateExpired,
            MdsError::ChainVerifyFailed,
            MdsError::IssuerNotCa,
            MdsError::PathLenExceeded,
            MdsError::LeafIsCa,
            MdsError::LeafIdentityMismatch,
            MdsError::SignatureInvalid,
            MdsError::InvalidPayload("not an object".into()),
            MdsError::InvalidNextUpdate("2026-13-45".into()),
            MdsError::ResponseTooLarge(1024),
            MdsError::InvalidEncoding,
            MdsError::LocalFileRead("permission denied".into()),
        ];

        for err in verification_failures {
            let rendered = err.to_string();
            assert!(
                !rendered.is_empty(),
                "every variant must render a diagnosable message"
            );
            match AxiamError::from(err) {
                AxiamError::Internal(msg) => assert_eq!(
                    msg, rendered,
                    "the Internal message must preserve the variant's own text for the audit log"
                ),
                other => panic!("{rendered} escaped the Internal bucket as {other:?}"),
            }
        }
    }

    /// `FetchFailed` is the one variant whose text reaches a caller (through
    /// ServiceUnavailable), so it carries the upstream detail rather than a
    /// rendered wrapper — a caller retrying a 503 needs to know why.
    #[test]
    fn fetch_failed_passes_the_upstream_message_through_verbatim() {
        match AxiamError::from(MdsError::FetchFailed("dns failure".into())) {
            AxiamError::ServiceUnavailable(msg) => assert_eq!(msg, "dns failure"),
            other => panic!("unexpected mapping: {other:?}"),
        }
    }

    #[test]
    fn parameterised_variants_name_their_parameter() {
        assert!(
            MdsError::ResponseTooLarge(4096)
                .to_string()
                .contains("4096")
        );
        assert!(
            MdsError::UnsupportedAlgorithm("none".into())
                .to_string()
                .contains("none")
        );
        assert!(
            MdsError::InvalidNextUpdate("nope".into())
                .to_string()
                .contains("nope")
        );
    }
}

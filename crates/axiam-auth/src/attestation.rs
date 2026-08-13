//! X3 wave 2 — attestation CA-list building/caching (spec D7, addendum
//! W2-D3) and the pure per-credential compliance-evaluation helper (spec D9,
//! the endpoint itself is later-wave REST work).
//!
//! ## Why this depends on `AttestationMetadataSource`, not `axiam-pki` (W2-D4)
//!
//! `axiam-auth` needs three things to enforce the attestation policy: the
//! effective [`WebauthnAttestationPolicy`] (resolved by the caller from
//! `WebauthnAttestationPolicyRepository` — an absent row means the default,
//! D5 — before calling into [`crate::webauthn::WebauthnService`]), an AAGUID
//! → [`MdsEntry`] lookup, and the DER attestation roots needed to build a
//! `webauthn-rs` `AttestationCaList`. The last two are exactly
//! [`AttestationMetadataSource`] (`axiam-core`, implemented over
//! `MdsRepository` in `axiam-db`). Depending on that small, data-only trait
//! rather than on `axiam-pki` directly turned out to be cheap — nothing in
//! this module or `crate::webauthn` needs `axiam-pki`'s certificate/JWT
//! verification types, only plain `MdsEntry`/DER-bytes data — so the W2-D4
//! preferred option is what shipped; `axiam-auth`'s `Cargo.toml` gained no
//! new dependency for X3.
//!
//! ## The CA-list cache (W2-D3)
//!
//! Building an `AttestationCaList` means an OpenSSL `X509::from_der` parse
//! per attestation root (up to ~255 unique certs on the live MDS BLOB,
//! addendum W2-D2) — cheap once, wasteful to repeat on every registration
//! start. [`AttestationCaCache`] follows the same shape as the other
//! process-wide caches in this codebase (`axiam_authz::decision_cache`,
//! `axiam_api_rest::tenant_org_cache`): a plain `Mutex`-guarded map, built
//! lazily, invalidated wholesale rather than per-key. Unlike those, it has no
//! TTL — nothing here goes stale on its own; it is stale only when its two
//! trigger events happen (an MDS refresh changes which roots exist, or a
//! tenant's `allowed_aaguids` changes which subset applies), and both are
//! discrete mutations the caller can hook directly rather than needing a
//! time-based fallback. `axiam-server` wiring those two triggers to
//! [`AttestationCaCache::invalidate`] is later-wave work; this module ships
//! the cache with an `invalidate` a caller can already reach.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use axiam_core::error::AxiamResult;
use axiam_core::models::webauthn_policy::{
    AttestationCandidate, AttestationDecision, AttestationDenyReason, AttestationMode,
    WebauthnAttestationPolicy, evaluate,
};
use axiam_core::repository::AttestationMetadataSource;
use uuid::Uuid;
use webauthn_rs::prelude::{AttestationCaList, AttestationCaListBuilder};

/// The fixed, non-specific reason text for a credential with no recorded
/// AAGUID (D9): "report them as `unknown` ... never as a violation". A
/// legacy credential predating X3, not a policy failure.
pub const UNKNOWN_CREDENTIAL_REASON: &str = "registered before attestation policy was enabled";

// ---------------------------------------------------------------------------
// CA-list cache (W2-D3)
// ---------------------------------------------------------------------------

/// Cache key: `None` = every MDS-known root (no `allowed_aaguids`
/// restriction); `Some(sorted, deduped aaguids)` = the filtered subset.
/// Sorting/deduping in [`cache_key`] makes two policies with the same
/// allowlist in different orders share one cache entry.
type CacheKey = Option<Vec<Uuid>>;

fn cache_key(allowed_aaguids: Option<&[Uuid]>) -> CacheKey {
    allowed_aaguids.map(|ids| {
        let mut v = ids.to_vec();
        v.sort_unstable();
        v.dedup();
        v
    })
}

/// Process-wide cache of built `AttestationCaList`s, keyed by the
/// `allowed_aaguids` restriction that produced them. See the module docs for
/// the invalidation contract.
#[derive(Default)]
pub struct AttestationCaCache {
    entries: Mutex<HashMap<CacheKey, Arc<AttestationCaList>>>,
}

impl AttestationCaCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every cached list. Call after an MDS refresh (the set of known
    /// roots changed) or an attestation-policy update (the
    /// `allowed_aaguids` restriction changed) — both invalidate the trust
    /// picture a previously-built list encoded (W2-D3).
    pub fn invalidate(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

    /// Number of distinct filters currently cached (test/observability
    /// helper).
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the cached `AttestationCaList` for `allowed_aaguids`, building
    /// and caching it on a miss.
    ///
    /// `allowed_aaguids: Some(list)` restricts the built list to those
    /// AAGUIDs (W2-D3: "the cryptographic layer and the policy layer
    /// agree"); `None` builds a list that accepts every AAGUID MDS has
    /// metadata for.
    pub async fn get_or_build<M: AttestationMetadataSource>(
        &self,
        metadata: &M,
        allowed_aaguids: Option<&[Uuid]>,
    ) -> AxiamResult<Arc<AttestationCaList>> {
        let key = cache_key(allowed_aaguids);
        if let Some(hit) = self
            .entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&key)
        {
            return Ok(Arc::clone(hit));
        }

        let built = Arc::new(build_ca_list(metadata, key.as_deref()).await?);
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(key, Arc::clone(&built));
        Ok(built)
    }
}

async fn build_ca_list<M: AttestationMetadataSource>(
    metadata: &M,
    allowed_aaguids: Option<&[Uuid]>,
) -> AxiamResult<AttestationCaList> {
    let roots = metadata.attestation_roots(allowed_aaguids).await?;
    let mut builder = AttestationCaListBuilder::new();
    for root in roots {
        // A single malformed root (a corrupt DER blob, however it got that
        // way) must not take down the whole list — skip and log it rather
        // than failing every registration for every OTHER authenticator.
        if let Err(e) = builder.insert_device_der(
            &root.der,
            root.aaguid,
            root.description.clone(),
            BTreeMap::new(),
        ) {
            tracing::warn!(
                aaguid = %root.aaguid,
                error = %e,
                "skipping MDS attestation root that failed to parse as X.509 DER"
            );
        }
    }
    Ok(builder.build())
}

// ---------------------------------------------------------------------------
// Compliance evaluation (D9's pure half)
// ---------------------------------------------------------------------------

/// The outcome of evaluating one stored credential against the *current*
/// policy (D9). Never causes a mutation — revocation stays the existing
/// admin credential-delete path (D7/D9: "never auto-revokes").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant(AttestationDenyReason),
    /// No recorded AAGUID — a credential registered before X3 shipped (D6:
    /// `aaguid` is `None` for every pre-X3 row). Always reported this way,
    /// **never** as a violation, regardless of what the current policy says.
    Unknown,
}

impl ComplianceStatus {
    /// `true` only for [`ComplianceStatus::NonCompliant`] — an `Unknown`
    /// credential is explicitly not a violation (D9).
    pub fn is_violation(self) -> bool {
        matches!(self, ComplianceStatus::NonCompliant(_))
    }
}

/// Evaluate one credential's stored `aaguid`/`attestation_format` (D6)
/// against the tenant's *current* [`WebauthnAttestationPolicy`] (D9).
///
/// Pure with respect to the policy engine — this only adds the two lookups
/// `axiam_core::models::webauthn_policy::evaluate` needs (the MDS entry) on
/// top of it; it does not itself decide anything `evaluate` doesn't already
/// decide, and it never mutates or deletes anything.
///
/// A credential with `aaguid: None` (every pre-X3 row, and any authenticator
/// that legitimately reports no AAGUID) is always [`ComplianceStatus::Unknown`],
/// checked **before** the `mode == None` short-circuit below so the ordering
/// matches D9 literally regardless of the tenant's current mode. For a
/// present AAGUID, `mode == None` still skips the MDS lookup entirely
/// (mirroring `evaluate`'s own D8-step-1 guarantee: a `mode: none` tenant
/// makes no MDS lookups on the registration path either, so the compliance
/// report should not either).
pub async fn evaluate_credential_compliance<M: AttestationMetadataSource>(
    policy: &WebauthnAttestationPolicy,
    aaguid: Option<Uuid>,
    attestation_format: Option<&str>,
    metadata: &M,
) -> AxiamResult<ComplianceStatus> {
    let Some(aaguid) = aaguid else {
        return Ok(ComplianceStatus::Unknown);
    };

    if policy.mode == AttestationMode::None {
        return Ok(ComplianceStatus::Compliant);
    }

    let entry = metadata.get_entry(aaguid).await?;
    let candidate = AttestationCandidate {
        aaguid: Some(aaguid),
        attestation_format,
        mds_entry: entry.as_ref(),
    };

    Ok(match evaluate(policy, &candidate) {
        AttestationDecision::Allow => ComplianceStatus::Compliant,
        AttestationDecision::Deny(reason) => ComplianceStatus::NonCompliant(reason),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::AxiamResult;
    use axiam_core::models::mds::{
        CertificationLevel, MdsAuthenticatorStatus, MdsEntry, MdsStatusReport,
    };
    use axiam_core::models::webauthn_policy::UnknownAaguidAction;
    use axiam_core::repository::AttestationRootMaterial;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A real, self-signed Ed25519 X.509 certificate (`CN=axiam-test-root`,
    /// generated once with `openssl req -x509 -newkey ed25519 ...` and
    /// vendored here as DER/base64 — no new dependency needed to produce a
    /// certificate `insert_device_der` will actually parse; the cache never
    /// verifies a chain, it only needs *some* valid X.509 DER).
    const TEST_ROOT_DER_B64: &str = "MIIBSDCB+6ADAgECAhQDiCypHmzEedN6JiRFDyTXDBUgRTAFBgMrZXAwGjEYMBYGA1UEAwwPYXhpYW0tdGVzdC1yb290MB4XDTI2MDgxMzA4MjcwOFoXDTM2MDgxMDA4MjcwOFowGjEYMBYGA1UEAwwPYXhpYW0tdGVzdC1yb290MCowBQYDK2VwAyEAyypYyUSxb2Q2w4Oz0JcGvoSJNHAsOCvC4s1wElt2yv6jUzBRMB0GA1UdDgQWBBQ5bN+q4O+R/Q4nq5Sq7Mc7GFMcuTAfBgNVHSMEGDAWgBQ5bN+q4O+R/Q4nq5Sq7Mc7GFMcuTAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAL3cY5942daBVLRMfhDxBVL02x8Ps7eO5Sokw1mRyX+OcrdRXhRbjl9+8FBtbXiAp4F0JSLg6JWzYC+gQ8AVcQQ=";

    fn self_signed_der(_cn: &str) -> Vec<u8> {
        STANDARD
            .decode(TEST_ROOT_DER_B64)
            .expect("vendored test DER must decode")
    }

    fn uuid(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    #[derive(Default)]
    struct MockMetadata {
        entries: HashMap<Uuid, MdsEntry>,
        roots: Vec<AttestationRootMaterial>,
        attestation_roots_calls: AtomicUsize,
    }

    impl AttestationMetadataSource for MockMetadata {
        async fn get_entry(&self, aaguid: Uuid) -> AxiamResult<Option<MdsEntry>> {
            Ok(self.entries.get(&aaguid).cloned())
        }

        async fn attestation_roots(
            &self,
            allowed_aaguids: Option<&[Uuid]>,
        ) -> AxiamResult<Vec<AttestationRootMaterial>> {
            self.attestation_roots_calls.fetch_add(1, Ordering::SeqCst);
            let roots = match allowed_aaguids {
                Some(allowed) => self
                    .roots
                    .iter()
                    .filter(|r| allowed.contains(&r.aaguid))
                    .cloned()
                    .collect(),
                None => self.roots.clone(),
            };
            Ok(roots)
        }
    }

    // --- AttestationCaCache ---

    #[tokio::test]
    async fn empty_metadata_builds_an_empty_list() {
        let cache = AttestationCaCache::new();
        let metadata = MockMetadata::default();
        let list = cache.get_or_build(&metadata, None).await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn builds_a_nonempty_list_from_one_root() {
        let cache = AttestationCaCache::new();
        let id = uuid(1);
        let metadata = MockMetadata {
            roots: vec![AttestationRootMaterial {
                aaguid: id,
                der: self_signed_der("test-root"),
                description: "Test Authenticator".into(),
            }],
            ..Default::default()
        };
        let list = cache.get_or_build(&metadata, None).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn malformed_der_is_skipped_not_fatal() {
        let cache = AttestationCaCache::new();
        let good = uuid(1);
        let bad = uuid(2);
        let metadata = MockMetadata {
            roots: vec![
                AttestationRootMaterial {
                    aaguid: bad,
                    der: b"not a certificate".to_vec(),
                    description: "Bad".into(),
                },
                AttestationRootMaterial {
                    aaguid: good,
                    der: self_signed_der("good-root"),
                    description: "Good".into(),
                },
            ],
            ..Default::default()
        };
        let list = cache.get_or_build(&metadata, None).await.unwrap();
        assert_eq!(list.len(), 1, "only the parseable root survives");
    }

    #[tokio::test]
    async fn second_call_with_same_filter_is_served_from_cache() {
        let cache = AttestationCaCache::new();
        let metadata = MockMetadata::default();
        cache.get_or_build(&metadata, None).await.unwrap();
        cache.get_or_build(&metadata, None).await.unwrap();
        assert_eq!(
            metadata.attestation_roots_calls.load(Ordering::SeqCst),
            1,
            "the second call must hit the cache, not the metadata source again"
        );
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn distinct_allowed_aaguid_filters_are_cached_separately() {
        let cache = AttestationCaCache::new();
        let a = uuid(1);
        let b = uuid(2);
        let metadata = MockMetadata::default();
        cache.get_or_build(&metadata, Some(&[a])).await.unwrap();
        cache.get_or_build(&metadata, Some(&[b])).await.unwrap();
        cache.get_or_build(&metadata, None).await.unwrap();
        assert_eq!(cache.len(), 3);
    }

    #[tokio::test]
    async fn reordered_allowlist_shares_one_cache_entry() {
        let cache = AttestationCaCache::new();
        let a = uuid(1);
        let b = uuid(2);
        let metadata = MockMetadata::default();
        cache.get_or_build(&metadata, Some(&[a, b])).await.unwrap();
        cache.get_or_build(&metadata, Some(&[b, a])).await.unwrap();
        assert_eq!(
            cache.len(),
            1,
            "the same set in a different order must hit the same cache entry"
        );
        assert_eq!(metadata.attestation_roots_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invalidate_clears_every_entry() {
        let cache = AttestationCaCache::new();
        let metadata = MockMetadata::default();
        cache.get_or_build(&metadata, None).await.unwrap();
        cache
            .get_or_build(&metadata, Some(&[uuid(1)]))
            .await
            .unwrap();
        assert!(!cache.is_empty());
        cache.invalidate();
        assert!(cache.is_empty());
    }

    // --- evaluate_credential_compliance ---

    fn entry_with_status(aaguid: Uuid, status: MdsAuthenticatorStatus) -> MdsEntry {
        MdsEntry {
            aaguid,
            description: Some("Test".into()),
            attestation_root_certificates: Vec::new(),
            status_reports: vec![MdsStatusReport {
                status,
                effective_date: None,
                certification_descriptor: None,
            }],
            time_of_last_status_change: None,
        }
    }

    #[tokio::test]
    async fn no_aaguid_is_always_unknown_even_under_direct_required() {
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            ..WebauthnAttestationPolicy::default()
        };
        let metadata = MockMetadata::default();
        let status = evaluate_credential_compliance(&policy, None, Some("packed"), &metadata)
            .await
            .unwrap();
        assert_eq!(status, ComplianceStatus::Unknown);
        assert!(!status.is_violation(), "unknown must never be a violation");
    }

    #[tokio::test]
    async fn mode_none_is_compliant_without_an_mds_lookup() {
        let policy = WebauthnAttestationPolicy::default(); // mode: None
        let id = uuid(3);
        let metadata = MockMetadata {
            entries: HashMap::from([(id, entry_with_status(id, MdsAuthenticatorStatus::Revoked))]),
            ..Default::default()
        };
        let status = evaluate_credential_compliance(&policy, Some(id), Some("packed"), &metadata)
            .await
            .unwrap();
        // Even a REVOKED entry is Compliant under mode: none — D8 step 1's
        // "no attestation requested, nothing to police" guarantee.
        assert_eq!(status, ComplianceStatus::Compliant);
    }

    #[tokio::test]
    async fn revoked_entry_is_noncompliant_under_direct_required() {
        let id = uuid(4);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::DirectRequired,
            unknown_aaguid: Some(UnknownAaguidAction::Allow),
            ..WebauthnAttestationPolicy::default()
        };
        let metadata = MockMetadata {
            entries: HashMap::from([(id, entry_with_status(id, MdsAuthenticatorStatus::Revoked))]),
            ..Default::default()
        };
        let status = evaluate_credential_compliance(&policy, Some(id), Some("packed"), &metadata)
            .await
            .unwrap();
        assert_eq!(
            status,
            ComplianceStatus::NonCompliant(AttestationDenyReason::AuthenticatorRevoked)
        );
        assert!(status.is_violation());
    }

    #[tokio::test]
    async fn compliant_entry_reports_compliant() {
        let id = uuid(5);
        let policy = WebauthnAttestationPolicy {
            mode: AttestationMode::Indirect,
            min_certification: Some(CertificationLevel::L1),
            unknown_aaguid: Some(UnknownAaguidAction::Allow),
            ..WebauthnAttestationPolicy::default()
        };
        let metadata = MockMetadata {
            entries: HashMap::from([(
                id,
                entry_with_status(id, MdsAuthenticatorStatus::FidoCertifiedL2),
            )]),
            ..Default::default()
        };
        let status = evaluate_credential_compliance(&policy, Some(id), Some("packed"), &metadata)
            .await
            .unwrap();
        assert_eq!(status, ComplianceStatus::Compliant);
        assert!(!status.is_violation());
    }
}

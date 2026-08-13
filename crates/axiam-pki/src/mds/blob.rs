//! FIDO MDS3 BLOB verification and parsing (D4).
//!
//! [`verify_and_parse`] implements D4 steps 1-9 in the pinned order. Every
//! step fails closed: there is no code path that returns a parsed
//! [`MdsBlob`] without every prior step having succeeded.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use chrono::{DateTime, NaiveDate, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use uuid::Uuid;
use x509_parser::prelude::*;

use axiam_core::models::mds::{MdsBlobMeta, MdsEntry, MdsStatusReport};

use super::MdsError;
use super::load_root_anchor;

/// Header `alg` values accepted for an MDS3 BLOB (D4 step 2). Exactly one —
/// `none` and every other algorithm are rejected with a distinct error, and
/// this is the *only* place `alg` is ever read from: it never influences
/// parsing before this check, and the payload is never consulted for it.
const ALLOWED_ALG: &str = "RS256";

/// Maximum accepted number of certificates in the JWT header's `x5c` claim
/// (D4 step 3) — bounds the chain-walk below against a pathologically long
/// (attacker-controlled) header.
const MAX_X5C_LEN: usize = 8;

/// Assert that a certificate is allowed to *issue* other certificates.
///
/// This is not a nicety, it is the control that makes the vendored anchor
/// mean anything. GlobalSign Root CA – R3 is a **public** CA root: it sits
/// above the certificates of the entire public web, not just the FIDO
/// Alliance's. Verifying signatures alone — "each `x5c[i]` verifies under
/// `x5c[i+1]`, and the last one verifies under our root" — is therefore
/// satisfied by a chain an attacker can assemble from an *ordinary*
/// end-entity certificate:
///
/// ```text
///   x5c = [ forged leaf (SAN mds.fidoalliance.org, signed by the attacker),
///           attacker's genuine EE cert (genuinely issued under R3),
///           genuine GlobalSign intermediate ]
/// ```
///
/// Every signature in that chain verifies, and the forged leaf carries
/// whatever SAN the attacker chose — so leaf-identity pinning does not stop
/// it either. What stops it is refusing to treat a non-CA certificate as an
/// issuer: an ordinary EE certificate carries `basicConstraints: CA=false`
/// (or omits the extension), so it can never be `x5c[i+1]`.
///
/// Requires, for every issuing position in the chain:
/// - `basicConstraints` present with `CA=true`; and
/// - if `keyUsage` is present, `keyCertSign` asserted (absent `keyUsage` is
///   permitted — it is optional in RFC 5280 and some older CA certificates
///   omit it — but a present-and-contradictory one is fatal).
fn assert_is_issuer(cert: &X509Certificate<'_>) -> Result<(), MdsError> {
    let bc = cert
        .basic_constraints()
        .map_err(|e| MdsError::InvalidCertificate(e.to_string()))?;
    match bc {
        Some(ext) if ext.value.ca => {}
        _ => return Err(MdsError::IssuerNotCa),
    }

    if let Some(ku) = cert
        .key_usage()
        .map_err(|e| MdsError::InvalidCertificate(e.to_string()))?
        && !ku.value.key_cert_sign()
    {
        return Err(MdsError::IssuerNotCa);
    }

    Ok(())
}

/// Assert that the chain's path-length constraints are respected.
///
/// `pathLenConstraint` on a CA certificate bounds how many intermediates may
/// appear *below* it. Ignoring it would let an attacker who controls a
/// deliberately-constrained sub-CA extend the chain further than its issuer
/// permitted. `depth_below` is the number of non-self-issued CA certificates
/// between this certificate and the leaf.
fn assert_path_len(cert: &X509Certificate<'_>, depth_below: usize) -> Result<(), MdsError> {
    let bc = cert
        .basic_constraints()
        .map_err(|e| MdsError::InvalidCertificate(e.to_string()))?;
    if let Some(ext) = bc
        && let Some(max) = ext.value.path_len_constraint
        && depth_below as u64 > max as u64
    {
        return Err(MdsError::PathLenExceeded);
    }
    Ok(())
}

/// A verified, parsed FIDO MDS3 BLOB: metadata plus every entry that carried
/// an AAGUID.
#[derive(Debug, Clone)]
pub struct MdsBlob {
    pub meta: MdsBlobMeta,
    pub entries: Vec<MdsEntry>,
}

// ---------------------------------------------------------------------------
// Raw payload shape (D4 step 7) — mirrors the FIDO MDS3 JSON schema exactly,
// including its camelCase field names and the split between entry-level and
// metadataStatement-level fields. Converted into the flat, storage-shaped
// `axiam_core::models::mds::MdsEntry` by `convert_entries` below.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawMdsPayload {
    no: i64,
    #[serde(rename = "nextUpdate")]
    next_update: String,
    #[serde(default)]
    entries: Vec<RawMdsEntry>,
}

#[derive(Debug, Deserialize)]
struct RawMdsEntry {
    /// Present for FIDO2/WebAuthn authenticators. Absent for legacy UAF/U2F
    /// entries (keyed by `aaid`/`attestationCertificateKeyIdentifiers`
    /// instead) — those are skipped by `convert_entries` (D1).
    #[serde(default)]
    aaguid: Option<String>,
    #[serde(default, rename = "metadataStatement")]
    metadata_statement: Option<RawMetadataStatement>,
    #[serde(default, rename = "statusReports")]
    status_reports: Vec<MdsStatusReport>,
    #[serde(default, rename = "timeOfLastStatusChange")]
    time_of_last_status_change: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawMetadataStatement {
    #[serde(default)]
    description: Option<String>,
    #[serde(default, rename = "attestationRootCertificates")]
    attestation_root_certificates: Vec<String>,
}

/// Convert raw payload entries into storage-shaped [`MdsEntry`] values,
/// skipping (and counting) entries with no `aaguid` — UAF/U2F entries, and
/// defensively any entry whose `aaguid` fails to parse as a UUID (D1).
fn convert_entries(raw: Vec<RawMdsEntry>) -> (Vec<MdsEntry>, usize) {
    let mut entries = Vec::with_capacity(raw.len());
    let mut skipped = 0usize;

    for e in raw {
        let aaguid = match e.aaguid.as_deref().map(Uuid::parse_str) {
            Some(Ok(id)) => id,
            _ => {
                skipped += 1;
                continue;
            }
        };

        let (description, attestation_root_certificates) = match e.metadata_statement {
            Some(ms) => (ms.description, ms.attestation_root_certificates),
            None => (None, Vec::new()),
        };

        entries.push(MdsEntry {
            aaguid,
            description,
            attestation_root_certificates,
            status_reports: e.status_reports,
            time_of_last_status_change: e.time_of_last_status_change,
        });
    }

    (entries, skipped)
}

// ---------------------------------------------------------------------------
// D4: verify_and_parse
// ---------------------------------------------------------------------------

/// Verify a FIDO MDS3 BLOB's signature chain back to the vendored root
/// anchor and parse its payload, in the exact order pinned by D4:
///
/// 1. Split into exactly 3 dot-separated segments; decode the header.
/// 2. Header `alg` must be exactly `RS256` — reject `none` and anything else.
/// 3. `x5c` must be present, non-empty, and ≤ 8 entries (standard base64 DER).
/// 4. Build the chain: every cert's validity window covers `now`; each
///    `x5c[i]` verifies under `x5c[i+1]`'s key; the last `x5c` cert verifies
///    under the vendored root's key (or, if it *is* the vendored root by DER
///    equality, the cert before it does — via the same per-`i` chain check).
/// 5. The leaf (`x5c[0]`) must carry `expected_leaf_dns` as a SAN DNS entry
///    (falling back to CN only when there is no SAN extension at all).
/// 6. Verify the JWT signature over `header.payload` with the leaf's RSA
///    public key.
/// 7. Only now does the payload JSON get parsed.
/// 8. Rollback protection is **not** performed here — see
///    [`super::decide_ingest_outcome`] and its doc comment for why.
/// 9. `nextUpdate < now` marks the result `stale`, logged at WARN; ingestion
///    still succeeds — staleness never hard-fails, policy decides.
///
/// Fails closed at every step: no branch returns `Ok` without every prior
/// check having passed.
pub fn verify_and_parse(
    blob: &str,
    now: DateTime<Utc>,
    expected_leaf_dns: &str,
) -> Result<MdsBlob, MdsError> {
    let root_der = load_root_anchor()?;
    verify_and_parse_with_anchor(blob, now, expected_leaf_dns, &root_der)
}

/// [`verify_and_parse`] with the trust anchor supplied by the caller instead
/// of loaded from the vendored PEM.
///
/// This is the single implementation — [`verify_and_parse`] is a thin wrapper
/// that passes the vendored anchor. The parameterization exists so the test
/// suite can drive **this exact code path** against a throwaway root, rather
/// than against a copy of it: a test that re-implements the logic it is
/// meant to guard silently stops guarding it the moment the two diverge, and
/// this pipeline is precisely where a silent divergence is most expensive.
pub fn verify_and_parse_with_anchor(
    blob: &str,
    now: DateTime<Utc>,
    expected_leaf_dns: &str,
    root_der: &[u8],
) -> Result<MdsBlob, MdsError> {
    // --- Step 1: exactly 3 segments; decode header ---
    let parts: Vec<&str> = blob.split('.').collect();
    if parts.len() != 3 {
        return Err(MdsError::MalformedJwt);
    }
    let header_b64 = parts[0];

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| MdsError::InvalidHeaderEncoding)?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| MdsError::InvalidHeaderJson)?;

    // --- Step 2: alg must be exactly RS256. Never read from the payload. ---
    let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
    if alg != ALLOWED_ALG {
        return Err(MdsError::UnsupportedAlgorithm(alg.to_string()));
    }

    // --- Step 3: x5c present, non-empty, <= 8 entries, standard base64 DER ---
    let x5c_json = header.get("x5c").and_then(|v| v.as_array());
    let x5c_json = match x5c_json {
        Some(arr) if !arr.is_empty() => arr,
        _ => return Err(MdsError::MissingX5c),
    };
    if x5c_json.len() > MAX_X5C_LEN {
        return Err(MdsError::X5cTooLong);
    }

    let mut cert_ders: Vec<Vec<u8>> = Vec::with_capacity(x5c_json.len());
    for v in x5c_json {
        let s = v.as_str().ok_or(MdsError::InvalidX5cEncoding)?;
        let der = STANDARD
            .decode(s)
            .map_err(|_| MdsError::InvalidX5cEncoding)?;
        cert_ders.push(der);
    }

    let mut certs: Vec<X509Certificate<'_>> = Vec::with_capacity(cert_ders.len());
    for der in &cert_ders {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| MdsError::InvalidCertificate(e.to_string()))?;
        certs.push(cert);
    }

    // --- Step 4: chain build ---
    let now_ts = now.timestamp();
    for cert in &certs {
        let validity = cert.validity();
        if now_ts < validity.not_before.timestamp() || now_ts > validity.not_after.timestamp() {
            return Err(MdsError::CertificateExpired);
        }
    }

    let n = certs.len();
    for i in 0..n.saturating_sub(1) {
        // `certs[i + 1]` is being used as an ISSUER here, so it must actually
        // be permitted to issue — see `assert_is_issuer` for why signature
        // verification alone is not enough under a public CA root.
        assert_is_issuer(&certs[i + 1])?;
        assert_path_len(&certs[i + 1], i)?;
        certs[i]
            .verify_signature(Some(certs[i + 1].public_key()))
            .map_err(|_| MdsError::ChainVerifyFailed)?;
    }

    let (_, root_cert) = X509Certificate::from_der(root_der)
        .map_err(|_| MdsError::InvalidCertificate("root anchor".into()))?;
    let last = certs.last().expect("x5c is non-empty, checked above");
    let last_is_root = last.as_raw() == root_der;
    if !last_is_root {
        // The last x5c entry is not our root itself, so it must be directly
        // signed BY our root (the common real-world shape: x5c carries only
        // leaf + intermediate, no root).
        assert_is_issuer(&root_cert)?;
        assert_path_len(&root_cert, n.saturating_sub(1))?;
        last.verify_signature(Some(root_cert.public_key()))
            .map_err(|_| MdsError::ChainVerifyFailed)?;
    }
    // If `last_is_root`, the per-`i` loop above already verified `certs[n-2]`
    // (the cert before it, if any) against `certs[n-1]`'s public key — and
    // `certs[n-1]` IS byte-identical to our trusted anchor, so that check
    // already used the real trusted key, and `assert_is_issuer` already ran
    // against it in that same iteration. No further action needed.

    // The leaf must NOT itself be a CA: a chain that ends in an issuing
    // certificate would let whoever holds it mint further certificates that
    // this verifier would then accept.
    if certs[0].is_ca() {
        return Err(MdsError::LeafIsCa);
    }

    // --- Step 5: leaf identity pinning ---
    let leaf = &certs[0];
    let leaf_matches = match leaf
        .subject_alternative_name()
        .map_err(|e| MdsError::InvalidCertificate(e.to_string()))?
    {
        Some(ext) => ext.value.general_names.iter().any(
            |gn| matches!(gn, GeneralName::DNSName(d) if d.eq_ignore_ascii_case(expected_leaf_dns)),
        ),
        // No SAN extension at all -> fall back to CN (D4 step 5).
        None => leaf
            .subject()
            .iter_common_name()
            .filter_map(|atv| atv.as_str().ok())
            .any(|cn| cn.eq_ignore_ascii_case(expected_leaf_dns)),
    };
    if !leaf_matches {
        return Err(MdsError::LeafIdentityMismatch);
    }

    // --- Step 6: verify the JWT signature with the leaf's RSA public key ---
    let spki = leaf.public_key();
    let decoding_key = DecodingKey::from_rsa_der(spki.subject_public_key.data.as_ref());
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let token_data = jsonwebtoken::decode::<serde_json::Value>(blob, &decoding_key, &validation)
        .map_err(|_| MdsError::SignatureInvalid)?;

    // --- Step 7: only now does the payload get parsed ---
    let raw_payload: RawMdsPayload = serde_json::from_value(token_data.claims)
        .map_err(|e| MdsError::InvalidPayload(e.to_string()))?;

    let (entries, skipped) = convert_entries(raw_payload.entries);
    if skipped > 0 {
        tracing::info!(
            skipped_entries = skipped,
            "MDS BLOB: skipped entries with no (or unparsable) aaguid — UAF/U2F entries"
        );
    }

    // --- Step 9: staleness (step 8, rollback, is handled by the caller —
    // see super::decide_ingest_outcome) ---
    let next_update = NaiveDate::parse_from_str(&raw_payload.next_update, "%Y-%m-%d")
        .map_err(|e| MdsError::InvalidNextUpdate(e.to_string()))?;
    let stale = next_update < now.date_naive();
    if stale {
        tracing::warn!(
            next_update = %next_update,
            now = %now,
            "MDS BLOB is stale (nextUpdate has passed) — ingesting anyway; policy decides"
        );
    }

    let meta = MdsBlobMeta {
        no: raw_payload.no,
        next_update,
        entry_count: entries.len() as u64,
        last_refreshed_at: now,
        stale,
    };

    Ok(MdsBlob { meta, entries })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// These are *synthetic* test vectors: a real FIDO MDS3 BLOB is a signed JWT
// from a live FIDO Alliance private key over a real CA chain, and is
// deliberately not committed to this repo (it's ~10 MB, and there is no way
// to "fake" a vendor-signed artifact honestly). Instead, this suite builds
// its own throwaway root -> intermediate -> leaf PKI with `rcgen` and signs
// a small synthetic payload with a leaf-embedded RSA key, verifying through
// a seam (`verify_and_parse_with_root`) that accepts an injected root DER
// instead of the real vendored anchor. `verify_and_parse` itself is only
// exercised indirectly through that seam for the positive/negative-chain
// cases; the digest-pin and real-anchor-loading behavior is covered
// separately in `super::tests` (`root_anchor_digest_matches_pin`).
//
// A `#[ignore]`d test further down runs the *actual* `verify_and_parse`
// (against the real vendored anchor) over a real downloaded BLOB when
// `AXIAM_MDS_BLOB_PATH` is set — see its doc comment for how to run it.
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use std::sync::LazyLock;

    /// A throwaway 2048-bit RSA key, generated fresh on first use.
    ///
    /// The JWT under test is always RS256, so these vectors need an RSA key
    /// to sign with, and `rcgen` cannot generate one (`ring` has no RSA
    /// keygen). It is generated here rather than embedded as a PEM literal:
    /// a committed private key is indistinguishable from a leaked one to
    /// every scanner that looks at this repository, and "it is only a test
    /// fixture" is a claim a reader has to take on trust. Generating it
    /// removes the question.
    ///
    /// `LazyLock` so the ~100ms keygen happens once for the whole module
    /// rather than per test.
    static TEST_LEAF_RSA_PKCS8_PEM: LazyLock<String> = LazyLock::new(|| {
        use rsa::RsaPrivateKey;
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};

        let mut rng = rand_core::OsRng;
        RsaPrivateKey::new(&mut rng, 2048)
            .expect("generate throwaway test RSA key")
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode throwaway test key as PKCS#8 PEM")
            .to_string()
    });

    const LEAF_DNS: &str = "mds.fidoalliance.org";

    struct TestChain {
        /// DER of the (throwaway) root — the seam's injected anchor.
        root_der: Vec<u8>,
        /// x5c-ready standard-base64 DER strings: `[leaf, intermediate]`.
        x5c: Vec<String>,
        leaf_rsa_pkcs8_pem: String,
    }

    /// Build root -> intermediate -> leaf, where the root/intermediate use
    /// Ed25519 (fast, and irrelevant to what's under test — the JWT itself
    /// is always RS256, signed by the leaf's RSA key) and the leaf carries
    /// the throwaway RSA key as its *subject* key (embedded in the leaf
    /// cert's SPKI, independent of which key signed the leaf cert itself).
    fn build_test_chain(leaf_dns: &str) -> TestChain {
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("root keygen");
        let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("root params");
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test MDS Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).expect("self-sign root");
        let root_der = root_cert.der().to_vec();
        let root_issuer = Issuer::from_params(&root_params, root_key);

        let intermediate_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("int keygen");
        let mut intermediate_params =
            CertificateParams::new(Vec::<String>::new()).expect("int params");
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "Test MDS Intermediate CA");
        intermediate_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .expect("sign intermediate");
        let intermediate_der = intermediate_cert.der().to_vec();
        let intermediate_issuer = Issuer::from_params(&intermediate_params, intermediate_key);

        let leaf_key = KeyPair::from_pkcs8_pem_and_sign_algo(
            &TEST_LEAF_RSA_PKCS8_PEM,
            &rcgen::PKCS_RSA_SHA256,
        )
        .expect("load leaf RSA key");
        let mut leaf_params =
            CertificateParams::new(vec![leaf_dns.to_string()]).expect("leaf params (SAN DNS)");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, leaf_dns);
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .expect("sign leaf");
        let leaf_der = leaf_cert.der().to_vec();

        let x5c = vec![
            STANDARD.encode(&leaf_der),
            STANDARD.encode(&intermediate_der),
        ];

        TestChain {
            root_der,
            x5c,
            leaf_rsa_pkcs8_pem: TEST_LEAF_RSA_PKCS8_PEM.clone(),
        }
    }

    /// Build a compact JWT: `header.payload.signature`, RS256-signed with
    /// `leaf_rsa_pkcs8_pem`, header carrying `alg`/`x5c` as given.
    fn build_jwt(
        alg: &str,
        x5c: &[String],
        payload_json: &serde_json::Value,
        leaf_rsa_pkcs8_pem: &str,
    ) -> String {
        let header = serde_json::json!({ "alg": alg, "typ": "JWT", "x5c": x5c });
        let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload_json).unwrap());
        let signing_input = format!("{header_b64}.{payload_b64}");

        if alg != "RS256" {
            // Callers testing alg rejection don't need (and, for "none",
            // conceptually shouldn't have) a real signature.
            return format!("{signing_input}.");
        }

        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(leaf_rsa_pkcs8_pem.as_bytes()).unwrap();
        let mut header_struct = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header_struct.x5c = Some(x5c.to_vec());
        // Signed via jsonwebtoken's own encoder (not the hand-built
        // header_b64/signing_input above) to guarantee the header JSON that
        // gets signed is exactly what jsonwebtoken itself produces.
        jsonwebtoken::encode(&header_struct, payload_json, &encoding_key).unwrap()
    }

    fn synthetic_payload(no: i64, next_update: &str) -> serde_json::Value {
        serde_json::json!({
            "no": no,
            "nextUpdate": next_update,
            "legalHeader": "Test fixture only — not a real FIDO MDS BLOB.",
            "entries": [
                {
                    "aaguid": "00000000-0000-0000-0000-000000000001",
                    "metadataStatement": {
                        "description": "Synthetic Test Authenticator",
                        "attestationRootCertificates": []
                    },
                    "statusReports": [
                        { "status": "FIDO_CERTIFIED_L1", "effectiveDate": "2020-01-01" }
                    ],
                    "timeOfLastStatusChange": "2020-01-01"
                },
                {
                    // No aaguid -> UAF/U2F-shaped entry, must be skipped.
                    "aaid": "0001#0001",
                    "statusReports": [
                        { "status": "FIDO_CERTIFIED" }
                    ]
                }
            ]
        })
    }

    /// Drives the **production** pipeline
    /// ([`super::verify_and_parse_with_anchor`]) against a throwaway root.
    /// There is deliberately no re-implementation of the verification logic
    /// in this module: a test that copies the code it guards stops guarding
    /// it the moment the two drift apart.
    fn verify_and_parse_with_root(
        blob: &str,
        now: DateTime<Utc>,
        expected_leaf_dns: &str,
        root_der: &[u8],
    ) -> Result<MdsBlob, MdsError> {
        super::verify_and_parse_with_anchor(blob, now, expected_leaf_dns, root_der)
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    // --- valid chain ---

    #[test]
    fn valid_chain_verifies_and_parses() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(276, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der);
        let blob = result.expect("valid synthetic chain must verify");

        assert_eq!(blob.meta.no, 276);
        assert!(!blob.meta.stale);
        // One entry has an aaguid, one (UAF/U2F-shaped) does not and must be skipped.
        assert_eq!(blob.entries.len(), 1);
        assert_eq!(
            blob.entries[0].description.as_deref(),
            Some("Synthetic Test Authenticator")
        );
    }

    // --- broken chain: leaf not signed by the intermediate ---

    #[test]
    fn broken_chain_leaf_not_signed_by_intermediate_is_rejected() {
        let chain_a = build_test_chain(LEAF_DNS);
        let chain_b = build_test_chain(LEAF_DNS);
        // Splice chain_b's leaf (x5c[0]) with chain_a's intermediate
        // (x5c[1]) — the leaf was never signed by this intermediate.
        let mismatched_x5c = vec![chain_b.x5c[0].clone(), chain_a.x5c[1].clone()];
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt(
            "RS256",
            &mismatched_x5c,
            &payload,
            &chain_b.leaf_rsa_pkcs8_pem,
        );

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain_a.root_der);
        assert!(matches!(result, Err(MdsError::ChainVerifyFailed)));
    }

    // --- wrong root ---

    #[test]
    fn wrong_root_is_rejected() {
        let chain = build_test_chain(LEAF_DNS);
        let other_chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        // Verify chain A's BLOB against chain B's (unrelated) root.
        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &other_chain.root_der);
        assert!(matches!(result, Err(MdsError::ChainVerifyFailed)));
    }

    // --- expired cert ---

    #[test]
    fn expired_intermediate_is_rejected() {
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Expired-Test Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_der = root_cert.der().to_vec();
        let root_issuer = Issuer::from_params(&root_params, root_key);

        let intermediate_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        intermediate_params
            .distinguished_name
            .push(DnType::CommonName, "Expired Test Intermediate CA");
        intermediate_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        // Already expired: valid a year ago through yesterday.
        let past_start = ::time::OffsetDateTime::now_utc() - ::time::Duration::days(400);
        let past_end = ::time::OffsetDateTime::now_utc() - ::time::Duration::days(1);
        intermediate_params.not_before = past_start;
        intermediate_params.not_after = past_end;
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        let intermediate_der = intermediate_cert.der().to_vec();
        let intermediate_issuer = Issuer::from_params(&intermediate_params, intermediate_key);

        let leaf_key = KeyPair::from_pkcs8_pem_and_sign_algo(
            &TEST_LEAF_RSA_PKCS8_PEM,
            &rcgen::PKCS_RSA_SHA256,
        )
        .unwrap();
        let mut leaf_params = CertificateParams::new(vec![LEAF_DNS.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, LEAF_DNS);
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .unwrap();
        let leaf_der = leaf_cert.der().to_vec();

        let x5c = vec![
            STANDARD.encode(&leaf_der),
            STANDARD.encode(&intermediate_der),
        ];
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &x5c, &payload, &TEST_LEAF_RSA_PKCS8_PEM);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &root_der);
        assert!(matches!(result, Err(MdsError::CertificateExpired)));
    }

    // --- alg: none ---

    #[test]
    fn alg_none_is_rejected() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("none", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der);
        assert!(matches!(result, Err(MdsError::UnsupportedAlgorithm(a)) if a == "none"));
    }

    #[test]
    fn unsupported_alg_is_rejected() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("HS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der);
        assert!(matches!(result, Err(MdsError::UnsupportedAlgorithm(a)) if a == "HS256"));
    }

    // --- tampered payload ---

    #[test]
    fn tampered_payload_fails_signature_check() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let mut segments: Vec<&str> = jwt.split('.').collect();
        // Flip the payload to a different (still validly base64url, still
        // valid JSON after decode) value without re-signing.
        let tampered_payload_json = serde_json::json!({
            "no": 999999,
            "nextUpdate": "2099-01-01",
            "entries": []
        });
        let tampered_payload_b64 =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered_payload_json).unwrap());
        segments[1] = &tampered_payload_b64;
        let tampered_jwt = segments.join(".");

        let result = verify_and_parse_with_root(&tampered_jwt, now(), LEAF_DNS, &chain.root_der);
        assert!(matches!(result, Err(MdsError::SignatureInvalid)));
    }

    #[test]
    fn one_byte_payload_tamper_fails_signature_check() {
        // D4 step 6's specific requirement: even a single flipped byte in
        // the signed region must fail signature verification.
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let mut bytes = jwt.into_bytes();
        // Flip one bit inside the payload segment (well past the first dot).
        let first_dot = bytes.iter().position(|&b| b == b'.').unwrap();
        let flip_at = first_dot + 5;
        bytes[flip_at] ^= 0x01;
        let tampered = String::from_utf8(bytes).unwrap();

        let result = verify_and_parse_with_root(&tampered, now(), LEAF_DNS, &chain.root_der);
        assert!(matches!(
            result,
            Err(MdsError::SignatureInvalid) | Err(MdsError::InvalidHeaderJson)
        ));
    }

    // --- missing x5c ---

    #[test]
    fn missing_x5c_is_rejected() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &[], &payload, &chain.leaf_rsa_pkcs8_pem);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der);
        assert!(matches!(result, Err(MdsError::MissingX5c)));
    }

    // --- wrong leaf DNS ---

    #[test]
    fn wrong_leaf_dns_is_rejected() {
        let chain = build_test_chain("not-mds.example.com");
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        // Verified against the *correct* expected DNS, but the leaf cert was
        // minted for a different name.
        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der);
        assert!(matches!(result, Err(MdsError::LeafIdentityMismatch)));
    }

    // --- stale nextUpdate ---

    #[test]
    fn stale_next_update_is_marked_stale_but_still_ingested() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2000-01-01"); // long past
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der);
        let blob = result.expect("staleness must not hard-fail ingestion");
        assert!(blob.meta.stale);
    }

    #[test]
    fn fresh_next_update_is_not_stale() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der);
        assert!(!result.unwrap().meta.stale);
    }

    // --- rollback (decide_ingest_outcome, D4 step 8) ---
    //
    // `verify_and_parse` itself has no notion of "stored no" (see its doc
    // comment) — rollback is exercised directly against
    // `super::super::decide_ingest_outcome` in `super::tests`, and here we
    // only confirm the parsed `no` a caller would feed into that decision.

    #[test]
    fn parsed_no_is_available_for_the_caller_to_run_rollback_protection_on() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(42, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let blob = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der).unwrap();
        assert_eq!(blob.meta.no, 42);
    }

    // --- the public-root splice attack (assert_is_issuer) ---

    #[test]
    fn end_entity_cert_cannot_be_used_as_an_issuer() {
        // The attack this closes: the vendored anchor is a *public* CA root,
        // so an attacker can legitimately obtain an ordinary end-entity
        // certificate beneath it. If issuer certificates were not required
        // to be CAs, the attacker could self-mint a leaf carrying
        // `mds.fidoalliance.org`, sign it with their own EE key, and present
        //
        //     x5c = [ forged leaf, attacker EE cert, genuine intermediate ]
        //
        // — a chain in which every signature verifies and the leaf carries
        // the pinned name. Only the CA check stops it.
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Public Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_der = root_cert.der().to_vec();
        let root_issuer = Issuer::from_params(&root_params, root_key);

        // An ordinary, genuinely-issued END-ENTITY certificate: CA=false.
        let attacker_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut attacker_params = CertificateParams::new(vec!["attacker.example".to_string()])
            .expect("attacker EE params");
        attacker_params
            .distinguished_name
            .push(DnType::CommonName, "attacker.example");
        attacker_params.is_ca = IsCa::NoCa;
        let attacker_cert = attacker_params
            .signed_by(&attacker_key, &root_issuer)
            .unwrap();
        let attacker_der = attacker_cert.der().to_vec();
        let attacker_issuer = Issuer::from_params(&attacker_params, attacker_key);

        // The attacker signs a leaf for the pinned MDS hostname with their
        // own EE key. Cryptographically valid; semantically forbidden.
        let leaf_key = KeyPair::from_pkcs8_pem_and_sign_algo(
            &TEST_LEAF_RSA_PKCS8_PEM,
            &rcgen::PKCS_RSA_SHA256,
        )
        .unwrap();
        let mut leaf_params = CertificateParams::new(vec![LEAF_DNS.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, LEAF_DNS);
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params.signed_by(&leaf_key, &attacker_issuer).unwrap();

        let x5c = vec![
            STANDARD.encode(leaf_cert.der()),
            STANDARD.encode(&attacker_der),
        ];
        let payload = synthetic_payload(999, "2099-01-01");
        let jwt = build_jwt("RS256", &x5c, &payload, &TEST_LEAF_RSA_PKCS8_PEM);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &root_der);
        assert!(
            matches!(result, Err(MdsError::IssuerNotCa)),
            "an end-entity certificate must never be accepted as an issuer, got {result:?}"
        );
    }

    #[test]
    fn leaf_that_is_itself_a_ca_is_rejected() {
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "Test Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_der = root_cert.der().to_vec();
        let root_issuer = Issuer::from_params(&root_params, root_key);

        let leaf_key = KeyPair::from_pkcs8_pem_and_sign_algo(
            &TEST_LEAF_RSA_PKCS8_PEM,
            &rcgen::PKCS_RSA_SHA256,
        )
        .unwrap();
        let mut leaf_params = CertificateParams::new(vec![LEAF_DNS.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, LEAF_DNS);
        leaf_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let leaf_cert = leaf_params.signed_by(&leaf_key, &root_issuer).unwrap();

        let x5c = vec![STANDARD.encode(leaf_cert.der())];
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &x5c, &payload, &TEST_LEAF_RSA_PKCS8_PEM);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &root_der);
        assert!(matches!(result, Err(MdsError::LeafIsCa)), "got {result:?}");
    }

    #[test]
    fn path_len_constraint_is_enforced() {
        // Root permits zero intermediates below it (pathLenConstraint = 0),
        // but the chain presents one. Must be rejected.
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "PathLen0 Root CA");
        root_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_der = root_cert.der().to_vec();
        let root_issuer = Issuer::from_params(&root_params, root_key);

        let mid_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut mid_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        mid_params
            .distinguished_name
            .push(DnType::CommonName, "Intermediate A");
        mid_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mid_cert = mid_params.signed_by(&mid_key, &root_issuer).unwrap();
        let mid_der = mid_cert.der().to_vec();
        let mid_issuer = Issuer::from_params(&mid_params, mid_key);

        let mid2_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut mid2_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        mid2_params
            .distinguished_name
            .push(DnType::CommonName, "Intermediate B");
        mid2_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mid2_cert = mid2_params.signed_by(&mid2_key, &mid_issuer).unwrap();
        let mid2_der = mid2_cert.der().to_vec();
        let mid2_issuer = Issuer::from_params(&mid2_params, mid2_key);

        let leaf_key = KeyPair::from_pkcs8_pem_and_sign_algo(
            &TEST_LEAF_RSA_PKCS8_PEM,
            &rcgen::PKCS_RSA_SHA256,
        )
        .unwrap();
        let mut leaf_params = CertificateParams::new(vec![LEAF_DNS.to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, LEAF_DNS);
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params.signed_by(&leaf_key, &mid2_issuer).unwrap();

        let x5c = vec![
            STANDARD.encode(leaf_cert.der()),
            STANDARD.encode(&mid2_der),
            STANDARD.encode(&mid_der),
        ];
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &x5c, &payload, &TEST_LEAF_RSA_PKCS8_PEM);

        let result = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &root_der);
        assert!(
            matches!(result, Err(MdsError::PathLenExceeded)),
            "got {result:?}"
        );
    }

    // --- entries without aaguid are skipped ---

    #[test]
    fn entries_without_aaguid_are_skipped() {
        let chain = build_test_chain(LEAF_DNS);
        let payload = synthetic_payload(1, "2099-01-01");
        let jwt = build_jwt("RS256", &chain.x5c, &payload, &chain.leaf_rsa_pkcs8_pem);

        let blob = verify_and_parse_with_root(&jwt, now(), LEAF_DNS, &chain.root_der).unwrap();
        // synthetic_payload has 2 entries: one with an aaguid, one without.
        assert_eq!(blob.entries.len(), 1);
    }

    // -------------------------------------------------------------------
    // Real-BLOB test (ignored by default)
    // -------------------------------------------------------------------
    //
    // Runs the *actual* `verify_and_parse` (against the real vendored
    // anchor, not the test seam above) over a real, freshly downloaded FIDO
    // MDS3 BLOB. Not run in CI because it needs network egress and a live
    // file this repo does not vendor.
    //
    // To run it locally:
    //   curl -s https://mds3.fidoalliance.org/ -o /tmp/mds-blob.jwt
    //   AXIAM_MDS_BLOB_PATH=/tmp/mds-blob.jwt cargo test -p axiam-pki \
    //     --lib mds::blob::tests::real_blob_verifies_against_vendored_anchor \
    //     -- --ignored
    #[test]
    #[ignore = "needs a real, freshly downloaded FIDO MDS3 BLOB — see doc comment for how to run"]
    fn real_blob_verifies_against_vendored_anchor() {
        let path = std::env::var("AXIAM_MDS_BLOB_PATH")
            .expect("set AXIAM_MDS_BLOB_PATH to a downloaded MDS3 BLOB file");
        let text = std::fs::read_to_string(path).expect("read BLOB file");
        let result = super::verify_and_parse(&text, Utc::now(), LEAF_DNS);
        let blob = result.expect("real BLOB must verify against the vendored anchor");
        assert!(blob.meta.no > 0);
        assert!(!blob.entries.is_empty());
    }
}

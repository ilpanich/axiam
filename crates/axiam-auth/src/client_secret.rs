//! Client-secret hashing (OBS-1).
//!
//! # What this replaces
//!
//! Until OBS-1 was remediated, OAuth2 client secrets and service-account
//! secrets were stored as an **unsalted, single-round SHA-256** digest. That
//! was safe *only* because every secret is 32 CSPRNG bytes produced by the
//! repository itself, with no operator-supplied path — an assumption held by
//! nothing stronger than a code comment. This module removes the dependence on
//! secret entropy: a stored hash is now a **keyed** HMAC-SHA256 tag, so an
//! attacker holding a dump of the `oauth2_client` / `service_account` tables
//! cannot mount an offline guessing attack at all without also holding the
//! server pepper.
//!
//! HMAC-SHA256 (rather than Argon2id) is deliberate. The client-credentials
//! grant is a machine-to-machine hot path measured at 2 727 req/s precisely
//! because it is *not* KDF-bound; the threat a KDF defends against — offline
//! brute force of a low-entropy secret — is already excluded by the 256-bit
//! CSPRNG secrets, and is now additionally excluded by the key. If a
//! caller-chosen client secret is ever accepted, revisit this: that is the
//! trigger condition OBS-1 recorded, and it would call for a salted KDF.
//!
//! # On-disk representation
//!
//! Two schemes coexist during migration. The scheme is identified by the
//! stored string itself, so no schema change and no backfill are required:
//!
//! | Scheme | Stored form | Length |
//! |---|---|---|
//! | v1 (legacy) | `<64 lowercase hex>` — bare `SHA-256(secret)` | 64 |
//! | v2 (current) | `v2.hs256$<64 lowercase hex>` — `HMAC-SHA256(k, secret)` | 73 |
//!
//! v1 hashes **cannot be re-derived** offline — only the digest was ever
//! stored, never the secret — so migration is necessarily lazy:
//! [`ClientSecretHasher::verify`] returns
//! [`ClientSecretVerdict::MatchNeedsUpgrade`] carrying the v2 replacement, and
//! the caller persists it with a compare-and-swap. The upgrade is produced
//! **only on a successful verification**; a failed verification never rehashes
//! and never writes.
//!
//! # Keying
//!
//! The HMAC key is derived once, at construction, from the configured server
//! pepper (`AXIAM__AUTH__PEPPER`) with a domain-separation label:
//!
//! ```text
//! k = HMAC-SHA256(pepper, "axiam.client-secret.v2")
//! ```
//!
//! The label keeps this key independent of the pepper's other use (Argon2id
//! password peppering), so the two never share key material directly.
//!
//! # Fail-closed posture
//!
//! The pepper is **mandatory** for client-secret hashing. There is no
//! bare-SHA-256 fallback: a missing pepper is a hard error, exactly like the
//! mandatory AMQP master signing key (SECHRD-08 / D-05c). Matching that
//! precedent, a *debug* build falls back to a documented dev-only pepper so
//! local runs and tests work without extra setup; a *release* build — the
//! production container image — fails closed with
//! [`AxiamError::ServiceUnavailable`].

use std::sync::OnceLock;

use axiam_core::error::AxiamError;
use hmac::{Hmac, Mac};
use secrecy::ExposeSecret;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::config::AuthConfig;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label mixed into the pepper to derive the v2 HMAC key.
/// Changing this string invalidates every stored v2 hash — treat it as part
/// of the on-disk format.
const KEY_DERIVATION_LABEL: &[u8] = b"axiam.client-secret.v2";

/// Scheme marker for the current (v2) client-secret hash format.
///
/// Present verbatim at the start of every v2 hash and included in the
/// constant-time comparison, so the version tag itself is never compared with
/// an early-exiting `==`.
pub const V2_PREFIX: &str = "v2.hs256$";

/// Length of a legacy (v1) stored hash: 64 lowercase hex chars of SHA-256.
pub const V1_HASH_LEN: usize = 64;

/// Length of a v2 stored hash: [`V2_PREFIX`] plus 64 lowercase hex chars.
pub const V2_HASH_LEN: usize = V2_PREFIX.len() + 64;

/// Documented dev/test-only pepper, used **only** in debug builds
/// (`cfg!(debug_assertions)` — i.e. never in the `cargo build --release`
/// binary that ships in the production container image, see
/// `docker/Dockerfile.server`) when `AXIAM__AUTH__PEPPER` is unset, so local
/// dev/test runs work without extra setup. This value MUST NOT be used in
/// production — [`ClientSecretHasher::from_auth_config`] fails closed rather
/// than falling back to it in a release build.
const DEV_DEFAULT_PEPPER: &[u8] = b"axiam-dev-only-client-secret-pepper-DO-NOT-USE-IN-PROD";

/// A pepper shorter than this is accepted but warned about at construction.
const WEAK_PEPPER_LEN: usize = 16;

/// Outcome of verifying a presented client secret against a stored hash.
///
/// Deliberately not a `bool`: the migration obligation is part of the result,
/// so a caller cannot verify a legacy row without being handed — and having to
/// look at — the replacement hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientSecretVerdict {
    /// The secret matched and the stored hash is already in the current
    /// scheme. Nothing to persist.
    Match,
    /// The secret matched a **legacy (v1)** stored hash. The caller SHOULD
    /// persist `upgraded_hash` (compare-and-swap against the hash it read) to
    /// migrate the row. Authentication has already succeeded — a failure to
    /// persist must be logged, not turned into an auth failure.
    MatchNeedsUpgrade { upgraded_hash: String },
    /// The secret did not match. Never rehash, never write.
    Mismatch,
}

impl ClientSecretVerdict {
    /// `true` for both matching variants.
    #[inline]
    pub fn is_match(&self) -> bool {
        !matches!(self, ClientSecretVerdict::Mismatch)
    }
}

/// Keyed hasher for client secrets. Construct once per process (see
/// [`install_from_config`]) — construction derives the HMAC key, hashing does
/// not.
#[derive(Clone)]
pub struct ClientSecretHasher {
    key: [u8; 32],
}

impl std::fmt::Debug for ClientSecretHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientSecretHasher(<redacted>)")
    }
}

impl Drop for ClientSecretHasher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ClientSecretHasher {
    /// Derive a hasher from raw pepper bytes.
    ///
    /// Prefer [`ClientSecretHasher::from_auth_config`]; this exists for tests
    /// and for callers that hold the pepper outside `AuthConfig`.
    pub fn from_pepper(pepper: &[u8]) -> Result<Self, AxiamError> {
        if pepper.is_empty() {
            return Err(AxiamError::ServiceUnavailable(
                "client-secret pepper is empty (AXIAM__AUTH__PEPPER) — client-secret hashing is \
                 keyed and has no unkeyed fallback (OBS-1)"
                    .to_string(),
            ));
        }
        if pepper.len() < WEAK_PEPPER_LEN {
            tracing::warn!(
                pepper_len = pepper.len(),
                "AXIAM__AUTH__PEPPER is shorter than {WEAK_PEPPER_LEN} bytes — use at least 32 \
                 bytes of CSPRNG output"
            );
        }
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(pepper)
            .expect("HMAC-SHA256 accepts a key of any length");
        mac.update(KEY_DERIVATION_LABEL);
        let mut key = [0u8; 32];
        key.copy_from_slice(&mac.finalize().into_bytes());
        Ok(Self { key })
    }

    /// Resolve a hasher from the authentication configuration, failing closed
    /// when no pepper is configured.
    ///
    /// - pepper set → derive the key from it;
    /// - pepper unset in a **debug** build → the documented
    ///   [`DEV_DEFAULT_PEPPER`], with a `warn!`;
    /// - pepper unset in a **release** build → `ServiceUnavailable`.
    ///
    /// There is deliberately no "degrade to unkeyed SHA-256" branch: silently
    /// weakening the control when unconfigured is the exact failure mode OBS-1
    /// objected to.
    pub fn from_auth_config(config: &AuthConfig) -> Result<Self, AxiamError> {
        Self::resolve(
            config.pepper.as_ref().map(|p| p.expose_secret()),
            cfg!(debug_assertions),
        )
    }

    /// Core resolution, with the debug-build fallback lifted into a parameter
    /// so both branches are testable from a single (debug) test binary.
    fn resolve(pepper: Option<&str>, allow_dev_default: bool) -> Result<Self, AxiamError> {
        match pepper {
            Some(p) if !p.is_empty() => Self::from_pepper(p.as_bytes()),
            _ if allow_dev_default => {
                tracing::warn!(
                    "AXIAM__AUTH__PEPPER not set — using the dev-only default client-secret \
                     pepper (NOT valid in a release/production build, OBS-1)"
                );
                Self::from_pepper(DEV_DEFAULT_PEPPER)
            }
            _ => Err(AxiamError::ServiceUnavailable(
                "client-secret pepper not configured (AXIAM__AUTH__PEPPER) — mandatory in \
                 production; client-secret hashing is keyed HMAC-SHA256 with no unkeyed \
                 fallback (OBS-1)"
                    .to_string(),
            )),
        }
    }

    /// Hash `secret` in the current (v2) scheme. The returned string is what
    /// goes in `client_secret_hash`.
    pub fn hash(&self, secret: &str) -> String {
        let mut buf = [0u8; V2_HASH_LEN];
        self.hash_into(secret, &mut buf);
        // `hash_into` writes only ASCII (the prefix plus lowercase hex).
        String::from_utf8(buf.to_vec()).expect("v2 hash encoding is ASCII by construction")
    }

    /// Write the v2 encoding of `secret` into a caller-owned stack buffer.
    ///
    /// Allocation-free: `Hmac<Sha256>` keeps its state inline and
    /// `hex::encode_to_slice` writes in place. This is what keeps the
    /// client-credentials hot path free of the per-request `String` the old
    /// `hash_client_secret` allocated.
    fn hash_into(&self, secret: &str, out: &mut [u8; V2_HASH_LEN]) {
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&self.key)
            .expect("HMAC-SHA256 accepts a 32-byte key");
        mac.update(secret.as_bytes());
        let tag = mac.finalize().into_bytes();
        out[..V2_PREFIX.len()].copy_from_slice(V2_PREFIX.as_bytes());
        hex::encode_to_slice(tag, &mut out[V2_PREFIX.len()..])
            .expect("64-byte tail holds exactly one hex-encoded 32-byte tag");
    }

    /// Verify `presented` against a `stored` hash in either scheme.
    ///
    /// Constant-time throughout: in both branches the candidate is fully
    /// computed and compared with [`ConstantTimeEq`] over the **entire** stored
    /// string, scheme marker included — there is no early `==` on the version
    /// tag and no short-circuit on a prefix mismatch. A `stored` value that is
    /// neither scheme (including the empty string used for public clients)
    /// falls through to a length-mismatched comparison and yields
    /// [`ClientSecretVerdict::Mismatch`] — fail closed.
    ///
    /// Which *branch* is taken is a function of the stored row only, never of
    /// the presented secret, so the (sub-microsecond) cost difference between
    /// SHA-256 and HMAC-SHA256 cannot be used as a secret oracle. It reveals
    /// at most which scheme a row is already stored in — not secret material,
    /// and observable from the migration itself.
    pub fn verify(&self, presented: &str, stored: &str) -> ClientSecretVerdict {
        if stored.len() == V1_HASH_LEN {
            // Legacy (v1): unsalted single-round SHA-256 (OBS-1).
            let mut candidate = [0u8; V1_HASH_LEN];
            legacy_v1_into(presented, &mut candidate);
            let matched = bool::from(candidate[..].ct_eq(stored.as_bytes()));
            candidate.zeroize();
            if matched {
                // Rehash ONLY after a successful verification.
                ClientSecretVerdict::MatchNeedsUpgrade {
                    upgraded_hash: self.hash(presented),
                }
            } else {
                ClientSecretVerdict::Mismatch
            }
        } else {
            let mut candidate = [0u8; V2_HASH_LEN];
            self.hash_into(presented, &mut candidate);
            let matched = bool::from(candidate[..].ct_eq(stored.as_bytes()));
            candidate.zeroize();
            if matched {
                ClientSecretVerdict::Match
            } else {
                ClientSecretVerdict::Mismatch
            }
        }
    }
}

/// Legacy (v1) hash: unsalted, single-round SHA-256, hex-encoded.
///
/// Retained **only** so pre-OBS-1 rows still authenticate while they migrate.
/// It is never produced for new or rotated secrets. Once an operator can show
/// no v1 rows remain (`client_secret_hash` of length 64), this and the v1 arm
/// of [`ClientSecretHasher::verify`] can be deleted.
fn legacy_v1_into(secret: &str, out: &mut [u8; V1_HASH_LEN]) {
    use sha2::Digest;
    let digest = Sha256::digest(secret.as_bytes());
    hex::encode_to_slice(digest, out).expect("64-byte buffer holds one hex-encoded 32-byte digest");
}

// ---------------------------------------------------------------------------
// Process-wide hasher
// ---------------------------------------------------------------------------

static GLOBAL_HASHER: OnceLock<ClientSecretHasher> = OnceLock::new();

/// Install the process-wide client-secret hasher from configuration.
///
/// Call once during startup, **before** the server begins accepting requests,
/// so a missing pepper is a startup failure rather than a first-request
/// failure. Returns the installed hasher.
///
/// Repositories (`create`, `rotate_secret`) and the OAuth2 token service all
/// read this single instance, which is what guarantees that creation, rotation
/// and verification cannot disagree about the key.
///
/// If a hasher is already installed the existing one is returned unchanged —
/// installation is first-write-wins, never a silent re-key.
pub fn install_from_config(config: &AuthConfig) -> Result<&'static ClientSecretHasher, AxiamError> {
    let hasher = ClientSecretHasher::from_auth_config(config)?;
    Ok(GLOBAL_HASHER.get_or_init(|| hasher))
}

/// Resolve the process-wide client-secret hasher.
///
/// Lock-free and allocation-free (`OnceLock::get` is a single acquire load),
/// so this is safe to call on the client-credentials hot path.
///
/// If nothing was installed: a **debug** build lazily installs the documented
/// dev-only pepper (so unit and integration tests need no wiring); a
/// **release** build fails closed.
pub fn global() -> Result<&'static ClientSecretHasher, AxiamError> {
    if let Some(h) = GLOBAL_HASHER.get() {
        return Ok(h);
    }
    let hasher = ClientSecretHasher::resolve(None, cfg!(debug_assertions))?;
    Ok(GLOBAL_HASHER.get_or_init(|| hasher))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn hasher() -> ClientSecretHasher {
        ClientSecretHasher::from_pepper(b"unit-test-pepper-0123456789abcdef").unwrap()
    }

    /// The exact pre-OBS-1 `axiam_db::hash_client_secret`, kept in the test
    /// module so the legacy-compatibility claims are pinned against an
    /// independent implementation rather than against `legacy_v1_into`.
    fn old_hash_client_secret(secret: &str) -> String {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(secret.as_bytes());
        hex::encode(h.finalize())
    }

    #[test]
    fn v2_hash_carries_the_version_marker_and_round_trips() {
        let h = hasher();
        let stored = h.hash("s3cr3t");
        assert!(stored.starts_with(V2_PREFIX), "stored = {stored}");
        assert_eq!(stored.len(), V2_HASH_LEN);
        assert!(
            stored[V2_PREFIX.len()..]
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(h.verify("s3cr3t", &stored), ClientSecretVerdict::Match);
    }

    #[test]
    fn v2_hash_is_deterministic_and_key_dependent() {
        let a = hasher();
        let b = ClientSecretHasher::from_pepper(b"a-different-pepper-entirely").unwrap();
        assert_eq!(a.hash("x"), a.hash("x"));
        assert_ne!(a.hash("x"), b.hash("x"));
        // A v2 hash made under a different pepper must not verify under ours.
        assert_eq!(a.verify("x", &b.hash("x")), ClientSecretVerdict::Mismatch);
    }

    #[test]
    fn v2_hash_differs_from_the_legacy_digest() {
        let h = hasher();
        assert_ne!(h.hash("x"), old_hash_client_secret("x"));
    }

    #[test]
    fn legacy_row_still_verifies_and_reports_an_upgrade() {
        let h = hasher();
        let legacy = old_hash_client_secret("legacy-secret");
        assert_eq!(legacy.len(), V1_HASH_LEN);
        match h.verify("legacy-secret", &legacy) {
            ClientSecretVerdict::MatchNeedsUpgrade { upgraded_hash } => {
                assert!(upgraded_hash.starts_with(V2_PREFIX));
                assert_eq!(upgraded_hash, h.hash("legacy-secret"));
                // The upgraded hash verifies with no further migration.
                assert_eq!(
                    h.verify("legacy-secret", &upgraded_hash),
                    ClientSecretVerdict::Match
                );
            }
            other => panic!("expected MatchNeedsUpgrade, got {other:?}"),
        }
    }

    #[test]
    fn failed_legacy_verification_never_produces_an_upgrade() {
        let h = hasher();
        let legacy = old_hash_client_secret("legacy-secret");
        assert_eq!(
            h.verify("wrong-secret", &legacy),
            ClientSecretVerdict::Mismatch,
            "a failed verification must never rehash"
        );
    }

    #[test]
    fn wrong_secret_fails_under_both_schemes() {
        let h = hasher();
        assert_eq!(
            h.verify("nope", &old_hash_client_secret("right")),
            ClientSecretVerdict::Mismatch
        );
        assert_eq!(
            h.verify("nope", &h.hash("right")),
            ClientSecretVerdict::Mismatch
        );
    }

    #[test]
    fn unparseable_or_empty_stored_hash_fails_closed() {
        let h = hasher();
        // Public clients store an empty hash — it must never authenticate,
        // not even against an empty presented secret.
        assert_eq!(h.verify("", ""), ClientSecretVerdict::Mismatch);
        assert_eq!(h.verify("anything", ""), ClientSecretVerdict::Mismatch);
        // A future/unknown scheme marker is a mismatch, not a panic.
        let unknown = format!("v9.xxxxx${}", &h.hash("x")[V2_PREFIX.len()..]);
        assert_eq!(h.verify("x", &unknown), ClientSecretVerdict::Mismatch);
        assert_eq!(h.verify("x", "garbage"), ClientSecretVerdict::Mismatch);
    }

    #[test]
    fn a_v2_hash_truncated_to_legacy_length_does_not_verify() {
        let h = hasher();
        let truncated: String = h.hash("x").chars().take(V1_HASH_LEN).collect();
        assert_eq!(truncated.len(), V1_HASH_LEN);
        assert_eq!(h.verify("x", &truncated), ClientSecretVerdict::Mismatch);
    }

    #[test]
    fn missing_pepper_fails_closed_in_a_release_build() {
        let err = ClientSecretHasher::resolve(None, /* allow_dev_default */ false)
            .expect_err("an unset pepper must fail closed in a release build");
        let msg = err.to_string();
        assert!(msg.contains("AXIAM__AUTH__PEPPER"), "message = {msg}");
    }

    #[test]
    fn empty_pepper_fails_closed_even_in_a_debug_build() {
        assert!(
            ClientSecretHasher::resolve(Some(""), true).is_ok(),
            "an empty configured pepper falls through to the debug dev default"
        );
        assert!(
            ClientSecretHasher::resolve(Some(""), false).is_err(),
            "an empty configured pepper must never silently key the HMAC"
        );
        assert!(
            ClientSecretHasher::from_pepper(b"").is_err(),
            "an empty pepper must be rejected outright"
        );
    }

    #[test]
    fn missing_pepper_uses_the_documented_dev_default_in_a_debug_build() {
        let h = ClientSecretHasher::resolve(None, true)
            .expect("a debug build must fall back to the documented dev default");
        let expected = ClientSecretHasher::from_pepper(DEV_DEFAULT_PEPPER).unwrap();
        assert_eq!(h.hash("x"), expected.hash("x"));
    }

    #[test]
    fn from_auth_config_uses_the_configured_pepper() {
        let config = AuthConfig {
            pepper: Some(SecretString::from("configured-pepper-value")),
            ..AuthConfig::default()
        };
        let h = ClientSecretHasher::from_auth_config(&config).unwrap();
        let expected = ClientSecretHasher::from_pepper(b"configured-pepper-value").unwrap();
        assert_eq!(h.hash("x"), expected.hash("x"));
    }

    #[test]
    fn the_derived_key_is_domain_separated_from_the_raw_pepper() {
        // The HMAC key must not be the pepper itself, otherwise the
        // client-secret MAC shares key material with password peppering.
        let pepper = b"unit-test-pepper-0123456789abcdef";
        let derived = ClientSecretHasher::from_pepper(pepper).unwrap();
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(pepper).unwrap();
        mac.update(b"x");
        let naive = format!("{V2_PREFIX}{}", hex::encode(mac.finalize().into_bytes()));
        assert_ne!(derived.hash("x"), naive);
    }

    #[test]
    fn global_hasher_is_available_in_tests_and_is_stable() {
        let a = global().expect("debug build resolves a dev-default hasher");
        let b = global().unwrap();
        assert_eq!(a.hash("x"), b.hash("x"));
        assert!(a.hash("x").starts_with(V2_PREFIX));
    }
}

//! Password verification and hashing using Argon2id.

use std::sync::OnceLock;

use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::AuthError;

/// Argon2id hash used for timing equalization on user-not-found /
/// unknown-account branches (SEC-026). Generated once per process by
/// [`hash_password`] on a random value, so it carries exactly
/// [`production_params`] and cannot drift from the hashes AXIAM stores
/// (SA-07 / C3). Shared by `AuthService` and `PasswordResetService`.
///
/// The plaintext is irrelevant: the verify's result is always discarded, and
/// its cost depends only on the Argon2 parameters encoded in the hash. Use
/// [`equalising_dummy_verify`] rather than calling `verify_password` on it.
///
/// Initialisation cannot fail for the static, valid parameters and a random
/// UUID input (`Params::new(19456, 2, 1)` is in range; hashing a short
/// password with an OS-RNG salt has no failure path), so `expect` documents an
/// invariant rather than a runtime risk. It also runs on first use, which a
/// startup warm-up can pre-empt; it never takes request input.
fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        hash_password(&Uuid::new_v4().simple().to_string(), None)
            .expect("hashing a random value with the static production Argon2 params cannot fail")
    })
}

/// The probe the timing-equalising verify feeds to Argon2: random per
/// process, stable within one, so no literal flows into the password sink.
fn dummy_probe() -> &'static str {
    static PROBE: OnceLock<String> = OnceLock::new();
    PROBE.get_or_init(|| Uuid::new_v4().simple().to_string())
}

/// One full Argon2id verify against [`dummy_hash`], result discarded.
///
/// Called on branches that would otherwise skip the hash (unknown user,
/// unknown address, an account serving a lockout, every refusal of gRPC
/// `ValidateCredentials`), so they cost what the real branch costs. The cost
/// is fixed by the parameters baked into the dummy hash, not by the probe, so the
/// probe is a runtime value rather than a literal. This is CPU-bound and
/// blocking: callers run it under `spawn_blocking` and a crypto permit — the
/// same permit, acquired the same way, as the verify it stands in for, or the
/// `503` it answers under saturation becomes the oracle (T-469).
pub fn equalising_dummy_verify(pepper: Option<&str>) {
    let _ = verify_password(dummy_probe(), dummy_hash(), pepper);
}

/// The single source of the Argon2id cost parameters for every hash AXIAM
/// writes, and for the timing-equalising dummy hash (SA-07): they cannot drift.
///
/// OWASP ASVS recommended: m=19456 (19 MiB), t=2, p=1.
fn production_params() -> Result<argon2::Params, AuthError> {
    argon2::Params::new(19456, 2, 1, None)
        .map_err(|e| AuthError::Crypto(format!("argon2 params: {e}")))
}

/// Hash a password with Argon2id using OWASP-recommended parameters.
///
/// If `pepper` is provided it is prepended to the password before
/// hashing. A fresh 16-byte salt is drawn from the OS RNG for each call
/// by `PasswordHasher::hash_password` itself.
pub fn hash_password(password: &str, pepper: Option<&str>) -> Result<String, AuthError> {
    let params = production_params()?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let peppered: Zeroizing<String>;
    let input: &[u8] = match pepper {
        Some(p) => {
            peppered = Zeroizing::new(format!("{p}{password}"));
            peppered.as_bytes()
        }
        None => password.as_bytes(),
    };

    // `peppered` is zeroized on drop at end of scope — including on the
    // `?`-propagated error path below (Drop runs during unwind/early-return).
    let hash = argon2
        .hash_password(input)
        .map_err(|e| AuthError::Crypto(format!("hash error: {e}")))?;

    Ok(hash.to_string())
}

/// Verify a plaintext password against an Argon2id PHC-format hash.
///
/// If `pepper` is provided it is prepended to the password before
/// verification — this must match the pepper used during hashing.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, or
/// `Err(AuthError::Crypto)` if the stored hash is malformed.
pub fn verify_password(
    password: &str,
    hash: &str,
    pepper: Option<&str>,
) -> Result<bool, AuthError> {
    let peppered: Zeroizing<String>;
    let input: &[u8] = match pepper {
        Some(p) => {
            peppered = Zeroizing::new(format!("{p}{password}"));
            peppered.as_bytes()
        }
        None => password.as_bytes(),
    };

    // `peppered` is zeroized on drop at end of scope — including on every
    // `?`-propagated error path below (Drop runs during unwind/early-return).
    let parsed_hash = argon2::PasswordHash::new(hash)
        .map_err(|e| AuthError::Crypto(format!("invalid hash format: {e}")))?;

    let argon2 = Argon2::default();
    match argon2.verify_password(input, &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
        Err(e) => Err(AuthError::Crypto(format!("verify error: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::PasswordHasher;

    /// Helper: hash a password with optional pepper using Argon2id.
    fn hash_password(password: &str, pepper: Option<&str>) -> String {
        let peppered: String;
        let input = match pepper {
            Some(p) => {
                peppered = format!("{p}{password}");
                peppered.as_bytes()
            }
            None => password.as_bytes(),
        };
        let argon2 = Argon2::default();
        argon2
            .hash_password(input)
            .expect("hashing failed")
            .to_string()
    }

    #[test]
    fn correct_password_matches() {
        let hash = hash_password("hunter2", None);
        assert!(verify_password("hunter2", &hash, None).unwrap());
    }

    #[test]
    fn wrong_password_does_not_match() {
        let hash = hash_password("hunter2", None);
        assert!(!verify_password("wrong", &hash, None).unwrap());
    }

    #[test]
    fn pepper_is_applied() {
        let hash = hash_password("hunter2", Some("pepper!"));
        assert!(verify_password("hunter2", &hash, Some("pepper!")).unwrap());
        // Without pepper should fail.
        assert!(!verify_password("hunter2", &hash, None).unwrap());
    }

    #[test]
    fn malformed_hash_returns_error() {
        let result = verify_password("pw", "not-a-hash", None);
        assert!(result.is_err());
    }

    #[test]
    fn the_dummy_probe_is_stable_within_a_process_and_never_empty() {
        assert_eq!(dummy_probe(), dummy_probe());
        assert!(!dummy_probe().is_empty());
    }

    #[test]
    fn the_equalising_verify_completes_with_and_without_a_pepper() {
        // Completes and returns; no panic on either pepper shape. The result
        // is discarded by design, so there is nothing else to assert, and a
        // wall-clock bound would only make this flaky.
        equalising_dummy_verify(None);
        equalising_dummy_verify(Some(&Uuid::new_v4().to_string()));
    }

    #[test]
    fn the_dummy_hash_is_a_parseable_argon2_phc_string() {
        // What makes the equalising verify do real work: a hash that did not
        // parse would fail fast and equalise nothing.
        let parsed = argon2::PasswordHash::new(dummy_hash()).expect("a valid PHC string");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
    }

    #[test]
    fn the_dummy_hash_uses_the_production_argon2_parameters() {
        let parsed = argon2::PasswordHash::new(dummy_hash()).expect("a valid PHC string");
        let got = argon2::Params::try_from(&parsed).expect("argon2 params in PHC string");
        let want = production_params().expect("production params");
        assert_eq!(got.m_cost(), want.m_cost(), "memory cost");
        assert_eq!(got.t_cost(), want.t_cost(), "time cost");
        assert_eq!(got.p_cost(), want.p_cost(), "parallelism");
        // `production_params()` leaves the output length unset (default 32);
        // the PHC string records it, so compare against a real hash instead.
        let real = super::hash_password("anything", None).expect("real hash");
        let real = argon2::PasswordHash::new(&real).expect("a valid PHC string");
        assert_eq!(
            parsed.hash.map(|h| h.len()),
            real.hash.map(|h| h.len()),
            "output length"
        );
        assert_eq!(parsed.version, real.version, "version");
        assert_eq!(parsed.algorithm.as_str(), "argon2id");
        assert_eq!(parsed.version, Some(0x13));
    }
}

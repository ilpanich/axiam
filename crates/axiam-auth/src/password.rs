//! Password verification using Argon2id.

use argon2::{Argon2, PasswordVerifier};

use crate::error::AuthError;

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
    let peppered: String;
    let input = match pepper {
        Some(p) => {
            peppered = format!("{p}{password}");
            peppered.as_bytes()
        }
        None => password.as_bytes(),
    };

    let parsed_hash = argon2::PasswordHash::new(hash)
        .map_err(|e| AuthError::Crypto(format!("invalid hash format: {e}")))?;

    let argon2 = Argon2::default();
    match argon2.verify_password(input, &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(AuthError::Crypto(format!("verify error: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::PasswordHasher;
    use argon2::password_hash::SaltString;
    use argon2::password_hash::rand_core::OsRng;

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
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(input, &salt)
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
}

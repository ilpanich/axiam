//! Password policy engine.
//!
//! Evaluates candidate passwords against the effective
//! [`PasswordPolicy`] resolved from org + tenant settings.
//!
//! Four check layers:
//! 1. **Complexity** — length, uppercase, lowercase, digit, symbol
//! 2. **History** — reject reuse of the last N passwords
//! 3. **HIBP breach** — k-Anonymity API (only 5-char SHA-1 prefix sent)
//! 4. **Orchestrator** — combines all checks into a single result

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::settings::PasswordPolicy;
use axiam_core::repository::PasswordHistoryRepository;
use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::password::verify_password;

// -----------------------------------------------------------------------
// Violation types
// -----------------------------------------------------------------------

/// A single password policy violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyViolation {
    TooShort { min: u32, actual: usize },
    MissingUppercase,
    MissingLowercase,
    MissingDigit,
    MissingSymbol,
    ReusedPassword { position: usize },
    BreachedPassword { occurrences: u64 },
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "password too short: minimum {min}, got {actual}")
            }
            Self::MissingUppercase => {
                write!(f, "password must contain an uppercase letter")
            }
            Self::MissingLowercase => {
                write!(f, "password must contain a lowercase letter")
            }
            Self::MissingDigit => {
                write!(f, "password must contain a digit")
            }
            Self::MissingSymbol => {
                write!(f, "password must contain a symbol")
            }
            Self::ReusedPassword { position } => write!(
                f,
                "password was used recently (position {position} in history)"
            ),
            Self::BreachedPassword { occurrences } => {
                write!(f, "password found in {occurrences} data breach(es)")
            }
        }
    }
}

/// Result of a full password policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyCheckResult {
    pub violations: Vec<PolicyViolation>,
}

impl PolicyCheckResult {
    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }

    /// Format all violations into a single error message.
    pub fn error_message(&self) -> String {
        self.violations
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// -----------------------------------------------------------------------
// Complexity checks (pure, synchronous)
// -----------------------------------------------------------------------

/// Check password against complexity requirements.
///
/// This is a pure function with no I/O — easy to unit test.
pub fn check_complexity(password: &str, policy: &PasswordPolicy) -> Vec<PolicyViolation> {
    let mut violations = Vec::new();

    let char_count = password.chars().count();
    if (char_count as u32) < policy.min_length {
        violations.push(PolicyViolation::TooShort {
            min: policy.min_length,
            actual: char_count,
        });
    }

    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        violations.push(PolicyViolation::MissingUppercase);
    }

    if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        violations.push(PolicyViolation::MissingLowercase);
    }

    if policy.require_digits && !password.chars().any(|c| c.is_ascii_digit()) {
        violations.push(PolicyViolation::MissingDigit);
    }

    if policy.require_symbols
        && !password
            .chars()
            .any(|c| !c.is_alphanumeric() && !c.is_whitespace())
    {
        violations.push(PolicyViolation::MissingSymbol);
    }

    violations
}

// -----------------------------------------------------------------------
// HIBP breach check (async, network)
// -----------------------------------------------------------------------

/// Compute the SHA-1 hash of a password and split into prefix + suffix
/// for the k-Anonymity HIBP API.
pub fn sha1_prefix_suffix(password: &str) -> (String, String) {
    let hash = Sha1::digest(password.as_bytes());
    let hex = hex::encode_upper(hash);
    let prefix = hex[..5].to_string();
    let suffix = hex[5..].to_string();
    (prefix, suffix)
}

/// Parse the HIBP range response body and find the occurrence count
/// for a given suffix.
///
/// Response format: one line per hash suffix, e.g.:
/// ```text
/// 003D68EB55068C33ACE09247EE4C639306B:3
/// 1E4C9B93F3F0682250B6CF8331B7EE68FD8:5
/// ```
///
/// Lines with count `0` are padding (added when `Add-Padding: true`).
pub fn parse_hibp_response(body: &str, suffix: &str) -> Option<u64> {
    for line in body.lines() {
        let line = line.trim();
        if let Some((line_suffix, count_str)) = line.split_once(':')
            && line_suffix.eq_ignore_ascii_case(suffix)
        {
            if let Ok(count) = count_str.trim().parse::<u64>()
                && count > 0
            {
                return Some(count);
            }
            return None;
        }
    }
    None
}

/// Check a password against the HIBP Pwned Passwords API using
/// k-Anonymity (only a 5-character SHA-1 prefix is sent).
///
/// Returns `Some(violation)` if breached, `None` if clean or on error.
/// HIBP is best-effort — network failures never block the user.
pub async fn check_hibp(
    password: &str,
    http_client: &reqwest::Client,
) -> Result<Option<PolicyViolation>, AxiamError> {
    let (prefix, suffix) = sha1_prefix_suffix(password);

    let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

    let response = match http_client
        .get(&url)
        .header("User-Agent", "AXIAM-IAM/0.1")
        .header("Add-Padding", "true")
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "HIBP API request failed; treating as not breached"
            );
            return Ok(None);
        }
    };

    if !response.status().is_success() {
        tracing::warn!(
            status = %response.status(),
            "HIBP API returned non-200; treating as not breached"
        );
        return Ok(None);
    }

    let body = match response.text().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Failed to read HIBP response body"
            );
            return Ok(None);
        }
    };

    Ok(parse_hibp_response(&body, &suffix)
        .map(|occurrences| PolicyViolation::BreachedPassword { occurrences }))
}

// -----------------------------------------------------------------------
// Password history check (async, DB)
// -----------------------------------------------------------------------

/// Check a candidate password against the user's recent password
/// history.
///
/// For each stored historical hash, we use Argon2id verification.
/// If `history_count` is 0, no check is performed.
pub async fn check_history<R: PasswordHistoryRepository>(
    password: &str,
    pepper: Option<&str>,
    tenant_id: Uuid,
    user_id: Uuid,
    history_count: u32,
    repo: &R,
) -> AxiamResult<Vec<PolicyViolation>> {
    if history_count == 0 {
        return Ok(Vec::new());
    }

    let entries = repo.get_recent(tenant_id, user_id, history_count).await?;

    let mut violations = Vec::new();
    for (idx, entry) in entries.iter().enumerate() {
        match verify_password(password, &entry.password_hash, pepper) {
            Ok(true) => {
                violations.push(PolicyViolation::ReusedPassword { position: idx + 1 });
                // One match is enough — stop early.
                break;
            }
            Ok(false) => continue,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    entry_id = %entry.id,
                    "Error verifying password history entry; skipping"
                );
                continue;
            }
        }
    }

    Ok(violations)
}

// -----------------------------------------------------------------------
// Full policy evaluation orchestrator
// -----------------------------------------------------------------------

/// Evaluate a candidate password against the full password policy.
///
/// Runs complexity checks (sync), then history + HIBP checks (async).
/// The `http_client` is `Option` so that callers can skip HIBP
/// (e.g., in unit tests or when the feature is disabled).
pub async fn evaluate_password<R: PasswordHistoryRepository>(
    password: &str,
    pepper: Option<&str>,
    policy: &PasswordPolicy,
    tenant_id: Uuid,
    user_id: Uuid,
    history_repo: &R,
    http_client: Option<&reqwest::Client>,
) -> AxiamResult<PolicyCheckResult> {
    let mut violations = check_complexity(password, policy);

    // History check
    if policy.password_history_count > 0 {
        let history_violations = check_history(
            password,
            pepper,
            tenant_id,
            user_id,
            policy.password_history_count,
            history_repo,
        )
        .await?;
        violations.extend(history_violations);
    }

    // HIBP breach check
    if policy.hibp_check_enabled
        && let Some(client) = http_client
        && let Ok(Some(violation)) = check_hibp(password, client).await
    {
        violations.push(violation);
    }

    Ok(PolicyCheckResult { violations })
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::settings::PasswordPolicy;

    fn default_policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digits: true,
            require_symbols: false,
            password_history_count: 5,
            hibp_check_enabled: false,
        }
    }

    fn relaxed_policy() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 0,
            require_uppercase: false,
            require_lowercase: false,
            require_digits: false,
            require_symbols: false,
            password_history_count: 0,
            hibp_check_enabled: false,
        }
    }

    // --- Complexity tests ---

    #[test]
    fn good_password_passes_complexity() {
        let policy = default_policy();
        let violations = check_complexity("MyStr0ngPassw0rd", &policy);
        assert!(violations.is_empty(), "got: {violations:?}");
    }

    #[test]
    fn too_short_password() {
        let policy = default_policy();
        let violations = check_complexity("Ab1", &policy);
        assert!(violations.contains(&PolicyViolation::TooShort { min: 12, actual: 3 }));
    }

    #[test]
    fn missing_uppercase() {
        let policy = default_policy();
        let violations = check_complexity("mystrongpassw0rd", &policy);
        assert!(violations.contains(&PolicyViolation::MissingUppercase));
    }

    #[test]
    fn missing_lowercase() {
        let policy = default_policy();
        let violations = check_complexity("MYSTRONGPASSW0RD", &policy);
        assert!(violations.contains(&PolicyViolation::MissingLowercase));
    }

    #[test]
    fn missing_digit() {
        let policy = default_policy();
        let violations = check_complexity("MyStrongPassword", &policy);
        assert!(violations.contains(&PolicyViolation::MissingDigit));
    }

    #[test]
    fn missing_symbol_when_required() {
        let mut policy = default_policy();
        policy.require_symbols = true;
        let violations = check_complexity("MyStr0ngPassw0rd", &policy);
        assert!(violations.contains(&PolicyViolation::MissingSymbol));
    }

    #[test]
    fn symbol_present_when_required() {
        let mut policy = default_policy();
        policy.require_symbols = true;
        let violations = check_complexity("MyStr0ng!Passw0rd", &policy);
        assert!(violations.is_empty(), "got: {violations:?}");
    }

    #[test]
    fn multiple_violations_returned() {
        let mut policy = default_policy();
        policy.require_symbols = true;
        let violations = check_complexity("short", &policy);
        // Should have: TooShort, MissingUppercase, MissingDigit,
        // MissingSymbol
        assert!(violations.len() >= 3, "got: {violations:?}");
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, PolicyViolation::TooShort { .. }))
        );
        assert!(violations.contains(&PolicyViolation::MissingUppercase));
        assert!(violations.contains(&PolicyViolation::MissingDigit));
        assert!(violations.contains(&PolicyViolation::MissingSymbol));
    }

    #[test]
    fn relaxed_policy_accepts_anything() {
        let policy = relaxed_policy();
        let violations = check_complexity("a", &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn empty_password_with_min_length_zero() {
        let policy = relaxed_policy();
        let violations = check_complexity("", &policy);
        assert!(violations.is_empty());
    }

    #[test]
    fn unicode_uppercase_accepted() {
        let mut policy = relaxed_policy();
        policy.require_uppercase = true;
        // Ü is uppercase
        let violations = check_complexity("über", &policy);
        assert!(
            violations.contains(&PolicyViolation::MissingUppercase),
            "ü is lowercase, so should fail"
        );
        let violations = check_complexity("Über", &policy);
        assert!(violations.is_empty(), "Ü is uppercase, should pass");
    }

    #[test]
    fn unicode_lowercase_accepted() {
        let mut policy = relaxed_policy();
        policy.require_lowercase = true;
        let violations = check_complexity("ÜBER", &policy);
        assert!(violations.contains(&PolicyViolation::MissingLowercase),);
        let violations = check_complexity("Über", &policy);
        assert!(violations.is_empty());
    }

    // --- SHA-1 prefix/suffix tests ---

    #[test]
    fn sha1_known_hash() {
        // SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = sha1_prefix_suffix("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    // --- HIBP response parsing tests ---

    #[test]
    fn parse_hibp_match() {
        let body = "\
1E4C9B93F3F0682250B6CF8331B7EE68FD8:5\r\n\
003D68EB55068C33ACE09247EE4C639306B:3\r\n\
00A1234567890ABCDEF1234567890ABCDEF:0\r\n";
        let result = parse_hibp_response(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(result, Some(5));
    }

    #[test]
    fn parse_hibp_no_match() {
        let body = "\
003D68EB55068C33ACE09247EE4C639306B:3\r\n\
00A1234567890ABCDEF1234567890ABCDEF:0\r\n";
        let result = parse_hibp_response(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
        assert_eq!(result, None);
    }

    #[test]
    fn parse_hibp_zero_count_is_not_breached() {
        let body = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\r\n";
        let result = parse_hibp_response(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(result, None);
    }

    #[test]
    fn parse_hibp_case_insensitive_suffix() {
        let body = "1e4c9b93f3f0682250b6cf8331b7ee68fd8:10\r\n";
        let result = parse_hibp_response(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(result, Some(10));
    }

    #[test]
    fn parse_hibp_empty_body() {
        let result = parse_hibp_response("", "ABCDE");
        assert_eq!(result, None);
    }

    // --- Display tests ---

    #[test]
    fn violation_display_messages() {
        assert!(
            PolicyViolation::TooShort { min: 12, actual: 3 }
                .to_string()
                .contains("minimum 12")
        );

        assert!(
            PolicyViolation::MissingUppercase
                .to_string()
                .contains("uppercase")
        );

        assert!(
            PolicyViolation::BreachedPassword { occurrences: 42 }
                .to_string()
                .contains("42")
        );
    }

    // --- Integration: evaluate_password with in-memory DB ---

    mod integration {
        use super::*;
        use argon2::password_hash::SaltString;
        use argon2::password_hash::rand_core::OsRng;
        use argon2::{Argon2, PasswordHasher};
        use axiam_core::models::password_history::CreatePasswordHistoryEntry;
        use axiam_core::repository::PasswordHistoryRepository;
        use axiam_db::SurrealPasswordHistoryRepository;
        use axiam_db::run_migrations;

        async fn setup_db() -> SurrealPasswordHistoryRepository<surrealdb::engine::local::Db> {
            let db = surrealdb::Surreal::new::<surrealdb::engine::local::Mem>(())
                .await
                .unwrap();
            db.use_ns("test").use_db("test").await.unwrap();
            run_migrations(&db).await.unwrap();
            SurrealPasswordHistoryRepository::new(db)
        }

        fn hash_pw(password: &str) -> String {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            argon2
                .hash_password(password.as_bytes(), &salt)
                .unwrap()
                .to_string()
        }

        #[tokio::test]
        async fn history_check_detects_reuse() {
            let repo = setup_db().await;
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();

            // Store a password in history
            repo.create(CreatePasswordHistoryEntry {
                tenant_id,
                user_id,
                password_hash: hash_pw("OldPassword123"),
            })
            .await
            .unwrap();

            // Check reuse
            let violations = check_history("OldPassword123", None, tenant_id, user_id, 5, &repo)
                .await
                .unwrap();

            assert_eq!(violations.len(), 1);
            assert!(matches!(
                violations[0],
                PolicyViolation::ReusedPassword { position: 1 }
            ));
        }

        #[tokio::test]
        async fn history_check_passes_new_password() {
            let repo = setup_db().await;
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();

            repo.create(CreatePasswordHistoryEntry {
                tenant_id,
                user_id,
                password_hash: hash_pw("OldPassword123"),
            })
            .await
            .unwrap();

            let violations =
                check_history("BrandNewPassword456", None, tenant_id, user_id, 5, &repo)
                    .await
                    .unwrap();

            assert!(violations.is_empty());
        }

        #[tokio::test]
        async fn history_check_skipped_when_count_zero() {
            let repo = setup_db().await;
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();

            repo.create(CreatePasswordHistoryEntry {
                tenant_id,
                user_id,
                password_hash: hash_pw("OldPassword123"),
            })
            .await
            .unwrap();

            // history_count = 0 means skip
            let violations = check_history("OldPassword123", None, tenant_id, user_id, 0, &repo)
                .await
                .unwrap();

            assert!(violations.is_empty());
        }

        #[tokio::test]
        async fn full_evaluate_combines_checks() {
            let repo = setup_db().await;
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();

            let policy = PasswordPolicy {
                min_length: 10,
                require_uppercase: true,
                require_lowercase: true,
                require_digits: true,
                require_symbols: false,
                password_history_count: 0,
                hibp_check_enabled: false,
            };

            // "short" fails min_length, missing uppercase, digit
            let result = evaluate_password("short", None, &policy, tenant_id, user_id, &repo, None)
                .await
                .unwrap();

            assert!(!result.is_ok());
            assert!(
                result
                    .violations
                    .iter()
                    .any(|v| matches!(v, PolicyViolation::TooShort { .. }))
            );
            assert!(
                result
                    .violations
                    .contains(&PolicyViolation::MissingUppercase)
            );
            assert!(result.violations.contains(&PolicyViolation::MissingDigit));
        }

        #[tokio::test]
        async fn full_evaluate_passes_good_password() {
            let repo = setup_db().await;
            let tenant_id = Uuid::new_v4();
            let user_id = Uuid::new_v4();

            let policy = PasswordPolicy {
                min_length: 8,
                require_uppercase: true,
                require_lowercase: true,
                require_digits: true,
                require_symbols: false,
                password_history_count: 0,
                hibp_check_enabled: false,
            };

            let result = evaluate_password(
                "MyG00dPassword",
                None,
                &policy,
                tenant_id,
                user_id,
                &repo,
                None,
            )
            .await
            .unwrap();

            assert!(result.is_ok(), "violations: {:?}", result.violations);
        }
    }
}

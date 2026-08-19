//! Secure Remote Password (SRP-6a) domain model.
//!
//! SRP is an **augmented PAKE**: the client proves knowledge of the password
//! without the password — or anything from which the password can be cheaply
//! recovered — ever crossing the wire. What the server stores instead is a
//! *verifier* `v = g^x mod N`, where `x` is derived from the password with a
//! deliberately expensive KDF.
//!
//! # What this actually buys AXIAM
//!
//! TLS 1.3 already protects the password in transit against a network
//! attacker. SRP closes a different set of holes, all of which are real in a
//! multi-tenant deployment the tenant does not fully own:
//!
//! - a reverse proxy, ingress controller, CDN or service mesh that terminates
//!   TLS sees every plaintext password today; under SRP it sees only `A`/`M1`,
//!   which are useless without the verifier;
//! - an accidental request-body log, a heap dump, or a crash reporter can no
//!   longer capture a plaintext password, because the server never has one;
//! - a stolen verifier database still costs the attacker a full KDF evaluation
//!   per candidate password, exactly as a stolen Argon2id hash database does.
//!
//! It does **not** protect against a fully compromised AXIAM server, and for
//! browser clients it does not protect against AXIAM serving malicious
//! JavaScript. Those are outside SRP's threat model and must not be claimed.
//!
//! # Divergence from RFC 5054, and why
//!
//! RFC 5054 §2.6 defines `x = SHA1(s | SHA1(I | ":" | p))`. Two deliberate
//! changes:
//!
//! 1. **SHA-256 everywhere instead of SHA-1.** SHA-1 is not acceptable in a
//!    system whose own security standards mandate Argon2id and Ed25519.
//! 2. **A memory-hard KDF instead of a bare hash for `x`.** A bare hash makes
//!    a leaked verifier database *cheaper* to attack offline than the
//!    Argon2id password hashes AXIAM stores today — adopting SRP would then be
//!    a net security regression at rest, which is not a trade worth making.
//!    So `x = OS2IP(KDF(I ":" p, s)) mod N`, where KDF is [`SrpKdf`].
//!
//! The identity `I` stays inside the KDF input exactly as RFC 5054 intends, so
//! a verifier remains bound to one identity and cannot be replayed against a
//! different account. Because AXIAM lets a user log in with *either* username
//! or email, the server tells the client which identity string to use in the
//! challenge response ([`SrpChallenge::identity`]) — the client must never
//! guess it from what the human typed.
//!
//! # Why not OPAQUE
//!
//! OPAQUE is the CFRG-selected aPAKE and is cryptographically stronger than
//! SRP: it has a security proof, uses standard elliptic curves, and resists
//! the pre-computation attack SRP is open to. It was not chosen here only
//! because vetted implementations do not exist across all eleven AXIAM SDK
//! languages. The wire format below is versioned (`group`, `kdf`) precisely so
//! a future OPAQUE mode can be added without breaking deployed clients.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AxiamError, AxiamResult};

// -----------------------------------------------------------------------
// Enforcement mode
// -----------------------------------------------------------------------

/// Whether SRP is offered, and whether password login is still accepted.
///
/// Set as an organization baseline and optionally tightened per tenant (see
/// [`crate::models::settings`]). The ordering `Disabled < Optional < Required`
/// is what "tighten-only" means for this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SrpMode {
    /// SRP is off. `/auth/srp/*` returns 404-equivalent behaviour and no
    /// verifier is recorded when a password is set. This is the default, so
    /// that an upgrade changes nothing for an existing deployment.
    #[default]
    Disabled,
    /// SRP is available and password login also still works. Setting a
    /// password (registration, change-password, reset completion) records a
    /// verifier alongside the Argon2id hash, so the tenant accumulates SRP
    /// coverage as users rotate credentials.
    Optional,
    /// Password login is **refused for any user who has an SRP verifier**.
    /// Users without one keep using password login — that carve-out is what
    /// stops `Required` from locking out every account that existed before the
    /// mode was turned on. See the module docs on [`SrpCredential`] for why a
    /// verifier cannot be back-filled from a stored Argon2id hash.
    Required,
}

impl std::fmt::Display for SrpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Optional => write!(f, "optional"),
            Self::Required => write!(f, "required"),
        }
    }
}

impl std::str::FromStr for SrpMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            other => Err(format!("invalid SRP mode: {other}")),
        }
    }
}

// -----------------------------------------------------------------------
// Group
// -----------------------------------------------------------------------

/// The RFC 5054 Appendix A safe-prime group a verifier was created under.
///
/// A verifier is only meaningful under the group it was generated with, so the
/// group is stored per credential rather than read from current policy —
/// changing the org-level group must not invalidate existing verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SrpGroup {
    /// RFC 5054 Appendix A, 2048-bit group.
    Rfc5054_2048,
    /// RFC 5054 Appendix A, 3072-bit group.
    Rfc5054_3072,
    /// RFC 5054 Appendix A, 4096-bit group. Default — it matches the RSA-4096
    /// floor AXIAM already sets for certificates.
    #[default]
    Rfc5054_4096,
}

impl SrpGroup {
    /// Size of the group modulus in bits.
    pub fn bits(self) -> u32 {
        match self {
            Self::Rfc5054_2048 => 2048,
            Self::Rfc5054_3072 => 3072,
            Self::Rfc5054_4096 => 4096,
        }
    }

    /// Size of the group modulus in bytes — the width every `PAD()` in the
    /// protocol pads to.
    pub fn byte_len(self) -> usize {
        (self.bits() / 8) as usize
    }
}

impl std::fmt::Display for SrpGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rfc5054_2048 => write!(f, "rfc5054_2048"),
            Self::Rfc5054_3072 => write!(f, "rfc5054_3072"),
            Self::Rfc5054_4096 => write!(f, "rfc5054_4096"),
        }
    }
}

impl std::str::FromStr for SrpGroup {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rfc5054_2048" => Ok(Self::Rfc5054_2048),
            "rfc5054_3072" => Ok(Self::Rfc5054_3072),
            "rfc5054_4096" => Ok(Self::Rfc5054_4096),
            other => Err(format!("invalid SRP group: {other}")),
        }
    }
}

// -----------------------------------------------------------------------
// KDF
// -----------------------------------------------------------------------

/// The key-derivation function used to turn a password into the SRP private
/// key `x`.
///
/// Both variants are mandatory for a server to *accept*; which one a client
/// must use is dictated per credential, because changing the KDF changes `x`
/// and therefore invalidates the verifier.
///
/// `Argon2id` is preferred and is what a newly created verifier gets unless
/// the client says it cannot do it. `Pbkdf2Sha256` exists because three SDK
/// languages (Swift, and Java/Kotlin and C# without pulling a third-party
/// crypto library into an authentication path) have no vetted Argon2 binding
/// in their standard distribution, and shipping SRP that only half the SDKs
/// can speak would be worse than shipping a weaker-but-universal fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SrpKdf {
    /// Argon2id. Memory-hard; matches the parameters AXIAM uses for
    /// server-side password hashing.
    #[default]
    Argon2id,
    /// PBKDF2-HMAC-SHA256. Not memory-hard — accepted only because it is
    /// available natively in every SDK language with no added dependency.
    Pbkdf2Sha256,
}

impl std::fmt::Display for SrpKdf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2id => write!(f, "argon2id"),
            Self::Pbkdf2Sha256 => write!(f, "pbkdf2_sha256"),
        }
    }
}

impl std::str::FromStr for SrpKdf {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "argon2id" => Ok(Self::Argon2id),
            "pbkdf2_sha256" => Ok(Self::Pbkdf2Sha256),
            other => Err(format!("invalid SRP KDF: {other}")),
        }
    }
}

/// Concrete cost parameters for an [`SrpKdf`].
///
/// Stored per credential and echoed to the client in the challenge, because a
/// client that used different parameters would derive a different `x` and fail
/// to authenticate. Raising the org-level cost therefore only affects
/// verifiers created *after* the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kdf", rename_all = "snake_case")]
pub enum SrpKdfParams {
    /// Argon2id cost parameters.
    Argon2id {
        /// Memory cost in KiB.
        memory_kib: u32,
        /// Time cost (number of passes).
        iterations: u32,
        /// Degree of parallelism.
        parallelism: u32,
    },
    /// PBKDF2-HMAC-SHA256 cost parameters.
    Pbkdf2Sha256 {
        /// Iteration count.
        iterations: u32,
    },
}

impl SrpKdfParams {
    /// OWASP-aligned defaults for `kdf`.
    ///
    /// The Argon2id values mirror `axiam_auth::password::hash_password`
    /// (m=19456 KiB, t=2, p=1) so the client-side cost of an SRP login is the
    /// same order as the server-side cost of a password login. The PBKDF2
    /// count is the OWASP 2023 recommendation for PBKDF2-HMAC-SHA256.
    pub fn defaults_for(kdf: SrpKdf) -> Self {
        match kdf {
            SrpKdf::Argon2id => Self::Argon2id {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 1,
            },
            SrpKdf::Pbkdf2Sha256 => Self::Pbkdf2Sha256 {
                iterations: 600_000,
            },
        }
    }

    /// The [`SrpKdf`] these parameters belong to.
    pub fn kdf(&self) -> SrpKdf {
        match self {
            Self::Argon2id { .. } => SrpKdf::Argon2id,
            Self::Pbkdf2Sha256 { .. } => SrpKdf::Pbkdf2Sha256,
        }
    }

    /// Reject parameters that are too weak to be worth storing, or so large
    /// that honouring them would be a self-inflicted denial of service.
    ///
    /// The ceilings matter: these parameters arrive from a *client* at
    /// enrolment time and are replayed to every future client that
    /// authenticates as that user, so an unbounded value would let one
    /// enrolment permanently wedge an account.
    pub fn validate(&self) -> AxiamResult<()> {
        let violation = match *self {
            Self::Argon2id {
                memory_kib,
                iterations,
                parallelism,
            } => {
                if !(8192..=1_048_576).contains(&memory_kib) {
                    Some(format!(
                        "argon2id memory_kib ({memory_kib}) must be between 8192 and 1048576"
                    ))
                } else if !(1..=10).contains(&iterations) {
                    Some(format!(
                        "argon2id iterations ({iterations}) must be between 1 and 10"
                    ))
                } else if !(1..=16).contains(&parallelism) {
                    Some(format!(
                        "argon2id parallelism ({parallelism}) must be between 1 and 16"
                    ))
                } else {
                    None
                }
            }
            Self::Pbkdf2Sha256 { iterations } => {
                if !(210_000..=10_000_000).contains(&iterations) {
                    Some(format!(
                        "pbkdf2_sha256 iterations ({iterations}) must be between 210000 and 10000000"
                    ))
                } else {
                    None
                }
            }
        };

        match violation {
            Some(message) => Err(AxiamError::Validation { message }),
            None => Ok(()),
        }
    }
}

// -----------------------------------------------------------------------
// Stored credential
// -----------------------------------------------------------------------

/// A stored SRP verifier for one user.
///
/// # Why this cannot be back-filled
///
/// `v = g^x mod N` and `x = KDF(I ":" p, s)`. Both need the *plaintext*
/// password. A stored Argon2id hash is, by construction, not invertible, so
/// there is no migration that mints verifiers for an existing user base — a
/// verifier can only appear at a moment when the plaintext is legitimately in
/// hand: registration, an authenticated password change, or password-reset
/// completion. This is the whole reason [`SrpMode::Required`] is scoped to
/// users who already have a credential rather than being a global switch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrpCredential {
    /// Primary key.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// The user this verifier authenticates.
    pub user_id: Uuid,
    /// Canonical identity string bound into `x`. Always the user's `username`,
    /// never the email — a user may log in with either, but only one value can
    /// be inside the KDF input.
    pub identity: String,
    /// Group the verifier was generated under.
    pub group: SrpGroup,
    /// KDF cost parameters used to derive `x`.
    pub kdf_params: SrpKdfParams,
    /// Lowercase-hex random salt `s`, 32 bytes.
    pub salt: String,
    /// Lowercase-hex verifier `v`, left-padded to the group's byte length.
    pub verifier: String,
    /// When the verifier was first recorded.
    pub created_at: DateTime<Utc>,
    /// When the verifier was last replaced (i.e. last password change).
    pub updated_at: DateTime<Utc>,
}

/// Input for creating or replacing a user's SRP verifier.
///
/// Every field is computed **on the client**; the server validates ranges and
/// stores the result. It never learns the password, which is the point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSrpCredential {
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// The user this verifier authenticates.
    pub user_id: Uuid,
    /// Canonical identity bound into `x` (the user's `username`).
    pub identity: String,
    /// Group used.
    pub group: SrpGroup,
    /// KDF cost parameters used.
    pub kdf_params: SrpKdfParams,
    /// Lowercase-hex 32-byte salt.
    pub salt: String,
    /// Lowercase-hex verifier.
    pub verifier: String,
}

/// The client-supplied half of an SRP enrolment, as it appears inside
/// registration / change-password / reset-completion request bodies.
///
/// Kept separate from [`CreateSrpCredential`] because the tenant, user and
/// canonical identity are all decided by the server from the authenticated
/// context — a client that could name them could enrol a verifier against
/// somebody else's account.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SrpEnrollment {
    /// Group the client used. Must be permitted by effective settings.
    #[schema(example = "rfc5054_4096")]
    pub group: String,
    /// KDF the client used.
    #[schema(example = "argon2id")]
    pub kdf: String,
    /// Argon2id memory cost in KiB. Required for `argon2id`, ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    /// KDF iteration/time cost.
    pub iterations: u32,
    /// Argon2id parallelism. Required for `argon2id`, ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// Lowercase-hex 32-byte salt the client generated.
    pub salt: String,
    /// Lowercase-hex verifier `v = g^x mod N`.
    pub verifier: String,
}

impl SrpEnrollment {
    /// Parse and range-check the wire form into validated domain values.
    ///
    /// Rejects anything that would produce an unusable credential: an unknown
    /// group or KDF, out-of-range cost parameters, a salt that is not exactly
    /// 32 hex-encoded bytes, or a verifier that is not lowercase hex within
    /// the group's width.
    pub fn parse(&self) -> AxiamResult<(SrpGroup, SrpKdfParams, String, String)> {
        let group: SrpGroup = self
            .group
            .parse()
            .map_err(|message: String| AxiamError::Validation { message })?;
        let kdf: SrpKdf = self
            .kdf
            .parse()
            .map_err(|message: String| AxiamError::Validation { message })?;

        let params = match kdf {
            SrpKdf::Argon2id => SrpKdfParams::Argon2id {
                memory_kib: self.memory_kib.ok_or_else(|| AxiamError::Validation {
                    message: "memory_kib is required for kdf=argon2id".into(),
                })?,
                iterations: self.iterations,
                parallelism: self.parallelism.ok_or_else(|| AxiamError::Validation {
                    message: "parallelism is required for kdf=argon2id".into(),
                })?,
            },
            SrpKdf::Pbkdf2Sha256 => SrpKdfParams::Pbkdf2Sha256 {
                iterations: self.iterations,
            },
        };
        params.validate()?;

        let salt = normalize_hex(&self.salt, "salt")?;
        if salt.len() != 64 {
            return Err(AxiamError::Validation {
                message: format!(
                    "salt must be 32 bytes (64 hex chars), got {}",
                    salt.len() / 2
                ),
            });
        }

        let verifier = normalize_hex(&self.verifier, "verifier")?;
        if verifier.len() > group.byte_len() * 2 {
            return Err(AxiamError::Validation {
                message: format!("verifier is wider than the {} group modulus", group.bits()),
            });
        }
        if verifier.chars().all(|c| c == '0') {
            // v == 0 makes every M1 verify trivially forgeable.
            return Err(AxiamError::Validation {
                message: "verifier must not be zero".into(),
            });
        }

        Ok((group, params, salt, verifier))
    }
}

/// Lowercase and validate a hex string, rejecting odd lengths and non-hex
/// characters.
fn normalize_hex(value: &str, label: &str) -> AxiamResult<String> {
    if value.is_empty() {
        return Err(AxiamError::Validation {
            message: format!("{label} must not be empty"),
        });
    }
    if value.len() % 2 != 0 {
        return Err(AxiamError::Validation {
            message: format!("{label} must have an even number of hex characters"),
        });
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AxiamError::Validation {
            message: format!("{label} must be hex-encoded"),
        });
    }
    Ok(value.to_ascii_lowercase())
}

// -----------------------------------------------------------------------
// Wire types for the challenge/verify exchange
// -----------------------------------------------------------------------

/// Server response to `POST /api/v1/auth/srp/challenge`.
///
/// Every field is safe to return for an identity that does not exist — the
/// server fabricates a stable, deterministic salt and a well-formed `B` in
/// that case, so this response cannot be used to enumerate accounts.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SrpChallenge {
    /// Opaque sealed server state. Must be echoed verbatim to
    /// `/auth/srp/verify`; the client cannot read or forge it.
    pub srp_session: String,
    /// The canonical identity string to feed into the KDF. The client MUST use
    /// this rather than whatever the human typed, because a user may
    /// authenticate by username *or* email while only one of them is bound
    /// into `x`.
    pub identity: String,
    /// Lowercase-hex salt `s`.
    pub salt: String,
    /// Group to compute in.
    #[schema(example = "rfc5054_4096")]
    pub group: String,
    /// KDF to derive `x` with.
    #[schema(example = "argon2id")]
    pub kdf: String,
    /// Argon2id memory cost in KiB; absent for PBKDF2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    /// KDF iteration/time cost.
    pub iterations: u32,
    /// Argon2id parallelism; absent for PBKDF2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// Server public ephemeral `B`, lowercase hex padded to the group width.
    pub b_pub: String,
}

/// Client request to `POST /api/v1/auth/srp/verify`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SrpVerifyRequest {
    /// The `srp_session` from the challenge response, echoed verbatim.
    pub srp_session: String,
    /// Client proof `M1`, lowercase hex.
    pub client_proof: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment(salt: &str, verifier: &str) -> SrpEnrollment {
        SrpEnrollment {
            group: "rfc5054_4096".into(),
            kdf: "argon2id".into(),
            memory_kib: Some(19456),
            iterations: 2,
            parallelism: Some(1),
            salt: salt.into(),
            verifier: verifier.into(),
        }
    }

    #[test]
    fn srp_mode_orders_disabled_below_optional_below_required() {
        // The tighten-only settings rule leans on this ordering.
        assert!(SrpMode::Disabled < SrpMode::Optional);
        assert!(SrpMode::Optional < SrpMode::Required);
    }

    #[test]
    fn srp_mode_round_trips_through_string() {
        for mode in [SrpMode::Disabled, SrpMode::Optional, SrpMode::Required] {
            assert_eq!(mode.to_string().parse::<SrpMode>().unwrap(), mode);
        }
        assert!("sometimes".parse::<SrpMode>().is_err());
    }

    #[test]
    fn srp_group_round_trips_and_reports_widths() {
        for group in [
            SrpGroup::Rfc5054_2048,
            SrpGroup::Rfc5054_3072,
            SrpGroup::Rfc5054_4096,
        ] {
            assert_eq!(group.to_string().parse::<SrpGroup>().unwrap(), group);
            assert_eq!(group.byte_len() * 8, group.bits() as usize);
        }
        assert_eq!(SrpGroup::default(), SrpGroup::Rfc5054_4096);
    }

    #[test]
    fn kdf_defaults_match_the_server_side_password_cost() {
        assert_eq!(
            SrpKdfParams::defaults_for(SrpKdf::Argon2id),
            SrpKdfParams::Argon2id {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 1,
            }
        );
        assert_eq!(
            SrpKdfParams::defaults_for(SrpKdf::Pbkdf2Sha256),
            SrpKdfParams::Pbkdf2Sha256 {
                iterations: 600_000
            }
        );
    }

    #[test]
    fn kdf_params_reject_costs_outside_the_accepted_band() {
        assert!(
            SrpKdfParams::defaults_for(SrpKdf::Argon2id)
                .validate()
                .is_ok()
        );
        assert!(
            SrpKdfParams::defaults_for(SrpKdf::Pbkdf2Sha256)
                .validate()
                .is_ok()
        );
        // Too weak to be worth storing.
        assert!(
            SrpKdfParams::Argon2id {
                memory_kib: 64,
                iterations: 1,
                parallelism: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            SrpKdfParams::Pbkdf2Sha256 { iterations: 1000 }
                .validate()
                .is_err()
        );
        // Large enough to wedge the account it is enrolled against.
        assert!(
            SrpKdfParams::Argon2id {
                memory_kib: 4_194_304,
                iterations: 2,
                parallelism: 1
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn enrollment_parses_a_well_formed_body() {
        let salt = "a".repeat(64);
        let verifier = "beef".repeat(16);
        let (group, params, parsed_salt, parsed_verifier) =
            enrollment(&salt, &verifier).parse().unwrap();
        assert_eq!(group, SrpGroup::Rfc5054_4096);
        assert_eq!(params.kdf(), SrpKdf::Argon2id);
        assert_eq!(parsed_salt, salt);
        assert_eq!(parsed_verifier, verifier);
    }

    #[test]
    fn enrollment_uppercases_are_normalized_to_lowercase_hex() {
        let (_, _, salt, verifier) = enrollment(&"A".repeat(64), "BEEF").parse().unwrap();
        assert_eq!(salt, "a".repeat(64));
        assert_eq!(verifier, "beef");
    }

    #[test]
    fn enrollment_rejects_a_salt_of_the_wrong_width() {
        assert!(enrollment(&"a".repeat(62), "beef").parse().is_err());
        assert!(enrollment(&"a".repeat(66), "beef").parse().is_err());
    }

    #[test]
    fn enrollment_rejects_non_hex_and_odd_length() {
        assert!(enrollment(&"z".repeat(64), "beef").parse().is_err());
        assert!(enrollment(&"a".repeat(64), "bee").parse().is_err());
        assert!(enrollment(&"a".repeat(64), "").parse().is_err());
    }

    #[test]
    fn enrollment_rejects_a_zero_verifier() {
        // v == 0 collapses S to 0 for every A, making M1 forgeable without
        // the password.
        assert!(
            enrollment(&"a".repeat(64), &"0".repeat(64))
                .parse()
                .is_err()
        );
    }

    #[test]
    fn enrollment_rejects_a_verifier_wider_than_the_group() {
        let mut e = enrollment(&"a".repeat(64), &"b".repeat(1026));
        e.group = "rfc5054_4096".into();
        assert!(e.parse().is_err());
    }

    #[test]
    fn enrollment_requires_argon2_specific_parameters() {
        let mut e = enrollment(&"a".repeat(64), "beef");
        e.memory_kib = None;
        assert!(e.parse().is_err());

        let mut e = enrollment(&"a".repeat(64), "beef");
        e.parallelism = None;
        assert!(e.parse().is_err());
    }

    #[test]
    fn enrollment_accepts_pbkdf2_without_argon2_parameters() {
        let mut e = enrollment(&"a".repeat(64), "beef");
        e.kdf = "pbkdf2_sha256".into();
        e.memory_kib = None;
        e.parallelism = None;
        e.iterations = 600_000;
        let (_, params, _, _) = e.parse().unwrap();
        assert_eq!(params.kdf(), SrpKdf::Pbkdf2Sha256);
    }
}

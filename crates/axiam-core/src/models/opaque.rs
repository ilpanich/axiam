//! OPAQUE (RFC 9807) domain model.
//!
//! OPAQUE is an **augmented PAKE**: the client proves knowledge of the
//! password without the password — or anything from which the password can be
//! cheaply recovered — ever crossing the wire. What the server stores instead
//! is a *registration record*: an envelope sealed under a key the client can
//! only reconstruct by running the password through the server's oblivious
//! PRF.
//!
//! # What this buys AXIAM
//!
//! TLS 1.3 already protects the password in transit against a network
//! attacker. OPAQUE closes a different set of holes, all of which are real in
//! a multi-tenant deployment the tenant does not fully own:
//!
//! - a reverse proxy, ingress controller, CDN or service mesh that terminates
//!   TLS sees every plaintext password today; under OPAQUE it sees a blinded
//!   group element and a MAC, which are useless without the record *and* the
//!   tenant's OPRF seed;
//! - an accidental request-body log, a heap dump, or a crash reporter can no
//!   longer capture a plaintext password, because the server never has one;
//! - a stolen record database is **not** offline-crackable on its own. This is
//!   the property SRP could not offer: recovering a password from a stolen
//!   OPAQUE record additionally requires the tenant's OPRF seed, and without
//!   it there is no offline dictionary attack to mount at any cost.
//!
//! It does **not** protect against a fully compromised AXIAM server, and for
//! browser clients it does not protect against AXIAM serving malicious
//! JavaScript. Those are outside OPAQUE's threat model and must not be
//! claimed.
//!
//! # Why OPAQUE rather than SRP
//!
//! AXIAM shipped SRP-6a first and replaced it wholesale. Three reasons, in
//! descending order of weight:
//!
//! 1. **Pre-computation resistance.** A stolen SRP verifier database is
//!    offline-attackable at exactly the cost of the KDF, which is why the SRP
//!    design had to bolt a memory-hard KDF onto RFC 5054's bare hash simply to
//!    match the Argon2id hashes it replaced. OPAQUE's OPRF removes the offline
//!    attack rather than repricing it.
//! 2. **It is a specification, not a construction.** RFC 9807 pins every byte;
//!    AXIAM's SRP had two documented divergences from RFC 5054 (SHA-256 for
//!    SHA-1, and `x` as a KDF output) that existed because the RFC was not
//!    good enough to adopt as written.
//! 3. **One implementation instead of eleven.** SRP is arithmetic simple
//!    enough that every SDK hand-rolled it — including a bundled Montgomery
//!    modular exponentiation in Swift. OPAQUE is not, so every AXIAM client
//!    binds the same audited core (see `crates/axiam-opaque`). Eleven
//!    hand-written OPRF and hash-to-curve implementations on an authentication
//!    path is a risk this project declined to take.
//!
//! A consequence worth naming: the KSF fallback SRP needed no longer exists.
//! `pbkdf2_sha256` was in the SRP wire format only because PHP, Swift and
//! pre-3.2 OpenSSL had no usable Argon2id, and a tenant serving those clients
//! had to weaken its whole KDF policy. One shared core makes Argon2id
//! universal, so [`OpaqueKsf`]'s second variant is `scrypt` — memory-hard
//! either way, and no tenant can land on a KDF that is not.
//!
//! # Identifiers, and why a rename no longer breaks a credential
//!
//! Under SRP the private key `x` was derived over `username ":" password`, so
//! renaming a user silently invalidated their verifier. OPAQUE binds the
//! record to a `credential_identifier` chosen by the *server*, so AXIAM stores
//! a random 32-byte value per credential
//! ([`OpaqueCredential::credential_identifier`]) that has no relationship to
//! any human-readable name. Renames are therefore free, and the identifier
//! leaks nothing if observed.
//!
//! The same shape is what makes the unknown-identity path honest: for a
//! username that does not exist the server derives a *deterministic* 32-byte
//! identifier from a per-tenant key, so repeated probes for the same
//! non-existent name get a stable answer, and the answer is drawn from the
//! same distribution as a real one.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AxiamError, AxiamResult};

// -----------------------------------------------------------------------
// Enforcement mode
// -----------------------------------------------------------------------

/// Whether OPAQUE is offered, and whether password login is still accepted.
///
/// Set as an organization baseline and optionally tightened per tenant (see
/// [`crate::models::settings`]). The ordering `Disabled < Optional < Required`
/// is what "tighten-only" means for this field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueMode {
    /// OPAQUE is off. `/auth/opaque/*` returns 404-equivalent behaviour and no
    /// record is created when a password is set. This is the default, so that
    /// an upgrade changes nothing for an existing deployment.
    #[default]
    Disabled,
    /// OPAQUE is available and password login also still works. Setting a
    /// password (registration, change-password, reset completion) additionally
    /// runs an OPAQUE registration, so the tenant accumulates coverage as
    /// users rotate credentials.
    Optional,
    /// Password login is **refused for the whole tenant**: `/auth/login`
    /// answers `403` with `opaque_required` for every principal, before any
    /// credential is examined.
    ///
    /// Tenant-wide rather than per-user, deliberately. Refusing only the users
    /// who *have* a record would make `/auth/login` an oracle: an attacker
    /// sending one junk password per name would learn from the `403`-vs-`401`
    /// split exactly which accounts exist and are enrolled, without ever
    /// guessing a password. A uniform refusal reveals a property of the
    /// tenant, which is not a secret, and nothing about any individual.
    ///
    /// The cost is that this mode **locks out anyone who has not yet enrolled**
    /// — and see [`OpaqueCredential`] for why nobody can be enrolled
    /// retroactively. Turning it on is therefore the last step of a migration,
    /// not the first: run a password-reset campaign under [`Self::Optional`]
    /// until [`OpaqueCredentialRepository::count_for_tenant`] matches the
    /// tenant's user count.
    ///
    /// [`OpaqueCredentialRepository::count_for_tenant`]: crate::repository::OpaqueCredentialRepository::count_for_tenant
    Required,
}

impl std::fmt::Display for OpaqueMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Optional => write!(f, "optional"),
            Self::Required => write!(f, "required"),
        }
    }
}

impl std::str::FromStr for OpaqueMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "disabled" => Ok(Self::Disabled),
            "optional" => Ok(Self::Optional),
            "required" => Ok(Self::Required),
            other => Err(format!("invalid OPAQUE mode: {other}")),
        }
    }
}

// -----------------------------------------------------------------------
// Ciphersuite
// -----------------------------------------------------------------------

/// The RFC 9807 ciphersuite a registration record was created under.
///
/// A record is only meaningful under the suite it was registered with, so the
/// suite is stored per credential rather than read from current policy —
/// changing the org-level suite must not invalidate existing records.
///
/// # Why there is one variant
///
/// This is deliberately a real field with a real ranking rather than a
/// constant, and it deliberately has one value today.
///
/// RFC 9807 also defines a P-256/SHA-256 profile, which is the slot a FIPS
/// deployment would want. It is not shipped yet because every additional suite
/// multiplies the part of this migration that is hardest to get right — the
/// cross-language conformance surface — and nothing in AXIAM's compliance
/// targets requires P-256 today. Keeping the field, its `Ord` ranking and the
/// tighten-only check means adding `P256Sha256` later is an additive change to
/// an existing lattice rather than a schema and policy break.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueSuite {
    /// `OPAQUE-3DH` over ristretto255, SHA-512, HKDF-SHA-512, HMAC-SHA-512 —
    /// the RFC 9807 recommended configuration.
    #[default]
    Ristretto255Sha512,
}

impl OpaqueSuite {
    /// Relative cryptographic strength, used by the tenant tighten-only check.
    ///
    /// Higher is stronger. Kept as an explicit function rather than leaning on
    /// the derived `Ord` so that adding a variant forces a deliberate decision
    /// about where it ranks instead of inheriting declaration order.
    pub fn rank(self) -> u8 {
        match self {
            Self::Ristretto255Sha512 => 1,
        }
    }

    /// Byte length of a serialized registration record under this suite.
    ///
    /// Used to reject a malformed record at the API boundary rather than
    /// letting it fail deep inside the protocol engine at the next login.
    pub fn record_len(self) -> usize {
        match self {
            // 32-byte client public key + 64-byte masking key + 96-byte envelope.
            Self::Ristretto255Sha512 => 192,
        }
    }
}

impl std::fmt::Display for OpaqueSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ristretto255Sha512 => write!(f, "ristretto255_sha512"),
        }
    }
}

impl std::str::FromStr for OpaqueSuite {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ristretto255_sha512" => Ok(Self::Ristretto255Sha512),
            other => Err(format!("invalid OPAQUE suite: {other}")),
        }
    }
}

/// True when `candidate` is at least as strong as `baseline`.
pub fn opaque_suite_is_at_least(candidate: OpaqueSuite, baseline: OpaqueSuite) -> bool {
    candidate.rank() >= baseline.rank()
}

// -----------------------------------------------------------------------
// Key-stretching function
// -----------------------------------------------------------------------

/// The key-stretching function applied to the OPRF output before it seals the
/// envelope (RFC 9807 §3.1, `Stretch`).
///
/// This runs **entirely on the client**. The server never evaluates it, and
/// therefore never learns anything from it — it only records which function
/// and cost a given credential was enrolled under, so that a later login can
/// be told to reproduce them. A client that stretched differently would derive
/// a different randomized password and fail to open its own envelope.
///
/// Both variants are memory-hard. That is a change from SRP, where the second
/// KDF was PBKDF2 purely because three SDK languages had no usable Argon2id;
/// one shared implementation core removes that constraint, so there is no
/// longer a reason for AXIAM to offer a KSF that a GPU farm enjoys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueKsf {
    /// Argon2id. Matches the parameters AXIAM uses for server-side password
    /// hashing, so a client's cost is the same order as the server's was.
    #[default]
    Argon2id,
    /// scrypt. Memory-hard, and the RFC's other named KSF. Offered for
    /// deployments that prefer a longer-standing construction, and as the
    /// weaker rung of the tighten-only ladder.
    Scrypt,
}

impl OpaqueKsf {
    /// Relative strength, used by the tenant tighten-only check.
    pub fn rank(self) -> u8 {
        match self {
            Self::Scrypt => 0,
            Self::Argon2id => 1,
        }
    }
}

impl std::fmt::Display for OpaqueKsf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Argon2id => write!(f, "argon2id"),
            Self::Scrypt => write!(f, "scrypt"),
        }
    }
}

impl std::str::FromStr for OpaqueKsf {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "argon2id" => Ok(Self::Argon2id),
            "scrypt" => Ok(Self::Scrypt),
            other => Err(format!("invalid OPAQUE KSF: {other}")),
        }
    }
}

/// True when `candidate` is at least as strong as `baseline`.
pub fn opaque_ksf_is_at_least(candidate: OpaqueKsf, baseline: OpaqueKsf) -> bool {
    candidate.rank() >= baseline.rank()
}

/// Concrete cost parameters for an [`OpaqueKsf`].
///
/// Stored per credential and echoed to the client at login, because a client
/// that stretched with different parameters would not reproduce the key that
/// opens its envelope. Raising the org-level cost therefore only affects
/// records created *after* the change; existing users keep working and move up
/// when they next set a password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "ksf", rename_all = "snake_case")]
pub enum OpaqueKsfParams {
    /// Argon2id cost parameters.
    Argon2id {
        /// Memory cost in KiB.
        memory_kib: u32,
        /// Time cost (number of passes).
        iterations: u32,
        /// Degree of parallelism.
        parallelism: u32,
    },
    /// scrypt cost parameters.
    Scrypt {
        /// CPU/memory cost, expressed as log2(N).
        log_n: u8,
        /// Block size.
        r: u32,
        /// Parallelism.
        p: u32,
    },
}

impl OpaqueKsfParams {
    /// OWASP-aligned defaults for `ksf`.
    ///
    /// The Argon2id values mirror `axiam_auth::password::hash_password`
    /// (m=19456 KiB, t=2, p=1). The scrypt values are the OWASP 2023
    /// recommendation (N=2^17, r=8, p=1).
    pub fn defaults_for(ksf: OpaqueKsf) -> Self {
        match ksf {
            OpaqueKsf::Argon2id => Self::Argon2id {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 1,
            },
            OpaqueKsf::Scrypt => Self::Scrypt {
                log_n: 17,
                r: 8,
                p: 1,
            },
        }
    }

    /// The [`OpaqueKsf`] these parameters belong to.
    pub fn ksf(&self) -> OpaqueKsf {
        match self {
            Self::Argon2id { .. } => OpaqueKsf::Argon2id,
            Self::Scrypt { .. } => OpaqueKsf::Scrypt,
        }
    }

    /// Reject parameters that are too weak to be worth storing, or so large
    /// that honouring them would be a self-inflicted denial of service.
    ///
    /// The ceilings matter: these parameters are chosen by a *client* at
    /// enrolment time and are replayed to every future client that
    /// authenticates as that user, so an unbounded value would let one
    /// enrolment permanently wedge an account on every device it owns.
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
            Self::Scrypt { log_n, r, p } => {
                // log_n <= 20 caps the working set at 2^20 * 8 * r bytes; with
                // the r ceiling below that is 1 GiB, matching the Argon2id cap.
                if !(14..=20).contains(&log_n) {
                    Some(format!("scrypt log_n ({log_n}) must be between 14 and 20"))
                } else if !(1..=16).contains(&r) {
                    Some(format!("scrypt r ({r}) must be between 1 and 16"))
                } else if !(1..=16).contains(&p) {
                    Some(format!("scrypt p ({p}) must be between 1 and 16"))
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

/// A stored OPAQUE registration record for one user.
///
/// # Why this cannot be back-filled
///
/// A record is an envelope sealed with a key derived from the *plaintext*
/// password by way of the tenant's OPRF. A stored Argon2id hash is, by
/// construction, not invertible, so there is no migration that mints records
/// for an existing user base — a record can only appear at a moment when the
/// plaintext is legitimately in hand on the client: registration, an
/// authenticated password change, or password-reset completion. This is the
/// whole reason [`OpaqueMode::Required`] is the last step of a migration
/// rather than a switch an operator flips.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueCredential {
    /// Primary key.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// The user this record authenticates.
    pub user_id: Uuid,
    /// Lowercase-hex 32-byte server-chosen credential identifier, bound into
    /// the OPRF key and the AKE transcript.
    ///
    /// Random, not derived from the username. That is what makes a rename free
    /// — under SRP the equivalent binding was the username itself, so renaming
    /// a user left a verifier no client could satisfy.
    pub credential_identifier: String,
    /// Ciphersuite the record was registered under.
    pub suite: OpaqueSuite,
    /// KSF cost parameters the client stretched with.
    pub ksf_params: OpaqueKsfParams,
    /// Lowercase-hex serialized RFC 9807 `RegistrationRecord`.
    pub record: String,
    /// When the record was first written.
    pub created_at: DateTime<Utc>,
    /// When the record was last replaced (i.e. last password change).
    pub updated_at: DateTime<Utc>,
}

/// Input for creating or replacing a user's OPAQUE record.
///
/// The record itself is computed **on the client**; the server validates
/// shapes and stores the result. It never learns the password, which is the
/// point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOpaqueCredential {
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// The user this record authenticates.
    pub user_id: Uuid,
    /// Lowercase-hex 32-byte credential identifier.
    pub credential_identifier: String,
    /// Ciphersuite used.
    pub suite: OpaqueSuite,
    /// KSF cost parameters used.
    pub ksf_params: OpaqueKsfParams,
    /// Lowercase-hex serialized registration record.
    pub record: String,
}

/// Per-tenant OPAQUE server key material.
///
/// Holds the serialized RFC 9807 `ServerSetup` — the OPRF seed and the
/// server's long-term AKE key pair — plus the key used to derive stable
/// identifiers for usernames that do not exist.
///
/// # Scope and rotation
///
/// Scoped per tenant, matching AXIAM's isolation model: one tenant's stolen
/// seed tells an attacker nothing about another's records, and each tenant's
/// unknown-identity answers are drawn from its own distribution.
///
/// **Rotating this destroys every record in the tenant.** The OPRF seed is an
/// input to the key that seals each envelope, so a new seed makes every
/// existing envelope unopenable — every user in the tenant would have to reset
/// their password. This is sharper than anything in the SRP design, where the
/// session key sealed only 120 seconds of in-flight state, and it is why the
/// material is created once per tenant and never rotated as routine hygiene.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaqueServerSetup {
    /// Owning tenant.
    pub tenant_id: Uuid,
    /// Ciphersuite this setup is valid for. A setup is suite-specific; a
    /// tenant that adopts a new suite gets a new setup alongside the old one.
    pub suite: OpaqueSuite,
    /// AES-256-GCM sealed serialized `ServerSetup`, lowercase hex.
    ///
    /// Encrypted at rest for the same reason CA private keys and MFA secrets
    /// are: a database dump alone must not hand over the seed that makes the
    /// records offline-crackable.
    pub sealed_setup: String,
    /// AES-256-GCM sealed 32-byte key used to derive credential identifiers
    /// for usernames that do not exist, lowercase hex.
    pub sealed_decoy_key: String,
    /// When the material was created.
    pub created_at: DateTime<Utc>,
}

// -----------------------------------------------------------------------
// Wire types — registration
// -----------------------------------------------------------------------

/// Client request to `POST /api/v1/auth/opaque/register/start`.
///
/// Unauthenticated, because it is needed while creating a user who does not
/// exist yet. That is safe: the server mints the credential identifier itself,
/// randomly, so an attacker calling this repeatedly obtains OPRF evaluations
/// under identifiers they did not choose and cannot predict. Had the
/// identifier been caller-supplied, this would instead be an oracle for
/// grinding a chosen user's OPRF offline.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaqueRegisterStartRequest {
    /// Organization slug. Either this or `org_id` is required.
    #[serde(default)]
    pub org_slug: Option<String>,
    /// Organization UUID. Either this or `org_slug` is required.
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// Tenant slug. Either this or `tenant_id` is required.
    #[serde(default)]
    pub tenant_slug: Option<String>,
    /// Tenant UUID. Either this or `tenant_slug` is required.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    /// Lowercase-hex serialized RFC 9807 `RegistrationRequest` (a blinded
    /// group element).
    pub registration_request: String,
}

/// Server response to `POST /api/v1/auth/opaque/register/start`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaqueRegisterStartResponse {
    /// Opaque sealed server state. Must be echoed verbatim to
    /// `/auth/opaque/register/finish`; the client cannot read or forge it.
    pub opaque_session: String,
    /// Lowercase-hex serialized RFC 9807 `RegistrationResponse` (the evaluated
    /// element and the server's public key).
    pub registration_response: String,
    /// Ciphersuite the client must use.
    #[schema(example = "ristretto255_sha512")]
    pub suite: String,
    /// KSF the client must stretch with.
    #[schema(example = "argon2id")]
    pub ksf: String,
    /// Argon2id memory cost in KiB; absent for scrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    /// Argon2id time cost; absent for scrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    /// Argon2id parallelism; absent for scrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// scrypt log2(N); absent for Argon2id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_n: Option<u8>,
    /// scrypt block size; absent for Argon2id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<u32>,
    /// scrypt parallelism; absent for Argon2id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,
}

/// The client-supplied half of an OPAQUE enrolment, as it appears inside
/// registration / change-password / reset-completion / bootstrap request
/// bodies.
///
/// There is no standalone `register/finish` endpoint, deliberately. A record
/// can only be created at a moment when the plaintext password legitimately
/// exists on the client, and every one of those moments is already an endpoint
/// that takes a password. A free-standing finish would be an endpoint whose
/// only job is to attach a credential to an account, which is a thing worth
/// not having.
///
/// Kept separate from [`CreateOpaqueCredential`] because the tenant, the user
/// and the credential identifier are all decided by the server — a client that
/// could name them could enrol a record against somebody else's account.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaqueEnrollment {
    /// The `opaque_session` from the register/start response, echoed verbatim.
    pub opaque_session: String,
    /// Lowercase-hex serialized RFC 9807 `RegistrationRecord`.
    pub registration_record: String,
}

// -----------------------------------------------------------------------
// Wire types — login
// -----------------------------------------------------------------------

/// Client request to `POST /api/v1/auth/opaque/login/start`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaqueLoginStartRequest {
    /// Organization slug. Either this or `org_id` is required.
    #[serde(default)]
    pub org_slug: Option<String>,
    /// Organization UUID. Either this or `org_slug` is required.
    #[serde(default)]
    pub org_id: Option<Uuid>,
    /// Tenant slug. Either this or `tenant_id` is required.
    #[serde(default)]
    pub tenant_slug: Option<String>,
    /// Tenant UUID. Either this or `tenant_slug` is required.
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    /// Username or email, as typed by the human.
    #[serde(alias = "username")]
    pub username_or_email: String,
    /// Lowercase-hex serialized RFC 9807 `KE1`.
    pub ke1: String,
}

/// Server response to `POST /api/v1/auth/opaque/login/start`.
///
/// Every field is safe to return for an identity that does not exist — the
/// server derives a stable decoy credential identifier and produces a
/// well-formed `KE2` from it, so this response cannot be used to enumerate
/// accounts.
///
/// Note what is *not* here: the credential identifier itself. It keys the
/// server's OPRF and never enters the client's computation, so returning it
/// would be a gratuitous disclosure. This is a real difference from SRP, whose
/// challenge had to carry the canonical `identity` because that string was
/// inside the client's key derivation.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaqueLoginStartResponse {
    /// Opaque sealed server state. Must be echoed verbatim to
    /// `/auth/opaque/login/finish`; the client cannot read or forge it.
    pub opaque_session: String,
    /// Lowercase-hex serialized RFC 9807 `KE2`.
    pub ke2: String,
    /// Ciphersuite in use.
    #[schema(example = "ristretto255_sha512")]
    pub suite: String,
    /// KSF to stretch with.
    #[schema(example = "argon2id")]
    pub ksf: String,
    /// Argon2id memory cost in KiB; absent for scrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    /// Argon2id time cost; absent for scrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    /// Argon2id parallelism; absent for scrypt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    /// scrypt log2(N); absent for Argon2id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_n: Option<u8>,
    /// scrypt block size; absent for Argon2id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<u32>,
    /// scrypt parallelism; absent for Argon2id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,
}

/// Client request to `POST /api/v1/auth/opaque/login/finish`.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OpaqueLoginFinishRequest {
    /// The `opaque_session` from the login/start response, echoed verbatim.
    pub opaque_session: String,
    /// Lowercase-hex serialized RFC 9807 `KE3`.
    pub ke3: String,
}

// -----------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------

/// Lowercase and validate a hex string, rejecting odd lengths, non-hex
/// characters and anything outside `expected_len` bytes when one is given.
pub fn normalize_hex(value: &str, label: &str, expected_len: Option<usize>) -> AxiamResult<String> {
    if value.is_empty() {
        return Err(AxiamError::Validation {
            message: format!("{label} must not be empty"),
        });
    }
    if !value.len().is_multiple_of(2) {
        return Err(AxiamError::Validation {
            message: format!("{label} must have an even number of hex characters"),
        });
    }
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AxiamError::Validation {
            message: format!("{label} must be hex-encoded"),
        });
    }
    if let Some(expected) = expected_len
        && value.len() != expected * 2
    {
        return Err(AxiamError::Validation {
            message: format!(
                "{label} must be {expected} bytes ({} hex chars), got {}",
                expected * 2,
                value.len() / 2
            ),
        });
    }
    Ok(value.to_ascii_lowercase())
}

/// Split [`OpaqueKsfParams`] into the flat, optional wire fields the
/// register/start and login/start responses carry.
///
/// Returned as a tuple in declaration order:
/// `(ksf, memory_kib, iterations, parallelism, log_n, r, p)`.
///
/// Flat-and-optional rather than a nested object because the SRP wire format
/// was flat and every SDK's parser is shaped for it; changing the protocol is
/// enough churn for one release without also changing how costs are carried.
#[allow(clippy::type_complexity)]
pub fn ksf_wire_fields(
    params: OpaqueKsfParams,
) -> (
    String,
    Option<u32>,
    Option<u32>,
    Option<u32>,
    Option<u8>,
    Option<u32>,
    Option<u32>,
) {
    match params {
        OpaqueKsfParams::Argon2id {
            memory_kib,
            iterations,
            parallelism,
        } => (
            OpaqueKsf::Argon2id.to_string(),
            Some(memory_kib),
            Some(iterations),
            Some(parallelism),
            None,
            None,
            None,
        ),
        OpaqueKsfParams::Scrypt { log_n, r, p } => (
            OpaqueKsf::Scrypt.to_string(),
            None,
            None,
            None,
            Some(log_n),
            Some(r),
            Some(p),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_mode_orders_disabled_below_optional_below_required() {
        // The tighten-only settings rule leans on this ordering.
        assert!(OpaqueMode::Disabled < OpaqueMode::Optional);
        assert!(OpaqueMode::Optional < OpaqueMode::Required);
    }

    #[test]
    fn opaque_mode_round_trips_through_string() {
        for mode in [
            OpaqueMode::Disabled,
            OpaqueMode::Optional,
            OpaqueMode::Required,
        ] {
            assert_eq!(mode.to_string().parse::<OpaqueMode>().unwrap(), mode);
        }
        assert!("sometimes".parse::<OpaqueMode>().is_err());
    }

    #[test]
    fn opaque_mode_defaults_to_disabled_so_an_upgrade_changes_nothing() {
        assert_eq!(OpaqueMode::default(), OpaqueMode::Disabled);
    }

    #[test]
    fn suite_round_trips_and_reports_its_record_width() {
        let suite = OpaqueSuite::Ristretto255Sha512;
        assert_eq!(suite.to_string().parse::<OpaqueSuite>().unwrap(), suite);
        assert_eq!(OpaqueSuite::default(), suite);
        // 32-byte client public key + 64-byte masking key + 96-byte envelope.
        assert_eq!(suite.record_len(), 192);
        assert!("p256_sha256".parse::<OpaqueSuite>().is_err());
    }

    #[test]
    fn suite_comparison_accepts_an_equal_baseline() {
        assert!(opaque_suite_is_at_least(
            OpaqueSuite::Ristretto255Sha512,
            OpaqueSuite::Ristretto255Sha512
        ));
    }

    #[test]
    fn ksf_round_trips_and_ranks_argon2id_above_scrypt() {
        for ksf in [OpaqueKsf::Argon2id, OpaqueKsf::Scrypt] {
            assert_eq!(ksf.to_string().parse::<OpaqueKsf>().unwrap(), ksf);
        }
        assert!("pbkdf2_sha256".parse::<OpaqueKsf>().is_err());
        assert_eq!(OpaqueKsf::default(), OpaqueKsf::Argon2id);

        assert!(opaque_ksf_is_at_least(
            OpaqueKsf::Argon2id,
            OpaqueKsf::Scrypt
        ));
        assert!(!opaque_ksf_is_at_least(
            OpaqueKsf::Scrypt,
            OpaqueKsf::Argon2id
        ));
        assert!(opaque_ksf_is_at_least(OpaqueKsf::Scrypt, OpaqueKsf::Scrypt));
    }

    #[test]
    fn ksf_defaults_match_the_server_side_password_cost() {
        assert_eq!(
            OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id),
            OpaqueKsfParams::Argon2id {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 1,
            }
        );
        assert_eq!(
            OpaqueKsfParams::defaults_for(OpaqueKsf::Scrypt),
            OpaqueKsfParams::Scrypt {
                log_n: 17,
                r: 8,
                p: 1
            }
        );
    }

    #[test]
    fn ksf_params_report_their_own_function() {
        assert_eq!(
            OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id).ksf(),
            OpaqueKsf::Argon2id
        );
        assert_eq!(
            OpaqueKsfParams::defaults_for(OpaqueKsf::Scrypt).ksf(),
            OpaqueKsf::Scrypt
        );
    }

    #[test]
    fn ksf_params_reject_costs_outside_the_accepted_band() {
        assert!(
            OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id)
                .validate()
                .is_ok()
        );
        assert!(
            OpaqueKsfParams::defaults_for(OpaqueKsf::Scrypt)
                .validate()
                .is_ok()
        );

        // Too weak to be worth storing.
        assert!(
            OpaqueKsfParams::Argon2id {
                memory_kib: 64,
                iterations: 1,
                parallelism: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            OpaqueKsfParams::Scrypt {
                log_n: 10,
                r: 8,
                p: 1
            }
            .validate()
            .is_err()
        );

        // Large enough to wedge every device the account owns.
        assert!(
            OpaqueKsfParams::Argon2id {
                memory_kib: 4_194_304,
                iterations: 2,
                parallelism: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            OpaqueKsfParams::Scrypt {
                log_n: 24,
                r: 8,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            OpaqueKsfParams::Scrypt {
                log_n: 17,
                r: 64,
                p: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            OpaqueKsfParams::Scrypt {
                log_n: 17,
                r: 8,
                p: 64
            }
            .validate()
            .is_err()
        );
        assert!(
            OpaqueKsfParams::Argon2id {
                memory_kib: 19456,
                iterations: 99,
                parallelism: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            OpaqueKsfParams::Argon2id {
                memory_kib: 19456,
                iterations: 2,
                parallelism: 99
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn normalize_hex_lowercases_and_accepts_a_correct_width() {
        assert_eq!(
            normalize_hex(&"AB".repeat(32), "credential_identifier", Some(32)).unwrap(),
            "ab".repeat(32)
        );
        assert_eq!(normalize_hex("BeEf", "record", None).unwrap(), "beef");
    }

    #[test]
    fn normalize_hex_rejects_empty_odd_non_hex_and_wrong_width() {
        assert!(normalize_hex("", "record", None).is_err());
        assert!(normalize_hex("bee", "record", None).is_err());
        assert!(normalize_hex("zzzz", "record", None).is_err());
        assert!(normalize_hex(&"ab".repeat(31), "record", Some(32)).is_err());
        assert!(normalize_hex(&"ab".repeat(33), "record", Some(32)).is_err());
    }

    #[test]
    fn ksf_wire_fields_carry_only_the_parameters_that_apply() {
        let (ksf, m, t, p, log_n, r, sp) =
            ksf_wire_fields(OpaqueKsfParams::defaults_for(OpaqueKsf::Argon2id));
        assert_eq!(ksf, "argon2id");
        assert_eq!((m, t, p), (Some(19456), Some(2), Some(1)));
        // scrypt-only fields must be absent, not zero — an SDK that read a
        // zero as a cost would stretch with the wrong parameters.
        assert_eq!((log_n, r, sp), (None, None, None));

        let (ksf, m, t, p, log_n, r, sp) =
            ksf_wire_fields(OpaqueKsfParams::defaults_for(OpaqueKsf::Scrypt));
        assert_eq!(ksf, "scrypt");
        assert_eq!((m, t, p), (None, None, None));
        assert_eq!((log_n, r, sp), (Some(17), Some(8), Some(1)));
    }
}

//! Where AXIAM's long-lived symmetric keys come from.
//!
//! This is a **port**: layer 0 declares what the rest of the system needs from
//! a key source, and layer 1 supplies the implementations. Nothing here knows
//! about environment variables, files or HTTP.
//!
//! # Why this exists
//!
//! AXIAM's OPAQUE setup key encrypts every tenant's OPRF seed at rest. Losing
//! it makes every registration record in every tenant unopenable; leaking it
//! turns a stolen credential database back into an offline-crackable one, which
//! is the single property the migration from SRP was for.
//!
//! A key that important should not be limited to one delivery mechanism.
//! Environment variables are convenient and also appear in container specs,
//! `/proc/<pid>/environ`, crash dumps and orchestrator APIs. A mounted file is
//! what Docker secrets and Kubernetes `Secret` volumes actually hand you. A KMS
//! is what an operator who cares reaches for, because access there is
//! authenticated, audited and revocable rather than being a string that was
//! copied somewhere once.
//!
//! Inverting the dependency lets a deployment choose, and lets a new source be
//! added without touching a line of authentication code.
//!
//! # Why this trait is synchronous
//!
//! Keys are resolved **once, during composition** — never on a request path.
//! A provider that needs to talk to the network does so while it is being
//! *built* (see `axiam_auth::secrets::VaultSecretProvider::fetch`) and then
//! answers from memory.
//!
//! That is not a shortcut, it is the behaviour worth having: it keeps a KMS off
//! the login hot path entirely, and it makes a KMS outage fail at startup —
//! loudly, before any traffic — rather than turning into intermittent login
//! failures an hour later. It also keeps the trait object-safe without a
//! proc-macro, which matters because the composition root picks an
//! implementation at runtime.
//!
//! # What a provider is not responsible for
//!
//! Deciding whether a missing key is fatal. A provider reports `Ok(None)` for
//! "this key is not configured" and reserves `Err` for "it is configured and I
//! could not get it" — a distinction the caller needs, because the first means
//! *fall back to password login* and the second means *fail closed*. Collapsing
//! them would let a Vault outage look like a deliberate decision to run without
//! OPAQUE.

use zeroize::Zeroizing;

use crate::error::AxiamResult;

/// The OPAQUE session-sealing key. Rotating it invalidates in-flight exchanges
/// and nothing else.
pub const OPAQUE_SESSION_KEY: &str = "opaque_session_key";

/// The OPAQUE setup key, which encrypts every tenant's OPRF seed at rest.
///
/// **Losing it requires a password reset for every user in every tenant.**
pub const OPAQUE_SETUP_KEY: &str = "opaque_setup_key";

/// Encrypts TOTP/MFA secrets at rest.
pub const MFA_ENCRYPTION_KEY: &str = "mfa_encryption_key";

/// Encrypts federated identity-provider client secrets at rest.
pub const FEDERATION_ENCRYPTION_KEY: &str = "federation_encryption_key";

/// Encrypts stored email addresses at rest.
pub const EMAIL_ENCRYPTION_KEY: &str = "email_encryption_key";

/// Encrypts CA private keys at rest.
///
/// Ranks with the token signing key for blast radius: a leaked CA key means an
/// attacker can mint certificates every mTLS client in the tenant will trust.
pub const PKI_ENCRYPTION_KEY: &str = "pki_encryption_key";

/// HMAC-SHA256 master key authenticating AMQP message payloads.
///
/// Signing is mandatory and there is no unsigned code path, so an absent key is
/// a startup failure in a release build. It is a 256-bit key here and a hex
/// string in `AmqpConfig::signing_key`; the composition root encodes it, which
/// is the right place for that adaptation — the port describes what the secret
/// *is*, not how one consumer spells it.
pub const AMQP_SIGNING_KEY: &str = "amqp_signing_key";

/// HMAC-SHA256 pepper for GDPR audit pseudonymisation.
///
/// Losing it makes existing audit pseudonyms unlinkable to any future one,
/// which breaks the audit trail rather than any login.
pub const GDPR_PSEUDONYM_PEPPER: &str = "gdpr_pseudonym_pepper";

/// Every 256-bit key this port defines, for providers that preload.
pub const ALL_KEYS: &[&str] = &[
    OPAQUE_SESSION_KEY,
    OPAQUE_SETUP_KEY,
    MFA_ENCRYPTION_KEY,
    FEDERATION_ENCRYPTION_KEY,
    EMAIL_ENCRYPTION_KEY,
    GDPR_PSEUDONYM_PEPPER,
    PKI_ENCRYPTION_KEY,
    AMQP_SIGNING_KEY,
];

/// The password pepper, prepended before Argon2id hashing.
///
/// Text rather than 32 bytes, and deliberately so: it is concatenated with the
/// password, not used as a key. **Changing it invalidates every stored password
/// hash.**
pub const AUTH_PEPPER: &str = "auth_pepper";

/// The Ed25519 private key AXIAM signs tokens with, PEM-encoded.
///
/// The single most valuable secret in the system: holding it means being able
/// to mint a token for any principal in any tenant.
pub const JWT_PRIVATE_KEY_PEM: &str = "jwt_private_key_pem";

/// The matching public key, PEM-encoded. Not secret, but it travels with the
/// private key and a mismatched pair is a confusing outage.
pub const JWT_PUBLIC_KEY_PEM: &str = "jwt_public_key_pem";

/// Every text secret this port defines, for providers that preload.
pub const ALL_SECRETS: &[&str] = &[AUTH_PEPPER, JWT_PRIVATE_KEY_PEM, JWT_PUBLIC_KEY_PEM];

/// A source of 256-bit symmetric keys, addressed by a stable logical name.
///
/// Names are logical (`opaque_setup_key`), not physical: translating one into
/// an environment variable, a path or a KMS secret is the provider's job. That
/// is what lets a deployment change where its keys live without any caller
/// learning about it.
pub trait SecretProvider: Send + Sync {
    /// Fetch the 256-bit key registered under `name`.
    ///
    /// Returns `Ok(None)` when the key is genuinely not configured, and `Err`
    /// when it is configured but could not be retrieved or is malformed. See
    /// the module docs for why those must not be collapsed.
    fn get_key(&self, name: &str) -> AxiamResult<Option<[u8; 32]>>;

    /// Fetch the text secret registered under `name`.
    ///
    /// Separate from [`Self::get_key`] because not every secret is 32 bytes:
    /// the password pepper is concatenated with a password rather than used as
    /// a key, and the token signing key is a PEM document. Forcing them through
    /// a `[u8; 32]` would mean hex-encoding a PEM, which is the kind of
    /// indirection that gets an operator's key rejected for a reason no error
    /// message explains.
    ///
    /// The value is returned in a [`Zeroizing`] wrapper so a caller that drops
    /// it does not leave it in a freed heap page. That is a small control, not
    /// a strong one — the secret is about to live in the process anyway.
    fn get_secret(&self, name: &str) -> AxiamResult<Option<Zeroizing<String>>>;

    /// A short label for logs and startup diagnostics, e.g. `"env"`.
    ///
    /// Present so an operator reading a log line can tell *which* source
    /// answered — the commonest OPAQUE misconfiguration is believing a key came
    /// from somewhere it did not.
    fn describe(&self) -> &'static str;
}

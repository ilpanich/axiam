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

use crate::error::AxiamResult;

/// The OPAQUE session-sealing key. Rotating it invalidates in-flight exchanges
/// and nothing else.
pub const OPAQUE_SESSION_KEY: &str = "opaque_session_key";

/// The OPAQUE setup key, which encrypts every tenant's OPRF seed at rest.
///
/// **Losing it requires a password reset for every user in every tenant.**
pub const OPAQUE_SETUP_KEY: &str = "opaque_setup_key";

/// Every key name this port defines, for providers that want to preload.
pub const ALL_KEYS: &[&str] = &[OPAQUE_SESSION_KEY, OPAQUE_SETUP_KEY];

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

    /// A short label for logs and startup diagnostics, e.g. `"env"`.
    ///
    /// Present so an operator reading a log line can tell *which* source
    /// answered — the commonest OPAQUE misconfiguration is believing a key came
    /// from somewhere it did not.
    fn describe(&self) -> &'static str;
}

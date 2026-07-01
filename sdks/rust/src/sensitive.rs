//! `Sensitive<T>` — a token-redaction newtype (CONTRACT.md §7).
//!
//! Wraps any token-carrying value so that it can never accidentally leak via
//! `Debug`, `Display`, `tracing`, or any other diagnostic sink. The inner
//! value is genuinely private (no `pub` field, no `Deref` impl); the only
//! path to the raw value is [`Sensitive::expose`], which is `pub(crate)` —
//! never part of this crate's public API surface.

use std::fmt;

/// Wraps a sensitive value (e.g. an access or refresh token) so it can never
/// be printed, logged, or serialized in its raw form.
///
/// See CONTRACT.md §7: "The raw token string MUST NOT be exposed via any
/// public getter API." and "Debug/logging representations ... MUST emit a
/// redacted placeholder."
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Wrap `value` so it is protected from Debug/Display leakage.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Crate-internal access to the raw value only.
    ///
    /// This is the *only* path to the wrapped value. It is intentionally
    /// `pub(crate)`, never `pub` — no downstream consumer of this crate may
    /// call it. Internal callers MUST NOT pass the returned value to any
    /// `Debug`/`Display`/logging/tracing sink.
    ///
    /// Unused until plans 16-02/16-03 wire in the first internal consumers
    /// (`TokenManager`, the gRPC auth interceptor); `#[allow(dead_code)]`
    /// is intentional here, not a lint suppression of a real issue.
    #[allow(dead_code)]
    pub(crate) fn expose(&self) -> &T {
        &self.0
    }

    /// Crate-internal clone of the wrapped value, still redaction-safe.
    ///
    /// `Sensitive<T>` deliberately does not derive `Clone` publicly (a public
    /// derive would let a redacted value be cloned and then exposed through
    /// unrelated code paths). This manual, crate-private clone exists for the
    /// few internal call sites (e.g. `TokenManager`) that need to duplicate a
    /// token into a fresh `Sensitive<T>` without ever surfacing the raw value.
    #[allow(dead_code)]
    pub(crate) fn clone_inner(&self) -> Sensitive<T>
    where
        T: Clone,
    {
        Sensitive(self.0.clone())
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sensitive(<redacted>)")
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SENSITIVE]")
    }
}

// Deliberately NOT derived: Serialize, Deserialize, Clone (public).
// A public derive of any of these would create a leak path around the
// redacting Debug/Display impls above (RESEARCH.md Pitfall 4).

//! AMQP configuration.

use axiam_core::error::AxiamError;
use serde::Deserialize;

/// Documented dev/test-only default AMQP master signing key (SECHRD-08 /
/// D-05c). Used ONLY as a fallback in debug builds (`cfg!(debug_assertions)`
/// — i.e. never in the `cargo build --release` binary that ships in the
/// production container image, see `docker/Dockerfile.server`) when
/// `AXIAM__AMQP__SIGNING_KEY` is unset, so local dev/test runs work without
/// extra setup. This key MUST NOT be used in production — see
/// [`AmqpConfig::resolve_signing_key`], which fails closed instead of
/// falling back to this constant in a release build.
const DEV_DEFAULT_SIGNING_KEY: &[u8] = b"axiam-dev-only-amqp-signing-key-DO-NOT-USE-IN-PROD";

/// Configuration for connecting to RabbitMQ.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AmqpConfig {
    /// AMQP connection URI (e.g., `amqp://localhost:5672`).
    pub url: String,
    /// Channel prefetch count for consumers.
    pub prefetch_count: u16,
    /// Delay between reconnection attempts in milliseconds.
    pub reconnect_delay_ms: u64,
    /// Maximum number of connection retries before giving up.
    pub max_retries: u32,
    /// HMAC-SHA256 master signing key for authenticating AMQP message
    /// payloads (SEC-022/055, SECHRD-08). Set via
    /// `AXIAM__AMQP__SIGNING_KEY` (hex-encoded key). Signing is mandatory —
    /// there is no unsigned code path (D-05c). Use
    /// [`AmqpConfig::resolve_signing_key`] to resolve this to the mandatory
    /// key that consumers/producers must use: a debug-build-only dev
    /// default is used when unset in development, but a release build
    /// fails closed (`AxiamError::ServiceUnavailable`) if unset.
    #[serde(default)]
    pub signing_key: Option<String>,
}

impl Default for AmqpConfig {
    fn default() -> Self {
        Self {
            url: "amqp://localhost:5672".into(),
            prefetch_count: 10,
            reconnect_delay_ms: 5000,
            max_retries: 5,
            signing_key: None,
        }
    }
}

impl AmqpConfig {
    /// Resolve the configured signing key to a mandatory master key
    /// (SECHRD-08 / D-05c).
    ///
    /// - If `signing_key` is set, hex-decode and return it (an invalid hex
    ///   value is a misconfiguration and fails closed).
    /// - If unset in a debug build (`cfg!(debug_assertions)` — dev/test),
    ///   fall back to the documented [`DEV_DEFAULT_SIGNING_KEY`] so local
    ///   runs work without extra setup.
    /// - If unset in a release build (the production container image builds
    ///   with `cargo build --release`), fail closed: return
    ///   `AxiamError::ServiceUnavailable` — AMQP signing is mandatory in
    ///   production, there is no unsigned/zero-key code path.
    pub fn resolve_signing_key(&self) -> Result<Vec<u8>, AxiamError> {
        match &self.signing_key {
            Some(hex_key) => hex::decode(hex_key).map_err(|e| {
                AxiamError::ServiceUnavailable(format!(
                    "AXIAM__AMQP__SIGNING_KEY is not valid hex: {e}"
                ))
            }),
            None if cfg!(debug_assertions) => {
                tracing::warn!(
                    "AXIAM__AMQP__SIGNING_KEY not set — using dev-only default AMQP signing key \
                     (NOT valid in a release/production build, SECHRD-08 / D-05c)"
                );
                Ok(DEV_DEFAULT_SIGNING_KEY.to_vec())
            }
            None => Err(AxiamError::ServiceUnavailable(
                "AMQP signing key not configured (AXIAM__AMQP__SIGNING_KEY) — mandatory in \
                 production (SECHRD-08 / D-05c)"
                    .to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_signing_key_decodes_configured_hex() {
        let cfg = AmqpConfig {
            signing_key: Some(hex::encode(b"a-32-byte-ish-test-signing-key!")),
            ..AmqpConfig::default()
        };
        let key = cfg
            .resolve_signing_key()
            .expect("valid hex key must resolve");
        assert_eq!(key, b"a-32-byte-ish-test-signing-key!".to_vec());
    }

    #[test]
    fn resolve_signing_key_rejects_invalid_hex() {
        let cfg = AmqpConfig {
            signing_key: Some("not-valid-hex!!".to_string()),
            ..AmqpConfig::default()
        };
        assert!(
            cfg.resolve_signing_key().is_err(),
            "invalid hex signing key must fail closed, not silently ignore"
        );
    }

    #[test]
    fn resolve_signing_key_falls_back_to_dev_default_when_unset_in_debug_build() {
        let cfg = AmqpConfig {
            signing_key: None,
            ..AmqpConfig::default()
        };
        // This test itself only runs in a debug build (`cargo test`), so the
        // dev-default fallback branch applies here.
        if cfg!(debug_assertions) {
            let key = cfg
                .resolve_signing_key()
                .expect("debug build must fall back to the documented dev default");
            assert_eq!(key, DEV_DEFAULT_SIGNING_KEY.to_vec());
        }
    }
}

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

/// TLS material for an `amqps://` broker connection (A6).
///
/// Every field is optional: with none set, an `amqps://` URL still connects,
/// verifying the broker against the **system** root store. The fields exist for
/// the two cases the system store cannot serve — a privately-issued broker
/// certificate, and mutual TLS toward the broker.
///
/// # There is deliberately no `verify_peer: false`
///
/// Not as an oversight, and not as something to add later behind a scary name.
/// A verification-skip switch is the single most reliably misused TLS option
/// there is: it appears in a dev compose file, it works, and it travels
/// unchanged into production, where it turns TLS into an expensive no-op
/// against exactly the attacker TLS exists to stop. `ca_cert_path` covers the
/// legitimate reason people reach for it (a self-signed or private-CA broker
/// certificate) without also covering the illegitimate ones.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AmqpTlsConfig {
    /// PEM bundle of the CA(s) that issued the broker's certificate.
    ///
    /// Unset = verify against the system root store. Set this when the broker
    /// certificate is issued by a private CA — including one issued by AXIAM's
    /// own `axiam-pki` org CA, which is the recommended dogfooding path.
    pub ca_cert_path: Option<String>,
    /// PEM client certificate, for mutual TLS toward the broker.
    ///
    /// Must be set together with [`Self::client_key_path`]; one without the
    /// other is a misconfiguration and fails closed rather than silently
    /// connecting without a client certificate.
    pub client_cert_path: Option<String>,
    /// PEM client private key matching [`Self::client_cert_path`].
    pub client_key_path: Option<String>,
}

impl AmqpTlsConfig {
    /// Whether any TLS material is configured at all.
    pub fn is_empty(&self) -> bool {
        self.ca_cert_path.is_none()
            && self.client_cert_path.is_none()
            && self.client_key_path.is_none()
    }

    /// Validate the combination, without touching the filesystem.
    ///
    /// The one rule: a client certificate and its key travel together. Half a
    /// client identity is never what an operator meant, and connecting anyway
    /// would silently drop the mutual half of mutual TLS.
    pub fn validate(&self) -> Result<(), AxiamError> {
        match (&self.client_cert_path, &self.client_key_path) {
            (Some(_), None) => Err(AxiamError::ServiceUnavailable(
                "AXIAM__AMQP__TLS__CLIENT_CERT_PATH is set without \
                 AXIAM__AMQP__TLS__CLIENT_KEY_PATH — a client certificate without its \
                 key cannot authenticate; set both or neither"
                    .into(),
            )),
            (None, Some(_)) => Err(AxiamError::ServiceUnavailable(
                "AXIAM__AMQP__TLS__CLIENT_KEY_PATH is set without \
                 AXIAM__AMQP__TLS__CLIENT_CERT_PATH; set both or neither"
                    .into(),
            )),
            _ => Ok(()),
        }
    }
}

/// Configuration for connecting to RabbitMQ.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AmqpConfig {
    /// AMQP connection URI.
    ///
    /// `amqps://host:5671` selects TLS (see [`AmqpConfig::is_tls`]);
    /// `amqp://host:5672` is plaintext and, in a release build, must be
    /// explicitly permitted via [`AmqpConfig::allow_plaintext`].
    pub url: String,
    /// TLS material for an `amqps://` connection (A6). Ignored for `amqp://`.
    #[serde(default)]
    pub tls: AmqpTlsConfig,
    /// Permit a plaintext `amqp://` broker URL in a **release** build (A6).
    ///
    /// Set via `AXIAM__AMQP__ALLOW_PLAINTEXT`. Default `false`, and the
    /// failure is deliberate: broker traffic carries authorization requests,
    /// audit events and outbound mail payloads across service boundaries, and
    /// the AMQP layer's HMAC gives those **authenticity and replay protection
    /// but not confidentiality** — plaintext means they cross the wire
    /// readable. This mirrors [`DEV_DEFAULT_SIGNING_KEY`]'s posture exactly:
    /// convenient in a debug build, an explicit operator decision in a release
    /// one.
    #[serde(default)]
    pub allow_plaintext: bool,
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
    /// Freshness skew window (seconds) for AMQP replay protection (NEW-4). An
    /// `AuthzRequest`/`AuditEventMessage` is accepted only when its `issued_at`
    /// lies within ±this many seconds of the consumer's clock. Set via
    /// `AXIAM__AMQP__REPLAY_SKEW_SECS`; defaults to
    /// [`crate::messages::DEFAULT_FRESHNESS_SKEW_SECS`] (5 minutes).
    #[serde(default = "default_replay_skew_secs")]
    pub replay_skew_secs: u64,
}

fn default_replay_skew_secs() -> u64 {
    crate::messages::DEFAULT_FRESHNESS_SKEW_SECS as u64
}

impl Default for AmqpConfig {
    fn default() -> Self {
        Self {
            url: "amqp://localhost:5672".into(),
            tls: AmqpTlsConfig::default(),
            allow_plaintext: false,
            prefetch_count: 10,
            reconnect_delay_ms: 5000,
            max_retries: 5,
            signing_key: None,
            replay_skew_secs: default_replay_skew_secs(),
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

    /// Whether [`Self::url`] selects a TLS connection (A6).
    ///
    /// Scheme-based, case-insensitive, and deliberately strict about the
    /// separator: `amqps://` is TLS, `amqp://` is not, and anything else is
    /// neither — [`Self::validate_transport_security`] rejects it rather than
    /// guessing. Matching on `amqps` without the `://` would classify a
    /// hypothetical `amqpsomething://` as TLS.
    pub fn is_tls(&self) -> bool {
        self.url.trim().to_ascii_lowercase().starts_with("amqps://")
    }

    /// Enforce the transport-security posture before any connection is
    /// attempted (A6).
    ///
    /// Rules, in order:
    ///
    /// 1. An unrecognised scheme fails — better a clear error at startup than
    ///    an unclear one from lapin at connect time.
    /// 2. TLS material that is internally inconsistent fails
    ///    ([`AmqpTlsConfig::validate`]).
    /// 3. A plaintext URL fails in a **release** build unless
    ///    [`Self::allow_plaintext`] is set, and logs a prominent warning when
    ///    it is. Debug builds allow plaintext silently-ish so `just dev-up`
    ///    keeps working.
    ///
    /// The project standard is "TLS 1.3 minimum for all external
    /// communication", and six SDKs consume AMQP directly, so broker traffic
    /// crosses service boundaries by design. Failing closed here is what makes
    /// that standard true of the broker rather than aspirational about it.
    pub fn validate_transport_security(&self) -> Result<(), AxiamError> {
        let url = self.url.trim().to_ascii_lowercase();
        let is_plaintext = url.starts_with("amqp://");

        if !self.is_tls() && !is_plaintext {
            return Err(AxiamError::ServiceUnavailable(format!(
                "AXIAM__AMQP__URL must start with amqps:// or amqp:// (got {:?})",
                self.url
            )));
        }

        self.tls.validate()?;

        if self.is_tls() {
            return Ok(());
        }

        // Plaintext from here down.
        if !self.tls.is_empty() {
            tracing::warn!(
                "AMQP TLS material is configured but the URL is plaintext amqp:// — \
                 the certificates will NOT be used. Switch the URL to amqps:// (port 5671)."
            );
        }

        if cfg!(debug_assertions) {
            tracing::debug!(
                "AMQP transport is plaintext (debug build) — broker payloads cross the \
                 wire readable; use amqps:// in any deployment"
            );
            return Ok(());
        }

        if self.allow_plaintext {
            tracing::warn!(
                "AMQP transport is PLAINTEXT and explicitly permitted via \
                 AXIAM__AMQP__ALLOW_PLAINTEXT. Authorization requests, audit events and \
                 outbound mail payloads cross the wire readable. HMAC signing gives \
                 authenticity and replay protection, NOT confidentiality — it is not a \
                 substitute for TLS."
            );
            return Ok(());
        }

        Err(AxiamError::ServiceUnavailable(
            "AMQP transport is plaintext (amqp://) in a release build. Broker traffic \
             carries authorization requests, audit events and mail payloads across \
             service boundaries, and HMAC signing protects their authenticity but not \
             their confidentiality. Use amqps:// (port 5671), or set \
             AXIAM__AMQP__ALLOW_PLAINTEXT=true to accept the exposure deliberately."
                .to_string(),
        ))
    }

    /// Resolve the configured freshness skew to a `chrono::Duration` for the
    /// AMQP replay-protection gate (NEW-4).
    pub fn replay_skew(&self) -> chrono::Duration {
        chrono::Duration::seconds(self.replay_skew_secs as i64)
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

    // -----------------------------------------------------------------
    // A6 — transport security
    // -----------------------------------------------------------------

    fn plaintext() -> AmqpConfig {
        AmqpConfig {
            url: "amqp://localhost:5672".into(),
            ..AmqpConfig::default()
        }
    }

    fn tls() -> AmqpConfig {
        AmqpConfig {
            url: "amqps://broker.internal:5671".into(),
            ..AmqpConfig::default()
        }
    }

    #[test]
    fn scheme_selects_the_transport() {
        assert!(tls().is_tls());
        assert!(!plaintext().is_tls());
        // Case-insensitive: an operator writing AMQPS:// meant TLS.
        assert!(
            AmqpConfig {
                url: "AMQPS://broker:5671".into(),
                ..AmqpConfig::default()
            }
            .is_tls()
        );
        // ...but the separator is load-bearing: a scheme that merely STARTS
        // with "amqps" is not amqps.
        assert!(
            !AmqpConfig {
                url: "amqpsomething://broker:5671".into(),
                ..AmqpConfig::default()
            }
            .is_tls()
        );
    }

    #[test]
    fn an_unrecognised_scheme_is_rejected() {
        let cfg = AmqpConfig {
            url: "http://broker:5672".into(),
            ..AmqpConfig::default()
        };
        let err = cfg
            .validate_transport_security()
            .expect_err("an unrecognised scheme must fail at startup, not at dial time");
        assert!(
            format!("{err}").contains("amqps://"),
            "the error must name the scheme the operator should use, got: {err}"
        );
    }

    #[test]
    fn tls_url_is_always_accepted() {
        tls()
            .validate_transport_security()
            .expect("amqps:// with system roots needs no extra configuration");
    }

    #[test]
    fn tls_material_is_optional_but_must_be_internally_consistent() {
        assert!(AmqpTlsConfig::default().validate().is_ok());
        assert!(
            AmqpTlsConfig {
                ca_cert_path: Some("/etc/axiam/broker-ca.pem".into()),
                ..Default::default()
            }
            .validate()
            .is_ok(),
            "a CA bundle alone is the common private-CA case"
        );

        let cert_only = AmqpTlsConfig {
            client_cert_path: Some("/etc/axiam/client.pem".into()),
            ..Default::default()
        };
        let err = cert_only
            .validate()
            .expect_err("half a client identity must fail closed");
        assert!(format!("{err}").contains("CLIENT_KEY_PATH"), "got: {err}");

        let key_only = AmqpTlsConfig {
            client_key_path: Some("/etc/axiam/client.key".into()),
            ..Default::default()
        };
        assert!(key_only.validate().is_err(), "…and so must the mirror case");
    }

    /// The whole point of the flag: a release binary must not quietly send
    /// authorization requests, audit events and mail payloads in the clear.
    ///
    /// This test asserts the behaviour of the build it runs in. `cargo test`
    /// is a debug build, so the assertion it can make here is the debug half
    /// (plaintext permitted for `just dev-up`); the release half is asserted
    /// by the same `cfg!` the code branches on, so the two cannot disagree.
    #[test]
    fn plaintext_posture_follows_the_build_profile() {
        let result = plaintext().validate_transport_security();

        if cfg!(debug_assertions) {
            assert!(
                result.is_ok(),
                "a debug build must keep plaintext working for local dev"
            );
        } else {
            let err = result.expect_err("a release build must refuse unflagged plaintext");
            assert!(
                format!("{err}").contains("AXIAM__AMQP__ALLOW_PLAINTEXT"),
                "the error must name the escape hatch, got: {err}"
            );
        }
    }

    #[test]
    fn explicitly_allowed_plaintext_is_accepted_in_any_build() {
        let cfg = AmqpConfig {
            allow_plaintext: true,
            ..plaintext()
        };
        cfg.validate_transport_security()
            .expect("an operator who set the flag has made the decision");
    }

    /// TLS material on a plaintext URL is a misconfiguration worth warning
    /// about — the certificates are silently unused — but it is not fatal,
    /// because the URL is what actually decides and it is unambiguous.
    #[test]
    fn tls_material_on_a_plaintext_url_still_validates() {
        let cfg = AmqpConfig {
            allow_plaintext: true,
            tls: AmqpTlsConfig {
                ca_cert_path: Some("/etc/axiam/broker-ca.pem".into()),
                ..Default::default()
            },
            ..plaintext()
        };
        assert!(cfg.validate_transport_security().is_ok());
    }

    /// A malformed client identity must fail even on a TLS URL — this is the
    /// path where it would otherwise silently drop the mutual half of mTLS.
    #[test]
    fn inconsistent_client_identity_fails_on_a_tls_url_too() {
        let cfg = AmqpConfig {
            tls: AmqpTlsConfig {
                client_cert_path: Some("/etc/axiam/client.pem".into()),
                ..Default::default()
            },
            ..tls()
        };
        assert!(cfg.validate_transport_security().is_err());
    }

    /// There must be no way to ask for TLS without verification. This test is
    /// a tripwire on the config surface itself: adding such a field would make
    /// it fail, which is the point.
    #[test]
    fn there_is_no_verification_skip_option() {
        let rendered = format!("{:?}", AmqpTlsConfig::default());
        for forbidden in ["verify", "insecure", "skip", "danger"] {
            assert!(
                !rendered.to_ascii_lowercase().contains(forbidden),
                "AmqpTlsConfig must not grow a {forbidden:?}-shaped field: a \
                 verification-skip switch travels from a dev compose file into \
                 production and turns TLS into an expensive no-op"
            );
        }
    }
}

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
    /// Unset = verify against the platform root store. Set this when the broker
    /// certificate is issued by a private CA — including one issued by AXIAM's
    /// own `axiam-pki` org CA, which is the recommended dogfooding path.
    ///
    /// # This ADDS a root; it does not replace the platform store (SEC-106)
    ///
    /// Setting this does **not** narrow the trust set to your CA. lapin hands
    /// the bundle to `tcp-stream`, whose rustls backend calls
    /// `RustlsConnectorConfig::add_parsable_certificates` on top of the
    /// platform verifier's existing roots
    /// (`tcp-stream-0.34/src/rustls_impl.rs`). So after setting it, a
    /// certificate for the broker's hostname issued by *any* publicly trusted
    /// CA is still accepted — the trust set got wider, not narrower, which is
    /// the opposite of what "pin my private broker CA" is usually meant to
    /// achieve.
    ///
    /// There is no configuration here that changes that: `OwnedTLSConfig`
    /// carries only an identity and a certificate chain, with no hook for a
    /// rustls `ClientConfig`. If you need the trust set actually restricted to
    /// your CA, restrict it at the platform trust store the container image
    /// ships (`/etc/ssl/certs`) and leave this unset, or authenticate the
    /// broker with mutual TLS via [`Self::client_cert_path`], which is a
    /// stronger statement than root pinning anyway.
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
    /// AMQP connection URI. **Must** be `amqps://host:5671` (A6).
    ///
    /// There is no plaintext option: see
    /// [`AmqpConfig::validate_transport_security`], which refuses every scheme
    /// but `amqps://` in every build profile.
    pub url: String,
    /// TLS material for the `amqps://` connection (A6).
    #[serde(default)]
    pub tls: AmqpTlsConfig,
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
            url: "amqps://localhost:5671".into(),
            tls: AmqpTlsConfig::default(),
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

    /// Whether [`Self::url`] names the one accepted transport (A6).
    ///
    /// Scheme-based, case-insensitive, and deliberately strict about the
    /// separator: only `amqps://` is TLS, and everything else —
    /// `amqp://` included — is not, so
    /// [`Self::validate_transport_security`] refuses it rather than guessing.
    /// Matching on `amqps` without the `://` would classify a hypothetical
    /// `amqpsomething://` as TLS.
    pub fn is_tls(&self) -> bool {
        self.url.trim().to_ascii_lowercase().starts_with("amqps://")
    }

    /// Enforce the transport-security posture before any connection is
    /// attempted (A6).
    ///
    /// Two rules, and neither has an exception:
    ///
    /// 1. The URL scheme **must** be `amqps://`. Every other scheme — plaintext
    ///    `amqp://` included — is refused, in a debug build exactly as in a
    ///    release one.
    /// 2. TLS material that is internally inconsistent fails
    ///    ([`AmqpTlsConfig::validate`]).
    ///
    /// # Why there is no plaintext escape hatch any more
    ///
    /// There used to be one: `AXIAM__AMQP__ALLOW_PLAINTEXT` permitted `amqp://`
    /// in a release build, and a debug build permitted it unconditionally. Both
    /// are gone, because the flag did what an escape hatch does. Four of the
    /// project's own stacks reached for it — dev compose, e2e compose, the
    /// benchmark target and CI — and every one of them recorded a locally sound
    /// reason (throwaway data, an ephemeral CI broker, a hop the benchmark is
    /// trying to measure). Sound reasons are what an exception collects; the net
    /// effect was that "AMQP is TLS-only" described no deployment artifact in
    /// the repository except the production compose file and the k8s manifests.
    ///
    /// The project standard is "TLS 1.3 minimum for all external
    /// communication", and broker traffic carries authorization requests, audit
    /// events and outbound mail payloads across service boundaries by design.
    /// HMAC signing (§8) gives those authenticity and replay protection but
    /// **not** confidentiality. Failing closed here — with no build profile and
    /// no environment variable that changes the answer — is what makes the
    /// standard true of the broker rather than aspirational about it, and it is
    /// the same posture the SDK reactor dialers already enforce on the other end
    /// of the same link (CONTRACT.md §8b rules 1 and 5).
    ///
    /// The cost is real and was accepted deliberately: every stack now needs
    /// broker TLS material before it boots. `scripts/gen-broker-tls.sh` mints
    /// it, `just dev-up` and `just e2e-up` call that script, and
    /// `docs/deployment/README.md` documents bringing your own certificate
    /// instead.
    pub fn validate_transport_security(&self) -> Result<(), AxiamError> {
        if !self.is_tls() {
            return Err(AxiamError::ServiceUnavailable(format!(
                "AXIAM__AMQP__URL must use amqps:// (port 5671) — got {:?}. AMQP is \
                 TLS-only: broker traffic carries authorization requests, audit events \
                 and mail payloads across service boundaries, and HMAC signing protects \
                 their authenticity but not their confidentiality. There is no plaintext \
                 option and no build profile in which one exists; run \
                 `scripts/gen-broker-tls.sh` to mint broker TLS material, or point \
                 AXIAM__AMQP__TLS__CA_CERT_PATH at your own CA bundle.",
                self.url
            )));
        }

        self.tls.validate()
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

    /// The default must be usable as-is only over TLS: a config nobody
    /// configured is the one most likely to reach a deployment by accident.
    #[test]
    fn the_default_url_is_tls() {
        assert!(AmqpConfig::default().is_tls());
        AmqpConfig::default()
            .validate_transport_security()
            .expect("the default config must satisfy the transport rule it enforces");
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

    /// Everything that is not `amqps://` is refused, and the error names the
    /// scheme the operator should have used — an error that only says "no" is
    /// an error someone reads twice.
    #[test]
    fn every_scheme_but_amqps_is_rejected() {
        for url in [
            "http://broker:5672",
            "amqp://broker:5672",
            // A scheme that merely STARTS with "amqps" is not amqps: the `://`
            // separator is load-bearing.
            "amqpsomething://broker:5671",
            "broker:5671",
            "",
        ] {
            let cfg = AmqpConfig {
                url: url.into(),
                ..AmqpConfig::default()
            };
            let err = cfg.validate_transport_security().unwrap_err();
            assert!(
                format!("{err}").contains("amqps://"),
                "the error for {url:?} must name the scheme to use, got: {err}"
            );
        }
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

    /// The rule the whole section exists for: plaintext is refused in **every**
    /// build profile, not merely in a release one.
    ///
    /// This test runs in a debug build (`cargo test` always does), which is
    /// precisely the profile that used to permit plaintext — so it asserts the
    /// half of the old behaviour that actually changed. There is no `cfg!`
    /// branch left for the two profiles to disagree about.
    #[test]
    fn plaintext_is_refused_in_every_build_profile() {
        let err = plaintext()
            .validate_transport_security()
            .expect_err("plaintext must be refused, debug build included");
        assert!(
            format!("{err}").contains("TLS-only"),
            "the error must say the transport is TLS-only rather than merely \
             discouraged, got: {err}"
        );
    }

    /// A tripwire on the config surface: the plaintext escape hatch is gone and
    /// must not grow back under another name. Re-adding a field here would fail
    /// this test, which is the point.
    #[test]
    fn there_is_no_plaintext_escape_hatch() {
        let rendered = format!("{:?}", AmqpConfig::default()).to_ascii_lowercase();
        for forbidden in ["plaintext", "allow_insecure", "insecure"] {
            assert!(
                !rendered.contains(forbidden),
                "AmqpConfig must not grow a {forbidden:?}-shaped field: four of this \
                 project's own stacks reached for the last one, each with a locally \
                 sound reason, and between them they left `AMQP is TLS-only` true of \
                 almost no deployment artifact in the repository"
            );
        }
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

//! Implementations of [`SecretProvider`] — where a deployment's keys actually
//! come from.
//!
//! Three ship: [`EnvSecretProvider`] (the default, and what AXIAM has always
//! done), [`FileSecretProvider`] (what Docker secrets and Kubernetes `Secret`
//! volumes hand you), and [`VaultSecretProvider`] (HashiCorp Vault KV v2).
//!
//! Adding a fourth — AWS KMS, GCP Secret Manager, PKCS#11 — is a new type
//! implementing the same trait and one arm in the composition root. Nothing in
//! `axiam-auth`'s authentication code, and nothing in `axiam-api-rest`, needs
//! to know it happened.
//!
//! # Which one is actually better, honestly
//!
//! `file` is **not** a security improvement over `env`. Both put the key on the
//! same side of the trust boundary as the process that reads it: an attacker
//! who can read a mounted secret file can generally also read
//! `/proc/<pid>/environ`. It ships because it is what secret managers mount,
//! not because it hardens anything.
//!
//! `vault` is a real improvement, for reasons that have nothing to do with
//! encryption strength: the key is never written into a container spec, a
//! Compose file, a CI variable or a shell history; access is authenticated per
//! workload, audited, and revocable after the fact; and rotation is a write to
//! Vault rather than a redeploy. The key still lands in this process's memory —
//! it has to, to decrypt anything — so this is defence against the ways keys
//! actually leak, not against a compromised server.
//!
//! The version that would survive a compromised server is envelope encryption
//! against a Transit-style API where the plaintext key never leaves the KMS.
//! That is a strictly larger change — every seal and open becomes a network
//! round trip — and it is the natural next implementation of this same trait.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::secrets::SecretProvider;
use zeroize::Zeroizing;

/// Parse a key that arrived as text.
///
/// Accepts 64 hex characters, tolerating surrounding whitespace because a file
/// written with `echo` has a trailing newline and an operator should not lose
/// an afternoon to that.
fn parse_key(name: &str, raw: &str) -> AxiamResult<[u8; 32]> {
    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed).map_err(|_| {
        AxiamError::Internal(format!(
            "{name} must be 64 hex characters (32 bytes); got {} characters that are not valid hex",
            trimmed.len()
        ))
    })?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        AxiamError::Internal(format!(
            "{name} must be exactly 32 bytes (256 bits); got {}",
            v.len()
        ))
    })
}

// ---------------------------------------------------------------------------
// env
// ---------------------------------------------------------------------------

/// Reads keys from `AXIAM__AUTH__<NAME>`, uppercased.
///
/// The default, and what every existing deployment already does.
#[derive(Debug, Default, Clone, Copy)]
pub struct EnvSecretProvider;

impl EnvSecretProvider {
    /// The environment variable a logical key name maps to.
    pub fn var_name(name: &str) -> String {
        format!("AXIAM__AUTH__{}", name.to_uppercase())
    }
}

impl SecretProvider for EnvSecretProvider {
    fn get_key(&self, name: &str) -> AxiamResult<Option<[u8; 32]>> {
        match std::env::var(Self::var_name(name)) {
            Ok(raw) => parse_key(&Self::var_name(name), &raw).map(Some),
            // Genuinely absent, which is a configuration choice rather than a
            // failure — see the port's module docs.
            Err(_) => Ok(None),
        }
    }

    fn get_secret(&self, name: &str) -> AxiamResult<Option<Zeroizing<String>>> {
        Ok(std::env::var(Self::var_name(name)).ok().map(Zeroizing::new))
    }

    fn describe(&self) -> &'static str {
        "env"
    }
}

// ---------------------------------------------------------------------------
// file
// ---------------------------------------------------------------------------

/// Reads each key from `<dir>/<name>`, the layout Docker secrets and Kubernetes
/// `Secret` volumes produce.
///
/// A missing file is `Ok(None)`; a present-but-unreadable or malformed one is
/// an error, because an operator who mounted a file meant for it to be used.
#[derive(Debug, Clone)]
pub struct FileSecretProvider {
    dir: PathBuf,
}

impl FileSecretProvider {
    /// Read keys from `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The path a logical key name maps to.
    pub fn path_for(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl SecretProvider for FileSecretProvider {
    fn get_key(&self, name: &str) -> AxiamResult<Option<[u8; 32]>> {
        let path: &Path = &self.path_for(name);
        match std::fs::read_to_string(path) {
            Ok(raw) => {
                // `Zeroizing` so the decoded text does not outlive this call in
                // a freed heap page. Not a strong control — the key is about to
                // live in the process anyway — but free.
                let raw = Zeroizing::new(raw);
                parse_key(&path.display().to_string(), &raw).map(Some)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AxiamError::Internal(format!(
                "{} exists but could not be read: {e}",
                path.display()
            ))),
        }
    }

    fn get_secret(&self, name: &str) -> AxiamResult<Option<Zeroizing<String>>> {
        let path: &Path = &self.path_for(name);
        match std::fs::read_to_string(path) {
            // Only a trailing newline is stripped, not all whitespace: a PEM
            // document is multi-line and meaningful, and a pepper could
            // legitimately end in a space. `echo` adding one newline is the
            // case worth forgiving; guessing beyond that would corrupt a
            // secret an operator set deliberately.
            Ok(raw) => Ok(Some(Zeroizing::new(
                raw.strip_suffix('\n').unwrap_or(&raw).to_string(),
            ))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AxiamError::Internal(format!(
                "{} exists but could not be read: {e}",
                path.display()
            ))),
        }
    }

    fn describe(&self) -> &'static str {
        "file"
    }
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

/// Keys fetched from HashiCorp Vault's KV v2 engine at startup, then served
/// from memory.
///
/// Built by [`VaultSecretProvider::fetch`], which is the only async part of
/// this module and the reason the trait itself can stay synchronous: a KMS
/// belongs at composition time, not on a login.
///
/// `Debug` prints only the key *names* it holds, never their bytes.
#[derive(Clone)]
pub struct VaultSecretProvider {
    keys: HashMap<String, [u8; 32]>,
    secrets: HashMap<String, String>,
}

impl std::fmt::Debug for VaultSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&str> = self
            .keys
            .keys()
            .chain(self.secrets.keys())
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        f.debug_struct("VaultSecretProvider")
            .field("names", &names)
            .finish()
    }
}

/// How to reach Vault.
///
/// `Debug` is hand-written to redact the token. A derived one would print it,
/// and this struct is exactly the kind of thing that ends up in a startup log
/// line or a panic message — §7's `Sensitive` reasoning applied to config.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultConfig {
    /// Base address, e.g. `https://vault.internal:8200`.
    pub address: String,
    /// A token with read access to `mount`/`path`.
    pub token: String,
    /// KV v2 mount point. Vault's default is `secret`.
    pub mount: String,
    /// Path within the mount holding AXIAM's keys as fields.
    pub path: String,
    /// PEM bundle for the CA that issued Vault's listener certificate.
    ///
    /// `None` means "verify against the built-in roots", which is right only
    /// for a Vault fronted by a publicly-trusted certificate. Anything issued
    /// by an internal PKI — a cert-manager `ClusterIssuer`, `just tls-certs` —
    /// needs its trust anchor named here: reqwest is built with `rustls-tls`,
    /// whose roots are compiled in, so there is no `SSL_CERT_FILE` to fall
    /// back on and the handshake simply fails.
    ///
    /// The same shape as `AXIAM__AMQP__TLS__CA_CERT_PATH` for the broker, and
    /// for the same reason: a path to a file, because the process needs the
    /// anchor before it is allowed to read any secret.
    pub ca_cert_path: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("address", &self.address)
            .field("token", &"<redacted>")
            .field("mount", &self.mount)
            .field("path", &self.path)
            .field("ca_cert_path", &self.ca_cert_path)
            .finish()
    }
}

impl VaultSecretProvider {
    /// Read every key in `names` from Vault, once.
    ///
    /// A key absent from the secret is `None` and not an error — a deployment
    /// may legitimately store only some of them here. Vault being unreachable,
    /// refusing the token, or returning something unparseable **is** an error,
    /// and the composition root is expected to let it stop startup. A key this
    /// important failing open would be worse than not booting.
    pub async fn fetch(
        client: &reqwest::Client,
        config: &VaultConfig,
        key_names: &[&str],
        secret_names: &[&str],
    ) -> AxiamResult<Self> {
        let url = format!(
            "{}/v1/{}/data/{}",
            config.address.trim_end_matches('/'),
            config.mount.trim_matches('/'),
            config.path.trim_matches('/')
        );

        let response = client
            .get(&url)
            .header("X-Vault-Token", &config.token)
            .send()
            .await
            .map_err(|e| {
                // Deliberately does not include the token or the response body.
                AxiamError::Internal(format!("vault: request to {url} failed: {e}"))
            })?;

        if !response.status().is_success() {
            return Err(AxiamError::Internal(format!(
                "vault: {url} answered {} — check the token's policy and the mount path",
                response.status()
            )));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| AxiamError::Internal(format!("vault: {url} returned non-JSON: {e}")))?;

        // KV v2 nests the secret under data.data; KV v1 does not. Accept both
        // so a deployment on the older engine is not silently told its keys are
        // absent.
        let fields = body
            .get("data")
            .and_then(|d| d.get("data").or(Some(d)))
            .ok_or_else(|| {
                AxiamError::Internal(format!("vault: {url} returned no `data` object"))
            })?;

        let mut keys = HashMap::new();
        for name in key_names {
            if let Some(raw) = fields.get(*name).and_then(|v| v.as_str()) {
                keys.insert((*name).to_string(), parse_key(name, raw)?);
            }
        }

        let mut secrets = HashMap::new();
        for name in secret_names {
            if let Some(raw) = fields.get(*name).and_then(|v| v.as_str()) {
                secrets.insert((*name).to_string(), raw.to_string());
            }
        }

        Ok(Self { keys, secrets })
    }

    /// Build directly from already-resolved values. For tests and for a caller
    /// that fetched by some other means.
    pub fn from_values(keys: HashMap<String, [u8; 32]>, secrets: HashMap<String, String>) -> Self {
        Self { keys, secrets }
    }
}

impl SecretProvider for VaultSecretProvider {
    fn get_key(&self, name: &str) -> AxiamResult<Option<[u8; 32]>> {
        Ok(self.keys.get(name).copied())
    }

    fn get_secret(&self, name: &str) -> AxiamResult<Option<Zeroizing<String>>> {
        Ok(self.secrets.get(name).cloned().map(Zeroizing::new))
    }

    fn describe(&self) -> &'static str {
        "vault"
    }
}

// ---------------------------------------------------------------------------
// selection
// ---------------------------------------------------------------------------

/// Which provider a deployment has chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretProviderKind {
    /// `AXIAM__AUTH__<NAME>` environment variables. The default.
    Env,
    /// One file per key under a directory.
    File {
        /// Directory holding the key files.
        dir: PathBuf,
    },
    /// HashiCorp Vault KV v2.
    Vault(Box<VaultConfig>),
}

impl SecretProviderKind {
    /// Parse the `AXIAM__AUTH__SECRET_PROVIDER` selector and its companions.
    ///
    /// Unknown values are refused rather than falling back to `env`. Falling
    /// back would mean a typo in the provider name silently reverts a
    /// deployment to reading environment variables that are probably not set,
    /// which presents as "OPAQUE stopped working" with nothing in the logs
    /// pointing at the cause.
    pub fn from_env() -> AxiamResult<Self> {
        match std::env::var("AXIAM__AUTH__SECRET_PROVIDER")
            .unwrap_or_else(|_| "env".into())
            .trim()
            .to_lowercase()
            .as_str()
        {
            "env" => Ok(Self::Env),
            "file" => {
                let dir = std::env::var("AXIAM__AUTH__SECRET_DIR").map_err(|_| {
                    AxiamError::Internal(
                        "AXIAM__AUTH__SECRET_PROVIDER=file requires AXIAM__AUTH__SECRET_DIR".into(),
                    )
                })?;
                Ok(Self::File { dir: dir.into() })
            }
            "vault" => {
                let required = |var: &str| {
                    std::env::var(var).map_err(|_| {
                        AxiamError::Internal(format!(
                            "AXIAM__AUTH__SECRET_PROVIDER=vault requires {var}"
                        ))
                    })
                };
                Ok(Self::Vault(Box::new(VaultConfig {
                    address: required("AXIAM__AUTH__VAULT_ADDR")?,
                    token: required("AXIAM__AUTH__VAULT_TOKEN")?,
                    mount: std::env::var("AXIAM__AUTH__VAULT_MOUNT")
                        .unwrap_or_else(|_| "secret".into()),
                    path: std::env::var("AXIAM__AUTH__VAULT_PATH")
                        .unwrap_or_else(|_| "axiam".into()),
                    ca_cert_path: std::env::var("AXIAM__AUTH__VAULT_CA_CERT_PATH")
                        .ok()
                        .filter(|v| !v.trim().is_empty())
                        .map(Into::into),
                })))
            }
            other => Err(AxiamError::Internal(format!(
                "AXIAM__AUTH__SECRET_PROVIDER=`{other}` is not a known provider \
                 (expected `env`, `file` or `vault`)"
            ))),
        }
    }

    /// Build the provider this selector names, doing any network work now.
    pub async fn build(
        &self,
        client: &reqwest::Client,
        key_names: &[&str],
        secret_names: &[&str],
    ) -> AxiamResult<Box<dyn SecretProvider>> {
        Ok(match self {
            Self::Env => Box::new(EnvSecretProvider),
            Self::File { dir } => Box::new(FileSecretProvider::new(dir.clone())),
            Self::Vault(config) => {
                // The shared bootstrap client trusts the built-in roots only.
                // When the operator names a CA, a second client is built that
                // also trusts that one — additively, so a Vault behind a public
                // certificate keeps working. Failing to read or parse the
                // bundle is fatal: continuing would fall back to the default
                // trust store, which is the check the operator asked for.
                let private_ca_client;
                let client = match &config.ca_cert_path {
                    None => client,
                    Some(path) => {
                        let pem = std::fs::read(path).map_err(|e| {
                            AxiamError::Internal(format!(
                                "vault: reading the CA bundle {} failed: {e}",
                                path.display()
                            ))
                        })?;
                        let anchors = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
                            AxiamError::Internal(format!(
                                "vault: {} is not a PEM certificate bundle: {e}",
                                path.display()
                            ))
                        })?;
                        let mut builder = reqwest::Client::builder();
                        for anchor in anchors {
                            builder = builder.add_root_certificate(anchor);
                        }
                        private_ca_client = builder.build().map_err(|e| {
                            AxiamError::Internal(format!(
                                "vault: building an HTTP client trusting {} failed: {e}",
                                path.display()
                            ))
                        })?;
                        &private_ca_client
                    }
                };
                Box::new(VaultSecretProvider::fetch(client, config, key_names, secret_names).await?)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::secrets::{OPAQUE_SESSION_KEY, OPAQUE_SETUP_KEY};

    /// A key minted per call rather than written as a literal.
    ///
    /// CodeQL's `rust/hardcoded-cryptographic-value` is right about shipping
    /// code, and nothing here depends on the value — only on it round-tripping.
    fn a_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).expect("a CSPRNG");
        key
    }

    // -- parsing ---------------------------------------------------------

    #[test]
    fn a_key_round_trips_through_hex() {
        let key = a_key();
        assert_eq!(parse_key("k", &hex::encode(key)).unwrap(), key);
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        // A file written with `echo` has a trailing newline, and an operator
        // should not lose an afternoon to that.
        let key = a_key();
        assert_eq!(
            parse_key("k", &format!("  {}\n", hex::encode(key))).unwrap(),
            key
        );
    }

    #[test]
    fn a_wrong_length_key_is_refused_rather_than_padded() {
        // Padding or truncating would produce a key that works consistently
        // and is not the one the operator configured — the worst outcome,
        // because everything appears fine until the real key is needed.
        let short = hex::encode([0u8; 16]);
        let err = parse_key("k", &short).unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "{err}");
    }

    #[test]
    fn a_non_hex_key_names_itself_in_the_error() {
        let err = parse_key("opaque_setup_key", "not hex at all")
            .unwrap_err()
            .to_string();
        assert!(err.contains("opaque_setup_key"), "{err}");
        assert!(err.contains("hex"), "{err}");
    }

    // -- file ------------------------------------------------------------

    #[test]
    fn the_file_provider_reads_one_file_per_key() {
        let dir = std::env::temp_dir().join(format!("axiam-secrets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = a_key();
        std::fs::write(dir.join(OPAQUE_SETUP_KEY), hex::encode(key)).unwrap();

        let provider = FileSecretProvider::new(&dir);
        assert_eq!(provider.get_key(OPAQUE_SETUP_KEY).unwrap(), Some(key));

        // A key this deployment did not mount is absent, not an error: that is
        // a configuration choice, and the caller decides what it means.
        assert_eq!(provider.get_key(OPAQUE_SESSION_KEY).unwrap(), None);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_malformed_mounted_file_is_an_error_not_an_absence() {
        // An operator who mounted a file meant for it to be used. Treating a
        // corrupt one as "not configured" would silently disable OPAQUE.
        let dir = std::env::temp_dir().join(format!("axiam-secrets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OPAQUE_SETUP_KEY), "clearly not a key").unwrap();

        let provider = FileSecretProvider::new(&dir);
        assert!(provider.get_key(OPAQUE_SETUP_KEY).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_file_provider_names_the_path_in_its_error() {
        // So an operator can see *which* mount is wrong without guessing.
        let dir = std::env::temp_dir().join(format!("axiam-secrets-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OPAQUE_SETUP_KEY), "zz").unwrap();

        let err = FileSecretProvider::new(&dir)
            .get_key(OPAQUE_SETUP_KEY)
            .unwrap_err()
            .to_string();
        assert!(err.contains(OPAQUE_SETUP_KEY), "{err}");

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- vault -----------------------------------------------------------

    #[test]
    fn the_vault_provider_serves_from_memory() {
        let key = a_key();
        let provider = VaultSecretProvider::from_values(
            HashMap::from([(OPAQUE_SETUP_KEY.to_string(), key)]),
            HashMap::new(),
        );
        assert_eq!(provider.get_key(OPAQUE_SETUP_KEY).unwrap(), Some(key));
        assert_eq!(provider.get_key(OPAQUE_SESSION_KEY).unwrap(), None);
    }

    #[test]
    fn vault_config_debug_redacts_the_token() {
        // This struct is exactly the kind of thing that ends up in a startup
        // log line or a panic message.
        let config = VaultConfig {
            address: "https://vault.internal:8200".into(),
            token: "hvs.THIS-MUST-NOT-APPEAR".into(),
            mount: "secret".into(),
            path: "axiam".into(),
            ca_cert_path: None,
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("THIS-MUST-NOT-APPEAR"), "{rendered}");
        assert!(rendered.contains("redacted"), "{rendered}");
        // The non-secret parts stay, because they are what makes the line
        // useful for diagnosing a misconfiguration.
        assert!(rendered.contains("vault.internal"), "{rendered}");
    }

    #[test]
    fn vault_provider_debug_renders_names_not_key_material() {
        let key = a_key();
        let provider = VaultSecretProvider::from_values(
            HashMap::from([(OPAQUE_SETUP_KEY.to_string(), key)]),
            HashMap::new(),
        );
        let rendered = format!("{provider:?}");
        assert!(!rendered.contains(&hex::encode(key)), "{rendered}");
        assert!(rendered.contains(OPAQUE_SETUP_KEY), "{rendered}");
    }

    // -- selection -------------------------------------------------------

    /// Serializes the tests that mutate the process environment.
    ///
    /// `cargo test` runs a crate's tests as threads in one process, so
    /// `set_var` in one is visible to every other. Without this the three tests
    /// below fail each other intermittently — which is worse than failing
    /// outright, because it reads as flakiness in CI.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn an_unknown_provider_name_is_refused_rather_than_defaulting() {
        // Falling back to `env` on a typo would silently revert a deployment to
        // reading variables that are probably not set, presenting as "OPAQUE
        // stopped working" with nothing in the logs pointing at the cause.
        //
        let _guard = env_lock();
        // SAFETY: serialized by `env_lock`, variable removed before returning.
        unsafe { std::env::set_var("AXIAM__AUTH__SECRET_PROVIDER", "valut") };
        let err = SecretProviderKind::from_env().unwrap_err().to_string();
        unsafe { std::env::remove_var("AXIAM__AUTH__SECRET_PROVIDER") };

        assert!(
            err.contains("valut"),
            "the error must quote what was set: {err}"
        );
        assert!(err.contains("env"), "and name the valid options: {err}");
    }

    #[test]
    fn file_without_a_directory_is_refused_at_startup() {
        let _guard = env_lock();
        // SAFETY: serialized by `env_lock`.
        unsafe { std::env::set_var("AXIAM__AUTH__SECRET_PROVIDER", "file") };
        unsafe { std::env::remove_var("AXIAM__AUTH__SECRET_DIR") };
        let err = SecretProviderKind::from_env().unwrap_err().to_string();
        unsafe { std::env::remove_var("AXIAM__AUTH__SECRET_PROVIDER") };

        assert!(err.contains("AXIAM__AUTH__SECRET_DIR"), "{err}");
    }

    #[test]
    fn the_default_is_env_so_an_existing_deployment_is_unaffected() {
        let _guard = env_lock();
        // SAFETY: serialized by `env_lock`.
        unsafe { std::env::remove_var("AXIAM__AUTH__SECRET_PROVIDER") };
        assert_eq!(
            SecretProviderKind::from_env().unwrap(),
            SecretProviderKind::Env
        );
    }

    #[test]
    fn a_vault_ca_bundle_is_optional_and_read_from_the_environment() {
        // The local stack and every cert-manager deployment front Vault with a
        // private CA. Without this path the handshake fails with a transport
        // error that says nothing about trust, so the variable existing — and
        // staying optional for a publicly-trusted Vault — is the contract.
        let _guard = env_lock();
        // SAFETY: serialized by `env_lock`, variables removed before returning.
        unsafe {
            std::env::set_var("AXIAM__AUTH__SECRET_PROVIDER", "vault");
            std::env::set_var("AXIAM__AUTH__VAULT_ADDR", "https://vault:8200");
            std::env::set_var("AXIAM__AUTH__VAULT_TOKEN", "t");
            std::env::remove_var("AXIAM__AUTH__VAULT_CA_CERT_PATH");
        }
        let without = SecretProviderKind::from_env().unwrap();

        // SAFETY: serialized by `env_lock`.
        unsafe { std::env::set_var("AXIAM__AUTH__VAULT_CA_CERT_PATH", "/etc/axiam/vault/ca.pem") };
        let with = SecretProviderKind::from_env().unwrap();

        // An empty value is the same as unset: a compose file that interpolates
        // a variable nobody exported would otherwise name the path "".
        // SAFETY: serialized by `env_lock`.
        unsafe { std::env::set_var("AXIAM__AUTH__VAULT_CA_CERT_PATH", "   ") };
        let blank = SecretProviderKind::from_env().unwrap();

        // SAFETY: serialized by `env_lock`.
        unsafe {
            std::env::remove_var("AXIAM__AUTH__SECRET_PROVIDER");
            std::env::remove_var("AXIAM__AUTH__VAULT_ADDR");
            std::env::remove_var("AXIAM__AUTH__VAULT_TOKEN");
            std::env::remove_var("AXIAM__AUTH__VAULT_CA_CERT_PATH");
        }

        let ca = |k: &SecretProviderKind| match k {
            SecretProviderKind::Vault(c) => c.ca_cert_path.clone(),
            other => panic!("expected a vault provider, got {other:?}"),
        };
        assert_eq!(ca(&without), None);
        assert_eq!(
            ca(&with),
            Some(std::path::PathBuf::from("/etc/axiam/vault/ca.pem"))
        );
        assert_eq!(ca(&blank), None);
    }

    #[test]
    fn env_var_names_are_derived_from_the_logical_name() {
        assert_eq!(
            EnvSecretProvider::var_name(OPAQUE_SETUP_KEY),
            "AXIAM__AUTH__OPAQUE_SETUP_KEY"
        );
    }
}

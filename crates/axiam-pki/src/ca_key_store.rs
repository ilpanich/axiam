//! Custodians for CA signing keys — the implementations behind
//! [`axiam_core::ca_keys::CaKeyStore`].
//!
//! Two of them today:
//!
//! * [`DatabaseCaKeyStore`] — AES-256-GCM ciphertext in the `ca_certificate`
//!   row, sealed under the process-wide `pki_encryption_key`. What AXIAM has
//!   always done, and still the default.
//! * [`VaultCaKeyStore`] — a HashiCorp Vault KV v2 secret. The row holds a path
//!   and no key material.
//!
//! A KMS is the next one, and the port is shaped so it slots in beside these
//! rather than replacing them: a deployment that adopts a new custodian keeps
//! the CAs it already had, because each row records which custodian holds its
//! key.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use axiam_core::ca_keys::{CaKeyCustody, CaKeyRef, CaKeyStore, StoredCaKey};
use axiam_core::error::{AxiamError, AxiamResult};
use reqwest::Client;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{decrypt_secret, encrypt_secret};

// ---------------------------------------------------------------------------
// database
// ---------------------------------------------------------------------------

/// The CA key sealed into its own row with AES-256-GCM.
///
/// The control this gives is real but bounded, and worth stating plainly: the
/// key and the thing that opens it are in the same blast radius. Whoever holds
/// a database dump *and* one process's `pki_encryption_key` holds every CA in
/// the deployment, and no record anywhere says they read it.
#[derive(Clone)]
pub struct DatabaseCaKeyStore {
    encryption_key: [u8; 32],
}

impl DatabaseCaKeyStore {
    pub fn new(encryption_key: [u8; 32]) -> Self {
        Self { encryption_key }
    }
}

impl CaKeyStore for DatabaseCaKeyStore {
    fn store<'a>(
        &'a self,
        _organization_id: Uuid,
        _ca_id: Uuid,
        private_key_pem: &'a str,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<StoredCaKey>> + Send + 'a>> {
        Box::pin(async move {
            let ciphertext = encrypt_secret(private_key_pem.as_bytes(), &self.encryption_key)?;
            Ok(StoredCaKey::Inline(ciphertext))
        })
    }

    fn load<'a>(
        &'a self,
        _key_ref: &'a CaKeyRef,
        inline: Option<&'a [u8]>,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Zeroizing<String>>> + Send + 'a>> {
        Box::pin(async move {
            let ciphertext = inline.ok_or_else(|| {
                AxiamError::Certificate("CA certificate has no stored private key".into())
            })?;
            let plaintext = decrypt_secret(ciphertext, &self.encryption_key)?;
            let pem = String::from_utf8(plaintext).map_err(|_| {
                // A wrong key produces an authentication failure inside
                // `decrypt_secret`, not this — so reaching here means the
                // ciphertext decrypted to bytes that are not a PEM, which is
                // corruption rather than a key mix-up.
                AxiamError::Crypto("decrypted CA private key is not valid UTF-8".into())
            })?;
            Ok(Zeroizing::new(pem))
        })
    }

    fn delete<'a>(
        &'a self,
        _key_ref: &'a CaKeyRef,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>> {
        // The material lives in the row; removing the row removes it.
        Box::pin(async { Ok(()) })
    }

    fn custody(&self) -> CaKeyCustody {
        CaKeyCustody::Database
    }

    fn describe(&self) -> &'static str {
        "database"
    }
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

/// How to reach Vault for CA key custody.
///
/// Deliberately separate from `axiam_auth::secrets::VaultConfig` even though
/// both address a KV v2 engine. That one names *one path* holding the
/// deployment's fixed startup secrets as fields; this one names a *prefix*
/// under which one secret per CA is created at runtime. Sharing a type would
/// mean one `path` field meaning two different things, and a policy that had to
/// grant both uses to one token.
///
/// `Debug` is hand-written to redact the token — this struct is exactly the
/// kind of thing that reaches a startup log line or a panic message.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultCaKeyConfig {
    /// Base address, e.g. `https://vault.internal:8200`.
    pub address: String,
    /// A token with create/read/delete on `mount`/`prefix`/*.
    pub token: String,
    /// KV v2 mount point. Vault's default is `secret`.
    pub mount: String,
    /// Path prefix under the mount. One secret is written per CA beneath it.
    pub prefix: String,
    /// PEM bundle for the CA that issued Vault's listener certificate.
    ///
    /// `None` verifies against the built-in roots, which is right only for a
    /// Vault fronted by a publicly-trusted certificate. reqwest is built with
    /// `rustls-tls`, whose roots are compiled in, so an internally-issued
    /// listener certificate has no `SSL_CERT_FILE` to fall back on and the
    /// handshake simply fails.
    pub ca_cert_path: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for VaultCaKeyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultCaKeyConfig")
            .field("address", &self.address)
            .field("token", &"<redacted>")
            .field("mount", &self.mount)
            .field("prefix", &self.prefix)
            .field("ca_cert_path", &self.ca_cert_path)
            .finish()
    }
}

/// The field name inside the Vault secret. One field, one key.
const VAULT_KEY_FIELD: &str = "private_key_pem";

/// How long to wait on Vault before giving up.
///
/// Bounded because this runs on the request that issues a certificate, not at
/// startup like the secret provider: an unbounded wait would turn a Vault
/// outage into hung request handlers rather than a refused issuance.
const VAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// CA keys held in HashiCorp Vault's KV v2 engine.
///
/// Each CA gets its own secret at `<mount>/data/<prefix>/<org_id>/<ca_id>`,
/// with the PEM in a single `private_key_pem` field. One secret per CA rather
/// than one secret with a field per CA, because Vault policy paths are the unit
/// of access control: an operator who wants to grant read on one organization's
/// CAs and not another's can write that as a path glob, and could not write it
/// at all if every key shared one secret.
///
/// The key still reaches AXIAM's memory to sign with — see the port's module
/// docs for why that is custody rather than the stronger property, and what
/// would be needed for the stronger one.
#[derive(Clone)]
pub struct VaultCaKeyStore {
    client: Client,
    config: VaultCaKeyConfig,
}

impl std::fmt::Debug for VaultCaKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultCaKeyStore")
            .field("config", &self.config)
            .finish()
    }
}

impl VaultCaKeyStore {
    /// Build a store, including the TLS trust anchor if one is configured.
    ///
    /// Fails rather than falling back to the built-in roots when the anchor is
    /// unreadable: silently verifying against a different trust store than the
    /// operator asked for is how a misconfiguration becomes a connection to
    /// something that is not their Vault.
    pub fn new(config: VaultCaKeyConfig) -> AxiamResult<Self> {
        let mut builder = Client::builder().timeout(VAULT_TIMEOUT);

        if let Some(ref path) = config.ca_cert_path {
            let pem = std::fs::read(path).map_err(|e| {
                AxiamError::Internal(format!(
                    "vault CA key store: could not read the trust anchor at {}: {e}",
                    path.display()
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                AxiamError::Internal(format!(
                    "vault CA key store: {} is not a PEM certificate: {e}",
                    path.display()
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let client = builder.build().map_err(|e| {
            AxiamError::Internal(format!(
                "vault CA key store: could not build HTTP client: {e}"
            ))
        })?;

        Ok(Self { client, config })
    }

    /// Build from an already-configured client. For tests, and for a caller
    /// that has its own client policy.
    pub fn with_client(client: Client, config: VaultCaKeyConfig) -> Self {
        Self { client, config }
    }

    /// The KV v2 *data* URL for one CA's secret.
    ///
    /// Ids are UUIDs and cannot contain a path separator, so there is nothing
    /// to escape — but the locator is built here once and stored, so a future
    /// change to the layout cannot strand keys written under the old one.
    fn data_url(&self, organization_id: Uuid, ca_id: Uuid) -> String {
        format!(
            "{}/v1/{}/data/{}/{organization_id}/{ca_id}",
            self.config.address.trim_end_matches('/'),
            self.config.mount.trim_matches('/'),
            self.config.prefix.trim_matches('/'),
        )
    }

    /// The KV v2 *metadata* URL, whose DELETE removes every version.
    ///
    /// A KV v2 `DELETE` on the data path only marks the latest version deleted
    /// and leaves it readable by anyone who can ask for a version number. For a
    /// CA signing key that is not deletion.
    fn metadata_url(&self, locator: &str) -> String {
        format!(
            "{}/v1/{}/metadata/{}",
            self.config.address.trim_end_matches('/'),
            self.config.mount.trim_matches('/'),
            locator.trim_matches('/'),
        )
    }

    /// The stored locator: the path *within the mount*, no address, no mount.
    ///
    /// Storing it that way means moving Vault to a new address, or remounting
    /// the engine, does not invalidate every CA row.
    fn locator(&self, organization_id: Uuid, ca_id: Uuid) -> String {
        format!(
            "{}/{organization_id}/{ca_id}",
            self.config.prefix.trim_matches('/')
        )
    }

    fn read_url(&self, locator: &str) -> String {
        format!(
            "{}/v1/{}/data/{}",
            self.config.address.trim_end_matches('/'),
            self.config.mount.trim_matches('/'),
            locator.trim_matches('/'),
        )
    }
}

impl CaKeyStore for VaultCaKeyStore {
    fn store<'a>(
        &'a self,
        organization_id: Uuid,
        ca_id: Uuid,
        private_key_pem: &'a str,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<StoredCaKey>> + Send + 'a>> {
        Box::pin(async move {
            let url = self.data_url(organization_id, ca_id);
            let body = serde_json::json!({
                "data": { VAULT_KEY_FIELD: private_key_pem },
                // Refuse to overwrite: a CA id is freshly generated, so an
                // existing secret at this path means either an id collision or
                // a retry of a call that already succeeded. Silently replacing
                // would destroy a live signing key.
                "options": { "cas": 0 },
            });

            let response = self
                .client
                .post(&url)
                .header("X-Vault-Token", &self.config.token)
                .json(&body)
                .send()
                .await
                // Deliberately carries neither the token nor the key.
                .map_err(|e| {
                    AxiamError::Internal(format!("vault: writing the CA key to {url} failed: {e}"))
                })?;

            if !response.status().is_success() {
                return Err(AxiamError::Internal(format!(
                    "vault: {url} answered {} on write — check the token's policy \
                     has create and update on this path",
                    response.status()
                )));
            }

            Ok(StoredCaKey::Referenced(
                self.locator(organization_id, ca_id),
            ))
        })
    }

    fn load<'a>(
        &'a self,
        key_ref: &'a CaKeyRef,
        _inline: Option<&'a [u8]>,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Zeroizing<String>>> + Send + 'a>> {
        Box::pin(async move {
            let url = self.read_url(&key_ref.locator);
            let response = self
                .client
                .get(&url)
                .header("X-Vault-Token", &self.config.token)
                .send()
                .await
                .map_err(|e| {
                    AxiamError::Internal(format!(
                        "vault: reading the CA key from {url} failed: {e}"
                    ))
                })?;

            if response.status() == reqwest::StatusCode::NOT_FOUND {
                // Distinguished from a transport failure because it means
                // something different: the CA row points at a secret that is
                // not there, which is a custody problem an operator has to fix,
                // not something a retry will resolve.
                return Err(AxiamError::Certificate(format!(
                    "vault holds no key for this CA at {}: it was deleted, or the \
                     mount was changed after the CA was created",
                    key_ref.locator
                )));
            }
            if !response.status().is_success() {
                return Err(AxiamError::Internal(format!(
                    "vault: {url} answered {} on read — check the token's policy \
                     has read on this path",
                    response.status()
                )));
            }

            let body: serde_json::Value = response.json().await.map_err(|e| {
                AxiamError::Internal(format!("vault: {url} returned non-JSON: {e}"))
            })?;

            // KV v2 nests under data.data; KV v1 does not. Accept both, as the
            // startup secret provider does, so a deployment on the older engine
            // is not told its key is absent.
            let pem = body
                .get("data")
                .and_then(|d| d.get("data").or(Some(d)))
                .and_then(|d| d.get(VAULT_KEY_FIELD))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    AxiamError::Certificate(format!(
                        "vault: the secret at {} has no `{VAULT_KEY_FIELD}` field",
                        key_ref.locator
                    ))
                })?;

            Ok(Zeroizing::new(pem.to_string()))
        })
    }

    fn delete<'a>(
        &'a self,
        key_ref: &'a CaKeyRef,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let url = self.metadata_url(&key_ref.locator);
            let response = self
                .client
                .delete(&url)
                .header("X-Vault-Token", &self.config.token)
                .send()
                .await
                .map_err(|e| {
                    AxiamError::Internal(format!("vault: deleting the CA key at {url} failed: {e}"))
                })?;

            // Already gone is success: this is called on revocation, and a
            // second revocation must not fail because the first one worked.
            if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND
            {
                return Ok(());
            }
            Err(AxiamError::Internal(format!(
                "vault: {url} answered {} on delete",
                response.status()
            )))
        })
    }

    fn custody(&self) -> CaKeyCustody {
        CaKeyCustody::Vault
    }

    fn describe(&self) -> &'static str {
        "vault"
    }
}

// ---------------------------------------------------------------------------
// external
// ---------------------------------------------------------------------------

/// A CA whose private key AXIAM does not hold.
///
/// Not a custodian so much as the absence of one, expressed as a type so the
/// signing path can ask the same question of every CA and get an answer that
/// says *why* rather than a bare "no key".
#[derive(Clone, Debug, Default)]
pub struct ExternalCaKeyStore;

impl CaKeyStore for ExternalCaKeyStore {
    fn store<'a>(
        &'a self,
        _organization_id: Uuid,
        _ca_id: Uuid,
        _private_key_pem: &'a str,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<StoredCaKey>> + Send + 'a>> {
        Box::pin(async {
            Err(AxiamError::Validation {
                message: "this CA's private key is held outside AXIAM and cannot be \
                          stored here"
                    .into(),
            })
        })
    }

    fn load<'a>(
        &'a self,
        _key_ref: &'a CaKeyRef,
        _inline: Option<&'a [u8]>,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Zeroizing<String>>> + Send + 'a>> {
        Box::pin(async {
            // `Validation`, not `Certificate`: this is a statement about the
            // request — the caller picked a CA that holds no key — and it has
            // to reach them. `Certificate` maps to a generic 500 whose body
            // says only "an internal error occurred".
            Err(AxiamError::Validation {
                message: "this CA was imported without a private key: AXIAM can trust \
                          certificates it signed but cannot issue new ones against it"
                    .into(),
            })
        })
    }

    fn delete<'a>(
        &'a self,
        _key_ref: &'a CaKeyRef,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    fn custody(&self) -> CaKeyCustody {
        CaKeyCustody::External
    }

    fn describe(&self) -> &'static str {
        "external"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----\n";

    fn key_ref(custody: CaKeyCustody, locator: &str) -> CaKeyRef {
        CaKeyRef {
            organization_id: Uuid::nil(),
            ca_id: Uuid::nil(),
            custody,
            locator: locator.to_string(),
        }
    }

    fn vault_config() -> VaultCaKeyConfig {
        VaultCaKeyConfig {
            address: "https://vault.internal:8200/".into(),
            token: "s.token".into(),
            mount: "/secret/".into(),
            prefix: "/axiam/ca/".into(),
            ca_cert_path: None,
        }
    }

    // --- database custodian ---

    #[tokio::test]
    async fn database_custody_round_trips_a_key() {
        let store = DatabaseCaKeyStore::new([7u8; 32]);
        let stored = store
            .store(Uuid::new_v4(), Uuid::new_v4(), PEM)
            .await
            .unwrap();
        let ciphertext = match stored {
            StoredCaKey::Inline(c) => c,
            other => panic!("the database custodian must hand back ciphertext, got {other:?}"),
        };
        assert_ne!(
            ciphertext,
            PEM.as_bytes(),
            "the row must not hold plaintext"
        );

        let loaded = store
            .load(&key_ref(CaKeyCustody::Database, ""), Some(&ciphertext))
            .await
            .unwrap();
        assert_eq!(&*loaded, PEM);
    }

    #[tokio::test]
    async fn database_custody_refuses_another_deployments_ciphertext() {
        let a = DatabaseCaKeyStore::new([7u8; 32]);
        let b = DatabaseCaKeyStore::new([9u8; 32]);
        let stored = a.store(Uuid::new_v4(), Uuid::new_v4(), PEM).await.unwrap();
        let StoredCaKey::Inline(ciphertext) = stored else {
            unreachable!()
        };
        assert!(
            b.load(&key_ref(CaKeyCustody::Database, ""), Some(&ciphertext))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn database_custody_rejects_ciphertext_too_short_to_hold_a_nonce() {
        let store = DatabaseCaKeyStore::new([7u8; 32]);
        let err = store
            .load(&key_ref(CaKeyCustody::Database, ""), Some(&[1, 2, 3]))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing nonce"), "{err}");
    }

    #[tokio::test]
    async fn database_custody_rejects_plaintext_that_is_not_a_pem() {
        // Reaching here means the ciphertext authenticated and decrypted to
        // bytes that are not text — corruption, not a key mix-up, and the
        // message says so.
        let store = DatabaseCaKeyStore::new([7u8; 32]);
        let ciphertext = crate::crypto::encrypt_secret(&[0xFF, 0xFE, 0x80], &[7u8; 32]).unwrap();
        let err = store
            .load(&key_ref(CaKeyCustody::Database, ""), Some(&ciphertext))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not valid UTF-8"), "{err}");
    }

    #[tokio::test]
    async fn database_custody_names_the_missing_key_rather_than_panicking() {
        let store = DatabaseCaKeyStore::new([7u8; 32]);
        let err = store
            .load(&key_ref(CaKeyCustody::Database, ""), None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no stored private key"), "{err}");
    }

    // --- vault custodian: URL construction, which is where a path bug hides ---

    #[test]
    fn vault_urls_normalise_the_slashes_an_operator_types() {
        let store = VaultCaKeyStore::with_client(Client::new(), vault_config());
        let org = Uuid::nil();
        let ca = Uuid::nil();

        assert_eq!(
            store.data_url(org, ca),
            format!("https://vault.internal:8200/v1/secret/data/axiam/ca/{org}/{ca}")
        );
        assert_eq!(store.locator(org, ca), format!("axiam/ca/{org}/{ca}"));
        assert_eq!(
            store.read_url(&store.locator(org, ca)),
            format!("https://vault.internal:8200/v1/secret/data/axiam/ca/{org}/{ca}")
        );
    }

    #[test]
    fn vault_delete_targets_metadata_so_every_version_goes() {
        // A KV v2 DELETE on the data path soft-deletes the latest version and
        // leaves it readable by version number. For a CA signing key that is
        // not deletion.
        let store = VaultCaKeyStore::with_client(Client::new(), vault_config());
        let locator = store.locator(Uuid::nil(), Uuid::nil());
        assert!(store.metadata_url(&locator).contains("/metadata/"));
        assert!(!store.metadata_url(&locator).contains("/data/"));
    }

    #[test]
    fn the_stored_locator_carries_no_address_or_mount() {
        // So that moving Vault, or remounting the engine, does not strand every
        // CA row in the database.
        let store = VaultCaKeyStore::with_client(Client::new(), vault_config());
        let locator = store.locator(Uuid::nil(), Uuid::nil());
        assert!(!locator.contains("vault.internal"));
        assert!(!locator.starts_with("secret"));
    }

    #[test]
    fn vault_config_debug_redacts_the_token() {
        let printed = format!("{:?}", vault_config());
        assert!(!printed.contains("s.token"), "{printed}");
        assert!(printed.contains("<redacted>"));
    }

    #[test]
    fn a_missing_trust_anchor_fails_rather_than_falling_back() {
        let config = VaultCaKeyConfig {
            ca_cert_path: Some("/nonexistent/vault-ca.pem".into()),
            ..vault_config()
        };
        let err = VaultCaKeyStore::new(config).unwrap_err();
        assert!(err.to_string().contains("trust anchor"), "{err}");
    }

    // --- external ---

    #[tokio::test]
    async fn an_external_ca_explains_why_it_cannot_sign() {
        let store = ExternalCaKeyStore;
        let err = store
            .load(&key_ref(CaKeyCustody::External, ""), None)
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("without a private key"), "{msg}");
        assert!(msg.contains("cannot issue"), "{msg}");
    }

    #[tokio::test]
    async fn an_external_ca_refuses_to_take_custody() {
        let store = ExternalCaKeyStore;
        assert!(
            store
                .store(Uuid::new_v4(), Uuid::new_v4(), PEM)
                .await
                .is_err()
        );
    }

    #[test]
    fn each_custodian_reports_its_own_kind() {
        assert_eq!(
            DatabaseCaKeyStore::new([0u8; 32]).custody(),
            CaKeyCustody::Database
        );
        assert_eq!(
            VaultCaKeyStore::with_client(Client::new(), vault_config()).custody(),
            CaKeyCustody::Vault
        );
        assert_eq!(ExternalCaKeyStore.custody(), CaKeyCustody::External);
    }
}

// ---------------------------------------------------------------------------
// the registry
// ---------------------------------------------------------------------------

/// Every custodian this process can reach, dispatching on what a CA row says.
///
/// The reason this exists rather than the composition root simply choosing one
/// store: a deployment that adopts Vault does not thereby move the CAs it
/// already has. Those rows still say `database`, their keys are still sealed
/// into them, and a signing path that consulted only the *current* setting
/// would fail to find them.
///
/// So: new CAs go to [`Self::default_store`], the one configured as current,
/// and reads go to whichever custodian the row names. Switching custodian is
/// then a decision about new CAs only, and migrating an old one is a deliberate
/// separate act rather than something that happens by restarting with a
/// different environment.
#[derive(Clone)]
pub struct CaKeyCustodians {
    database: Option<DatabaseCaKeyStore>,
    vault: Option<VaultCaKeyStore>,
    external: ExternalCaKeyStore,
    /// `None` when a deployment has configured no custodian at all.
    ///
    /// That is a legitimate state, not a misconfiguration: a deployment that
    /// issues no certificates — no CAs, no mTLS — has no reason to hold a PKI
    /// key, and refusing to start would break it for a feature it does not
    /// use. Generating a CA is then what fails, with a message naming what to
    /// set, which is where the operator actually is when they need it.
    default_custody: Option<CaKeyCustody>,
}

impl std::fmt::Debug for CaKeyCustodians {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaKeyCustodians")
            .field("database", &self.database.is_some())
            .field("vault", &self.vault.is_some())
            .field("default", &self.default_custody)
            .finish()
    }
}

impl CaKeyCustodians {
    /// Build the set, choosing `default_custody` for new CAs.
    ///
    /// `None` means nothing is configured, which is allowed and is what a
    /// deployment that issues no certificates has. `Some(..)` is an operator
    /// asking for a specific custodian, and *that* fails here when the
    /// custodian is not actually available — an operator who configured Vault
    /// and silently got database custody would have exactly the property they
    /// were trying to stop having.
    ///
    /// The distinction matters more than it looks. Making "nothing configured"
    /// a startup failure refuses to boot every deployment that has no CAs at
    /// all, for a feature it never touches; making an *explicit* choice fail
    /// silently is how a security control quietly stops applying. Only the
    /// second is worth stopping the process for.
    pub fn new(
        database: Option<DatabaseCaKeyStore>,
        vault: Option<VaultCaKeyStore>,
        default_custody: Option<CaKeyCustody>,
    ) -> AxiamResult<Self> {
        if let Some(requested) = default_custody {
            let available = match requested {
                CaKeyCustody::Database => database.is_some(),
                CaKeyCustody::Vault => vault.is_some(),
                // Never a default: it would mean generating CAs whose keys are
                // discarded, which is a CA that can sign nothing.
                CaKeyCustody::External => false,
            };
            if !available {
                return Err(AxiamError::Internal(format!(
                    "CA key custody is set to `{requested}` but that custodian is not \
                     configured: database custody needs AXIAM__PKI__ENCRYPTION_KEY, vault \
                     custody needs AXIAM__PKI__VAULT_ADDR and AXIAM__PKI__VAULT_TOKEN"
                )));
            }
        }
        Ok(Self {
            database,
            vault,
            external: ExternalCaKeyStore,
            default_custody,
        })
    }

    /// Which custodian new CAs are created with, or `None` if none is configured.
    pub fn default_custody(&self) -> Option<CaKeyCustody> {
        self.default_custody
    }

    /// The custodian for a new CA.
    ///
    /// The failure an operator meets when they generate their first CA on a
    /// deployment that never configured PKI — which is where the message about
    /// what to set is most use, and long after the process would have refused
    /// to start.
    pub fn default_store(&self) -> AxiamResult<&dyn CaKeyStore> {
        let custody = self.default_custody.ok_or_else(|| {
            AxiamError::Internal(
                "no CA key custodian is configured, so a CA signing key cannot be \
                 stored: set AXIAM__PKI__ENCRYPTION_KEY to keep it encrypted in the \
                 database, or AXIAM__PKI__VAULT_ADDR and AXIAM__PKI__VAULT_TOKEN to \
                 keep it in Vault"
                    .into(),
            )
        })?;
        self.store_for(custody)
    }

    /// The custodian a given CA row names.
    ///
    /// A row naming a custodian this process cannot reach is an error that says
    /// which one and what configures it — the shape an operator meets after
    /// restoring a database into a deployment configured differently, and the
    /// one moment a clear message saves an afternoon.
    pub fn store_for(&self, custody: CaKeyCustody) -> AxiamResult<&dyn CaKeyStore> {
        match custody {
            CaKeyCustody::Database => self
                .database
                .as_ref()
                .map(|s| s as &dyn CaKeyStore)
                .ok_or_else(|| {
                    AxiamError::Internal(
                        "this CA's key is sealed into its row, but AXIAM__PKI__ENCRYPTION_KEY \
                         is not set — the key cannot be opened"
                            .into(),
                    )
                }),
            CaKeyCustody::Vault => self
                .vault
                .as_ref()
                .map(|s| s as &dyn CaKeyStore)
                .ok_or_else(|| {
                    AxiamError::Internal(
                        "this CA's key is in Vault, but no Vault is configured — set \
                         AXIAM__PKI__VAULT_ADDR and AXIAM__PKI__VAULT_TOKEN"
                            .into(),
                    )
                }),
            CaKeyCustody::External => Ok(&self.external),
        }
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    fn vault() -> VaultCaKeyStore {
        VaultCaKeyStore::with_client(
            Client::new(),
            VaultCaKeyConfig {
                address: "https://vault.internal:8200".into(),
                token: "t".into(),
                mount: "secret".into(),
                prefix: "axiam/ca".into(),
                ca_cert_path: None,
            },
        )
    }

    #[test]
    fn a_default_that_is_not_configured_is_refused_rather_than_substituted() {
        // Falling back would hand an operator who asked for Vault exactly the
        // property they were trying to stop having, silently.
        let err = CaKeyCustodians::new(
            Some(DatabaseCaKeyStore::new([0u8; 32])),
            None,
            Some(CaKeyCustody::Vault),
        )
        .unwrap_err();
        assert!(err.to_string().contains("VAULT_ADDR"), "{err}");

        let err =
            CaKeyCustodians::new(None, Some(vault()), Some(CaKeyCustody::Database)).unwrap_err();
        assert!(err.to_string().contains("ENCRYPTION_KEY"), "{err}");
    }

    #[test]
    fn external_is_never_a_default() {
        // It would mean generating CAs whose keys are discarded.
        assert!(
            CaKeyCustodians::new(
                Some(DatabaseCaKeyStore::new([0u8; 32])),
                Some(vault()),
                Some(CaKeyCustody::External),
            )
            .is_err()
        );
    }

    #[test]
    fn no_custodian_at_all_builds_and_fails_only_at_use() {
        // The regression this exists for: making "nothing configured" a startup
        // failure refuses to boot every deployment that issues no certificates,
        // for a feature it never touches — which is exactly what the e2e stack
        // is. The failure belongs where the operator is when they need the
        // message: generating their first CA.
        let custodians = CaKeyCustodians::new(None, None, None)
            .expect("a deployment with no PKI key must still start");
        assert_eq!(custodians.default_custody(), None);

        let err = match custodians.default_store() {
            Ok(_) => panic!("there is no custodian to hand back"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("ENCRYPTION_KEY"), "{msg}");
        assert!(
            msg.contains("VAULT_ADDR"),
            "both ways out, not just one: {msg}"
        );
    }

    #[test]
    fn reads_follow_the_row_not_the_current_default() {
        // The whole point: adopting Vault must not strand the CAs that already
        // exist under database custody.
        let custodians = CaKeyCustodians::new(
            Some(DatabaseCaKeyStore::new([0u8; 32])),
            Some(vault()),
            Some(CaKeyCustody::Vault),
        )
        .unwrap();

        assert_eq!(
            custodians.default_store().unwrap().custody(),
            CaKeyCustody::Vault
        );
        assert_eq!(
            custodians
                .store_for(CaKeyCustody::Database)
                .unwrap()
                .custody(),
            CaKeyCustody::Database
        );
    }

    #[test]
    fn a_row_naming_an_unreachable_custodian_says_what_configures_it() {
        // What an operator meets after restoring a database into a deployment
        // configured differently.
        let custodians = CaKeyCustodians::new(
            Some(DatabaseCaKeyStore::new([0u8; 32])),
            None,
            Some(CaKeyCustody::Database),
        )
        .unwrap();
        let err = match custodians.store_for(CaKeyCustody::Vault) {
            Ok(_) => panic!("an unreachable custodian must not resolve"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("VAULT_ADDR"), "{err}");
    }

    #[test]
    fn an_external_row_resolves_without_any_custodian_configured() {
        let custodians = CaKeyCustodians::new(
            Some(DatabaseCaKeyStore::new([0u8; 32])),
            None,
            Some(CaKeyCustody::Database),
        )
        .unwrap();
        assert_eq!(
            custodians
                .store_for(CaKeyCustody::External)
                .unwrap()
                .custody(),
            CaKeyCustody::External
        );
    }
}

// ---------------------------------------------------------------------------
// building the set from configuration
// ---------------------------------------------------------------------------

/// Environment variable naming which custodian new CAs are created with.
pub const CA_KEY_STORE_ENV: &str = "AXIAM__PKI__CA_KEY_STORE";
/// Vault address for CA key custody.
pub const CA_VAULT_ADDR_ENV: &str = "AXIAM__PKI__VAULT_ADDR";
/// Vault token for CA key custody.
pub const CA_VAULT_TOKEN_ENV: &str = "AXIAM__PKI__VAULT_TOKEN";
/// KV v2 mount holding the CA keys. Defaults to Vault's own default, `secret`.
pub const CA_VAULT_MOUNT_ENV: &str = "AXIAM__PKI__VAULT_MOUNT";
/// Path prefix under the mount. Defaults to [`DEFAULT_CA_VAULT_PREFIX`].
pub const CA_VAULT_PREFIX_ENV: &str = "AXIAM__PKI__VAULT_PREFIX";
/// Trust anchor for Vault's listener certificate.
pub const CA_VAULT_CA_CERT_ENV: &str = "AXIAM__PKI__VAULT_CA_CERT_PATH";

/// Where CA keys live under the mount when nothing says otherwise.
pub const DEFAULT_CA_VAULT_PREFIX: &str = "axiam/ca-keys";
/// Vault's own default KV mount.
pub const DEFAULT_CA_VAULT_MOUNT: &str = "secret";

/// Assemble the custodians a deployment has configured.
///
/// One function rather than composition-root code, because the composition
/// root is not the only caller: the test `AppState` builds them too, and two
/// copies of "which custodian is the default" is the kind of divergence that
/// makes a test suite agree with itself and not with production.
///
/// The default custodian is `database` when nothing says otherwise, which is
/// what every existing deployment already had. Naming `vault` without the
/// address and token is a startup failure rather than a silent fallback: an
/// operator who asked for Vault and got the database would have exactly the
/// property they were trying to stop having.
pub fn custodians_from_env(encryption_key: Option<[u8; 32]>) -> AxiamResult<CaKeyCustodians> {
    let database = encryption_key.map(DatabaseCaKeyStore::new);

    let vault = match (
        std::env::var(CA_VAULT_ADDR_ENV)
            .ok()
            .filter(|v| !v.is_empty()),
        std::env::var(CA_VAULT_TOKEN_ENV)
            .ok()
            .filter(|v| !v.is_empty()),
    ) {
        (Some(address), Some(token)) => Some(VaultCaKeyStore::new(VaultCaKeyConfig {
            address,
            token,
            mount: std::env::var(CA_VAULT_MOUNT_ENV)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_CA_VAULT_MOUNT.to_string()),
            prefix: std::env::var(CA_VAULT_PREFIX_ENV)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_CA_VAULT_PREFIX.to_string()),
            ca_cert_path: std::env::var(CA_VAULT_CA_CERT_ENV)
                .ok()
                .filter(|v| !v.is_empty())
                .map(std::path::PathBuf::from),
        })?),
        // An address with no token, or the reverse, is a half-finished
        // configuration and worth saying so — it is otherwise indistinguishable
        // from not having configured Vault at all, right up until the default
        // custodian check fails with a message about a variable that *is* set.
        (Some(_), None) => {
            return Err(AxiamError::Internal(format!(
                "{CA_VAULT_ADDR_ENV} is set but {CA_VAULT_TOKEN_ENV} is not"
            )));
        }
        (None, Some(_)) => {
            return Err(AxiamError::Internal(format!(
                "{CA_VAULT_TOKEN_ENV} is set but {CA_VAULT_ADDR_ENV} is not"
            )));
        }
        (None, None) => None,
    };

    let default_custody = match std::env::var(CA_KEY_STORE_ENV) {
        // An explicit request. `CaKeyCustodians::new` refuses it when the named
        // custodian is not actually configured — the one case worth stopping
        // the process for.
        Ok(raw) if !raw.trim().is_empty() => {
            Some(raw.trim().parse::<CaKeyCustody>().map_err(|e| {
                AxiamError::Internal(format!(
                    "{CA_KEY_STORE_ENV}: {e} — expected `database` or `vault`"
                ))
            })?)
        }
        // Vault configured and no explicit choice means Vault: an operator who
        // wired up an address and a token did so in order to use it, and
        // making them also set a third variable is a step whose only outcome is
        // being forgotten.
        _ if vault.is_some() => Some(CaKeyCustody::Vault),
        _ if database.is_some() => Some(CaKeyCustody::Database),
        // Nothing configured at all. Not an error: a deployment that issues no
        // certificates has no reason to hold a PKI key, and refusing to start
        // would break it for a feature it never uses.
        _ => None,
    };

    CaKeyCustodians::new(database, vault, default_custody)
}

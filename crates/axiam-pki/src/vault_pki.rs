//! CA keys that are born inside HashiCorp Vault and never leave it.
//!
//! [`VaultCaKeyStore`](crate::ca_key_store::VaultCaKeyStore) puts a key AXIAM
//! generated into Vault's KV engine. This is the other arrangement, and the
//! difference is not a degree: Vault's **PKI secrets engine** generates the key
//! itself, exposes no API that exports it, and signs on AXIAM's behalf. The
//! private key of a CA under this custodian has never existed in this process,
//! so a compromise of AXIAM — memory dump, malicious build, an operator with a
//! shell — yields certificates that Vault's audit log records, and no key.
//!
//! # The shape, and where it comes from
//!
//! HashiCorp's own PKI walkthrough is the model, and this implements it
//! literally:
//!
//! 1. `POST <root_mount>/root/generate/internal` — a root whose key stays in
//!    Vault. `internal` (rather than `exported`) is what makes that true.
//! 2. `POST <int_mount>/intermediate/generate/internal` — a second key, also
//!    kept, and a CSR.
//! 3. `POST <root_mount>/issuer/<root>/sign-intermediate` — the root signs it.
//! 4. `POST <int_mount>/intermediate/set-signed` — the signed certificate goes
//!    back to the mount holding its key, which is now an issuer.
//! 5. `POST <int_mount>/issuer/<int>/sign-verbatim` — every leaf, thereafter.
//!
//! The two-tier structure is not ceremony. A root that signs exactly one
//! intermediate and nothing else can have that intermediate revoked and
//! replaced without redistributing the trust anchor, which is the one PKI
//! operation that is otherwise impossible to perform quietly.
//!
//! # What this does *not* remove
//!
//! On the BYOK path — [`CaKeyStore::import_ca`] — the key an operator supplies
//! passes through AXIAM's memory on its way to `issuers/import/bundle`. It has
//! to: AXIAM is the thing receiving the HTTP request. What the operator gets is
//! that AXIAM never *stores* it, and every use of it afterwards is Vault's.
//!
//! # Mounts, not a mount per CA
//!
//! Both mounts are enabled by the operator and shared by every CA. The
//! alternative — AXIAM enabling a mount per CA — needs `sys/mounts` write,
//! which is a permission that can rewrite the whole Vault. Sharing two mounts
//! and addressing issuers by id keeps the token's policy to the PKI paths
//! themselves. Vault has supported multiple issuers per mount since 1.11.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use axiam_core::ca_keys::{
    CaGenerationRequest, CaKeyCustody, CaKeyRef, CaKeyStore, CustodiedIntermediate, GeneratedCa,
    IntermediateCaRequest, IntermediateSigningRequest, LeafSigningRequest, SignedLeaf, StoredCaKey,
};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::KeyAlgorithm;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

/// How long to wait on Vault before giving up.
///
/// Longer than the KV store's ten seconds because these calls do real work:
/// generating an RSA-4096 root inside Vault is seconds of CPU, not a lookup.
/// Still bounded, because this runs on the request that generates a CA or
/// issues a certificate, and an unbounded wait turns a Vault outage into hung
/// request handlers rather than a refused issuance.
const VAULT_PKI_TIMEOUT: Duration = Duration::from_secs(60);

/// Vault's own conventional mount for a root PKI engine.
pub const DEFAULT_PKI_ROOT_MOUNT: &str = "pki";
/// Vault's own conventional mount for an intermediate PKI engine.
pub const DEFAULT_PKI_INT_MOUNT: &str = "pki_int";

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------

/// How to reach the two PKI mounts.
///
/// `Debug` is hand-written to redact the token — this struct is exactly the
/// kind of thing that reaches a startup log line or a panic message.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultPkiConfig {
    /// Base address, e.g. `https://vault.internal:8200`.
    pub address: String,
    /// A token whose policy covers the paths in this module's header.
    pub token: String,
    /// PKI mount holding the roots AXIAM generates.
    pub root_mount: String,
    /// PKI mount holding the issuing intermediates, and the issuer that signs
    /// every leaf.
    pub int_mount: String,
    /// PEM bundle for the CA that issued Vault's listener certificate.
    ///
    /// `None` verifies against the built-in roots, which is right only for a
    /// Vault fronted by a publicly-trusted certificate: reqwest is built with
    /// `rustls-tls`, whose roots are compiled in, so an internally-issued
    /// listener certificate has no `SSL_CERT_FILE` to fall back on.
    pub ca_cert_path: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for VaultPkiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultPkiConfig")
            .field("address", &self.address)
            .field("token", &"<redacted>")
            .field("root_mount", &self.root_mount)
            .field("int_mount", &self.int_mount)
            .field("ca_cert_path", &self.ca_cert_path)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// locator
// ---------------------------------------------------------------------------

/// One issuer inside one mount, addressed the way Vault addresses it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPkiIssuer {
    /// The PKI mount, without leading or trailing slashes.
    pub mount: String,
    /// Vault's `issuer_id` — a UUID it minted, not a name.
    pub issuer: String,
    /// Vault's `key_id` for the key beneath that issuer.
    pub key: String,
}

/// Everything needed to sign with, and later delete, a `vault_pki` CA.
///
/// Serialised into the CA row's single `key_locator` string, because the row
/// has one column for "where the custodian put it" and this custodian put it in
/// four places. JSON rather than a delimited form so that adding a field later
/// — a namespace, a second intermediate — does not have to guess how many
/// separators an old row had.
///
/// The mounts are recorded rather than re-read from configuration for the same
/// reason the custodian itself is recorded per CA: an operator who changes
/// `AXIAM__PKI__VAULT_PKI_INT_MOUNT` has not moved the issuers that already
/// exist, and a signing path that consulted the current setting would look in
/// the wrong mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultPkiLocator {
    /// The issuer that signs leaves.
    pub issuing: VaultPkiIssuer,
    /// The root the issuing intermediate was created beneath.
    ///
    /// `None` when the issuing certificate *is* the root, and when the CA was
    /// imported rather than generated — in both cases there is no second issuer
    /// to clean up on revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<VaultPkiIssuer>,
}

impl VaultPkiLocator {
    /// Read a locator back out of a CA row.
    pub fn parse(locator: &str) -> AxiamResult<Self> {
        serde_json::from_str(locator).map_err(|e| {
            AxiamError::Certificate(format!(
                "this CA's key locator is not one this custodian wrote: {e}"
            ))
        })
    }

    fn encode(&self) -> AxiamResult<String> {
        serde_json::to_string(self).map_err(|e| {
            AxiamError::Internal(format!("vault pki: could not encode the key locator: {e}"))
        })
    }

    /// The issuer to sign a *CA* with, which is not the one that signs leaves.
    ///
    /// `issuing` is created with `max_path_length: 0` — it may sign leaves and
    /// nothing else, so a certificate it issued to another CA would be rejected
    /// by every validator that checked the chain. The root above it has no such
    /// constraint, and is what a new tier hangs from.
    ///
    /// `None` root means there is no second tier: the CA was created with
    /// `issue_from_root`, or imported, and `issuing` is the top of what AXIAM
    /// has. Whatever constraints that certificate carries are then the
    /// operator's own, and Vault will refuse the signature if they forbid it.
    fn signing_issuer(&self) -> &VaultPkiIssuer {
        self.root.as_ref().unwrap_or(&self.issuing)
    }
}

// ---------------------------------------------------------------------------
// store
// ---------------------------------------------------------------------------

/// CA keys generated and held by Vault's PKI secrets engine.
#[derive(Clone)]
pub struct VaultPkiCaKeyStore {
    client: Client,
    config: VaultPkiConfig,
}

impl std::fmt::Debug for VaultPkiCaKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultPkiCaKeyStore")
            .field("config", &self.config)
            .finish()
    }
}

impl VaultPkiCaKeyStore {
    /// Build a store, including the TLS trust anchor if one is configured.
    ///
    /// Fails rather than falling back to the built-in roots when the anchor is
    /// unreadable: silently verifying against a different trust store than the
    /// operator asked for is how a misconfiguration becomes a connection to
    /// something that is not their Vault.
    pub fn new(config: VaultPkiConfig) -> AxiamResult<Self> {
        let mut builder = Client::builder().timeout(VAULT_PKI_TIMEOUT);

        if let Some(ref path) = config.ca_cert_path {
            let pem = std::fs::read(path).map_err(|e| {
                AxiamError::Internal(format!(
                    "vault PKI CA key store: could not read the trust anchor at {}: {e}",
                    path.display()
                ))
            })?;
            let cert = reqwest::Certificate::from_pem(&pem).map_err(|e| {
                AxiamError::Internal(format!(
                    "vault PKI CA key store: {} is not a PEM certificate: {e}",
                    path.display()
                ))
            })?;
            builder = builder.add_root_certificate(cert);
        }

        let client = builder.build().map_err(|e| {
            AxiamError::Internal(format!(
                "vault PKI CA key store: could not build HTTP client: {e}"
            ))
        })?;

        Ok(Self { client, config })
    }

    /// Build from an already-configured client. For tests, and for a caller
    /// that has its own client policy.
    pub fn with_client(client: Client, config: VaultPkiConfig) -> Self {
        Self { client, config }
    }

    fn url(&self, mount: &str, path: &str) -> String {
        format!(
            "{}/v1/{}/{}",
            self.config.address.trim_end_matches('/'),
            mount.trim_matches('/'),
            path.trim_start_matches('/'),
        )
    }

    /// `POST` a JSON body and return the response's `data` object.
    ///
    /// Vault's warnings are logged rather than swallowed. They are how it tells
    /// you a TTL was capped to the mount's `max_lease_ttl` — a 30-day default
    /// that silently turns a requested ten-year root into a month-long one, and
    /// the single most likely way a working configuration surprises an operator.
    async fn post(&self, url: &str, body: serde_json::Value) -> AxiamResult<serde_json::Value> {
        let response = self
            .client
            .post(url)
            .header("X-Vault-Token", &self.config.token)
            .json(&body)
            // Deliberately carries neither the token nor the request body.
            .send()
            .await
            .map_err(|e| AxiamError::Internal(format!("vault pki: {url} could not be reached: {e}")))?;

        let status = response.status();
        let payload: serde_json::Value = response.json().await.unwrap_or(serde_json::Value::Null);

        if !status.is_success() {
            return Err(AxiamError::Certificate(format!(
                "vault pki: {url} answered {status}: {}",
                vault_errors(&payload)
            )));
        }

        log_warnings(url, &payload);

        payload
            .get("data")
            .cloned()
            .filter(|d| !d.is_null())
            .ok_or_else(|| {
                AxiamError::Internal(format!("vault pki: {url} answered {status} with no `data`"))
            })
    }

    /// `DELETE` a path, treating "already gone" as success.
    async fn delete(&self, url: &str) -> AxiamResult<()> {
        let response = self
            .client
            .delete(url)
            .header("X-Vault-Token", &self.config.token)
            .send()
            .await
            .map_err(|e| AxiamError::Internal(format!("vault pki: deleting {url} failed: {e}")))?;

        // Already gone is success: this runs on revocation, and a second
        // revocation must not fail because the first one worked.
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        Err(AxiamError::Internal(format!(
            "vault pki: {url} answered {} on delete",
            response.status()
        )))
    }

    /// Generate a root whose key stays inside Vault.
    async fn generate_root(
        &self,
        request: &CaGenerationRequest,
    ) -> AxiamResult<(String, VaultPkiIssuer)> {
        let (key_type, key_bits) = key_params(&request.key_algorithm);
        let url = self.url(&self.config.root_mount, "root/generate/internal");
        let data = self
            .post(
                &url,
                serde_json::json!({
                    "common_name": request.subject,
                    "ttl": ttl_days(request.validity_days),
                    "key_type": key_type,
                    "key_bits": key_bits,
                    // Names are for whoever opens Vault's UI; the locator
                    // addresses by id, so a rename cannot strand a CA row.
                    "issuer_name": format!("axiam-root-{}", request.ca_id),
                    "key_name": format!("axiam-root-{}", request.ca_id),
                    "format": "pem",
                }),
            )
            .await?;

        let certificate = string_field(&data, "certificate", &url)?;
        Ok((
            certificate,
            VaultPkiIssuer {
                mount: self.config.root_mount.trim_matches('/').to_string(),
                issuer: string_field(&data, "issuer_id", &url)?,
                key: string_field(&data, "key_id", &url)?,
            },
        ))
    }

    /// `POST issuer/{id}/sign-intermediate` — the one call that mints a CA.
    ///
    /// Shared by the three paths that need it: creating the organization CA's
    /// own intermediate, creating a tenant signing CA, and signing a CSR a
    /// tenant produced elsewhere. The constraints are stated here once so those
    /// three cannot drift into issuing differently-powered CAs.
    ///
    /// Returns the certificate and, when Vault named one, the issuing CA's own
    /// certificate — the chain entry a relying party needs and cannot get from
    /// anywhere else, because the issuer's certificate lives inside Vault.
    async fn sign_as_intermediate(
        &self,
        signer: &VaultPkiIssuer,
        csr_pem: &str,
        subject: &str,
        ttl: String,
    ) -> AxiamResult<(String, Option<String>)> {
        let url = self.url(
            &signer.mount,
            &format!("issuer/{}/sign-intermediate", signer.issuer),
        );
        let signed = self
            .post(
                &url,
                serde_json::json!({
                    "csr": csr_pem,
                    "common_name": subject,
                    "ttl": ttl,
                    "format": "pem",
                    // Signs leaves and nothing else. Without this it inherits an
                    // unconstrained path length and could mint further CAs — a
                    // capability nothing in AXIAM uses and everything downstream
                    // would have to trust.
                    "max_path_length": 0,
                    // The CSR's own subject and extensions are ignored in favour
                    // of what is named here: `use_csr_values` would let the
                    // request describe its own powers, and AXIAM has already
                    // decided what they are.
                    "use_csr_values": false,
                }),
            )
            .await?;

        let certificate = string_field(&signed, "certificate", &url)?;
        let issuing_ca = signed
            .get("issuing_ca")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty() && s.trim() != certificate.trim())
            .map(str::to_string);
        Ok((certificate, issuing_ca))
    }

    /// Create the intermediate key and CSR, have the root sign it, and hand the
    /// signed certificate back to the mount that holds its key.
    async fn generate_intermediate(
        &self,
        request: &CaGenerationRequest,
        subject: &str,
        validity_days: u32,
        root: &VaultPkiIssuer,
    ) -> AxiamResult<(String, VaultPkiIssuer)> {
        let (key_type, key_bits) = key_params(&request.key_algorithm);

        let generate_url = self.url(&self.config.int_mount, "intermediate/generate/internal");
        let generated = self
            .post(
                &generate_url,
                serde_json::json!({
                    "common_name": subject,
                    "key_type": key_type,
                    "key_bits": key_bits,
                    "key_name": format!("axiam-int-{}", request.ca_id),
                    "format": "pem",
                }),
            )
            .await?;
        let csr = string_field(&generated, "csr", &generate_url)?;

        let (certificate, _issuing_ca) = self
            .sign_as_intermediate(root, &csr, subject, ttl_days(validity_days))
            .await?;

        let set_url = self.url(&self.config.int_mount, "intermediate/set-signed");
        let imported = self
            .post(&set_url, serde_json::json!({ "certificate": certificate }))
            .await?;
        let issuer = first_imported_issuer(&imported, &set_url)?;
        // The key was created by `intermediate/generate/internal`, so
        // `set-signed` imports no key and `imported_keys` is empty; the id we
        // want is the one that call already returned.
        let key = string_field(&generated, "key_id", &generate_url)?;

        Ok((
            certificate,
            VaultPkiIssuer {
                mount: self.config.int_mount.trim_matches('/').to_string(),
                issuer,
                key,
            },
        ))
    }
}

impl CaKeyStore for VaultPkiCaKeyStore {
    /// Refused, and the refusal is the feature.
    ///
    /// Reaching here means a caller generated a CA key in this process and
    /// asked Vault's PKI engine to keep it — which is
    /// [`crate::ca_key_store::VaultCaKeyStore`]'s job, under custody `vault`.
    /// The PKI engine has nowhere to put a key that has no certificate.
    fn store<'a>(
        &'a self,
        _organization_id: Uuid,
        _ca_id: Uuid,
        _private_key_pem: &'a str,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<StoredCaKey>> + Send + 'a>> {
        Box::pin(async {
            Err(AxiamError::Validation {
                message: "Vault's PKI engine stores a key only together with the \
                          certificate it belongs to: generate the CA in Vault, or import \
                          the certificate and key together"
                    .into(),
            })
        })
    }

    /// Refused: there is no API that exports this key, by design.
    ///
    /// `Validation` rather than `Certificate` so the sentence reaches the
    /// caller — `Certificate` maps to a 500 whose body says only that an
    /// internal error occurred, and this is not an error at all but a
    /// statement about how the CA was made.
    fn load<'a>(
        &'a self,
        _key_ref: &'a CaKeyRef,
        _inline: Option<&'a [u8]>,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Zeroizing<String>>> + Send + 'a>> {
        Box::pin(async {
            Err(AxiamError::Validation {
                message: "this CA's private key was generated inside Vault's PKI engine and \
                          cannot be exported: AXIAM signs through Vault instead of holding \
                          the key"
                    .into(),
            })
        })
    }

    /// Remove the issuer, then the key it used — in that order, because Vault
    /// refuses to delete a key an issuer still references.
    ///
    /// Both tiers go: the root exists to sign one intermediate, and a root
    /// whose only intermediate has been revoked signs nothing anyone should
    /// accept.
    fn delete<'a>(
        &'a self,
        key_ref: &'a CaKeyRef,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>> {
        Box::pin(async move {
            let locator = VaultPkiLocator::parse(&key_ref.locator)?;
            let mut issuers = vec![locator.issuing];
            issuers.extend(locator.root);
            for issuer in issuers {
                self.delete(&self.url(&issuer.mount, &format!("issuer/{}", issuer.issuer)))
                    .await?;
                self.delete(&self.url(&issuer.mount, &format!("key/{}", issuer.key)))
                    .await?;
            }
            Ok(())
        })
    }

    fn generates_cas(&self) -> bool {
        true
    }

    fn generate_ca<'a>(
        &'a self,
        request: &'a CaGenerationRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<GeneratedCa>> + Send + 'a>> {
        Box::pin(async move {
            let (root_pem, root) = self.generate_root(request).await?;

            let (certificate_pem, chain_pem, locator) = match request.intermediate {
                Some(ref spec) => {
                    let (int_pem, issuing) = self
                        .generate_intermediate(request, &spec.subject, spec.validity_days, &root)
                        .await?;
                    (
                        int_pem,
                        // Built here rather than taken from Vault's `ca_chain`,
                        // whose contents differ between endpoints and versions.
                        // The root's certificate came back from the call that
                        // created it, and that is the only copy anything
                        // outside Vault will ever see.
                        vec![root_pem],
                        VaultPkiLocator {
                            issuing,
                            root: Some(root),
                        },
                    )
                }
                None => (
                    root_pem,
                    Vec::new(),
                    VaultPkiLocator {
                        issuing: root,
                        root: None,
                    },
                ),
            };

            Ok(GeneratedCa {
                certificate_pem,
                chain_pem,
                locator: locator.encode()?,
            })
        })
    }

    /// BYOK: hand Vault a key and the certificate it belongs to, together.
    ///
    /// The imported issuer goes into the *issuing* mount, because that is the
    /// mount leaves are signed from and an imported CA is by definition the one
    /// doing the signing — there is no root above it that AXIAM created.
    fn import_ca<'a>(
        &'a self,
        _organization_id: Uuid,
        _ca_id: Uuid,
        certificate_pem: &'a str,
        private_key_pem: &'a str,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<StoredCaKey>> + Send + 'a>> {
        Box::pin(async move {
            let url = self.url(&self.config.int_mount, "issuers/import/bundle");
            // Key first: Vault reads the bundle as a stream of PEM blocks and
            // does not care about order, but a human reading a failed request
            // in an audit log does.
            let bundle = format!(
                "{}\n{}",
                private_key_pem.trim_end(),
                certificate_pem.trim_end()
            );
            let data = self
                .post(&url, serde_json::json!({ "pem_bundle": bundle }))
                .await?;

            let issuer = first_imported_issuer(&data, &url)?;
            let key = data
                .get("mapping")
                .and_then(|m| m.get(&issuer))
                .and_then(|v| v.as_str())
                .filter(|k| !k.is_empty())
                .ok_or_else(|| {
                    // Vault maps issuer -> key and leaves the value empty for an
                    // issuer it holds no key for. That means the bundle carried
                    // a certificate and no usable key, which would produce a CA
                    // that lists as issuable and fails at the first signature.
                    AxiamError::Validation {
                        message: "Vault imported the certificate but no private key for it: \
                                  check the bundle contains the key that matches this CA"
                            .into(),
                    }
                })?
                .to_string();

            let locator = VaultPkiLocator {
                issuing: VaultPkiIssuer {
                    mount: self.config.int_mount.trim_matches('/').to_string(),
                    issuer,
                    key,
                },
                root: None,
            };
            Ok(StoredCaKey::Referenced(locator.encode()?))
        })
    }

    fn signs_remotely(&self) -> bool {
        true
    }

    /// Sign a leaf with `sign-verbatim`, which takes the CSR's subject and
    /// extensions as given.
    ///
    /// Verbatim rather than a Vault role because AXIAM has already decided what
    /// the certificate says — subject, validity, key algorithm, and the tenant
    /// policy behind them. A role would restate a subset of those rules in a
    /// second place, and the two would drift.
    ///
    /// The cost is that the token's policy on this path is what stands between
    /// a compromised AXIAM and a certificate for any name at all. An operator
    /// who wants Vault to enforce names as well can point the mount's role at
    /// the same issuer; what they cannot do is have neither.
    fn sign_csr<'a>(
        &'a self,
        key_ref: &'a CaKeyRef,
        request: &'a LeafSigningRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<SignedLeaf>> + Send + 'a>> {
        Box::pin(async move {
            let locator = VaultPkiLocator::parse(&key_ref.locator)?;
            let url = self.url(
                &locator.issuing.mount,
                &format!("issuer/{}/sign-verbatim", locator.issuing.issuer),
            );
            let data = self
                .post(
                    &url,
                    serde_json::json!({
                        "csr": request.csr_pem,
                        "ttl": format!("{}s", request.ttl_seconds.max(1)),
                        "format": "pem",
                    }),
                )
                .await?;

            let certificate_pem = string_field(&data, "certificate", &url)?;
            // `ca_chain` means different things at different Vault versions —
            // sometimes including the leaf. Drop anything equal to the
            // certificate itself rather than trusting the shape.
            let chain_pem = data
                .get("ca_chain")
                .and_then(|c| c.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|v| v.as_str())
                        .filter(|pem| pem.trim() != certificate_pem.trim())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();

            Ok(SignedLeaf {
                certificate_pem,
                chain_pem,
            })
        })
    }

    /// Create a tenant signing CA whose key is born in — and stays in — Vault.
    ///
    /// The same three calls as [`Self::generate_intermediate`], pointed at an
    /// issuer that already exists rather than one this call just made: Vault
    /// generates the key and a CSR in the issuing mount, the parent's signing
    /// issuer signs it, and `intermediate/set-signed` hands the certificate
    /// back to the mount that holds the key. Vault can then issue this tenant's
    /// leaves itself, which is the whole point — the key never exists here, so
    /// there is nothing for AXIAM to lose.
    fn generate_intermediate_ca<'a>(
        &'a self,
        parent: &'a CaKeyRef,
        request: &'a IntermediateCaRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<CustodiedIntermediate>> + Send + 'a>> {
        Box::pin(async move {
            let parent_locator = VaultPkiLocator::parse(&parent.locator)?;
            let signer = parent_locator.signing_issuer();
            let (key_type, key_bits) = key_params(&request.key_algorithm);

            let generate_url = self.url(&self.config.int_mount, "intermediate/generate/internal");
            let generated = self
                .post(
                    &generate_url,
                    serde_json::json!({
                        "common_name": request.subject,
                        "key_type": key_type,
                        "key_bits": key_bits,
                        "key_name": format!("axiam-tenant-int-{}", request.ca_id),
                        "format": "pem",
                    }),
                )
                .await?;
            let csr = string_field(&generated, "csr", &generate_url)?;

            let (certificate, issuing_ca) = self
                .sign_as_intermediate(
                    signer,
                    &csr,
                    &request.subject,
                    ttl_days(request.validity_days),
                )
                .await?;

            let set_url = self.url(&self.config.int_mount, "intermediate/set-signed");
            let imported = self
                .post(&set_url, serde_json::json!({ "certificate": certificate }))
                .await?;
            let issuer = first_imported_issuer(&imported, &set_url)?;
            // The key came from `intermediate/generate/internal`, so
            // `set-signed` imports no key and `imported_keys` is empty; the id
            // wanted here is the one that call already returned.
            let key = string_field(&generated, "key_id", &generate_url)?;

            Ok(CustodiedIntermediate {
                certificate_pem: certificate,
                chain_pem: issuing_ca.into_iter().collect(),
                locator: VaultPkiLocator {
                    issuing: VaultPkiIssuer {
                        mount: self.config.int_mount.trim_matches('/').to_string(),
                        issuer,
                        key,
                    },
                    // No root to clean up on revocation: the root above this one
                    // belongs to the organization CA and outlives it.
                    root: None,
                }
                .encode()?,
            })
        })
    }

    /// Sign somebody else's CSR as a CA, with `sign-intermediate`.
    ///
    /// Not `sign-verbatim`, which is what leaves use: verbatim takes the CSR's
    /// own extensions, and a request that asked to be an unconstrained CA would
    /// get to be one. `sign-intermediate` with `use_csr_values: false` means
    /// AXIAM states what the certificate is and Vault ignores what the request
    /// wanted.
    fn sign_intermediate_csr<'a>(
        &'a self,
        parent: &'a CaKeyRef,
        request: &'a IntermediateSigningRequest,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<SignedLeaf>> + Send + 'a>> {
        Box::pin(async move {
            let parent_locator = VaultPkiLocator::parse(&parent.locator)?;
            let (certificate_pem, issuing_ca) = self
                .sign_as_intermediate(
                    parent_locator.signing_issuer(),
                    &request.csr_pem,
                    &request.subject,
                    format!("{}s", request.ttl_seconds.max(1)),
                )
                .await?;
            Ok(SignedLeaf {
                certificate_pem,
                chain_pem: issuing_ca.into_iter().collect(),
            })
        })
    }

    fn custody(&self) -> CaKeyCustody {
        CaKeyCustody::VaultPki
    }

    fn describe(&self) -> &'static str {
        "vault_pki"
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Vault's `key_type` and `key_bits` for one of AXIAM's algorithms.
///
/// Note what this makes possible: Vault generates RSA keys, and rcgen's `ring`
/// backend does not. `Rsa4096` is refused by `POST .../ca-certificates` under
/// every other custodian and works under this one.
fn key_params(algorithm: &KeyAlgorithm) -> (&'static str, u32) {
    match algorithm {
        KeyAlgorithm::Ed25519 => ("ed25519", 0),
        KeyAlgorithm::Rsa4096 => ("rsa", 4096),
    }
}

/// Days as a Vault duration string.
fn ttl_days(days: u32) -> String {
    format!("{}h", u64::from(days) * 24)
}

/// Pull a non-empty string field out of a Vault `data` object.
fn string_field(data: &serde_json::Value, field: &str, url: &str) -> AxiamResult<String> {
    data.get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            AxiamError::Internal(format!(
                "vault pki: {url} returned no `{field}` — check the mount is a PKI engine"
            ))
        })
}

/// The one issuer a `set-signed` or `import/bundle` call created.
///
/// More than one means the bundle carried a chain, which AXIAM does not send:
/// taking the first would pick an issuer arbitrarily and record a locator that
/// signs with something other than the certificate in the row.
fn first_imported_issuer(data: &serde_json::Value, url: &str) -> AxiamResult<String> {
    let imported: Vec<&str> = data
        .get("imported_issuers")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    match imported.as_slice() {
        [one] => Ok((*one).to_string()),
        [] => Err(AxiamError::Validation {
            message: format!(
                "vault pki: {url} imported no issuer — Vault already holds this \
                 certificate, so it belongs to a CA that exists"
            ),
        }),
        many => Err(AxiamError::Validation {
            message: format!(
                "vault pki: {url} imported {} issuers — send one certificate, not a chain",
                many.len()
            ),
        }),
    }
}

/// Vault's `errors` array, flattened for a message.
fn vault_errors(payload: &serde_json::Value) -> String {
    let errors: Vec<&str> = payload
        .get("errors")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if errors.is_empty() {
        "no error detail".to_string()
    } else {
        errors.join("; ")
    }
}

/// Surface Vault's warnings, which are how a capped TTL is reported.
fn log_warnings(url: &str, payload: &serde_json::Value) {
    if let Some(warnings) = payload.get("warnings").and_then(|v| v.as_array()) {
        for warning in warnings.iter().filter_map(|v| v.as_str()) {
            tracing::warn!(%url, warning, "vault pki returned a warning");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> VaultPkiConfig {
        VaultPkiConfig {
            address: "https://vault.internal:8200/".into(),
            token: "s.token".into(),
            root_mount: "/pki/".into(),
            int_mount: "/pki_int/".into(),
            ca_cert_path: None,
        }
    }

    fn store() -> VaultPkiCaKeyStore {
        VaultPkiCaKeyStore::new(config()).unwrap()
    }

    #[test]
    fn urls_survive_slashes_on_either_side() {
        // The address ends with one and both mounts are wrapped in them; a
        // naive `format!` produces `//v1//pki//root/...`, which Vault answers
        // with a 404 that says nothing about why.
        assert_eq!(
            store().url("/pki/", "root/generate/internal"),
            "https://vault.internal:8200/v1/pki/root/generate/internal"
        );
    }

    #[test]
    fn the_token_is_not_in_the_debug_output() {
        let rendered = format!("{:?}", store());
        assert!(!rendered.contains("s.token"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn a_locator_round_trips_through_the_single_column_it_lives_in() {
        let locator = VaultPkiLocator {
            issuing: VaultPkiIssuer {
                mount: "pki_int".into(),
                issuer: "issuer-1".into(),
                key: "key-1".into(),
            },
            root: Some(VaultPkiIssuer {
                mount: "pki".into(),
                issuer: "issuer-0".into(),
                key: "key-0".into(),
            }),
        };
        let encoded = locator.encode().unwrap();
        assert_eq!(VaultPkiLocator::parse(&encoded).unwrap(), locator);
    }

    #[test]
    fn a_locator_from_another_custodian_is_refused_rather_than_guessed_at() {
        // A `vault` (KV) row's locator is a bare path. Reading it as this
        // custodian's would otherwise produce a mount named after nothing.
        let err = VaultPkiLocator::parse("axiam/ca-keys/org/ca").unwrap_err();
        assert!(
            err.to_string().contains("not one this custodian wrote"),
            "{err}"
        );
    }

    #[test]
    fn ttl_is_expressed_in_hours_because_vault_has_no_day_unit() {
        assert_eq!(ttl_days(3650), "87600h");
        assert_eq!(ttl_days(1), "24h");
    }

    #[test]
    fn key_params_ask_vault_for_the_algorithm_the_row_will_record() {
        assert_eq!(key_params(&KeyAlgorithm::Ed25519), ("ed25519", 0));
        assert_eq!(key_params(&KeyAlgorithm::Rsa4096), ("rsa", 4096));
    }

    #[test]
    fn one_imported_issuer_is_the_only_answer_that_is_usable() {
        let one = serde_json::json!({ "imported_issuers": ["a"] });
        assert_eq!(first_imported_issuer(&one, "u").unwrap(), "a");

        // Nothing imported means Vault already had it — a different CA row
        // already signs with this issuer, and two rows sharing one would both
        // claim to be able to revoke it.
        let none = serde_json::json!({ "imported_issuers": [] });
        let err = first_imported_issuer(&none, "u").unwrap_err();
        assert!(err.to_string().contains("already holds"), "{err}");

        let many = serde_json::json!({ "imported_issuers": ["a", "b"] });
        let err = first_imported_issuer(&many, "u").unwrap_err();
        assert!(err.to_string().contains("not a chain"), "{err}");
    }

    #[test]
    fn vault_errors_are_repeated_verbatim_because_they_name_the_policy() {
        let payload = serde_json::json!({ "errors": ["permission denied"] });
        assert_eq!(vault_errors(&payload), "permission denied");
        assert_eq!(vault_errors(&serde_json::json!({})), "no error detail");
    }

    #[test]
    fn a_missing_field_names_the_field_and_the_likely_cause() {
        let err = string_field(&serde_json::json!({}), "certificate", "u").unwrap_err();
        assert!(err.to_string().contains("certificate"), "{err}");
        assert!(err.to_string().contains("PKI engine"), "{err}");
    }
}

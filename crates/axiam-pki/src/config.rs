//! PKI configuration types.

/// PKI configuration — holds the AES-256-GCM key for encrypting CA private keys.
///
/// `encryption_key` is `Option` — absent means the operator has not configured
/// the key yet. Operations that encrypt private key material (CA generation,
/// PGP AuditSigning key generation) will return an error rather than silently
/// encrypting with a known-zero key (SEC-012).
#[derive(Clone)]
pub struct PkiConfig {
    pub encryption_key: Option<[u8; 32]>,
}

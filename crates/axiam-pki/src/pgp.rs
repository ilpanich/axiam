//! OpenPGP key management — generation, audit signing, and encryption.

use aes_gcm::aead::{Aead, OsRng as AeadOsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::AuditLogEntry;
use axiam_core::models::pgp_key::{
    CreatePgpKey, EncryptedExport, GeneratedPgpKey, PgpKey, PgpKeyAlgorithm, PgpKeyPurpose,
    SignedAuditBatch, StorePgpKey,
};
use axiam_core::repository::{PaginatedResult, Pagination, PgpKeyRepository};
use chrono::Utc;
use pgp::composed::{
    ArmorOptions, Deserializable, KeyType, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
    SignedSecretKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails, KeyVersion, Password};
use rand_core::OsRng;
use uuid::Uuid;

use crate::PkiConfig;

/// Service for OpenPGP key management, audit signing, and encryption.
#[derive(Clone)]
pub struct PgpService<R> {
    repo: R,
    config: PkiConfig,
}

impl<R: PgpKeyRepository> PgpService<R> {
    pub fn new(repo: R, config: PkiConfig) -> Self {
        Self { repo, config }
    }

    /// Generate an OpenPGP keypair.
    ///
    /// - **AuditSigning**: encrypts private key with AES-256-GCM, stores it.
    /// - **Export**: does NOT store the private key; returns it once.
    pub async fn generate(&self, input: CreatePgpKey) -> AxiamResult<GeneratedPgpKey> {
        let user_id = format!("{} <{}>", input.name, input.email);
        let secret_key = generate_keypair(&input.algorithm, &user_id)?;
        let public_key = secret_key.to_public_key();

        let private_key_armored: String = secret_key
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| AxiamError::Crypto(format!("failed to armor private key: {e}")))?;

        let public_key_armored: String = public_key
            .to_armored_string(ArmorOptions::default())
            .map_err(|e| AxiamError::Crypto(format!("failed to armor public key: {e}")))?;

        let fingerprint = hex::encode(public_key.fingerprint());

        // Encrypt private key for storage (only for AuditSigning)
        let encrypted_private_key = if input.purpose == PgpKeyPurpose::AuditSigning {
            Some(encrypt_private_key(
                private_key_armored.as_bytes(),
                &self.config.encryption_key,
            )?)
        } else {
            None
        };

        let store = StorePgpKey {
            tenant_id: input.tenant_id,
            name: input.name,
            purpose: input.purpose,
            public_key_armored,
            fingerprint,
            algorithm: input.algorithm,
            encrypted_private_key,
        };

        let key = self.repo.create(store).await?;

        Ok(GeneratedPgpKey {
            key,
            private_key_armored,
        })
    }

    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<PgpKey> {
        self.repo.get_by_id(tenant_id, id).await
    }

    pub async fn revoke(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.repo.revoke(tenant_id, id).await
    }

    pub async fn list(
        &self,
        tenant_id: Uuid,
        pagination: Pagination,
    ) -> AxiamResult<PaginatedResult<PgpKey>> {
        self.repo.list(tenant_id, pagination).await
    }

    /// Sign a batch of audit log entries with the tenant's AuditSigning key.
    pub async fn sign_audit_batch(
        &self,
        tenant_id: Uuid,
        entries: Vec<AuditLogEntry>,
    ) -> AxiamResult<SignedAuditBatch> {
        let signing_key = self.repo.get_signing_key(tenant_id).await?;

        let encrypted_pk = signing_key
            .encrypted_private_key
            .as_ref()
            .ok_or_else(|| AxiamError::Crypto("signing key has no encrypted private key".into()))?;

        let private_key_pem = decrypt_private_key(encrypted_pk, &self.config.encryption_key)?;
        let private_key_armored = String::from_utf8(private_key_pem)
            .map_err(|e| AxiamError::Crypto(format!("invalid UTF-8 in private key: {e}")))?;

        let (secret_key, _) = SignedSecretKey::from_string(&private_key_armored)
            .map_err(|e| AxiamError::Crypto(format!("failed to parse private key: {e}")))?;

        // Serialize entries to JSON
        let entry_ids: Vec<Uuid> = entries.iter().map(|e| e.id).collect();
        let data = serde_json::to_vec(&entries)
            .map_err(|e| AxiamError::Crypto(format!("failed to serialize entries: {e}")))?;

        // Sign the data using MessageBuilder
        let mut msg_builder = MessageBuilder::from_bytes("audit-batch", data);
        msg_builder.sign(
            &secret_key.primary_key,
            Password::default(),
            HashAlgorithm::Sha256,
        );
        let signed_msg = msg_builder
            .to_armored_string(OsRng, ArmorOptions::default())
            .map_err(|e| AxiamError::Crypto(format!("failed to sign data: {e}")))?;

        Ok(SignedAuditBatch {
            batch_id: Uuid::new_v4(),
            tenant_id,
            signing_key_id: signing_key.id,
            entry_ids,
            signature_armored: signed_msg,
            signed_at: Utc::now(),
        })
    }

    /// Encrypt data with a recipient's PGP public key.
    pub async fn encrypt_for_export(
        &self,
        tenant_id: Uuid,
        key_id: Uuid,
        plaintext: &[u8],
    ) -> AxiamResult<EncryptedExport> {
        let key = self.repo.get_by_id(tenant_id, key_id).await?;

        let (public_key, _) = SignedPublicKey::from_string(&key.public_key_armored)
            .map_err(|e| AxiamError::Crypto(format!("failed to parse public key: {e}")))?;

        let plaintext_owned = plaintext.to_vec();
        let mut builder = MessageBuilder::from_bytes("export.bin", plaintext_owned)
            .seipd_v1(OsRng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(OsRng, &public_key)
            .map_err(|e| AxiamError::Crypto(format!("failed to encrypt data: {e}")))?;

        let ciphertext_armored: String = builder
            .to_armored_string(OsRng, ArmorOptions::default())
            .map_err(|e| AxiamError::Crypto(format!("failed to armor ciphertext: {e}")))?;

        Ok(EncryptedExport {
            recipient_key_id: key_id,
            ciphertext_armored,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn generate_keypair(algorithm: &PgpKeyAlgorithm, user_id: &str) -> AxiamResult<SignedSecretKey> {
    let key_type = match algorithm {
        PgpKeyAlgorithm::Ed25519 => KeyType::Ed25519Legacy,
        PgpKeyAlgorithm::Rsa4096 => KeyType::Rsa(4096),
    };

    let mut builder = SecretKeyParamsBuilder::default();
    builder
        .key_type(key_type)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(user_id.into())
        .preferred_symmetric_algorithms(smallvec::smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec::smallvec![HashAlgorithm::Sha256])
        .version(KeyVersion::V4);

    let params = builder
        .build()
        .map_err(|e| AxiamError::Crypto(format!("failed to build key params: {e}")))?;

    let signed_secret_key = params
        .generate(OsRng)
        .map_err(|e| AxiamError::Crypto(format!("failed to generate keypair: {e}")))?;

    Ok(signed_secret_key)
}

fn encrypt_private_key(plaintext: &[u8], key_bytes: &[u8; 32]) -> AxiamResult<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM encryption failed: {e}")))?;

    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn decrypt_private_key(encrypted: &[u8], key_bytes: &[u8; 32]) -> AxiamResult<Vec<u8>> {
    if encrypted.len() < 12 {
        return Err(AxiamError::Crypto("ciphertext too short".into()));
    }
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| AxiamError::Crypto(format!("AES-256-GCM decryption failed: {e}")))
}

//! Federation client-secret encryption helpers (D-10..D-13).
//!
//! Uses the split-output AES-256-GCM variant from `axiam_auth::crypto`
//! (plan 04-01 Task 1) so each of `client_secret_nonce` and
//! `client_secret_ciphertext` lands in its own DB column (D-11).
//!
//! The bundled variant (`aes256gcm_encrypt`/`aes256gcm_decrypt`) is NOT used
//! here — that is exclusively for TOTP secret storage.

use axiam_auth::crypto::{decrypt_separate, encrypt_separate};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::repository::{AuditLogRepository, FederationConfigRepository};
use tracing::error;
use uuid::Uuid;

use crate::error::FederationError;

// ---------------------------------------------------------------------------
// Key versioning
// ---------------------------------------------------------------------------

/// Returns the current key version for newly encrypted secrets.
///
/// Used by `migrate_plaintext_federation_secrets` and by
/// `encrypt_client_secret` callers. Enables future key rotation without
/// re-encrypting all secrets at once.
pub fn current_key_version() -> i64 {
    1
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt
// ---------------------------------------------------------------------------

/// Encrypt a federation `client_secret` using AES-256-GCM with a fresh nonce.
///
/// Returns `(nonce_b64, ciphertext_b64)` for storage in the
/// `client_secret_nonce` and `client_secret_ciphertext` columns (D-11).
///
/// Uses [`axiam_auth::crypto::encrypt_separate`] — do NOT use the bundled
/// `aes256gcm_encrypt` function which is reserved for TOTP storage.
pub fn encrypt_client_secret(
    key: &[u8; 32],
    plaintext: &str,
) -> Result<(String, String), FederationError> {
    encrypt_separate(key, plaintext.as_bytes())
        .map_err(|e| FederationError::CryptoError(e.to_string()))
}

/// Decrypt a federation `client_secret` from the split-column format (D-11).
///
/// Accepts base64-encoded `nonce_b64` and `ciphertext_b64` as stored in the
/// `client_secret_nonce` and `client_secret_ciphertext` columns.
pub fn decrypt_client_secret(
    key: &[u8; 32],
    nonce_b64: &str,
    ciphertext_b64: &str,
) -> Result<String, FederationError> {
    let bytes = decrypt_separate(key, nonce_b64, ciphertext_b64)
        .map_err(|e| FederationError::CryptoError(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| FederationError::CryptoError(format!("UTF-8 decode: {e}")))
}

/// Resolve the effective `client_secret` for a federation config, with
/// automatic fallback for the brief rolling-deploy window during the
/// boot backfill (RESEARCH §8 risk #5).
///
/// Resolution order:
///
/// 1. If `client_secret_nonce` and `client_secret_ciphertext` are both present
///    → decrypt and return.
/// 2. If only the legacy plaintext `client_secret` is present (pre-backfill
///    row still in flight) → return as-is (fallback for deploy window).
/// 3. Otherwise → `Err(FederationError::ConfigIncomplete)`.
pub fn decrypt_client_secret_or_legacy(
    key: &[u8; 32],
    nonce_b64: Option<&str>,
    ciphertext_b64: Option<&str>,
    legacy_plaintext: &str,
) -> Result<String, FederationError> {
    match (nonce_b64, ciphertext_b64) {
        (Some(n), Some(c)) => decrypt_client_secret(key, n, c),
        _ if !legacy_plaintext.is_empty() => {
            // Decrypt-or-legacy fallback: backfill has not run yet for this row.
            // This code path is only active during the brief boot window between
            // DB migration and the backfill task completing.
            Ok(legacy_plaintext.to_string())
        }
        _ => Err(FederationError::ConfigIncomplete),
    }
}

// ---------------------------------------------------------------------------
// Boot backfill
// ---------------------------------------------------------------------------

/// Encrypt any remaining plaintext `client_secret` rows in `federation_config`.
///
/// Called once at server startup after schema migrations (D-12). The predicate
/// `client_secret_ciphertext IS NONE AND client_secret IS NOT NONE AND
/// client_secret != ""` is self-clearing: once a row is migrated it no longer
/// matches the query, making repeated calls safe.
///
/// Per-row errors are logged and skipped — the loop continues to the next row.
/// The failed rows will be retried on the next boot.
///
/// Returns the number of rows successfully migrated.
pub async fn migrate_plaintext_federation_secrets<FR, AR>(
    fed_repo: &FR,
    audit_repo: &AR,
    key: &[u8; 32],
) -> Result<usize, axiam_core::error::AxiamError>
where
    FR: FederationConfigRepository,
    AR: AuditLogRepository,
{
    let rows = fed_repo.list_with_legacy_plaintext_secret().await?;
    let mut migrated = 0usize;

    for config in rows {
        let plaintext = &config.client_secret;
        if plaintext.is_empty() {
            continue;
        }

        let (nonce_b64, ct_b64) = match encrypt_client_secret(key, plaintext) {
            Ok(pair) => pair,
            Err(e) => {
                error!(
                    config_id = %config.id,
                    tenant_id = %config.tenant_id,
                    error = %e,
                    "federation secret backfill: encrypt failed — skipping row"
                );
                continue;
            }
        };

        if let Err(e) = fed_repo
            .set_encrypted_secret(
                config.tenant_id,
                config.id,
                nonce_b64,
                ct_b64,
                current_key_version(),
            )
            .await
        {
            error!(
                config_id = %config.id,
                tenant_id = %config.tenant_id,
                error = %e,
                "federation secret backfill: DB write failed — skipping row"
            );
            continue;
        }

        // Emit one audit entry per migrated row (D-12 auditability).
        let audit_entry = CreateAuditLogEntry {
            tenant_id: config.tenant_id,
            actor_id: Uuid::nil(), // system actor
            actor_type: ActorType::System,
            action: "federation_secret_migrated".to_string(),
            resource_id: Some(config.id),
            outcome: AuditOutcome::Success,
            ip_address: None,
            metadata: Some(serde_json::json!({
                "event": "federation_secret_migrated",
                "config_id": config.id.to_string(),
                "tenant_id": config.tenant_id.to_string(),
                "key_version": current_key_version(),
            })),
        };

        if let Err(e) = audit_repo.append(audit_entry).await {
            // Audit failure is non-fatal — the secret is already encrypted.
            error!(
                config_id = %config.id,
                error = %e,
                "federation secret backfill: audit log write failed (non-fatal)"
            );
        }

        migrated += 1;
    }

    Ok(migrated)
}

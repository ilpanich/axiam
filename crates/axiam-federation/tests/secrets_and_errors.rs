//! Unit tests for federation client-secret encryption (`secrets`), the
//! `FederationError` → `AxiamError` mapping (`error`), and the boot backfill
//! migration. No external services required — repositories are mocked.

use std::sync::Mutex;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{AuditLogEntry, CreateAuditLogEntry};
use axiam_core::models::federation::{
    CreateFederationConfig, FederationConfig, FederationProtocol, UpdateFederationConfig,
};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, FederationConfigRepository, PaginatedResult, Pagination,
};
use axiam_federation::error::FederationError;
use axiam_federation::secrets::{
    current_key_version, decrypt_client_secret, decrypt_client_secret_or_legacy,
    encrypt_client_secret, migrate_plaintext_federation_secrets,
};
use chrono::Utc;
use uuid::Uuid;

const KEY: [u8; 32] = [7u8; 32];

// ---------------------------------------------------------------------------
// encrypt / decrypt
// ---------------------------------------------------------------------------

#[test]
fn encrypt_then_decrypt_roundtrips() {
    let (nonce, ct) = encrypt_client_secret(&KEY, "super-secret").unwrap();
    assert!(!nonce.is_empty());
    assert!(!ct.is_empty());
    let out = decrypt_client_secret(&KEY, &nonce, &ct).unwrap();
    assert_eq!(out, "super-secret");
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let (nonce, ct) = encrypt_client_secret(&KEY, "secret").unwrap();
    let wrong = [9u8; 32];
    let err = decrypt_client_secret(&wrong, &nonce, &ct).unwrap_err();
    assert!(matches!(err, FederationError::CryptoError(_)));
}

#[test]
fn decrypt_with_garbage_ciphertext_fails() {
    let err = decrypt_client_secret(&KEY, "bad-nonce", "bad-ct").unwrap_err();
    assert!(matches!(err, FederationError::CryptoError(_)));
}

#[test]
fn key_version_is_one() {
    assert_eq!(current_key_version(), 1);
}

// ---------------------------------------------------------------------------
// decrypt_client_secret_or_legacy
// ---------------------------------------------------------------------------

#[test]
fn or_legacy_prefers_encrypted_columns() {
    let (nonce, ct) = encrypt_client_secret(&KEY, "encrypted-val").unwrap();
    let out =
        decrypt_client_secret_or_legacy(&KEY, Some(&nonce), Some(&ct), "legacy-plain").unwrap();
    assert_eq!(out, "encrypted-val");
}

#[test]
fn or_legacy_falls_back_to_plaintext() {
    let out = decrypt_client_secret_or_legacy(&KEY, None, None, "legacy-plain").unwrap();
    assert_eq!(out, "legacy-plain");
}

#[test]
fn or_legacy_config_incomplete_when_nothing_present() {
    let err = decrypt_client_secret_or_legacy(&KEY, None, None, "").unwrap_err();
    assert!(matches!(err, FederationError::ConfigIncomplete));
}

// ---------------------------------------------------------------------------
// FederationError → AxiamError mapping
// ---------------------------------------------------------------------------

#[test]
fn error_maps_to_expected_axiam_variants() {
    let cases: Vec<(FederationError, fn(&AxiamError) -> bool)> = vec![
        (
            FederationError::ConfigNotFound("cfg".into()),
            (|e| matches!(e, AxiamError::NotFound { .. })) as fn(&AxiamError) -> bool,
        ),
        (FederationError::ConfigDisabled, |e| {
            matches!(e, AxiamError::Validation { .. })
        }),
        (FederationError::ProtocolMismatch("m".into()), |e| {
            matches!(e, AxiamError::Validation { .. })
        }),
        (FederationError::InvalidMetadataUrl("m".into()), |e| {
            matches!(e, AxiamError::Validation { .. })
        }),
        (FederationError::IdTokenValidationFailed("m".into()), |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::SamlResponseFailed("m".into()), |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::JwtSignatureInvalid, |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::JwtClaimRejected("m".into()), |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::AlgorithmNotAllowed("m".into()), |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::JwksKidUnknown, |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::SamlSignatureInvalid("m".into()), |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::AssertionReplay, |e| {
            matches!(e, AxiamError::AuthenticationFailed { .. })
        }),
        (FederationError::InvalidIdpCert("m".into()), |e| {
            matches!(e, AxiamError::Validation { .. })
        }),
        (FederationError::DiscoveryFailed("m".into()), |e| {
            matches!(e, AxiamError::ServiceUnavailable(_))
        }),
        (FederationError::TokenExchangeFailed("m".into()), |e| {
            matches!(e, AxiamError::ServiceUnavailable(_))
        }),
        (FederationError::JwksFetchFailed("m".into()), |e| {
            matches!(e, AxiamError::ServiceUnavailable(_))
        }),
        (FederationError::ConfigIncomplete, |e| {
            matches!(e, AxiamError::Internal(_))
        }),
        (FederationError::CryptoError("m".into()), |e| {
            matches!(e, AxiamError::Internal(_))
        }),
        (FederationError::Internal("m".into()), |e| {
            matches!(e, AxiamError::Internal(_))
        }),
        (FederationError::SamlMetadataFailed("m".into()), |e| {
            matches!(e, AxiamError::Internal(_))
        }),
        (FederationError::ProvisioningFailed("m".into()), |e| {
            matches!(e, AxiamError::Internal(_))
        }),
    ];
    for (fed_err, check) in cases {
        // Display must be non-empty.
        assert!(!fed_err.to_string().is_empty());
        let axiam: AxiamError = fed_err.into();
        assert!(check(&axiam), "unexpected mapping: {axiam:?}");
    }
}

// ---------------------------------------------------------------------------
// Mock repositories for migrate_plaintext_federation_secrets
// ---------------------------------------------------------------------------

fn make_config(plaintext: &str) -> FederationConfig {
    FederationConfig {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        provider: "okta".into(),
        protocol: FederationProtocol::OidcConnect,
        metadata_url: Some("https://idp.example.com/.well-known".into()),
        client_id: "cid".into(),
        client_secret: plaintext.into(),
        attribute_map: serde_json::Value::Null,
        enabled: true,
        allowed_algorithms: vec!["RS256".into()],
        idp_signing_cert_pem: None,
        client_secret_ciphertext: None,
        client_secret_nonce: None,
        client_secret_key_version: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

struct MockFedRepo {
    rows: Vec<FederationConfig>,
    set_calls: Mutex<usize>,
    fail_set: bool,
}

impl FederationConfigRepository for MockFedRepo {
    async fn create(&self, _i: CreateFederationConfig) -> AxiamResult<FederationConfig> {
        unimplemented!()
    }
    async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<FederationConfig> {
        unimplemented!()
    }
    async fn update(
        &self,
        _t: Uuid,
        _i: Uuid,
        _u: UpdateFederationConfig,
    ) -> AxiamResult<FederationConfig> {
        unimplemented!()
    }
    async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn list(
        &self,
        _t: Uuid,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<FederationConfig>> {
        unimplemented!()
    }
    async fn list_with_legacy_plaintext_secret(&self) -> AxiamResult<Vec<FederationConfig>> {
        Ok(self.rows.clone())
    }
    async fn set_encrypted_secret(
        &self,
        _t: Uuid,
        _c: Uuid,
        _n: String,
        _ct: String,
        _v: i64,
    ) -> AxiamResult<()> {
        *self.set_calls.lock().unwrap() += 1;
        if self.fail_set {
            Err(AxiamError::Database("write failed".into()))
        } else {
            Ok(())
        }
    }
}

struct MockAuditRepo {
    appends: Mutex<usize>,
    fail_append: bool,
}

impl AuditLogRepository for MockAuditRepo {
    async fn append(&self, input: CreateAuditLogEntry) -> AxiamResult<AuditLogEntry> {
        *self.appends.lock().unwrap() += 1;
        if self.fail_append {
            return Err(AxiamError::Database("audit failed".into()));
        }
        Ok(AuditLogEntry {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            actor_id: input.actor_id,
            actor_type: input.actor_type,
            action: input.action,
            resource_id: input.resource_id,
            outcome: input.outcome,
            ip_address: input.ip_address,
            metadata: input.metadata.unwrap_or(serde_json::Value::Null),
            timestamp: Utc::now(),
        })
    }
    async fn list(
        &self,
        _t: Uuid,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn list_system(
        &self,
        _f: AuditLogFilter,
        _p: Pagination,
    ) -> AxiamResult<PaginatedResult<AuditLogEntry>> {
        unimplemented!()
    }
    async fn get_by_ids(&self, _t: Uuid, _ids: &[Uuid]) -> AxiamResult<Vec<AuditLogEntry>> {
        unimplemented!()
    }
    async fn pseudonymize_actor(&self, _t: Uuid, _u: Uuid, _p: &str) -> AxiamResult<u64> {
        unimplemented!()
    }
}

#[tokio::test]
async fn migrate_encrypts_plaintext_rows_and_audits() {
    let fed = MockFedRepo {
        rows: vec![make_config("secret-a"), make_config("secret-b")],
        set_calls: Mutex::new(0),
        fail_set: false,
    };
    let audit = MockAuditRepo {
        appends: Mutex::new(0),
        fail_append: false,
    };
    let migrated = migrate_plaintext_federation_secrets(&fed, &audit, &KEY)
        .await
        .unwrap();
    assert_eq!(migrated, 2);
    assert_eq!(*fed.set_calls.lock().unwrap(), 2);
    assert_eq!(*audit.appends.lock().unwrap(), 2);
}

#[tokio::test]
async fn migrate_skips_empty_plaintext_rows() {
    let fed = MockFedRepo {
        rows: vec![make_config(""), make_config("real")],
        set_calls: Mutex::new(0),
        fail_set: false,
    };
    let audit = MockAuditRepo {
        appends: Mutex::new(0),
        fail_append: false,
    };
    let migrated = migrate_plaintext_federation_secrets(&fed, &audit, &KEY)
        .await
        .unwrap();
    assert_eq!(migrated, 1);
    assert_eq!(*fed.set_calls.lock().unwrap(), 1);
}

#[tokio::test]
async fn migrate_continues_when_db_write_fails() {
    let fed = MockFedRepo {
        rows: vec![make_config("a"), make_config("b")],
        set_calls: Mutex::new(0),
        fail_set: true,
    };
    let audit = MockAuditRepo {
        appends: Mutex::new(0),
        fail_append: false,
    };
    // All set_encrypted_secret calls fail → 0 migrated, but no panic and both attempted.
    let migrated = migrate_plaintext_federation_secrets(&fed, &audit, &KEY)
        .await
        .unwrap();
    assert_eq!(migrated, 0);
    assert_eq!(*fed.set_calls.lock().unwrap(), 2);
    assert_eq!(*audit.appends.lock().unwrap(), 0);
}

#[tokio::test]
async fn migrate_audit_failure_is_non_fatal() {
    let fed = MockFedRepo {
        rows: vec![make_config("a")],
        set_calls: Mutex::new(0),
        fail_set: false,
    };
    let audit = MockAuditRepo {
        appends: Mutex::new(0),
        fail_append: true,
    };
    // Audit append fails but the secret is already encrypted → still counts as migrated.
    let migrated = migrate_plaintext_federation_secrets(&fed, &audit, &KEY)
        .await
        .unwrap();
    assert_eq!(migrated, 1);
}

#[tokio::test]
async fn migrate_empty_row_set_yields_zero() {
    let fed = MockFedRepo {
        rows: vec![],
        set_calls: Mutex::new(0),
        fail_set: false,
    };
    let audit = MockAuditRepo {
        appends: Mutex::new(0),
        fail_append: false,
    };
    let migrated = migrate_plaintext_federation_secrets(&fed, &audit, &KEY)
        .await
        .unwrap();
    assert_eq!(migrated, 0);
}

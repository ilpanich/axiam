//! Integration tests for CertService — leaf cert issuance and CA validation.

use axiam_core::models::certificate::{
    CertificateStatus, CertificateType, CreateCaCertificate, CreateCertificate, KeyAlgorithm,
    StoreCaCertificate,
};
use axiam_core::repository::CaCertificateRepository;
use axiam_db::repository::{SurrealCaCertificateRepository, SurrealCertificateRepository};
use axiam_pki::ca::{CaService, PkiConfig};
use axiam_pki::cert::CertService;
use chrono::{Duration, Utc};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;

type TestDb = surrealdb::engine::local::Db;

async fn setup_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn test_pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: Some([0u8; 32]), // gitleaks:allow
    }
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

/// Generate a CA, then issue a leaf cert against it — happy path.
#[tokio::test]
async fn cert_generate_against_active_ca_succeeds() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config(), sem);

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    let generated = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=device-001".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("Leaf cert generation must succeed");

    assert!(
        generated
            .certificate
            .public_cert_pem
            .contains("CERTIFICATE"),
        "leaf cert PEM must contain CERTIFICATE header"
    );
    assert!(
        !generated.private_key_pem.is_empty(),
        "leaf private key must be returned"
    );
}

// ---------------------------------------------------------------------------
// Reject cases
// ---------------------------------------------------------------------------

/// Revoking the CA must prevent leaf cert issuance (inactive CA reject).
#[tokio::test]
async fn cert_generate_rejects_revoked_ca() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let svc_cert = CertService::new(ca_repo.clone(), cert_repo, test_pki_config(), sem);

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Revoked CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    svc_ca
        .revoke(org_id, ca.certificate.id)
        .await
        .expect("revoke must succeed");

    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=device-002".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(
        result.is_err(),
        "leaf cert issuance against a revoked CA must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("not active"),
        "error must mention 'not active', got: {err_msg}"
    );
}

/// Storing a CA with `not_after` in the past must block leaf cert issuance (expired CA reject).
#[tokio::test]
async fn cert_generate_rejects_expired_ca() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let now = Utc::now();

    // Build an expired CA row directly via StoreCaCertificate so not_after is in the past.
    // The CA is generated with normal rcgen to produce real cert PEM and key data,
    // then stored with a backdated not_after so CertService sees it as expired.
    use axiam_pki::ca::PkiConfig as Cfg;
    let temp_config = Cfg {
        encryption_key: Some([0u8; 32]), // gitleaks:allow
    };
    let svc_ca_temp = CaService::new(
        ca_repo.clone(),
        temp_config,
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );
    let real_ca = svc_ca_temp
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Expired CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 1,
        })
        .await
        .expect("CA generation must succeed");

    // Now insert a second, manipulated CA row with not_after in the past.
    // We use the real generated key material so rcgen can reconstruct and sign with it,
    // but override the validity window to be expired.
    let expired_ca = ca_repo
        .create(StoreCaCertificate {
            organization_id: org_id,
            subject: "Expired CA Clone".into(),
            public_cert_pem: real_ca.certificate.public_cert_pem.clone(),
            fingerprint: format!("expired-{}", real_ca.certificate.fingerprint),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: now - Duration::days(10),
            not_after: now - Duration::days(1), // expired yesterday
            encrypted_private_key: real_ca.certificate.encrypted_private_key.clone(),
        })
        .await
        .expect("direct CA row creation must succeed");

    let svc_cert = CertService::new(
        ca_repo,
        cert_repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: expired_ca.id,
                subject: "CN=device-003".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(
        result.is_err(),
        "leaf cert issuance against an expired CA must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    // Assert the specific reject reason. A `|| contains("valid")` fallback was too
    // broad ("valid" appears in many unrelated messages); the CA-expiry path must
    // explicitly mention expiry.
    assert!(
        err_msg.contains("expired"),
        "error must mention expiry, got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// QUAL-05/D-08: CA reconstruction must derive the issuer DN from the real CA
// certificate PEM, not from the (mutable) stored `subject` field.
// ---------------------------------------------------------------------------

/// A leaf cert's Issuer DN must be byte-identical to the CA cert's real Subject
/// DN — even when the CA record's `subject` field has drifted from the DN
/// actually embedded in the already-issued CA certificate (e.g. a later rename
/// that did not reissue the CA). The old `build_ca_params(&ca_cert.subject)`
/// path reconstructs the signing CA from the mutable `subject` field and would
/// silently embed the drifted value as the leaf's Issuer; the fix
/// (`CertificateParams::from_ca_cert_pem`) reconstructs from the real CA cert
/// PEM, so drift in the `subject` field cannot leak into the Issuer DN (T-29-11).
#[tokio::test]
async fn cert_generate_issuer_dn_matches_real_ca_subject_not_stored_subject_field() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();

    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());

    // Generate a real CA — its certificate PEM embeds Subject DN "CN=Real CA Subject".
    let real_ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Real CA Subject".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    // Insert a manipulated CA row: the same real cert PEM + key material, but a
    // DIFFERENT `subject` field value — simulating drift between the DB record
    // and the DN actually baked into the certificate.
    let manipulated_ca = ca_repo
        .create(StoreCaCertificate {
            organization_id: org_id,
            subject: "Drifted Subject Inc".into(),
            public_cert_pem: real_ca.certificate.public_cert_pem.clone(),
            fingerprint: format!("drifted-{}", real_ca.certificate.fingerprint),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: real_ca.certificate.not_before,
            not_after: real_ca.certificate.not_after,
            encrypted_private_key: real_ca.certificate.encrypted_private_key.clone(),
        })
        .await
        .expect("manipulated CA row creation must succeed");

    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config(), sem);

    let generated = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: manipulated_ca.id,
                subject: "CN=leaf-001".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf cert generation must succeed");

    // Ground truth: the real CA cert's actual Subject DN (parsed from the PEM).
    let (_, ca_pem_obj) =
        x509_parser::pem::parse_x509_pem(real_ca.certificate.public_cert_pem.as_bytes())
            .expect("CA PEM must parse");
    let (_, ca_x509) = x509_parser::prelude::parse_x509_certificate(&ca_pem_obj.contents)
        .expect("CA cert must parse");
    let real_ca_subject_dn = ca_x509.subject().to_string();

    // The leaf cert's Issuer DN.
    let (_, leaf_pem_obj) =
        x509_parser::pem::parse_x509_pem(generated.certificate.public_cert_pem.as_bytes())
            .expect("leaf PEM must parse");
    let (_, leaf_x509) = x509_parser::prelude::parse_x509_certificate(&leaf_pem_obj.contents)
        .expect("leaf cert must parse");
    let leaf_issuer_dn = leaf_x509.issuer().to_string();

    assert_eq!(
        leaf_issuer_dn, real_ca_subject_dn,
        "leaf Issuer DN must be byte-identical to the real CA cert's Subject DN, \
         not derived from the (possibly stale) stored `subject` field"
    );

    // Control assertion: chain verification against the real CA cert still succeeds.
    leaf_x509
        .verify_signature(Some(ca_x509.public_key()))
        .expect("leaf cert must still verify against the CA's public key");
}

// ---------------------------------------------------------------------------
// validity_days bounds (A6 additions)
// ---------------------------------------------------------------------------

/// `validity_days == 0` must be rejected before any DB/crypto work happens.
#[tokio::test]
async fn cert_generate_rejects_zero_validity_days() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config(), sem);

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Zero-Days CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=zero-days".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 0,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(result.is_err(), "validity_days == 0 must be rejected");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("validity_days must be between 1"),
        "got: {err_msg}"
    );
}

/// `validity_days` above the effective max (default 365, no tenant override)
/// must be rejected with a message citing the hard cap.
#[tokio::test]
async fn cert_generate_rejects_validity_days_above_default_max() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config(), sem);

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Over-Max CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 3650,
        })
        .await
        .expect("CA generation must succeed");

    // No max_validity_days override passed -> effective_max defaults to
    // DEFAULT_LEAF_CERT_VALIDITY_DAYS (365). Request more than that.
    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=over-max".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 400,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(result.is_err(), "validity_days above effective max must fail");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("validity_days must be between 1 and 365"),
        "got: {err_msg}"
    );
    assert!(
        err_msg.contains("825"),
        "error must mention the CA/Browser Forum hard cap, got: {err_msg}"
    );
}

/// A `max_validity_days` override above the hard cap (825) must be clamped
/// down to the hard cap, not honored verbatim.
#[tokio::test]
async fn cert_generate_clamps_tenant_override_to_hard_cap() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config(), sem);

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Long-Lived CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 3650,
        })
        .await
        .expect("CA generation must succeed");

    // Tenant override of 2000 days is above the 825-day hard cap, so
    // requesting 900 days (between the cap and the override) must still fail.
    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=clamped".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 900,
                metadata: None,
            },
            Some(2000),
        )
        .await;

    assert!(
        result.is_err(),
        "requested validity above the 825-day hard cap must fail even with a higher tenant override"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("validity_days must be between 1 and 825"),
        "got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Missing key material
// ---------------------------------------------------------------------------

/// A CA row with no `encrypted_private_key` stored must block leaf issuance.
#[tokio::test]
async fn cert_generate_rejects_ca_with_no_stored_private_key() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let now = Utc::now();

    // Insert a CA row directly with encrypted_private_key = None (simulating a
    // CA row that predates key storage, or whose key was purged).
    let ca_no_key = ca_repo
        .create(StoreCaCertificate {
            organization_id: org_id,
            subject: "Keyless CA".into(),
            public_cert_pem: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"
                .into(),
            fingerprint: "keyless-fingerprint".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            not_before: now - Duration::days(1),
            not_after: now + Duration::days(365),
            encrypted_private_key: None,
        })
        .await
        .expect("direct CA row creation must succeed");

    let svc_cert = CertService::new(
        ca_repo,
        cert_repo,
        test_pki_config(),
        std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
    );

    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca_no_key.id,
                subject: "CN=keyless".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(
        result.is_err(),
        "leaf issuance against a CA with no stored private key must fail"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("no stored private key"),
        "got: {err_msg}"
    );
}

/// `PkiConfig.encryption_key == None` must block leaf issuance even against a
/// perfectly valid, active CA (SEC-012: encryption key must be present).
#[tokio::test]
async fn cert_generate_rejects_when_encryption_key_not_configured() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));

    // CA is generated with a real encryption key configured...
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "No-Enc-Key Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    // ...but the CertService is built with no encryption key configured.
    let no_key_config = PkiConfig {
        encryption_key: None,
    };
    let svc_cert = CertService::new(ca_repo, cert_repo, no_key_config, sem);

    let result = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=no-enc-key".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await;

    assert!(
        result.is_err(),
        "leaf issuance must fail when no encryption key is configured"
    );
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("ENCRYPTION_KEY not set"),
        "got: {err_msg}"
    );
}

// ---------------------------------------------------------------------------
// Algorithm coverage
// ---------------------------------------------------------------------------

/// RSA-4096 CA generation exercises the `Rsa4096` arm of `generate_keypair`
/// end-to-end through `CaService::generate`. SURFACED LIMITATION (not endorsed):
/// rcgen's `ring` backend cannot *generate* RSA keys, so this path errors today
/// even though RSA-4096 is a documented certificate target. This test pins the
/// current behavior and covers the error-propagation path; if RSA key
/// generation becomes available, restore the full success-flow assertions.
#[tokio::test]
async fn cert_generate_rsa4096_ca_errors_under_ring_backend() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let _cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());

    let result = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "RSA Test CA".into(),
            key_algorithm: KeyAlgorithm::Rsa4096,
            validity_days: 365,
        })
        .await;

    assert!(
        result.is_err(),
        "expected RSA-4096 CA generation to error under the ring backend"
    );
}

/// `get`, `get_by_fingerprint`, `list`, and `revoke` thin wrappers.
#[tokio::test]
async fn cert_service_read_and_revoke_wrappers_work() {
    let db = setup_db().await;
    let ca_repo = SurrealCaCertificateRepository::new(db.clone());
    let cert_repo = SurrealCertificateRepository::new(db.clone());

    let org_id = uuid::Uuid::new_v4();
    let tenant_id = uuid::Uuid::new_v4();
    let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(4));
    let svc_ca = CaService::new(ca_repo.clone(), test_pki_config(), sem.clone());
    let svc_cert = CertService::new(ca_repo, cert_repo, test_pki_config(), sem);

    let ca = svc_ca
        .generate(CreateCaCertificate {
            organization_id: org_id,
            subject: "Wrapper Test CA".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
        })
        .await
        .expect("CA generation must succeed");

    let generated = svc_cert
        .generate(
            org_id,
            CreateCertificate {
                tenant_id,
                issuer_ca_id: ca.certificate.id,
                subject: "CN=wrapper-device".into(),
                cert_type: CertificateType::Device,
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 30,
                metadata: None,
            },
            None,
        )
        .await
        .expect("leaf generation must succeed");

    let fetched = svc_cert
        .get(tenant_id, generated.certificate.id)
        .await
        .expect("get must succeed");
    assert_eq!(fetched.id, generated.certificate.id);

    let by_fp = svc_cert
        .get_by_fingerprint(tenant_id, &generated.certificate.fingerprint)
        .await
        .expect("get_by_fingerprint must succeed");
    assert_eq!(by_fp.id, generated.certificate.id);

    let page = svc_cert
        .list(tenant_id, axiam_core::repository::Pagination::default())
        .await
        .expect("list must succeed");
    assert!(page.items.iter().any(|c| c.id == generated.certificate.id));

    svc_cert
        .revoke(tenant_id, generated.certificate.id)
        .await
        .expect("revoke must succeed");
    let revoked = svc_cert
        .get(tenant_id, generated.certificate.id)
        .await
        .expect("get after revoke must succeed");
    assert_eq!(revoked.status, CertificateStatus::Revoked);
}
